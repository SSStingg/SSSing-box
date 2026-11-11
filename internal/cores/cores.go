package cores

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CoreDef describes one downloadable core.
type CoreDef struct {
	Name     string // xray | hysteria | sing-box
	Title    string
	Repo     string                   // owner/repo on GitHub
	BinName  string                   // binary file name inside the asset
	AssetSub func(arch string) string // substring that must appear in the asset name
}

func arch() string {
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return "amd64"
}

func Defs() []CoreDef {
	// 退役说明：xray 与 hysteria 已从面板下架（sing-box 接管全部节点），
	// 旧二进制仍留在磁盘上，等用户确认后再删；面板不再提供安装/更新入口，
	// 已装旧核的更新检查也随之下线。
	// 顺序即卡片顺序：sing-box 在上（主内核）。
	return []CoreDef{
		{Name: "sing-box", Title: "Sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box",
			AssetSub: func(arch string) string { return "linux-" + arch }},
	}
}

// DetectSingBoxVersion runs `sing-box version` and parses its first line
// ("sing-box version 1.14.4"). Used when the binary was placed by hand
// instead of through the panel installer, so the card never shows a blank
// version for an installed core. 5 秒超时：二进制被换成挂起程序时调用方
// 不再永久阻塞；失败与未安装都返回 ""（调用方只在已装时补版本）。
func DetectSingBoxVersion(bin string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "version").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "sing-box" && f[1] == "version" {
			return f[2]
		}
	}
	return ""
}

func DefByName(name string) (CoreDef, bool) {
	for _, d := range Defs() {
		if d.Name == name {
			return d, true
		}
	}
	return CoreDef{}, false
}

// ---- GitHub releases ----

type Release struct {
	Tag    string   `json:"tag"`
	Assets []string `json:"assets"`
}

var (
	relCacheMu sync.Mutex
	relCache   = map[string]struct {
		at time.Time
		rs []Release
	}{}
)

// CompareSemver 比较两个版本号（可带 v 前缀，如 v1.2.3、1.2.3-alpha.1）。
// 返回 -1/0/+1。数字段按数值比，缺失段按 0；预发布后缀（-alpha/-beta/
// -rc）小于同数字的正式版；解析失败的段按 0 处理并退化为字典序比较，
// 保证总有确定顺序。不引第三方 semver 库。
func CompareSemver(a, b string) int {
	pa, preA := splitSemver(a)
	pb, preB := splitSemver(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		na, nb := 0, 0
		if i < len(pa) {
			na = pa[i]
		}
		if i < len(pb) {
			nb = pb[i]
		}
		if na != nb {
			if na < nb {
				return -1
			}
			return 1
		}
	}
	if preA == preB {
		return 0
	}
	if preA == "" {
		return 1 // 正式版大于预发布版
	}
	if preB == "" {
		return -1
	}
	return comparePreRelease(preA, preB)
}

func splitSemver(v string) (nums []int, pre string) {
	v = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(v), "v"), "V")
	if i := strings.Index(v, "+"); i >= 0 { // 构建元数据不参与比较
		v = v[:i]
	}
	if i := strings.Index(v, "-"); i >= 0 {
		pre = v[i+1:]
		v = v[:i]
	}
	for _, s := range strings.Split(v, ".") {
		n, err := strconv.Atoi(s)
		if err != nil {
			n = 0
		}
		nums = append(nums, n)
	}
	return nums, pre
}

func comparePreRelease(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		if i >= len(as) {
			return -1 // 段更少的预发布版本更小
		}
		if i >= len(bs) {
			return 1
		}
		an, aerr := strconv.Atoi(as[i])
		bn, berr := strconv.Atoi(bs[i])
		if aerr == nil && berr == nil {
			if an != bn {
				if an < bn {
					return -1
				}
				return 1
			}
			continue
		}
		if as[i] != bs[i] {
			if as[i] < bs[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	Draft   bool   `json:"draft"`
	Pre     bool   `json:"prerelease"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// forgejoAPIBase：Forgejo API 根地址（面板自身仓库的来源），测试时可指到本地 httptest 服务。
// （2026-11-11 教训：这个变量名原来叫 githubAPIBase，实际却指向 Forgejo，
// 名不副实直接导致一次事故——只改它一个变量就把内核下载也带去了 Forgejo；
// 改名，名字必须说真话。）
var forgejoAPIBase = "https://998919.xyz/api/v1"

// upstreamAPIBase：上游内核仓库的 API 根地址（GitHub）。SagerNet/sing-box
// 等上游项目不在 Forgejo 上，内核下载必须走这里，不能走 Forgejo。
// （2026-11-11 教训：只改 forgejoAPIBase 一个变量，把内核下载也带去了
// Forgejo，Forgejo 上没有 sagernet 这个用户，下载直接 404。）
var upstreamAPIBase = "https://api.github.com"

// apiBaseFor 按仓库选 API：内核仓库（Defs 里有的上游项目）走 GitHub，
// 面板自己的仓库走 Forgejo；未知仓库直接报错，绝不默认走某一方，
// 否则仓库名写错只会静默 404，排障走弯路。
func apiBaseFor(repo string) (string, error) {
	if repoNameToCore(repo) != "" {
		return upstreamAPIBase, nil
	}
	if strings.EqualFold(strings.TrimSpace(repo), PanelRepo) {
		return forgejoAPIBase, nil
	}
	return "", fmt.Errorf("unknown repo %s", repo)
}

func ListReleases(repo string) ([]Release, error) {
	relCacheMu.Lock()
	if c, ok := relCache[repo]; ok && time.Since(c.at) < time.Hour {
		relCacheMu.Unlock()
		return c.rs, nil
	}
	relCacheMu.Unlock()
	return ListReleasesFresh(repo)
}

// ListReleasesAll：与 ListReleases 相同，但保留预发布版（测试版），
// 只过滤草稿。版本弹窗“显示所有内核”用它；默认的版本列表与“检查更
// 新”“更新到最新版”仍走 ListReleases（只含正式版），不会误装测试版。
func ListReleasesAll(repo string) ([]Release, error) {
	key := repo + "#all"
	relCacheMu.Lock()
	if c, ok := relCache[key]; ok && time.Since(c.at) < time.Hour {
		relCacheMu.Unlock()
		return c.rs, nil
	}
	relCacheMu.Unlock()
	return ListReleasesFreshAll(repo)
}

// ListReleasesFresh 不读缓存，直接拉取并刷新缓存。手动“检查更新”和
// “更新到最新版”必须走它，否则 1 小时缓存会让刚发的新版查不到。
// 返回的列表已过滤草稿与预发布版，并按 semver 从大到小排好，
// 所以调用方取 rels[0] 就是真正的最新正式版。
func ListReleasesFresh(repo string) ([]Release, error) {
	return listReleasesFreshFiltered(repo, false)
}

// ListReleasesFreshAll：与 ListReleasesFresh 相同，但保留预发布版
// （只过滤草稿），供版本弹窗“显示所有内核”用。
func ListReleasesFreshAll(repo string) ([]Release, error) {
	return listReleasesFreshFiltered(repo, true)
}

// listReleasesFreshFiltered 拉取、过滤、排序并写缓存；includePre 为
// true 时保留预发布版。缓存键：正式版用仓库名，含测试版的加 "#all"。
func listReleasesFreshFiltered(repo string, includePre bool) ([]Release, error) {
	base, err := apiBaseFor(repo)
	if err != nil {
		return nil, err
	}
	url := base + "/repos/" + repo + "/releases?limit=30"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sssingbox-panel")
	req.Header.Set("Accept", "application/vnd.github+json")
	// GITHUB_TOKEN 只发给 GitHub 上游：Forgejo 的调用本来就是匿名的，
	// 令牌发给自建站一旦对方记日志即失窃（曾把令牌误发给 Forgejo，
	// 现按目标源区分，只发给 api.github.com）。
	if base == upstreamAPIBase {
		if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		// 上游响应体只记日志，不拼进返回的错误：原样返回会把上游
		// 的内部细节（路径、提示）直接送到前端。
		label := "forgejo"
		if base == upstreamAPIBase {
			label = "github"
		}
		log.Printf("release 接口 %s 返回 %d：%s", label, resp.StatusCode, strings.TrimSpace(string(body)))
		return nil, fmt.Errorf("%s api %d", label, resp.StatusCode)
	}
	var gr []ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return nil, err
	}
	var out []Release
	for _, r := range gr {
		if r.Draft || (!includePre && r.Pre) {
			continue // 草稿不参与；预发布版只在“显示所有内核”时保留
		}
		rel := Release{Tag: r.TagName}
		for _, a := range r.Assets {
			rel.Assets = append(rel.Assets, a.Name+"|"+a.BrowserDownloadURL)
		}
		out = append(out, rel)
	}
	// 按 semver 从大到小排：API 的返回顺序不可靠，rels[0] 必须是最新版。
	sort.Slice(out, func(i, j int) bool {
		return CompareSemver(out[i].Tag, out[j].Tag) > 0
	})
	cacheKey := repo
	if includePre {
		cacheKey = repo + "#all"
	}
	relCacheMu.Lock()
	relCache[cacheKey] = struct {
		at time.Time
		rs []Release
	}{time.Now(), out}
	relCacheMu.Unlock()
	return out, nil
}

// releasesForVersion 按安装意图选版本列表：不指定版本（更新到最新版）
// 时只取正式版，绝不装上测试版；指定了具体版本（含测试版）时取全部
// 列表，让手动安装测试版能找到对应资产。
func releasesForVersion(repo, version string) ([]Release, error) {
	if version == "" {
		return ListReleases(repo)
	}
	return ListReleasesAll(repo)
}

func FindAsset(repo, version string) (assetName, url string, err error) {
	def, ok := DefByName(repoNameToCore(repo))
	if !ok {
		return "", "", fmt.Errorf("unknown repo %s", repo)
	}
	rels, err := releasesForVersion(repo, version)
	if err != nil {
		return "", "", err
	}
	sub := def.AssetSub(arch())
	for _, r := range rels {
		if version != "" && r.Tag != version && strings.TrimPrefix(r.Tag, "v") != strings.TrimPrefix(version, "v") {
			continue
		}
		for _, a := range r.Assets {
			parts := strings.SplitN(a, "|", 2)
			if len(parts) != 2 {
				continue
			}
			name := parts[0]
			if !strings.Contains(name, sub) {
				continue
			}
			// skip checksum/signature sidecars
			lower := strings.ToLower(name)
			if strings.Contains(lower, "sha256") || strings.Contains(lower, "checksum") || strings.HasSuffix(lower, ".sig") || strings.HasSuffix(lower, ".asc") {
				continue
			}
			// xray: prefer the exact zip (avoid .dgst etc.)
			if def.Name == "xray" && !strings.HasSuffix(lower, ".zip") {
				continue
			}
			if def.Name == "sing-box" && !strings.HasSuffix(lower, ".tar.gz") {
				continue
			}
			return name, parts[1], nil
		}
		if version != "" {
			break
		}
	}
	return "", "", fmt.Errorf("no asset for %s %s (%s)", repo, version, sub)
}

func repoNameToCore(repo string) string {
	repo = strings.TrimSpace(repo)
	for _, d := range Defs() {
		if strings.EqualFold(d.Repo, repo) {
			return d.Name
		}
	}
	return ""
}

// ---- install ----

type Manager struct {
	Dir string // data dir; cores live in Dir/cores
	mu  sync.Mutex
	// 安装进度：名字 -> downloading/installing。单独一把锁，
	// 绝不能复用 mu——Install 安装时全程占着 mu，进度查询要是也
	// 等 mu，就永远查不到进行中的阶段，前端按钮又会没反馈。
	progMu sync.Mutex
	prog   map[string]string
}

// PanelRepo：面板自己的 Forgejo 仓库（在线更新的来源）。
const PanelRepo = "SSSting/SSSing-box"

func (m *Manager) setProgress(name, phase string) {
	m.progMu.Lock()
	defer m.progMu.Unlock()
	if m.prog == nil {
		m.prog = map[string]string{}
	}
	m.prog[name] = phase
}

func (m *Manager) clearProgress(name string) {
	m.progMu.Lock()
	defer m.progMu.Unlock()
	delete(m.prog, name)
}

// Progress 返回一份当前安装进度的快照，供 /api/cores/progress 用。
func (m *Manager) Progress() map[string]string {
	m.progMu.Lock()
	defer m.progMu.Unlock()
	out := map[string]string{}
	for k, v := range m.prog {
		out[k] = v
	}
	return out
}

func NewManager(dir string) *Manager {
	os.MkdirAll(filepath.Join(dir, "cores"), 0755)
	return &Manager{Dir: dir}
}

func (m *Manager) BinPath(name string) string {
	// 名字只允许是单文件名：调用方万一传进带 / 或 .. 的名字，
	// Join 会直接跳出 cores 目录。Base 之后最多是同名文件，
	// 正常名（sing-box）不受影响。
	return filepath.Join(m.Dir, "cores", filepath.Base(name))
}

func (m *Manager) LogPath(name string) string {
	return filepath.Join(m.Dir, "cores", filepath.Base(name)+".log")
}

func (m *Manager) Installed(name string) bool {
	fi, err := os.Stat(m.BinPath(name))
	return err == nil && !fi.IsDir() && fi.Size() > 0
}

// smokeTest：新二进制必须能被系统执行且正常退出。错架构/损坏的下载在
// Start 阶段就报 exec format error；能启动但立即非零退出的坏二进制
// 也必须判失败（以前只看能不能 Start，退出码直接丢掉，坏包照样装上）。
func smokeTest(bin string, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

// Install downloads version ("" = latest) of a core and places the binary.
func (m *Manager) Install(name, version string) (string, error) {
	// 安装串行化：两个并发安装会共用 dest.new，互相覆盖。
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setProgress(name, "downloading")
	defer m.clearProgress(name)
	// arch() 把非 arm64 一律当 amd64：386/armv7 等机器会下错
	// 包、装完跑不起来。面板只发这两个架构，先拦住。
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return "", fmt.Errorf("不支持的架构 %s（只支持 amd64/arm64）", runtime.GOARCH)
	}
	def, ok := DefByName(name)
	if !ok {
		return "", fmt.Errorf("unknown core %s", name)
	}
	assetName, url, err := FindAsset(def.Repo, version)
	if err != nil {
		return "", err
	}
	// resolve version tag from releases（与 FindAsset 同一份列表：
	// 指定测试版时也要在含测试版的列表里找，否则 tag 落空）。
	rels, _ := releasesForVersion(def.Repo, version)
	tag := ""
	for _, r := range rels {
		for _, a := range r.Assets {
			if strings.HasPrefix(a, assetName+"|") {
				tag = r.Tag
				break
			}
		}
		if tag != "" {
			break
		}
	}
	if tag == "" {
		tag = version
	}
	tmp, err := os.CreateTemp("", "sssingbox-core-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		tmp.Close()
		return "", err
	}
	req.Header.Set("User-Agent", "sssingbox-panel")
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		tmp.Close()
		return "", err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		tmp.Close()
		return "", fmt.Errorf("download %d", resp.StatusCode)
	}
	// 下载封顶 512MB：失控的重定向/错误页面不能把磁盘打满。
	const maxDownload = 512 * 1024 * 1024
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxDownload+1))
	resp.Body.Close()
	tmp.Close()
	if err != nil {
		return "", err
	}
	if n > maxDownload {
		return "", fmt.Errorf("下载超过 512MB 上限，疑似异常响应")
	}
	// 下载完、解压写入开始：前端按钮从“下载中”翻成“安装中”。
	m.setProgress(name, "installing")

	lower := strings.ToLower(assetName)
	var binData []byte
	switch {
	case strings.HasSuffix(lower, ".zip"):
		binData, err = extractZip(tmpName, def.BinName)
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		binData, err = extractTarGz(tmpName, def.BinName)
	default:
		binData, err = os.ReadFile(tmpName)
	}
	if err != nil {
		return "", fmt.Errorf("extract %s: %w", assetName, err)
	}
	if len(binData) == 0 {
		return "", fmt.Errorf("empty binary in %s", assetName)
	}
	dest := m.BinPath(name)
	// 先写 .new 再冒烟，过了才重命名到位：冒烟失败时旧文件原样不动，
	// 不用 .prev 备份、不留残留。以前是先备份旧版再替换，备份写失败
	// 时冒烟一挂就直接删掉原来能跑的内核。
	defer os.Remove(dest + ".new")
	if err := os.WriteFile(dest+".new", binData, 0755); err != nil {
		return "", err
	}
	probe := []string{"--help"}
	if name == "sing-box" {
		probe = []string{"version"}
	}
	if err := smokeTest(dest+".new", probe); err != nil {
		return "", fmt.Errorf("新二进制冒烟失败：%w", err)
	}
	// sing-box 再核对版本号：上游 Release 不带任何校验文件（2026-11-11
	// 实测 168 个资产里零 sha256/sig，哈希校验做不了），退而求其次，
	// 要求新二进制自报的版本必须等于要装的 tag，错版/被换过的包在这里
	// 拦住。下载走 HTTPS，传输层本身有 TLS 完整性保护。
	if name == "sing-box" && tag != "" {
		if v := DetectSingBoxVersion(dest + ".new"); v != strings.TrimPrefix(tag, "v") {
			return "", fmt.Errorf("新二进制版本不符：要装 %s，自报 %s", tag, v)
		}
	}
	if err := os.Rename(dest+".new", dest); err != nil {
		return "", err
	}
	// xray: also extract geoip.dat/geosite.dat (best-effort) so the
	// geoip:private routing rule can work; failure here is non-fatal.
	if name == "xray" && strings.HasSuffix(lower, ".zip") {
		m.extractGeoFiles(tmpName)
	}
	return tag, nil
}

// extractGeoFiles pulls geoip.dat / geosite.dat out of an xray zip into cores/.
func (m *Manager) extractGeoFiles(zipPath string) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return
	}
	defer r.Close()
	for _, f := range r.File {
		base := filepath.Base(f.Name)
		if base != "geoip.dat" && base != "geosite.dat" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, 64*1024*1024+1))
		rc.Close()
		if err != nil || len(data) == 0 || len(data) > 64*1024*1024 {
			continue
		}
		_ = os.WriteFile(filepath.Join(m.Dir, "cores", base), data, 0644)
	}
}

// maxExtractBytes：解压单个文件的上限（与下载上限一致）。zip 炸弹
// 解压后体积远超压缩包，不设上限会把面板进程内存撑爆。
const maxExtractBytes = 512 * 1024 * 1024

func extractZip(path, binName string) ([]byte, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	for _, f := range r.File {
		base := filepath.Base(f.Name)
		if base == binName {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			data, err := io.ReadAll(io.LimitReader(rc, maxExtractBytes+1))
			if err != nil {
				return nil, err
			}
			if len(data) > maxExtractBytes {
				return nil, fmt.Errorf("解压后文件超过 512MB 上限")
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("binary %s not in zip", binName)
}

func extractTarGz(path, binName string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if filepath.Base(hdr.Name) == binName && hdr.Typeflag == tar.TypeReg {
			if hdr.Size > maxExtractBytes {
				return nil, fmt.Errorf("解压后文件超过 512MB 上限")
			}
			data, err := io.ReadAll(io.LimitReader(tr, maxExtractBytes+1))
			if err != nil {
				return nil, err
			}
			if len(data) > maxExtractBytes {
				return nil, fmt.Errorf("解压后文件超过 512MB 上限")
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("binary %s not in tarball", binName)
}
