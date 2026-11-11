package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"sssingbox/internal/cores"
	"sssingbox/internal/version"
)

// ---------- 面板在线更新 ----------
// 仿龟甲方式：自动检查、手动更新。
// 检查：面板启动后后台每 12 小时查一次 Forgejo Release，最新版和检查时间
//   存进 settings；打开面板设置时也会查一次。更新永远是用户手动点，
//   绝不自动装。
// 更新：下载对应架构的 Release 包 → 校验 sha256 → 解包 → 冒烟测新二进制
//   的 version → 备份旧二进制 → 原子替换 → 按服务管理重启。重启只在
//   标准安装路径（/usr/local/bin/sssingbox）且有服务管理时自动做：
//   演示面板、无服务管理的进程不自动重启，免得误重启生产服务，返回
//   restart_required 让用户手动重启。

// updateRestartRequired：更新后要不要用户手动重启。两个条件任一成立
// 就要手动重启：① 二进制不在标准路径（演示/手动起的面板，重启服务会
// 误重启同一台机上的生产服务）；② 无服务管理（容器/手动启动，根本
// 没有服务可重启）。v1.0.1 之前只看①，标准路径的 OpenRC 面板也被当
// 成“能自动重启”，结果重启命令还是写死的 systemctl，静默失败。
func updateRestartRequired(exe string, kind initKind) bool {
	return exe != "/usr/local/bin/sssingbox" || kind == initNone
}

func (s *Server) setUpdPhase(p string) {
	s.updMu.Lock()
	s.updPhase = p
	s.updMu.Unlock()
}

func (s *Server) getUpdPhase() string {
	s.updMu.Lock()
	defer s.updMu.Unlock()
	return s.updPhase
}

func (s *Server) startPanelUpdateChecker() {
	go func() {
		time.Sleep(5 * time.Minute)
		for {
			_, _ = s.checkPanelUpdate(false)
			time.Sleep(12 * time.Hour)
		}
	}()
}

func normTag(t string) string { return strings.TrimPrefix(t, "v") }

// checkPanelUpdate 查面板最新版，存进 settings，返回最新 tag。
// force=true 时不读 1 小时缓存（手动点“检查更新”必须强制刷新，
// 否则面板启动后一小时内发的新版永远查不到）；自动检查走缓存，
// 免得每次打开设置页都打 GitHub API。
func (s *Server) checkPanelUpdate(force bool) (string, error) {
	list := cores.ListReleases
	if force {
		list = cores.ListReleasesFresh
	}
	rels, err := list(cores.PanelRepo)
	if err != nil {
		return "", err
	}
	if len(rels) == 0 {
		return "", fmt.Errorf("没有找到 Release")
	}
	// rels 已由 cores 按 semver 从大到小排好且过滤了草稿/预发布版，
	// rels[0] 就是真正的最新正式版（以前直接取首条，API 顺序一乱
	// 就会把旧版/预发布版当最新版）。
	latest := rels[0].Tag
	if latest == "" {
		return "", fmt.Errorf("最新 Release 没有 tag")
	}
	_ = s.app.Store.SetSetting("panel_latest", latest)
	_ = s.app.Store.SetSetting("panel_latest_at", time.Now().Format("2006-01-02 15:04"))
	return latest, nil
}

func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	// 手动点“检查更新”带 force=true，强制刷新；打开设置页的自动检查不带，
	// 走 1 小时缓存。请求体解析失败时按不强制处理，别让旧前端报错。
	var body struct {
		Force bool `json:"force"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	latest, err := s.checkPanelUpdate(body.Force)
	if err != nil {
		// 查不到就回落到上次存的值，别直接报错让设置页空着。
		latest = s.app.Store.GetSetting("panel_latest")
		if latest == "" {
			errJSON(w, 500, "检查失败："+err.Error())
			return
		}
	}
	current := version.Version
	// 真正的 semver 比较：最新版大于当前版才叫有更新。以前是纯不等比较，
	// 当前版比 Release 列表还新时也会提示“更新”并真把面板降级。
	hasUpdate := current != "dev" && latest != "" && cores.CompareSemver(latest, current) > 0
	okJSON(w, map[string]interface{}{
		"current":    current,
		"latest":     latest,
		"has_update": hasUpdate,
		"checked_at": s.app.Store.GetSetting("panel_latest_at"),
	})
}

func (s *Server) handleUpdateProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	okJSON(w, map[string]interface{}{"phase": s.getUpdPhase()})
}

func (s *Server) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	// 并发守卫：更新是长流程（下载+替换+重启），进行中再点直接拒绝，
	// 不许两个更新流程撞在一起（以前只靠 writeMu 串行，第二次仍会
	// 判定“不是最新”而重新下载替换，正撞上第一次的重启窗口）。
	if !atomic.CompareAndSwapInt32(&s.updRunning, 0, 1) {
		errJSON(w, 409, "已有更新在进行中，请稍后再试")
		return
	}
	defer atomic.StoreInt32(&s.updRunning, 0)
	current := version.Version
	if current == "dev" {
		errJSON(w, 400, "开发版不走在线更新，请用安装器重装")
		return
	}
	// 更新必须装真正的最新版，不能吃缓存。
	latest, err := s.checkPanelUpdate(true)
	if err != nil {
		errJSON(w, 500, "检查最新版失败："+err.Error())
		return
	}
	// semver 比较：最新版不大于当前版就不更新，绝不降级。
	if cores.CompareSemver(latest, current) <= 0 {
		errJSON(w, 400, "已是最新版")
		return
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		errJSON(w, 400, fmt.Sprintf("不支持的架构 %s（只支持 amd64/arm64）", runtime.GOARCH))
		return
	}
	asset := "sssingbox-linux-" + runtime.GOARCH + ".tar.gz"
	rels, err := cores.ListReleasesFresh(cores.PanelRepo)
	if err != nil {
		errJSON(w, 500, "获取 Release 失败："+err.Error())
		return
	}
	var assetURL, shaURL string
	for _, rel := range rels {
		if rel.Tag != latest {
			continue
		}
		for _, a := range rel.Assets {
			parts := strings.SplitN(a, "|", 2)
			if len(parts) != 2 {
				continue
			}
			if parts[0] == asset {
				assetURL = parts[1]
			}
			if parts[0] == asset+".sha256" {
				shaURL = parts[1]
			}
		}
		break
	}
	if assetURL == "" {
		errJSON(w, 500, "最新 Release 里没有 "+asset)
		return
	}
	s.setUpdPhase("downloading")
	defer s.setUpdPhase("")
	dl := func(url string, limit int64) ([]byte, error) {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "sssingbox-panel")
		resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("download %d", resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return nil, err
		}
		// 超限必须报错，不许静默截断：截断的包只有 sha256 能兜底，
		// 而 sha256 一旦缺失就等于零校验装了个半截包。
		if int64(len(data)) > limit {
			return nil, fmt.Errorf("下载超过 %d 字节上限，疑似异常响应", limit)
		}
		return data, nil
	}
	pkg, err := dl(assetURL, 512*1024*1024)
	if err != nil {
		errJSON(w, 500, "下载失败："+err.Error())
		return
	}
	// sha256 校验是强制的：Release 里没有校验文件就直接中止，绝不跳过。
	// 以前是“有文件才验”，一次漏发 .sha256 就会让所有更新零校验装机。
	if shaURL == "" {
		errJSON(w, 500, "最新 Release 里没有 sha256 校验文件，已放弃更新")
		return
	}
	shaB, err := dl(shaURL, 64*1024)
	if err != nil {
		errJSON(w, 500, "下载校验文件失败："+err.Error())
		return
	}
	want := strings.Fields(string(shaB))
	if len(want) == 0 {
		errJSON(w, 500, "校验文件为空")
		return
	}
	sum := sha256.Sum256(pkg)
	if hex.EncodeToString(sum[:]) != strings.ToLower(want[0]) {
		errJSON(w, 500, "sha256 校验失败，包可能损坏，已放弃更新")
		return
	}
	s.setUpdPhase("installing")
	// 解包：tar 里只有一个 sssingbox 二进制。
	newBin, err := extractPanelBinary(pkg)
	if err != nil {
		errJSON(w, 500, "解包失败："+err.Error())
		return
	}
	defer os.Remove(newBin)
	// 冒烟：新二进制必须能跑且报的就是最新版，否则不替换。
	// 带 10 秒超时（挂起的新二进制不能一直占着写锁）；版本比对用精确
	// 相等不用子串包含（子串会误匹配更长版本号的输出）。
	smokeCtx, smokeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer smokeCancel()
	out, err := exec.CommandContext(smokeCtx, newBin, "version").Output()
	if err != nil {
		errJSON(w, 500, fmt.Sprintf("新二进制冒烟失败（已放弃更新）：%v", err))
		return
	}
	gotVer := ""
	if f := strings.Fields(strings.TrimSpace(string(out))); len(f) >= 2 {
		gotVer = normTag(f[1])
	}
	if gotVer != normTag(latest) {
		errJSON(w, 500, fmt.Sprintf("新二进制版本不符（已放弃更新）：要 %s，自报 %s", latest, strings.TrimSpace(string(out))))
		return
	}
	exe, err := os.Executable()
	if err != nil {
		errJSON(w, 500, "取当前二进制路径失败："+err.Error())
		return
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	oldData, err := os.ReadFile(exe)
	if err != nil {
		errJSON(w, 500, "读旧二进制失败："+err.Error())
		return
	}
	// 回滚备份只用一个固定名文件（rollback.go）：每次更新覆盖它，
	// 成功启动后新二进制会删掉它，稳态零备份。以前是带时间戳的
	// .bak-<时间戳>，每更一次磁盘上就多一个 20MB 文件。
	bak := panelBackupPath(exe)
	if err := os.WriteFile(bak, oldData, 0755); err != nil {
		errJSON(w, 500, "备份旧二进制失败："+err.Error())
		return
	}
	// 顺手清掉以前攒下的带时间戳旧备份。
	CleanupStaleBackups(exe)
	newData, err := os.ReadFile(newBin)
	if err != nil {
		errJSON(w, 500, "读新二进制失败："+err.Error())
		return
	}
	// .new 残留统一清掉：重命名成功后它已不存在，失败时 defer 负责收尾。
	defer os.Remove(exe + ".new")
	if err := os.WriteFile(exe+".new", newData, 0755); err != nil {
		errJSON(w, 500, "写新二进制失败："+err.Error())
		return
	}
	if err := os.Rename(exe+".new", exe); err != nil {
		errJSON(w, 500, "替换二进制失败："+err.Error())
		return
	}
	// 自动重启只在标准路径 + 有服务管理时做；演示面板（非标准路径）
	// 与手动启动（无服务管理）不自动重启，免得误重启生产服务。
	// 重启按探测到的服务管理来（v1.0.2 修：以前写死 systemctl，OpenRC
	// 上静默失败，面板永不重启，前端还谎称更新完成）；重启失败记日志，
	// 不再静默丢掉（响应已发出，日志是唯一记录；前端还会比对版本号，
	// 版本没变就报失败，不会再谎称完成）。
	kind := panelInitKind()
	restartRequired := updateRestartRequired(exe, kind)
	if !restartRequired {
		s.setUpdPhase("restarting")
		if cmd := restartPanelCommand(kind); cmd != nil {
			go func() {
				time.Sleep(time.Second)
				if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
					// 重启命令被信号杀掉是预期的，不是失败：systemd 停服务
					// 时会杀掉服务进程组里的这个子进程（--no-block 也一样，
					// 停服务的动作比客户端退出快），重启本身正在进行。
					// 只有非信号退出（命令不存在、非零退出码）才算真失败。
					var exitErr *exec.ExitError
					if errors.As(err, &exitErr) {
						if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
							log.Printf("面板正在重启（更新后重启命令随服务停止而退出）")
							return
						}
					}
					log.Printf("面板更新后重启失败（%s）：%v，请手动重启面板服务", strings.Join(cmd, " "), err)
				}
			}()
		} else {
			// 防御：服务管理类型与重启命令对不上时，不谎称已重启。
			restartRequired = true
		}
	}
	okJSON(w, map[string]interface{}{"version": latest, "restart_required": restartRequired, "backup": bak})
}

func extractPanelBinary(pkg []byte) (string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(pkg))
	if err != nil {
		return "", err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if filepath.Base(hdr.Name) != "sssingbox" || hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, 512*1024*1024+1))
		if err != nil {
			return "", err
		}
		if len(data) == 0 {
			return "", fmt.Errorf("包里的二进制为空")
		}
		tmp, err := os.CreateTemp("", "sssingbox-update-*")
		if err != nil {
			return "", err
		}
		tmpName := tmp.Name()
		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return "", err
		}
		tmp.Close()
		_ = os.Chmod(tmpName, 0755)
		return tmpName, nil
	}
	return "", fmt.Errorf("包里没有 sssingbox 二进制")
}
