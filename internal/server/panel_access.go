package server

// ---------- 面板访问：根路径防扫 + 端口 + 域名 ----------
// 根路径（3x-ui 式）：面板只活在 /<随机路径>/ 下面，裸 IP:端口扫不到面板。
// 新装默认随机 5 位小写英文（初始设置时生成）；老面板升级后路径为空，
// 仍走根目录（不锁死老用户），去设置页设一个立即生效，不用重启。
// 订阅链接（/sub/<token>）不进路径门：token 本身就是密钥。
// 本机回环（SSH 菜单、安装器）不进路径门：能登本机的人已经有 root。

import (
	crand "crypto/rand"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// ---------- 面板改端口：服务文件按实际服务管理类型找 ----------
// 2026-11-03 v1.0.1 修：以前这里写死 systemd 单元路径，OpenRC / procd /
// sysvinit 上根本没有那个文件，改端口却回“已保存、待手动重启”，实际
// 什么都没写（服务文件、进程、监听端口全是旧的），手动重启也没用。
// 现在按安装脚本同一套探测逻辑（systemd → OpenRC → procd → sysvinit →
// 无服务管理）找服务文件、按对应文件格式改端口、用对应方式重启；
// 找不到服务文件时直接报错并给出手动重启命令，不再谎称已写入。

type initKind string

const (
	initSystemd  initKind = "systemd"
	initOpenRC   initKind = "openrc"
	initProcd    initKind = "procd"
	initSysvinit initKind = "sysvinit"
	initNone     initKind = "none"
)

// testInitKind / testServiceFile：单测覆盖用，生产恒为空（走真实探测）。
var testInitKind initKind
var testServiceFile string

func panelInitKind() initKind {
	if testInitKind != "" {
		return testInitKind
	}
	return detectPanelInit()
}

// detectInputs：探测的全部输入（纯数据，单测可任意构造）。
type detectInputs struct {
	p1                                       string
	hasSysdDir, hasOpenwrt, hasInitd, hasRcd bool
	lookPath                                 func(string) (string, error)
}

func detectPanelInit() initKind {
	p1 := ""
	if b, err := os.ReadFile("/proc/1/comm"); err == nil {
		p1 = strings.TrimSpace(string(b))
	}
	_, sysdDirErr := os.Stat("/run/systemd/system")
	_, openwrtErr := os.Stat("/etc/openwrt_release")
	_, initdErr := os.Stat("/etc/init.d")
	_, rcdErr := os.Stat("/etc/rc.d")
	return detectPanelInitFrom(detectInputs{
		p1:         p1,
		hasSysdDir: sysdDirErr == nil,
		hasOpenwrt: openwrtErr == nil,
		hasInitd:   initdErr == nil,
		hasRcd:     rcdErr == nil,
		lookPath:   exec.LookPath,
	})
}

// detectPanelInitFrom：纯函数，单测全覆盖（与 install.sh detect_init 同逻辑）。
func detectPanelInitFrom(in detectInputs) initKind {
	if in.p1 == "systemd" && in.hasSysdDir {
		if _, err := in.lookPath("systemctl"); err == nil {
			return initSystemd
		}
	}
	if _, err := in.lookPath("rc-update"); err == nil {
		if _, err := in.lookPath("rc-service"); err == nil {
			return initOpenRC
		}
	}
	if in.hasOpenwrt {
		return initProcd
	}
	if _, err := in.lookPath("procd"); err == nil {
		return initProcd
	}
	if (in.p1 == "init" || in.p1 == "") && in.hasInitd {
		if _, err := in.lookPath("update-rc.d"); err == nil {
			return initSysvinit
		}
		if _, err := in.lookPath("chkconfig"); err == nil {
			return initSysvinit
		}
		if in.hasRcd {
			return initSysvinit
		}
	}
	return initNone
}

// panelServiceFile：当前服务管理对应的服务文件，无服务管理时为空。
func panelServiceFile() string {
	if testServiceFile != "" {
		return testServiceFile
	}
	switch panelInitKind() {
	case initSystemd:
		return "/etc/systemd/system/sssingbox.service"
	case initOpenRC, initProcd, initSysvinit:
		return "/etc/init.d/sssingbox"
	default:
		return ""
	}
}

// restartPanelCommand：对应服务管理的重启命令，无服务管理时为 nil。
// systemd 必须加 --no-block：不加的话 systemctl restart 会等到重启完成
// 才返回，但重启会停掉面板自己的 cgroup，连这个 systemctl 客户端一起
// 杀掉，命令死于 signal: terminated，日志谎称“重启失败”（教训）。
// --no-block 只把重启任务入队就返回，客户端在停服务前就退出了；重启
// 是否真的成功由前端轮询版本号确认，不靠这条命令的退出码。
func restartPanelCommand(kind initKind) []string {
	switch kind {
	case initSystemd:
		return []string{"systemctl", "--no-block", "restart", "sssingbox"}
	case initOpenRC:
		return []string{"rc-service", "sssingbox", "restart"}
	case initProcd, initSysvinit:
		return []string{"/etc/init.d/sssingbox", "restart"}
	default:
		return nil
	}
}

// manualRestartCmd：无服务文件时给用户的手动重启命令（带数据目录与新端口）。
func manualRestartCmd(dataDir, binPath string, newPort int) string {
	if binPath == "" {
		binPath = "sssingbox"
	}
	if dataDir == "" {
		dataDir = "/var/lib/sssingbox"
	}
	return binPath + " -data " + dataDir + " -port " + strconv.Itoa(newPort)
}

// clientIPOf：只认 RemoteAddr，不认 X-Forwarded-For（那是能伪造的）。
func clientIPOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isLoopbackIP(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.IsLoopback()
}

// panelPath：当前根路径（去头尾斜杠），空 = 根目录模式。
func (s *Server) panelPath() string {
	return strings.Trim(s.app.Store.GetSetting("panel_path"), "/")
}

// panelDisabled：面板访问是否已关闭（默认开启）。关闭后只挡外网请求，
// 订阅（/sub/）与本机回环（SSH 菜单、安装器）不受影响，代理照常跑。
// 开关立即生效，不用重启；本机回环永远能进，SSH 菜单随时能再打开。
func (s *Server) panelDisabled() bool {
	return s.app.Store.GetSetting("panel_disabled") == "1"
}

// panelBase：前端拼地址用的前缀，"" 或 "/abc12"。
func (s *Server) panelBase() string {
	if p := s.panelPath(); p != "" {
		return "/" + p
	}
	return ""
}

// panelPathGate：包在整棵路由外面。它改 r.URL.Path 再交给内层 mux，
// 内层按改写后的路径重新匹配，所以 /api、静态文件都不用改。
func (s *Server) panelPathGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sub/") {
			next.ServeHTTP(w, r)
			return
		}
		if isLoopbackIP(clientIPOf(r)) {
			// 回环同样要剥前缀：否则本机用带路径地址打开时，
			// 内层路由拿着 /<路径>/api/... 找不到文件（实测抓到的 bug）。
			if p := s.panelPath(); p != "" {
				prefix := "/" + p
				if r.URL.Path == prefix {
					r.URL.Path = "/"
				} else if strings.HasPrefix(r.URL.Path, prefix+"/") {
					r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
				}
			}
			next.ServeHTTP(w, r)
			return
		}
		// 面板访问已关闭：只挡外网，订阅与本机回环已在上面放行。
		if s.panelDisabled() {
			http.Error(w, "面板访问已关闭", http.StatusForbidden)
			return
		}
		p := s.panelPath()
		if p == "" {
			next.ServeHTTP(w, r)
			return
		}
		prefix := "/" + p
		if r.URL.Path == prefix {
			r.URL.Path = "/"
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, prefix+"/") {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
			next.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

func randPanelPath() string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 5)
	_, _ = crand.Read(b)
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

func validPanelPath(p string) bool {
	if p == "" {
		return true
	}
	if len(p) > 32 || p == "sub" || p == "api" {
		return false
	}
	for _, c := range p {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

var servicePortQuotedRe = regexp.MustCompile(`-port\s*=?\s*["']\d+["']`)
var servicePortRe = regexp.MustCompile(`-port\s*=?\s*\d+`)

// rewriteServicePort：改服务文件里的面板端口。只动真正起面板的那几行
// （ExecStart / command_args / procd_set_param command / ARGS=），注释行
// 不动；-port 后数字可带 =、可带引号（procd 的 -port "18081"、OpenRC
// command_args 引号里的 -port 18081 都覆盖），统一改成 -port <新>。
// 注意引号要成对处理：带引号的数字（-port "18081"）连引号一起换，
// 不带引号的数字（-port 18081）绝不吞掉后面的引号（那是外层
// command_args="..." 的收引号，吞了脚本就破了）——所以先换带引号的，
// 再换不带引号的，后一遍对前一遍的结果是幂等的。
func rewriteServicePort(content string, newPort int) (string, error) {
	lines := strings.Split(content, "\n")
	changed := false
	for i, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.Contains(ln, "ExecStart") && !strings.Contains(ln, "command_args") && !strings.Contains(ln, "procd_set_param") && !strings.Contains(ln, "ARGS=") {
			continue
		}
		if servicePortQuotedRe.MatchString(ln) || servicePortRe.MatchString(ln) {
			ln = servicePortQuotedRe.ReplaceAllString(ln, "-port "+strconv.Itoa(newPort))
			ln = servicePortRe.ReplaceAllString(ln, "-port "+strconv.Itoa(newPort))
			lines[i] = ln
			changed = true
		}
	}
	if !changed {
		return "", fmt.Errorf("服务文件里没有 -port 参数")
	}
	return strings.Join(lines, "\n"), nil
}

func firewallAllowPort(port int) {
	if _, err := exec.LookPath("ufw"); err == nil {
		_ = exec.Command("ufw", "allow", strconv.Itoa(port)+"/tcp").Run()
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		_ = exec.Command("firewall-cmd", "--permanent", "--add-port="+strconv.Itoa(port)+"/tcp").Run()
		_ = exec.Command("firewall-cmd", "--reload").Run()
	}
}

// portTaken：新端口能不能绑（面板自己占的当前端口不在此列，因为测的是新端口）。
func portTaken(port int) bool {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}
