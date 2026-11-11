package server

// v1.2.0：2FA（TOTP + 恢复码 + 新 IP 验证）与面板访问（根路径/端口/域名）。

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTOTP_RFC6238Vectors(t *testing.T) {
	// RFC 6238 附录 B 的 SHA1 向量：密钥 ASCII "12345678901234567890"，
	// base32 为 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ；8 位码取后 6 位。
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
	}
	for _, c := range cases {
		got, err := totpCodeAt(secret, time.Unix(c.unix, 0))
		if err != nil || got != c.want {
			t.Fatalf("t=%d 应得 %s，得到 %s（err %v）", c.unix, c.want, got, err)
		}
	}
}

func TestTOTP_VerifyWindow(t *testing.T) {
	secret := randTOTPSecret()
	now := time.Now()
	code, _ := totpCodeAt(secret, now)
	if !verifyTOTP(secret, code, now) {
		t.Fatal("当前步的码应能通过")
	}
	if !verifyTOTP(secret, code, now.Add(30*time.Second)) {
		t.Fatal("前后一步容忍：下一秒步应能通过")
	}
	if verifyTOTP(secret, code, now.Add(90*time.Second)) {
		t.Fatal("三步之外应拒绝")
	}
	if verifyTOTP(secret, "000000", now) && code != "000000" {
		t.Fatal("错码应拒绝")
	}
}

func TestTOTP_RecoverySingleUse(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	codes := genRecoveryCodes()
	if len(codes) != 10 {
		t.Fatalf("恢复码应为 10 个，得到 %d", len(codes))
	}
	_ = s.app.Store.SetSetting("totp_recovery", hashRecoveryCodes(codes))
	if !s.tryRecoveryCode(codes[3]) {
		t.Fatal("未用过的恢复码应命中")
	}
	if s.tryRecoveryCode(codes[3]) {
		t.Fatal("用过的恢复码再次用应拒绝（一次性）")
	}
	if s.recoveryLeft() != 9 {
		t.Fatalf("用掉 1 个后应剩 9 个，得到 %d", s.recoveryLeft())
	}
}

func TestPanelPath_Validation(t *testing.T) {
	ok := []string{"", "abc12", "a", "Ab3-x_9", strings.Repeat("a", 32)}
	for _, p := range ok {
		if !validPanelPath(p) {
			t.Fatalf("路径 %q 应合法", p)
		}
	}
	bad := []string{"sub", "api", "a/b", "a b", "中文", strings.Repeat("a", 33)}
	for _, p := range bad {
		if validPanelPath(p) {
			t.Fatalf("路径 %q 应拒绝", p)
		}
	}
}

func TestPanelPath_Random(t *testing.T) {
	for i := 0; i < 20; i++ {
		p := randPanelPath()
		if len(p) != 5 || !validPanelPath(p) {
			t.Fatalf("随机路径应为 5 位合法英文，得到 %q", p)
		}
		for _, c := range p {
			if c < 'a' || c > 'z' {
				t.Fatalf("随机路径只用小写英文，得到 %q", p)
			}
		}
	}
}

func TestPanelPath_Gate(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok:" + r.URL.Path)) })
	gate := s.panelPathGate(next)
	get := func(path, remote string) (int, string) {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	// 根目录模式：全部放行。
	if code, body := get("/api/me", "203.0.113.9:1234"); code != 200 || body != "ok:/api/me" {
		t.Fatalf("根目录模式应放行，得到 %d %q", code, body)
	}
	_ = s.app.Store.SetSetting("panel_path", "abc12")
	// 带正确前缀：剥掉前缀进内层。
	if code, body := get("/abc12/api/me", "203.0.113.9:1234"); code != 200 || body != "ok:/api/me" {
		t.Fatalf("正确前缀应剥掉放行，得到 %d %q", code, body)
	}
	if code, body := get("/abc12", "203.0.113.9:1234"); code != 200 || body != "ok:/" {
		t.Fatalf("裸前缀应回到首页，得到 %d %q", code, body)
	}
	// 裸地址与错前缀：一律 404，不露面板指纹。
	if code, _ := get("/", "203.0.113.9:1234"); code != 404 {
		t.Fatalf("裸根路径应 404，得到 %d", code)
	}
	if code, _ := get("/api/me", "203.0.113.9:1234"); code != 404 {
		t.Fatalf("无前缀的 API 应 404，得到 %d", code)
	}
	// 订阅链接不进路径门（token 本身就是密钥）。
	if code, _ := get("/sub/anything", "203.0.113.9:1234"); code != 200 {
		t.Fatalf("订阅链接应绕过路径门，得到 %d", code)
	}
	// 本机回环不进路径门（SSH 菜单、安装器），但带了前缀也要剥掉，
	// 否则内层路由拿着 /<路径>/api/... 找不到文件。
	if code, _ := get("/api/me", "127.0.0.1:1234"); code != 200 {
		t.Fatalf("回环应绕过路径门，得到 %d", code)
	}
	if code, body := get("/abc12/api/me", "127.0.0.1:1234"); code != 200 || body != "ok:/api/me" {
		t.Fatalf("回环带前缀也应剥掉放行，得到 %d %q", code, body)
	}
}

func TestPanelAccess_DisableGate(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok:" + r.URL.Path)) })
	gate := s.panelPathGate(next)
	get := func(path, remote string) (int, string) {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	// 默认开启：外网放行。
	if s.panelDisabled() {
		t.Fatal("默认应为开启")
	}
	if code, _ := get("/api/me", "203.0.113.9:1234"); code != 200 {
		t.Fatalf("默认开启时外网应放行，得到 %d", code)
	}
	// 关闭后：外网 403，本机回环与订阅不受影响。
	_ = s.app.Store.SetSetting("panel_disabled", "1")
	if !s.panelDisabled() {
		t.Fatal("置 1 后应为关闭")
	}
	if code, _ := get("/api/me", "203.0.113.9:1234"); code != 403 {
		t.Fatalf("关闭后外网应 403，得到 %d", code)
	}
	if code, _ := get("/", "203.0.113.9:1234"); code != 403 {
		t.Fatalf("关闭后外网首页应 403，得到 %d", code)
	}
	if code, _ := get("/api/me", "127.0.0.1:1234"); code != 200 {
		t.Fatalf("关闭后回环应放行，得到 %d", code)
	}
	if code, _ := get("/sub/anything", "203.0.113.9:1234"); code != 200 {
		t.Fatalf("关闭后订阅应放行，得到 %d", code)
	}
	// 再打开：外网恢复。
	_ = s.app.Store.SetSetting("panel_disabled", "0")
	if s.panelDisabled() {
		t.Fatal("置 0 后应为开启")
	}
	if code, _ := get("/api/me", "203.0.113.9:1234"); code != 200 {
		t.Fatalf("再打开后外网应放行，得到 %d", code)
	}
}

func TestPanelAccess_ToggleAPI(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	call := func(body string) (bool, string, map[string]interface{}) {
		rec := postJSON(t, s, s.handleSettingsAction, "/api/settings/panel-enabled", body, nil)
		var out struct {
			OK   bool                   `json:"ok"`
			Err  string                 `json:"error"`
			Data map[string]interface{} `json:"data"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
			t.Fatalf("解响应失败：%v", err)
		}
		return out.OK, out.Err, out.Data
	}
	// 关闭。
	ok, errMsg, data := call(`{"enabled":false}`)
	if !ok {
		t.Fatalf("关闭应成功，得到错误：%s", errMsg)
	}
	if data["panel_disabled"] != true {
		t.Fatalf("关闭后应返回 panel_disabled=true，得到 %v", data)
	}
	if !s.panelDisabled() {
		t.Fatal("关闭后 panelDisabled 应为真")
	}
	// 打开。
	ok, errMsg, data = call(`{"enabled":true}`)
	if !ok {
		t.Fatalf("打开应成功，得到错误：%s", errMsg)
	}
	if data["panel_disabled"] != false {
		t.Fatalf("打开后应返回 panel_disabled=false，得到 %v", data)
	}
	if s.panelDisabled() {
		t.Fatal("打开后 panelDisabled 应为假")
	}
}

func TestPanelAccess_RewriteServicePort(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string // 改后必须含有的片段（空=应报错）
	}{
		{"systemd ExecStart", "[Service]\nExecStart=/usr/local/bin/sssingbox -port 18081 -data /var/lib/sssingbox\n", "-port 19090"},
		{"systemd -port= 形式", "[Service]\nExecStart=/usr/local/bin/sssingbox -port=18081\n", "-port 19090"},
		{"OpenRC command_args（外层引号不能被吞）", "#!/sbin/openrc-run\ncommand=\"/usr/local/bin/sssingbox\"\ncommand_args=\"-data /var/lib/sssingbox -port 18081\"\n", "command_args=\"-data /var/lib/sssingbox -port 19090\""},
		{"procd 带引号数字", "procd_set_param command \"/usr/local/bin/sssingbox\" -data \"/var/lib/sssingbox\" -port \"18081\"\n", "-port 19090"},
		{"sysvinit ARGS=", "ARGS=\"-data /var/lib/sssingbox -port 18081\"\n", "ARGS=\"-data /var/lib/sssingbox -port 19090\""},
	}
	for _, c := range cases {
		got, err := rewriteServicePort(c.src, 19090)
		if err != nil {
			t.Fatalf("%s：应成功，得到错误 %v", c.name, err)
		}
		if !strings.Contains(got, c.want) || strings.Contains(got, "18081") {
			t.Fatalf("%s：应含 %q 且不含旧端口，得到 %q", c.name, c.want, got)
		}
	}
	// 注释行里的 -port 不动。
	got, err := rewriteServicePort("# 旧端口 -port 18081\nExecStart=/usr/local/bin/sssingbox -port 18081\n", 19090)
	if err != nil || !strings.Contains(got, "# 旧端口 -port 18081") || !strings.Contains(got, "-port 19090") {
		t.Fatalf("注释行应原样保留，得到 %q（err %v）", got, err)
	}
	// 非起面板的行（不含那几个标记）里的 -port 不动，应报错。
	if _, err := rewriteServicePort("foo -port 18081\n", 19090); err == nil {
		t.Fatal("非服务行里的 -port 不应被改，应报错")
	}
	if _, err := rewriteServicePort("[Service]\nExecStart=/bin/foo\n", 19090); err == nil {
		t.Fatal("没有 -port 参数应报错")
	}
}

func TestDetectPanelInitFrom(t *testing.T) {
	lookPathStub := func(found ...string) func(string) (string, error) {
		set := map[string]bool{}
		for _, f := range found {
			set[f] = true
		}
		return func(name string) (string, error) {
			if set[name] {
				return "/usr/bin/" + name, nil
			}
			return "", fmt.Errorf("not found")
		}
	}
	cases := []struct {
		name string
		in   detectInputs
		want initKind
	}{
		{"systemd", detectInputs{p1: "systemd", hasSysdDir: true, lookPath: lookPathStub("systemctl")}, initSystemd},
		{"systemd 但无 /run/systemd/system 不算", detectInputs{p1: "systemd", lookPath: lookPathStub("systemctl")}, initNone},
		{"systemd 但无 systemctl 不算", detectInputs{p1: "systemd", hasSysdDir: true, lookPath: lookPathStub()}, initNone},
		{"OpenRC", detectInputs{p1: "init", lookPath: lookPathStub("rc-update", "rc-service")}, initOpenRC},
		{"OpenRC 优先于 sysvinit", detectInputs{p1: "init", hasInitd: true, lookPath: lookPathStub("rc-update", "rc-service", "update-rc.d")}, initOpenRC},
		{"只有 rc-update 不算 OpenRC", detectInputs{p1: "init", lookPath: lookPathStub("rc-update")}, initNone},
		{"procd（openwrt 文件）", detectInputs{p1: "procd", hasOpenwrt: true, lookPath: lookPathStub()}, initProcd},
		{"procd（工具）", detectInputs{lookPath: lookPathStub("procd")}, initProcd},
		{"sysvinit（update-rc.d）", detectInputs{p1: "init", hasInitd: true, lookPath: lookPathStub("update-rc.d")}, initSysvinit},
		{"sysvinit（chkconfig）", detectInputs{p1: "init", hasInitd: true, lookPath: lookPathStub("chkconfig")}, initSysvinit},
		{"sysvinit（/etc/rc.d）", detectInputs{p1: "init", hasInitd: true, hasRcd: true, lookPath: lookPathStub()}, initSysvinit},
		{"sysvinit 但 PID1 不是 init 不算", detectInputs{p1: "sshd", hasInitd: true, lookPath: lookPathStub("update-rc.d")}, initNone},
		{"容器（PID1=sshd，无工具）", detectInputs{p1: "sshd", lookPath: lookPathStub()}, initNone},
	}
	for _, c := range cases {
		if got := detectPanelInitFrom(c.in); got != c.want {
			t.Fatalf("%s：应为 %q，得到 %q", c.name, c.want, got)
		}
	}
}

func TestRestartPanelCommand(t *testing.T) {
	if got := restartPanelCommand(initSystemd); strings.Join(got, " ") != "systemctl --no-block restart sssingbox" {
		t.Fatalf("systemd 重启命令不对：%v", got)
	}
	if got := restartPanelCommand(initOpenRC); strings.Join(got, " ") != "rc-service sssingbox restart" {
		t.Fatalf("OpenRC 重启命令不对：%v", got)
	}
	if got := restartPanelCommand(initProcd); strings.Join(got, " ") != "/etc/init.d/sssingbox restart" {
		t.Fatalf("procd 重启命令不对：%v", got)
	}
	if got := restartPanelCommand(initSysvinit); strings.Join(got, " ") != "/etc/init.d/sssingbox restart" {
		t.Fatalf("sysvinit 重启命令不对：%v", got)
	}
	if got := restartPanelCommand(initNone); got != nil {
		t.Fatalf("无服务管理不应有重启命令：%v", got)
	}
}

func TestManualRestartCmd(t *testing.T) {
	if got := manualRestartCmd("/var/lib/sssingbox", "/usr/local/bin/sssingbox", 48081); got != "/usr/local/bin/sssingbox -data /var/lib/sssingbox -port 48081" {
		t.Fatalf("手动重启命令不对：%q", got)
	}
	if got := manualRestartCmd("", "", 18081); got != "sssingbox -data /var/lib/sssingbox -port 18081" {
		t.Fatalf("默认值不对：%q", got)
	}
}

func TestPanelAccess_Combined(t *testing.T) {
	// v1.2.2：端口+路径一次改完。v1.0.1 起：无服务文件时端口改动直接
	// 报错（不再谎称已写入），有服务文件时见 TestPanelAccess_PortWithServiceFile。
	freePort := func(t *testing.T) int {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("取空闲端口失败：%v", err)
		}
		p := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		return p
	}
	call := func(s *Server, body string) (bool, string, map[string]interface{}) {
		rec := postJSON(t, s, s.handleSettingsAction, "/api/settings/panel-access", body, nil)
		var out struct {
			OK   bool                   `json:"ok"`
			Err  string                 `json:"error"`
			Data map[string]interface{} `json:"data"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
			t.Fatalf("解响应失败：%v", err)
		}
		return out.OK, out.Err, out.Data
	}

	// 本函数内凡是触及服务文件的用例一律走“无服务管理”（单测覆盖文件
	// 见 TestPanelAccess_PortWithServiceFile），不依赖测试机真实状态。
	testInitKind = initNone
	testServiceFile = ""
	defer func() { testInitKind = ""; testServiceFile = "" }()

	// 双改 + 无服务文件（v1.0.1 修）：直接报错，路径也不落盘（两项
	// 要么都改、要么都不改），不再出现“路径改了、端口丢了还谎称已保存”。
	s := newAuthTestServer(t, "u1", "oldpass123")
	p1 := freePort(t)
	ok, errMsg, data := call(s, fmt.Sprintf(`{"port":%d,"path":"zz771"}`, p1))
	if ok {
		t.Fatal("双改 + 无服务文件应失败")
	}
	if !strings.Contains(errMsg, "手动") {
		t.Fatalf("双改 + 无服务文件应提示手动重启命令，得到：%s", errMsg)
	}
	if data != nil {
		t.Fatalf("失败响应不应带 data：%v", data)
	}
	if got := s.app.Store.GetSetting("panel_path"); got != "" {
		t.Fatalf("双改失败时路径不应落盘，得到 %q", got)
	}

	// 非法端口 + 合法路径：先全验，路径也不许落盘。
	s2 := newAuthTestServer(t, "u1", "oldpass123")
	if ok, _, _ := call(s2, `{"port":70000,"path":"ok123"}`); ok {
		t.Fatal("端口超范围应失败")
	}
	if got := s2.app.Store.GetSetting("panel_path"); got != "" {
		t.Fatalf("非法端口时路径不应落盘，得到 %q", got)
	}

	// 保留路径 + 合法端口：同样全失败。
	if ok, _, _ := call(s2, fmt.Sprintf(`{"port":%d,"path":"api"}`, freePort(t))); ok {
		t.Fatal("保留路径 api 应失败")
	}
	if got := s2.app.Store.GetSetting("panel_path"); got != "" {
		t.Fatalf("保留路径时路径不应落盘，得到 %q", got)
	}

	// 只改路径：不碰端口，不用重启。
	s3 := newAuthTestServer(t, "u1", "oldpass123")
	ok, errMsg, data = call(s3, `{"port":0,"path":"abc"}`)
	if !ok {
		t.Fatalf("只改路径应成功，得到错误：%s", errMsg)
	}
	if data["restart_required"] != false || data["path"] != "abc" {
		t.Fatalf("只改路径响应不对：%v", data)
	}

	// 只改端口 + 无服务文件：同样直接报错。
	s4 := newAuthTestServer(t, "u1", "oldpass123")
	p4 := freePort(t)
	ok, errMsg, _ = call(s4, fmt.Sprintf(`{"port":%d,"path":""}`, p4))
	if ok {
		t.Fatal("只改端口 + 无服务文件应失败")
	}
	if !strings.Contains(errMsg, "手动") {
		t.Fatalf("只改端口 + 无服务文件应提示手动重启命令，得到：%s", errMsg)
	}
	if got := s4.app.Store.GetSetting("panel_path"); got != "" {
		t.Fatalf("只改端口失败时路径应不动，得到 %q", got)
	}

	// 两项都不改：直接成功，不动任何东西。
	ok, errMsg, data = call(s3, `{"port":0,"path":"abc"}`)
	if !ok {
		t.Fatalf("无改动应成功，得到错误：%s", errMsg)
	}
	if data["restart_required"] != false {
		t.Fatalf("无改动不应要求重启：%v", data)
	}
}

func TestPanelAccess_PortWithServiceFile(t *testing.T) {
	// 有服务文件时改端口应真写文件（v1.0.1 修的核心）。服务类型用
	// openrc / procd / sysvinit（重启命令不存在时静默失败，响应仍是
	// restart_required=false，即“已发出重启”）；systemd 类型由实机
	// 测试覆盖，不在单测里触发真实的 daemon-reload。
	freePort := func(t *testing.T) int {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("取空闲端口失败：%v", err)
		}
		p := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		return p
	}
	call := func(s *Server, path, body string) (bool, string, map[string]interface{}) {
		rec := postJSON(t, s, s.handleSettingsAction, path, body, nil)
		var out struct {
			OK   bool                   `json:"ok"`
			Err  string                 `json:"error"`
			Data map[string]interface{} `json:"data"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
			t.Fatalf("解响应失败：%v", err)
		}
		return out.OK, out.Err, out.Data
	}
	writeSvc := func(t *testing.T, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "sssingbox.service")
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("写单测服务文件失败：%v", err)
		}
		return p
	}
	withSvc := func(kind initKind, svc string) func() {
		testInitKind = kind
		testServiceFile = svc
		return func() { testInitKind = ""; testServiceFile = "" }
	}
	readSvc := func(t *testing.T, p string) string {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("读单测服务文件失败：%v", err)
		}
		return string(b)
	}

	// OpenRC：双改，文件真写（外层引号 intact），路径落盘。
	s := newAuthTestServer(t, "u1", "oldpass123")
	svc := writeSvc(t, "#!/sbin/openrc-run\ncommand=\"/usr/local/bin/sssingbox\"\ncommand_args=\"-data /var/lib/sssingbox -port 18081\"\n")
	defer withSvc(initOpenRC, svc)()
	p := freePort(t)
	ok, errMsg, data := call(s, "/api/settings/panel-access", fmt.Sprintf(`{"port":%d,"path":"oc123"}`, p))
	if !ok {
		t.Fatalf("OpenRC 双改应成功，得到错误：%s", errMsg)
	}
	if data["port"] != float64(p) || data["path"] != "oc123" || data["restart_required"] != false {
		t.Fatalf("OpenRC 双改响应不对：%v", data)
	}
	if got := readSvc(t, svc); !strings.Contains(got, fmt.Sprintf(`command_args="-data /var/lib/sssingbox -port %d"`, p)) {
		t.Fatalf("OpenRC 服务文件应真写新端口且外层引号 intact，得到 %q", got)
	}
	if got := s.app.Store.GetSetting("panel_path"); got != "oc123" {
		t.Fatalf("OpenRC 双改后路径应落盘，得到 %q", got)
	}

	// procd：带引号数字，双改。
	s = newAuthTestServer(t, "u1", "oldpass123")
	svc = writeSvc(t, "procd_set_param command \"/usr/local/bin/sssingbox\" -data \"/var/lib/sssingbox\" -port \"18081\"\n")
	defer withSvc(initProcd, svc)()
	p = freePort(t)
	ok, errMsg, data = call(s, "/api/settings/panel-access", fmt.Sprintf(`{"port":%d,"path":"pc456"}`, p))
	if !ok {
		t.Fatalf("procd 双改应成功，得到错误：%s", errMsg)
	}
	if got := readSvc(t, svc); !strings.Contains(got, fmt.Sprintf("-port %d", p)) || strings.Contains(got, "18081") {
		t.Fatalf("procd 服务文件应真写新端口且旧端口消失，得到 %q", got)
	}
	if got := s.app.Store.GetSetting("panel_path"); got != "pc456" {
		t.Fatalf("procd 双改后路径应落盘，得到 %q", got)
	}

	// sysvinit：ARGS=，双改。
	s = newAuthTestServer(t, "u1", "oldpass123")
	svc = writeSvc(t, "ARGS=\"-data /var/lib/sssingbox -port 18081\"\n")
	defer withSvc(initSysvinit, svc)()
	p = freePort(t)
	ok, errMsg, data = call(s, "/api/settings/panel-access", fmt.Sprintf(`{"port":%d,"path":"sv789"}`, p))
	if !ok {
		t.Fatalf("sysvinit 双改应成功，得到错误：%s", errMsg)
	}
	if got := readSvc(t, svc); !strings.Contains(got, fmt.Sprintf(`ARGS="-data /var/lib/sssingbox -port %d"`, p)) {
		t.Fatalf("sysvinit 服务文件应真写新端口，得到 %q", got)
	}

	// 端口单独改（port 接口）+ OpenRC 文件。
	s = newAuthTestServer(t, "u1", "oldpass123")
	svc = writeSvc(t, "#!/sbin/openrc-run\ncommand_args=\"-data /var/lib/sssingbox -port 18081\"\n")
	defer withSvc(initOpenRC, svc)()
	p = freePort(t)
	ok, errMsg, data = call(s, "/api/settings/port", fmt.Sprintf(`{"port":%d}`, p))
	if !ok {
		t.Fatalf("端口单独改应成功，得到错误：%s", errMsg)
	}
	if data["port"] != float64(p) || data["restart_required"] != false {
		t.Fatalf("端口单独改响应不对：%v", data)
	}
	if got := readSvc(t, svc); !strings.Contains(got, fmt.Sprintf("-port %d", p)) {
		t.Fatalf("端口单独改后服务文件应真写新端口，得到 %q", got)
	}
	if got := s.app.Store.GetSetting("panel_path"); got != "" {
		t.Fatalf("端口单独改时路径应不动，得到 %q", got)
	}

	// 服务文件不存在（systemd 类型但单元缺失）：双改直接报错，路径不落盘。
	s = newAuthTestServer(t, "u1", "oldpass123")
	defer withSvc(initSystemd, filepath.Join(t.TempDir(), "no-such.service"))()
	p = freePort(t)
	ok, errMsg, _ = call(s, "/api/settings/panel-access", fmt.Sprintf(`{"port":%d,"path":"nofile"}`, p))
	if ok {
		t.Fatal("服务文件缺失时双改应失败")
	}
	if !strings.Contains(errMsg, "读服务文件失败") {
		t.Fatalf("服务文件缺失应报读失败，得到：%s", errMsg)
	}
	if got := s.app.Store.GetSetting("panel_path"); got != "" {
		t.Fatalf("服务文件缺失时路径不应落盘，得到 %q", got)
	}

	// 无服务管理：双改直接报错，路径不落盘。
	s = newAuthTestServer(t, "u1", "oldpass123")
	defer withSvc(initNone, "")()
	p = freePort(t)
	ok, errMsg, _ = call(s, "/api/settings/panel-access", fmt.Sprintf(`{"port":%d,"path":"nonem"}`, p))
	if ok {
		t.Fatal("无服务管理时双改应失败")
	}
	if !strings.Contains(errMsg, "找不到面板服务文件") {
		t.Fatalf("无服务管理应报找不到服务文件，得到：%s", errMsg)
	}
	if got := s.app.Store.GetSetting("panel_path"); got != "" {
		t.Fatalf("无服务管理时路径不应落盘，得到 %q", got)
	}
}
