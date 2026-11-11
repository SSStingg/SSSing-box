package server

// v1.2.0：2FA 登录全流程。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustTmp(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		OK   bool `json:"ok"`
		Data struct {
			Need2FA bool   `json:"need_2fa"`
			Tmp     string `json:"tmp"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("解登录响应失败：%v", err)
	}
	if !out.Data.Need2FA || out.Data.Tmp == "" {
		t.Fatal("2FA 开通且新 IP 时登录应返回 need_2fa + tmp")
	}
	return out.Data.Tmp
}

func Test2FA_FullFlow(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)

	// 开通：begin 生成待开通密钥，用它算当前动态码开通。
	rec := postJSON(t, s, s.handle2FABegin, "/api/settings/2fa/begin", `{}`, c)
	if ok, msg := decodeOK(t, rec); !ok {
		t.Fatalf("begin 应成功：%s", msg)
	}
	pending := s.getTOTPSecretValue("totp_pending")
	if pending == "" {
		t.Fatal("begin 后应有待开通密钥")
	}
	code, err := totpCodeAt(pending, time.Now())
	if err != nil {
		t.Fatalf("算码失败：%v", err)
	}
	rec = postJSON(t, s, s.handle2FAEnable, "/api/settings/2fa/enable", `{"code":"`+code+`"}`, c)
	if ok, msg := decodeOK(t, rec); !ok {
		t.Fatalf("输对动态码应开通：%s", msg)
	}
	// 恢复码明文只在 enable 响应里出现一次；这里只验库里个数（10 个）。
	if s.recoveryLeft() != 10 {
		t.Fatalf("开通后恢复码应为 10 个，得到 %d", s.recoveryLeft())
	}
	// 新 IP（测试请求的 192.0.2.1 与开通时的回环不同）登录：应进第二步。
	// 注意：开通时 totpMarkIP 记的是测试请求的 192.0.2.1，所以先清掉，
	// 模拟“新 IP”；否则同一测试 IP 会直接跳过 2FA。
	_ = s.app.Store.SetSetting("totp_ips", "")
	rec = postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"oldpass123","remember":false}`, nil)
	tmp := mustTmp(t, rec)

	// 第二步输错码：不给会话，且临时凭证被消费掉（一次性），再用同一个
	// tmp 直接 401；要试就重新登录领新凭证。
	rec = postJSON(t, s, s.handleLogin2FA, "/api/login/2fa", `{"tmp":"`+tmp+`","code":"000000"}`, nil)
	if ok, _ := decodeOK(t, rec); ok {
		t.Fatal("错动态码不应登录")
	}
	rec = postJSON(t, s, s.handleLogin2FA, "/api/login/2fa", `{"tmp":"`+tmp+`","code":"000000"}`, nil)
	if rec.Code != 401 {
		t.Fatalf("消费过的临时凭证应 401，得到 %d", rec.Code)
	}
	// 重新登录领新 tmp，再输对码：给会话，且该 IP 被记为已验证。
	rec = postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"oldpass123","remember":false}`, nil)
	tmp = mustTmp(t, rec)
	secret := s.getTOTPSecretValue("totp_secret")
	code2, _ := totpCodeAt(secret, time.Now())
	rec = postJSON(t, s, s.handleLogin2FA, "/api/login/2fa", `{"tmp":"`+tmp+`","code":"`+code2+`"}`, nil)
	if ok, msg := decodeOK(t, rec); !ok {
		t.Fatalf("对动态码应登录：%s", msg)
	}
	if len(rec.Result().Cookies()) == 0 {
		t.Fatal("第二步成功应下发会话 cookie")
	}
	// 同一 IP 再登录：直接给会话，不再要 2FA。
	rec = postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"oldpass123","remember":false}`, nil)
	var out struct {
		Data struct {
			Need2FA bool `json:"need_2fa"`
		} `json:"data"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&out)
	if out.Data.Need2FA {
		t.Fatal("已验证 IP 再登录不应再要 2FA")
	}
}

func TestTOTPSecretEncryptedAtRest(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)
	rec := postJSON(t, s, s.handle2FABegin, "/api/settings/2fa/begin", `{}`, c)
	if ok, msg := decodeOK(t, rec); !ok {
		t.Fatalf("begin 应成功：%s", msg)
	}
	// 库里存的应是密文（v1: 前缀），不是明文密钥。
	stored := s.app.Store.GetSetting("totp_pending")
	if !strings.HasPrefix(stored, "v1:") {
		t.Fatalf("待开通密钥应加密存储，得到 %q", stored)
	}
	// 解密后应能算出正确的动态码。
	plain := s.getTOTPSecretValue("totp_pending")
	if plain == "" {
		t.Fatal("解密后密钥不应为空")
	}
	if _, err := totpCodeAt(plain, time.Now()); err != nil {
		t.Fatalf("解密出的密钥应能算码：%v", err)
	}
	// 密钥文件应存在且 0600。
	fi, err := os.Stat(filepath.Join(s.app.Dir, ".totp_key"))
	if err != nil {
		t.Fatalf("密钥文件应存在：%v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("密钥文件应为 0600，得到 %o", fi.Mode().Perm())
	}
}

func TestTOTPLegacyPlaintextMigrated(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	// 模拟老面板留下的明文密钥。
	_ = s.app.Store.SetSetting("totp_secret", "JBSWY3DPEHPK3PXP")
	got := s.getTOTPSecretValue("totp_secret")
	if got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("旧明文应能正常读出，得到 %q", got)
	}
	stored := s.app.Store.GetSetting("totp_secret")
	if !strings.HasPrefix(stored, "v1:") {
		t.Fatalf("读一次后旧明文应升级成密文，得到 %q", stored)
	}
}

func TestTOTPIPExpiry(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	// 刚标记的 IP 应通过。
	s.totpMarkIP("203.0.113.7")
	if !s.totpIPVerified("203.0.113.7") {
		t.Fatal("刚标记的 IP 应已验证")
	}
	// 过期的条目应不通过。
	expired, _ := json.Marshal([]totpIPEntry{{IP: "203.0.113.8", Exp: time.Now().Add(-time.Hour).Unix()}})
	_ = s.app.Store.SetSetting("totp_ips", string(expired))
	if s.totpIPVerified("203.0.113.8") {
		t.Fatal("过期的 IP 不应再信任")
	}
	// 旧格式（纯字符串列表）应按过期处理。
	legacy, _ := json.Marshal([]string{"203.0.113.9"})
	_ = s.app.Store.SetSetting("totp_ips", string(legacy))
	if s.totpIPVerified("203.0.113.9") {
		t.Fatal("旧格式 IP 列表应按过期处理，不再信任")
	}
}

func Test2FA_RecoveryAndReset(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)
	// 直接布好已开通状态：密钥固定，恢复码已知。
	_ = s.app.Store.SetSetting("totp_secret", "JBSWY3DPEHPK3PXP")
	codes := []string{"ABCD-EFGH", "IJKL-MNOP"}
	_ = s.app.Store.SetSetting("totp_recovery", hashRecoveryCodes(codes))

	// 新 IP 登录进第二步，用恢复码登录成功；同一恢复码再用应失败。
	rec := postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"oldpass123"}`, nil)
	tmp := mustTmp(t, rec)
	rec = postJSON(t, s, s.handleLogin2FA, "/api/login/2fa", `{"tmp":"`+tmp+`","code":"ABCD-EFGH"}`, nil)
	if ok, msg := decodeOK(t, rec); !ok {
		t.Fatalf("恢复码应能登录：%s", msg)
	}
	_ = s.app.Store.SetSetting("totp_ips", "")
	rec = postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"oldpass123"}`, nil)
	tmp = mustTmp(t, rec)
	rec = postJSON(t, s, s.handleLogin2FA, "/api/login/2fa", `{"tmp":"`+tmp+`","code":"ABCD-EFGH"}`, nil)
	if ok, _ := decodeOK(t, rec); ok {
		t.Fatal("用过的恢复码应拒绝（一次性）")
	}

	// reset：非回环拒绝，回环放行（直接调 handler，只验回环门；
	// 会话鉴权在路由层 requireAuth，与其他设置接口同一层）。
	req := httptest.NewRequest("POST", "/api/settings/2fa/reset", strings.NewReader(`{}`))
	req.RemoteAddr = "203.0.113.9:1234"
	req.AddCookie(c)
	rec2 := httptest.NewRecorder()
	s.handle2FAReset(rec2, req)
	if rec2.Code != 403 {
		t.Fatalf("非回环 reset 应 403，得到 %d", rec2.Code)
	}
	req2 := httptest.NewRequest("POST", "/api/settings/2fa/reset", strings.NewReader(`{}`))
	req2.RemoteAddr = "127.0.0.1:1234"
	req2.AddCookie(c)
	rec3 := httptest.NewRecorder()
	s.handle2FAReset(rec3, req2)
	if ok, msg := decodeOK(t, rec3); !ok {
		t.Fatalf("回环 reset 应成功：%s", msg)
	}
	if s.app.Store.GetSetting("totp_secret") != "" {
		t.Fatal("reset 后密钥应清空")
	}
}

// ---------- 2FA 密钥损坏 fail-closed ----------

// enable2FAForTest：走 begin/enable 全流程开通 2FA，返回明文密钥。
func enable2FAForTest(t *testing.T, s *Server, c *http.Cookie) string {
	t.Helper()
	rec := postJSON(t, s, s.handle2FABegin, "/api/settings/2fa/begin", `{}`, c)
	if ok, msg := decodeOK(t, rec); !ok {
		t.Fatalf("begin 应成功：%s", msg)
	}
	pending := s.getTOTPSecretValue("totp_pending")
	if pending == "" {
		t.Fatal("begin 后应有待开通密钥")
	}
	code, err := totpCodeAt(pending, time.Now())
	if err != nil {
		t.Fatalf("算码失败：%v", err)
	}
	rec = postJSON(t, s, s.handle2FAEnable, "/api/settings/2fa/enable", `{"code":"`+code+`"}`, c)
	if ok, msg := decodeOK(t, rec); !ok {
		t.Fatalf("输对动态码应开通：%s", msg)
	}
	secret := s.getTOTPSecretValue("totp_secret")
	if secret == "" {
		t.Fatal("开通后应有密钥")
	}
	return secret
}

// breakTOTPKey：模拟 .totp_key 丢失——删掉文件，下次 totpKey() 会生成
// 一把新密钥，旧密文从此解不开。
func breakTOTPKey(t *testing.T, s *Server) {
	t.Helper()
	if err := os.Remove(filepath.Join(s.app.Dir, ".totp_key")); err != nil {
		t.Fatalf("删密钥文件失败：%v", err)
	}
}

// TestTOTPKeyLost_FailClosed：.totp_key 丢了，2FA 必须拒绝登录（fail-closed），
// 绝不能当成“没开通”跳过；状态接口要报 broken；本机回环登录不受影响。
func TestTOTPKeyLost_FailClosed(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)
	enable2FAForTest(t, s, c)
	// 新 IP 登录前先清掉已验证 IP，模拟外网登录。
	_ = s.app.Store.SetSetting("totp_ips", "")
	breakTOTPKey(t, s)

	// 外网登录：密码对了也应拒绝，且不下发会话。
	rec := postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"oldpass123","remember":false}`, nil)
	if rec.Code != 500 {
		t.Fatalf("密钥损坏时登录应 500 拒绝，得到 %d", rec.Code)
	}
	if ok, msg := decodeOK(t, rec); ok {
		t.Fatal("密钥损坏时登录不应成功")
	} else if !strings.Contains(msg, "二次验证密钥损坏") {
		t.Fatalf("拒绝原因应明说密钥损坏，得到 %q", msg)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("密钥损坏时不应下发会话")
	}
	// 状态接口：enabled 仍为 true（确实开通了），broken 为 true。
	req := httptest.NewRequest("GET", "/api/settings/2fa/status", nil)
	req.AddCookie(c)
	rec2 := httptest.NewRecorder()
	s.handle2FAStatus(rec2, req)
	var st struct {
		Data struct {
			Enabled bool `json:"enabled"`
			Broken  bool `json:"broken"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rec2.Body).Decode(&st); err != nil {
		t.Fatalf("解状态响应失败：%v", err)
	}
	if !st.Data.Enabled || !st.Data.Broken {
		t.Fatalf("密钥损坏时状态应为 enabled=true broken=true，得到 enabled=%v broken=%v", st.Data.Enabled, st.Data.Broken)
	}
	// 本机回环登录不受影响（SSH 菜单要靠回环登录来恢复）。
	req3 := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"u1","password":"oldpass123","remember":false}`))
	req3.RemoteAddr = "127.0.0.1:1234"
	rec3 := httptest.NewRecorder()
	s.handleLogin(rec3, req3)
	if ok, msg := decodeOK(t, rec3); !ok {
		t.Fatalf("回环登录应成功（恢复口），得到错误：%s", msg)
	}
}

// TestTOTPKeyLost_No2FA_Unaffected：没开通 2FA 的面板，.totp_key 丢不丢
// 都不影响登录（不要误伤正常登录）。
func TestTOTPKeyLost_No2FA_Unaffected(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	// 没开通 2FA，也没有密钥文件。
	if rec := postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"oldpass123","remember":false}`, nil); rec.Code != 200 {
		t.Fatalf("没开通 2FA 时登录应成功，得到 %d", rec.Code)
	}
}

// TestTOTPPendingBroken：待开通密钥损坏时，开通接口要明说密钥损坏，
// 别谎称“请先点开通”。
func TestTOTPPendingBroken(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)
	rec := postJSON(t, s, s.handle2FABegin, "/api/settings/2fa/begin", `{}`, c)
	if ok, msg := decodeOK(t, rec); !ok {
		t.Fatalf("begin 应成功：%s", msg)
	}
	breakTOTPKey(t, s)
	rec = postJSON(t, s, s.handle2FAEnable, "/api/settings/2fa/enable", `{"code":"000000"}`, c)
	if rec.Code != 500 {
		t.Fatalf("待开通密钥损坏时开通应 500，得到 %d", rec.Code)
	}
	if _, msg := decodeOK(t, rec); !strings.Contains(msg, "二次验证密钥损坏") {
		t.Fatalf("开通失败原因应明说密钥损坏，得到 %q", msg)
	}
}

// Test2FADowngrade：降级准备——已加密的密钥解密后写回明文，旧版能读。
func Test2FADowngrade(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)
	secret := enable2FAForTest(t, s, c)
	// 库里应是密文。
	if stored := s.app.Store.GetSetting("totp_secret"); !strings.HasPrefix(stored, "v1:") {
		t.Fatalf("开通后库里应是密文，得到 %q", stored)
	}
	// 非回环拒绝。
	req := httptest.NewRequest("POST", "/api/settings/2fa/downgrade", strings.NewReader(`{}`))
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	s.handle2FADowngrade(rec, req)
	if rec.Code != 403 {
		t.Fatalf("非回环降级准备应 403，得到 %d", rec.Code)
	}
	// 回环转换：写回明文，且值就是原来的密钥。
	req2 := httptest.NewRequest("POST", "/api/settings/2fa/downgrade", strings.NewReader(`{}`))
	req2.RemoteAddr = "127.0.0.1:1234"
	req2.AddCookie(c)
	rec2 := httptest.NewRecorder()
	s.handle2FADowngrade(rec2, req2)
	if ok, msg := decodeOK(t, rec2); !ok {
		t.Fatalf("回环降级准备应成功：%s", msg)
	}
	if got := s.app.Store.GetSetting("totp_secret"); got != secret {
		t.Fatalf("转换后库里应是明文密钥，得到 %q", got)
	}
	// 再转一次：已经是明文，无需转换。
	req3 := httptest.NewRequest("POST", "/api/settings/2fa/downgrade", strings.NewReader(`{}`))
	req3.RemoteAddr = "127.0.0.1:1234"
	req3.AddCookie(c)
	rec3 := httptest.NewRecorder()
	s.handle2FADowngrade(rec3, req3)
	var out struct {
		Data struct {
			AlreadyPlain bool `json:"already_plain"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rec3.Body).Decode(&out); err != nil || !out.Data.AlreadyPlain {
		t.Fatalf("第二次转换应报 already_plain，得到 %v", out)
	}
	// 未开通：无需转换。
	s2 := newAuthTestServer(t, "u1", "oldpass123")
	req4 := httptest.NewRequest("POST", "/api/settings/2fa/downgrade", strings.NewReader(`{}`))
	req4.RemoteAddr = "127.0.0.1:1234"
	rec4 := httptest.NewRecorder()
	s2.handle2FADowngrade(rec4, req4)
	if rec4.Code != 400 {
		t.Fatalf("未开通时降级准备应 400，得到 %d", rec4.Code)
	}
	// 密钥损坏：转不了。
	s3 := newAuthTestServer(t, "u1", "oldpass123")
	c3 := loginCookie(t, s3, `{"username":"u1","password":"oldpass123"}`)
	enable2FAForTest(t, s3, c3)
	breakTOTPKey(t, s3)
	req5 := httptest.NewRequest("POST", "/api/settings/2fa/downgrade", strings.NewReader(`{}`))
	req5.RemoteAddr = "127.0.0.1:1234"
	req5.AddCookie(c3)
	rec5 := httptest.NewRecorder()
	s3.handle2FADowngrade(rec5, req5)
	if rec5.Code != 500 {
		t.Fatalf("密钥损坏时降级准备应 500，得到 %d", rec5.Code)
	}
}
