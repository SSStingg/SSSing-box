package server

// ---------- 2FA 设置接口 ----------
// 开通流程：begin 生成待开通密钥（二维码 + 手动密钥）→ 用户在验证器里
// 看到 6 位码 → enable 验对一次才正式生效，并一次发 10 个恢复码
// （只显示这一次）。换一个 = 重新生成待开通密钥，旧密钥不受影响，
// 直到新密钥验对开通为止。关闭要验一次动态码（或恢复码）；
// SSH 菜单的 reset 只允许本机回环调用，丢了 2FA 时的恢复口。

import (
	"net/http"
	"strings"
	"time"
)

func (s *Server) handle2FAStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	// broken 单独报：密钥损坏时 enabled 仍为 true（确实开通了），
	// 但登录会被拒绝——前端据此显示“密钥损坏”，别显示成“未开通”。
	state, _ := s.totpSecretRead("totp_secret")
	okJSON(w, map[string]interface{}{
		"enabled":       state != totpSecretNone,
		"broken":        state == totpSecretBroken,
		"recovery_left": s.recoveryLeft(),
	})
}

func (s *Server) totpBeginResponse(w http.ResponseWriter, r *http.Request) {
	secret := randTOTPSecret()
	s.setTOTPSecretValue("totp_pending", secret)
	username, _ := s.sessionUser(r)
	otpauth := totpOTPAuthURL(username, secret)
	qr, err := totpQR(otpauth)
	if err != nil {
		errJSON(w, 500, err.Error())
		return
	}
	okJSON(w, map[string]interface{}{
		"secret":      secret,
		"otpauth_url": otpauth,
		"qr":          qr,
	})
}

func (s *Server) handle2FABegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	s.totpBeginResponse(w, r)
}

func (s *Server) handle2FARegenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	s.totpBeginResponse(w, r)
}

func (s *Server) handle2FAEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := s.readJSON(r, &body); err != nil {
		errJSON(w, 400, "请求格式不对")
		return
	}
	pendingState, pending := s.totpSecretRead("totp_pending")
	if pendingState == totpSecretBroken {
		errJSON(w, 500, "二次验证密钥损坏，请重新点开通生成密钥")
		return
	}
	if pending == "" {
		errJSON(w, 400, "请先点开通 2FA 生成密钥")
		return
	}
	if !verifyTOTP(pending, body.Code, time.Now()) {
		errJSON(w, 400, "动态码不对")
		return
	}
	s.setTOTPSecretValue("totp_secret", pending)
	s.setTOTPSecretValue("totp_pending", "")
	codes := genRecoveryCodes()
	_ = s.app.Store.SetSetting("totp_recovery", hashRecoveryCodes(codes))
	s.totpMarkIP(clientIPOf(r))
	okJSON(w, map[string]interface{}{"recovery": codes})
}

func (s *Server) handle2FADisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := s.readJSON(r, &body); err != nil {
		errJSON(w, 400, "请求格式不对")
		return
	}
	secretState, secret := s.totpSecretRead("totp_secret")
	if secretState == totpSecretBroken {
		errJSON(w, 500, "二次验证密钥损坏，请用本机 SSH 菜单关闭二次验证")
		return
	}
	if secret == "" {
		errJSON(w, 400, "2FA 未开通")
		return
	}
	if verifyTOTP(secret, body.Code, time.Now()) || s.tryRecoveryCode(body.Code) {
		s.totpClear()
		okJSON(w, nil)
		return
	}
	errJSON(w, 400, "动态码不对")
}

func (s *Server) handle2FAReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	// 只允许本机回环：SSH 菜单跑在本机上，浏览器会话即使被盗也关不掉 2FA。
	if !isLoopbackIP(clientIPOf(r)) {
		errJSON(w, 403, "关闭 2FA 只能在本机 SSH 菜单里操作")
		return
	}
	s.totpClear()
	okJSON(w, nil)
}

// handle2FADowngrade：降级准备——把已加密的 TOTP 密钥解密后写回明文，
// 供降级后的旧版读取（旧版把 v1: 密文当明文 base32 解码，动态码永远验不过）。
// 只允许本机回环（SSH 菜单调用）。
// 注意：写回明文后，下次登录读到明文会立刻重新加密——转换后请立即降级，
// 不要再登录面板，否则又要重转一次。降级后请尽快重新开通 2FA（升回新版
// 后会自动重新加密）。密钥损坏时转不了，走 SSH 菜单关 2FA。
func (s *Server) handle2FADowngrade(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	if !isLoopbackIP(clientIPOf(r)) {
		errJSON(w, 403, "2FA 降级准备只能在本机 SSH 菜单里操作")
		return
	}
	stored := s.app.Store.GetSetting("totp_secret")
	if stored == "" {
		errJSON(w, 400, "2FA 未开通，无需转换")
		return
	}
	if !strings.HasPrefix(stored, "v1:") {
		okJSON(w, map[string]interface{}{"already_plain": true})
		return
	}
	state, plain := s.totpSecretRead("totp_secret")
	if state == totpSecretBroken || plain == "" {
		errJSON(w, 500, "二次验证密钥损坏，无法解密，请用本机 SSH 菜单关闭二次验证后重新开通")
		return
	}
	// 直接写明文（绕开 setTOTPSecretValue 的加密），供降级后的旧版读取。
	if err := s.app.Store.SetSetting("totp_secret", plain); err != nil {
		errJSON(w, 500, err.Error())
		return
	}
	okJSON(w, map[string]interface{}{"converted": true})
}
