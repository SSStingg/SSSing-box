package server

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"sssingbox/internal/cores"
	"sssingbox/internal/proxy"
	"sssingbox/internal/stats"
	"sssingbox/internal/store"
	"sssingbox/internal/sysinfo"
	"sssingbox/internal/version"
)

// ---------- 登录失败限流 ----------
// 同一 IP 连续失败 5 次锁定 15 分钟（登录密码与 2FA 动态码共用一个计数，
// 内存态，面板重启清零）。只记 IP 不记账号：面板实质只有一个管理员，
// 按账号锁会让攻击者换个不存在的账号就绕过；按 IP 锁则 NAT 后多用户
// 共用出口时可能误伤，15 分钟后自动解，误伤有限。
type loginFailState struct {
	count       int
	firstFail   time.Time
	lockedUntil time.Time
}

const (
	loginMaxFails   = 5
	loginLockPeriod = 15 * time.Minute
	loginFailWindow = 15 * time.Minute
)

func (s *Server) loginAllowed(ip string) bool {
	if ip == "" {
		return true
	}
	s.loginFailMu.Lock()
	defer s.loginFailMu.Unlock()
	st, ok := s.loginFails[ip]
	if !ok {
		return true
	}
	now := time.Now()
	if !st.lockedUntil.IsZero() {
		if now.Before(st.lockedUntil) {
			return false
		}
		delete(s.loginFails, ip) // 锁过期，清零重算
		return true
	}
	if now.Sub(st.firstFail) > loginFailWindow {
		delete(s.loginFails, ip) // 窗口过期，清零重算
	}
	return true
}

func (s *Server) loginFailed(ip string) {
	if ip == "" {
		return
	}
	s.loginFailMu.Lock()
	defer s.loginFailMu.Unlock()
	if s.loginFails == nil {
		s.loginFails = map[string]*loginFailState{}
	}
	st, ok := s.loginFails[ip]
	if !ok {
		s.loginFails[ip] = &loginFailState{count: 1, firstFail: time.Now()}
		return
	}
	if time.Since(st.firstFail) > loginFailWindow {
		st.count = 1
		st.firstFail = time.Now()
		st.lockedUntil = time.Time{}
		return
	}
	st.count++
	if st.count >= loginMaxFails {
		st.lockedUntil = time.Now().Add(loginLockPeriod)
	}
}

func (s *Server) loginSucceeded(ip string) {
	if ip == "" {
		return
	}
	s.loginFailMu.Lock()
	delete(s.loginFails, ip)
	s.loginFailMu.Unlock()
}

// ---------- 密码长度 ----------
// bcrypt 硬上限 72 字节：超了 GenerateFromPassword 返回错误，以前三处都
// 把错误吞了（hash, _ := ...），空哈希直接入库，管理员设完超长密码就
// 永远登不上，只能进库手动修。长度与哈希错误都在这里一次性判掉。
const maxPasswordBytes = 72

func hashPassword(pw string) (string, error) {
	if len(pw) > maxPasswordBytes {
		return "", fmt.Errorf("密码不能超过 %d 字节", maxPasswordBytes)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// isBcryptHash：粗略判断是不是一条合法 bcrypt 哈希（$2a$/$2b$/$2y$ 开头，
// 60 字节）。空哈希与非法值都算损坏——之前超长密码的 bug 会把空哈希
// 写入库，那种账号对什么密码都验不过，只能走本机 CLI 重置。
func isBcryptHash(h string) bool {
	return len(h) == 60 && (strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") || strings.HasPrefix(h, "$2y$"))
}

// dummyHash：未知用户登录时也跑一次 bcrypt（时序对齐用）。值是启动时
// 用 crypto/rand 现抽的随机数算出的一条 bcrypt 哈希，明文无人知晓，
// 永远比对不上，只用来把响应时间拉平，让攻击者无法从快慢分辨账号存不存在。
// 注意：绝不能用固定明文算这条哈希——固定明文写在公开源码里，攻击者
// 拿它当口令就能直接通过比对（v1.0.2 安全修复：不存在的用户凭固定占位
// 口令可获得管理会话）。
var dummyHash = func() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	h, _ := bcrypt.GenerateFromPassword(b, bcrypt.DefaultCost)
	return string(h)
}()

// session 是内存登录态：24h 有效。改密码时除当前会话外全部吊销，
// 所以会话里必须记用户名（改密码按当前登录用户查改，不再写死 admin）。
type session struct {
	username string
	exp      time.Time
	created  time.Time // 建会话时间：记住登录的轮换按它算
	remember bool      // 30 天记住登录：轮换只针对这种长会话
}

type Server struct {
	app      *App
	poller   *stats.Poller
	sessions map[string]session
	sessMu   sync.Mutex
	// writeMu 串行化一切写操作：两个并发 PUT/删除/链式改动不再
	// 交错读-改-写；后台配额循环只走 applyMu，不抢这把锁，
	// 故不存在锁顺序倒置。内核安装耗时较长，期间写接口会等它，
	// 这是故意的：安装与 ApplyAll 交错更危险。
	writeMu   sync.Mutex
	startedAt time.Time
	statsErr  string
	statsMu   sync.Mutex
	webFS     http.FileSystem

	// 在线更新进度（update.go）：downloading/installing/restarting，空=闲置。
	updMu    sync.Mutex
	updPhase string
	// 在线更新进行中守卫（update.go）：更新是长流程，进行中再点直接拒绝。
	updRunning int32
	// 首次监听成功后的回调（panelcert.go）：main 用它删掉更新留下的
	// .bak 回滚备份，稳态零备份。
	onFirstListen func()
	// 登录失败限流：IP -> 连续失败记录，5 次失败锁 15 分钟（内存态，重启清零）。
	loginFailMu sync.Mutex
	loginFails  map[string]*loginFailState
	// 2FA 登录第二步的临时凭证（totp.go）：128 位随机 token，5 分钟有效。
	totpTmpMu sync.Mutex
	totpTmp   map[string]totpChallenge
	// 面板域名证书（panelcert.go）：数据目录 certs/panel/。
	certs *panelCertManager
	// Serve 循环与监听重启：启用 HTTPS / 换证 / 续期时重启监听。
	restartCh   chan struct{}
	serveMu     sync.Mutex
	curSrv      *http.Server
	stopped     bool
	servingTLS  bool
	servingCert string
}

// mutating 把一次写操作包进 writeMu：读请求顺带等写完成，
// 看到的总是一份完整状态。
func (s *Server) mutating(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
		next(w, r)
	}
}

func New(app *App, webFS http.FileSystem) *Server {
	s := &Server{
		app:       app,
		sessions:  map[string]session{},
		startedAt: time.Now(),
		webFS:     webFS,
		restartCh: make(chan struct{}, 1),
	}
	s.certs = newPanelCertManager(filepath.Join(app.Dir, "certs", "panel"), app.Store.GetSetting, app.Store.SetSetting)
	s.certs.restartFn = func() { s.RequestRestart() }
	s.poller = stats.NewPoller(s.portTags)
	s.startPanelUpdateChecker()
	return s
}

// portTags：nft 统计用的端口 -> 入站 tag 映射。
func (s *Server) portTags() map[int]string {
	tags := map[int]string{}
	list, _ := s.app.Store.ListInbounds()
	for _, in := range list {
		if !in.Enabled {
			continue
		}
		tags[in.Port] = "in-" + in.ID
	}
	return tags
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]interface{}{"ok": false, "error": msg})
}

func okJSON(w http.ResponseWriter, v interface{}) {
	writeJSON(w, 200, map[string]interface{}{"ok": true, "data": v})
}

func (s *Server) readJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	// 请求体封顶 1MB：解码器直接读 Body 时，超大体会被
	// 悄悄截断成“半截 JSON”——要么报错含糊，要么（配合
	// 宽松结构）读出缺字段的请求蒙混过关。先整读、超了就拒。
	const maxBody = 1 << 20
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxBody {
		return fmt.Errorf("请求体超过 1MB")
	}
	return json.Unmarshal(body, v)
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) authed(r *http.Request) bool {
	c, err := r.Cookie("sssingbox_session")
	if err != nil {
		return false
	}
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	sess, ok := s.sessions[c.Value]
	if !ok {
		return false
	}
	if time.Now().After(sess.exp) {
		delete(s.sessions, c.Value) // 过期会话当场清掉，不在内存里永久驻留
		return false
	}
	return true
}

// sweepExpiredSessions：定期清掉过期的内存会话（authed 只清遇到的那一条，
// 从不登录的过期会话靠这轮清掉，免得 sessions map 无限长）。
func (s *Server) sweepExpiredSessions() {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	now := time.Now()
	for tok, sess := range s.sessions {
		if now.After(sess.exp) {
			delete(s.sessions, tok)
		}
	}
}

// maybeRotateSession：记住登录（30 天）轮换。长会话被盗后 30 天都有效，
// 所以建会话超过 7 天的记住登录在下次请求时换发新 token、旧 token 作废，
// 有效期不变（只换凭证，不延长窗口）。24 小时会话不轮换：窗口本来就短，
// 轮换反而会在并发请求里互相顶掉。
func (s *Server) maybeRotateSession(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("sssingbox_session")
	if err != nil {
		return
	}
	s.sessMu.Lock()
	sess, ok := s.sessions[c.Value]
	if !ok || !sess.remember || time.Since(sess.created) < 7*24*time.Hour {
		s.sessMu.Unlock()
		return
	}
	// 轮换：新 token、同过期时间、同用户；旧 token 立即作废。
	newTok := randToken()
	s.sessions[newTok] = session{username: sess.username, exp: sess.exp, created: time.Now(), remember: true}
	delete(s.sessions, c.Value)
	s.sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sssingbox_session", Value: newTok, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(time.Until(sess.exp).Seconds())})
}

// sessionUser 返回当前登录会话的用户名（改密码等按用户操作的接口用）。
func (s *Server) sessionUser(r *http.Request) (string, bool) {
	c, err := r.Cookie("sssingbox_session")
	if err != nil {
		return "", false
	}
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	sess, ok := s.sessions[c.Value]
	if !ok || time.Now().After(sess.exp) {
		return "", false
	}
	return sess.username, true
}

// revokeSessionsExcept 吊销除 keep 外的全部会话（改密码后调用：
// 偷来的旧会话立即失效，当前操作者不受影响）。
func (s *Server) revokeSessionsExcept(keep string) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	for tok := range s.sessions {
		if tok != keep {
			delete(s.sessions, tok)
		}
	}
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			errJSON(w, 401, "未登录")
			return
		}
		s.maybeRotateSession(w, r)
		next(w, r)
	}
}

// ---------- routes ----------

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	// static
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			s.serveFile(w, r, "index.html")
			return
		}
		s.serveFile(w, r, strings.TrimPrefix(r.URL.Path, "/"))
	})
	// auth (public)
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/login/2fa", s.handleLogin2FA)
	mux.HandleFunc("/api/logout", s.handleLogout)
	mux.HandleFunc("/api/me", s.handleMe)
	mux.HandleFunc("/api/setup-status", s.handleSetupStatus)
	mux.HandleFunc("/api/setup", s.handleSetup)
	mux.HandleFunc("/sub/", s.handleSub)
	// api (authed)
	auth := s.requireAuth
	mux.HandleFunc("/api/version", auth(s.handleVersion))
	mux.HandleFunc("/api/system", auth(s.handleSystem))
	mux.HandleFunc("/api/usage", auth(s.handleUsage))
	mux.HandleFunc("/api/cores", auth(s.handleCores))
	// 进度查询不走 mutating：安装本身占着 writeMu，进度要是也等
	// 这把锁，就永远查不到进行中的阶段（前端按钮没反馈的根因之一）。
	mux.HandleFunc("/api/cores/progress", auth(s.handleCoreProgress))
	mux.HandleFunc("/api/cores/", auth(s.mutating(s.handleCoreAction)))
	// 在线更新：check 不走 mutating（Forgejo 拉取耗时，不能堵住全部写接口）；
	// apply 走 mutating（二进制替换期间不许其他写操作交错）；progress 不走 mutating。
	mux.HandleFunc("/api/update/check", auth(s.handleUpdateCheck))
	mux.HandleFunc("/api/update/apply", auth(s.mutating(s.handleUpdateApply)))
	mux.HandleFunc("/api/update/progress", auth(s.handleUpdateProgress))
	mux.HandleFunc("/api/inbounds", auth(s.mutating(s.handleInbounds)))
	mux.HandleFunc("/api/inbounds/", auth(s.mutating(s.handleInboundAction)))
	mux.HandleFunc("/api/suggest-port", auth(s.handleSuggestPort))
	mux.HandleFunc("/api/sni-list", auth(s.handleSNIList))
	mux.HandleFunc("/api/sni-random", auth(s.handleSNIRandom))
	mux.HandleFunc("/api/bnodes", auth(s.mutating(s.handleBNodes)))
	mux.HandleFunc("/api/bnodes/", auth(s.mutating(s.handleBNodeAction)))
	mux.HandleFunc("/api/bnodes-latency", auth(s.handleBNodesLatency))
	mux.HandleFunc("/api/chains", auth(s.mutating(s.handleChains)))
	mux.HandleFunc("/api/chains/", auth(s.mutating(s.handleChainAction)))
	mux.HandleFunc("/api/settings", auth(s.mutating(s.handleSettings)))
	mux.HandleFunc("/api/settings/", auth(s.mutating(s.handleSettingsAction)))
	mux.HandleFunc("/api/settings/2fa/status", auth(s.handle2FAStatus))
	mux.HandleFunc("/api/settings/2fa/begin", auth(s.mutating(s.handle2FABegin)))
	mux.HandleFunc("/api/settings/2fa/regenerate", auth(s.mutating(s.handle2FARegenerate)))
	mux.HandleFunc("/api/settings/2fa/enable", auth(s.mutating(s.handle2FAEnable)))
	mux.HandleFunc("/api/settings/2fa/disable", auth(s.mutating(s.handle2FADisable)))
	mux.HandleFunc("/api/settings/2fa/reset", auth(s.mutating(s.handle2FAReset)))
	mux.HandleFunc("/api/settings/2fa/downgrade", auth(s.mutating(s.handle2FADowngrade)))
	return s.panelPathGate(mux)
}

func (s *Server) serveFile(w http.ResponseWriter, r *http.Request, name string) {
	if strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	f, err := s.webFS.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, _ := f.Stat()
	if fi != nil && fi.IsDir() {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(name, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(name, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	}
	// 首页注入当前根路径前缀：前端拼静态地址和 API 地址都靠它；
	// 根目录模式下替换为空串，页面行为与以前完全一致。
	if name == "index.html" {
		b, err := io.ReadAll(f)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		b = bytes.ReplaceAll(b, []byte("__PANEL_BASE__"), []byte(s.panelBase()))
		// 静态资源带版本号：换版后 URL 就变，浏览器不会拿旧 app.js
		// 继续跑（在线升级完前端修复“没生效”多半是这个原因）。
		b = bytes.ReplaceAll(b, []byte("__APP_VERSION__"), []byte(version.Version))
		w.Write(b)
		return
	}
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, name, time.Time{}, rs)
}

// ---------- auth handlers ----------

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Remember bool   `json:"remember"`
	}
	if err := s.readJSON(r, &body); err != nil {
		errJSON(w, 400, "请求格式不对")
		return
	}
	hash, err := s.app.Store.GetUser(body.Username)
	if err != nil {
		// 未知用户也跑一次 bcrypt（dummyHash）：不跑的话未知用户直接 401，
		// 响应时间明显短于已知用户，时序上能枚举账号。
		hash = dummyHash
	}
	if !s.loginAllowed(clientIPOf(r)) {
		errJSON(w, 429, "登录失败次数过多，请 15 分钟后再试")
		return
	}
	// 已损坏的密码哈希（空或非法）：之前超长密码的 bug 会把空哈希
	// 写入库，对什么密码都验不过。明说修复路，别只给“账号或密码不对”
	// 让用户干等。未知用户走 dummyHash（合法哈希），不会误进这条。
	if err == nil && !isBcryptHash(hash) {
		s.loginFailed(clientIPOf(r))
		errJSON(w, 401, "账号密码已损坏，请用本机 CLI（sssingbox admin reset）重置密码")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)) != nil {
		s.loginFailed(clientIPOf(r))
		errJSON(w, 401, "账号或密码不对")
		return
	}
	// 纵深防御：未知用户即使比对通过也不发会话。dummyHash 是随机数，
	// 正常情况下不可能通过；这里是万一哈希逻辑被改坏时的最后一道闸。
	// 注意顺序：bcrypt 必须先跑完再判，不能跳过比对直接 401，否则
	// 未知用户的响应时间明显短于已知用户，时序上能枚举账号。
	if err != nil {
		s.loginFailed(clientIPOf(r))
		errJSON(w, 401, "账号或密码不对")
		return
	}
	s.loginSucceeded(clientIPOf(r))
	// 2FA 第二步：已开通、本机回环之外、且该 IP 没验证过时，不直接发会话，
	// 只给一个 5 分钟有效的临时凭证，前端凭它再交一次动态码。
	// 记住登录的时长选择也带进临时凭证，第二步建会话时再兑现。
	// 密钥损坏时 fail-closed：直接拒绝登录（本机回环除外——SSH 菜单要靠
	// 回环登录来恢复，堵了它就没人能修了）。
	totpState, _ := s.totpSecretRead("totp_secret")
	if !isLoopbackIP(clientIPOf(r)) && totpState == totpSecretBroken {
		errJSON(w, 500, "二次验证密钥损坏，请用本机 SSH 菜单关闭二次验证后重新开通")
		return
	}
	if totpState == totpSecretOK && !isLoopbackIP(clientIPOf(r)) && !s.totpIPVerified(clientIPOf(r)) {
		tmp := randToken()
		s.totpChallengePut(tmp, totpChallenge{username: body.Username, remember: body.Remember, exp: time.Now().Add(5 * time.Minute)})
		okJSON(w, map[string]interface{}{"need_2fa": true, "tmp": tmp})
		return
	}
	// 记住登录：会话与 cookie 一起延长到 30 天（不绑 IP：出口 IP 会变，
	// 绑 IP 反而把人踢下线）；不勾则保持 24 小时。
	exp := time.Now().Add(24 * time.Hour)
	maxAge := 86400
	if body.Remember {
		exp = time.Now().Add(30 * 24 * time.Hour)
		maxAge = 30 * 86400
	}
	tok := randToken()
	s.sessMu.Lock()
	s.sessions[tok] = session{username: body.Username, exp: exp, created: time.Now(), remember: body.Remember}
	s.sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sssingbox_session", Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
	okJSON(w, map[string]interface{}{"username": body.Username})
}

// handleLogin2FA：登录第二步。凭第一步的临时凭证 + 动态码（或恢复码）
// 换正式会话；临时凭证用一次就作废（Take 时直接删），输错码要重新登录
// 领新凭证，不许拿同一个凭证反复试；动态码失败也计入登录限流。
// 成功后该 IP 记为已验证，下次直接登录。
func (s *Server) handleLogin2FA(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var body struct {
		Tmp  string `json:"tmp"`
		Code string `json:"code"`
	}
	if err := s.readJSON(r, &body); err != nil || body.Tmp == "" || body.Code == "" {
		errJSON(w, 400, "请求格式不对")
		return
	}
	if !s.loginAllowed(clientIPOf(r)) {
		errJSON(w, 429, "登录失败次数过多，请 15 分钟后再试")
		return
	}
	ch, ok := s.totpChallengeTake(body.Tmp)
	if !ok {
		errJSON(w, 401, "验证已过期，请重新登录")
		return
	}
	// 密钥损坏时 fail-closed：动态码验不了，恢复码也不放行（第一步已经
	// 拦住了，这里是纵深防御）——恢复路是本机 SSH 菜单。
	totpState, secret := s.totpSecretRead("totp_secret")
	if totpState == totpSecretBroken {
		errJSON(w, 500, "二次验证密钥损坏，请用本机 SSH 菜单关闭二次验证后重新开通")
		return
	}
	passed := false
	if secret != "" && verifyTOTP(secret, body.Code, time.Now()) {
		passed = true
	} else if s.tryRecoveryCode(body.Code) {
		passed = true
	}
	if !passed {
		// 临时凭证在 Take 时已经消费掉，输错码要重新登录领新凭证；
		// 这次失败计入登录限流（5 次锁 15 分钟）。
		s.loginFailed(clientIPOf(r))
		errJSON(w, 401, "动态码不对")
		return
	}
	s.loginSucceeded(clientIPOf(r))
	exp := time.Now().Add(24 * time.Hour)
	maxAge := 86400
	if ch.remember {
		exp = time.Now().Add(30 * 24 * time.Hour)
		maxAge = 30 * 86400
	}
	tok := randToken()
	s.sessMu.Lock()
	s.sessions[tok] = session{username: ch.username, exp: exp, created: time.Now(), remember: ch.remember}
	s.sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sssingbox_session", Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
	s.totpMarkIP(clientIPOf(r))
	okJSON(w, map[string]interface{}{"username": ch.username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("sssingbox_session"); err == nil {
		s.sessMu.Lock()
		delete(s.sessions, c.Value)
		s.sessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "sssingbox_session", Value: "", Path: "/", MaxAge: -1})
	okJSON(w, nil)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	username, ok := s.sessionUser(r)
	if !ok {
		errJSON(w, 401, "未登录")
		return
	}
	okJSON(w, map[string]interface{}{"authed": true, "username": username})
}

// ---------- first-run setup ----------
// 初始设置：只有数据库里一个用户都没有时才能用，建好第一个管理员后
// 这两个接口就再也进不来（已有管理员的面板不受影响）。

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	// version 供更新后轮询比对：光通着不算成功，版本号对上了才算
	// （v1.0.2 修：以前只看通不通，旧进程一直通着，前端谎称更新完成）。
	okJSON(w, map[string]interface{}{"setup_required": s.app.Store.UserCount() == 0, "version": version.Version})
}

func (s *Server) setSession(w http.ResponseWriter, username string) {
	tok := randToken()
	s.sessMu.Lock()
	s.sessions[tok] = session{username: username, exp: time.Now().Add(24 * time.Hour), created: time.Now(), remember: false}
	s.sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sssingbox_session", Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 86400})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	if s.app.Store.UserCount() != 0 {
		errJSON(w, 403, "管理员已存在，无需初始设置")
		return
	}
	var body struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		Password2 string `json:"password2"`
	}
	if err := s.readJSON(r, &body); err != nil {
		errJSON(w, 400, "请求格式不对")
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if body.Username == "" {
		errJSON(w, 400, "用户名不能为空")
		return
	}
	if len(body.Password) < 6 {
		errJSON(w, 400, "密码至少 6 位")
		return
	}
	if body.Password != body.Password2 {
		errJSON(w, 400, "两次输入的密码不一致")
		return
	}
	hash, err := hashPassword(body.Password)
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	if err := s.app.Store.CreateUser(body.Username, string(hash)); err != nil {
		errJSON(w, 500, err.Error())
		return
	}
	// 新装默认根路径：初始设置时才生成（只跑这一次），老面板升级不受影响。
	panelPath := s.app.Store.GetSetting("panel_path")
	if panelPath == "" {
		panelPath = randPanelPath()
		_ = s.app.Store.SetSetting("panel_path", panelPath)
	}
	s.setSession(w, body.Username)
	okJSON(w, map[string]interface{}{"username": body.Username, "panel_path": panelPath})
}

// effectiveAddress：节点链接/订阅用的 host。当前选用证书的首域名就是面板域名，
// 直接用它；没选证书才用服务器 IP（面板域名模块已删，不再有第三个域名来源）。
func (s *Server) effectiveAddress(in *store.Inbound) string {
	if s.certs != nil {
		for _, c := range s.certs.listCerts() {
			if c.Selected && len(c.Domains) > 0 && c.Domains[0] != "" {
				return c.Domains[0]
			}
		}
	}
	return in.Address
}

// ---------- system & usage ----------

// handleVersion：面板自身版本 + 更新源状态。
// 更新源已固定为面板自己的 Forgejo 仓库（cores.PanelRepo），
// 不再靠 update_url 设置项——源一直都在，一键更新始终启用。
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	okJSON(w, map[string]interface{}{
		"version":                  version.Version,
		"update_source_configured": true,
	})
}

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	sys := sysinfo.Snapshot(s.app.Dir)
	sbSt := s.app.Sup.Status("sing-box")
	coreRows, _ := s.app.Store.ListCores()
	verMap := map[string]string{}
	for _, c := range coreRows {
		verMap[c.Name] = c.Version
	}
	okJSON(w, map[string]interface{}{
		"system": sys,
		"cores": map[string]interface{}{
			"sing-box": map[string]interface{}{"running": sbSt.Running, "version": verMap["sing-box"]},
		},
		"panel_uptime_sec": int64(time.Since(s.startedAt).Seconds()),
		"public_ip":        s.app.PublicIP(),
		"public_ipv6":      s.app.PublicIPv6(),
	})
}

func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	inbounds, err := s.app.Store.ListInbounds()
	if err != nil {
		errJSON(w, 500, err.Error())
		return
	}
	today := time.Now().Format("2006-01-02")
	month := time.Now().Format("2006-01")
	daily, _ := s.app.Store.DailyTraffic(today)
	monthly, _ := s.app.Store.MonthlyTraffic(month)
	total, _ := s.app.Store.TotalTraffic()
	rates := s.poller.Realtime()
	type node struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Protocol   string `json:"protocol"`
		Port       int    `json:"port"`
		Address    string `json:"address"`
		SNI        string `json:"sni"`
		Enabled    bool   `json:"enabled"`
		Running    bool   `json:"running"`
		Link       string `json:"link"`
		Link6      string `json:"link6"`
		TmeLink    string `json:"tme_link"`
		TodayUp    int64  `json:"today_up"`
		TodayDown  int64  `json:"today_down"`
		MonthUp    int64  `json:"month_up"`
		MonthDown  int64  `json:"month_down"`
		TotalUp    int64  `json:"total_up"`
		TotalDown  int64  `json:"total_down"`
		RateUp     int64  `json:"rate_up"`
		RateDown   int64  `json:"rate_down"`
		TCPConns   int    `json:"tcp_conns"`
		UDPConns   int    `json:"udp_conns"`
		Online     int    `json:"online"`
		QuotaMode  string `json:"quota_mode"`
		QuotaBytes int64  `json:"quota_bytes"`
	}
	var nodes []node
	var tTodayUp, tTodayDown, tMonthUp, tMonthDown, tTotalUp, tTotalDown int64
	for _, in := range inbounds {
		d := daily[in.ID]
		m := monthly[in.ID]
		t := total[in.ID]
		rt := rates["in-"+in.ID]
		// 停用的节点没有监听：按端口数出来的连接只会是别的程序
		// 的，算到它头上是张冠李戴，直接记 0。
		// -1 是前端约定的“无 UDP”哨兵（非 UDP 协议保持 -1，
		// 前端据此不把该节点计入 UDP 合计），别改成 0。
		tcp, udp := 0, 0
		if in.Enabled {
			tcp = sysinfo.TCPConnections(map[int]bool{in.Port: true})
			if in.Protocol == "hy2" || in.Protocol == "tuic" || in.Protocol == "wireguard" {
				udp = sysinfo.UDPConntrack(map[int]bool{in.Port: true})
			} else {
				// -1 是前端约定的“无 UDP”哨兵：前端据此不把该
				// 节点计入 UDP 合计，改成 0 会让合计行误显示。
				udp = -1
			}
		}
		// 全部节点都跑在 sing-box 里（含 hy2/tuic/naive/wg）。
		running := s.app.Sup.Status("sing-box").Running && in.Enabled
		online := 0
		link, tme := s.inboundLinks(in)
		link6, _ := s.inboundLinks6(in)
		nodes = append(nodes, node{
			ID: in.ID, Name: in.Name, Protocol: in.Protocol, Port: in.Port,
			Address: s.effectiveAddress(in), SNI: in.SNI, Enabled: in.Enabled, Running: running,
			QuotaMode: in.QuotaMode, QuotaBytes: in.QuotaBytes,
			Link: link, Link6: link6, TmeLink: tme,
			TodayUp: d[0], TodayDown: d[1], MonthUp: m[0], MonthDown: m[1],
			TotalUp: t[0], TotalDown: t[1], RateUp: rt[0], RateDown: rt[1],
			TCPConns: tcp, UDPConns: udp, Online: online,
		})
		tTodayUp += d[0]
		tTodayDown += d[1]
		tMonthUp += m[0]
		tMonthDown += m[1]
		tTotalUp += t[0]
		tTotalDown += t[1]
	}
	s.statsMu.Lock()
	statsErr := s.statsErr
	s.statsMu.Unlock()
	okJSON(w, map[string]interface{}{
		"nodes": nodes,
		"totals": map[string]interface{}{
			"today_up": tTodayUp, "today_down": tTodayDown,
			"month_up": tMonthUp, "month_down": tMonthDown,
			"total_up": tTotalUp, "total_down": tTotalDown,
		},
		"stats_error": statsErr,
	})
}

// ---------- cores ----------

func (s *Server) handleCores(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	rows, _ := s.app.Store.ListCores()
	byName := map[string]*store.Core{}
	for _, c := range rows {
		byName[c.Name] = c
	}
	type row struct {
		Name      string `json:"name"`
		Title     string `json:"title"`
		Installed bool   `json:"installed"`
		Version   string `json:"version"`
		Latest    string `json:"latest"`
		HasUpdate bool   `json:"has_update"`
		Running   bool   `json:"running"`
		NoUpdate  bool   `json:"no_update"`
		Note      string `json:"note"`
	}
	var out []row
	for _, d := range cores.Defs() {
		c := byName[d.Name]
		ver, latest := "", ""
		installed := s.app.Mgr.Installed(d.Name)
		if c != nil {
			ver, latest = c.Version, c.Latest
		}
		// 版本兜底：二进制是手动放进来的（没走面板安装），DB 里没有版本号时
		// 直接问二进制自己，问到了就显示并补记到 DB，卡片不再空着。
		if installed && ver == "" && d.Name == "sing-box" {
			if v := cores.DetectSingBoxVersion(s.app.Mgr.BinPath("sing-box")); v != "" {
				ver = v
				rec := &store.Core{Name: d.Name, Version: ver, Installed: true}
				if c != nil {
					rec.Latest, rec.LastCheck = c.Latest, c.LastCheck
				}
				_ = s.app.Store.UpsertCore(rec)
			}
		}
		running := false
		if d.Name == "sing-box" {
			running = s.app.Sup.Status("sing-box").Running
		}
		out = append(out, row{
			Name: d.Name, Title: d.Title, Installed: installed, Version: ver,
			Latest: latest, HasUpdate: installed && latest != "" && latest != ver,
			Running: running, NoUpdate: false, Note: "",
		})
	}
	okJSON(w, out)
}

// handleCoreProgress：返回各内核当前的安装阶段（downloading/installing）。
// 前端安装时每 800ms 查一次，按真实阶段改按钮文案；安装结束后进度自动清掉。
func (s *Server) handleCoreProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	okJSON(w, s.app.Mgr.Progress())
}

func (s *Server) handleCoreAction(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/cores/")
	parts := strings.SplitN(rest, "/", 2)
	name := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	def, ok := cores.DefByName(name)
	if !ok {
		errJSON(w, 404, "未知内核")
		return
	}
	switch action {
	case "versions":
		if r.Method != "GET" {
			errJSON(w, 405, "method")
			return
		}
		// 默认只列正式版；版本弹窗“显示所有内核”时带 ?all=1，含测试版。
		// “检查更新”“更新到最新版”不走这里，仍只认正式版。
		var rels []cores.Release
		var err error
		if r.URL.Query().Get("all") == "1" {
			rels, err = cores.ListReleasesAll(def.Repo)
		} else {
			rels, err = cores.ListReleases(def.Repo)
		}
		if err != nil {
			errJSON(w, 500, "获取版本列表失败："+err.Error())
			return
		}
		var tags []string
		for _, rel := range rels {
			tags = append(tags, rel.Tag)
		}
		okJSON(w, tags)
	case "install":
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		var body struct {
			Version string `json:"version"`
		}
		_ = s.readJSON(r, &body)
		var tag string
		var err error
		tag, err = s.app.Mgr.Install(name, body.Version)
		if err != nil {
			errJSON(w, 500, "下载安装失败："+err.Error())
			return
		}
		recErr := s.app.Store.UpsertCore(&store.Core{Name: name, Version: tag, Installed: true, Latest: tag, LastCheck: time.Now().Unix()})
		if err := s.app.ApplyAll(); err != nil {
			errJSON(w, 500, "安装成功但启动失败："+err.Error())
			return
		}
		if recErr != nil {
			errJSON(w, 500, "安装成功但版本记录失败（下次打开核心卡片会显示旧版本）："+recErr.Error())
			return
		}
		s.poller = stats.NewPoller(s.portTags)
		okJSON(w, map[string]interface{}{"version": tag})
	case "check":
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		rels, err := cores.ListReleases(def.Repo)
		if err != nil {
			errJSON(w, 500, "检查失败："+err.Error())
			return
		}
		latest := ""
		if len(rels) > 0 {
			latest = rels[0].Tag
		}
		rows, _ := s.app.Store.ListCores()
		cur := &store.Core{Name: name}
		for _, c := range rows {
			if c.Name == name {
				cur = c
			}
		}
		cur.Latest = latest
		cur.LastCheck = time.Now().Unix()
		cur.Installed = s.app.Mgr.Installed(name)
		_ = s.app.Store.UpsertCore(cur)
		okJSON(w, map[string]interface{}{"latest": latest})
	case "restart":
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		if err := s.app.ApplyAll(); err != nil {
			errJSON(w, 500, "重启失败："+err.Error())
			return
		}
		okJSON(w, nil)
	case "log":
		if r.Method != "GET" {
			errJSON(w, 405, "method")
			return
		}
		b, err := os.ReadFile(s.app.Mgr.LogPath(name))
		if err != nil {
			okJSON(w, "")
			return
		}
		lines := strings.Split(string(b), "\n")
		if len(lines) > 100 {
			lines = lines[len(lines)-100:]
		}
		okJSON(w, strings.Join(lines, "\n"))
	case "clear-log":
		// 手动清理：立即清空该内核的日志文件。运行中的核心不受影响，
		// 监督器持有 O_APPEND 句柄，后续日志写到清空后的文件开头。
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		s.app.Sup.ClearLog(name)
		okJSON(w, nil)
	default:
		errJSON(w, 404, "未知操作")
	}
}

// ---------- inbounds ----------

func (s *Server) inboundLinks(in *store.Inbound) (link, tme string) {
	addr := s.effectiveAddress(in)
	switch in.Protocol {
	case "vless":
		var cfg proxy.VLESSConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.VLESSLink(cfg.UUID, addr, in.Port, in.SNI, cfg, in.Name), ""
	case "hy2":
		var cfg proxy.Hy2Config
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.Hy2Link(addr, in.Port, in.SNI, cfg, in.Name), ""
	case "vmess":
		var cfg proxy.VMessConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.VMessLink(addr, in.Port, cfg, in.Name, in.SNI), ""
	case "ss":
		var cfg proxy.SSConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.SSLink(addr, in.Port, cfg, in.Name), ""
	case "socks":
		var cfg proxy.SocksConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.SocksLink(addr, in.Port, cfg, in.Name), ""
	case "http":
		var cfg proxy.HTTPConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.HTTPLink(addr, in.Port, cfg, in.Name), ""
	case "trojan":
		var cfg proxy.TrojanConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.TrojanLink(addr, in.Port, in.SNI, cfg, in.Name), ""
	case "wireguard":
		var cfg proxy.WGConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.WGClientConfig(addr, in.Port, cfg, in.Name), ""
	case "tuic":
		var cfg proxy.TUICConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.TUICLink(addr, in.Port, in.SNI, cfg, in.Name), ""
	case "anytls":
		var cfg proxy.AnyTLSConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.AnyTLSLink(addr, in.Port, in.SNI, cfg, in.Name), ""
	case "naive":
		var cfg proxy.NaiveConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.NaiveLink(cfg, in.Port), ""
	case "snell":
		var cfg proxy.SnellConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.SnellLink(addr, in.Port, cfg, in.Name), ""
	case "shadowtls":
		var cfg proxy.ShadowTLSConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.ShadowTLSClientJSON(addr, in.Port, cfg, in.Name), ""
	}
	return "", ""
}

// inboundLinks6 builds the same node link as inboundLinks, but over the
// server's public IPv6 address. It returns "" when the server has no
// public IPv6, and for domain-based nodes (CF/TLS modes, Naive) whose link
// host is a domain (not a server IP) — those need no separate IPv6 link. URL-style links get the
// bracketed host ([ipv6]:port); VMess "add" takes the
// bare address, as that format requires.
// inboundListensV6：该入站是否真的在双栈上监听。WireGuard endpoint
// 不写 listen、天然双 socket，恒为真；其余 sing-box 入站空 Listen 表示走默认 "::"（双栈）。
func inboundListensV6(in *store.Inbound) bool {
	if in.Protocol == "wireguard" {
		return true
	}
	var listen string
	switch in.Protocol {
	case "vless":
		var cfg proxy.VLESSConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		listen = cfg.Listen
	case "vmess":
		var cfg proxy.VMessConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		listen = cfg.Listen
	case "trojan":
		var cfg proxy.TrojanConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		listen = cfg.Listen
	case "ss":
		var cfg proxy.SSConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		listen = cfg.Listen
	case "socks":
		var cfg proxy.SocksConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		listen = cfg.Listen
	case "http":
		var cfg proxy.HTTPConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		listen = cfg.Listen
	case "hy2":
		var cfg proxy.Hy2Config
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		listen = cfg.Listen
	case "tuic":
		var cfg proxy.TUICConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		listen = cfg.Listen
	case "anytls":
		var cfg proxy.AnyTLSConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		listen = cfg.Listen
	case "naive":
		var cfg proxy.NaiveConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		listen = cfg.Listen
	case "snell":
		var cfg proxy.SnellConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		listen = cfg.Listen
	case "shadowtls":
		var cfg proxy.ShadowTLSConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		listen = cfg.Listen
	default:
		return false
	}
	return listen == "" || listen == "::"
}

func (s *Server) inboundLinks6(in *store.Inbound) (link, tme string) {
	ip6 := s.app.PublicIPv6()
	if ip6 == "" {
		return "", ""
	}
	// 只给真双栈监听的入站发 v6 链接：以前不管监听是什么都发，v4-only
	// 节点的 link6 根本连不上，纯误导。空 Listen 表示走默认 "::"（双栈）。
	if !inboundListensV6(in) {
		return "", ""
	}
	b := ip6
	// v6 链接名字后加 -ipv6：订阅里 v4/v6 两行同名，客户端里分不清。
	name := in.Name + "-ipv6"
	switch in.Protocol {
	case "vless":
		var cfg proxy.VLESSConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		if cfg.Mode == "ws" || cfg.Mode == "h2" || cfg.Mode == "httpupgrade" {
			return "", ""
		}
		return proxy.VLESSLink(cfg.UUID, b, in.Port, in.SNI, cfg, name), ""
	case "hy2":
		var cfg proxy.Hy2Config
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.Hy2Link(b, in.Port, in.SNI, cfg, name), ""
	case "vmess":
		var cfg proxy.VMessConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		if cfg.Mode == "cf" || cfg.Mode == "http" || cfg.Mode == "quic" || cfg.Mode == "h2" || cfg.Mode == "httpupgrade" {
			return "", ""
		}
		return proxy.VMessLink(ip6, in.Port, cfg, name, in.SNI), ""
	case "ss":
		var cfg proxy.SSConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.SSLink(b, in.Port, cfg, name), ""
	case "socks":
		var cfg proxy.SocksConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.SocksLink(b, in.Port, cfg, name), ""
	case "http":
		var cfg proxy.HTTPConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.HTTPLink(b, in.Port, cfg, name), ""
	case "trojan":
		var cfg proxy.TrojanConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		if cfg.Mode == "cf" || cfg.Mode == "h2" || cfg.Mode == "httpupgrade" {
			return "", ""
		}
		return proxy.TrojanLink(b, in.Port, in.SNI, cfg, name), ""
	case "wireguard":
		var cfg proxy.WGConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.WGClientConfig(b, in.Port, cfg, name), ""
	case "tuic":
		var cfg proxy.TUICConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.TUICLink(b, in.Port, in.SNI, cfg, name), ""
	case "anytls":
		var cfg proxy.AnyTLSConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.AnyTLSLink(b, in.Port, in.SNI, cfg, name), ""
	case "naive":
		// Naive 链接 host 是真实域名，不需要单独的 IPv6 链接。
		return "", ""
	case "snell":
		var cfg proxy.SnellConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.SnellLink(b, in.Port, cfg, name), ""
	case "shadowtls":
		var cfg proxy.ShadowTLSConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.ShadowTLSClientJSON(b, in.Port, cfg, name), ""
	}
	return "", ""
}

func (s *Server) handleInbounds(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		list, _ := s.app.Store.ListInbounds()
		type row struct {
			*store.Inbound
			Link    string `json:"link"`
			Link6   string `json:"link6"`
			TmeLink string `json:"tme_link"`
		}
		out := []row{}
		for _, in := range list {
			link, tme := s.inboundLinks(in)
			link6, _ := s.inboundLinks6(in)
			out = append(out, row{Inbound: in, Link: link, Link6: link6, TmeLink: tme})
		}
		okJSON(w, out)
	case "POST":
		var body struct {
			Protocol   string                 `json:"protocol"`
			Port       int                    `json:"port"`
			Name       string                 `json:"name"`
			Address    string                 `json:"address"`
			SNI        string                 `json:"sni"`
			Advanced   map[string]interface{} `json:"advanced"`
			QuotaMode  string                 `json:"quota_mode"`
			QuotaBytes int64                  `json:"quota_bytes"`
		}
		if err := s.readJSON(r, &body); err != nil {
			errJSON(w, 400, "请求格式不对")
			return
		}
		if body.QuotaMode != "" && body.QuotaMode != "total" && body.QuotaMode != "down" {
			errJSON(w, 400, "流量限额模式不对")
			return
		}
		if body.SNI != "" && !validSNI(body.SNI) {
			errJSON(w, 400, "伪装域名格式不对：只能是合法域名或 IP，不能含空格、中文或特殊字符")
			return
		}
		if body.SNI != "" && proxy.IsRealityMode(body.Protocol, advancedMode(body.Advanced)) {
			if blocked, err := proxy.SNIBehindCloudflare(body.SNI); err != nil {
				errJSON(w, 400, "伪装域名解析失败，无法确认是否套 Cloudflare，请检查域名后重试")
				return
			} else if blocked {
				errJSON(w, 400, "伪装域名套了 Cloudflare，不能用作 Reality 伪装，换一个")
				return
			}
		}
		if body.QuotaMode == "" {
			body.QuotaBytes = 0
		}
		// 限额校验必须在 createInbound 之前：createInbound 内部会先落盘一次，
		// 校验放后面时 400 照样返回、节点却已入库（回归复测抓到的真 bug：
		// quota 0/-5 返回 400，T-Q 节点却留在了库里）。
		// 限额 <=0 时 checkQuota 又把它当无限制跳过，等于假限额。
		if body.QuotaMode != "" && body.QuotaBytes <= 0 {
			errJSON(w, 400, "流量限额必须大于 0（不限量请把模式留空）")
			return
		}
		if core := requiredCore(body.Protocol); core != "" && !s.app.Mgr.Installed(core) {
			errJSON(w, 400, core+" 内核还没安装：先去“系统状态”页的内核卡片安装 "+core+"，装好再创建节点")
			return
		}
		in, err := s.createInbound(body.Protocol, body.Port, body.Name, body.Address, body.SNI, body.Advanced)
		if err == nil {
			in.QuotaMode = body.QuotaMode
			in.QuotaBytes = body.QuotaBytes
			if in.QuotaMode == "" {
				in.QuotaBytes = 0
			}
			err = s.app.Store.UpsertInbound(in)
		}
		if err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		if err := s.app.ApplyAll(); err != nil {
			errJSON(w, 500, "节点已保存但启动失败："+err.Error())
			return
		}
		link, tme := s.inboundLinks(in)
		link6, _ := s.inboundLinks6(in)
		okJSON(w, map[string]interface{}{"inbound": in, "link": link, "link6": link6, "tme_link": tme})
	default:
		errJSON(w, 405, "method")
	}
}

// advancedMode：创建/编辑节点请求里 advanced.mode（前端传的传输模式）。
func advancedMode(adv map[string]interface{}) string {
	if adv == nil {
		return ""
	}
	m, _ := adv["mode"].(string)
	return m
}

// configMode：已存节点的传输模式（编辑时 advanced 没传 mode 就用它判断）。
func configMode(protocol, configJSON string) string {
	switch protocol {
	case "vless":
		var cfg proxy.VLESSConfig
		_ = json.Unmarshal([]byte(configJSON), &cfg)
		return cfg.Mode
	case "trojan":
		var cfg proxy.TrojanConfig
		_ = json.Unmarshal([]byte(configJSON), &cfg)
		return cfg.Mode
	}
	return ""
}

// validSNI：SNI 必须是合法主机名或 IP 字面量。面板以前照单全收，
// "a b.com"、中文域名、300 字符这种垃圾 SNI 也能建成“跑着但永远
// 连不上”的节点（sing-box check 照过，TLS 握手时才死），行为测试
// 1.5 实测确认。空串不由这里判（创建时部分协议会自动补 SNI）。
func validSNI(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func (s *Server) suggestPort(protocol string, mode ...string) (int, string) {
	tcpUsed := sysinfo.ListeningTCPPorts()
	udpUsed := sysinfo.BoundUDPPorts()
	list, _ := s.app.Store.ListInbounds()
	for _, in := range list {
		// TCP 与 UDP 端口分开编号：节点端口只记到自己那边的表里，
		// 别让面板里的 UDP 节点拦住 TCP 建议（或反过来）。
		if store.UDPOnlyProtocol(in.Protocol) {
			udpUsed[in.Port] = true
		} else {
			tcpUsed[in.Port] = true
		}
		// 统计端口也要预留：HY2 的 StatsPort 只在进程跑着时才占
		// 系统端口；节点停着时 ListeningTCPPorts 里没有它，
		// suggestPort 若把 19000-19999 段内的统计端口建议出去，
		// HY2 下次启动就绑不上统计端口（用量直接断掉）。
		// 兜底范围也一样：10000-19999 的 fallback 会扫进统计段。
		var sp struct {
			StatsPort int `json:"stats_port"`
		}
		if in.Protocol == "hy2" && json.Unmarshal([]byte(in.Config), &sp) == nil && sp.StatsPort > 0 {
			tcpUsed[sp.StatsPort] = true
		}
		// ShadowTLS 内层 SS 的回环端口也要预留：suggestPort 若把它
		// 建议出去，新节点一启用就和内层 SS 抢端口。
		if in.Protocol == "shadowtls" {
			var stc proxy.ShadowTLSConfig
			if json.Unmarshal([]byte(in.Config), &stc) == nil && stc.InnerPort > 0 {
				tcpUsed[stc.InnerPort] = true
			}
		}
	}
	// panel's own ports
	if p := s.app.Store.GetSetting("panel_port"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			tcpUsed[n] = true
		}
	}
	// sing-box 没有 xray 那种 API 端口，不再预留 10085；中转端口 18099 也随旧架构退役。
	free := func(p int) bool {
		// TCP 与 UDP 端口分开编号（见 store.UDPOnlyProtocol）：UDP 协议只看
		// UDP 有没有被占，TCP 协议只看 TCP，别拿另一边的占用误拦。
		if store.UDPOnlyProtocol(protocol) {
			return !udpUsed[p]
		}
		return !tcpUsed[p]
	}
	// VMess/Trojan 的 CF 模式例外：源站端口必须是 CF 允许的代理端口，
	// 否则 CF 根本不转发，节点就是死的。
	if (protocol == "vmess" || protocol == "trojan") && len(mode) > 0 && mode[0] == "cf" {
		for _, p := range proxy.CFPorts {
			if free(p) {
				return p, fmt.Sprintf("CF 模式：源站端口必须是 CF 允许的端口，建议 %d", p)
			}
		}
		return 0, "CF 允许的端口都被占用了"
	}
	// 顺序是抗封禁的取舍，不是随便排的：TCP 协议 443 最像正常 HTTPS，
	// 8443 是次选；两个都被占才去高位随机端口，常用端口
	// （2053/2083/2096 这些代理圈熟面孔）不再主动建议，
	// 免得一眼就被认出来是代理。
	// HY2/TUIC 是 UDP/QUIC：UDP 443 是标准 QUIC 端口，国内运营商会拦，
	// 默认不建议 443；先给 8443，8443 被占才去高位随机端口。
	if protocol == "hy2" || protocol == "tuic" {
		if free(8443) {
			return 8443, "8443 端口可用"
		}
	} else {
		if free(443) {
			return 443, "443 端口可用"
		}
		if free(8443) {
			if o := portOccupier(443); o != "" {
				return 8443, fmt.Sprintf("443 已被 %s 占用，建议 8443", o)
			}
			return 8443, "443 已被占用，建议 8443"
		}
	}
	for i := 0; i < 200; i++ {
		var rb [2]byte
		_, _ = rand.Read(rb[:])
		p := 50000 + (int(rb[0])<<8|int(rb[1]))%10000
		if free(p) {
			if protocol == "hy2" || protocol == "tuic" {
				return p, fmt.Sprintf("8443 已被占用，建议高位随机端口 %d", p)
			}
			return p, fmt.Sprintf("443/8443 都被占用，建议高位随机端口 %d", p)
		}
	}
	for p := 10000; p < 20000; p++ {
		if free(p) {
			return p, fmt.Sprintf("常用端口都被占用，建议 %d", p)
		}
	}
	return 0, "没有可用端口"
}

func portOccupier(port int) string {
	out, err := exec.Command("ss", "-tlnp").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, ":"+strconv.Itoa(port)+" ") && !strings.Contains(line, ":"+strconv.Itoa(port)+"\t") {
			continue
		}
		// users:(("nginx",pid=...,fd=...))
		if i := strings.Index(line, `users:(("`); i >= 0 {
			rest := line[i+len(`users:(("`):]
			if j := strings.Index(rest, `"`); j > 0 {
				return rest[:j]
			}
		}
	}
	return ""
}

// requiredCore：每种入站协议跑在哪个内核上。全部协议都跑在 sing-box；
// 以前创建时不拦，节点存进去了却永远是“核心未启动”，用户还以为建好了——
// 所以创建和克隆时先拦，缺核就明说去装。
func requiredCore(protocol string) string {
	switch protocol {
	case "vless", "vmess", "ss", "socks", "http", "trojan", "wireguard", "hy2", "tuic", "anytls", "naive", "snell", "shadowtls":
		return "sing-box"
	}
	return ""
}

// normalizeVLESS/normalizeVMess/normalizeTrojan：创建与编辑共用的按模式归一化。
// 空 Mode 按默认档处理；非法 Mode 直接报错，绝不静默改写成默认档
// （以前非法值被悄悄改成 Reality/TCP，服务端与用户意图脱节，链接还跟着错）。
// 编辑时复用同一函数：模式切换后旧档残留字段（WS 的 Domain/Path、
// Reality 的密钥/Dest）按新档重算，不再出现“切回 Reality 还留着 WS 路径”。
func (s *Server) normalizeVLESS(cfg *proxy.VLESSConfig, sni string) error {
	switch cfg.Mode {
	case "ws", "h2", "httpupgrade":
		if cfg.Domain == "" {
			cfg.Domain = sni
		}
		if cfg.Path == "" {
			cfg.Path = "/" + randHexID() + randHexID()
		}
	case "", "reality":
		cfg.Mode = "reality"
		cfg.Domain = ""
		cfg.Path = ""
		if cfg.PrivateKey == "" || cfg.PublicKey == "" {
			priv, pub, err := genRealityKeypair()
			if err != nil {
				return fmt.Errorf("生成 Reality 密钥失败：%w", err)
			}
			cfg.PrivateKey, cfg.PublicKey = priv, pub
		}
		if cfg.Dest == "" {
			cfg.Dest = sni + ":443"
		}
	default:
		return fmt.Errorf("不支持的 VLESS 传输模式：%s", cfg.Mode)
	}
	return nil
}

func (s *Server) normalizeVMess(cfg *proxy.VMessConfig, sni string, port int) error {
	switch cfg.Mode {
	case "cf":
		cfg.Domain = sni
		if cfg.Path == "" {
			cfg.Path = "/" + randHexID() + randHexID()
		}
		if !proxy.IsCFPort(port) {
			return fmt.Errorf("VMess CF 模式源站端口必须是 CF 允许的端口：443/2053/2083/2087/2096/8443，当前 %d 不行", port)
		}
	case "http", "quic", "h2", "httpupgrade":
		cfg.Domain = sni
		if cfg.Path == "" {
			cfg.Path = "/" + randHexID() + randHexID()
		}
	case "", "tcp":
		cfg.Mode = "tcp"
		cfg.Domain = ""
		cfg.Path = ""
	default:
		return fmt.Errorf("不支持的 VMess 传输模式：%s", cfg.Mode)
	}
	return nil
}

func (s *Server) normalizeTrojan(cfg *proxy.TrojanConfig, sni string, port int) error {
	switch cfg.Mode {
	case "cf":
		cfg.Domain = sni
		if cfg.Path == "" {
			cfg.Path = "/" + randHexID() + randHexID()
		}
		if !proxy.IsCFPort(port) {
			return fmt.Errorf("Trojan CF 模式源站端口必须是 CF 允许的端口：443/2053/2083/2087/2096/8443，当前 %d 不行", port)
		}
	case "h2", "httpupgrade":
		cfg.Domain = sni
		if cfg.Path == "" {
			cfg.Path = "/" + randHexID() + randHexID()
		}
	case "", "reality":
		cfg.Mode = "reality"
		cfg.Domain = ""
		cfg.Path = ""
		if cfg.PrivateKey == "" || cfg.PublicKey == "" {
			priv, pub, err := genRealityKeypair()
			if err != nil {
				return fmt.Errorf("生成 Reality 密钥失败：%w", err)
			}
			cfg.PrivateKey, cfg.PublicKey = priv, pub
		}
		if cfg.Dest == "" {
			cfg.Dest = sni + ":443"
		}
	default:
		return fmt.Errorf("不支持的 Trojan 传输模式：%s", cfg.Mode)
	}
	return nil
}

// normalizeSnell：创建与编辑共用。Version 非 5/6 直接报错，
// 不静默改回 5（用户意图与服务端脱节）；v6 的 PSK 必须
// 12-255 字节，短了直接报错，不自动拉长（拉长等于换密码，
// 旧链接悄悄失效）。
func (s *Server) normalizeSnell(cfg *proxy.SnellConfig) error {
	switch cfg.Version {
	case 0:
		cfg.Version = 5
	case 5, 6:
	default:
		return fmt.Errorf("不支持的 Snell 版本：%d（只支持 5 / 6）", cfg.Version)
	}
	if cfg.PSK == "" {
		return fmt.Errorf("Snell 必须设置 PSK")
	}
	if cfg.Version == 5 {
		if cfg.ObfsMode == "" {
			cfg.ObfsMode = "http"
		}
		if cfg.ObfsMode != "none" && cfg.ObfsMode != "http" {
			return fmt.Errorf("不支持的 Snell 混淆模式：%s（只支持 none / http）", cfg.ObfsMode)
		}
		if cfg.ObfsMode == "http" && cfg.ObfsHost == "" {
			cfg.ObfsHost = "bing.com"
		}
	} else {
		if len(cfg.PSK) < 12 || len(cfg.PSK) > 255 {
			return fmt.Errorf("Snell v6 的 PSK 必须是 12-255 字节，当前 %d 字节", len(cfg.PSK))
		}
		if cfg.Mode == "" {
			cfg.Mode = "default"
		}
		if cfg.Mode != "default" && cfg.Mode != "unshaped" && cfg.Mode != "unsafe-raw" {
			return fmt.Errorf("不支持的 Snell v6 模式：%s", cfg.Mode)
		}
	}
	return nil
}

// normalizeShadowTLS：创建与编辑共用。版本只认 3；
// strict_mode 强制 true（最佳预设，不开放关闭）；
// 握手站必须是合法域名；内层 SS 缺失时按默认补齐。
func (s *Server) normalizeShadowTLS(cfg *proxy.ShadowTLSConfig) error {
	cfg.Version = 3
	cfg.StrictMode = true
	if cfg.Password == "" {
		return fmt.Errorf("ShadowTLS 必须设置密码")
	}
	if cfg.Handshake == "" {
		cfg.Handshake = "gateway.icloud.com"
	}
	if !validSNI(cfg.Handshake) {
		return fmt.Errorf("ShadowTLS 握手站域名格式不对：%s", cfg.Handshake)
	}
	if cfg.SSMethod == "" {
		cfg.SSMethod = "2022-blake3-aes-128-gcm"
	}
	if cfg.SSPassword == "" {
		cfg.SSPassword = proxy.SSKey(cfg.SSMethod)
	}
	return nil
}

func (s *Server) createInbound(protocol string, port int, name, address, sni string, advanced map[string]interface{}) (*store.Inbound, error) {
	switch protocol {
	case "vless", "hy2", "vmess", "ss", "socks", "http", "trojan", "wireguard", "tuic", "anytls", "naive", "snell", "shadowtls":
	default:
		return nil, fmt.Errorf("不支持的协议：%s", protocol)
	}
	if port == 0 {
		mode := ""
		if protocol == "vmess" || protocol == "trojan" {
			if m, ok := advanced["mode"].(string); ok {
				mode = m
			}
		}
		p, _ := s.suggestPort(protocol, mode)
		if p == 0 {
			return nil, fmt.Errorf("没有可用端口")
		}
		port = p
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("端口范围 1-65535")
	}
	if s.app.Store.PortInUse(port, protocol, "") {
		return nil, fmt.Errorf("端口 %d 已被本面板其他节点占用", port)
	}
	tcpUsed := sysinfo.ListeningTCPPorts()
	if !store.UDPOnlyProtocol(protocol) && tcpUsed[port] {
		return nil, fmt.Errorf("端口 %d 已被系统其他程序占用", port)
	}
	if protocol == "hy2" && sysinfo.BoundUDPPorts()[port] {
		return nil, fmt.Errorf("端口 %d 的 UDP 已被占用（Hy2 需要 UDP）", port)
	}
	if protocol == "tuic" && sysinfo.BoundUDPPorts()[port] {
		return nil, fmt.Errorf("端口 %d 的 UDP 已被占用（TUIC 需要 UDP）", port)
	}
	if protocol == "wireguard" && sysinfo.BoundUDPPorts()[port] {
		return nil, fmt.Errorf("端口 %d 的 UDP 已被占用（WireGuard 走 UDP）", port)
	}
	if name == "" {
		short := map[string]string{"vless": "VLESS", "hy2": "HY2", "vmess": "VMESS", "ss": "SS", "socks": "SOCKS", "http": "HTTP", "trojan": "TROJAN", "wireguard": "WG", "tuic": "TUIC", "anytls": "ANYTLS", "naive": "NAIVE", "snell": "SNELL", "shadowtls": "SHADOWTLS"}[protocol]
		name = fmt.Sprintf("%s-%d", short, port)
	}
	if address == "" {
		address = s.app.PublicIP()
		if address == "" {
			return nil, fmt.Errorf("无法自动获取公网 IP，请手动填写节点地址")
		}
	}
	// 只有需要域名的协议才自动给 SNI：SS/SOCKS/HTTP/VMess-TCP
	// 的 SNI 毫无意义，留空；VMess/Trojan 的 CF 模式域名是必填项，
	// 没填直接报错，不拿精选清单糊弄。
	vmessCF := protocol == "vmess"
	if vmessCF {
		if m, ok := advanced["mode"].(string); ok && m == "cf" {
			if sni == "" {
				return nil, fmt.Errorf("VMess CF 模式需要填写已接入 Cloudflare 的域名")
			}
		} else {
			vmessCF = false
		}
	}
	trojanCF := protocol == "trojan"
	if trojanCF {
		if m, ok := advanced["mode"].(string); ok && m == "cf" {
			if sni == "" {
				return nil, fmt.Errorf("Trojan CF 模式需要填写已接入 Cloudflare 的域名")
			}
		} else {
			trojanCF = false
		}
	}
	// Naive 必须用真实域名 + CA 证书：没域名直接报错，不拿精选清单糊弄。
	if protocol == "naive" && sni == "" {
		return nil, fmt.Errorf("Naive 需要填写真实域名（CA 证书上的域名，解析到本机）")
	}
	// TLS 档（VLESS WS/H2/HTTPUpgrade、Trojan H2/HTTPUpgrade）留空域名时不再拿
	// Reality 伪装清单自动填 SNI：伪装域名不指向本机，填进链接就成了死链；
	// 留空时链接改用服务器地址（见各 Link builder 的 address 回退），同样能通。
	tlsMode := false
	if m, ok := advanced["mode"].(string); ok {
		if protocol == "vless" && (m == "ws" || m == "h2" || m == "httpupgrade") {
			tlsMode = true
		}
		if protocol == "trojan" && (m == "h2" || m == "httpupgrade") {
			tlsMode = true
		}
	}
	if sni == "" && !tlsMode && (protocol == "vless" || protocol == "hy2" || protocol == "tuic" || protocol == "anytls" || (protocol == "trojan" && !trojanCF)) {
		sni = proxy.RecommendSNI("").Domain
	}
	id := s.uniqueID(func(id string) bool { _, err := s.app.Store.GetInbound(id); return err == nil })
	now := time.Now().Unix()
	in := &store.Inbound{
		ID: id, Name: name, Protocol: protocol, Port: port,
		Address: address, SNI: sni, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	switch protocol {
	case "vless":
		cfg := proxy.DefaultVLESS()
		mergeAdvanced(&cfg, advanced)
		if err := s.normalizeVLESS(&cfg, sni); err != nil {
			return nil, err
		}
		in.Config = store.MustJSON(cfg)
	case "hy2":
		cfg := proxy.DefaultHy2()
		mergeAdvanced(&cfg, advanced)
		// sing-box Hy2 没有 hysteria 二进制的 stats 端口，不再分配 StatsPort/StatsSecret。
		if cfg.HopPorts != "" {
			if err := proxy.ValidateHopPorts(cfg.HopPorts, sysinfo.BoundUDPPorts(), port); err != nil {
				return nil, err
			}
		}
		in.Config = store.MustJSON(cfg)
	case "vmess":
		cfg := proxy.DefaultVMess()
		mergeAdvanced(&cfg, advanced)
		if err := s.normalizeVMess(&cfg, sni, port); err != nil {
			return nil, err
		}
		in.Config = store.MustJSON(cfg)
	case "ss":
		cfg := proxy.DefaultSS()
		mergeAdvanced(&cfg, advanced)
		// 2022 方法的密码必须是对应长度的密钥：用户没填密码
		// 就按最终选的方法重生成，不能拿默认方法的密钥凑合，
		// 否则 xray 会因为密钥长度不对起不来。
		if pw, ok := advanced["password"].(string); !ok || pw == "" {
			cfg.Password = proxy.SSKey(cfg.Method)
		}
		in.Config = store.MustJSON(cfg)
	case "socks":
		cfg := proxy.DefaultSocks()
		mergeAdvanced(&cfg, advanced)
		// 空凭证绝不能入库：以前只在 Apply 层拦，节点已保存为启用态，
		// 之后每次 Apply 都失败，等于毒丸；创建时直接 400。
		if cfg.User == "" || cfg.Pass == "" {
			return nil, fmt.Errorf("SOCKS 节点必须设置用户名和密码（空凭证会变成无认证公开代理）")
		}
		in.Config = store.MustJSON(cfg)
	case "http":
		cfg := proxy.DefaultHTTP()
		mergeAdvanced(&cfg, advanced)
		if cfg.User == "" || cfg.Pass == "" {
			return nil, fmt.Errorf("HTTP 节点必须设置用户名和密码（空凭证会变成无认证公开代理）")
		}
		in.Config = store.MustJSON(cfg)
	case "trojan":
		cfg := proxy.DefaultTrojan()
		mergeAdvanced(&cfg, advanced)
		if err := s.normalizeTrojan(&cfg, sni, port); err != nil {
			return nil, err
		}
		in.Config = store.MustJSON(cfg)
	case "tuic":
		cfg := proxy.DefaultTUIC()
		mergeAdvanced(&cfg, advanced)
		in.Config = store.MustJSON(cfg)
	case "anytls":
		cfg := proxy.DefaultAnyTLS()
		mergeAdvanced(&cfg, advanced)
		in.Config = store.MustJSON(cfg)
	case "naive":
		cfg := proxy.DefaultNaive()
		mergeAdvanced(&cfg, advanced)
		// 域名 = SNI（真实域名，CA 证书上的名字）；证书建好节点后单独上传，
		// 没证书时 Apply 会明说缺证书，不会偷偷自签。
		cfg.Domain = sni
		in.Config = store.MustJSON(cfg)
	case "wireguard":
		cfg := proxy.DefaultWG()
		mergeAdvanced(&cfg, advanced)
		if cfg.ServerPriv == "" || cfg.ServerPub == "" || cfg.ClientPriv == "" || cfg.ClientPub == "" {
			return nil, fmt.Errorf("WireGuard 密钥生成失败，请重试")
		}
		if cfg.ClientIP == "" {
			cfg.ClientIP = "10.0.0.2/32"
		}
		if _, _, err := net.ParseCIDR(cfg.ClientIP); err != nil {
			return nil, fmt.Errorf("WireGuard 客户端 IP 不是合法 CIDR：%s", cfg.ClientIP)
		}
		in.Config = store.MustJSON(cfg)
	case "snell":
		cfg := proxy.DefaultSnell()
		mergeAdvanced(&cfg, advanced)
		if err := s.normalizeSnell(&cfg); err != nil {
			return nil, err
		}
		in.Config = store.MustJSON(cfg)
	case "shadowtls":
		cfg := proxy.DefaultShadowTLS()
		mergeAdvanced(&cfg, advanced)
		if err := s.normalizeShadowTLS(&cfg); err != nil {
			return nil, err
		}
		if cfg.InnerPort == 0 {
			cfg.InnerPort = s.allocInnerPort()
			if cfg.InnerPort == 0 {
				return nil, fmt.Errorf("没有可用的内层端口（20000-20999 都被占用了）")
			}
		}
		in.Config = store.MustJSON(cfg)
	}
	if protocol == "naive" {
		// 没证书的节点先停用：上传证书时自动启用，避免一创建就启动失败。
		in.Enabled = false
	}
	if err := s.app.Store.UpsertInbound(in); err != nil {
		return nil, err
	}
	return in, nil
}

func randHexID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// uniqueID：生成库里不存在的 id。以前 4 字节 + 从不判重，Upsert 碰撞
// 即无声覆盖旧节点（用量、链式引用全被新节点继承）。
func (s *Server) uniqueID(exists func(string) bool) string {
	for i := 0; i < 100; i++ {
		id := randHexID()
		if !exists(id) {
			return id
		}
	}
	// 64 位空间里 100 次都撞上基本不可能；真撞上也返回新 id 报错给上层，
	// 不再静默复用旧 id。
	return randHexID()
}

func randLetters(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

// allocStatsPort picks a free loopback port in 19000-19999 for hy2
// stats endpoints (trafficStats / prometheus), avoiding DB and system use.
func (s *Server) allocStatsPort() int {
	used := map[int]bool{}
	for p := range sysinfo.ListeningTCPPorts() {
		used[p] = true
	}
	inbounds, _ := s.app.Store.ListInbounds()
	for _, in := range inbounds {
		switch in.Protocol {
		case "hy2":
			var cfg proxy.Hy2Config
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			if cfg.StatsPort > 0 {
				used[cfg.StatsPort] = true
			}
		}
	}
	for p := 19000; p < 20000; p++ {
		if !used[p] {
			return p
		}
	}
	return 0
}

// allocInnerPort：给 ShadowTLS 内层 SS 分一个回环端口（20000-20999）。
// 内层端口绝不能和节点端口、HY2 统计端口撞上，也不能被
// suggestPort 再建议出去（见 suggestPort 里的预留）。
func (s *Server) allocInnerPort() int {
	used := map[int]bool{}
	for p := range sysinfo.ListeningTCPPorts() {
		used[p] = true
	}
	inbounds, _ := s.app.Store.ListInbounds()
	for _, in := range inbounds {
		used[in.Port] = true
		switch in.Protocol {
		case "hy2":
			var cfg proxy.Hy2Config
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			if cfg.StatsPort > 0 {
				used[cfg.StatsPort] = true
			}
		case "shadowtls":
			var cfg proxy.ShadowTLSConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			if cfg.InnerPort > 0 {
				used[cfg.InnerPort] = true
			}
		}
	}
	for p := 20000; p < 21000; p++ {
		if !used[p] {
			return p
		}
	}
	return 0
}

func mergeAdvanced(dst interface{}, advanced map[string]interface{}) {
	if len(advanced) == 0 {
		return
	}
	b, _ := json.Marshal(advanced)
	_ = json.Unmarshal(b, dst)
}

func (s *Server) handleInboundAction(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/inbounds/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	in, err := s.app.Store.GetInbound(id)
	if err != nil {
		errJSON(w, 404, "节点不存在")
		return
	}
	switch action {
	case "":
		switch r.Method {
		case "GET":
			link, tme := s.inboundLinks(in)
			link6, _ := s.inboundLinks6(in)
			okJSON(w, map[string]interface{}{"inbound": in, "link": link, "link6": link6, "tme_link": tme})
		case "PUT":
			var body struct {
				Name       *string                `json:"name"`
				Address    *string                `json:"address"`
				SNI        *string                `json:"sni"`
				Port       *int                   `json:"port"`
				Enabled    *bool                  `json:"enabled"`
				Advanced   map[string]interface{} `json:"advanced"`
				QuotaMode  *string                `json:"quota_mode"`
				QuotaBytes *int64                 `json:"quota_bytes"`
			}
			if err := s.readJSON(r, &body); err != nil {
				errJSON(w, 400, "请求格式不对")
				return
			}
			if body.SNI != nil && *body.SNI != "" && !validSNI(*body.SNI) {
				errJSON(w, 400, "伪装域名格式不对：只能是合法域名或 IP，不能含空格、中文或特殊字符")
				return
			}
			if body.SNI != nil && *body.SNI != "" {
				mode := configMode(in.Protocol, in.Config)
				if body.Advanced != nil {
					if m, ok := body.Advanced["mode"].(string); ok && m != "" {
						mode = m
					}
				}
				if proxy.IsRealityMode(in.Protocol, mode) {
					if blocked, err := proxy.SNIBehindCloudflare(*body.SNI); err != nil {
						errJSON(w, 400, "伪装域名解析失败，无法确认是否套 Cloudflare，请检查域名后重试")
						return
					} else if blocked {
						errJSON(w, 400, "伪装域名套了 Cloudflare，不能用作 Reality 伪装，换一个")
						return
					}
				}
			}
			// PUT 清空名字/地址会留下无名节点或坏链接：创建时空名字会
			// 自动命名，编辑时清空没有合理语义，直接拒绝。
			if body.Name != nil && strings.TrimSpace(*body.Name) == "" {
				errJSON(w, 400, "节点名不能为空")
				return
			}
			if body.Address != nil && strings.TrimSpace(*body.Address) == "" {
				errJSON(w, 400, "节点 IP 不能为空")
				return
			}
			oldSNI := in.SNI
			if body.Name != nil {
				in.Name = *body.Name
			}
			if body.Address != nil {
				in.Address = *body.Address
			}
			oldPort := in.Port
			if body.Port != nil && *body.Port != in.Port {
				if *body.Port < 1 || *body.Port > 65535 {
					errJSON(w, 400, "端口范围 1-65535")
					return
				}
				if s.app.Store.PortInUse(*body.Port, in.Protocol, in.ID) {
					errJSON(w, 400, fmt.Sprintf("端口 %d 已被本面板其他节点占用", *body.Port))
					return
				}
				if !store.UDPOnlyProtocol(in.Protocol) && sysinfo.ListeningTCPPorts()[*body.Port] {
					errJSON(w, 400, fmt.Sprintf("端口 %d 已被系统其他程序占用", *body.Port))
					return
				}
				// 编辑端口丢了创建时的 UDP 检查：Hy2/TUIC/WG 走 UDP，TCP 空闲不够。
				if (in.Protocol == "hy2" || in.Protocol == "tuic" || in.Protocol == "wireguard") && sysinfo.BoundUDPPorts()[*body.Port] {
					errJSON(w, 400, fmt.Sprintf("端口 %d 的 UDP 已被占用", *body.Port))
					return
				}
				in.Port = *body.Port
			}
			if body.Enabled != nil {
				in.Enabled = *body.Enabled
			}
			if body.QuotaMode != nil {
				if *body.QuotaMode != "" && *body.QuotaMode != "total" && *body.QuotaMode != "down" {
					errJSON(w, 400, "流量限额模式不对")
					return
				}
				in.QuotaMode = *body.QuotaMode
			}
			if body.QuotaBytes != nil {
				if *body.QuotaBytes < 0 {
					errJSON(w, 400, "流量限额不能为负数")
					return
				}
				in.QuotaBytes = *body.QuotaBytes
			}
			if in.QuotaMode == "" {
				in.QuotaBytes = 0
			}
			// 只在本次请求动了限额时校验合并结果：历史遗留的
			// “有模式无字节”节点，改其他字段时不被限额挡住。
			if (body.QuotaMode != nil || body.QuotaBytes != nil) && in.QuotaMode != "" && in.QuotaBytes <= 0 {
				errJSON(w, 400, "流量限额必须大于 0（不限量请把模式留空）")
				return
			}
			if body.SNI != nil && *body.SNI != in.SNI {
				in.SNI = *body.SNI
				// dest follows sni unless user customized it
				if in.Protocol == "vless" {
					var cfg proxy.VLESSConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					if cfg.Mode == "ws" || cfg.Mode == "h2" || cfg.Mode == "httpupgrade" {
						cfg.Domain = in.SNI
					} else if cfg.Dest == "" || cfg.Dest == oldSNI+":443" {
						cfg.Dest = in.SNI + ":443"
					}
					in.Config = store.MustJSON(cfg)
				}
				if in.Protocol == "vmess" {
					// TLS/HTTP 档的域名既在 SNI 列也在配置里，两边同步。
					var cfg proxy.VMessConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					if cfg.Mode == "cf" || cfg.Mode == "http" || cfg.Mode == "quic" || cfg.Mode == "h2" || cfg.Mode == "httpupgrade" {
						cfg.Domain = in.SNI
						in.Config = store.MustJSON(cfg)
					}
				}
				if in.Protocol == "trojan" {
					// Reality 档换 SNI 时 dest 跟着换（除非之前手动改过）；
					// TLS 档的域名两边同步。
					var cfg proxy.TrojanConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					if cfg.Mode == "cf" || cfg.Mode == "h2" || cfg.Mode == "httpupgrade" {
						cfg.Domain = in.SNI
					} else if cfg.Dest == "" || cfg.Dest == oldSNI+":443" {
						cfg.Dest = in.SNI + ":443"
					}
					in.Config = store.MustJSON(cfg)
				}
				if in.Protocol == "naive" {
					// Naive 的域名就是 SNI（CA 证书上的名字），两边同步。
					var cfg proxy.NaiveConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					cfg.Domain = in.SNI
					in.Config = store.MustJSON(cfg)
				}
			}
			if len(body.Advanced) > 0 {
				switch in.Protocol {
				case "vless":
					var cfg proxy.VLESSConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					mergeAdvanced(&cfg, body.Advanced)
					// 编辑复用创建的归一化：模式切换后旧档残留字段按新档重算。
					if err := s.normalizeVLESS(&cfg, in.SNI); err != nil {
						errJSON(w, 400, err.Error())
						return
					}
					in.Config = store.MustJSON(cfg)
				case "hy2":
					var cfg proxy.Hy2Config
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					mergeAdvanced(&cfg, body.Advanced)
					if cfg.HopPorts != "" {
						if err := proxy.ValidateHopPorts(cfg.HopPorts, sysinfo.BoundUDPPorts(), oldPort, in.Port); err != nil {
							errJSON(w, 400, err.Error())
							return
						}
					}
					in.Config = store.MustJSON(cfg)
				case "vmess":
					var cfg proxy.VMessConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					mergeAdvanced(&cfg, body.Advanced)
					if err := s.normalizeVMess(&cfg, in.SNI, in.Port); err != nil {
						errJSON(w, 400, err.Error())
						return
					}
					in.Config = store.MustJSON(cfg)
				case "ss":
					var cfg proxy.SSConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					oldMethod := cfg.Method
					mergeAdvanced(&cfg, body.Advanced)
					_, pwProvided := body.Advanced["password"]
					if (!pwProvided && cfg.Method != oldMethod) || cfg.Password == "" {
						cfg.Password = proxy.SSKey(cfg.Method)
					}
					in.Config = store.MustJSON(cfg)
				case "socks":
					var cfg proxy.SocksConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					mergeAdvanced(&cfg, body.Advanced)
					if cfg.User == "" || cfg.Pass == "" {
						errJSON(w, 400, "SOCKS 节点必须设置用户名和密码（空凭证会变成无认证公开代理）")
						return
					}
					in.Config = store.MustJSON(cfg)
				case "http":
					var cfg proxy.HTTPConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					mergeAdvanced(&cfg, body.Advanced)
					if cfg.User == "" || cfg.Pass == "" {
						errJSON(w, 400, "HTTP 节点必须设置用户名和密码（空凭证会变成无认证公开代理）")
						return
					}
					in.Config = store.MustJSON(cfg)
				case "trojan":
					var cfg proxy.TrojanConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					mergeAdvanced(&cfg, body.Advanced)
					if err := s.normalizeTrojan(&cfg, in.SNI, in.Port); err != nil {
						errJSON(w, 400, err.Error())
						return
					}
					in.Config = store.MustJSON(cfg)
				case "tuic":
					var cfg proxy.TUICConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					mergeAdvanced(&cfg, body.Advanced)
					in.Config = store.MustJSON(cfg)
				case "anytls":
					var cfg proxy.AnyTLSConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					mergeAdvanced(&cfg, body.Advanced)
					in.Config = store.MustJSON(cfg)
				case "naive":
					var cfg proxy.NaiveConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					mergeAdvanced(&cfg, body.Advanced)
					in.Config = store.MustJSON(cfg)
				case "snell":
					var cfg proxy.SnellConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					mergeAdvanced(&cfg, body.Advanced)
					if err := s.normalizeSnell(&cfg); err != nil {
						errJSON(w, 400, err.Error())
						return
					}
					in.Config = store.MustJSON(cfg)
				case "shadowtls":
					var cfg proxy.ShadowTLSConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					mergeAdvanced(&cfg, body.Advanced)
					if err := s.normalizeShadowTLS(&cfg); err != nil {
						errJSON(w, 400, err.Error())
						return
					}
					// 内层端口只在创建时分配：编辑绝不能把它清零，
					// 否则 Apply 时内层 SS 没端口可听。
					if cfg.InnerPort == 0 {
						cfg.InnerPort = s.allocInnerPort()
						if cfg.InnerPort == 0 {
							errJSON(w, 400, "没有可用的内层端口（20000-20999 都被占用了）")
							return
						}
					}
					in.Config = store.MustJSON(cfg)
				case "wireguard":
					var cfg proxy.WGConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					mergeAdvanced(&cfg, body.Advanced)
					if cfg.ClientIP == "" {
						errJSON(w, 400, "WireGuard 节点未设置客户端 IP")
						return
					}
					if _, _, err := net.ParseCIDR(cfg.ClientIP); err != nil {
						errJSON(w, 400, "WireGuard 客户端 IP 不是合法 CIDR（如 10.0.0.2/32）")
						return
					}
					in.Config = store.MustJSON(cfg)
				}
			}
			// 端口与模式联动校验：只改端口不改模式时归一化没跑，但结果仍可能
			// 是 CF 模式 + 非 CF 端口（死的节点），这里按合并后的结果再拦一次。
			if in.Protocol == "vmess" || in.Protocol == "trojan" {
				var mode string
				if in.Protocol == "vmess" {
					var cfg proxy.VMessConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					mode = cfg.Mode
				} else {
					var cfg proxy.TrojanConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					mode = cfg.Mode
				}
				if mode == "cf" && !proxy.IsCFPort(in.Port) {
					errJSON(w, 400, fmt.Sprintf("CF 模式源站端口必须是 CF 允许的端口，当前 %d 不行", in.Port))
					return
				}
			}
			in.UpdatedAt = time.Now().Unix()
			if err := s.app.Store.UpsertInbound(in); err != nil {
				errJSON(w, 500, err.Error())
				return
			}
			if err := s.app.ApplyAll(); err != nil {
				errJSON(w, 500, "已保存但启动失败："+err.Error())
				return
			}
			// 调低限额后立即结算一次：以前只靠后台增量触发，节点闲置时
			// 超限永不生效，订阅里还继续发它的链接。
			s.checkQuota(in.ID)
			link, tme := s.inboundLinks(in)
			link6, _ := s.inboundLinks6(in)
			okJSON(w, map[string]interface{}{"inbound": in, "link": link, "link6": link6, "tme_link": tme})
		case "DELETE":
			// 级联清理：删节点前先记下协议与证书路径（删后就查不到了）。
			naiveCert, naiveKey := "", ""
			if in.Protocol == "naive" {
				var cfg proxy.NaiveConfig
				_ = json.Unmarshal([]byte(in.Config), &cfg)
				naiveCert, naiveKey = cfg.CertFile, cfg.KeyFile
			}
			if err := s.app.Store.DeleteInbound(id); err != nil {
				errJSON(w, 500, err.Error())
				return
			}
			// 悬空链式由 DeleteInbound 的事务一并清掉（原子），
			// 这里不再事后删——事后删失败是静默的，事务失败则
			// 整个删除回滚，节点还在，前端如实看到 500。
			if naiveCert != "" {
				_ = os.Remove(naiveCert)
			}
			if naiveKey != "" {
				_ = os.Remove(naiveKey)
			}
			if err := s.app.ApplyAll(); err != nil {
				errJSON(w, 500, "已删除但重启失败："+err.Error())
				return
			}
			okJSON(w, nil)
		default:
			errJSON(w, 405, "method")
		}
	case "reset-traffic":
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		if err := s.app.Store.ResetTraffic(id); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		okJSON(w, nil)
	case "clone":
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		if core := requiredCore(in.Protocol); core != "" && !s.app.Mgr.Installed(core) {
			errJSON(w, 400, core+" 内核还没安装：先去“系统状态”页的内核卡片安装 "+core+"，装好再克隆节点")
			return
		}
		// 克隆：同协议、同伪装域名、同高级配置，但端口重新建议、
		// 身份凭证全部换新（UUID/Reality 密钥、Hy2 密码），
		// Naive 证书文件单独复制一份，绝不和原节点共用。
		// 名字 = 原名 + 随机 3 个字母；克隆出来默认是停用的，
		// 要用的时候手动开启，避免一克隆就抢端口、跑流量。
		// CF 节点克隆必须把 mode 传给建议端口：以前没传，443/8443
		// 被占时克隆出 5xxxx 端口，启用即死节点（CF 不转发该端口）。
		cloneMode := ""
		switch in.Protocol {
		case "vmess":
			var cfg proxy.VMessConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			cloneMode = cfg.Mode
		case "trojan":
			var cfg proxy.TrojanConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			cloneMode = cfg.Mode
		}
		port, _ := s.suggestPort(in.Protocol, cloneMode)
		if port == 0 {
			errJSON(w, 400, "没有可用端口")
			return
		}
		now := time.Now().Unix()
		clone := &store.Inbound{
			ID: s.uniqueID(func(id string) bool { _, err := s.app.Store.GetInbound(id); return err == nil }), Name: in.Name + "-" + randLetters(3), Protocol: in.Protocol,
			Port: port, Address: in.Address, SNI: in.SNI, Enabled: false,
			CreatedAt: now, UpdatedAt: now,
			QuotaMode: in.QuotaMode, QuotaBytes: in.QuotaBytes,
		}
		switch in.Protocol {
		case "vless":
			var cfg proxy.VLESSConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			cfg.UUID = proxy.DefaultVLESS().UUID
			// Reality 密钥/ShortID 只有 Reality 档用得上：TLS 档
			// （ws/h2/httpupgrade）克隆时不带原节点的密钥对，
			// 免得以后切回 Reality 时误以为这是新密钥；
			// 切回时 normalizeVLESS 会按空密钥重生成。
			if cfg.Mode == "reality" || cfg.Mode == "" {
				cfg.ShortID = randHexID()[:8]
				priv, pub, err := genRealityKeypair()
				if err != nil {
					errJSON(w, 500, "生成 Reality 密钥失败："+err.Error())
					return
				}
				cfg.PrivateKey, cfg.PublicKey = priv, pub
			} else {
				cfg.ShortID, cfg.PrivateKey, cfg.PublicKey = "", "", ""
			}
			clone.Config = store.MustJSON(cfg)
		case "hy2":
			var cfg proxy.Hy2Config
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			cfg.Password = proxy.DefaultHy2().Password
			clone.Config = store.MustJSON(cfg)
		case "vmess":
			var cfg proxy.VMessConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			cfg.UUID = proxy.DefaultVMess().UUID
			clone.Config = store.MustJSON(cfg)
		case "ss":
			var cfg proxy.SSConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			cfg.Password = proxy.SSKey(cfg.Method)
			clone.Config = store.MustJSON(cfg)
		case "socks":
			var cfg proxy.SocksConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			cfg.User = proxy.DefaultSocks().User
			cfg.Pass = proxy.DefaultSocks().Pass
			clone.Config = store.MustJSON(cfg)
		case "http":
			var cfg proxy.HTTPConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			cfg.User = proxy.DefaultHTTP().User
			cfg.Pass = proxy.DefaultHTTP().Pass
			clone.Config = store.MustJSON(cfg)
		case "trojan":
			var cfg proxy.TrojanConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			cfg.Password = proxy.DefaultTrojan().Password
			// 同 VLESS：Reality 密钥/ShortID 只有 Reality 档用，
			// TLS 档（cf/h2/httpupgrade）不带原节点密钥对。
			if cfg.Mode == "reality" || cfg.Mode == "" {
				cfg.ShortID = randHexID()[:8]
				priv, pub, err := genRealityKeypair()
				if err != nil {
					errJSON(w, 500, "生成 Reality 密钥失败："+err.Error())
					return
				}
				cfg.PrivateKey, cfg.PublicKey = priv, pub
			} else {
				cfg.ShortID, cfg.PrivateKey, cfg.PublicKey = "", "", ""
			}
			clone.Config = store.MustJSON(cfg)
		case "wireguard":
			var cfg proxy.WGConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			fresh := proxy.DefaultWG()
			cfg.ServerPriv, cfg.ServerPub = fresh.ServerPriv, fresh.ServerPub
			cfg.ClientPriv, cfg.ClientPub = fresh.ClientPriv, fresh.ClientPub
			clone.Config = store.MustJSON(cfg)
		case "tuic":
			var cfg proxy.TUICConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			fresh := proxy.DefaultTUIC()
			cfg.UUID, cfg.Password = fresh.UUID, fresh.Password
			clone.Config = store.MustJSON(cfg)
		case "anytls":
			var cfg proxy.AnyTLSConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			cfg.Password = proxy.DefaultAnyTLS().Password
			clone.Config = store.MustJSON(cfg)
		case "naive":
			var cfg proxy.NaiveConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			fresh := proxy.DefaultNaive()
			cfg.Username, cfg.Password = fresh.Username, fresh.Password
			// 证书单独复制一份给新节点（同域名所以证书仍有效）；
			// 复制失败时清掉引用，启用时 Apply 明说缺证书，
			// 绝不让新节点指着原节点的文件。
			if cfg.CertFile != "" && cfg.KeyFile != "" {
				newCert := filepath.Join(s.app.ConfigDir(), "naive-"+clone.ID+".crt")
				newKey := filepath.Join(s.app.ConfigDir(), "naive-"+clone.ID+".key")
				certData, certErr := os.ReadFile(cfg.CertFile)
				keyData, keyErr := os.ReadFile(cfg.KeyFile)
				if certErr == nil && keyErr == nil &&
					os.WriteFile(newCert, certData, 0644) == nil &&
					os.WriteFile(newKey, keyData, 0600) == nil {
					cfg.CertFile, cfg.KeyFile = newCert, newKey
				} else {
					os.Remove(newCert)
					os.Remove(newKey)
					cfg.CertFile, cfg.KeyFile = "", ""
				}
			}
			clone.Config = store.MustJSON(cfg)
		case "snell":
			var cfg proxy.SnellConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			cfg.PSK = proxy.DefaultSnell().PSK
			clone.Config = store.MustJSON(cfg)
		case "shadowtls":
			var cfg proxy.ShadowTLSConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			fresh := proxy.DefaultShadowTLS()
			cfg.Password, cfg.SSPassword = fresh.Password, fresh.SSPassword
			cfg.InnerPort = s.allocInnerPort()
			if cfg.InnerPort == 0 {
				errJSON(w, 400, "没有可用的内层端口（20000-20999 都被占用了）")
				return
			}
			clone.Config = store.MustJSON(cfg)
		default:
			errJSON(w, 400, "不支持的协议")
			return
		}
		if err := s.app.Store.UpsertInbound(clone); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		if err := s.app.ApplyAll(); err != nil {
			errJSON(w, 500, "克隆已保存但启动失败："+err.Error())
			return
		}
		link, tme := s.inboundLinks(clone)
		link6, _ := s.inboundLinks6(clone)
		okJSON(w, map[string]interface{}{"inbound": clone, "link": link, "link6": link6, "tme_link": tme})
	case "sni-change":
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		var body struct {
			SNI string `json:"sni"`
		}
		_ = s.readJSON(r, &body)
		newSNI := body.SNI
		if newSNI == "" {
			newSNI = proxy.RecommendSNI(in.SNI).Domain
		}
		if body.SNI != "" && !validSNI(body.SNI) {
			errJSON(w, 400, "伪装域名格式不对：只能是合法域名或 IP，不能含空格、中文或特殊字符")
			return
		}
		if body.SNI != "" && proxy.IsRealityMode(in.Protocol, configMode(in.Protocol, in.Config)) {
			if blocked, err := proxy.SNIBehindCloudflare(body.SNI); err != nil {
				errJSON(w, 400, "伪装域名解析失败，无法确认是否套 Cloudflare，请检查域名后重试")
				return
			} else if blocked {
				errJSON(w, 400, "伪装域名套了 Cloudflare，不能用作 Reality 伪装，换一个")
				return
			}
		}
		oldSNI := in.SNI
		in.SNI = newSNI
		if in.Protocol == "vless" {
			var cfg proxy.VLESSConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			if cfg.Mode == "ws" || cfg.Mode == "h2" || cfg.Mode == "httpupgrade" {
				cfg.Domain = newSNI
			} else if cfg.Dest == "" || cfg.Dest == oldSNI+":443" {
				cfg.Dest = newSNI + ":443"
			}
			in.Config = store.MustJSON(cfg)
		}
		if in.Protocol == "vmess" {
			var cfg proxy.VMessConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			if cfg.Mode == "cf" || cfg.Mode == "http" || cfg.Mode == "quic" || cfg.Mode == "h2" || cfg.Mode == "httpupgrade" {
				cfg.Domain = newSNI
				in.Config = store.MustJSON(cfg)
			}
		}
		if in.Protocol == "trojan" {
			var cfg proxy.TrojanConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			if cfg.Mode == "cf" || cfg.Mode == "h2" || cfg.Mode == "httpupgrade" {
				cfg.Domain = newSNI
			} else if cfg.Dest == "" || cfg.Dest == oldSNI+":443" {
				cfg.Dest = newSNI + ":443"
			}
			in.Config = store.MustJSON(cfg)
		}
		if in.Protocol == "naive" {
			var cfg proxy.NaiveConfig
			_ = json.Unmarshal([]byte(in.Config), &cfg)
			cfg.Domain = newSNI
			in.Config = store.MustJSON(cfg)
		}
		in.UpdatedAt = time.Now().Unix()
		if err := s.app.Store.UpsertInbound(in); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		if err := s.app.ApplyAll(); err != nil {
			errJSON(w, 500, "伪装域名已换但启动失败："+err.Error())
			return
		}
		link, tme := s.inboundLinks(in)
		link6, _ := s.inboundLinks6(in)
		okJSON(w, map[string]interface{}{"inbound": in, "link": link, "link6": link6, "tme_link": tme, "sni": newSNI})
	case "cert":
		// Naive 证书上传：只收 PEM 文本，配对校验通过才落盘。
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		if in.Protocol != "naive" {
			errJSON(w, 400, "只有 Naive 节点需要上传证书")
			return
		}
		var body struct {
			Cert string `json:"cert"`
			Key  string `json:"key"`
		}
		if err := s.readJSON(r, &body); err != nil || body.Cert == "" || body.Key == "" {
			errJSON(w, 400, "证书和私钥不能为空")
			return
		}
		if _, err := tls.X509KeyPair([]byte(body.Cert), []byte(body.Key)); err != nil {
			errJSON(w, 400, "证书与私钥不匹配或格式不对："+err.Error())
			return
		}
		certPath := filepath.Join(s.app.ConfigDir(), "naive-"+in.ID+".crt")
		keyPath := filepath.Join(s.app.ConfigDir(), "naive-"+in.ID+".key")
		// 两文件先写临时文件、都成功后再一起重命名：以前先写证书后写私钥，
		// 私钥写失败时盘上是新证书 + 旧私钥的错配组合，原正常节点直接变坏。
		tmpCert := certPath + ".tmp"
		tmpKey := keyPath + ".tmp"
		if err := os.WriteFile(tmpCert, []byte(body.Cert), 0600); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		if err := os.WriteFile(tmpKey, []byte(body.Key), 0600); err != nil {
			_ = os.Remove(tmpCert)
			errJSON(w, 500, err.Error())
			return
		}
		if err := os.Rename(tmpCert, certPath); err != nil {
			_ = os.Remove(tmpCert)
			_ = os.Remove(tmpKey)
			errJSON(w, 500, err.Error())
			return
		}
		if err := os.Rename(tmpKey, keyPath); err != nil {
			_ = os.Remove(tmpKey)
			errJSON(w, 500, err.Error())
			return
		}
		var cfg proxy.NaiveConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		cfg.CertFile, cfg.KeyFile = certPath, keyPath
		in.Config = store.MustJSON(cfg)
		// 上传证书即启用（按钮文案就是“上传并启动”；手动停用的节点传了证书也会启用，
		// 这是上传动作本身的语义，不是悄悄改状态）。
		in.Enabled = true
		in.UpdatedAt = time.Now().Unix()
		if err := s.app.Store.UpsertInbound(in); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		if err := s.app.ApplyAll(); err != nil {
			errJSON(w, 500, "证书已保存但启动失败："+err.Error())
			return
		}
		link, _ := s.inboundLinks(in)
		okJSON(w, map[string]interface{}{"inbound": in, "link": link})
	case "qr":
		if r.Method != "GET" {
			errJSON(w, 405, "method")
			return
		}
		link, _ := s.inboundLinks(in)
		if link == "" {
			errJSON(w, 404, "无链接")
			return
		}
		png, err := qrcodePNG(link)
		if err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Write(png)
	case "log":
		if r.Method != "GET" {
			errJSON(w, 405, "method")
			return
		}
		// 全部节点都跑在 sing-box 里，看 sing-box 日志。
		logPath := s.app.Mgr.LogPath("sing-box")
		b, err := os.ReadFile(logPath)
		if err != nil {
			okJSON(w, "")
			return
		}
		lines := strings.Split(string(b), "\n")
		if len(lines) > 100 {
			lines = lines[len(lines)-100:]
		}
		okJSON(w, strings.Join(lines, "\n"))
	default:
		errJSON(w, 404, "未知操作")
	}
}

func (s *Server) handleSuggestPort(w http.ResponseWriter, r *http.Request) {
	proto := r.URL.Query().Get("protocol")
	mode := r.URL.Query().Get("mode")
	port, reason := s.suggestPort(proto, mode)
	okJSON(w, map[string]interface{}{"port": port, "reason": reason})
}

func (s *Server) handleSNIList(w http.ResponseWriter, r *http.Request) {
	okJSON(w, proxy.SNIList)
}

func (s *Server) handleSNIRandom(w http.ResponseWriter, r *http.Request) {
	ex := r.URL.Query().Get("exclude")
	okJSON(w, proxy.RecommendSNI(ex))
}

// ---------- bnodes & chains ----------

func (s *Server) handleBNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		list, _ := s.app.Store.ListBNodes()
		if list == nil {
			list = []*store.BNode{}
		}
		// 显示名解码：老数据里 SS 节点的名字是粘贴链接时存的 #fragment
		// 原样（百分号编码），直接显示就是乱码；这里只解码显示，存储
		// 的链接不动，订阅发给客户端的还是原链接（客户端自己会解码）。
		out := make([]*store.BNode, 0, len(list))
		for _, b := range list {
			cp := *b
			cp.Name = proxy.DecodeFragment(b.Name)
			out = append(out, &cp)
		}
		okJSON(w, out)
	case "POST":
		var body struct {
			Link string `json:"link"`
			Name string `json:"name"`
		}
		if err := s.readJSON(r, &body); err != nil || body.Link == "" {
			errJSON(w, 400, "链接为空")
			return
		}
		p, err := proxy.ParseBLink(body.Link)
		if err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		if p.Protocol == "hysteria2" {
			// hy2 B is supported via sing-box handoff; allowed
		}
		// 链接去重：同一条链接（只比 # 之前，名字后缀不算）
		// 贴两次不再建第二行——重复的 B 节点会让链式下拉、
		// 订阅和测活都出现双份，还容易把两条当成两个节点。
		if existing, _ := s.app.Store.ListBNodes(); existing != nil {
			base := body.Link
			if i := strings.Index(base, "#"); i >= 0 {
				base = base[:i]
			}
			for _, b := range existing {
				bl := b.Link
				if i := strings.Index(bl, "#"); i >= 0 {
					bl = bl[:i]
				}
				if bl == base {
					okJSON(w, b)
					return
				}
			}
		}
		// 以前 name 字段直接被忽略，存的是链接 #fragment 里的名字，
		// 前端按 name 回显就会对不上（行为测试 2.6）；显式传了名就用它。
		bnName := p.Name
		if body.Name != "" {
			bnName = body.Name
		}
		bn := &store.BNode{
			ID: s.uniqueID(func(id string) bool { _, err := s.app.Store.GetBNode(id); return err == nil }), Name: bnName, Protocol: p.Protocol,
			Link: body.Link, Config: store.MustJSON(p.Outbound), CreatedAt: time.Now().Unix(),
		}
		if err := s.app.Store.UpsertBNode(bn); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		okJSON(w, bn)
	default:
		errJSON(w, 405, "method")
	}
}

func (s *Server) handleBNodeAction(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/bnodes/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	switch action {
	case "parse":
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		var body struct {
			Link string `json:"link"`
		}
		if err := s.readJSON(r, &body); err != nil {
			errJSON(w, 400, "链接为空")
			return
		}
		p, err := proxy.ParseBLink(body.Link)
		if err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		okJSON(w, map[string]interface{}{"protocol": p.Protocol, "name": p.Name})
	case "":
		if r.Method == "DELETE" {
			if err := s.app.Store.DeleteBNode(id); err != nil {
				errJSON(w, 500, err.Error())
				return
			}
			// 悬空链式由 DeleteBNode 的事务一并清掉（原子），
			// 下面必须 ApplyAll：以前删 B 节点不触发 Apply，
			// 链式出站还残留在 singbox.json 里继续跑。
			if err := s.app.ApplyAll(); err != nil {
				errJSON(w, 500, "已删除但重启失败："+err.Error())
				return
			}
			okJSON(w, nil)
			return
		}
		errJSON(w, 405, "method")
	default:
		errJSON(w, 404, "未知操作")
	}
}

// handleBNodesLatency：本机 → 每个 B 节点服务器的 TCP 建连延迟，
// 前端在入站列表页每 3 秒轮询一次，只更新 ping 数字不重绘列表。
// Hy2 走 UDP，TCP 探活永远不通，所以 Hy2 直接返回 udp、不给假数字；
// 域名节点测的是解析后的地址，CF 域名测到的是 CF 边缘，属实。
func (s *Server) handleBNodesLatency(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	list, _ := s.app.Store.ListBNodes()
	type row struct {
		ID   string `json:"id"`
		MS   int64  `json:"ms"`   // -1 = 不通/超时；hy2 时无意义，看 Kind
		Kind string `json:"kind"` // "tcp" | "udp"
	}
	out := []row{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, b := range list {
		b := b
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := row{ID: b.ID, MS: -1, Kind: "tcp"}
			if b.Protocol == "hysteria2" {
				r.Kind = "udp"
				mu.Lock()
				out = append(out, r)
				mu.Unlock()
				return
			}
			host, port, err := proxy.BNodeHostPort(b.Link)
			if err != nil {
				mu.Lock()
				out = append(out, r)
				mu.Unlock()
				return
			}
			start := time.Now()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), 2*time.Second)
			if err == nil {
				_ = conn.Close()
				r.MS = time.Since(start).Milliseconds()
			}
			mu.Lock()
			out = append(out, r)
			mu.Unlock()
		}()
	}
	wg.Wait()
	okJSON(w, out)
}

func (s *Server) handleChains(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		list, _ := s.app.Store.ListChains()
		if list == nil {
			list = []*store.Chain{}
		}
		okJSON(w, list)
	case "POST":
		var body struct {
			Name      string `json:"name"`
			InboundID string `json:"inbound_id"`
			List      string `json:"list"`
			Mode      string `json:"mode"`
			BNodeID   string `json:"bnode_id"`
		}
		if err := s.readJSON(r, &body); err != nil {
			errJSON(w, 400, "请求格式不对")
			return
		}
		if body.InboundID == "" || body.BNodeID == "" {
			errJSON(w, 400, "A 节点和 B 节点都要选")
			return
		}
		in, err := s.app.Store.GetInbound(body.InboundID)
		if err != nil || in.Protocol != "vless" {
			errJSON(w, 400, "链式 A 节点必须是本机 VLESS 节点")
			return
		}
		_, err = s.app.Store.GetBNode(body.BNodeID)
		if err != nil {
			errJSON(w, 400, "B 节点不存在")
			return
		}
		mode := body.Mode
		if mode != "" && mode != "split" && mode != "direct" {
			errJSON(w, 400, "链式方式不对")
			return
		}
		if mode == "direct" {
			// 直接链式不用清单：全部流量 A 进 B 出。
			body.List = ""
		} else {
			mode = "split"
			if strings.TrimSpace(body.List) == "" {
				errJSON(w, 400, "域名或 IP 清单不能为空")
				return
			}
			// 清单逐行校验 + 归一化：非法行按行号拒绝，scheme/路径/端口/
			// 前导点全部剥掉再存，存进去的就是实际会匹配的样子。
			suffixes, cidrs, err := proxy.ParseChainList(body.List)
			if err != nil {
				errJSON(w, 400, err.Error())
				return
			}
			body.List = strings.Join(append(append([]string{}, suffixes...), cidrs...), "\n")
		}
		// 一个 A 节点只能有一条链式：两条链式抢同一个入站，
		// 路由会互相覆盖，流量不知道该走哪个 B，索性建的时候就拦住。
		existing, _ := s.app.Store.ListChains()
		for _, c := range existing {
			if c.InboundID == body.InboundID {
				errJSON(w, 400, "该 A 节点已有链式规则，一个 A 节点只能有一条链式")
				return
			}
		}
		name := body.Name
		if name == "" {
			name = "链式-" + in.Name
		}
		ch := &store.Chain{
			ID: s.uniqueID(func(id string) bool {
				list, _ := s.app.Store.ListChains()
				for _, c := range list {
					if c.ID == id {
						return true
					}
				}
				return false
			}), Name: name, InboundID: body.InboundID,
			List: body.List, Mode: mode, BNodeID: body.BNodeID, Enabled: true, CreatedAt: time.Now().Unix(),
		}
		if err := s.app.Store.UpsertChain(ch); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		if err := s.app.ApplyAll(); err != nil {
			errJSON(w, 500, "链式已保存但启动失败："+err.Error())
			return
		}
		okJSON(w, ch)
	default:
		errJSON(w, 405, "method")
	}
}

// chainLink：链式对外暴露的链接 = A 节点链接、名字换成链名。
func (s *Server) chainLink(ch *store.Chain) (link, link6 string) {
	in, err := s.app.Store.GetInbound(ch.InboundID)
	if err != nil {
		return "", ""
	}
	cp := *in
	cp.Name = ch.Name
	link, _ = s.inboundLinks(&cp)
	link6, _ = s.inboundLinks6(&cp)
	return link, link6
}

func (s *Server) handleChainAction(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/chains/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}
	chains, _ := s.app.Store.ListChains()
	var ch *store.Chain
	for _, c := range chains {
		if c.ID == id {
			ch = c
			break
		}
	}
	if ch == nil {
		errJSON(w, 404, "链式不存在")
		return
	}
	// 链式链接：就是 A 节点链接、名字换成链名（和订阅里链式入口同一条）。
	// 客户端只连 A，链式在服务端 sing-box 里完成，所以不存在另一条
	// “链式协议”链接；链式链接就是拿着链名的 A 链接。
	if action == "link" || action == "qr" {
		if r.Method != "GET" {
			errJSON(w, 405, "method")
			return
		}
		link, link6 := s.chainLink(ch)
		if link == "" {
			errJSON(w, 404, "A 节点不存在")
			return
		}
		if action == "link" {
			okJSON(w, map[string]string{"link": link, "link6": link6, "name": ch.Name})
			return
		}
		png, err := qrcodePNG(link)
		if err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Write(png)
		return
	}
	switch r.Method {
	case "PUT":
		var body struct {
			Name      *string `json:"name"`
			InboundID *string `json:"inbound_id"`
			List      *string `json:"list"`
			Mode      *string `json:"mode"`
			BNodeID   *string `json:"bnode_id"`
			Enabled   *bool   `json:"enabled"`
		}
		if err := s.readJSON(r, &body); err != nil {
			errJSON(w, 400, "请求格式不对")
			return
		}
		if body.Name != nil {
			// 与节点 PUT 一致：编辑时清空名字没有合理语义，直接拒绝。
			if strings.TrimSpace(*body.Name) == "" {
				errJSON(w, 400, "链式名不能为空")
				return
			}
			ch.Name = *body.Name
		}
		if body.InboundID != nil {
			if *body.InboundID != ch.InboundID {
				others, _ := s.app.Store.ListChains()
				for _, c := range others {
					if c.ID != ch.ID && c.InboundID == *body.InboundID {
						errJSON(w, 400, "该 A 节点已有链式规则，一个 A 节点只能有一条链式")
						return
					}
				}
				// PUT 复用创建的 A 节点校验：以前只查一链，不查 A 是否 VLESS。
				in, err := s.app.Store.GetInbound(*body.InboundID)
				if err != nil || in.Protocol != "vless" {
					errJSON(w, 400, "链式 A 节点必须是本机 VLESS 节点")
					return
				}
			}
			ch.InboundID = *body.InboundID
		}
		if body.Mode != nil {
			m := *body.Mode
			if m != "" && m != "split" && m != "direct" {
				errJSON(w, 400, "链式方式不对")
				return
			}
			if m == "direct" {
				// 切到直接链式：清单直接清掉，不用填。
				ch.Mode = "direct"
				ch.List = ""
			} else {
				// 切回分流：必须有清单（新传的，或已存的）。
				if body.List != nil {
					suffixes, cidrs, err := proxy.ParseChainList(*body.List)
					if err != nil {
						errJSON(w, 400, err.Error())
						return
					}
					ch.List = strings.Join(append(append([]string{}, suffixes...), cidrs...), "\n")
				} else if strings.TrimSpace(ch.List) == "" {
					errJSON(w, 400, "切回分流要填域名或 IP 清单")
					return
				}
				ch.Mode = "split"
			}
		} else if body.List != nil && ch.Mode != "direct" {
			// 原分流链式改清单：复用创建的清单校验 + 归一化。
			// 直接链式下送来的清单直接忽略（前端在直接模式下不显示清单框）。
			suffixes, cidrs, err := proxy.ParseChainList(*body.List)
			if err != nil {
				errJSON(w, 400, err.Error())
				return
			}
			ch.List = strings.Join(append(append([]string{}, suffixes...), cidrs...), "\n")
		}
		if body.BNodeID != nil {
			// PUT 复用创建的 B 节点校验：以前只换 id，不查存在。
			_, err := s.app.Store.GetBNode(*body.BNodeID)
			if err != nil {
				errJSON(w, 400, "B 节点不存在")
				return
			}
			ch.BNodeID = *body.BNodeID
		}
		if body.Enabled != nil {
			ch.Enabled = *body.Enabled
		}
		if err := s.app.Store.UpsertChain(ch); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		if err := s.app.ApplyAll(); err != nil {
			errJSON(w, 500, "已保存但启动失败："+err.Error())
			return
		}
		okJSON(w, ch)
	case "DELETE":
		if err := s.app.Store.DeleteChain(id); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		if err := s.app.ApplyAll(); err != nil {
			errJSON(w, 500, "已删除但重启失败："+err.Error())
			return
		}
		okJSON(w, nil)
	default:
		errJSON(w, 405, "method")
	}
}

// ---------- settings ----------

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	tok := s.app.Store.GetSetting("sub_token")
	var exList []string
	if raw := s.app.Store.GetSetting("sub_excluded"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &exList)
	}
	if exList == nil {
		exList = []string{}
	}
	okJSON(w, map[string]interface{}{
		"panel_port":     s.app.Store.GetSetting("panel_port"),
		"panel_path":     s.app.Store.GetSetting("panel_path"),
		"panel_disabled": s.app.Store.GetSetting("panel_disabled") == "1",
		"public_ip":      s.app.PublicIP(),
		"public_ipv6":    s.app.PublicIPv6(),
		"sub_token":      tok,
		"panel_https":    s.app.Store.GetSetting("panel_https") == "1",
		"panel_cert":     s.app.Store.GetSetting("panel_cert"),
		"sub_excluded":   exList,
		"version":        version.Version,
	})
}

// syncCliCredentials：面板改账号/密码时同步更新 CLI 凭证文件，让改动立即
// 对 SSH 命令行也生效，不用再跑 sssingbox login。文件不存在时不创建
// （手动部署本来就没有 CLI 凭证文件，别凭空造一个）；只传了 username
// 或 password 其中一项时，另一项沿用文件里的旧值；写失败也不影响面板
// 本身的改动（面板登录以数据库为准，CLI 只是它的一个副本）。
func (s *Server) syncCliCredentials(username, password string) {
	path := filepath.Join(s.app.Dir, ".cli-credentials")
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var c struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return
	}
	if username != "" {
		c.Username = username
	}
	if password != "" {
		c.Password = password
	}
	out, err := json.Marshal(c)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, out, 0600)
}

func (s *Server) handleSettingsAction(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/settings/")
	switch rest {
	case "username":
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		var body struct {
			New string `json:"new"`
		}
		if err := s.readJSON(r, &body); err != nil {
			errJSON(w, 400, "请求格式不对")
			return
		}
		old, ok := s.sessionUser(r)
		if !ok || old == "" {
			errJSON(w, 401, "未登录")
			return
		}
		body.New = strings.TrimSpace(body.New)
		if body.New == "" || len(body.New) > 32 || strings.ContainsAny(body.New, " \t\n") {
			errJSON(w, 400, "新账号不能为空、不能含空格、不能超 32 位")
			return
		}
		if body.New != old {
			if _, err := s.app.Store.GetUser(body.New); err == nil {
				errJSON(w, 400, "账号已存在")
				return
			}
			if err := s.app.Store.RenameUser(old, body.New); err != nil {
				errJSON(w, 500, err.Error())
				return
			}
			// 账号改了，CLI 凭证文件里的账号同步跟上，SSH 命令行不用再跑 login。
			s.syncCliCredentials(body.New, "")
		}
		// 当前会话跟上新账号，其他会话吊销（旧账号的会话不能再留着）。
		if c, err := r.Cookie("sssingbox_session"); err == nil {
			s.sessMu.Lock()
			if sess, ok := s.sessions[c.Value]; ok {
				sess.username = body.New
				s.sessions[c.Value] = sess
			}
			s.sessMu.Unlock()
			s.revokeSessionsExcept(c.Value)
		}
		okJSON(w, map[string]interface{}{"username": body.New})
	case "password":
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		var body struct {
			Old  string `json:"old"`
			New  string `json:"new"`
			New2 string `json:"new2"`
		}
		if err := s.readJSON(r, &body); err != nil {
			errJSON(w, 400, "请求格式不对")
			return
		}
		// 改密码必须验旧密码：只靠会话凭证不够——管理员离开座位时，
		// 任何人都能在已登录的面板上把密码换掉。旧密码缺失或不对都拒绝。
		username, ok := s.sessionUser(r)
		if !ok || username == "" {
			errJSON(w, 401, "未登录")
			return
		}
		if body.Old == "" {
			errJSON(w, 400, "请先输入旧密码")
			return
		}
		curHash, err := s.app.Store.GetUser(username)
		if err != nil || bcrypt.CompareHashAndPassword([]byte(curHash), []byte(body.Old)) != nil {
			errJSON(w, 401, "旧密码不对")
			return
		}
		if body.New2 != "" && body.New2 != body.New {
			errJSON(w, 400, "两次输入的新密码不一致")
			return
		}
		if len(body.New) < 6 {
			errJSON(w, 400, "新密码至少 6 位")
			return
		}
		nh, err := hashPassword(body.New)
		if err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		if err := s.app.Store.UpdatePassword(username, string(nh)); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		// 密码改了，CLI 凭证文件里的密码同步跟上，SSH 命令行不用再跑 login。
		s.syncCliCredentials(username, body.New)
		if c, err := r.Cookie("sssingbox_session"); err == nil {
			s.revokeSessionsExcept(c.Value)
		}
		okJSON(w, nil)
	case "password-local":
		// 本机改密码（SSH 菜单、安装器菜单用）：只允许本机回环调用，不用验
		// 旧密码——能连到 127.0.0.1 就等于已经拿到服务器 shell，旧密码没有
		// 意义。其余与 password 完全一致（长度校验、哈希、CLI 凭证同步、
		// 吊销其他会话）。Web 面板改密码仍走 password，必须验旧密码。
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		if !isLoopbackIP(clientIPOf(r)) {
			errJSON(w, 403, "本机改密码只能在本机 SSH 里操作")
			return
		}
		var bodyLocal struct {
			New  string `json:"new"`
			New2 string `json:"new2"`
		}
		if err := s.readJSON(r, &bodyLocal); err != nil {
			errJSON(w, 400, "请求格式不对")
			return
		}
		usernameLocal, ok := s.sessionUser(r)
		if !ok || usernameLocal == "" {
			errJSON(w, 401, "未登录")
			return
		}
		if bodyLocal.New2 != "" && bodyLocal.New2 != bodyLocal.New {
			errJSON(w, 400, "两次输入的新密码不一致")
			return
		}
		if len(bodyLocal.New) < 6 {
			errJSON(w, 400, "新密码至少 6 位")
			return
		}
		nhLocal, err := hashPassword(bodyLocal.New)
		if err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		if err := s.app.Store.UpdatePassword(usernameLocal, string(nhLocal)); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		s.syncCliCredentials(usernameLocal, bodyLocal.New)
		if c, err := r.Cookie("sssingbox_session"); err == nil {
			s.revokeSessionsExcept(c.Value)
		}
		okJSON(w, nil)
	case "login":
		// 面板登录一表保存：新账号留空=不改，新密码留空=不改、只输一遍；
		// 两项都空直接拒绝。老 username/password 接口留着（命令行、安装器在用）。
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		var body struct {
			Username    string `json:"username"`
			Password    string `json:"password"`
			OldPassword string `json:"old_password"`
		}
		if err := s.readJSON(r, &body); err != nil {
			errJSON(w, 400, "请求格式不对")
			return
		}
		old, ok := s.sessionUser(r)
		if !ok || old == "" {
			errJSON(w, 401, "未登录")
			return
		}
		body.Username = strings.TrimSpace(body.Username)
		if body.Username == "" && body.Password == "" {
			errJSON(w, 400, "账号和密码都留空，没有要改的内容")
			return
		}
		// 改密码必须验旧密码（只改账号时不用）：同 /api/settings/password。
		if body.Password != "" {
			if body.OldPassword == "" {
				errJSON(w, 400, "改密码请先输入旧密码")
				return
			}
			curHash, err := s.app.Store.GetUser(old)
			if err != nil || bcrypt.CompareHashAndPassword([]byte(curHash), []byte(body.OldPassword)) != nil {
				errJSON(w, 401, "旧密码不对")
				return
			}
		}
		// 先全验过再落盘，避免改完账号才发现密码不合格、改一半。
		newName := old
		if body.Username != "" && body.Username != old {
			if len(body.Username) > 32 || strings.ContainsAny(body.Username, " \t\n") {
				errJSON(w, 400, "新账号不能含空格、不能超 32 位")
				return
			}
			if _, err := s.app.Store.GetUser(body.Username); err == nil {
				errJSON(w, 400, "账号已存在")
				return
			}
			newName = body.Username
		}
		if body.Password != "" && len(body.Password) < 6 {
			errJSON(w, 400, "新密码至少 6 位")
			return
		}
		if newName != old {
			if err := s.app.Store.RenameUser(old, newName); err != nil {
				errJSON(w, 500, err.Error())
				return
			}
		}
		if body.Password != "" {
			nh, err := hashPassword(body.Password)
			if err != nil {
				errJSON(w, 400, err.Error())
				return
			}
			if err := s.app.Store.UpdatePassword(newName, string(nh)); err != nil {
				errJSON(w, 500, err.Error())
				return
			}
		}
		// CLI 凭证同步：只传改了的那项，另一项沿用文件旧值。
		u, p := "", ""
		if newName != old {
			u = newName
		}
		if body.Password != "" {
			p = body.Password
		}
		s.syncCliCredentials(u, p)
		if c, err := r.Cookie("sssingbox_session"); err == nil {
			s.sessMu.Lock()
			if sess, ok := s.sessions[c.Value]; ok {
				sess.username = newName
				s.sessions[c.Value] = sess
			}
			s.sessMu.Unlock()
			s.revokeSessionsExcept(c.Value)
		}
		okJSON(w, map[string]interface{}{"username": newName})
	case "port":
		// 设置页改面板端口：按实际服务管理改对应服务文件 + 重启（重启在
		// 回包 800ms 后做，浏览器才收得到确认）；只有 systemd 需要
		// daemon-reload。找不到服务文件时直接报错并给出手动重启命令，
		// 不再谎称“已写入、待手动重启”（v1.0.1 修：OpenRC 上那个谎言
		// 让手动重启也永远到不了新端口）。
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		var body struct {
			Port int `json:"port"`
		}
		if err := s.readJSON(r, &body); err != nil {
			errJSON(w, 400, "请求格式不对")
			return
		}
		if body.Port < 1 || body.Port > 65535 {
			errJSON(w, 400, "端口范围 1-65535")
			return
		}
		cur := 0
		if p := s.app.Store.GetSetting("panel_port"); p != "" {
			cur, _ = strconv.Atoi(p)
		}
		if body.Port == cur {
			okJSON(w, map[string]interface{}{"port": body.Port, "restart_required": false})
			return
		}
		if portTaken(body.Port) {
			errJSON(w, 400, "端口已被占用")
			return
		}
		kind := panelInitKind()
		svcFile := panelServiceFile()
		if svcFile == "" {
			bin, _ := os.Executable()
			errJSON(w, 500, "找不到面板服务文件（容器或手动启动），端口未改动，请手动用新端口重启面板："+manualRestartCmd(s.app.Dir, bin, body.Port))
			return
		}
		b, err := os.ReadFile(svcFile)
		if err != nil {
			bin, _ := os.Executable()
			errJSON(w, 500, "读服务文件失败，端口未改动，请手动用新端口重启面板："+manualRestartCmd(s.app.Dir, bin, body.Port)+"（"+err.Error()+"）")
			return
		}
		updated, err := rewriteServicePort(string(b), body.Port)
		if err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		mode := os.FileMode(0644)
		if fi, err := os.Stat(svcFile); err == nil {
			mode = fi.Mode()
		}
		if err := os.WriteFile(svcFile, []byte(updated), mode); err != nil {
			errJSON(w, 500, "写服务文件失败："+err.Error())
			return
		}
		// 只有 systemd 需要 daemon-reload（单元被缓存）；OpenRC / procd /
		// sysvinit 每次启服务都重读脚本，不用重载。
		if kind == initSystemd {
			if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
				okJSON(w, map[string]interface{}{"port": body.Port, "restart_required": true, "note": "daemon-reload 失败：" + strings.TrimSpace(string(out))})
				return
			}
		}
		firewallAllowPort(body.Port)
		okJSON(w, map[string]interface{}{"port": body.Port, "restart_required": false})
		if cmd := restartPanelCommand(kind); cmd != nil {
			go func() {
				time.Sleep(800 * time.Millisecond)
				_ = exec.Command(cmd[0], cmd[1:]...).Run()
			}()
		}
	case "panel-enabled":
		// SSH 菜单开关面板访问：立即生效，不用重启。关闭后只挡外网，
		// 订阅与本机回环不受影响，代理照常跑；本机随时能再打开。
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := s.readJSON(r, &body); err != nil {
			errJSON(w, 400, "请求格式不对")
			return
		}
		val := "0"
		if !body.Enabled {
			val = "1"
		}
		_ = s.app.Store.SetSetting("panel_disabled", val)
		okJSON(w, map[string]interface{}{"panel_disabled": !body.Enabled})
	case "panel-path":
		// 设置页改根路径：立即生效，不用重启（路径门每次请求都读设置）。
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		var body struct {
			Path string `json:"path"`
		}
		if err := s.readJSON(r, &body); err != nil {
			errJSON(w, 400, "请求格式不对")
			return
		}
		path := strings.Trim(body.Path, "/ ")
		if !validPanelPath(path) {
			errJSON(w, 400, "路径只能是 1-32 位英文、数字、-、_，不能用 sub、api，留空回到根目录")
			return
		}
		_ = s.app.Store.SetSetting("panel_path", path)
		okJSON(w, map[string]interface{}{"panel_path": path})
	case "panel-access":
		// 设置页“面板访问”一次改端口+路径：老前端先改路径、再改端口，
		// 第二步请求还带着旧路径前缀，新路径门一挡就是 404（路径改
		// 成了、端口没改成）。合并成一次请求就没有这个窗口：先把
		// 两项全验完、再应用；端口要重启才生效，路径立即生效。
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		var body struct {
			Port int    `json:"port"`
			Path string `json:"path"`
		}
		if err := s.readJSON(r, &body); err != nil {
			errJSON(w, 400, "请求格式不对")
			return
		}
		curPort := 0
		if p := s.app.Store.GetSetting("panel_port"); p != "" {
			curPort, _ = strconv.Atoi(p)
		}
		curPath := s.app.Store.GetSetting("panel_path")
		newPath := strings.Trim(body.Path, "/ ")
		portChanged := body.Port != 0 && body.Port != curPort
		pathChanged := newPath != curPath
		if portChanged {
			if body.Port < 1 || body.Port > 65535 {
				errJSON(w, 400, "端口范围 1-65535")
				return
			}
			if portTaken(body.Port) {
				errJSON(w, 400, "端口已被占用")
				return
			}
		}
		if pathChanged && !validPanelPath(newPath) {
			errJSON(w, 400, "路径只能是 1-32 位英文、数字、-、_，不能用 sub、api，留空回到根目录")
			return
		}
		if !portChanged && !pathChanged {
			okJSON(w, map[string]interface{}{"port": curPort, "path": curPath, "restart_required": false})
			return
		}
		restartRequired := false
		note := ""
		kind := panelInitKind()
		if portChanged {
			// 服务文件找不到/读不出时直接报错，路径也不落盘（两项要么
			// 都改、要么都不改，不再出现“只改路径、端口丢了还谎称已保存”）。
			svcFile := panelServiceFile()
			if svcFile == "" {
				bin, _ := os.Executable()
				errJSON(w, 500, "找不到面板服务文件（容器或手动启动），端口与路径都未改动，请手动用新端口重启面板："+manualRestartCmd(s.app.Dir, bin, body.Port))
				return
			}
			b, err := os.ReadFile(svcFile)
			if err != nil {
				bin, _ := os.Executable()
				errJSON(w, 500, "读服务文件失败，端口与路径都未改动，请手动用新端口重启面板："+manualRestartCmd(s.app.Dir, bin, body.Port)+"（"+err.Error()+"）")
				return
			}
			updated, err := rewriteServicePort(string(b), body.Port)
			if err != nil {
				errJSON(w, 500, err.Error())
				return
			}
			mode := os.FileMode(0644)
			if fi, err := os.Stat(svcFile); err == nil {
				mode = fi.Mode()
			}
			if err := os.WriteFile(svcFile, []byte(updated), mode); err != nil {
				errJSON(w, 500, "写服务文件失败："+err.Error())
				return
			}
			// 只有 systemd 需要 daemon-reload；其他服务管理重读脚本。
			if kind == initSystemd {
				if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
					// 服务文件已写入新端口，手动重启后生效；路径照常立即生效。
					restartRequired = true
					note = "daemon-reload 失败：" + strings.TrimSpace(string(out))
				}
			}
			firewallAllowPort(body.Port)
		}
		if pathChanged {
			_ = s.app.Store.SetSetting("panel_path", newPath)
		}
		respPort := curPort
		if portChanged {
			respPort = body.Port
		}
		resp := map[string]interface{}{"port": respPort, "path": newPath, "restart_required": restartRequired}
		if note != "" {
			resp["note"] = note
		}
		okJSON(w, resp)
		if portChanged && !restartRequired {
			if cmd := restartPanelCommand(kind); cmd != nil {
				go func() {
					time.Sleep(800 * time.Millisecond)
					_ = exec.Command(cmd[0], cmd[1:]...).Run()
				}()
			}
		}
	case "sub-token":
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		tok := randToken()[:24]
		if err := s.app.Store.SetSetting("sub_token", tok); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		okJSON(w, map[string]interface{}{"sub_token": tok})
	case "sub-excluded":
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		var body struct {
			Excluded []string `json:"excluded"`
		}
		if err := s.readJSON(r, &body); err != nil {
			errJSON(w, 400, "请求格式不对")
			return
		}
		if body.Excluded == nil {
			body.Excluded = []string{}
		}
		raw, _ := json.Marshal(body.Excluded)
		if err := s.app.Store.SetSetting("sub_excluded", string(raw)); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		okJSON(w, nil)
	case "certs":
		if r.Method != "GET" {
			errJSON(w, 405, "method")
			return
		}
		s.handlePanelCerts(w, r)
	case "cert-manual":
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		s.handlePanelCertManual(w, r)
	case "cert-acme":
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		s.handlePanelCertAcme(w, r)
	case "cert-acme-status":
		if r.Method != "GET" {
			errJSON(w, 405, "method")
			return
		}
		s.handlePanelCertAcmeStatus(w, r)
	case "panel-https":
		if r.Method != "POST" {
			errJSON(w, 405, "method")
			return
		}
		s.handlePanelHTTPS(w, r)
	default:
		errJSON(w, 404, "未知操作")
	}
}

// ---------- subscription ----------

// ---------- background loops ----------

// quotaThreshold：限额提前 1G 停（1000G 到 999G 停），
// 限额本身不足 1G 时按 99.9% 停，避免还没跑就超。
func quotaThreshold(q int64) int64 {
	if q > 1<<30 {
		return q - (1 << 30)
	}
	return q * 999 / 1000
}

// checkQuota：节点用了超过限额门槛就停用并落盘生效，
// 只在跨越门槛那一刻做一次（停用后下次循环已跳过）。
func (s *Server) checkQuota(id string) {
	in, err := s.app.Store.GetInbound(id)
	if err != nil || !in.Enabled || in.QuotaMode == "" || in.QuotaBytes <= 0 {
		return
	}
	totals, _ := s.app.Store.TotalTraffic()
	t, ok := totals[id]
	if !ok {
		return
	}
	var used int64
	if in.QuotaMode == "down" {
		used = t[1]
	} else {
		used = t[0] + t[1]
	}
	if used >= quotaThreshold(in.QuotaBytes) {
		in.Enabled = false
		// 写库失败绝不能继续 Apply：Apply 是按库里状态生成的，
		// 库没改成就 Apply 等于没停用，超量节点继续跑。
		// 写库失败本轮跳过，下轮（3 秒后）重算重写，自愈。
		if err := s.app.Store.UpsertInbound(in); err == nil {
			_ = s.app.ApplyAll()
		}
	}
}

func (s *Server) StartBackground() {
	// 面板证书续期：启动即查一次，之后每 6 小时一查（只续 ACME 自动续签的证）。
	go s.certs.renewalLoop()
	// 过期会话清理：每小时清一次内存里过期的登录会话（authed 只清遇到的那一条）。
	go func() {
		for {
			time.Sleep(time.Hour)
			s.sweepExpiredSessions()
		}
	}()
	// traffic accumulation + realtime, every 3s
	go func() {
		// addTrafficFailed：记账失败的状态机，只在“成功→失败”
		// 跃变时打一条日志——每 3 秒打一次会把 panel.log 刷爆，
		// 完全不打则库一坏、用量静默丢数周。
		addTrafficFailed := map[string]bool{}
		addTraffic := func(id string, up, down int64) {
			if err := s.app.Store.AddTraffic(id, up, down); err != nil {
				if !addTrafficFailed[id] {
					addTrafficFailed[id] = true
					log.Printf("记账失败（节点 %s，本轮 %d/%d 字节未入库，恢复前不再重复报警）：%v", id, up, down, err)
				}
			} else {
				delete(addTrafficFailed, id)
			}
		}
		tick := 0
		for {
			time.Sleep(3 * time.Second)
			tick++
			// 日志控量：单文件超 10MB 只留最新 2000 行，后台每轮都扫一遍，
			// 长期不重启的核心也不会把日志堆上天。
			s.app.Sup.TrimLogs()
			if s.app.Mgr.Installed("sing-box") && s.app.Sup.Status("sing-box").Running {
				// nft 规则随节点走：每次轮询同步一次（只增缺失、只删多余），
				// 重启/手动 flush 后自愈；同步失败时 PollOnce 的错误会报出来。
				wantPorts := map[int]bool{}
				if list, err := s.app.Store.ListInbounds(); err == nil {
					for _, in := range list {
						if in.Enabled {
							wantPorts[in.Port] = true
						}
					}
				}
				// 同步失败也继续 PollOnce：计数器本身不停，少一轮
				// 规则同步只影响新增/删除的端口；但失败必须留痕，
				// 不能像以前那样用 _ 丢掉。
				syncErr := stats.SyncStatsRules(wantPorts)
				deltas, err := s.poller.PollOnce()
				if err != nil {
					s.statsMu.Lock()
					s.statsErr = err.Error()
					s.statsMu.Unlock()
				} else if syncErr != nil {
					s.statsMu.Lock()
					s.statsErr = "nft 规则同步失败：" + syncErr.Error()
					s.statsMu.Unlock()
				} else {
					s.statsMu.Lock()
					s.statsErr = ""
					s.statsMu.Unlock()
					for tag, d := range deltas {
						id := strings.TrimPrefix(tag, "in-")
						if id == tag {
							continue
						}
						if _, err := s.app.Store.GetInbound(id); err != nil {
							continue
						}
						if d[0] > 0 || d[1] > 0 {
							addTraffic(id, d[0], d[1])
							s.checkQuota(id)
						}
					}
				}
			}
			// 全量配额扫（每 10 轮 ≈ 30 秒）：只靠增量触发时，调低限额后
			// 闲置的节点超限永不生效；全量扫补上这个口子。
			if tick%10 == 0 {
				if list, err := s.app.Store.ListInbounds(); err == nil {
					for _, in := range list {
						if in.Enabled && in.QuotaMode != "" {
							s.checkQuota(in.ID)
						}
					}
				}
			}
		}
	}()
	// core update check, every 12h
	go func() {
		for {
			time.Sleep(12 * time.Hour)
			rows, _ := s.app.Store.ListCores()
			for _, c := range rows {
				if !c.Installed {
					continue
				}
				def, ok := cores.DefByName(c.Name)
				if !ok {
					continue
				}
				rels, err := cores.ListReleases(def.Repo)
				if err != nil || len(rels) == 0 {
					continue
				}
				c.Latest = rels[0].Tag
				c.LastCheck = time.Now().Unix()
				_ = s.app.Store.UpsertCore(c)
			}
		}
	}()
}

func qrcodePNG(content string) ([]byte, error) {
	return qrcodeEncode(content)
}
