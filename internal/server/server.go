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
	"net/url"
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
type loginFailState struct {
	count       int
	firstFail   time.Time
	lockedUntil time.Time
}

const (
	loginMaxFails   = 5
	loginLockPeriod = 15 * time.Minute
	loginFailWindow = 15 * time.Minute
	loginMaxEntries = 10000
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
		delete(s.loginFails, ip)
		return true
	}
	if now.Sub(st.firstFail) > loginFailWindow {
		delete(s.loginFails, ip)
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
	now := time.Now()
	st, ok := s.loginFails[ip]
	if !ok {
		// 防随机代理 IP 无限撑大 map：超上限时先清过期项，仍满则淘汰一条未锁定旧项。
		if len(s.loginFails) >= loginMaxEntries {
			for k, v := range s.loginFails {
				if (!v.lockedUntil.IsZero() && now.After(v.lockedUntil)) || (v.lockedUntil.IsZero() && now.Sub(v.firstFail) > loginFailWindow) {
					delete(s.loginFails, k)
				}
			}
			if len(s.loginFails) >= loginMaxEntries {
				for k, v := range s.loginFails {
					if v.lockedUntil.IsZero() {
						delete(s.loginFails, k)
						break
					}
				}
			}
		}
		s.loginFails[ip] = &loginFailState{count: 1, firstFail: now}
		return
	}
	if now.Sub(st.firstFail) > loginFailWindow {
		st.count = 1
		st.firstFail = now
		st.lockedUntil = time.Time{}
		return
	}
	st.count++
	if st.count >= loginMaxFails {
		st.lockedUntil = now.Add(loginLockPeriod)
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

func isBcryptHash(h string) bool {
	return len(h) == 60 && (strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") || strings.HasPrefix(h, "$2y$"))
}

var dummyHash = func() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	h, _ := bcrypt.GenerateFromPassword(b, bcrypt.DefaultCost)
	return string(h)
}()

type session struct {
	username string
	exp      time.Time
	created  time.Time
	remember bool
}

type Server struct {
	app           *App
	poller        *stats.Poller
	sessions      map[string]session
	sessMu        sync.Mutex
	writeMu       sync.Mutex
	startedAt     time.Time
	statsErr      string
	statsMu       sync.Mutex
	webFS         http.FileSystem
	updMu         sync.Mutex
	updPhase      string
	updRunning    int32
	onFirstListen func()
	loginFailMu   sync.Mutex
	loginFails    map[string]*loginFailState
	totpTmpMu     sync.Mutex
	totpTmp       map[string]totpChallenge
	certs         *panelCertManager
	restartCh     chan struct{}
	serveMu       sync.Mutex
	curSrv        *http.Server
	stopped       bool
	servingTLS    bool
	servingCert   string
}

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

func (s *Server) portTags() map[string]string {
	tags := map[string]string{}
	list, _ := s.app.Store.ListInbounds()
	for _, in := range list {
		if !in.Enabled {
			continue
		}
		for _, proto := range store.ProtocolTransports(in.Protocol) {
			tags[proto+":"+strconv.Itoa(in.Port)] = "in-" + in.ID
		}
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

// isHTTPSRequest：直连 TLS，或经本机反代（X-Forwarded-Proto: https）都算 HTTPS。
// 反代头只信任回环来源（本机 nginx/龟甲反代），外网直连的请求即使带这个头也不认，
// 否则明文面板会被骗发 Secure cookie，导致登录后会话发不回来。
func isHTTPSRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return false
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *Server) writeSessionCookie(w http.ResponseWriter, r *http.Request, tok string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sssingbox_session",
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPSRequest(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
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
		delete(s.sessions, c.Value)
		return false
	}
	return true
}

// sweepExpiredSessions：定期清理过期的会话、登录失败限流记录与 2FA 临时凭证，防止内存只增不减。
func (s *Server) sweepExpiredSessions() {
	now := time.Now()
	s.sessMu.Lock()
	for tok, sess := range s.sessions {
		if now.After(sess.exp) {
			delete(s.sessions, tok)
		}
	}
	s.sessMu.Unlock()

	s.loginFailMu.Lock()
	for ip, st := range s.loginFails {
		if (!st.lockedUntil.IsZero() && now.After(st.lockedUntil)) || (st.lockedUntil.IsZero() && now.Sub(st.firstFail) > loginFailWindow) {
			delete(s.loginFails, ip)
		}
	}
	s.loginFailMu.Unlock()

	s.totpTmpMu.Lock()
	for tok, ch := range s.totpTmp {
		if now.After(ch.exp) {
			delete(s.totpTmp, tok)
		}
	}
	s.totpTmpMu.Unlock()
}

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
	newTok := randToken()
	s.sessions[newTok] = session{username: sess.username, exp: sess.exp, created: time.Now(), remember: true}
	delete(s.sessions, c.Value)
	s.sessMu.Unlock()
	s.writeSessionCookie(w, r, newTok, int(time.Until(sess.exp).Seconds()))
}

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

func (s *Server) revokeSessionsExcept(keep string) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	for tok := range s.sessions {
		if tok != keep {
			delete(s.sessions, tok)
		}
	}
}

// checkSameOrigin 防御 CSRF（特别是 multipart/form-data 跨站表单上传）。
// 只对非 GET/HEAD/OPTIONS 状态变更请求生效；本机回环（CLI/脚本）以及无 Origin/Referer 的非浏览器测试调用按同源校验。
func checkSameOrigin(r *http.Request) bool {
	if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
		return true
	}
	if isLoopbackIP(clientIPOf(r)) {
		return true
	}
	src := r.Header.Get("Origin")
	if src == "" {
		src = r.Header.Get("Referer")
	}
	if src == "" {
		// 现代浏览器跨域表单或 fetch POST 必然携带 Origin（若被 Referrer-Policy 剥离 Referer 仍有 Origin）；
		// 只有在非浏览器直连或同站特殊策略下才同时为空，若请求是 multipart/form-data 则强制要求同源头防止 <form> 盲打。
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		if strings.HasPrefix(ct, "multipart/form-data") || strings.HasPrefix(ct, "application/x-www-form-urlencoded") || strings.HasPrefix(ct, "text/plain") {
			return false
		}
		return true
	}
	if src == "null" {
		return false
	}
	u, err := url.Parse(src)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			errJSON(w, 401, "未登录")
			return
		}
		if !checkSameOrigin(r) {
			errJSON(w, 403, "跨站请求已被拦截")
			return
		}
		s.maybeRotateSession(w, r)
		next(w, r)
	}
}

// ---------- routes ----------

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			s.serveFile(w, r, "index.html")
			return
		}
		s.serveFile(w, r, strings.TrimPrefix(r.URL.Path, "/"))
	})
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/login/2fa", s.handleLogin2FA)
	mux.HandleFunc("/api/logout", s.handleLogout)
	mux.HandleFunc("/api/me", s.handleMe)
	mux.HandleFunc("/api/setup-status", s.handleSetupStatus)
	mux.HandleFunc("/api/setup", s.mutating(s.handleSetup))
	mux.HandleFunc("/sub/", s.handleSub)

	auth := s.requireAuth
	mux.HandleFunc("/api/version", auth(s.handleVersion))
	mux.HandleFunc("/api/system", auth(s.handleSystem))
	mux.HandleFunc("/api/usage", auth(s.handleUsage))
	mux.HandleFunc("/api/cores", auth(s.handleCores))
	mux.HandleFunc("/api/cores/progress", auth(s.handleCoreProgress))
	mux.HandleFunc("/api/cores/", auth(s.handleCoreAction))
	mux.HandleFunc("/api/update/check", auth(s.handleUpdateCheck))
	mux.HandleFunc("/api/update/apply", auth(s.handleUpdateApply))
	mux.HandleFunc("/api/update/progress", auth(s.handleUpdateProgress))
	mux.HandleFunc("/api/inbounds", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			s.handleInbounds(w, r)
			return
		}
		s.mutating(s.handleInbounds)(w, r)
	}))
	mux.HandleFunc("/api/inbounds/", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			s.handleInboundAction(w, r)
			return
		}
		s.mutating(s.handleInboundAction)(w, r)
	}))
	mux.HandleFunc("/api/suggest-port", auth(s.handleSuggestPort))
	mux.HandleFunc("/api/sni-list", auth(s.handleSNIList))
	mux.HandleFunc("/api/sni-random", auth(s.handleSNIRandom))
	mux.HandleFunc("/api/bnodes", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			s.handleBNodes(w, r)
			return
		}
		s.mutating(s.handleBNodes)(w, r)
	}))
	mux.HandleFunc("/api/bnodes/", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			s.handleBNodeAction(w, r)
			return
		}
		s.mutating(s.handleBNodeAction)(w, r)
	}))
	mux.HandleFunc("/api/bnodes-latency", auth(s.handleBNodesLatency))
	mux.HandleFunc("/api/chains", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			s.handleChains(w, r)
			return
		}
		s.mutating(s.handleChains)(w, r)
	}))
	mux.HandleFunc("/api/chains/", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			s.handleChainAction(w, r)
			return
		}
		s.mutating(s.handleChainAction)(w, r)
	}))
	mux.HandleFunc("/api/settings", auth(s.handleSettings))
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
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
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
	if name == "index.html" {
		b, err := io.ReadAll(f)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		b = bytes.ReplaceAll(b, []byte("__PANEL_BASE__"), []byte(s.panelBase()))
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
		hash = dummyHash
	}
	if !s.loginAllowed(clientIPOf(r)) {
		errJSON(w, 429, "登录失败次数过多，请 15 分钟后再试")
		return
	}
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
	if err != nil {
		s.loginFailed(clientIPOf(r))
		errJSON(w, 401, "账号或密码不对")
		return
	}
	s.loginSucceeded(clientIPOf(r))
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
	s.writeSessionCookie(w, r, tok, maxAge)
	okJSON(w, map[string]interface{}{"username": body.Username})
}

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
	s.writeSessionCookie(w, r, tok, maxAge)
	s.totpMarkIP(clientIPOf(r))
	okJSON(w, map[string]interface{}{"username": ch.username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("sssingbox_session"); err == nil {
		s.sessMu.Lock()
		delete(s.sessions, c.Value)
		s.sessMu.Unlock()
	}
	s.writeSessionCookie(w, r, "", -1)
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

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	okJSON(w, map[string]interface{}{"setup_required": s.app.Store.UserCount() == 0, "version": version.Version})
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request, username string) {
	tok := randToken()
	s.sessMu.Lock()
	s.sessions[tok] = session{username: username, exp: time.Now().Add(24 * time.Hour), created: time.Now(), remember: false}
	s.sessMu.Unlock()
	s.writeSessionCookie(w, r, tok, 86400)
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
	if body.Username == "" || len(body.Username) > 32 || strings.ContainsAny(body.Username, " \t\n") {
		errJSON(w, 400, "用户名不能为空、不能含空格、不能超 32 位")
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
	panelPath := s.app.Store.GetSetting("panel_path")
	if panelPath == "" {
		panelPath = randPanelPath()
		_ = s.app.Store.SetSetting("panel_path", panelPath)
	}
	s.setSession(w, r, body.Username)
	okJSON(w, map[string]interface{}{"username": body.Username, "panel_path": panelPath})
}

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
	tcpByPort := sysinfo.TCPConnectionsByPort()
	udpByPort, udpOK := sysinfo.UDPConntrackByPort()
	for _, in := range inbounds {
		d := daily[in.ID]
		m := monthly[in.ID]
		t := total[in.ID]
		rt := rates["in-"+in.ID]
		tcp, udp := 0, 0
		if in.Enabled {
			tcp = tcpByPort[in.Port]
			if store.UDPOnlyProtocol(in.Protocol) {
				if udpOK {
					udp = udpByPort[in.Port]
				} else {
					udp = -1
				}
			} else {
				udp = -1
			}
		}
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
		tag, err := s.app.Mgr.Install(name, body.Version)
		if err != nil {
			errJSON(w, 500, "下载安装失败："+err.Error())
			return
		}
		s.writeMu.Lock()
		recErr := s.app.Store.UpsertCore(&store.Core{Name: name, Version: tag, Installed: true, Latest: tag, LastCheck: time.Now().Unix()})
		applyErr := s.app.ApplyAll()
		if applyErr == nil {
			s.poller.Reset()
		}
		s.writeMu.Unlock()
		if applyErr != nil {
			errJSON(w, 500, "安装成功但启动失败："+applyErr.Error())
			return
		}
		if recErr != nil {
			errJSON(w, 500, "安装成功但版本记录失败（下次打开核心卡片会显示旧版本）："+recErr.Error())
			return
		}
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
		s.writeMu.Lock()
		err := s.app.ApplyAll()
		s.writeMu.Unlock()
		if err != nil {
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
		return proxy.ShadowTLSLink(addr, in.Port, cfg, in.Name), ""
	}
	return "", ""
}

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
	if !inboundListensV6(in) {
		return "", ""
	}
	b := ip6
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
		return "", ""
	case "snell":
		var cfg proxy.SnellConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.SnellLink(b, in.Port, cfg, name), ""
	case "shadowtls":
		var cfg proxy.ShadowTLSConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.ShadowTLSLink(b, in.Port, cfg, name), ""
	}
	return "", ""
}

// resyncAfterRollback：应用失败后库已回滚，但内核可能已按坏配置重启过
// （ApplyAll 先重启内核、后同步跳端口 nft，nft 一失败内核就留着坏配置跑）。
// 库已干净，再应用一次把运行中的内核同步回库的状态。失败只记日志，
// 不改动本次已返回给用户的错误。
func (s *Server) resyncAfterRollback() {
	if err := s.app.ApplyAll(); err != nil {
		log.Printf("回滚后重应用失败（内核与库可能不一致）：%v", err)
	}
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
		if body.QuotaMode != "" && body.QuotaBytes <= 0 {
			errJSON(w, 400, "流量限额必须大于 0（不限量请把模式留空）")
			return
		}
		if core := requiredCore(body.Protocol); core != "" && !s.app.Mgr.Installed(core) {
			errJSON(w, 400, core+" 内核还没安装：先去“系统概览”页的内核卡片安装 "+core+"，装好再创建节点")
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
			_ = s.app.Store.DeleteInbound(in.ID)
			s.resyncAfterRollback()
			errJSON(w, 500, "节点启动失败（已撤销创建）："+err.Error())
			return
		}
		link, tme := s.inboundLinks(in)
		link6, _ := s.inboundLinks6(in)
		okJSON(w, map[string]interface{}{"inbound": in, "link": link, "link6": link6, "tme_link": tme})
	default:
		errJSON(w, 405, "method")
	}
}

func advancedMode(adv map[string]interface{}) string {
	if adv == nil {
		return ""
	}
	m, _ := adv["mode"].(string)
	return m
}

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
		for _, t := range store.ProtocolTransports(in.Protocol) {
			if t == "udp" {
				udpUsed[in.Port] = true
			} else {
				tcpUsed[in.Port] = true
			}
		}
		if in.Protocol == "hy2" {
			var hc proxy.Hy2Config
			if json.Unmarshal([]byte(in.Config), &hc) == nil {
				if hc.StatsPort > 0 {
					tcpUsed[hc.StatsPort] = true
				}
				if start, end, err := proxy.ParseHopPorts(hc.HopPorts); err == nil {
					for p := start; p <= end; p++ {
						udpUsed[p] = true
					}
				}
			}
		}
		if in.Protocol == "shadowtls" {
			var stc proxy.ShadowTLSConfig
			if json.Unmarshal([]byte(in.Config), &stc) == nil && stc.InnerPort > 0 {
				tcpUsed[stc.InnerPort] = true
			}
		}
	}
	if p := s.app.Store.GetSetting("panel_port"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			tcpUsed[n] = true
		}
	}
	free := func(p int) bool {
		for _, t := range store.ProtocolTransports(protocol) {
			if t == "udp" && udpUsed[p] {
				return false
			}
			if t == "tcp" && tcpUsed[p] {
				return false
			}
		}
		return true
	}
	if (protocol == "vmess" || protocol == "trojan") && len(mode) > 0 && mode[0] == "cf" {
		for _, p := range proxy.CFPorts {
			if free(p) {
				return p, fmt.Sprintf("CF 模式：源站端口必须是 CF 允许的端口，建议 %d", p)
			}
		}
		return 0, "CF 允许的端口都被占用了"
	}
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
		if i := strings.Index(line, `users:(("`); i >= 0 {
			rest := line[i+len(`users:(("`):]
			if j := strings.Index(rest, `"`); j > 0 {
				return rest[:j]
			}
		}
	}
	return ""
}

func requiredCore(protocol string) string {
	switch protocol {
	case "vless", "vmess", "ss", "socks", "http", "trojan", "wireguard", "hy2", "tuic", "anytls", "naive", "snell", "shadowtls":
		return "sing-box"
	}
	return ""
}

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
			// 留空 = 从 SNI 池随机推荐，bing.com 永不入选。
			cfg.ObfsHost = proxy.RandomSnellObfsHost()
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
	udpUsed := sysinfo.BoundUDPPorts()
	for _, t := range store.ProtocolTransports(protocol) {
		if t == "tcp" && tcpUsed[port] {
			return nil, fmt.Errorf("端口 %d 的 TCP 已被系统其他程序占用", port)
		}
		if t == "udp" && udpUsed[port] {
			return nil, fmt.Errorf("端口 %d 的 UDP 已被系统其他程序占用", port)
		}
	}
	if name == "" {
		short := map[string]string{"vless": "VLESS", "hy2": "HY2", "vmess": "VMess", "ss": "SS", "socks": "SOCKS", "http": "HTTP", "trojan": "TROJAN", "wireguard": "WG", "tuic": "TUIC", "anytls": "ANYTLS", "naive": "NAIVE", "snell": "SNELL", "shadowtls": "SHADOWTLS"}[protocol]
		name = fmt.Sprintf("%s-%d", short, port)
	}
	if address == "" {
		address = s.app.PublicIP()
		if address == "" {
			return nil, fmt.Errorf("无法自动获取公网 IP，请手动填写节点地址")
		}
	}
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
	if protocol == "naive" && sni == "" {
		return nil, fmt.Errorf("Naive 需要填写真实域名（CA 证书上的域名，解析到本机）")
	}
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
		if pw, ok := advanced["password"].(string); !ok || pw == "" {
			cfg.Password = proxy.SSKey(cfg.Method)
		}
		in.Config = store.MustJSON(cfg)
	case "socks":
		cfg := proxy.DefaultSocks()
		mergeAdvanced(&cfg, advanced)
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

func (s *Server) uniqueID(exists func(string) bool) string {
	for i := 0; i < 100; i++ {
		id := randHexID()
		if !exists(id) {
			return id
		}
	}
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

func (s *Server) allocStatsPort() int {
	used := map[int]bool{}
	for p := range sysinfo.ListeningTCPPorts() {
		used[p] = true
	}
	inbounds, _ := s.app.Store.ListInbounds()
	for _, in := range inbounds {
		if in.Protocol == "hy2" {
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

// allocInnerPort：给 ShadowTLS 内层 SS 分配回环端口（20000-20999），并避开 Hy2 跳跃段。
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
			if start, end, err := proxy.ParseHopPorts(cfg.HopPorts); err == nil {
				for p := start; p <= end; p++ {
					if p >= 20000 && p < 21000 {
						used[p] = true
					}
				}
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
	oldIn := *in
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
				tcpUsed := sysinfo.ListeningTCPPorts()
				udpUsed := sysinfo.BoundUDPPorts()
				for _, t := range store.ProtocolTransports(in.Protocol) {
					if t == "tcp" && tcpUsed[*body.Port] {
						errJSON(w, 400, fmt.Sprintf("端口 %d 的 TCP 已被系统其他程序占用", *body.Port))
						return
					}
					if t == "udp" && udpUsed[*body.Port] {
						errJSON(w, 400, fmt.Sprintf("端口 %d 的 UDP 已被系统其他程序占用", *body.Port))
						return
					}
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
			if (body.QuotaMode != nil || body.QuotaBytes != nil) && in.QuotaMode != "" && in.QuotaBytes <= 0 {
				errJSON(w, 400, "流量限额必须大于 0（不限量请把模式留空）")
				return
			}
			if body.SNI != nil && *body.SNI != in.SNI {
				in.SNI = *body.SNI
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
					var cfg proxy.VMessConfig
					_ = json.Unmarshal([]byte(in.Config), &cfg)
					if cfg.Mode == "cf" || cfg.Mode == "http" || cfg.Mode == "quic" || cfg.Mode == "h2" || cfg.Mode == "httpupgrade" {
						cfg.Domain = in.SNI
						in.Config = store.MustJSON(cfg)
					}
				}
				if in.Protocol == "trojan" {
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
				_ = s.app.Store.UpsertInbound(&oldIn)
				s.resyncAfterRollback()
				errJSON(w, 500, "修改未生效（已回滚配置）："+err.Error())
				return
			}
			s.checkQuotaLocked(in.ID)
			link, tme := s.inboundLinks(in)
			link6, _ := s.inboundLinks6(in)
			okJSON(w, map[string]interface{}{"inbound": in, "link": link, "link6": link6, "tme_link": tme})
		case "DELETE":
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
			errJSON(w, 400, core+" 内核还没安装：先去“系统概览”页的内核卡片安装 "+core+"，装好再克隆节点")
			return
		}
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
			if cfg.CertFile != "" && cfg.KeyFile != "" {
				newCert := filepath.Join(s.app.ConfigDir(), "naive-"+clone.ID+".crt")
				newKey := filepath.Join(s.app.ConfigDir(), "naive-"+clone.ID+".key")
				certData, certErr := os.ReadFile(cfg.CertFile)
				keyData, keyErr := os.ReadFile(cfg.KeyFile)
				if certErr == nil && keyErr == nil &&
					os.WriteFile(newCert, certData, 0600) == nil &&
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
			_ = s.app.Store.DeleteInbound(clone.ID)
			s.resyncAfterRollback()
			errJSON(w, 500, "克隆启动失败（已撤销创建）："+err.Error())
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
			_ = s.app.Store.UpsertInbound(&oldIn)
			s.resyncAfterRollback()
			errJSON(w, 500, "伪装域名未换（已回滚配置）："+err.Error())
			return
		}
		link, tme := s.inboundLinks(in)
		link6, _ := s.inboundLinks6(in)
		okJSON(w, map[string]interface{}{"inbound": in, "link": link, "link6": link6, "tme_link": tme, "sni": newSNI})
	case "cert":
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
		oldIn := *in
		var cfg proxy.NaiveConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		cfg.CertFile, cfg.KeyFile = certPath, keyPath
		in.Config = store.MustJSON(cfg)
		in.Enabled = true
		in.UpdatedAt = time.Now().Unix()
		if err := s.app.Store.UpsertInbound(in); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		if err := s.app.ApplyAll(); err != nil {
			_ = s.app.Store.UpsertInbound(&oldIn)
			s.resyncAfterRollback()
			errJSON(w, 500, "证书已保存但启动失败（已回滚配置）："+err.Error())
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
	// 支持多个 exclude（?exclude=a&exclude=b），单值照旧兼容。
	exs := r.URL.Query()["exclude"]
	okJSON(w, proxy.RecommendSNIExcluding(exs...))
}

// ---------- bnodes & chains ----------

func (s *Server) handleBNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		list, _ := s.app.Store.ListBNodes()
		if list == nil {
			list = []*store.BNode{}
		}
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

// isInternalTarget 拦截本机回环、私网、链路本地与未指定地址，防止借延迟探活探测内网端口（SSRF）。
func isInternalTarget(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return true
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return true
		}
	}
	return false
}

func (s *Server) handleBNodesLatency(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	list, _ := s.app.Store.ListBNodes()
	type row struct {
		ID   string `json:"id"`
		MS   int64  `json:"ms"`
		Kind string `json:"kind"`
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
			if err != nil || isInternalTarget(host) {
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

// validateChainInput 统一校验链式创建与编辑参数：
// 1. 支持除 WireGuard / dokodemo 外全部 12 种本地协议作为入口 A；
// 2. 强制单 A 节点唯一绑定一条链式配置，防多链抢同一入站；
// 3. 支持 direct 全局直通与 split 多节点分流（B1/B2/B3... + 可选未命中兜底 B）；
// 4. 向下兼容旧版单分流参数（仅传 bnode_id + list）。
func (s *Server) validateChainInput(excludeChainID, inboundID, mode, bnodeID string, routes []store.ChainRoute, legacyList string) (*store.Inbound, string, string, []store.ChainRoute, error) {
	if inboundID == "" {
		return nil, "", "", nil, fmt.Errorf("请选择入口 A 节点")
	}
	in, err := s.app.Store.GetInbound(inboundID)
	if err != nil || !proxy.CanBeChainA(in.Protocol) {
		return nil, "", "", nil, fmt.Errorf("入口 A 节点不存在或协议不支持链式（支持除 WireGuard、dokodemo 外全部本机节点）")
	}
	existing, _ := s.app.Store.ListChains()
	for _, c := range existing {
		if c.ID != excludeChainID && c.InboundID == inboundID {
			return nil, "", "", nil, fmt.Errorf("该 A 节点已有链式规则，一个 A 节点只能有一条链式（多节点分流请在该规则中添加分流组）")
		}
	}
	if mode != "" && mode != "split" && mode != "direct" {
		return nil, "", "", nil, fmt.Errorf("链式方式不对")
	}
	if mode == "direct" {
		if bnodeID == "" {
			return nil, "", "", nil, fmt.Errorf("全局直通模式必须选择落地 B 节点")
		}
		if _, err := s.app.Store.GetBNode(bnodeID); err != nil {
			return nil, "", "", nil, fmt.Errorf("B 节点不存在")
		}
		return in, "direct", bnodeID, []store.ChainRoute{}, nil
	}

	// split 多路分流模式（兼容旧调用：未传 routes 时由 bnode_id + list 升格为第 1 组）
	if len(routes) == 0 && bnodeID != "" && strings.TrimSpace(legacyList) != "" {
		routes = []store.ChainRoute{{BNodeID: bnodeID, List: legacyList}}
		bnodeID = ""
	}
	if len(routes) == 0 {
		return nil, "", "", nil, fmt.Errorf("域名或 IP 分流组不能为空")
	}
	specs := make([]proxy.ChainRouteSpec, len(routes))
	for i, r := range routes {
		if r.BNodeID == "" {
			return nil, "", "", nil, fmt.Errorf("第 %d 组未选择落地 B 节点", i+1)
		}
		if _, err := s.app.Store.GetBNode(r.BNodeID); err != nil {
			return nil, "", "", nil, fmt.Errorf("第 %d 组的 B 节点不存在", i+1)
		}
		specs[i] = proxy.ChainRouteSpec{BNodeID: r.BNodeID, List: r.List}
	}
	normLists, err := proxy.ValidateAndNormalizeRoutes(specs)
	if err != nil {
		return nil, "", "", nil, err
	}
	if bnodeID != "" {
		if _, err := s.app.Store.GetBNode(bnodeID); err != nil {
			return nil, "", "", nil, fmt.Errorf("默认兜底 B 节点不存在")
		}
		for i, r := range routes {
			if r.BNodeID == bnodeID {
				return nil, "", "", nil, fmt.Errorf("默认兜底节点与第 %d 组相同：其余流量既然也走该节点，直接删掉第 %d 组即可", i+1, i+1)
			}
		}
	}
	cleanRoutes := make([]store.ChainRoute, len(routes))
	for i := range routes {
		cleanRoutes[i] = store.ChainRoute{BNodeID: routes[i].BNodeID, List: normLists[i]}
	}
	return in, "split", bnodeID, cleanRoutes, nil
}

func (s *Server) handleChains(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		list, err := s.app.Store.ListChains()
		if err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		if list == nil {
			list = []*store.Chain{}
		}
		okJSON(w, list)
	case "POST":
		var body struct {
			Name      string             `json:"name"`
			InboundID string             `json:"inbound_id"`
			List      string             `json:"list"`
			Mode      string             `json:"mode"`
			BNodeID   string             `json:"bnode_id"`
			Routes    []store.ChainRoute `json:"routes"`
		}
		if err := s.readJSON(r, &body); err != nil {
			errJSON(w, 400, "请求格式不对")
			return
		}
		in, mode, fbBNodeID, cleanRoutes, err := s.validateChainInput("", body.InboundID, body.Mode, body.BNodeID, body.Routes, body.List)
		if err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		name := strings.TrimSpace(body.Name)
		if name == "" {
			name = "链式-" + in.Name
		}
		legacyList := ""
		if mode == "split" && len(cleanRoutes) == 1 && fbBNodeID == "" {
			legacyList = cleanRoutes[0].List
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
			}),
			Name:      name,
			InboundID: body.InboundID,
			List:      legacyList,
			Mode:      mode,
			BNodeID:   fbBNodeID,
			Routes:    cleanRoutes,
			Enabled:   true,
			CreatedAt: time.Now().Unix(),
		}
		if err := s.app.Store.UpsertChain(ch); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		if err := s.app.ApplyAll(); err != nil {
			_ = s.app.Store.DeleteChain(ch.ID)
			s.resyncAfterRollback()
			errJSON(w, 500, "链式启动失败（已撤销创建）："+err.Error())
			return
		}
		okJSON(w, ch)
	default:
		errJSON(w, 405, "method")
	}
}

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
	oldCh := *ch
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
			Name      *string             `json:"name"`
			InboundID *string             `json:"inbound_id"`
			List      *string             `json:"list"`
			Mode      *string             `json:"mode"`
			BNodeID   *string             `json:"bnode_id"`
			Routes    *[]store.ChainRoute `json:"routes"`
			Enabled   *bool               `json:"enabled"`
		}
		if err := s.readJSON(r, &body); err != nil {
			errJSON(w, 400, "请求格式不对")
			return
		}
		if body.Name != nil {
			if strings.TrimSpace(*body.Name) == "" {
				errJSON(w, 400, "链式名不能为空")
				return
			}
			ch.Name = strings.TrimSpace(*body.Name)
		}
		if body.Enabled != nil {
			ch.Enabled = *body.Enabled
		}
		// 若本次请求修改了路由结构相关的任意字段，统一跑全量冲突与合法性校验
		if body.InboundID != nil || body.Mode != nil || body.BNodeID != nil || body.Routes != nil || body.List != nil {
			inID := ch.InboundID
			if body.InboundID != nil {
				inID = *body.InboundID
			}
			mode := ch.Mode
			if body.Mode != nil {
				mode = *body.Mode
			}
			bID := ch.BNodeID
			if body.BNodeID != nil {
				bID = *body.BNodeID
			}
			rts := ch.Routes
			if body.Routes != nil {
				rts = *body.Routes
			} else if body.List != nil && mode != "direct" {
				// 兼容仅改单路 List/BNodeID 的旧式 PUT 请求
				targetB := bID
				if targetB == "" && len(ch.Routes) > 0 {
					targetB = ch.Routes[0].BNodeID
				}
				rts = []store.ChainRoute{{BNodeID: targetB, List: *body.List}}
				if body.BNodeID != nil {
					bID = ""
				}
			}
			legacyList := ch.List
			if body.List != nil {
				legacyList = *body.List
			}
			_, cleanMode, fbBNodeID, cleanRoutes, err := s.validateChainInput(ch.ID, inID, mode, bID, rts, legacyList)
			if err != nil {
				errJSON(w, 400, err.Error())
				return
			}
			ch.InboundID = inID
			ch.Mode = cleanMode
			ch.BNodeID = fbBNodeID
			ch.Routes = cleanRoutes
			if cleanMode == "direct" {
				ch.List = ""
			} else if len(cleanRoutes) == 1 && fbBNodeID == "" {
				ch.List = cleanRoutes[0].List
			} else {
				ch.List = ""
			}
		}
		if err := s.app.Store.UpsertChain(ch); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		if err := s.app.ApplyAll(); err != nil {
			_ = s.app.Store.UpsertChain(&oldCh)
			s.resyncAfterRollback()
			errJSON(w, 500, "修改未生效（已回滚配置）："+err.Error())
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
			s.syncCliCredentials(body.New, "")
		}
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
		s.syncCliCredentials(username, body.New)
		if c, err := r.Cookie("sssingbox_session"); err == nil {
			s.revokeSessionsExcept(c.Value)
		}
		okJSON(w, nil)
	case "password-local":
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
			if kind == initSystemd {
				if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
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

// ---------- background loops ----------

func quotaThreshold(q int64) int64 {
	if q > 1<<30 {
		return q - (1 << 30)
	}
	return q * 999 / 1000
}

// checkQuotaLocked 在调用方已持有 s.writeMu 时执行配额检查与停用。
func (s *Server) checkQuotaLocked(id string) {
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
		if err := s.app.Store.UpsertInbound(in); err == nil {
			_ = s.app.ApplyAll()
		}
	}
}

// checkQuota 供后台轮询协程调用：先无锁快检，仅在达到阈值时加 s.writeMu 二次确认并停用。
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
	if used < quotaThreshold(in.QuotaBytes) {
		return
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.checkQuotaLocked(id)
}

func (s *Server) StartBackground() {
	go s.certs.renewalLoop()
	go func() {
		for {
			time.Sleep(time.Hour)
			s.sweepExpiredSessions()
		}
	}()
	go func() {
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
			s.app.Sup.TrimLogs()
			if s.app.Mgr.Installed("sing-box") && s.app.Sup.Status("sing-box").Running {
				wantTCP := map[int]bool{}
				wantUDP := map[int]bool{}
				if list, err := s.app.Store.ListInbounds(); err == nil {
					for _, in := range list {
						if !in.Enabled {
							continue
						}
						for _, proto := range store.ProtocolTransports(in.Protocol) {
							if proto == "udp" {
								wantUDP[in.Port] = true
							} else {
								wantTCP[in.Port] = true
							}
						}
					}
				}
				syncErr := stats.SyncStatsRules(wantTCP, wantUDP)
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
