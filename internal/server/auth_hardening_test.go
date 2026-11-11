package server

import (
	"path/filepath"
	"strings"
	"testing"

	"sssingbox/internal/store"
)

// 登录限流 + 密码 72 字节上限。

func TestLoginRateLimit(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	// 连续 5 次输错密码都应 401。
	for i := 0; i < 5; i++ {
		rec := postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"wrongpass"}`, nil)
		if rec.Code != 401 {
			t.Fatalf("第 %d 次输错密码应 401，得到 %d", i+1, rec.Code)
		}
	}
	// 第 6 次（哪怕密码对了）也应 429 锁定。
	rec := postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"oldpass123"}`, nil)
	if rec.Code != 429 {
		t.Fatalf("锁定期内登录应 429，得到 %d", rec.Code)
	}
}

func TestLoginSuccessResetsFailures(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	for i := 0; i < 4; i++ {
		rec := postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"wrongpass"}`, nil)
		if rec.Code != 401 {
			t.Fatalf("输错密码应 401，得到 %d", rec.Code)
		}
	}
	// 登录成功应清零计数。
	rec := postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"oldpass123"}`, nil)
	if ok, _ := decodeOK(t, rec); !ok || rec.Code != 200 {
		t.Fatalf("成功登录应 200，得到 %d", rec.Code)
	}
	// 清零后要重新攒满 5 次才锁。
	for i := 0; i < 5; i++ {
		rec := postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"wrongpass"}`, nil)
		if rec.Code != 401 {
			t.Fatalf("清零后第 %d 次输错应 401，得到 %d", i+1, rec.Code)
		}
	}
	rec = postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"oldpass123"}`, nil)
	if rec.Code != 429 {
		t.Fatalf("重新攒满 5 次后应 429，得到 %d", rec.Code)
	}
}

func TestPasswordTooLong(t *testing.T) {
	long := strings.Repeat("a", 73)
	// 初始设置：超长密码应拒绝（以前 bcrypt 报错被吞，空哈希入库锁死账号）。
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("建临时 Store 失败：%v", err)
	}
	t.Cleanup(func() { st.Close() })
	empty := &Server{app: &App{Store: st}, sessions: map[string]session{}}
	rec := postJSON(t, empty, empty.handleSetup, "/api/setup", `{"username":"u1","password":"`+long+`","password2":"`+long+`"}`, nil)
	if rec.Code != 400 {
		t.Fatalf("超长密码初始设置应 400，得到 %d", rec.Code)
	}
	if st.UserCount() != 0 {
		t.Fatal("超长密码被拒后不应建出用户")
	}
	// 改密码：超长新密码应拒绝。
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)
	rec = postJSON(t, s, s.handleSettingsAction, "/api/settings/password", `{"old":"oldpass123","new":"`+long+`","new2":"`+long+`"}`, c)
	if rec.Code != 400 {
		t.Fatalf("超长新密码应 400，得到 %d", rec.Code)
	}
	if !loginOK(t, s, `{"username":"u1","password":"oldpass123"}`) {
		t.Fatal("超长密码被拒后旧密码应仍能登录")
	}
	// 设置页：超长密码应拒绝。
	rec = postJSON(t, s, s.handleSettingsAction, "/api/settings/login", `{"username":"","password":"`+long+`","old_password":"oldpass123"}`, c)
	if rec.Code != 400 {
		t.Fatalf("设置页超长密码应 400，得到 %d", rec.Code)
	}
	if !loginOK(t, s, `{"username":"u1","password":"oldpass123"}`) {
		t.Fatal("设置页超长密码被拒后旧密码应仍能登录")
	}
	// 72 字节正好是上限，应通过（初始设置走一遍）。
	st2, err := store.Open(filepath.Join(t.TempDir(), "test2.db"))
	if err != nil {
		t.Fatalf("建临时 Store 失败：%v", err)
	}
	t.Cleanup(func() { st2.Close() })
	empty2 := &Server{app: &App{Store: st2}, sessions: map[string]session{}}
	exact := strings.Repeat("b", 72)
	rec = postJSON(t, empty2, empty2.handleSetup, "/api/setup", `{"username":"u1","password":"`+exact+`","password2":"`+exact+`"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("72 字节密码应通过，得到 %d", rec.Code)
	}
}

// ---------- 空哈希账号登录明说修复路 ----------

// TestLoginBrokenHash：库里是空哈希或非法哈希的账号，登录要明说
// “账号密码已损坏，请用本机 CLI 重置密码”，别只给“账号或密码不对”。
func TestLoginBrokenHash(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	// 空哈希：之前超长密码 bug 的产物。
	if err := s.app.Store.UpdatePassword("u1", ""); err != nil {
		t.Fatalf("写空哈希失败：%v", err)
	}
	rec := postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"oldpass123"}`, nil)
	if rec.Code != 401 {
		t.Fatalf("空哈希登录应 401，得到 %d", rec.Code)
	}
	if _, msg := decodeOK(t, rec); !strings.Contains(msg, "账号密码已损坏") {
		t.Fatalf("空哈希登录应明说密码损坏，得到 %q", msg)
	}
	// 非法哈希：同样明说。
	if err := s.app.Store.UpdatePassword("u1", "not-a-bcrypt-hash"); err != nil {
		t.Fatalf("写非法哈希失败：%v", err)
	}
	rec = postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"oldpass123"}`, nil)
	if rec.Code != 401 {
		t.Fatalf("非法哈希登录应 401，得到 %d", rec.Code)
	}
	if _, msg := decodeOK(t, rec); !strings.Contains(msg, "账号密码已损坏") {
		t.Fatalf("非法哈希登录应明说密码损坏，得到 %q", msg)
	}
	// 正常哈希不受影响（对照组）。
	s2 := newAuthTestServer(t, "u1", "oldpass123")
	if !loginOK(t, s2, `{"username":"u1","password":"oldpass123"}`) {
		t.Fatal("正常账号应能登录")
	}
}
