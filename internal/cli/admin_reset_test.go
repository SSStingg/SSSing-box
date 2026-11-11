package cli

// admin reset 是空哈希账号的修复路——它自己不能再写空哈希。

import (
	"bufio"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"sssingbox/internal/store"
)

func feedStdin(t *testing.T, input string) func() {
	t.Helper()
	old := stdin
	stdin = bufio.NewReader(strings.NewReader(input))
	return func() { stdin = old }
}

func newResetTestStore(t *testing.T) (string, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "sssingbox.db"))
	if err != nil {
		t.Fatalf("建临时 Store 失败：%v", err)
	}
	t.Cleanup(func() { st.Close() })
	h, _ := bcrypt.GenerateFromPassword([]byte("oldpass123"), bcrypt.DefaultCost)
	if err := st.CreateUser("admin", string(h)); err != nil {
		t.Fatalf("建用户失败：%v", err)
	}
	return dir, st
}

// TestAdminResetRejectsTooLongPassword：超 72 字节的新密码应拒绝，
// 且库里的旧哈希原样不动（以前 GenerateFromPassword 的错误被吞了，
// 空哈希直接入库，修账号的路自己就是锁死账号的路）。
func TestAdminResetRejectsTooLongPassword(t *testing.T) {
	dir, st := newResetTestStore(t)
	oldHash, _ := st.GetUser("admin")
	long := strings.Repeat("a", 73)
	defer feedStdin(t, "\n"+long+"\n"+long+"\n")()
	if rc := runAdminReset(options{dataDir: dir}); rc == 0 {
		t.Fatal("73 字节密码重置应失败")
	}
	got, _ := st.GetUser("admin")
	if got != oldHash {
		t.Fatalf("超长密码被拒后旧哈希应原样不动，得到 %q", got)
	}
	if got == "" {
		t.Fatal("旧哈希不应被写空")
	}
}

// TestAdminResetRepairsEmptyHash：库里是空哈希的账号（旧版超长密码 bug
// 的产物），admin reset 应能直接修好，不用旧密码。
func TestAdminResetRepairsEmptyHash(t *testing.T) {
	dir, st := newResetTestStore(t)
	if err := st.UpdatePassword("admin", ""); err != nil {
		t.Fatalf("写空哈希失败：%v", err)
	}
	defer feedStdin(t, "\nnewpass123\nnewpass123\n")()
	if rc := runAdminReset(options{dataDir: dir}); rc != 0 {
		t.Fatal("空哈希账号应能通过 admin reset 修好")
	}
	got, _ := st.GetUser("admin")
	if err := bcrypt.CompareHashAndPassword([]byte(got), []byte("newpass123")); err != nil {
		t.Fatalf("重置后的哈希应对上新密码：%v", err)
	}
}

// TestAdminResetRejectsShortPassword：短于 6 位的新密码应拒绝。
func TestAdminResetRejectsShortPassword(t *testing.T) {
	dir, st := newResetTestStore(t)
	oldHash, _ := st.GetUser("admin")
	defer feedStdin(t, "\nabc\nabc\n")()
	if rc := runAdminReset(options{dataDir: dir}); rc == 0 {
		t.Fatal("3 位密码重置应失败")
	}
	if got, _ := st.GetUser("admin"); got != oldHash {
		t.Fatal("短密码被拒后旧哈希应原样不动")
	}
}
