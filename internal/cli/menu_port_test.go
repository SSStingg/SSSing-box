package cli

// 菜单改端口走服务端 panel-access 接口，不再自己改服务文件。
// 此文件只留端口解析测试 + 接口调用测试；服务文件改写由服务端
// panel_access_test.go 覆盖。

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sssingbox/internal/store"
	"testing"
)

// TestChangePanelPortCallsAPI：改端口应 POST /api/settings/panel-access，
// 且把当前路径一起带上（服务端一次改端口+路径，避免两步改的 404 窗口）。
func TestChangePanelPortCallsAPI(t *testing.T) {
	var gotPath string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Method != "POST" {
			t.Errorf("应为 POST，得到 %s", r.Method)
		}
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &gotBody); err != nil {
			t.Fatalf("请求体应为 JSON：%v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"data":{"port":19090,"path":"oc123","restart_required":false}}`))
	}))
	defer srv.Close()

	c := &client{base: srv.URL, http: srv.Client()}
	resp, err := changePanelPort(c, 19090, "oc123")
	if err != nil {
		t.Fatalf("应调用成功：%v", err)
	}
	if gotPath != "/api/settings/panel-access" {
		t.Fatalf("应调 panel-access 接口，得到 %s", gotPath)
	}
	if p, _ := gotBody["port"].(float64); p != 19090 {
		t.Fatalf("端口应为 19090，得到 %v", gotBody["port"])
	}
	if p, _ := gotBody["path"].(string); p != "oc123" {
		t.Fatalf("路径应原样带上 oc123，得到 %v", gotBody["path"])
	}
	if p, _ := resp["port"].(float64); p != 19090 {
		t.Fatalf("返回的端口应为 19090，得到 %v", resp["port"])
	}
}

// TestChangePanelPortServerError：服务端报错（如端口被占）时，错误应原样
// 透传给菜单打印，不谎称改成功。
func TestChangePanelPortServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false,"error":"端口已被占用"}`))
	}))
	defer srv.Close()

	c := &client{base: srv.URL, http: srv.Client()}
	if _, err := changePanelPort(c, 19090, ""); err == nil {
		t.Fatal("服务端报错时应返回错误")
	} else if err.Error() != "端口已被占用" {
		t.Fatalf("错误应透传“端口已被占用”，得到 %q", err.Error())
	}
}

func TestResolvePanelPortFromDB(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "sssingbox.db"))
	if err != nil {
		t.Fatalf("建测试库失败：%v", err)
	}
	if err := st.SetSetting("panel_port", "38083"); err != nil {
		t.Fatalf("写 panel_port 失败：%v", err)
	}
	st.Close()
	if got := resolvePanelPort(dir); got != 38083 {
		t.Fatalf("应读到库里的 38083，得到 %d", got)
	}
}

func TestResolvePanelPortFallbackNoDB(t *testing.T) {
	dir := t.TempDir()
	// 库不存在：回落 18081，且不得创建库文件。
	if got := resolvePanelPort(dir); got != 18081 {
		t.Fatalf("无库时应回落 18081，得到 %d", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "sssingbox.db")); !os.IsNotExist(err) {
		t.Fatal("无库时不得创建库文件")
	}
}

func TestResolvePanelPortFallbackBadValue(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "sssingbox.db"))
	if err != nil {
		t.Fatalf("建测试库失败：%v", err)
	}
	if err := st.SetSetting("panel_port", "abc"); err != nil {
		t.Fatalf("写 panel_port 失败：%v", err)
	}
	st.Close()
	if got := resolvePanelPort(dir); got != 18081 {
		t.Fatalf("非法值时应回落 18081，得到 %d", got)
	}
}
