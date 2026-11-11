package server

// v1.0.2：在线更新重启（按服务管理来 + 手动重启判定 + setup-status 带版本）。

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"sssingbox/internal/version"
)

func TestUpdateRestartRequired(t *testing.T) {
	cases := []struct {
		name string
		exe  string
		kind initKind
		want bool
	}{
		{"标准路径 + systemd 自动重启", "/usr/local/bin/sssingbox", initSystemd, false},
		{"标准路径 + OpenRC 自动重启", "/usr/local/bin/sssingbox", initOpenRC, false},
		{"标准路径 + procd 自动重启", "/usr/local/bin/sssingbox", initProcd, false},
		{"标准路径 + sysvinit 自动重启", "/usr/local/bin/sssingbox", initSysvinit, false},
		{"标准路径 + 无服务管理 手动重启", "/usr/local/bin/sssingbox", initNone, true},
		{"非标准路径 + systemd 手动重启（演示面板）", "/tmp/sssingbox", initSystemd, true},
		{"非标准路径 + 无服务管理 手动重启", "/tmp/sssingbox", initNone, true},
	}
	for _, c := range cases {
		if got := updateRestartRequired(c.exe, c.kind); got != c.want {
			t.Fatalf("%s：应为 %v，得到 %v", c.name, c.want, got)
		}
	}
}

func TestSetupStatus_HasVersion(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	req := httptest.NewRequest("GET", "/api/setup-status", nil)
	rec := httptest.NewRecorder()
	s.handleSetupStatus(rec, req)
	var out struct {
		OK   bool `json:"ok"`
		Data struct {
			SetupRequired bool   `json:"setup_required"`
			Version       string `json:"version"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("解响应失败：%v", err)
	}
	if !out.OK {
		t.Fatal("setup-status 应成功")
	}
	if out.Data.Version != version.Version {
		t.Fatalf("setup-status 应带当前版本号 %q，得到 %q", version.Version, out.Data.Version)
	}
}
