package server

import (
	"net/http"
	"net/http/httptest"
	"sssingbox/internal/store"
	"testing"
)

func TestSubFormat(t *testing.T) {
	cases := []struct{ format, ua, want string }{
		{"singbox", "", "singbox"},
		{"clash", "", "clash"},
		{"base64", "", "base64"},
		{"", "Hiddify/2.5.0", "singbox"},
		// Hiddify 的 UA 里同时带 ClashMeta：hiddify 必须先于 clash 命中。
		{"", "Hiddify/2.5.0 ClashMeta", "singbox"},
		{"", "sing-box/1.14.4", "singbox"},
		{"", "Karing/1.0", "singbox"},
		{"", "NekoBox/1.3", "singbox"},
		{"", "ClashMeta/1.19", "clash"},
		{"", "clash-verge/2.0", "clash"},
		{"", "mihomo/1.19", "clash"},
		{"", "Stash/2.0", "clash"},
		{"", "v2rayN/6.0", "base64"},
		{"", "Shadowrocket/2.0", "base64"},
		{"", "Mozilla/5.0", "base64"},
		{"", "", "base64"},
		// ?format= 永远优先于 UA。
		{"clash", "Hiddify/2.5.0", "clash"},
		{"singbox", "ClashMeta/1.19", "singbox"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodGet, "/sub/token?format="+tc.format, nil)
		if tc.ua != "" {
			r.Header.Set("User-Agent", tc.ua)
		}
		if got := subFormat(r); got != tc.want {
			t.Errorf("format=%q ua=%q: got %q want %q", tc.format, tc.ua, got, tc.want)
		}
	}
}

// TestSubLink6SkipsMultiline：链接列表的 v6 行不能是多行文本。
// ShadowTLS/WireGuard 的 v6 内容是多行 JSON/配置（弹窗 textarea 用），
// 进了按行解析的链接列表就是一堆碎行（2026-11-12 复查，RN 没 IPv6
// 所以一直没暴露，双栈机器上必现）。
func TestSubLink6SkipsMultiline(t *testing.T) {
	s := &Server{}
	for _, proto := range []string{"shadowtls", "wireguard"} {
		if got := s.subLink6(&store.Inbound{Protocol: proto}); got != "" {
			t.Fatalf("%s 的 v6 行必须为空，实际 %q", proto, got)
		}
	}
}
