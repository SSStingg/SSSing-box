package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sssingbox/internal/store"
	"strings"
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
// WireGuard 的 v6 内容是多行配置（弹窗 textarea 用），进了按行解析的
// 链接列表就是一堆碎行（2026-11-12 复查，RN 没 IPv6 所以一直没暴露，
// 双栈机器上必现）。ShadowTLS 的 v6 行是单行 shadowtls://
// 链接（原多行 JSON 已改走链接），同样不能含换行。
func TestSubLink6SkipsMultiline(t *testing.T) {
	s, _ := setupChainTestServer(t)
	if got := s.subLink6(&store.Inbound{Protocol: "wireguard"}); got != "" {
		t.Fatalf("wireguard 的 v6 行必须为空，实际 %q", got)
	}
	st := &store.Inbound{Protocol: "shadowtls", Port: 443, Name: "ST-443", Config: `{"version":3,"password":"pw","handshake":"gateway.icloud.com","ss_method":"2022-blake3-aes-128-gcm","ss_password":"AAAAAAAAAAAAAAAAAAAAAA==","inner_port":20001}`}
	got := s.subLink6(st)
	if strings.Contains(got, "\n") {
		t.Fatalf("shadowtls 的 v6 行不能含换行，实际 %q", got)
	}
	if got != "" && !strings.HasPrefix(got, "shadowtls://") {
		t.Fatalf("shadowtls 的 v6 行应为 shadowtls:// 链接，实际 %q", got)
	}
}

// TestSubChainNameInAllFormats：链名要进全部三种订阅格式（与 base64 一致）。
// 2026-11-18：base64 早有链名副本，sing-box/Clash 漏了，补上。
func TestSubChainNameInAllFormats(t *testing.T) {
	s, st := setupChainTestServer(t)
	_ = st.UpsertInbound(&store.Inbound{ID: "in-vless", Name: "VLESS-443", Protocol: "vless", Port: 443, Address: "1.2.3.4", Config: `{"uuid":"11111111-2222-3333-4444-555555555555"}`, Enabled: true})
	_ = st.UpsertChain(&store.Chain{ID: "ch-1", Name: "VLESS-VLESS", InboundID: "in-vless", Mode: "split", Routes: []store.ChainRoute{{BNodeID: "b1", List: "example.com"}}, Enabled: true})
	locals, bnodes := s.collectSubNodes(nil)

	links, err := base64.StdEncoding.DecodeString(s.renderSubLinks(locals, bnodes, nil))
	if err != nil {
		t.Fatalf("base64 订阅解码失败：%v", err)
	}
	if !strings.Contains(string(links), "VLESS-VLESS") {
		t.Fatalf("base64 订阅缺链名：\n%s", links)
	}
	sb, err := s.renderSubSingBox(locals, bnodes)
	if err != nil {
		t.Fatalf("sing-box 订阅生成失败：%v", err)
	}
	if !strings.Contains(string(sb), `"tag": "VLESS-VLESS"`) {
		t.Fatalf("sing-box 订阅缺链名：\n%s", sb)
	}
	cl, err := s.renderSubClash(locals, bnodes)
	if err != nil {
		t.Fatalf("Clash 订阅生成失败：%v", err)
	}
	if !strings.Contains(string(cl), "name: VLESS-VLESS") {
		t.Fatalf("Clash 订阅缺链名：\n%s", cl)
	}
}
