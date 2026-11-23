package store

import "testing"

// PortInUse 只拦同一种传输：TCP 节点占着 443，UDP 节点照样能建 443；
// 同传输的才算占用（2026-11-12 TCP/UDP 误拦的同类问题）。
func TestPortInUseTransportAware(t *testing.T) {
	s, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.UpsertInbound(&Inbound{ID: "v1", Name: "VLESS-443", Protocol: "vless", Port: 443, Enabled: true, Config: "{}"}); err != nil {
		t.Fatal(err)
	}
	if !s.PortInUse(443, "vless", "") {
		t.Fatal("vless on 443 should block another vless on 443")
	}
	if s.PortInUse(443, "hy2", "") {
		t.Fatal("vless (TCP) on 443 must not block hy2 (UDP) on 443")
	}
	if s.PortInUse(443, "hy2", "v1") {
		t.Fatal("excluded node must not count")
	}
	if s.PortInUse(8443, "hy2", "") {
		t.Fatal("nothing on 8443")
	}
	if err := s.UpsertInbound(&Inbound{ID: "h1", Name: "HY2-443", Protocol: "hy2", Port: 443, Enabled: true, Config: "{}"}); err != nil {
		t.Fatal(err)
	}
	if !s.PortInUse(443, "hy2", "") {
		t.Fatal("hy2 on 443 should block another hy2 on 443")
	}
	if !s.PortInUse(443, "tuic", "") {
		t.Fatal("hy2 (UDP) on 443 should block tuic (UDP) on 443")
	}
	if !s.PortInUse(443, "vless", "") {
		t.Fatal("vless on 443 should still block another vless on 443")
	}
	if s.PortInUse(443, "hy2", "h1") {
		t.Fatal("excluding the only hy2 node must free UDP 443")
	}
}

// Snell 监听与数据面都是 TCP（不是 UDP）：统计规则必须按 TCP 建，
// 否则 Snell 流量永远计为 0（2026-11-23 实测 3MB 下行 udp 计数不动）。
func TestProtocolTransports(t *testing.T) {
	cases := map[string][]string{
		"snell":     {"tcp"},
		"ss":        {"tcp", "udp"},
		"hy2":       {"udp"},
		"tuic":      {"udp"},
		"wireguard": {"udp"},
		"vless":     {"tcp"},
		"trojan":    {"tcp"},
		"shadowtls": {"tcp"},
	}
	for proto, want := range cases {
		got := ProtocolTransports(proto)
		if len(got) != len(want) {
			t.Fatalf("%s: got %v, want %v", proto, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: got %v, want %v", proto, got, want)
			}
		}
	}
}

// ProtocolsShareTransport：ss 双绑 TCP+UDP，所以跟纯 TCP 和纯 UDP 都冲突；
// snell 只走 TCP，跟 hy2（UDP）不冲突；同传输的互相冲突。
func TestProtocolsShareTransport(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"ss", "hy2", true},
		{"ss", "tuic", true},
		{"ss", "wireguard", true},
		{"ss", "vless", true},
		{"ss", "ss", true},
		{"snell", "hy2", false},
		{"snell", "vless", true},
		{"snell", "ss", true},
		{"hy2", "tuic", true},
		{"vless", "vmess", true},
		{"vless", "hy2", false},
		{"shadowtls", "hy2", false},
		{"shadowtls", "vless", true},
	}
	for _, tc := range cases {
		if got := ProtocolsShareTransport(tc.a, tc.b); got != tc.want {
			t.Errorf("ProtocolsShareTransport(%q,%q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
		if got := ProtocolsShareTransport(tc.b, tc.a); got != tc.want {
			t.Errorf("ProtocolsShareTransport(%q,%q) = %v, want %v (symmetry)", tc.b, tc.a, got, tc.want)
		}
	}
}

// PortInUse 按传输层交集判断：hy2 占着 UDP 18911，ss（TCP+UDP）就建不上去了；
// 反过来 ss 占着，hy2 和 vless 也都建不上；snell（TCP）拦不住 hy2。
func TestPortInUseSSSharesUDP(t *testing.T) {
	s, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.UpsertInbound(&Inbound{ID: "h1", Name: "HY2-18911", Protocol: "hy2", Port: 18911, Enabled: true, Config: "{}"}); err != nil {
		t.Fatal(err)
	}
	if !s.PortInUse(18911, "ss", "") {
		t.Fatal("hy2 (UDP) on 18911 should block ss (TCP+UDP) on 18911")
	}
	if s.PortInUse(18911, "snell", "") {
		t.Fatal("hy2 (UDP) on 18911 must not block snell (TCP) on 18911")
	}
	if err := s.UpsertInbound(&Inbound{ID: "s1", Name: "SS-18912", Protocol: "ss", Port: 18912, Enabled: true, Config: "{}"}); err != nil {
		t.Fatal(err)
	}
	if !s.PortInUse(18912, "hy2", "") {
		t.Fatal("ss (TCP+UDP) on 18912 should block hy2 (UDP) on 18912")
	}
	if !s.PortInUse(18912, "vless", "") {
		t.Fatal("ss (TCP+UDP) on 18912 should block vless (TCP) on 18912")
	}
	if !s.PortInUse(18912, "ss", "") {
		t.Fatal("ss on 18912 should block another ss on 18912")
	}
}
