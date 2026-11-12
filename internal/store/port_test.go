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
