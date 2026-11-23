package server

import (
	"testing"

	"sssingbox/internal/proxy"
)

// normalizeSnell：v5 + http + 空 Host 时填 SNI 池随机 Host，永不为 bing.com。
func TestNormalizeSnellFillsRandomHost(t *testing.T) {
	s := &Server{}
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		cfg := proxy.SnellConfig{Version: 5, PSK: "0123456789abcdef0123456789abcdef", ObfsMode: "http"}
		if err := s.normalizeSnell(&cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.ObfsHost == "" || cfg.ObfsHost == "bing.com" || cfg.ObfsHost == "www.bing.com" {
			t.Fatalf("bad normalized obfs host: %q", cfg.ObfsHost)
		}
		seen[cfg.ObfsHost] = true
	}
	if len(seen) < 2 {
		t.Fatal("normalized obfs host never varies")
	}
	// 显式指定的 Host 原样保留。
	cfg := proxy.SnellConfig{Version: 5, PSK: "0123456789abcdef0123456789abcdef", ObfsMode: "http", ObfsHost: "www.example.com"}
	if err := s.normalizeSnell(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ObfsHost != "www.example.com" {
		t.Fatalf("explicit host overwritten: %q", cfg.ObfsHost)
	}
}

// normalizeShadowTLS：默认握手站仍是 gateway.icloud.com。
func TestNormalizeShadowTLSKeepsDefaultHandshake(t *testing.T) {
	s := &Server{}
	cfg := proxy.ShadowTLSConfig{Password: "pw123456", SSPassword: "AAAAAAAAAAAAAAAAAAAAAA=="}
	if err := s.normalizeShadowTLS(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Handshake != "gateway.icloud.com" {
		t.Fatalf("default handshake = %q, want gateway.icloud.com", cfg.Handshake)
	}
	cfg2 := proxy.ShadowTLSConfig{Password: "pw123456", SSPassword: "AAAAAAAAAAAAAAAAAAAAAA==", Handshake: "www.example.com"}
	if err := s.normalizeShadowTLS(&cfg2); err != nil {
		t.Fatal(err)
	}
	if cfg2.Handshake != "www.example.com" {
		t.Fatalf("explicit handshake overwritten: %q", cfg2.Handshake)
	}
}
