package proxy

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestClashProxy(t *testing.T) {
	uuid := "11111111-2222-3333-4444-555555555555"
	pub := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	addr := "203.0.113.10"
	sni := "www.example.com"

	// ShadowTLS → ss + plugin shadow-tls，版本必须写 3。
	p, err := ClashProxy("shadowtls", mustJSON(t, ShadowTLSConfig{Password: "stpass", Handshake: "gateway.icloud.com", SSMethod: "2022-blake3-aes-128-gcm", SSPassword: "AAAAAAAAAAAAAAAAAAAAAA=="}), addr, 53545, sni, "SHADOWTLS-1")
	if err != nil {
		t.Fatal(err)
	}
	if p["type"] != "ss" || p["plugin"] != "shadow-tls" {
		t.Fatalf("ShadowTLS Clash 条目不对：%v", p)
	}
	po := p["plugin-opts"].(map[string]interface{})
	if po["host"] != "gateway.icloud.com" || po["version"] != 3 || po["password"] != "stpass" {
		t.Fatalf("ShadowTLS plugin-opts 不对：%v", po)
	}
	// Snell v5 → version=4；v6 必须报错跳过。
	p, err = ClashProxy("snell", mustJSON(t, SnellConfig{Version: 5, PSK: "snelltestpsk1234567890abcdef", ObfsMode: "http", ObfsHost: "bing.com"}), addr, 10019, sni, "SNELL-V5")
	if err != nil {
		t.Fatal(err)
	}
	if p["version"] != 4 {
		t.Fatalf("Snell v5 在 Clash 里必须写 version=4：%v", p)
	}
	if _, err := ClashProxy("snell", mustJSON(t, SnellConfig{Version: 6, PSK: "snelltestpsk1234567890abcdef", Mode: "default"}), addr, 10020, sni, "SNELL-V6"); err == nil {
		t.Fatal("Snell v6 在 Clash 里必须跳过（mihomo 无 v6）")
	}
	// Naive → http + tls。
	p, err = ClashProxy("naive", mustJSON(t, NaiveConfig{Username: "nu", Password: "np", Domain: "test.example.com"}), addr, 443, sni, "NAIVE-1")
	if err != nil {
		t.Fatal(err)
	}
	if p["type"] != "http" || p["tls"] != true || p["server"] != "test.example.com" {
		t.Fatalf("Naive Clash 条目不对：%v", p)
	}
	// VLESS Reality → reality-opts。
	p, err = ClashProxy("vless", mustJSON(t, VLESSConfig{UUID: uuid, Flow: "xtls-rprx-vision", ShortID: "abcd1234", PublicKey: pub}), addr, 443, sni, "VLESS-1")
	if err != nil {
		t.Fatal(err)
	}
	if p["reality-opts"] == nil || p["tls"] != true {
		t.Fatalf("VLESS Reality Clash 条目不对：%v", p)
	}
	// AnyTLS。
	p, err = ClashProxy("anytls", mustJSON(t, AnyTLSConfig{Name: "au", Password: "ap"}), addr, 443, sni, "ANYTLS-1")
	if err != nil {
		t.Fatal(err)
	}
	if p["type"] != "anytls" || p["skip-cert-verify"] != true {
		t.Fatalf("AnyTLS Clash 条目不对：%v", p)
	}
}

func TestClashConfigYAML(t *testing.T) {
	addr := "203.0.113.10"
	var proxies []map[string]interface{}
	for _, tc := range []struct {
		proto, cfg string
		port       int
		name       string
	}{
		{"vless", mustJSON(t, VLESSConfig{UUID: "11111111-2222-3333-4444-555555555555", Flow: "xtls-rprx-vision", ShortID: "abcd1234", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}), 443, "VLESS-443"},
		{"ss", mustJSON(t, SSConfig{Method: "2022-blake3-aes-128-gcm", Password: "AAAAAAAAAAAAAAAAAAAAAA=="}), 8388, "SS-8388"},
		{"shadowtls", mustJSON(t, ShadowTLSConfig{Password: "stpass", Handshake: "gateway.icloud.com", SSMethod: "2022-blake3-aes-128-gcm", SSPassword: "AAAAAAAAAAAAAAAAAAAAAA=="}), 53545, "SHADOWTLS-1"},
		{"wireguard", mustJSON(t, WGConfig{ServerPriv: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ServerPub: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ClientPriv: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ClientPub: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ClientIP: "10.0.0.2/32"}), 10018, "WG-1"},
	} {
		p, err := ClashProxy(tc.proto, tc.cfg, addr, tc.port, "www.example.com", tc.name)
		if err != nil {
			t.Fatalf("%s: %v", tc.proto, err)
		}
		proxies = append(proxies, p)
	}
	out, err := yaml.Marshal(ClashConfig(proxies))
	if err != nil {
		t.Fatal(err)
	}
	// YAML 必须能解析回结构，且节点全在。
	var doc map[string]interface{}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("YAML 解析失败：%v\n%s", err, out)
	}
	pl, ok := doc["proxies"].([]interface{})
	if !ok || len(pl) != 4 {
		t.Fatalf("YAML 里 proxies 不是 4 条：%v", doc["proxies"])
	}
	raw := string(out)
	for _, n := range []string{"VLESS-443", "SS-8388", "SHADOWTLS-1", "WG-1"} {
		if !strings.Contains(raw, n) {
			t.Fatalf("YAML 里缺节点 %s", n)
		}
	}
	if !strings.Contains(raw, "shadow-tls") || !strings.Contains(raw, "version: 3") {
		t.Fatal("YAML 里 ShadowTLS 插件信息丢了")
	}
}
