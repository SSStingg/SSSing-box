package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseShadowTLSLink(t *testing.T) {
	p, err := ParseBLink("shadowtls://stpass123@1.2.3.4:53545?version=3&handshake=gateway.icloud.com&ss-method=2022-blake3-aes-128-gcm&ss-password=AAAAAAAAAAAAAAAAAAAAAA%3D%3D#TestSTLS")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Protocol != "shadowtls" || p.Name != "TestSTLS" {
		t.Fatalf("protocol/name = %q/%q", p.Protocol, p.Name)
	}
	want := map[string]interface{}{
		"type": "shadowtls", "server": "1.2.3.4", "server_port": 53545,
		"version": 3, "password": "stpass123", "handshake": "gateway.icloud.com",
		"ss_method": "2022-blake3-aes-128-gcm", "ss_password": "AAAAAAAAAAAAAAAAAAAAAA==",
	}
	for k, v := range want {
		if p.Outbound[k] != v {
			t.Fatalf("outbound[%q] = %#v, want %#v", k, p.Outbound[k], v)
		}
	}
}

// 省略 version/handshake/ss-method 时按默认值补齐。
func TestParseShadowTLSDefaults(t *testing.T) {
	p, err := ParseBLink("shadowtls://pw@203.0.113.9:443?ss-password=AAAAAAAAAAAAAAAAAAAAAA%3D%3D")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Outbound["version"] != 3 {
		t.Fatalf("version = %#v, want 3", p.Outbound["version"])
	}
	if p.Outbound["handshake"] != "gateway.icloud.com" {
		t.Fatalf("handshake = %#v", p.Outbound["handshake"])
	}
	if p.Outbound["ss_method"] != "2022-blake3-aes-128-gcm" {
		t.Fatalf("ss_method = %#v", p.Outbound["ss_method"])
	}
	if p.Name != "shadowtls-203.0.113.9" {
		t.Fatalf("name fallback = %q", p.Name)
	}
}

func TestParseShadowTLSBad(t *testing.T) {
	for _, link := range []string{
		"shadowtls://@1.2.3.4:53545?ss-password=AAAAAAAAAAAAAAAAAAAAAA%3D%3D",             // 无密码
		"shadowtls://pw@:53545?ss-password=AAAAAAAAAAAAAAAAAAAAAA%3D%3D",                  // 无地址
		"shadowtls://pw@1.2.3.4?ss-password=AAAAAAAAAAAAAAAAAAAAAA%3D%3D",                 // 无端口
		"shadowtls://pw@1.2.3.4:53545",                                                    // 无内层 SS 密码
		"shadowtls://pw@1.2.3.4:53545?version=2&ss-password=AAAAAAAAAAAAAAAAAAAAAA%3D%3D", // 只支持 v3
	} {
		if _, err := ParseBLink(link); err == nil {
			t.Errorf("link %q should fail", link)
		}
	}
}

func TestSingBoxBOutboundShadowTLS(t *testing.T) {
	// B 节点存储配置必须走 ParseBLink + Marshal（与面板入库同路），不用面板结构体手拼。
	p, err := ParseBLink("shadowtls://stpass123@1.2.3.4:53545?version=3&handshake=gateway.icloud.com&ss-method=2022-blake3-aes-128-gcm&ss-password=AAAAAAAAAAAAAAAAAAAAAA%3D%3D#STLS-B")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg, _ := json.Marshal(p.Outbound)
	obs, err := SingBoxBOutbound("shadowtls", string(cfg), "chain-b-x")
	if err != nil {
		t.Fatalf("outbound: %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("shadowtls should emit exactly 2 outbounds, got %d", len(obs))
	}
	ss, st := obs[0], obs[1]
	// 第一个是 SS 出站，detour 指向第二个。
	if ss["type"] != "shadowsocks" || ss["tag"] != "chain-b-x" || ss["server"] != "1.2.3.4" || ss["server_port"] != 53545 {
		t.Fatalf("ss outbound = %#v", ss)
	}
	if ss["method"] != "2022-blake3-aes-128-gcm" || ss["password"] != "AAAAAAAAAAAAAAAAAAAAAA==" {
		t.Fatalf("ss method/password = %#v/%#v", ss["method"], ss["password"])
	}
	if ss["detour"] != "chain-b-x-shadowtls" {
		t.Fatalf("ss detour = %#v, want chain-b-x-shadowtls", ss["detour"])
	}
	// 第二个是 shadowtls 出站，tag 与 detour 对得上。
	if st["type"] != "shadowtls" || st["tag"] != "chain-b-x-shadowtls" || st["server"] != "1.2.3.4" || st["server_port"] != 53545 {
		t.Fatalf("shadowtls outbound = %#v", st)
	}
	if st["version"] != 3 || st["password"] != "stpass123" {
		t.Fatalf("shadowtls version/password = %#v/%#v", st["version"], st["password"])
	}
	tlsMap, ok := st["tls"].(map[string]interface{})
	if !ok || tlsMap["server_name"] != "gateway.icloud.com" {
		t.Fatalf("shadowtls tls = %#v", st["tls"])
	}
}

func TestSingBoxBOutboundShadowTLSBad(t *testing.T) {
	for _, cfg := range []string{
		`{"type":"shadowtls","server":"1.2.3.4","server_port":53545,"version":3,"handshake":"gateway.icloud.com","ss_method":"2022-blake3-aes-128-gcm","ss_password":"AAAAAAAAAAAAAAAAAAAAAA=="}`,                 // 缺密码
		`{"type":"shadowtls","server":"1.2.3.4","server_port":53545,"version":3,"password":"pw","handshake":"gateway.icloud.com","ss_method":"2022-blake3-aes-128-gcm"}`,                                          // 缺内层 SS 密码
		`{"type":"shadowtls","server":"1.2.3.4","server_port":53545,"version":2,"password":"pw","handshake":"gateway.icloud.com","ss_method":"2022-blake3-aes-128-gcm","ss_password":"AAAAAAAAAAAAAAAAAAAAAA=="}`, // v2
		`{"type":"shadowtls","server":"1.2.3.4","server_port":0,"version":3,"password":"pw","handshake":"gateway.icloud.com","ss_method":"2022-blake3-aes-128-gcm","ss_password":"AAAAAAAAAAAAAAAAAAAAAA=="}`,     // 端口 0
	} {
		if _, err := SingBoxBOutbound("shadowtls", cfg, "chain-b-x"); err == nil {
			t.Errorf("config %q should fail", cfg)
		}
	}
}

func TestShadowTLSLinkRoundTrip(t *testing.T) {
	// 面板自产链接必须能粘贴回来（面板间互拷就靠它）。
	link := ShadowTLSLink("203.0.113.20", 53545, ShadowTLSConfig{
		Password: "st-pass_123", Handshake: "gateway.icloud.com",
		SSMethod: "2022-blake3-aes-128-gcm", SSPassword: "AAAAAAAAAAAAAAAAAAAAAA==",
	}, "RN-ShadowTLS")
	if !strings.HasPrefix(link, "shadowtls://") || !strings.Contains(link, "ss-password=") || !strings.Contains(link, "handshake=gateway.icloud.com") {
		t.Fatalf("link = %s", link)
	}
	p, err := ParseBLink(link)
	if err != nil {
		t.Fatalf("own link should re-parse: %v (link=%s)", err, link)
	}
	if p.Protocol != "shadowtls" || p.Name != "RN-ShadowTLS" {
		t.Fatalf("protocol/name = %q/%q", p.Protocol, p.Name)
	}
	if p.Outbound["password"] != "st-pass_123" || p.Outbound["ss_password"] != "AAAAAAAAAAAAAAAAAAAAAA==" {
		t.Fatalf("passwords = %#v/%#v", p.Outbound["password"], p.Outbound["ss_password"])
	}
	// 含 base64 特殊字符的密码也要能原样回来。
	link2 := ShadowTLSLink("203.0.113.20", 53545, ShadowTLSConfig{
		Password: "a+b/c=", Handshake: "", SSMethod: "", SSPassword: "x+y/z==",
	}, "esc")
	p2, err := ParseBLink(link2)
	if err != nil {
		t.Fatalf("escaped link should re-parse: %v (link=%s)", err, link2)
	}
	if p2.Outbound["password"] != "a+b/c=" || p2.Outbound["ss_password"] != "x+y/z==" {
		t.Fatalf("escaped passwords = %#v/%#v", p2.Outbound["password"], p2.Outbound["ss_password"])
	}
	if p2.Outbound["handshake"] != "gateway.icloud.com" || p2.Outbound["ss_method"] != "2022-blake3-aes-128-gcm" {
		t.Fatalf("defaults = %#v/%#v", p2.Outbound["handshake"], p2.Outbound["ss_method"])
	}
}

func TestClashBProxyShadowTLS(t *testing.T) {
	p, err := ParseBLink("shadowtls://stpass123@1.2.3.4:53545?version=3&handshake=gateway.icloud.com&ss-method=2022-blake3-aes-128-gcm&ss-password=AAAAAAAAAAAAAAAAAAAAAA%3D%3D#STLS-B")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg, _ := json.Marshal(p.Outbound)
	proxy, err := ClashBProxy("shadowtls", string(cfg), "STLS-B")
	if err != nil {
		t.Fatalf("clash: %v", err)
	}
	if proxy["type"] != "ss" || proxy["cipher"] != "2022-blake3-aes-128-gcm" || proxy["password"] != "AAAAAAAAAAAAAAAAAAAAAA==" {
		t.Fatalf("clash proxy = %#v", proxy)
	}
	if proxy["plugin"] != "shadow-tls" {
		t.Fatalf("plugin = %#v", proxy["plugin"])
	}
	opts, ok := proxy["plugin-opts"].(map[string]interface{})
	if !ok || opts["host"] != "gateway.icloud.com" || opts["password"] != "stpass123" || opts["version"] != 3 {
		t.Fatalf("plugin-opts = %#v", proxy["plugin-opts"])
	}
}
