package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestClientOutboundsAllProtocols(t *testing.T) {
	uuid := "11111111-2222-3333-4444-555555555555"
	priv := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	pub := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	addr := "203.0.113.10"
	sni := "www.example.com"

	cases := []struct {
		proto string
		cfg   string
		port  int
		check func(t *testing.T, obs, eps []map[string]interface{})
	}{
		{"vless", mustJSON(t, VLESSConfig{UUID: uuid, Flow: "xtls-rprx-vision", ShortID: "abcd1234", PrivateKey: priv, PublicKey: pub}), 443, func(t *testing.T, obs, eps []map[string]interface{}) {
			tls := obs[0]["tls"].(map[string]interface{})
			if tls["reality"] == nil || tls["utls"] == nil {
				t.Fatal("VLESS Reality 出站缺 reality/utls")
			}
			if obs[0]["flow"] != "xtls-rprx-vision" {
				t.Fatal("VLESS flow 丢了")
			}
		}},
		{"vless", mustJSON(t, VLESSConfig{UUID: uuid, Mode: "ws", Domain: "test.example.com", Path: "/ws"}), 8443, func(t *testing.T, obs, eps []map[string]interface{}) {
			if obs[0]["server"] != "test.example.com" || obs[0]["transport"] == nil {
				t.Fatal("VLESS WS 出站 server/transport 不对")
			}
		}},
		{"vmess", mustJSON(t, VMessConfig{UUID: uuid, Mode: "tcp"}), 10001, func(t *testing.T, obs, eps []map[string]interface{}) {
			if obs[0]["security"] != "auto" || obs[0]["tls"] != nil {
				t.Fatal("VMess TCP 出站不该有 tls")
			}
		}},
		{"vmess", mustJSON(t, VMessConfig{UUID: uuid, Mode: "cf", Domain: "test.example.com", Path: "/vmess"}), 10002, func(t *testing.T, obs, eps []map[string]interface{}) {
			if obs[0]["server"] != "test.example.com" || obs[0]["transport"] == nil {
				t.Fatal("VMess CF 出站 server/transport 不对")
			}
		}},
		{"trojan", mustJSON(t, TrojanConfig{Password: "trojanpass", Mode: "reality", ShortID: "ef123456", PrivateKey: priv, PublicKey: pub}), 443, func(t *testing.T, obs, eps []map[string]interface{}) {
			tls := obs[0]["tls"].(map[string]interface{})
			if tls["reality"] == nil || tls["utls"] == nil {
				t.Fatal("Trojan Reality 出站缺 reality/utls")
			}
		}},
		{"ss", mustJSON(t, SSConfig{Method: "2022-blake3-aes-128-gcm", Password: "AAAAAAAAAAAAAAAAAAAAAA=="}), 8388, nil},
		{"socks", mustJSON(t, SocksConfig{User: "socksuser", Pass: "sockspass"}), 1080, nil},
		{"http", mustJSON(t, HTTPConfig{User: "httpuser", Pass: "httppass"}), 8080, nil},
		{"hy2", mustJSON(t, Hy2Config{Password: "hy2pass", ObfsType: "salamander", ObfsPassword: "obfspass"}), 8443, func(t *testing.T, obs, eps []map[string]interface{}) {
			if obs[0]["obfs"] == nil {
				t.Fatal("HY2 salamander 混淆丢了")
			}
		}},
		{"tuic", mustJSON(t, TUICConfig{UUID: uuid, Password: "tuicpass"}), 8443, nil},
		{"anytls", mustJSON(t, AnyTLSConfig{Name: "anyuser", Password: "anypass"}), 443, nil},
		{"naive", mustJSON(t, NaiveConfig{Username: "naiveuser", Password: "naivepass", Domain: "test.example.com"}), 443, func(t *testing.T, obs, eps []map[string]interface{}) {
			if obs[0]["server"] != "test.example.com" {
				t.Fatal("Naive 出站 server 必须是域名")
			}
			tls := obs[0]["tls"].(map[string]interface{})
			if tls["insecure"] != nil {
				t.Fatal("Naive 是 CA 证书，出站不该 insecure")
			}
		}},
		{"snell", mustJSON(t, SnellConfig{Version: 5, PSK: "snelltestpsk1234567890abcdef", ObfsMode: "http", ObfsHost: "bing.com"}), 10019, func(t *testing.T, obs, eps []map[string]interface{}) {
			// 服务端 v5 → 出站 version=4（没有 v5 客户端）。
			if obs[0]["version"] != 4 || obs[0]["obfs_mode"] != "http" || obs[0]["obfs_host"] != "bing.com" {
				t.Fatalf("Snell v5 出站映射不对：%v", obs[0])
			}
		}},
		{"snell", mustJSON(t, SnellConfig{Version: 6, PSK: "snelltestpsk1234567890abcdef", Mode: "default"}), 10020, func(t *testing.T, obs, eps []map[string]interface{}) {
			if obs[0]["version"] != 6 || obs[0]["mode"] != "default" {
				t.Fatalf("Snell v6 出站不对：%v", obs[0])
			}
		}},
		{"shadowtls", mustJSON(t, ShadowTLSConfig{Password: "stpass1234567890", Handshake: "gateway.icloud.com", StrictMode: true, SSMethod: "2022-blake3-aes-128-gcm", SSPassword: "AAAAAAAAAAAAAAAAAAAAAA==", InnerPort: 20001}), 10021, func(t *testing.T, obs, eps []map[string]interface{}) {
			if len(obs) != 2 || obs[0]["type"] != "shadowsocks" || obs[1]["type"] != "shadowtls" {
				t.Fatalf("ShadowTLS 必须是 SS + shadowtls 两个出站：%v", obs)
			}
			if obs[0]["detour"] != obs[1]["tag"] {
				t.Fatal("ShadowTLS SS 出站 detour 没指到 shadowtls 出站")
			}
		}},
		{"wireguard", mustJSON(t, WGConfig{ServerPriv: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ServerPub: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ClientPriv: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ClientPub: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ClientIP: "10.0.0.2/32"}), 10018, func(t *testing.T, obs, eps []map[string]interface{}) {
			// 1.13 起无 WG 出站：只有端点，tag 即节点名，进选单。
			if len(obs) != 0 {
				t.Fatal("WireGuard 不该产出站")
			}
			if len(eps) != 1 || eps[0]["type"] != "wireguard" || eps[0]["tag"] != "TEST-wireguard" {
				t.Fatalf("WireGuard 必须产一个 tag 为节点名的 endpoint：%v", eps)
			}
		}},
	}
	for _, tc := range cases {
		obs, eps, err := ClientOutbounds(tc.proto, tc.cfg, addr, tc.port, sni, "TEST-"+tc.proto)
		if err != nil {
			t.Fatalf("%s: %v", tc.proto, err)
		}
		if len(obs) == 0 && len(eps) == 0 {
			t.Fatalf("%s: 没有出站也没有端点", tc.proto)
		}
		if len(obs) > 0 && obs[0]["tag"] != "TEST-"+tc.proto {
			t.Fatalf("%s: tag 不对：%v", tc.proto, obs[0]["tag"])
		}
		if tc.check != nil {
			tc.check(t, obs, eps)
		}
	}
	// Snell 非法版本必须报错，不静默降级。
	if _, _, err := ClientOutbounds("snell", mustJSON(t, SnellConfig{Version: 4, PSK: "x"}), addr, 10019, sni, "X"); err == nil {
		t.Fatal("Snell version=4 入站不该存在，客户端生成必须报错")
	}
}

func TestShareLinksSingleLine(t *testing.T) {
	// Naive 单行链接。
	nl := NaiveShareLink(NaiveConfig{Username: "u", Password: "p@ss:word", Domain: "test.example.com"}, 443, "NAIVE-1")
	if !strings.HasPrefix(nl, "naive+https://") || strings.Contains(nl, "\n") {
		t.Fatalf("Naive 链接必须是单行 naive+https：%q", nl)
	}
	if !strings.Contains(nl, "test.example.com:443") || !strings.HasSuffix(nl, "#NAIVE-1") {
		t.Fatalf("Naive 链接缺域名/端口/名字：%q", nl)
	}
}

// TestClientConfigFull 生成一份覆盖 13 协议的订阅客户端 JSON，
// 供 sing-box check 做结构校验（见 /tmp/sssingbox-client-check/ 输出）。
func TestClientConfigFull(t *testing.T) {
	uuid := "11111111-2222-3333-4444-555555555555"
	priv := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	pub := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	addr := "203.0.113.10"
	sni := "www.example.com"
	var outs []interface{}
	var eps []interface{}
	add := func(proto, cfg string, port int, name string) {
		t.Helper()
		obs, endpoints, err := ClientOutbounds(proto, cfg, addr, port, sni, name)
		if err != nil {
			t.Fatalf("%s: %v", proto, err)
		}
		for _, ob := range obs {
			outs = append(outs, ob)
		}
		for _, ep := range endpoints {
			eps = append(eps, ep)
		}
	}
	add("vless", mustJSON(t, VLESSConfig{UUID: uuid, Flow: "xtls-rprx-vision", ShortID: "abcd1234", PrivateKey: priv, PublicKey: pub}), 443, "VLESS-443")
	add("vless", mustJSON(t, VLESSConfig{UUID: uuid, Mode: "ws", Domain: "test.example.com", Path: "/ws"}), 8443, "VLESS-WS")
	add("vmess", mustJSON(t, VMessConfig{UUID: uuid, Mode: "tcp"}), 10001, "VMESS-TCP")
	add("vmess", mustJSON(t, VMessConfig{UUID: uuid, Mode: "cf", Domain: "test.example.com", Path: "/vmess"}), 10002, "VMESS-CF")
	add("trojan", mustJSON(t, TrojanConfig{Password: "trojanpass", Mode: "reality", ShortID: "ef123456", PrivateKey: priv, PublicKey: pub}), 443, "TROJAN-443")
	add("ss", mustJSON(t, SSConfig{Method: "2022-blake3-aes-128-gcm", Password: "AAAAAAAAAAAAAAAAAAAAAA=="}), 8388, "SS-8388")
	add("socks", mustJSON(t, SocksConfig{User: "socksuser", Pass: "sockspass"}), 1080, "SOCKS-1080")
	add("http", mustJSON(t, HTTPConfig{User: "httpuser", Pass: "httppass"}), 8080, "HTTP-8080")
	add("hy2", mustJSON(t, Hy2Config{Password: "hy2pass", ObfsType: "salamander", ObfsPassword: "obfspass"}), 8443, "HY2-8443")
	add("tuic", mustJSON(t, TUICConfig{UUID: uuid, Password: "tuicpass"}), 8443, "TUIC-8443")
	add("anytls", mustJSON(t, AnyTLSConfig{Name: "anyuser", Password: "anypass"}), 443, "ANYTLS-443")
	add("naive", mustJSON(t, NaiveConfig{Username: "naiveuser", Password: "naivepass", Domain: "test.example.com"}), 443, "NAIVE-443")
	add("snell", mustJSON(t, SnellConfig{Version: 5, PSK: "snelltestpsk1234567890abcdef", ObfsMode: "http", ObfsHost: "bing.com"}), 10019, "SNELL-V5")
	add("snell", mustJSON(t, SnellConfig{Version: 6, PSK: "snelltestpsk1234567890abcdef", Mode: "default"}), 10020, "SNELL-V6")
	add("shadowtls", mustJSON(t, ShadowTLSConfig{Password: "stpass1234567890", Handshake: "gateway.icloud.com", StrictMode: true, SSMethod: "2022-blake3-aes-128-gcm", SSPassword: "AAAAAAAAAAAAAAAAAAAAAA==", InnerPort: 20001}), 10021, "SHADOWTLS-10021")
	add("wireguard", mustJSON(t, WGConfig{ServerPriv: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ServerPub: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ClientPriv: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ClientPub: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ClientIP: "10.0.0.2/32"}), 10018, "WG-10018")

	cfg := SingBoxClientConfig(outs, eps)
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	dir := "/tmp/sssingbox-client-check"
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client.json"), b, 0644); err != nil {
		t.Fatal(err)
	}
	// 链接形态回归（2026-11-12 客户端匹配审计）：
	// HY2/TUIC/AnyTLS 必须带 security=tls；HY2 不得有非标准 /?。
	hy2 := Hy2Link("1.2.3.4", 8443, "www.example.com", Hy2Config{Password: "pw", ObfsType: "salamander", ObfsPassword: "ob"}, "H")
	if !strings.Contains(hy2, "security=tls") || strings.Contains(hy2, "/?") || !strings.HasPrefix(hy2, "hysteria2://pw@1.2.3.4:8443?") {
		t.Fatalf("Hy2Link 形态不对：%s", hy2)
	}
	tuic := TUICLink("1.2.3.4", 443, "www.example.com", TUICConfig{UUID: "u", Password: "p"}, "T")
	if !strings.Contains(tuic, "security=tls") {
		t.Fatalf("TUICLink 缺 security=tls：%s", tuic)
	}
	anytls := AnyTLSLink("1.2.3.4", 443, "www.example.com", AnyTLSConfig{Password: "p"}, "A")
	if !strings.Contains(anytls, "security=tls") {
		t.Fatalf("AnyTLSLink 缺 security=tls：%s", anytls)
	}
	// ShadowTLS 载体 tag 必须带 §hide§（Hiddify 隐藏约定），且 SS 的
	// detour 必须指到它；选单里不得出现任何含 §hide§ 的 tag。
	stJSON := ShadowTLSClientJSON("1.2.3.4", 53545, ShadowTLSConfig{SSMethod: "2022-blake3-aes-128-gcm", SSPassword: "ssp", Password: "stp", Handshake: "gateway.icloud.com"}, "S")
	var stDoc map[string]interface{}
	if err := json.Unmarshal([]byte(stJSON), &stDoc); err != nil {
		t.Fatal(err)
	}
	stObs := stDoc["outbounds"].([]interface{})
	if len(stObs) != 2 || stObs[1].(map[string]interface{})["tag"] != "S-shadowtls §hide§" || stObs[0].(map[string]interface{})["detour"] != "S-shadowtls §hide§" {
		t.Fatalf("ShadowTLS 载体 tag/detour 不对：%s", stJSON)
	}
	// 选单里必须有全部节点出站 tag + direct，但不能含 ShadowTLS 载体出站。
	var cfgDoc map[string]interface{}
	if err := json.Unmarshal(b, &cfgDoc); err != nil {
		t.Fatal(err)
	}
	cfgOuts := cfgDoc["outbounds"].([]interface{})
	var sel map[string]interface{}
	for _, o := range cfgOuts {
		if m, ok := o.(map[string]interface{}); ok && m["type"] == "selector" {
			sel = m
		}
	}
	if sel == nil {
		t.Fatal("客户端 JSON 里缺选单")
	}
	for _, tag := range sel["outbounds"].([]interface{}) {
		if s, _ := tag.(string); strings.Contains(s, "§hide§") {
			t.Fatal("选单里不能出现 ShadowTLS 载体出站")
		}
	}
	raw := string(b)
	for _, name := range []string{"VLESS-443", "VLESS-WS", "VMESS-TCP", "VMESS-CF", "TROJAN-443", "SS-8388", "SOCKS-1080", "HTTP-8080", "HY2-8443", "TUIC-8443", "ANYTLS-443", "NAIVE-443", "SNELL-V5", "SNELL-V6", "SHADOWTLS-10021", "WG-10018"} {
		if !strings.Contains(raw, `"tag": "`+name+`"`) {
			t.Fatalf("客户端 JSON 里缺节点 %s", name)
		}
	}
}

// TestHy2BandwidthInts：HY2 限速进订阅 JSON 必须是数字。
// Hy2Config 里限速是字符串；直接原样写进出站会是 "up_mbps": "100"，
// / sing-box 不认字符串限速，整份订阅在客户端加载失败（2026-11-12 复查）。
func TestHy2BandwidthInts(t *testing.T) {
	obs, _, err := ClientOutbounds("hy2", mustJSON(t, Hy2Config{Password: "pw", UpMbps: "100", DownMbps: "50"}), "1.2.3.4", 8443, "www.example.com", "HY2-BW")
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 {
		t.Fatalf("HY2 应产一个出站，实际 %d", len(obs))
	}
	if v, ok := obs[0]["up_mbps"].(int); !ok || v != 100 {
		t.Fatalf("up_mbps 必须是数字 100，实际 %#v", obs[0]["up_mbps"])
	}
	if v, ok := obs[0]["down_mbps"].(int); !ok || v != 50 {
		t.Fatalf("down_mbps 必须是数字 50，实际 %#v", obs[0]["down_mbps"])
	}
	// 不填限速时不写字段；非法值也不写，不拖垮订阅。
	obs, _, err = ClientOutbounds("hy2", mustJSON(t, Hy2Config{Password: "pw", UpMbps: "abc", DownMbps: "0"}), "1.2.3.4", 8443, "www.example.com", "HY2-BW2")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := obs[0]["up_mbps"]; ok {
		t.Fatal("非法 up_mbps 不该进订阅")
	}
	if _, ok := obs[0]["down_mbps"]; ok {
		t.Fatal("0 down_mbps 不该进订阅")
	}
}
