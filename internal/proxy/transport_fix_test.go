package proxy

import (
	"testing"
)

// H2 与 HTTPUpgrade 订阅输出回归测试（2026-11-18 修的两个真 bug）：
// sing-box 客户端配置里没有 "h2" 传输类型，H2 必须写 "type": "http" 且 host 为数组；
// mihomo 里 HTTPUpgrade 必须写 network ws + ws-opts v2ray-http-upgrade，不是 network httpupgrade。
func TestH2ClientTransportIsHTTP(t *testing.T) {
	domain := "www.example.com"
	path := "/h2path"
	addr := "203.0.113.10"
	uuid := "11111111-2222-3333-4444-555555555555"

	cases := []struct {
		proto string
		cfg   string
	}{
		{"vless", mustJSON(t, VLESSConfig{UUID: uuid, Mode: "h2", Domain: domain, Path: path})},
		{"vmess", mustJSON(t, VMessConfig{UUID: uuid, Mode: "h2", Domain: domain, Path: path})},
		{"trojan", mustJSON(t, TrojanConfig{Password: "pw123456", Mode: "h2", Domain: domain, Path: path})},
	}
	for _, c := range cases {
		obs, _, err := ClientOutbounds(c.proto, c.cfg, addr, 443, domain, "test-h2")
		if err != nil {
			t.Fatalf("%s h2: %v", c.proto, err)
		}
		if len(obs) == 0 {
			t.Fatalf("%s h2: 没有出站", c.proto)
		}
		tr, ok := obs[0]["transport"].(map[string]interface{})
		if !ok {
			t.Fatalf("%s h2: 出站缺 transport", c.proto)
		}
		if tr["type"] != "http" {
			t.Fatalf("%s h2: transport type 是 %v，想要 http", c.proto, tr["type"])
		}
		hosts, ok := tr["host"].([]string)
		if !ok || len(hosts) != 1 || hosts[0] != domain {
			t.Fatalf("%s h2: host 是 %v，想要 [%s]", c.proto, tr["host"], domain)
		}
		if tr["path"] != path {
			t.Fatalf("%s h2: path 是 %v，想要 %s", c.proto, tr["path"], path)
		}
	}
}

func TestClashHttpUpgradeIsWS(t *testing.T) {
	domain := "www.example.com"
	path := "/up"
	addr := "203.0.113.10"
	uuid := "11111111-2222-3333-4444-555555555555"

	cases := []struct {
		proto string
		cfg   string
	}{
		{"vless", mustJSON(t, VLESSConfig{UUID: uuid, Mode: "httpupgrade", Domain: domain, Path: path})},
		{"vmess", mustJSON(t, VMessConfig{UUID: uuid, Mode: "httpupgrade", Domain: domain, Path: path})},
		{"trojan", mustJSON(t, TrojanConfig{Password: "pw123456", Mode: "httpupgrade", Domain: domain, Path: path})},
	}
	for _, c := range cases {
		p, err := ClashProxy(c.proto, c.cfg, addr, 443, domain, "test-up")
		if err != nil {
			t.Fatalf("%s httpupgrade: %v", c.proto, err)
		}
		if p["network"] != "ws" {
			t.Fatalf("%s httpupgrade: network 是 %v，想要 ws", c.proto, p["network"])
		}
		opts, ok := p["ws-opts"].(map[string]interface{})
		if !ok {
			t.Fatalf("%s httpupgrade: 缺 ws-opts", c.proto)
		}
		if opts["v2ray-http-upgrade"] != true {
			t.Fatalf("%s httpupgrade: ws-opts 缺 v2ray-http-upgrade", c.proto)
		}
		if opts["path"] != path {
			t.Fatalf("%s httpupgrade: path 是 %v，想要 %s", c.proto, opts["path"], path)
		}
		headers, ok := opts["headers"].(map[string]interface{})
		if !ok || headers["Host"] != domain {
			t.Fatalf("%s httpupgrade: Host 是 %v，想要 %s", c.proto, opts["headers"], domain)
		}
	}
}
