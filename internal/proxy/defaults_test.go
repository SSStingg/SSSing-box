package proxy

import (
	"strings"
	"testing"
)

// 默认参数：WG MTU 1420→1280（三处渲染 + 官方客户端文本配置）。
func TestWGEndpointMTU1280(t *testing.T) {
	cfg := WGConfig{ServerPriv: "sp", ServerPub: "spub", ClientPriv: "cp", ClientPub: "cpub", ClientIP: "10.0.0.2/32"}
	ep := SingBoxWGEndpoint("t", 51820, cfg)
	if ep["mtu"] != 1280 {
		t.Fatalf("server endpoint mtu = %v, want 1280", ep["mtu"])
	}
	p, err := ClashProxy("wireguard", mustJSON(t, cfg), "1.2.3.4", 51820, "", "WG")
	if err != nil {
		t.Fatal(err)
	}
	if p["mtu"] != 1280 {
		t.Fatalf("clash proxy mtu = %v, want 1280", p["mtu"])
	}
	_, eps, err := ClientOutbounds("wireguard", mustJSON(t, cfg), "1.2.3.4", 51820, "", "WG")
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0]["mtu"] != 1280 {
		t.Fatalf("sing-box client endpoint mtu = %v, want 1280", eps)
	}
	if !strings.Contains(WGClientConfig("1.2.3.4", 51820, cfg, "WG"), "MTU = 1280") {
		t.Fatal("official client text config lacks MTU = 1280")
	}
}

// DefaultSnell：新建 Snell v5 默认混淆 Host 是 SNI 池随机值，永不为 bing.com。
func TestDefaultSnellRandomHost(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		c := DefaultSnell()
		if c.ObfsHost == "" || c.ObfsHost == "bing.com" || c.ObfsHost == "www.bing.com" {
			t.Fatalf("bad default snell host: %q", c.ObfsHost)
		}
		seen[c.ObfsHost] = true
	}
	if len(seen) < 2 {
		t.Fatal("DefaultSnell host never varies")
	}
}
