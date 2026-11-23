package proxy

import (
	"encoding/json"
	"testing"
)

// Clash 订阅必须包含外部 B 节点；Snell v6 不被 mihomo 支持，应跳过。
// B 节点配置是链接解析后的存储格式（vless 为 xray outbound，
// snell 为 sing-box 风格 outbound），与 SingBoxBOutbound 的输入一致。
func TestClashBProxy(t *testing.T) {
	pb, err := ParseBLink("vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?type=ws&security=tls&path=%2Fws&sni=example.com#B-VLESS")
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(pb.Outbound)
	p, err := ClashBProxy("vless", string(cfg), "B-VLESS")
	if err != nil {
		t.Fatal(err)
	}
	if p["type"] != "vless" || p["name"] != "B-VLESS" || p["uuid"] != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("vless bnode clash entry wrong: %v", p)
	}
	if p["network"] != "ws" || p["tls"] != true {
		t.Fatalf("vless bnode clash transport/tls wrong: %v", p)
	}

	pb, err = ParseBLink("snell://snelltestpsk1234567890abcdef@203.0.113.10:10019?version=6#B-SNELL6")
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ = json.Marshal(pb.Outbound)
	if _, err := ClashBProxy("snell", string(cfg), "B-SNELL6"); err == nil {
		t.Fatalf("snell v6 should be skipped for Clash")
	}

	pb, err = ParseBLink("snell://snelltestpsk1234567890abcdef@203.0.113.10:10019?version=5&obfs=http&obfs-host=bing.com#B-SNELL5")
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ = json.Marshal(pb.Outbound)
	p, err = ClashBProxy("snell", string(cfg), "B-SNELL5")
	if err != nil {
		t.Fatal(err)
	}
	if p["type"] != "snell" || p["version"] != 4 {
		t.Fatalf("snell v5 clash entry wrong: %v", p)
	}
}
