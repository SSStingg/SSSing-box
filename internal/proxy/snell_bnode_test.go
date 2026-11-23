package proxy

import (
	"testing"
)

func TestParseSnellV5Link(t *testing.T) {
	p, err := ParseBLink("snell://psk12345678@1.2.3.4:12345?version=4&obfs=http&obfs-host=example.com#TestSnell")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Protocol != "snell" || p.Name != "TestSnell" {
		t.Fatalf("protocol/name = %q/%q", p.Protocol, p.Name)
	}
	if v := p.Outbound["version"]; v != 5 {
		t.Fatalf("version = %v (%T), want int 5 (panel numbering)", v, v)
	}
	if p.Outbound["obfs_mode"] != "http" || p.Outbound["obfs_host"] != "example.com" {
		t.Fatalf("obfs_mode/obfs_host = %#v/%#v", p.Outbound["obfs_mode"], p.Outbound["obfs_host"])
	}
	if _, ok := p.Outbound["obfs"]; ok {
		t.Fatalf("must not carry obfs object, got %#v", p.Outbound["obfs"])
	}
}

func TestParseSnellV6Link(t *testing.T) {
	p, err := ParseBLink("snell://psk12345678@1.2.3.4:12345?version=6&mode=default#V6")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if v := p.Outbound["version"]; v != 6 {
		t.Fatalf("version = %v (%T), want int 6", v, v)
	}
	if p.Outbound["mode"] != "default" {
		t.Fatalf("mode = %#v", p.Outbound["mode"])
	}
	if _, ok := p.Outbound["obfs"]; ok {
		t.Fatalf("v6 must not carry obfs, got %#v", p.Outbound["obfs"])
	}
}

func TestParseSnellBad(t *testing.T) {
	for _, link := range []string{
		"snell://@1.2.3.4:12345?version=4",            // 无 psk
		"snell://psk12345678@:12345?version=4",        // 无地址
		"snell://psk12345678@1.2.3.4?version=4",       // 无端口
		"snell://psk12345678@1.2.3.4:12345?version=7", // 不支持的版本
	} {
		if _, err := ParseBLink(link); err == nil {
			t.Errorf("link %q should fail", link)
		}
	}
}

func TestSingBoxBOutboundSnellV5(t *testing.T) {
	cfg := mustJSON(t, map[string]interface{}{
		"type": "snell", "server": "1.2.3.4", "server_port": 12345,
		"version": 5, "psk": "psk12345678",
		"obfs_mode": "http", "obfs_host": "example.com",
	})
	obs, err := SingBoxBOutbound("snell", cfg, "chain-b-x")
	if err != nil {
		t.Fatalf("outbound: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("snell should emit exactly 1 outbound, got %d", len(obs))
	}
	ob := obs[0]
	if ob["type"] != "snell" || ob["server"] != "1.2.3.4" || ob["server_port"] != 12345 {
		t.Fatalf("outbound = %#v", ob)
	}
	// 面板 v5 -> 线路 version 4（sing-box 出站不认 5）
	if v := ob["version"]; v != 4 {
		t.Fatalf("version = %v (%T), want int 4 (wire version)", v, v)
	}
	if ob["obfs_mode"] != "http" || ob["obfs_host"] != "example.com" {
		t.Fatalf("obfs_mode/obfs_host = %#v/%#v", ob["obfs_mode"], ob["obfs_host"])
	}
	if _, ok := ob["obfs"]; ok {
		t.Fatalf("must not carry obfs field, got %#v", ob["obfs"])
	}
}

func TestSingBoxBOutboundSnellV6(t *testing.T) {
	cfg := mustJSON(t, map[string]interface{}{
		"type": "snell", "server": "1.2.3.4", "server_port": 12345,
		"version": 6, "psk": "psk12345678", "mode": "default",
	})
	obs, err := SingBoxBOutbound("snell", cfg, "chain-b-x")
	if err != nil {
		t.Fatalf("outbound: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("snell should emit exactly 1 outbound, got %d", len(obs))
	}
	ob := obs[0]
	if v := ob["version"]; v != 6 {
		t.Fatalf("version = %v (%T), want int 6", v, v)
	}
	if ob["mode"] != "default" {
		t.Fatalf("mode = %#v", ob["mode"])
	}
	if _, ok := ob["obfs"]; ok {
		t.Fatalf("v6 outbound must not carry obfs, got %#v", ob["obfs"])
	}
	if _, ok := ob["obfs_mode"]; ok {
		t.Fatalf("v6 outbound must not carry obfs_mode, got %#v", ob["obfs_mode"])
	}
}

func TestSingBoxBOutboundSnellLegacyObfs(t *testing.T) {
	// 旧存法 obfs 对象仍要能转成 obfs_mode
	cfg := mustJSON(t, map[string]interface{}{
		"type": "snell", "server": "1.2.3.4", "server_port": 12345,
		"version": 5, "psk": "psk12345678",
		"obfs": map[string]interface{}{"type": "http", "host": "example.com"},
	})
	obs, err := SingBoxBOutbound("snell", cfg, "chain-b-x")
	if err != nil {
		t.Fatalf("outbound: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("snell should emit exactly 1 outbound, got %d", len(obs))
	}
	ob := obs[0]
	if ob["version"] != 4 || ob["obfs_mode"] != "http" || ob["obfs_host"] != "example.com" {
		t.Fatalf("outbound = %#v", ob)
	}
}

func TestSingBoxBOutboundSnellBad(t *testing.T) {
	// 缺 psk
	cfg := mustJSON(t, map[string]interface{}{
		"type": "snell", "server": "1.2.3.4", "server_port": 12345, "version": 5,
	})
	if _, err := SingBoxBOutbound("snell", cfg, "chain-b-x"); err == nil {
		t.Errorf("missing psk should fail")
	}
	// 非法端口
	cfg = mustJSON(t, map[string]interface{}{
		"type": "snell", "server": "1.2.3.4", "server_port": 0, "version": 5, "psk": "x",
	})
	if _, err := SingBoxBOutbound("snell", cfg, "chain-b-x"); err == nil {
		t.Errorf("port 0 should fail")
	}
}
