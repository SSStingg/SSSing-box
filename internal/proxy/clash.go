package proxy

import (
	"encoding/json"
	"fmt"
)

// ---------- Clash / mihomo YAML（订阅 clash 格式用） ----------
//
// mihomo 能表示的协议才进 YAML；表示不了的跳过（不让一个
// 坏条目拖垮整份 YAML，调用方按错误跳过该节点）：
//   - Snell v6：mihomo 没有 v6（只认 1-5，v5 服务端按 v4 拨号），
//     v6 节点跳过；服务端 v5 写 version=4。
//   - Naive：mihomo 没有 naive 类型，但 Naive 线上就是 TLS 之上的
//     HTTP 代理，按 http + tls 写（3x-ui-naive 同款做法）。
//   - AnyTLS：mihomo 有 anytls 类型（password/sni/skip-cert-verify）。
//   - ShadowTLS：没有独立类型，用 ss + plugin shadow-tls
//     （plugin-opts: host/password/version: 3，版本必须写死，
//     各家客户端缺省都是 v2）。
//   - WireGuard：mihomo 有 wireguard 类型。

// ClashProxy：本地入站 → 一条 mihomo proxies 条目。
// address/port/sni/name 与 ClientOutbounds 同口径。
func ClashProxy(protocol, configJSON, address string, port int, sni, name string) (map[string]interface{}, error) {
	base := func(typ string) map[string]interface{} {
		return map[string]interface{}{
			"name":   name,
			"type":   typ,
			"server": address,
			"port":   port,
		}
	}
	switch protocol {
	case "vless":
		var cfg VLESSConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, err
		}
		mode := cfg.Mode
		if mode == "" {
			mode = "reality"
		}
		p := base("vless")
		p["uuid"] = cfg.UUID
		p["tls"] = true
		switch mode {
		case "reality":
			p["servername"] = sni
			p["reality-opts"] = map[string]interface{}{
				"public-key": cfg.PublicKey,
				"short-id":   cfg.ShortID,
			}
			fp := cfg.Fingerprint
			if fp == "" {
				fp = "chrome"
			}
			p["client-fingerprint"] = fp
			if cfg.Flow != "" {
				p["flow"] = cfg.Flow
			}
		case "ws", "h2", "httpupgrade":
			domain := tlsDomain(cfg.Domain, sni, address)
			p["server"] = domain
			p["servername"] = domain
			p["skip-cert-verify"] = true
			p["network"] = mode
			if mode == "ws" {
				p["ws-opts"] = map[string]interface{}{
					"path":    cfg.Path,
					"headers": map[string]interface{}{"Host": domain},
				}
			} else if mode == "h2" {
				p["h2-opts"] = map[string]interface{}{
					"host": []string{domain},
					"path": cfg.Path,
				}
			}
		default:
			return nil, fmt.Errorf("不支持的 VLESS 档位：%s", mode)
		}
		return p, nil
	case "vmess":
		var cfg VMessConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, err
		}
		p := base("vmess")
		p["uuid"] = cfg.UUID
		p["alterId"] = 0
		p["cipher"] = "auto"
		switch cfg.Mode {
		case "tcp", "":
			p["tls"] = false
		case "cf":
			domain := tlsDomain(cfg.Domain, sni, address)
			p["server"] = domain
			p["tls"] = true
			p["servername"] = domain
			p["network"] = "ws"
			p["ws-opts"] = map[string]interface{}{
				"path":    cfg.Path,
				"headers": map[string]interface{}{"Host": domain},
			}
		case "http":
			host := cfg.Domain
			if host == "" {
				host = address
			}
			p["network"] = "http"
			p["http-opts"] = map[string]interface{}{
				"path":    []string{cfg.Path},
				"headers": map[string]interface{}{"Host": []string{host}},
			}
		case "quic", "h2", "httpupgrade":
			domain := tlsDomain(cfg.Domain, sni, address)
			p["server"] = domain
			p["tls"] = true
			p["servername"] = domain
			p["skip-cert-verify"] = true
			p["network"] = cfg.Mode
			if cfg.Mode == "h2" {
				p["h2-opts"] = map[string]interface{}{
					"host": []string{domain},
					"path": cfg.Path,
				}
			}
		default:
			return nil, fmt.Errorf("不支持的 VMess 档位：%s", cfg.Mode)
		}
		return p, nil
	case "trojan":
		var cfg TrojanConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, err
		}
		mode := cfg.Mode
		if mode == "" {
			mode = "reality"
		}
		p := base("trojan")
		p["password"] = cfg.Password
		p["tls"] = true
		switch mode {
		case "reality":
			p["sni"] = sni
			p["reality-opts"] = map[string]interface{}{
				"public-key": cfg.PublicKey,
				"short-id":   cfg.ShortID,
			}
			p["client-fingerprint"] = "chrome"
		case "cf":
			domain := tlsDomain(cfg.Domain, sni, address)
			p["server"] = domain
			p["sni"] = domain
			p["network"] = "ws"
			p["ws-opts"] = map[string]interface{}{
				"path":    cfg.Path,
				"headers": map[string]interface{}{"Host": domain},
			}
		case "h2", "httpupgrade":
			domain := tlsDomain(cfg.Domain, sni, address)
			p["server"] = domain
			p["sni"] = domain
			p["skip-cert-verify"] = true
			p["network"] = mode
			if mode == "h2" {
				p["h2-opts"] = map[string]interface{}{
					"host": []string{domain},
					"path": cfg.Path,
				}
			}
		default:
			return nil, fmt.Errorf("不支持的 Trojan 档位：%s", mode)
		}
		return p, nil
	case "ss":
		var cfg SSConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, err
		}
		p := base("ss")
		p["cipher"] = cfg.Method
		p["password"] = cfg.Password
		p["udp"] = true
		return p, nil
	case "socks":
		var cfg SocksConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, err
		}
		p := base("socks5")
		p["username"] = cfg.User
		p["password"] = cfg.Pass
		p["udp"] = true
		return p, nil
	case "http":
		var cfg HTTPConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, err
		}
		p := base("http")
		p["username"] = cfg.User
		p["password"] = cfg.Pass
		p["tls"] = false
		return p, nil
	case "hy2":
		var cfg Hy2Config
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, err
		}
		p := base("hysteria2")
		p["password"] = cfg.Password
		p["sni"] = sni
		p["skip-cert-verify"] = true
		p["alpn"] = []string{"h3"}
		if cfg.ObfsType == "salamander" {
			p["obfs"] = "salamander"
			p["obfs-password"] = cfg.ObfsPassword
		}
		if _, _, err := ParseHopPorts(cfg.HopPorts); err == nil {
			p["ports"] = cfg.HopPorts
		}
		return p, nil
	case "tuic":
		var cfg TUICConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, err
		}
		p := base("tuic")
		p["uuid"] = cfg.UUID
		p["password"] = cfg.Password
		p["sni"] = sni
		p["alpn"] = []string{"h3"}
		p["skip-cert-verify"] = true
		p["congestion-controller"] = "bbr"
		p["udp-relay-mode"] = "native"
		return p, nil
	case "anytls":
		var cfg AnyTLSConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, err
		}
		p := base("anytls")
		p["password"] = cfg.Password
		p["sni"] = sni
		p["client-fingerprint"] = "chrome"
		p["skip-cert-verify"] = true
		return p, nil
	case "naive":
		var cfg NaiveConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, err
		}
		if cfg.Domain == "" {
			return nil, fmt.Errorf("Naive 节点缺少域名，无法生成 Clash 代理")
		}
		// mihomo 没有 naive 类型；Naive 线上就是 TLS 之上的 HTTP
		// 代理，按 http + tls 写。
		p := base("http")
		p["server"] = cfg.Domain
		p["username"] = cfg.Username
		p["password"] = cfg.Password
		p["tls"] = true
		p["sni"] = cfg.Domain
		return p, nil
	case "snell":
		var cfg SnellConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, err
		}
		if cfg.Version == 6 {
			return nil, fmt.Errorf("mihomo 不支持 Snell v6，跳过")
		}
		if cfg.Version != 5 {
			return nil, fmt.Errorf("不支持的 Snell 版本：%d", cfg.Version)
		}
		p := base("snell")
		p["psk"] = cfg.PSK
		// 服务端 v5 → 写 version=4（mihomo 按 v4 拨 v5 服务端）。
		p["version"] = 4
		p["udp"] = true
		if cfg.ObfsMode == "http" {
			p["obfs-opts"] = map[string]interface{}{
				"mode": "http",
				"host": cfg.ObfsHost,
			}
		}
		return p, nil
	case "shadowtls":
		var cfg ShadowTLSConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, err
		}
		p := base("ss")
		p["cipher"] = cfg.SSMethod
		p["password"] = cfg.SSPassword
		p["udp"] = true
		p["plugin"] = "shadow-tls"
		p["plugin-opts"] = map[string]interface{}{
			"host":     cfg.Handshake,
			"password": cfg.Password,
			"version":  3,
		}
		return p, nil
	case "wireguard":
		var cfg WGConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, err
		}
		p := base("wireguard")
		p["ip"] = cfg.ClientIP
		p["private-key"] = cfg.ClientPriv
		p["public-key"] = cfg.ServerPub
		p["udp"] = true
		p["mtu"] = 1420
		p["persistent-keepalive"] = 25
		p["allowed-ips"] = []string{"0.0.0.0/0", "::/0"}
		return p, nil
	}
	return nil, fmt.Errorf("不支持的协议：%s", protocol)
}

// ClashConfig：订阅用的完整 mihomo YAML 文档（map 形式，
// 调用方用 yaml.Marshal 输出）。proxies 为 ClashProxy 的产出。
// 选单与自动选择都指向全部节点；内网段直连，其余走选单。
func ClashConfig(proxies []map[string]interface{}) map[string]interface{} {
	var names []string
	for _, p := range proxies {
		if n, ok := p["name"].(string); ok && n != "" {
			names = append(names, n)
		}
	}
	selProxies := []interface{}{}
	for _, n := range names {
		selProxies = append(selProxies, n)
	}
	selProxies = append(selProxies, "DIRECT")
	groups := []interface{}{
		map[string]interface{}{
			"name":    "🚀 节点选择",
			"type":    "select",
			"proxies": selProxies,
		},
	}
	if len(names) > 0 {
		testProxies := []interface{}{}
		for _, n := range names {
			testProxies = append(testProxies, n)
		}
		groups = append(groups, map[string]interface{}{
			"name":     "♻️ 自动选择",
			"type":     "url-test",
			"proxies":  testProxies,
			"url":      "http://www.gstatic.com/generate_204",
			"interval": 300,
		})
	}
	return map[string]interface{}{
		"port":         7890,
		"socks-port":   7891,
		"allow-lan":    false,
		"mode":         "rule",
		"log-level":    "info",
		"proxies":      proxies,
		"proxy-groups": groups,
		"rules": []interface{}{
			"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
			"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
			"IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
			"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
			"MATCH,🚀 节点选择",
		},
	}
}
