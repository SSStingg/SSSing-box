package proxy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// ---------- 客户端出站（订阅 sing-box JSON 用） ----------
//
// 本地入站 → sing-box 客户端出站。字段与入站生成器、链接生成器
// 逐项对齐：同一份配置，服务端入站怎么接，客户端出站就怎么写。
// 关键映射：
//   - Snell：入站 5/6，出站只认 4/6——服务端 v5 必须写出站 version=4，
//     v5 的 TCP 线协议与 v4 相同，没有 v5 客户端。
//   - Reality 出站：sing-box 强制要求 utls，fingerprint 取入站配置，缺省 chrome。
//   - ShadowTLS：没有 URL 链接，固定两个出站（SS detour 到 shadowtls），
//     直接复用 ShadowTLSClientJSON 的产出。
//   - WireGuard：sing-box 1.13 起出站已移除，改 endpoints 段端点；
//     端点 tag 直接用节点名，选单里引用它。
//   - H2 传输：sing-box 没有 "h2" 传输类型，客户端与服务端统一写 "type": "http"
//     且 host 为字符串数组，配合 TLS 自动协商 HTTP/2。

// ClientOutbounds：本地入站 → 客户端出站（+ WireGuard 端点）。
// address 是订阅用的服务器地址（域名或公网 IP），sni 是入站 SNI，
// name 是节点名（即出站 tag）。不支持的协议/缺关键字段返回错误，
// 调用方跳过该节点（订阅里不出现，不让一个坏节点拖垮整份订阅）。
func ClientOutbounds(protocol, configJSON, address string, port int, sni, name string) (outbounds, endpoints []map[string]interface{}, err error) {
	base := func(typ string) map[string]interface{} {
		return map[string]interface{}{
			"type":        typ,
			"tag":         name,
			"server":      address,
			"server_port": port,
		}
	}
	switch protocol {
	case "vless":
		var cfg VLESSConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, nil, err
		}
		mode := cfg.Mode
		if mode == "" {
			mode = "reality"
		}
		ob := base("vless")
		ob["uuid"] = cfg.UUID
		switch mode {
		case "reality":
			ob["tls"] = realityClientTLS(sni, cfg.PublicKey, cfg.ShortID, cfg.Fingerprint)
			if cfg.Flow != "" {
				ob["flow"] = cfg.Flow
			}
		case "ws", "h2", "httpupgrade":
			domain := tlsDomain(cfg.Domain, sni, address)
			ob["server"] = domain
			ob["tls"] = tlsClient(domain, true)
			ob["transport"] = transportOutbound(mode, cfg.Path, domain)
		default:
			return nil, nil, fmt.Errorf("不支持的 VLESS 档位：%s", mode)
		}
		return []map[string]interface{}{ob}, nil, nil
	case "vmess":
		var cfg VMessConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, nil, err
		}
		ob := base("vmess")
		ob["uuid"] = cfg.UUID
		ob["security"] = "auto"
		switch cfg.Mode {
		case "tcp", "":
			// 裸 TCP，无 tls、无 transport。
		case "cf":
			domain := tlsDomain(cfg.Domain, sni, address)
			ob["server"] = domain
			ob["tls"] = tlsClient(domain, false)
			ob["transport"] = wsTransport(cfg.Path, domain)
		case "http":
			host := cfg.Domain
			if host == "" {
				host = address
			}
			ob["transport"] = httpTransport(host, cfg.Path)
		case "quic":
			domain := tlsDomain(cfg.Domain, sni, address)
			ob["server"] = domain
			ob["tls"] = tlsClient(domain, true)
			ob["transport"] = map[string]interface{}{"type": "quic"}
		case "h2", "httpupgrade":
			domain := tlsDomain(cfg.Domain, sni, address)
			ob["server"] = domain
			ob["tls"] = tlsClient(domain, true)
			ob["transport"] = transportOutbound(cfg.Mode, cfg.Path, domain)
		default:
			return nil, nil, fmt.Errorf("不支持的 VMess 档位：%s", cfg.Mode)
		}
		return []map[string]interface{}{ob}, nil, nil
	case "trojan":
		var cfg TrojanConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, nil, err
		}
		mode := cfg.Mode
		if mode == "" {
			mode = "reality"
		}
		ob := base("trojan")
		ob["password"] = cfg.Password
		switch mode {
		case "reality":
			ob["tls"] = realityClientTLS(sni, cfg.PublicKey, cfg.ShortID, "chrome")
		case "cf":
			domain := tlsDomain(cfg.Domain, sni, address)
			ob["server"] = domain
			ob["tls"] = tlsClient(domain, false)
			ob["transport"] = wsTransport(cfg.Path, domain)
		case "h2", "httpupgrade":
			domain := tlsDomain(cfg.Domain, sni, address)
			ob["server"] = domain
			ob["tls"] = tlsClient(domain, true)
			ob["transport"] = transportOutbound(mode, cfg.Path, domain)
		default:
			return nil, nil, fmt.Errorf("不支持的 Trojan 档位：%s", mode)
		}
		return []map[string]interface{}{ob}, nil, nil
	case "ss":
		var cfg SSConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, nil, err
		}
		ob := base("shadowsocks")
		ob["method"] = cfg.Method
		ob["password"] = cfg.Password
		return []map[string]interface{}{ob}, nil, nil
	case "socks":
		var cfg SocksConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, nil, err
		}
		ob := base("socks")
		ob["version"] = "5"
		ob["username"] = cfg.User
		ob["password"] = cfg.Pass
		return []map[string]interface{}{ob}, nil, nil
	case "http":
		var cfg HTTPConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, nil, err
		}
		ob := base("http")
		ob["username"] = cfg.User
		ob["password"] = cfg.Pass
		return []map[string]interface{}{ob}, nil, nil
	case "hy2":
		var cfg Hy2Config
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, nil, err
		}
		ob := base("hysteria2")
		ob["password"] = cfg.Password
		tls := map[string]interface{}{"enabled": true, "insecure": true, "alpn": []string{"h3"}}
		if sni != "" {
			tls["server_name"] = sni
		}
		ob["tls"] = tls
		if cfg.ObfsType == "salamander" {
			ob["obfs"] = map[string]interface{}{"type": "salamander", "password": cfg.ObfsPassword}
		}
		if start, end, err := ParseHopPorts(cfg.HopPorts); err == nil {
			ob["server_ports"] = []string{fmt.Sprintf("%d:%d", start, end)}
		}
		// 限速必须是数字：Hy2Config 里存的是字符串，不转 int 会导致客户端加载失败。
		if v, err := strconv.Atoi(cfg.UpMbps); err == nil && v > 0 {
			ob["up_mbps"] = v
		}
		if v, err := strconv.Atoi(cfg.DownMbps); err == nil && v > 0 {
			ob["down_mbps"] = v
		}
		return []map[string]interface{}{ob}, nil, nil
	case "tuic":
		var cfg TUICConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, nil, err
		}
		ob := base("tuic")
		ob["uuid"] = cfg.UUID
		ob["password"] = cfg.Password
		tls := map[string]interface{}{"enabled": true, "insecure": true, "alpn": []string{"h3"}}
		if sni != "" {
			tls["server_name"] = sni
		}
		ob["tls"] = tls
		ob["congestion_control"] = "bbr"
		ob["udp_relay_mode"] = "native"
		return []map[string]interface{}{ob}, nil, nil
	case "anytls":
		var cfg AnyTLSConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, nil, err
		}
		ob := base("anytls")
		ob["password"] = cfg.Password
		tls := map[string]interface{}{"enabled": true, "insecure": true}
		if sni != "" {
			tls["server_name"] = sni
		}
		ob["tls"] = tls
		return []map[string]interface{}{ob}, nil, nil
	case "naive":
		var cfg NaiveConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, nil, err
		}
		if cfg.Domain == "" {
			return nil, nil, fmt.Errorf("Naive 节点缺少域名，无法生成客户端出站")
		}
		ob := base("naive")
		ob["server"] = cfg.Domain
		ob["username"] = cfg.Username
		ob["password"] = cfg.Password
		ob["tls"] = map[string]interface{}{"enabled": true, "server_name": cfg.Domain}
		return []map[string]interface{}{ob}, nil, nil
	case "snell":
		var cfg SnellConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, nil, err
		}
		ob := base("snell")
		ob["psk"] = cfg.PSK
		switch cfg.Version {
		case 5:
			// 服务端 v5 → 客户端 version=4（无 v5 客户端）。
			ob["version"] = 4
			if cfg.ObfsMode != "" {
				ob["obfs_mode"] = cfg.ObfsMode
			}
			if cfg.ObfsMode == "http" && cfg.ObfsHost != "" {
				ob["obfs_host"] = cfg.ObfsHost
			}
		case 6:
			ob["version"] = 6
			if cfg.Mode != "" {
				ob["mode"] = cfg.Mode
			}
		default:
			return nil, nil, fmt.Errorf("不支持的 Snell 版本：%d", cfg.Version)
		}
		return []map[string]interface{}{ob}, nil, nil
	case "shadowtls":
		var cfg ShadowTLSConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, nil, err
		}
		raw := ShadowTLSClientJSON(address, port, cfg, name)
		var doc struct {
			Outbounds []map[string]interface{} `json:"outbounds"`
		}
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			return nil, nil, err
		}
		if len(doc.Outbounds) != 2 {
			return nil, nil, fmt.Errorf("ShadowTLS 客户端 JSON 不是两个出站")
		}
		return doc.Outbounds, nil, nil
	case "wireguard":
		var cfg WGConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, nil, err
		}
		ep := map[string]interface{}{
			"type":        "wireguard",
			"tag":         name,
			"system":      false,
			"mtu":         1280,
			"address":     []string{cfg.ClientIP},
			"private_key": cfg.ClientPriv,
			"peers": []interface{}{map[string]interface{}{
				"address":                       address,
				"port":                          port,
				"public_key":                    cfg.ServerPub,
				"allowed_ips":                   []string{"0.0.0.0/0", "::/0"},
				"persistent_keepalive_interval": 25,
			}},
		}
		return nil, []map[string]interface{}{ep}, nil
	}
	return nil, nil, fmt.Errorf("不支持的协议：%s", protocol)
}

// tlsClient：普通 TLS 客户端（自签证书的档 insecure=true；CF/CA 证书的档 false）。
func tlsClient(serverName string, insecure bool) map[string]interface{} {
	tls := map[string]interface{}{"enabled": true, "server_name": serverName}
	if insecure {
		tls["insecure"] = true
	}
	return tls
}

// realityClientTLS：Reality 客户端 TLS。sing-box 强制要求 utls，
// fingerprint 取入站配置，缺省 chrome。
func realityClientTLS(serverName, publicKey, shortID, fingerprint string) map[string]interface{} {
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	tls := map[string]interface{}{
		"enabled":     true,
		"server_name": serverName,
		"reality": map[string]interface{}{
			"enabled":    true,
			"public_key": publicKey,
		},
		"utls": map[string]interface{}{"enabled": true, "fingerprint": fingerprint},
	}
	if shortID != "" {
		tls["reality"].(map[string]interface{})["short_id"] = shortID
	}
	return tls
}

// tlsDomain：TLS 档的域名回退链，与链接生成器一致：Domain → SNI → 服务器地址。
func tlsDomain(domain, sni, address string) string {
	if domain != "" {
		return domain
	}
	if sni != "" {
		return sni
	}
	return address
}

// transportOutbound：ws/h2/httpupgrade 客户端传输。
// 注意：sing-box 没有 "h2" 传输类型，HTTP/2 走 "type": "http"（配 TLS 即协商 H2），host 为 []string。
func transportOutbound(mode, path, host string) map[string]interface{} {
	switch mode {
	case "ws":
		return wsTransport(path, host)
	case "h2":
		return httpTransport(host, path)
	case "httpupgrade":
		return httpUpgradeTransport(host, path)
	}
	return nil
}

// SingBoxClientConfig：订阅用的完整 sing-box 客户端配置。
func SingBoxClientConfig(nodeOutbounds []interface{}, endpoints []interface{}) map[string]interface{} {
	const selectorTag = "🚀 节点选择"
	detourTargets := map[string]bool{}
	for _, o := range nodeOutbounds {
		if m, ok := o.(map[string]interface{}); ok {
			if d, ok := m["detour"].(string); ok && d != "" {
				detourTargets[d] = true
			}
		}
	}
	var tags []string
	for _, o := range nodeOutbounds {
		if m, ok := o.(map[string]interface{}); ok {
			if t, ok := m["tag"].(string); ok && t != "" && !detourTargets[t] {
				tags = append(tags, t)
			}
		}
	}
	for _, e := range endpoints {
		if m, ok := e.(map[string]interface{}); ok {
			if t, ok := m["tag"].(string); ok && t != "" {
				tags = append(tags, t)
			}
		}
	}
	selOuts := []interface{}{}
	for _, t := range tags {
		selOuts = append(selOuts, t)
	}
	selOuts = append(selOuts, "direct")
	sel := map[string]interface{}{
		"type":      "selector",
		"tag":       selectorTag,
		"outbounds": selOuts,
	}
	if len(tags) > 0 {
		sel["default"] = tags[0]
	} else {
		sel["default"] = "direct"
	}
	outs := []interface{}{
		map[string]interface{}{"type": "direct", "tag": "direct"},
		sel,
	}
	outs = append(outs, nodeOutbounds...)
	cfg := map[string]interface{}{
		"log": map[string]interface{}{"level": "warn"},
		"dns": map[string]interface{}{
			"servers": []interface{}{map[string]interface{}{
				"tag":    "remote",
				"type":   "tls",
				"server": "8.8.8.8",
				"detour": selectorTag,
			}},
			"final": "remote",
		},
		"inbounds": []interface{}{map[string]interface{}{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      "127.0.0.1",
			"listen_port": 2080,
		}},
		"outbounds": outs,
		"route": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{"action": "sniff"},
				map[string]interface{}{"action": "route", "ip_is_private": true, "outbound": "direct"},
			},
			"final": selectorTag,
		},
	}
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}
	return cfg
}

// NaiveShareLink：Naive 单行分享链接。域名为空返回 ""（调用方跳过）。
func NaiveShareLink(cfg NaiveConfig, port int, name string) string {
	if cfg.Domain == "" {
		return ""
	}
	u := &url.URL{
		Scheme:   "naive+https",
		User:     url.UserPassword(cfg.Username, cfg.Password),
		Host:     hostPort(cfg.Domain, port),
		Fragment: name,
	}
	return u.String()
}
