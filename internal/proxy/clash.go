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
//     HTTP 代理，按 http + tls 写。
//   - AnyTLS：mihomo 有 anytls 类型（password/sni/skip-cert-verify）。
//   - ShadowTLS：用 ss + plugin shadow-tls（version: 3 必须显式写死）。
//   - WireGuard：mihomo 有 wireguard 类型。
//   - HTTPUpgrade：mihomo 里走 network: "ws" + ws-opts.v2ray-http-upgrade: true，
//     不是 network: "httpupgrade"。

// ClashProxy：本地入站 → 一条 mihomo proxies 条目。
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
		p["udp"] = true
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
			switch mode {
			case "ws":
				p["network"] = "ws"
				p["ws-opts"] = map[string]interface{}{
					"path":    cfg.Path,
					"headers": map[string]interface{}{"Host": domain},
				}
			case "h2":
				p["network"] = "h2"
				p["h2-opts"] = map[string]interface{}{
					"host": []string{domain},
					"path": cfg.Path,
				}
			case "httpupgrade":
				// mihomo 里 HTTPUpgrade 走 network ws + v2ray-http-upgrade，不是 network httpupgrade。
				p["network"] = "ws"
				p["ws-opts"] = map[string]interface{}{
					"path":               cfg.Path,
					"headers":            map[string]interface{}{"Host": domain},
					"v2ray-http-upgrade": true,
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
		p["udp"] = true
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
			switch cfg.Mode {
			case "h2":
				p["network"] = "h2"
				p["h2-opts"] = map[string]interface{}{
					"host": []string{domain},
					"path": cfg.Path,
				}
			case "httpupgrade":
				p["network"] = "ws"
				p["ws-opts"] = map[string]interface{}{
					"path":               cfg.Path,
					"headers":            map[string]interface{}{"Host": domain},
					"v2ray-http-upgrade": true,
				}
			case "quic":
				p["network"] = "quic"
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
		p["udp"] = true
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
			if mode == "h2" {
				p["network"] = "h2"
				p["h2-opts"] = map[string]interface{}{
					"host": []string{domain},
					"path": cfg.Path,
				}
			} else {
				p["network"] = "ws"
				p["ws-opts"] = map[string]interface{}{
					"path":               cfg.Path,
					"headers":            map[string]interface{}{"Host": domain},
					"v2ray-http-upgrade": true,
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
		p["udp"] = true
		return p, nil
	case "naive":
		var cfg NaiveConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, err
		}
		if cfg.Domain == "" {
			return nil, fmt.Errorf("Naive 节点缺少域名，无法生成 Clash 代理")
		}
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
		p["mtu"] = 1280
		p["persistent-keepalive"] = 25
		p["allowed-ips"] = []string{"0.0.0.0/0", "::/0"}
		return p, nil
	}
	return nil, fmt.Errorf("不支持的协议：%s", protocol)
}

// ClashConfig：订阅用的完整 mihomo YAML 文档（map 形式，调用方用 yaml.Marshal 输出）。
func ClashConfig(proxies []map[string]interface{}) map[string]interface{} {
	var names []string
	for _, p := range proxies {
		if n, ok := p["name"].(string); ok && n != "" {
			names = append(names, n)
		}
	}
	selProxies := []interface{}{}
	if len(names) > 0 {
		selProxies = append(selProxies, "♻️ 自动选择")
	}
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

// ClashBProxy：将 BNode 的存储配置转换为 mihomo proxies 条目。
// 复用 SingBoxBOutbound 的转换结果（server/server_port/tls/transport 均为 sing-box 形态）。
// ShadowTLS 例外：mihomo 里它是 ss + shadow-tls 插件（与本地入站的 ClashProxy 画法一致），
// 直接读存储配置拼，不走 sing-box 的双出站。
func ClashBProxy(protocol, configJSON, name string) (map[string]interface{}, error) {
	if protocol == "shadowtls" {
		var stored map[string]interface{}
		if err := json.Unmarshal([]byte(configJSON), &stored); err != nil {
			return nil, fmt.Errorf("B 节点配置解析失败：%w", err)
		}
		if sbStr(stored, "password") == "" {
			return nil, fmt.Errorf("shadowtls B 节点缺少密码")
		}
		if sbStr(stored, "ss_password") == "" {
			return nil, fmt.Errorf("shadowtls B 节点缺少内层 SS 密码")
		}
		handshake := sbStr(stored, "handshake")
		if handshake == "" {
			handshake = "gateway.icloud.com"
		}
		method := sbStr(stored, "ss_method")
		if method == "" {
			method = "2022-blake3-aes-128-gcm"
		}
		p := map[string]interface{}{
			"name": name, "type": "ss",
			"server": sbStr(stored, "server"), "port": sbInt(stored["server_port"]),
			"cipher": method, "password": sbStr(stored, "ss_password"), "udp": true,
			"plugin":      "shadow-tls",
			"plugin-opts": map[string]interface{}{"host": handshake, "password": sbStr(stored, "password"), "version": 3},
		}
		if err := checkBServer(map[string]interface{}{"server": p["server"], "server_port": p["port"]}); err != nil {
			return nil, err
		}
		return p, nil
	}
	obs, err := SingBoxBOutbound(protocol, configJSON, name)
	if err != nil {
		return nil, err
	}
	ob := obs[0]
	base := func(typ string) map[string]interface{} {
		return map[string]interface{}{
			"name":   name,
			"type":   typ,
			"server": ob["server"],
			"port":   ob["server_port"],
		}
	}
	applyTLS := func(p map[string]interface{}, sniKey string) {
		tlsMap := sbMap(ob, "tls")
		if tlsMap == nil {
			return
		}
		p["tls"] = true
		if sn := sbStr(tlsMap, "server_name"); sn != "" {
			p[sniKey] = sn
		}
		if inc, _ := tlsMap["insecure"].(bool); inc {
			p["skip-cert-verify"] = true
		}
		if utls := sbMap(tlsMap, "utls"); utls != nil {
			if fp := sbStr(utls, "fingerprint"); fp != "" {
				p["client-fingerprint"] = fp
			}
		}
		if alpn, ok := tlsMap["alpn"].([]interface{}); ok && len(alpn) > 0 {
			p["alpn"] = alpn
		}
		if real := sbMap(tlsMap, "reality"); real != nil {
			p["reality-opts"] = map[string]interface{}{
				"public-key": sbStr(real, "public_key"),
				"short-id":   sbStr(real, "short_id"),
			}
		}
	}
	applyTransport := func(p map[string]interface{}) error {
		tr := sbMap(ob, "transport")
		if tr == nil {
			return nil
		}
		switch sbStr(tr, "type") {
		case "ws":
			p["network"] = "ws"
			wsOpts := map[string]interface{}{"path": sbStr(tr, "path")}
			if hm := sbMap(tr, "headers"); hm != nil && sbStr(hm, "Host") != "" {
				wsOpts["headers"] = map[string]interface{}{"Host": sbStr(hm, "Host")}
			}
			p["ws-opts"] = wsOpts
		case "http":
			p["network"] = "h2"
			h2Opts := map[string]interface{}{"path": sbStr(tr, "path")}
			if hs, ok := tr["host"].([]string); ok && len(hs) > 0 {
				h2Opts["host"] = hs
			}
			p["h2-opts"] = h2Opts
		case "httpupgrade":
			p["network"] = "ws"
			wsOpts := map[string]interface{}{
				"path":               sbStr(tr, "path"),
				"v2ray-http-upgrade": true,
			}
			if h := sbStr(tr, "host"); h != "" {
				wsOpts["headers"] = map[string]interface{}{"Host": h}
			}
			p["ws-opts"] = wsOpts
		case "grpc":
			p["network"] = "grpc"
			p["grpc-opts"] = map[string]interface{}{"grpc-service-name": sbStr(tr, "service_name")}
		case "quic":
			p["network"] = "quic"
		}
		return nil
	}

	switch sbStr(ob, "type") {
	case "vless":
		p := base("vless")
		p["uuid"] = ob["uuid"]
		p["udp"] = true
		if f := sbStr(ob, "flow"); f != "" {
			p["flow"] = f
		}
		applyTLS(p, "servername")
		_ = applyTransport(p)
		return p, nil
	case "vmess":
		p := base("vmess")
		p["uuid"] = ob["uuid"]
		p["alterId"] = 0
		p["cipher"] = "auto"
		p["udp"] = true
		applyTLS(p, "servername")
		_ = applyTransport(p)
		return p, nil
	case "trojan":
		p := base("trojan")
		p["password"] = ob["password"]
		p["udp"] = true
		applyTLS(p, "sni")
		_ = applyTransport(p)
		return p, nil
	case "shadowsocks":
		p := base("ss")
		p["cipher"] = ob["method"]
		p["password"] = ob["password"]
		p["udp"] = true
		return p, nil
	case "socks":
		p := base("socks5")
		if u := sbStr(ob, "username"); u != "" {
			p["username"] = u
			p["password"] = sbStr(ob, "password")
		}
		p["udp"] = true
		return p, nil
	case "http":
		p := base("http")
		if u := sbStr(ob, "username"); u != "" {
			p["username"] = u
			p["password"] = sbStr(ob, "password")
		}
		applyTLS(p, "sni")
		return p, nil
	case "hysteria2":
		p := base("hysteria2")
		p["password"] = ob["password"]
		applyTLS(p, "sni")
		if obfs := sbMap(ob, "obfs"); obfs != nil && sbStr(obfs, "type") == "salamander" {
			p["obfs"] = "salamander"
			p["obfs-password"] = sbStr(obfs, "password")
		}
		return p, nil
	case "snell":
		if sbInt(ob["version"]) == 6 {
			return nil, fmt.Errorf("mihomo 不支持 Snell v6，跳过")
		}
		p := base("snell")
		p["psk"] = ob["psk"]
		p["version"] = 4
		p["udp"] = true
		if sbStr(ob, "obfs_mode") == "http" {
			p["obfs-opts"] = map[string]interface{}{
				"mode": "http",
				"host": sbStr(ob, "obfs_host"),
			}
		}
		return p, nil
	default:
		return nil, fmt.Errorf("不支持的 B 节点协议：%s", protocol)
	}
}
