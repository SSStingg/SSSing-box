package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// ---------- sing-box 全量配置生成器 ----------
//
// 把面板节点记录翻译成 sing-box JSON。字段名以 sing-box 官方文档为准：
// 入站页（TUIC / Naive / Hysteria2）、TLS 共享页（reality / certificate_path）、
// WireGuard 端点页、路由规则动作页（sniff / route）、V2Ray 传输页。
// 生成结果必须过 `sing-box check` 校验（见 singbox_test.go），文档核对代替不了这一步。

// ---------- 新增协议配置 ----------

type TUICConfig struct {
	UUID     string `json:"uuid"`
	Password string `json:"password"`
	Listen   string `json:"listen"`
}

func DefaultTUIC() TUICConfig {
	return TUICConfig{UUID: newUUID(), Password: randHex(8)}
}

type AnyTLSConfig struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	Listen   string `json:"listen"`
}

func DefaultAnyTLS() AnyTLSConfig {
	return AnyTLSConfig{Name: "user", Password: randHex(8)}
}

type NaiveConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain"` // 真域名：Naive 必须用 CA 证书，自签不行
	Listen   string `json:"listen"`
	CertFile string `json:"cert_file"` // 上传的 CA 证书（Apply 层校验存在）
	KeyFile  string `json:"key_file"`
}

func DefaultNaive() NaiveConfig {
	return NaiveConfig{Username: "user-" + randHex(3), Password: randHex(8)}
}

// ---------- Snell ----------

type SnellConfig struct {
	Version  int    `json:"version"` // 5 | 6，默认 5
	PSK      string `json:"psk"`
	ObfsMode string `json:"obfs_mode"` // v5：none | http，默认 http
	ObfsHost string `json:"obfs_host"` // v5 http 混淆 Host，默认从 SNI 池随机（排除 bing.com）
	Mode     string `json:"mode"`      // v6：default | unshaped | unsafe-raw，默认 default
	Listen   string `json:"listen"`
}

func DefaultSnell() SnellConfig {
	return SnellConfig{Version: 5, PSK: randHex(16), ObfsMode: "http", ObfsHost: RandomSnellObfsHost(), Mode: "default"}
}

func SingBoxSnellInbound(tag string, port int, cfg SnellConfig) map[string]interface{} {
	ver := cfg.Version
	if ver != 5 && ver != 6 {
		ver = 5
	}
	in := map[string]interface{}{
		"type":        "snell",
		"tag":         tag,
		"listen":      sbListen(cfg.Listen, "::"),
		"listen_port": port,
		"version":     ver,
		"psk":         cfg.PSK,
	}
	if ver == 5 {
		mode := cfg.ObfsMode
		if mode == "" {
			mode = "http"
		}
		in["obfs_mode"] = mode
	} else {
		mode := cfg.Mode
		if mode == "" {
			mode = "default"
		}
		in["mode"] = mode
	}
	return in
}

func SnellLink(address string, port int, cfg SnellConfig, name string) string {
	ver := cfg.Version
	if ver != 5 && ver != 6 {
		ver = 5
	}
	urlVer := 4
	if ver == 6 {
		urlVer = 6
	}
	v := url.Values{}
	v.Set("version", strconv.Itoa(urlVer))
	if ver == 5 {
		mode := cfg.ObfsMode
		if mode == "" {
			mode = "http"
		}
		if mode == "http" {
			v.Set("obfs", "http")
			host := cfg.ObfsHost
			if host == "" {
				// normalize 创建时一定会填随机 Host，这里只是兜底——
				// 绝不回退到 bing.com（已退役的默认 Host）。
				host = RandomSnellObfsHost()
			}
			v.Set("obfs-host", host)
		}
	} else {
		mode := cfg.Mode
		if mode == "" {
			mode = "default"
		}
		v.Set("mode", mode)
	}
	return "snell://" + qesc(cfg.PSK) + "@" + hostPort(address, port) + "?" + v.Encode() + "#" + url.PathEscape(name)
}

// ShadowTLSLink：面板自定的 shadowtls:// 分享链接（非公开标准）。
// 密码放 userinfo（qesc 转义）、内层 SS 密码放查询串；version 省略即 3。
func ShadowTLSLink(address string, port int, cfg ShadowTLSConfig, name string) string {
	method := cfg.SSMethod
	if method == "" {
		method = "2022-blake3-aes-128-gcm"
	}
	handshake := cfg.Handshake
	if handshake == "" {
		handshake = "gateway.icloud.com"
	}
	v := url.Values{}
	v.Set("version", "3")
	v.Set("handshake", handshake)
	v.Set("ss-method", method)
	v.Set("ss-password", cfg.SSPassword)
	return "shadowtls://" + qesc(cfg.Password) + "@" + hostPort(address, port) + "?" + v.Encode() + "#" + url.PathEscape(name)
}

// ---------- ShadowTLS ----------

type ShadowTLSConfig struct {
	Version    int    `json:"version"`     // 3，固定
	Password   string `json:"password"`    // ShadowTLS 密码
	Handshake  string `json:"handshake"`   // 握手站域名，默认 gateway.icloud.com
	StrictMode bool   `json:"strict_mode"` // 固定 true
	SSMethod   string `json:"ss_method"`   // 内层 SS 方法
	SSPassword string `json:"ss_password"` // 内层 SS 密码
	InnerPort  int    `json:"inner_port"`  // 内层 SS 回环端口（创建时分配）
	Listen     string `json:"listen"`
}

func DefaultShadowTLS() ShadowTLSConfig {
	return ShadowTLSConfig{
		Version:    3,
		Password:   randHex(16),
		Handshake:  "gateway.icloud.com",
		StrictMode: true,
		SSMethod:   "2022-blake3-aes-128-gcm",
		SSPassword: SSKey("2022-blake3-aes-128-gcm"),
	}
}

func SingBoxShadowTLSInbound(tag string, port int, cfg ShadowTLSConfig) map[string]interface{} {
	handshake := cfg.Handshake
	if handshake == "" {
		handshake = "gateway.icloud.com"
	}
	return map[string]interface{}{
		"type":        "shadowtls",
		"tag":         tag,
		"listen":      sbListen(cfg.Listen, "::"),
		"listen_port": port,
		"version":     3,
		"users":       []interface{}{map[string]interface{}{"name": "user", "password": cfg.Password}},
		"handshake":   map[string]interface{}{"server": handshake, "server_port": 443},
		"strict_mode": true,
		"detour":      tag + "-ss",
	}
}

func SingBoxShadowTLSInnerSS(tag string, cfg ShadowTLSConfig) map[string]interface{} {
	method := cfg.SSMethod
	if method == "" {
		method = "2022-blake3-aes-128-gcm"
	}
	return map[string]interface{}{
		"type":        "shadowsocks",
		"tag":         tag,
		"listen":      "127.0.0.1",
		"listen_port": cfg.InnerPort,
		"method":      method,
		"password":    cfg.SSPassword,
	}
}

func ShadowTLSClientJSON(address string, port int, cfg ShadowTLSConfig, name string) string {
	method := cfg.SSMethod
	if method == "" {
		method = "2022-blake3-aes-128-gcm"
	}
	handshake := cfg.Handshake
	if handshake == "" {
		handshake = "gateway.icloud.com"
	}
	doc := map[string]interface{}{
		"outbounds": []interface{}{
			map[string]interface{}{
				"type":        "shadowsocks",
				"tag":         name,
				"server":      address,
				"server_port": port,
				"method":      method,
				"password":    cfg.SSPassword,
				"detour":      name + "-shadowtls §hide§",
			},
			map[string]interface{}{
				"type":        "shadowtls",
				"tag":         name + "-shadowtls §hide§",
				"server":      address,
				"server_port": port,
				"version":     3,
				"password":    cfg.Password,
				"tls":         map[string]interface{}{"enabled": true, "server_name": handshake},
			},
		},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}

// ---------- TLS / 传输小件 ----------

func sbListen(listen, def string) string {
	if listen != "" {
		return listen
	}
	return def
}

func realityTLS(serverName, privateKey, shortID, dest string) map[string]interface{} {
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		host, portStr = dest, "443"
	}
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}
	r := map[string]interface{}{
		"enabled": true,
		"handshake": map[string]interface{}{
			"server":      host,
			"server_port": port,
		},
		"private_key": privateKey,
	}
	if shortID != "" {
		r["short_id"] = []string{shortID}
	}
	tls := map[string]interface{}{"enabled": true, "reality": r}
	if serverName != "" {
		tls["server_name"] = serverName
	}
	return tls
}

func certTLS(serverName, certPath, keyPath string) map[string]interface{} {
	tls := map[string]interface{}{
		"enabled":          true,
		"certificate_path": certPath,
		"key_path":         keyPath,
	}
	if serverName != "" {
		tls["server_name"] = serverName
	}
	return tls
}

func wsTransport(path, host string) map[string]interface{} {
	t := map[string]interface{}{"type": "ws"}
	if path != "" {
		t["path"] = path
	}
	if host != "" {
		t["headers"] = map[string]interface{}{"Host": host}
	}
	return t
}

func httpTransport(host, path string) map[string]interface{} {
	t := map[string]interface{}{"type": "http"}
	if host != "" {
		t["host"] = []string{host}
	}
	if path != "" {
		t["path"] = path
	}
	return t
}

func httpUpgradeTransport(host, path string) map[string]interface{} {
	t := map[string]interface{}{"type": "httpupgrade"}
	if host != "" {
		t["host"] = host
	}
	if path != "" {
		t["path"] = path
	}
	return t
}

// ---------- VLESS ----------

func SingBoxVLESSInbound(tag string, port int, sni string, cfg VLESSConfig) map[string]interface{} {
	mode := cfg.Mode
	if mode == "" {
		mode = "reality"
	}
	in := map[string]interface{}{
		"type":        "vless",
		"tag":         tag,
		"listen":      sbListen(cfg.Listen, "::"),
		"listen_port": port,
	}
	switch mode {
	case "reality":
		dest := cfg.Dest
		if dest == "" {
			dest = sni + ":443"
		}
		user := map[string]interface{}{"uuid": cfg.UUID}
		if cfg.Flow != "" {
			user["flow"] = cfg.Flow
		}
		in["users"] = []interface{}{user}
		in["tls"] = realityTLS(sni, cfg.PrivateKey, cfg.ShortID, dest)
	default:
		domain := cfg.Domain
		if domain == "" {
			domain = sni
		}
		in["users"] = []interface{}{map[string]interface{}{"uuid": cfg.UUID}}
		in["tls"] = certTLS(domain, cfg.CertFile, cfg.KeyFile)
		switch mode {
		case "ws":
			in["transport"] = wsTransport(cfg.Path, domain)
		case "h2":
			in["transport"] = httpTransport(domain, cfg.Path)
		case "httpupgrade":
			in["transport"] = httpUpgradeTransport(domain, cfg.Path)
		}
	}
	return in
}

// ---------- VMess ----------

func SingBoxVMessInbound(tag string, port int, cfg VMessConfig) map[string]interface{} {
	mode := cfg.Mode
	if mode == "" {
		mode = "tcp"
	}
	in := map[string]interface{}{
		"type":        "vmess",
		"tag":         tag,
		"listen":      sbListen(cfg.Listen, "::"),
		"listen_port": port,
		"users":       []interface{}{map[string]interface{}{"uuid": cfg.UUID, "alterId": 0}},
	}
	switch mode {
	case "tcp":
	case "cf":
		in["tls"] = certTLS(cfg.Domain, cfg.CertFile, cfg.KeyFile)
		in["transport"] = wsTransport(cfg.Path, cfg.Domain)
	case "http":
		in["transport"] = httpTransport(cfg.Domain, cfg.Path)
	case "quic":
		in["tls"] = certTLS(cfg.Domain, cfg.CertFile, cfg.KeyFile)
		in["transport"] = map[string]interface{}{"type": "quic"}
	case "h2":
		in["tls"] = certTLS(cfg.Domain, cfg.CertFile, cfg.KeyFile)
		in["transport"] = httpTransport(cfg.Domain, cfg.Path)
	case "httpupgrade":
		in["tls"] = certTLS(cfg.Domain, cfg.CertFile, cfg.KeyFile)
		in["transport"] = httpUpgradeTransport(cfg.Domain, cfg.Path)
	}
	return in
}

// ---------- Trojan ----------

func SingBoxTrojanInbound(tag string, port int, sni string, cfg TrojanConfig) map[string]interface{} {
	mode := cfg.Mode
	if mode == "" {
		mode = "reality"
	}
	in := map[string]interface{}{
		"type":        "trojan",
		"tag":         tag,
		"listen":      sbListen(cfg.Listen, "::"),
		"listen_port": port,
		"users":       []interface{}{map[string]interface{}{"password": cfg.Password}},
	}
	switch mode {
	case "reality":
		dest := cfg.Dest
		if dest == "" {
			dest = sni + ":443"
		}
		in["tls"] = realityTLS(sni, cfg.PrivateKey, cfg.ShortID, dest)
	case "cf":
		domain := cfg.Domain
		if domain == "" {
			domain = sni
		}
		in["tls"] = certTLS(domain, cfg.CertFile, cfg.KeyFile)
		in["transport"] = wsTransport(cfg.Path, domain)
	case "h2":
		domain := cfg.Domain
		if domain == "" {
			domain = sni
		}
		in["tls"] = certTLS(domain, cfg.CertFile, cfg.KeyFile)
		in["transport"] = httpTransport(domain, cfg.Path)
	case "httpupgrade":
		domain := cfg.Domain
		if domain == "" {
			domain = sni
		}
		in["tls"] = certTLS(domain, cfg.CertFile, cfg.KeyFile)
		in["transport"] = httpUpgradeTransport(domain, cfg.Path)
	}
	return in
}

// ---------- Shadowsocks / SOCKS / HTTP ----------

func SingBoxSSInbound(tag string, port int, cfg SSConfig) map[string]interface{} {
	return map[string]interface{}{
		"type":        "shadowsocks",
		"tag":         tag,
		"listen":      sbListen(cfg.Listen, "::"),
		"listen_port": port,
		"method":      cfg.Method,
		"password":    cfg.Password,
	}
}

func sbUserPassInbound(typ, tag string, port int, listen, user, pass string) map[string]interface{} {
	in := map[string]interface{}{
		"type":        typ,
		"tag":         tag,
		"listen":      sbListen(listen, "::"),
		"listen_port": port,
	}
	if user != "" || pass != "" {
		in["users"] = []interface{}{map[string]interface{}{"username": user, "password": pass}}
	}
	return in
}

func SingBoxSocksInbound(tag string, port int, cfg SocksConfig) map[string]interface{} {
	return sbUserPassInbound("socks", tag, port, cfg.Listen, cfg.User, cfg.Pass)
}

func SingBoxHTTPInbound(tag string, port int, cfg HTTPConfig) map[string]interface{} {
	return sbUserPassInbound("http", tag, port, cfg.Listen, cfg.User, cfg.Pass)
}

// ---------- Hysteria2 / TUIC / AnyTLS / Naive ----------

func SingBoxHy2Inbound(tag string, port int, sni, certPath, keyPath string, cfg Hy2Config) map[string]interface{} {
	in := map[string]interface{}{
		"type":        "hysteria2",
		"tag":         tag,
		"listen":      sbListen(cfg.Listen, "::"),
		"listen_port": port,
		"users":       []interface{}{map[string]interface{}{"password": cfg.Password}},
		"tls":         certTLS(sni, certPath, keyPath),
	}
	in["tls"].(map[string]interface{})["alpn"] = []string{"h3"}
	if cfg.ObfsType != "" {
		in["obfs"] = map[string]interface{}{"type": cfg.ObfsType, "password": cfg.ObfsPassword}
	}
	if v, err := strconv.Atoi(cfg.UpMbps); err == nil && v > 0 {
		in["up_mbps"] = v
	}
	if v, err := strconv.Atoi(cfg.DownMbps); err == nil && v > 0 {
		in["down_mbps"] = v
	}
	if cfg.IgnoreClient {
		in["ignore_client_bandwidth"] = true
	}
	return in
}

func SingBoxTUICInbound(tag string, port int, sni, certPath, keyPath string, cfg TUICConfig) map[string]interface{} {
	in := map[string]interface{}{
		"type":               "tuic",
		"tag":                tag,
		"listen":             sbListen(cfg.Listen, "::"),
		"listen_port":        port,
		"users":              []interface{}{map[string]interface{}{"uuid": cfg.UUID, "password": cfg.Password}},
		"congestion_control": "bbr",
		"zero_rtt_handshake": false,
		"tls":                certTLS(sni, certPath, keyPath),
	}
	in["tls"].(map[string]interface{})["alpn"] = []string{"h3"}
	return in
}

func SingBoxAnyTLSInbound(tag string, port int, sni, certPath, keyPath string, cfg AnyTLSConfig) map[string]interface{} {
	return map[string]interface{}{
		"type":        "anytls",
		"tag":         tag,
		"listen":      sbListen(cfg.Listen, "::"),
		"listen_port": port,
		"users":       []interface{}{map[string]interface{}{"name": cfg.Name, "password": cfg.Password}},
		"tls":         certTLS(sni, certPath, keyPath),
	}
}

func SingBoxNaiveInbound(tag string, port int, cfg NaiveConfig, certPath, keyPath string) map[string]interface{} {
	return map[string]interface{}{
		"type":        "naive",
		"tag":         tag,
		"listen":      sbListen(cfg.Listen, "::"),
		"listen_port": port,
		"network":     "tcp",
		"users":       []interface{}{map[string]interface{}{"username": cfg.Username, "password": cfg.Password}},
		"tls":         certTLS(cfg.Domain, certPath, keyPath),
	}
}

// ---------- WireGuard 端点 ----------

func SingBoxWGEndpoint(tag string, port int, cfg WGConfig) map[string]interface{} {
	ep := map[string]interface{}{
		"type":        "wireguard",
		"tag":         tag,
		"system":      false,
		"mtu":         1280,
		"address":     []string{"10.0.0.1/32"},
		"private_key": cfg.ServerPriv,
		"listen_port": port,
		"peers": []interface{}{map[string]interface{}{
			"public_key":  cfg.ClientPub,
			"allowed_ips": []string{cfg.ClientIP},
		}},
	}
	if cfg.Listen != "" {
		ep["listen"] = cfg.Listen
	}
	return ep
}

// ---------- B 节点出站转换 ----------

func sbStr(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func sbMap(m map[string]interface{}, key string) map[string]interface{} {
	if m == nil {
		return nil
	}
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}

func sbList(m map[string]interface{}, key string) []interface{} {
	if m == nil {
		return nil
	}
	if v, ok := m[key].([]interface{}); ok {
		return v
	}
	return nil
}

func sbInt(v interface{}) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}

func xrayTLSOutbound(ss map[string]interface{}) (map[string]interface{}, error) {
	sec := sbStr(ss, "security")
	switch sec {
	case "reality":
		rs := sbMap(ss, "realitySettings")
		tls := map[string]interface{}{
			"enabled": true,
			"reality": map[string]interface{}{
				"enabled":    true,
				"public_key": sbStr(rs, "publicKey"),
			},
		}
		if sn := sbStr(rs, "serverName"); sn != "" {
			tls["server_name"] = sn
		}
		if sid := sbStr(rs, "shortId"); sid != "" {
			tls["reality"].(map[string]interface{})["short_id"] = sid
		}
		fp := sbStr(rs, "fingerprint")
		if fp == "" {
			fp = "chrome"
		}
		tls["utls"] = map[string]interface{}{"enabled": true, "fingerprint": fp}
		return tls, nil
	case "tls":
		ts := sbMap(ss, "tlsSettings")
		tls := map[string]interface{}{"enabled": true}
		if sn := sbStr(ts, "serverName"); sn != "" {
			tls["server_name"] = sn
		}
		if b, ok := ts["allowInsecure"].(bool); ok && b {
			tls["insecure"] = true
		}
		if fp := sbStr(ts, "fingerprint"); fp != "" {
			tls["utls"] = map[string]interface{}{"enabled": true, "fingerprint": fp}
		}
		if alpn, ok := ts["alpn"].([]interface{}); ok && len(alpn) > 0 {
			tls["alpn"] = alpn
		}
		return tls, nil
	case "none", "":
		return nil, nil
	default:
		return nil, fmt.Errorf("不支持的安全层：%s", sec)
	}
}

func xrayTransportOutbound(ss map[string]interface{}) (map[string]interface{}, error) {
	netw := sbStr(ss, "network")
	switch netw {
	case "tcp":
		ts := sbMap(ss, "tcpSettings")
		header := sbMap(ts, "header")
		if sbStr(header, "type") == "http" {
			req := sbMap(header, "request")
			var host, path string
			if hm, ok := req["headers"].(map[string]interface{}); ok {
				if h, ok := hm["Host"].([]interface{}); ok && len(h) > 0 {
					host, _ = h[0].(string)
				}
			}
			if ps, ok := req["path"].([]interface{}); ok && len(ps) > 0 {
				path, _ = ps[0].(string)
			}
			return httpTransport(host, path), nil
		}
		return nil, nil
	case "ws":
		ws := sbMap(ss, "wsSettings")
		var host string
		if hm, ok := ws["headers"].(map[string]interface{}); ok {
			switch h := hm["Host"].(type) {
			case string:
				host = h
			case []interface{}:
				if len(h) > 0 {
					host, _ = h[0].(string)
				}
			case []string:
				if len(h) > 0 {
					host = h[0]
				}
			}
		}
		return wsTransport(sbStr(ws, "path"), host), nil
	case "grpc":
		gs := sbMap(ss, "grpcSettings")
		return map[string]interface{}{"type": "grpc", "service_name": sbStr(gs, "serviceName")}, nil
	case "h2":
		hs := sbMap(ss, "httpSettings")
		var host string
		if h, ok := hs["host"].([]interface{}); ok && len(h) > 0 {
			host, _ = h[0].(string)
		} else if h, ok := hs["host"].([]string); ok && len(h) > 0 {
			host = h[0]
		}
		return httpTransport(host, sbStr(hs, "path")), nil
	case "httpupgrade":
		hus := sbMap(ss, "httpupgradeSettings")
		return httpUpgradeTransport(sbStr(hus, "host"), sbStr(hus, "path")), nil
	case "quic":
		return map[string]interface{}{"type": "quic"}, nil
	case "":
		return nil, nil
	default:
		return nil, fmt.Errorf("不支持的传输：%s", netw)
	}
}

func checkBServer(ob map[string]interface{}) error {
	if sbStr(ob, "server") == "" {
		return fmt.Errorf("B 节点出站地址为空")
	}
	if p := sbInt(ob["server_port"]); p < 1 || p > 65535 {
		return fmt.Errorf("B 节点出站端口 %d 非法", p)
	}
	return nil
}

// SingBoxBOutbound：把 B 节点的存储配置转成 sing-box 出站。
// 一般协议返回 1 个出站；ShadowTLS 返回 2 个（SS 出站在前、其 detour 指向
// shadowtls 出站在后），调用方必须把两个都追加进 outbounds，路由指向第一个的 tag。
func SingBoxBOutbound(protocol, configJSON, tag string) ([]map[string]interface{}, error) {
	switch protocol {
	case "hy2":
		protocol = "hysteria2"
	case "ss":
		protocol = "shadowsocks"
	}
	var stored map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &stored); err != nil {
		return nil, fmt.Errorf("B 节点配置解析失败：%w", err)
	}
	if protocol == "hysteria2" {
		stored["tag"] = tag
		if err := checkBServer(stored); err != nil {
			return nil, err
		}
		return []map[string]interface{}{stored}, nil
	}
	ss := sbMap(stored, "streamSettings")
	settings := sbMap(stored, "settings")
	switch protocol {
	case "vless", "vmess":
		vnext := sbList(settings, "vnext")
		if len(vnext) == 0 {
			return nil, fmt.Errorf("%s B 节点缺少 vnext", protocol)
		}
		node, _ := vnext[0].(map[string]interface{})
		users := sbList(node, "users")
		if len(users) == 0 {
			return nil, fmt.Errorf("%s B 节点缺少用户", protocol)
		}
		user, _ := users[0].(map[string]interface{})
		tls, err := xrayTLSOutbound(ss)
		if err != nil {
			return nil, err
		}
		tr, err := xrayTransportOutbound(ss)
		if err != nil {
			return nil, err
		}
		ob := map[string]interface{}{
			"type":        protocol,
			"tag":         tag,
			"server":      sbStr(node, "address"),
			"server_port": sbInt(node["port"]),
		}
		if protocol == "vless" {
			ob["uuid"] = sbStr(user, "id")
			if tr == nil {
				if f := sbStr(user, "flow"); f != "" {
					ob["flow"] = f
				}
			}
		} else {
			ob["uuid"] = sbStr(user, "id")
			if aid := sbInt(user["alterId"]); aid != 0 {
				return nil, fmt.Errorf("vmess B 节点 alterId=%d 非 0，sing-box 只支持 AEAD（alterId=0）", aid)
			}
			if s := sbStr(user, "security"); s != "" {
				ob["security"] = s
			}
		}
		if tls != nil {
			ob["tls"] = tls
		}
		if tr != nil {
			ob["transport"] = tr
		}
		if err := checkBServer(ob); err != nil {
			return nil, err
		}
		return []map[string]interface{}{ob}, nil
	case "trojan":
		servers := sbList(settings, "servers")
		if len(servers) == 0 {
			return nil, fmt.Errorf("trojan B 节点缺少服务器")
		}
		srv, _ := servers[0].(map[string]interface{})
		tls, err := xrayTLSOutbound(ss)
		if err != nil {
			return nil, err
		}
		tr, err := xrayTransportOutbound(ss)
		if err != nil {
			return nil, err
		}
		ob := map[string]interface{}{
			"type":        "trojan",
			"tag":         tag,
			"server":      sbStr(srv, "address"),
			"server_port": sbInt(srv["port"]),
			"password":    sbStr(srv, "password"),
		}
		if tls != nil {
			ob["tls"] = tls
		}
		if tr != nil {
			ob["transport"] = tr
		}
		if err := checkBServer(ob); err != nil {
			return nil, err
		}
		return []map[string]interface{}{ob}, nil
	case "shadowsocks":
		servers := sbList(settings, "servers")
		if len(servers) == 0 {
			return nil, fmt.Errorf("ss B 节点缺少服务器")
		}
		srv, _ := servers[0].(map[string]interface{})
		ob := map[string]interface{}{
			"type":        "shadowsocks",
			"tag":         tag,
			"server":      sbStr(srv, "address"),
			"server_port": sbInt(srv["port"]),
			"method":      sbStr(srv, "method"),
			"password":    sbStr(srv, "password"),
		}
		if err := checkBServer(ob); err != nil {
			return nil, err
		}
		return []map[string]interface{}{ob}, nil
	case "snell":
		ver := sbInt(stored["version"])
		if ver == 4 {
			ver = 5 // 个别外链直接写线路版 4，等同面板 v5
		}
		if ver != 5 && ver != 6 {
			ver = 5
		}
		if sbStr(stored, "psk") == "" {
			return nil, fmt.Errorf("snell B 节点缺少密钥")
		}
		// 线路版本号：面板 v5 对应 sing-box 出站 version 4（客户端按 v4 拨号），
		// 面板 v6 对应 version 6；sing-box 出站不认 version 5，也不认 obfs 字段。
		wireVer := 4
		if ver == 6 {
			wireVer = 6
		}
		ob := map[string]interface{}{
			"type":        "snell",
			"tag":         tag,
			"server":      sbStr(stored, "server"),
			"server_port": sbInt(stored["server_port"]),
			"version":     wireVer,
			"psk":         sbStr(stored, "psk"),
		}
		if ver == 5 {
			// v5 HTTP 混淆走 obfs_mode/obfs_host（与入站同名字段）。
			mode := sbStr(stored, "obfs_mode")
			host := sbStr(stored, "obfs_host")
			if mode == "" {
				// 兼容旧存法：obfs 对象 {type:http, host}
				if rawObfs, ok := stored["obfs"]; ok {
					if m, ok := rawObfs.(map[string]interface{}); ok && sbStr(m, "type") == "http" {
						mode = "http"
						host = sbStr(m, "host")
					}
				}
			}
			if mode == "http" {
				if host == "" {
					host = "bing.com"
				}
				ob["obfs_mode"] = "http"
				ob["obfs_host"] = host
			}
		} else if m := sbStr(stored, "mode"); m != "" {
			ob["mode"] = m
		}
		if err := checkBServer(ob); err != nil {
			return nil, err
		}
		return []map[string]interface{}{ob}, nil
	case "shadowtls":
		// ShadowTLS 是两段式：SS 出站 detour 到 shadowtls 出站。
		// 两个出站的 server/port 相同；路由指向 SS 出站（tag），detour 指向 tag+"-shadowtls"。
		ver := sbInt(stored["version"])
		if ver == 0 {
			ver = 3
		}
		if ver != 3 {
			return nil, fmt.Errorf("shadowtls B 节点不支持的版本 %d（仅支持 v3）", ver)
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
		ss := map[string]interface{}{
			"type":        "shadowsocks",
			"tag":         tag,
			"server":      sbStr(stored, "server"),
			"server_port": sbInt(stored["server_port"]),
			"method":      method,
			"password":    sbStr(stored, "ss_password"),
			"detour":      tag + "-shadowtls",
		}
		st := map[string]interface{}{
			"type":        "shadowtls",
			"tag":         tag + "-shadowtls",
			"server":      sbStr(stored, "server"),
			"server_port": sbInt(stored["server_port"]),
			"version":     3,
			"password":    sbStr(stored, "password"),
			"tls":         map[string]interface{}{"enabled": true, "server_name": handshake},
		}
		if err := checkBServer(ss); err != nil {
			return nil, err
		}
		if err := checkBServer(st); err != nil {
			return nil, err
		}
		return []map[string]interface{}{ss, st}, nil
	case "socks", "http":
		servers := sbList(settings, "servers")
		if len(servers) == 0 {
			return nil, fmt.Errorf("%s B 节点缺少服务器", protocol)
		}
		srv, _ := servers[0].(map[string]interface{})
		ob := map[string]interface{}{
			"type":        protocol,
			"tag":         tag,
			"server":      sbStr(srv, "address"),
			"server_port": sbInt(srv["port"]),
		}
		if users := sbList(srv, "users"); len(users) > 0 {
			if u, ok := users[0].(map[string]interface{}); ok {
				ob["username"] = sbStr(u, "user")
				ob["password"] = sbStr(u, "pass")
			}
		}
		if tls, ok := stored["tls"]; ok {
			ob["tls"] = tls
		}
		if err := checkBServer(ob); err != nil {
			return nil, err
		}
		return []map[string]interface{}{ob}, nil
	default:
		return nil, fmt.Errorf("不支持的 B 节点协议：%s", protocol)
	}
}

// ---------- 链式与多节点分流路由 ----------

// CanBeChainA 判断本地入站协议能否作为链式入口 A。
// WireGuard 在 sing-box 中是 endpoint 而非 inbound，不走入站嗅探路由，其余 12 种入站协议全部支持。
func CanBeChainA(protocol string) bool {
	switch protocol {
	case "vless", "vmess", "trojan", "hy2", "tuic", "anytls", "naive", "snell", "ss", "socks", "http", "shadowtls":
		return true
	}
	return false
}

// ChainInboundTag 返回链式入口在 sing-box 路由表里绑定的入站 tag。
// ShadowTLS 外层入站只拆 TLS 握手并 detour 到内层 SS 入站（in-<id>-ss），
// 真正进入路由器的流量来自 in-<id>-ss，其余协议直接绑 in-<id>。
func ChainInboundTag(id, protocol string) string {
	if protocol == "shadowtls" {
		return "in-" + id + "-ss"
	}
	return "in-" + id
}

// ChainRouteInput：单组“清单 -> B 出站”输入。
type ChainRouteInput struct {
	OutboundTag string
	List        string
}

// ChainRouteSpec：校验层接收的分流组原始输入。
type ChainRouteSpec struct {
	BNodeID string
	List    string
}

// ChainInput：一条入口 A 的链式路由输入（兼容旧单路字段与新多路 Routes）。
type ChainInput struct {
	InboundTag  string            // in-<A 节点 id> 或 in-<A>-ss
	OutboundTag string            // Direct 模式的出站；多路 Routes 非空时若非空则作为该 A 节点的未命中兜底出站；Routes 为空时兼容老单路出站
	List        string            // 兼容老单路分流清单（Routes 为空时使用）
	Routes      []ChainRouteInput // 多路分流组（按顺序评估，已做无重叠校验）
	Direct      bool              // 全局直通：A 的全部流量都走 OutboundTag
}

// ValidateAndNormalizeRoutes 严格校验多路分流组：
// 1. 同一条链内禁止重复选择同一个 B 节点（提示直接合并清单）；
// 2. 组内自动去重，跨组严格拦截重复域名及父子包含域名（如 google.com 与 mail.google.com）；
// 3. 跨组严格拦截重叠的 IP / CIDR 网段（如 1.1.1.0/24 与 1.1.1.1）。
func ValidateAndNormalizeRoutes(routes []ChainRouteSpec) ([]string, error) {
	if len(routes) == 0 {
		return nil, fmt.Errorf("至少需要添加 1 个分流落地组")
	}
	if len(routes) > 50 {
		return nil, fmt.Errorf("分流组最多不超过 50 个")
	}
	seenB := map[string]int{}
	type domainClaim struct {
		group  int
		domain string
	}
	type prefixClaim struct {
		group int
		raw   string
		pfx   netip.Prefix
	}
	var allDomains []domainClaim
	var allPrefixes []prefixClaim
	normalized := make([]string, len(routes))

	for i, r := range routes {
		gNum := i + 1
		if r.BNodeID == "" {
			return nil, fmt.Errorf("第 %d 组未选择落地 B 节点", gNum)
		}
		if prev, ok := seenB[r.BNodeID]; ok {
			return nil, fmt.Errorf("第 %d 组与第 %d 组选择了同一个 B 节点，请将清单合并到同一组", gNum, prev)
		}
		seenB[r.BNodeID] = gNum

		suffixes, cidrs, err := ParseChainList(r.List)
		if err != nil {
			return nil, fmt.Errorf("第 %d 组：%w", gNum, err)
		}

		cleanDomains := make([]string, 0, len(suffixes))
		seenDomInGroup := map[string]bool{}
		for _, d := range suffixes {
			dl := strings.ToLower(d)
			if seenDomInGroup[dl] {
				continue
			}
			seenDomInGroup[dl] = true
			for _, prev := range allDomains {
				if dl == prev.domain || strings.HasSuffix(dl, "."+prev.domain) || strings.HasSuffix(prev.domain, "."+dl) {
					return nil, fmt.Errorf("分流冲突：第 %d 组的域名 %q 与第 %d 组的 %q 重复或存在子域名包含关系", gNum, d, prev.group, prev.domain)
				}
			}
			allDomains = append(allDomains, domainClaim{group: gNum, domain: dl})
			cleanDomains = append(cleanDomains, dl)
		}

		cleanCIDRs := make([]string, 0, len(cidrs))
		seenPfxInGroup := map[netip.Prefix]bool{}
		for _, c := range cidrs {
			var pfx netip.Prefix
			if strings.Contains(c, "/") {
				p, err := netip.ParsePrefix(c)
				if err != nil {
					return nil, fmt.Errorf("第 %d 组的网段 %q 格式无效", gNum, c)
				}
				pfx = p.Masked()
			} else {
				addr, err := netip.ParseAddr(c)
				if err != nil {
					return nil, fmt.Errorf("第 %d 组的 IP %q 格式无效", gNum, c)
				}
				pfx = netip.PrefixFrom(addr, addr.BitLen())
			}
			if seenPfxInGroup[pfx] {
				continue
			}
			seenPfxInGroup[pfx] = true
			for _, prev := range allPrefixes {
				if pfx.Overlaps(prev.pfx) {
					return nil, fmt.Errorf("分流冲突：第 %d 组的 IP/网段 %q 与第 %d 组的 %q 存在重叠", gNum, c, prev.group, prev.raw)
				}
			}
			allPrefixes = append(allPrefixes, prefixClaim{group: gNum, raw: c, pfx: pfx})
			cleanCIDRs = append(cleanCIDRs, c)
		}

		normalized[i] = strings.Join(append(cleanDomains, cleanCIDRs...), "\n")
	}
	return normalized, nil
}

// SingBoxChainRules 生成链式嗅探与分流路由规则。
func SingBoxChainRules(chains []ChainInput) []map[string]interface{} {
	if len(chains) == 0 {
		return nil
	}
	var aTags []interface{}
	seenIn := map[string]bool{}
	for _, ch := range chains {
		if !seenIn[ch.InboundTag] {
			seenIn[ch.InboundTag] = true
			aTags = append(aTags, ch.InboundTag)
		}
	}
	rules := []map[string]interface{}{
		{"inbound": aTags, "action": "sniff"},
	}
	for _, ch := range chains {
		if ch.Direct {
			if ch.OutboundTag != "" {
				rules = append(rules, map[string]interface{}{
					"inbound":  []string{ch.InboundTag},
					"action":   "route",
					"outbound": ch.OutboundTag,
				})
			}
			continue
		}
		if len(ch.Routes) > 0 {
			for _, rt := range ch.Routes {
				if rt.OutboundTag == "" {
					continue
				}
				suffixes, cidrs := splitDomainList(rt.List)
				if len(suffixes) > 0 {
					rules = append(rules, map[string]interface{}{
						"inbound":       []string{ch.InboundTag},
						"action":        "route",
						"outbound":      rt.OutboundTag,
						"domain_suffix": suffixes,
					})
				}
				if len(cidrs) > 0 {
					rules = append(rules, map[string]interface{}{
						"inbound":  []string{ch.InboundTag},
						"action":   "route",
						"outbound": rt.OutboundTag,
						"ip_cidr":  cidrs,
					})
				}
			}
			// 多路分流下若额外指定了未命中兜底 B 节点（OutboundTag 非空），追加在该入站规则末尾
			if ch.OutboundTag != "" {
				rules = append(rules, map[string]interface{}{
					"inbound":  []string{ch.InboundTag},
					"action":   "route",
					"outbound": ch.OutboundTag,
				})
			}
			continue
		}
		// 兼容旧版单路调用（Routes 为空时按 List + OutboundTag 生成，不产生兜底 catch-all）
		suffixes, cidrs := splitDomainList(ch.List)
		if len(suffixes) > 0 {
			rules = append(rules, map[string]interface{}{
				"inbound":       []string{ch.InboundTag},
				"action":        "route",
				"outbound":      ch.OutboundTag,
				"domain_suffix": suffixes,
			})
		}
		if len(cidrs) > 0 {
			rules = append(rules, map[string]interface{}{
				"inbound":  []string{ch.InboundTag},
				"action":   "route",
				"outbound": ch.OutboundTag,
				"ip_cidr":  cidrs,
			})
		}
	}
	return rules
}

// ParseChainList 解析链式清单：按行切分，去空行/# 注释、去 scheme、
// 路径、端口、前导 *. 与前导点，校验每行是合法域名或 IP/CIDR。
func ParseChainList(listText string) (suffixes, cidrs []string, err error) {
	if len(listText) > 256*1024 {
		return nil, nil, fmt.Errorf("链式清单超过 256KB 上限")
	}
	lines := strings.Split(listText, "\n")
	if len(lines) > 5000 {
		return nil, nil, fmt.Errorf("链式清单超过 5000 行上限")
	}
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "://"); idx >= 0 {
			line = line[idx+3:]
		}
		if isIPOrCIDR(line) {
			cidrs = append(cidrs, line)
			continue
		}
		if idx := strings.IndexAny(line, "/?"); idx >= 0 {
			line = line[:idx]
		}
		if strings.HasPrefix(line, "[") {
			if idx := strings.Index(line, "]"); idx >= 0 {
				rest := line[idx+1:]
				if rest != "" && !strings.HasPrefix(rest, ":") {
					return nil, nil, fmt.Errorf("第 %d 行 %q 格式不对", i+1, raw)
				}
				line = line[1:idx]
			}
		} else if h, _, splitErr := net.SplitHostPort(line); splitErr == nil {
			line = h
		}
		line = strings.TrimPrefix(line, "*.")
		line = strings.TrimPrefix(line, ".")
		if line == "" {
			return nil, nil, fmt.Errorf("第 %d 行 %q 清理后为空", i+1, raw)
		}
		if isIPOrCIDR(line) {
			cidrs = append(cidrs, line)
			continue
		}
		if !validChainDomain(line) {
			return nil, nil, fmt.Errorf("第 %d 行 %q 不是合法域名", i+1, raw)
		}
		suffixes = append(suffixes, line)
	}
	if len(suffixes) == 0 && len(cidrs) == 0 {
		return nil, nil, fmt.Errorf("链式清单解析后为空（只有空行或注释），不会生成分流规则")
	}
	return suffixes, cidrs, nil
}

func validChainDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func splitDomainList(listText string) (suffixes, cidrs []string) {
	suffixes, cidrs, _ = ParseChainList(listText)
	return suffixes, cidrs
}

// ---------- 全量配置 ----------

func SingBoxFullConfig(inbounds []interface{}, endpoints []interface{}, outbounds []interface{}, rules []map[string]interface{}) map[string]interface{} {
	outs := []interface{}{map[string]interface{}{"type": "direct", "tag": "direct"}}
	outs = append(outs, outbounds...)
	ruleList := []interface{}{}
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	if inbounds == nil {
		inbounds = []interface{}{}
	}
	cfg := map[string]interface{}{
		"log":       map[string]interface{}{"level": "warn"},
		"inbounds":  inbounds,
		"outbounds": outs,
		"route": map[string]interface{}{
			"rules": ruleList,
			"final": "direct",
		},
	}
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}
	return cfg
}

// ---------- 新协议客户端链接 ----------

func TUICLink(address string, port int, sni string, cfg TUICConfig, name string) string {
	v := url.Values{}
	v.Set("security", "tls")
	v.Set("congestion_control", "bbr")
	v.Set("udp_relay_mode", "native")
	v.Set("alpn", "h3")
	if sni != "" {
		v.Set("sni", sni)
	}
	v.Set("allow_insecure", "1")
	u := &url.URL{
		Scheme:   "tuic",
		User:     url.UserPassword(cfg.UUID, cfg.Password),
		Host:     hostPort(address, port),
		RawQuery: v.Encode(),
		Fragment: name,
	}
	return u.String()
}

func AnyTLSLink(address string, port int, sni string, cfg AnyTLSConfig, name string) string {
	v := url.Values{}
	v.Set("security", "tls")
	if sni != "" {
		v.Set("sni", sni)
	}
	v.Set("insecure", "1")
	u := &url.URL{
		Scheme:   "anytls",
		User:     url.UserPassword("", cfg.Password),
		Host:     hostPort(address, port),
		RawQuery: v.Encode(),
		Fragment: name,
	}
	s := u.String()
	return strings.Replace(s, "anytls://:", "anytls://", 1)
}

func NaiveLink(cfg NaiveConfig, port int) string {
	proxyURL := &url.URL{
		Scheme: "https",
		User:   url.UserPassword(cfg.Username, cfg.Password),
		Host:   hostPort(cfg.Domain, port),
	}
	doc := map[string]interface{}{
		"listen": "socks://127.0.0.1:1080",
		"proxy":  proxyURL.String(),
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}
