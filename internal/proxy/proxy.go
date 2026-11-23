package proxy

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ---------- small helpers ----------

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func qesc(s string) string { return url.QueryEscape(s) }

// ---------- VLESS config ----------

type VLESSConfig struct {
	UUID        string `json:"uuid"`
	Flow        string `json:"flow"`        // xtls-rprx-vision or ""
	Fingerprint string `json:"fingerprint"` // chrome (client link)
	SpiderX     string `json:"spider_x"`    // client link, default "/"
	Dest        string `json:"dest"`        // SNI:443
	ShortID     string `json:"short_id"`
	PrivateKey  string `json:"private_key"`
	PublicKey   string `json:"public_key"`
	Listen      string `json:"listen"` // default 0.0.0.0
	// sing-box 档位：""=reality（老记录默认）| "ws" | "h2" | "httpupgrade"；
	// TLS 档用 Domain/Path/CertFile/KeyFile（Apply 层在生成前补齐证书）。
	Mode     string `json:"mode"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

func DefaultVLESS() VLESSConfig {
	return VLESSConfig{
		UUID:        newUUID(),
		Flow:        "xtls-rprx-vision",
		Fingerprint: "chrome",
		SpiderX:     "/",
		ShortID:     randHex(4),
	}
}

func isIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// hostPort：把 host 与端口拼成 URL host:port。IPv6 地址自动加方括号；
// 调用方已经带方括号的先剥掉再拼，避免双方括号。所有链接生成器都要
// 走这里，不要手写 %s:%d——裸 IPv6 + 端口会让客户端无法区分地址与端口。
func hostPort(host string, port int) string {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func VLESSLink(uuid, address string, port int, sni string, cfg VLESSConfig, name string) string {
	mode := cfg.Mode
	if mode == "" {
		mode = "reality"
	}
	if mode != "reality" {
		// WS/H2/HTTPUpgrade-TLS 档：直连域名 + 证书 TLS，自签证书所以客户端要 allowInsecure；
		// 没有 flow/pbk/sid（那是 Reality 才有的），host 固定是域名。
		// 域名与 SNI 都空时（默认留空）回退到服务器地址，否则下发死链。
		domain := cfg.Domain
		if domain == "" {
			domain = sni
		}
		if domain == "" {
			domain = address
		}
		v := url.Values{}
		v.Set("encryption", "none")
		v.Set("security", "tls")
		v.Set("sni", domain)
		v.Set("type", mode)
		if cfg.Path != "" {
			v.Set("path", cfg.Path)
		}
		v.Set("host", domain)
		v.Set("allowInsecure", "1")
		return fmt.Sprintf("vless://%s@%s?%s#%s", uuid, hostPort(domain, port), v.Encode(), url.PathEscape(name))
	}
	v := url.Values{}
	v.Set("encryption", "none")
	if cfg.Flow != "" {
		v.Set("flow", cfg.Flow)
	}
	v.Set("security", "reality")
	v.Set("sni", sni)
	if cfg.Fingerprint != "" {
		v.Set("fp", cfg.Fingerprint)
	}
	v.Set("pbk", cfg.PublicKey)
	if cfg.ShortID != "" {
		v.Set("sid", cfg.ShortID)
	}
	v.Set("type", "tcp")
	if cfg.SpiderX != "" && cfg.SpiderX != "/" {
		v.Set("spiderX", cfg.SpiderX)
	}
	return fmt.Sprintf("vless://%s@%s?%s#%s", uuid, hostPort(address, port), v.Encode(), url.PathEscape(name))
}

// ---------- B-node link parsing ----------

// ParsedB is a parsed outbound node (for chaining).
type ParsedB struct {
	Protocol string                 `json:"protocol"` // vless|vmess|trojan|shadowsocks|socks|http|hysteria2
	Name     string                 `json:"name"`
	Outbound map[string]interface{} `json:"outbound"` // xray outbound object (without tag); for hy2: sing-box outbound
	Tag      string                 `json:"tag"`
}

// DecodeFragment：把链接 #fragment 还原成显示名。SS 解析是手切字符串，
// fragment 还是百分号编码原样；其他协议走 url.Parse，Fragment 已解码。
// 解码失败（如名字里有字面 %）就原样返回，绝不弄坏名字。
func DecodeFragment(frag string) string {
	if frag == "" {
		return ""
	}
	if d, err := url.PathUnescape(frag); err == nil {
		return d
	}
	return frag
}

func ParseBLink(link string) (*ParsedB, error) {
	link = strings.TrimSpace(link)
	if link == "" {
		return nil, fmt.Errorf("链接为空")
	}
	scheme := strings.SplitN(link, "://", 2)[0]
	switch scheme {
	case "vless":
		return parseVLESS(link)
	case "vmess":
		return parseVMess(link)
	case "trojan":
		return parseTrojan(link)
	case "ss":
		return parseSS(link)
	case "socks", "socks5":
		return parseSocksHTTP(link, "socks", false)
	case "http", "https":
		return parseSocksHTTP(link, "http", scheme == "https")
	case "hysteria2", "hy2":
		return parseHy2(link)
	case "snell":
		return parseSnell(link)
	case "shadowtls":
		return parseShadowTLS(link)
	default:
		return nil, fmt.Errorf("不支持的协议：%s（支持 vless/vmess/trojan/ss/socks/http/hysteria2/snell/shadowtls）", scheme)
	}
}

func parseVLESS(link string) (*ParsedB, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(u.Port())
	q := u.Query()
	uuid := u.User.Username()
	if uuid == "" || u.Hostname() == "" || port == 0 {
		return nil, fmt.Errorf("vless 链接缺少 uuid/地址/端口")
	}
	user := map[string]interface{}{"id": uuid, "encryption": "none"}
	if f := q.Get("flow"); f != "" {
		user["flow"] = f
	}
	out := map[string]interface{}{
		"protocol": "vless",
		"settings": map[string]interface{}{
			"vnext": []interface{}{map[string]interface{}{
				"address": u.Hostname(), "port": port, "users": []interface{}{user},
			}},
		},
	}
	typ := q.Get("type")
	if typ == "" {
		typ = "tcp"
	}
	sec := q.Get("security")
	if sec == "" {
		sec = "none"
	}
	ss := map[string]interface{}{"network": typ, "security": sec}
	switch sec {
	case "reality":
		ss["realitySettings"] = map[string]interface{}{
			"serverName": q.Get("sni"),
			"fingerprint": func() string {
				if v := q.Get("fp"); v != "" {
					return v
				}
				return "chrome"
			}(),
			"publicKey": q.Get("pbk"),
			"shortId":   q.Get("sid"),
			"spiderX": func() string {
				if v := q.Get("spiderX"); v != "" {
					return v
				}
				return "/"
			}(),
		}
	case "tls":
		tls := map[string]interface{}{}
		if v := q.Get("sni"); v != "" {
			tls["serverName"] = v
		}
		if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" {
			tls["allowInsecure"] = true
		}
		if v := q.Get("fp"); v != "" {
			tls["fingerprint"] = v
		}
		if v := q.Get("alpn"); v != "" {
			tls["alpn"] = strings.Split(v, ",")
		}
		ss["tlsSettings"] = tls
	}
	switch typ {
	case "ws":
		ss["wsSettings"] = map[string]interface{}{"path": q.Get("path"), "headers": map[string]interface{}{"Host": q.Get("host")}}
	case "grpc":
		ss["grpcSettings"] = map[string]interface{}{"serviceName": q.Get("serviceName")}
	case "h2":
		host := q.Get("host")
		if host == "" {
			host = q.Get("sni")
		}
		ss["httpSettings"] = map[string]interface{}{"path": q.Get("path"), "host": []string{host}}
	case "httpupgrade":
		host := q.Get("host")
		if host == "" {
			host = q.Get("sni")
		}
		ss["httpupgradeSettings"] = map[string]interface{}{"path": q.Get("path"), "host": host}
	case "tcp":
		if ht := q.Get("headerType"); ht == "http" {
			ss["tcpSettings"] = map[string]interface{}{"header": map[string]interface{}{"type": "http", "request": map[string]interface{}{"headers": map[string]interface{}{"Host": []string{q.Get("host")}}, "path": []string{q.Get("path")}}}}
		}
	default:
		return nil, fmt.Errorf("vless 传输 %s 暂不支持（支持 tcp/ws/grpc/h2/httpupgrade）", typ)
	}
	out["streamSettings"] = ss
	name := u.Fragment
	if name == "" {
		name = fmt.Sprintf("vless-%s", u.Hostname())
	}
	return &ParsedB{Protocol: "vless", Name: name, Outbound: out}, nil
}

// flexInt：VMess JSON 里 port/aid 可能是数字也可能是字符串（面板自产链接
// 写数字、外部链接多写字符串），两种都接受；以前只认字符串，自产链接
// 粘贴回来就解析失败，带 # 后缀的链接也一样（base64 解码前要先剥后缀）。
func flexInt(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n
	}
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		p, _ := strconv.Atoi(str)
		return p
	}
	return 0
}

func parseVMess(link string) (*ParsedB, error) {
	rest := strings.TrimPrefix(link, "vmess://")
	rest = strings.SplitN(rest, "#", 2)[0]
	rest = strings.SplitN(rest, "?", 2)[0]
	rest = strings.TrimSpace(rest)
	raw, err := base64.RawStdEncoding.DecodeString(rest)
	if err != nil {
		raw, err = base64.StdEncoding.DecodeString(rest)
		if err != nil {
			return nil, fmt.Errorf("vmess 链接解码失败")
		}
	}
	var v struct {
		PS   string          `json:"ps"`
		Add  string          `json:"add"`
		Port json.RawMessage `json:"port"`
		ID   string          `json:"id"`
		Aid  json.RawMessage `json:"aid"`
		Net  string          `json:"net"`
		Type string          `json:"type"`
		Host string          `json:"host"`
		Path string          `json:"path"`
		TLS  string          `json:"tls"`
		SNI  string          `json:"sni"`
		Alpn string          `json:"alpn"`
		FP   string          `json:"fp"`
		PBK  string          `json:"pbk"`
		SID  string          `json:"sid"`
		SPX  string          `json:"spx"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	port := flexInt(v.Port)
	if v.ID == "" || v.Add == "" || port == 0 {
		return nil, fmt.Errorf("vmess 链接缺少 id/地址/端口")
	}
	aid := flexInt(v.Aid)
	out := map[string]interface{}{
		"protocol": "vmess",
		"settings": map[string]interface{}{
			"vnext": []interface{}{map[string]interface{}{
				"address": v.Add, "port": port,
				"users": []interface{}{map[string]interface{}{"id": v.ID, "alterId": aid, "security": "auto"}},
			}},
		},
	}
	netw := v.Net
	if netw == "" {
		netw = "tcp"
	}
	// 转换层支持 tcp/ws/grpc/h2/httpupgrade/quic：其他传输以前创建成功、
	// Apply 时才炸全站，现在创建时就拒绝（与 VLESS 解析器同款口径）。
	switch netw {
	case "tcp", "ws", "grpc", "h2", "httpupgrade", "quic":
	default:
		return nil, fmt.Errorf("VMess 传输 %s 暂不支持做 B 节点（仅 tcp/ws/grpc/h2/httpupgrade/quic）", netw)
	}
	ss := map[string]interface{}{"network": netw}
	sec := "none"
	switch v.TLS {
	case "tls":
		sec = "tls"
	case "reality":
		// Reality 以前被当成 none 丢掉：VMess+Reality 链接转出来是明文，
		// 连 Reality 服务端必然握手失败，且无任何警告。
		sec = "reality"
	}
	ss["security"] = sec
	if sec == "reality" {
		sni := v.SNI
		if sni == "" {
			sni = v.Host
		}
		rs := map[string]interface{}{}
		if sni != "" {
			rs["serverName"] = sni
		}
		if v.PBK != "" {
			rs["publicKey"] = v.PBK
		}
		if v.SID != "" {
			rs["shortId"] = v.SID
		}
		if v.FP != "" {
			rs["fingerprint"] = v.FP
		}
		if v.SPX != "" {
			rs["spiderX"] = v.SPX
		}
		ss["realitySettings"] = rs
	}
	if sec == "tls" {
		tls := map[string]interface{}{}
		sni := v.SNI
		if sni == "" {
			sni = v.Host
		}
		if sni != "" {
			tls["serverName"] = sni
		}
		if v.FP != "" {
			tls["fingerprint"] = v.FP
		}
		if v.Alpn != "" {
			tls["alpn"] = strings.Split(v.Alpn, ",")
		}
		ss["tlsSettings"] = tls
	}
	switch netw {
	case "ws":
		ss["wsSettings"] = map[string]interface{}{"path": v.Path, "headers": map[string]interface{}{"Host": v.Host}}
	case "grpc":
		ss["grpcSettings"] = map[string]interface{}{"serviceName": v.Path}
	case "h2":
		host := v.Host
		if host == "" {
			host = v.SNI
		}
		ss["httpSettings"] = map[string]interface{}{"path": v.Path, "host": []string{host}}
	case "httpupgrade":
		host := v.Host
		if host == "" {
			host = v.SNI
		}
		ss["httpupgradeSettings"] = map[string]interface{}{"path": v.Path, "host": host}
	case "quic":
		ss["quicSettings"] = map[string]interface{}{}
	case "tcp":
		if v.Type == "http" {
			ss["tcpSettings"] = map[string]interface{}{"header": map[string]interface{}{"type": "http", "request": map[string]interface{}{"headers": map[string]interface{}{"Host": []string{v.Host}}, "path": []string{v.Path}}}}
		}
	}
	out["streamSettings"] = ss
	name := v.PS
	if name == "" {
		name = "vmess-" + v.Add
	}
	return &ParsedB{Protocol: "vmess", Name: name, Outbound: out}, nil
}

func parseTrojan(link string) (*ParsedB, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(u.Port())
	pass, _ := u.User.Password()
	if pass == "" {
		pass = u.User.Username()
	}
	if pass == "" || u.Hostname() == "" || port == 0 {
		return nil, fmt.Errorf("trojan 链接缺少密码/地址/端口")
	}
	q := u.Query()
	typ := q.Get("type")
	if typ == "" {
		typ = "tcp"
	}
	sec := q.Get("security")
	if sec == "" {
		sec = "tls"
	}
	ss := map[string]interface{}{"network": typ, "security": sec}
	switch sec {
	case "reality":
		ss["realitySettings"] = map[string]interface{}{
			"serverName": q.Get("sni"),
			"fingerprint": func() string {
				if v := q.Get("fp"); v != "" {
					return v
				}
				return "chrome"
			}(),
			"publicKey": q.Get("pbk"),
			"shortId":   q.Get("sid"),
			"spiderX": func() string {
				if v := q.Get("spiderX"); v != "" {
					return v
				}
				return "/"
			}(),
		}
	case "tls":
		tls := map[string]interface{}{}
		if v := q.Get("sni"); v != "" {
			tls["serverName"] = v
		} else {
			tls["serverName"] = u.Hostname()
		}
		if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" {
			tls["allowInsecure"] = true
		}
		if v := q.Get("fp"); v != "" {
			tls["fingerprint"] = v
		}
		if v := q.Get("alpn"); v != "" {
			tls["alpn"] = strings.Split(v, ",")
		}
		ss["tlsSettings"] = tls
	default:
		return nil, fmt.Errorf("trojan 安全层 %s 暂不支持（支持 reality/tls）", sec)
	}
	switch typ {
	case "ws":
		ss["wsSettings"] = map[string]interface{}{"path": q.Get("path"), "headers": map[string]interface{}{"Host": q.Get("host")}}
	case "h2":
		host := q.Get("host")
		if host == "" {
			host = q.Get("sni")
		}
		ss["httpSettings"] = map[string]interface{}{"path": q.Get("path"), "host": []string{host}}
	case "httpupgrade":
		host := q.Get("host")
		if host == "" {
			host = q.Get("sni")
		}
		ss["httpupgradeSettings"] = map[string]interface{}{"path": q.Get("path"), "host": host}
	case "tcp":
	default:
		return nil, fmt.Errorf("trojan 传输 %s 暂不支持（支持 tcp/ws/h2/httpupgrade）", typ)
	}
	out := map[string]interface{}{
		"protocol": "trojan",
		"settings": map[string]interface{}{
			"servers": []interface{}{map[string]interface{}{"address": u.Hostname(), "port": port, "password": pass}},
		},
		"streamSettings": ss,
	}
	name := u.Fragment
	if name == "" {
		name = "trojan-" + u.Hostname()
	}
	return &ParsedB{Protocol: "trojan", Name: name, Outbound: out}, nil
}

// parseSnell 解析面板自己的 Snell 分享链接：
// snell://<psk>@<host>:<port>?version=<4|6>&obfs=http&obfs-host=<host>#<name>（v5）
// snell://<psk>@<host>:<port>?version=6&mode=<default|unshaped|unsafe-raw>#<name>（v6）
// 链接里的 version 是 Shadowrocket/mihomo 口径：4 = 面板 v5，6 = 面板 v6；
// 5 也按 v5 收（个别工具这么写）。version 存面板口径（5|6），
// 线路版本号（v5 写 4）由 SingBoxBOutbound 转换。返回 sing-box 形态的出站对象（与 hy2 同路）。
func parseSnell(link string) (*ParsedB, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	psk := u.User.Username()
	port, _ := strconv.Atoi(u.Port())
	if psk == "" || u.Hostname() == "" || port == 0 {
		return nil, fmt.Errorf("snell 链接缺少密钥/地址/端口")
	}
	ver := 5
	switch q := u.Query(); q.Get("version") {
	case "", "4", "5":
		ver = 5
	case "6":
		ver = 6
	default:
		return nil, fmt.Errorf("不支持的 Snell 版本：%s", q.Get("version"))
	}
	ob := map[string]interface{}{
		"type":        "snell",
		"server":      u.Hostname(),
		"server_port": port,
		"version":     ver,
		"psk":         psk,
	}
	if ver == 5 && u.Query().Get("obfs") == "http" {
		host := u.Query().Get("obfs-host")
		if host == "" {
			host = "bing.com"
		}
		ob["obfs_mode"] = "http"
		ob["obfs_host"] = host
	}
	if ver == 6 {
		if m := u.Query().Get("mode"); m != "" {
			ob["mode"] = m
		}
	}
	name := u.Fragment
	if name == "" {
		name = "snell-" + u.Hostname()
	}
	return &ParsedB{Protocol: "snell", Name: name, Outbound: ob}, nil
}

// shadowtls://<密码>@<host>:<port>?version=3&handshake=<站>&ss-method=<方法>&ss-password=<内层密码>#<名字>
// 面板自定格式（非公开标准，与 snell:// 同路）：version 省略默认 3，
// handshake 省略默认 gateway.icloud.com，ss-method 省略默认 2022-blake3-aes-128-gcm。
// 内层 SS 密码必填——没有它 SS 出站无法认证。存的是 sing-box 形态的出站对象，
// 由 SingBoxBOutbound 转成 SS 出站 + shadowtls detour 出站两个。
func parseShadowTLS(link string) (*ParsedB, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	pw := u.User.Username()
	port, _ := strconv.Atoi(u.Port())
	if pw == "" || u.Hostname() == "" || port == 0 {
		return nil, fmt.Errorf("shadowtls 链接缺少密码/地址/端口")
	}
	q := u.Query()
	switch q.Get("version") {
	case "", "3":
	default:
		return nil, fmt.Errorf("不支持的 ShadowTLS 版本：%s（仅支持 v3）", q.Get("version"))
	}
	handshake := q.Get("handshake")
	if handshake == "" {
		handshake = "gateway.icloud.com"
	}
	method := q.Get("ss-method")
	if method == "" {
		method = "2022-blake3-aes-128-gcm"
	}
	ssPw := q.Get("ss-password")
	if ssPw == "" {
		return nil, fmt.Errorf("shadowtls 链接缺少内层 SS 密码（ss-password）")
	}
	ob := map[string]interface{}{
		"type":        "shadowtls",
		"server":      u.Hostname(),
		"server_port": port,
		"version":     3,
		"password":    pw,
		"handshake":   handshake,
		"ss_method":   method,
		"ss_password": ssPw,
	}
	name := u.Fragment
	if name == "" {
		name = "shadowtls-" + u.Hostname()
	}
	return &ParsedB{Protocol: "shadowtls", Name: name, Outbound: ob}, nil
}

func parseSS(link string) (*ParsedB, error) {
	rest := strings.TrimPrefix(link, "ss://")
	// forms: ss://base64(method:pass@host:port)#name  OR  ss://base64(method:pass)@host:port#name
	frag := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		frag = rest[i+1:]
		rest = rest[:i]
	}
	if i := strings.Index(rest, "?"); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimSuffix(rest, "/")
	var method, pass, host string
	var port int
	if strings.Contains(rest, "@") {
		parts := strings.SplitN(rest, "@", 2)
		up, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			up, err = base64.URLEncoding.DecodeString(parts[0])
			if err != nil {
				return nil, fmt.Errorf("ss 链接解码失败")
			}
		}
		mp := strings.SplitN(string(up), ":", 2)
		if len(mp) != 2 {
			return nil, fmt.Errorf("ss 链接格式不对")
		}
		method, pass = mp[0], mp[1]
		hp := parts[1]
		h, p, err := net.SplitHostPort(hp)
		if err != nil {
			return nil, err
		}
		host = h
		port, _ = strconv.Atoi(p)
	} else {
		raw, err := base64.RawURLEncoding.DecodeString(rest)
		if err != nil {
			raw, err = base64.URLEncoding.DecodeString(rest)
			if err != nil {
				return nil, fmt.Errorf("ss 链接解码失败")
			}
		}
		// method:pass@host:port
		s := string(raw)
		at := strings.LastIndex(s, "@")
		if at < 0 {
			return nil, fmt.Errorf("ss 链接格式不对")
		}
		mp := strings.SplitN(s[:at], ":", 2)
		if len(mp) != 2 {
			return nil, fmt.Errorf("ss 链接格式不对")
		}
		method, pass = mp[0], mp[1]
		h, p, err := net.SplitHostPort(s[at+1:])
		if err != nil {
			return nil, err
		}
		host = h
		port, _ = strconv.Atoi(p)
	}
	if method == "" || pass == "" || host == "" || port == 0 {
		return nil, fmt.Errorf("ss 链接缺少方法/密码/地址/端口")
	}
	out := map[string]interface{}{
		"protocol": "shadowsocks",
		"settings": map[string]interface{}{
			"servers": []interface{}{map[string]interface{}{"address": host, "port": port, "method": method, "password": pass}},
		},
	}
	name := DecodeFragment(frag)
	if name == "" {
		name = "ss-" + host
	}
	return &ParsedB{Protocol: "shadowsocks", Name: name, Outbound: out}, nil
}

func parseSocksHTTP(link, proto string, isTLS bool) (*ParsedB, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(u.Port())
	if u.Hostname() == "" || port == 0 {
		return nil, fmt.Errorf("%s 链接缺少地址/端口", proto)
	}
	server := map[string]interface{}{"address": u.Hostname(), "port": port}
	if u.User != nil {
		pw, _ := u.User.Password()
		server["users"] = []interface{}{map[string]interface{}{"user": u.User.Username(), "pass": pw}}
	}
	out := map[string]interface{}{
		"protocol": proto,
		"settings": map[string]interface{}{"servers": []interface{}{server}},
	}
	// https 链接以前解析一步就丢了 scheme，转出来是明文 http 去连 TLS 端口。
	// 现在把 TLS 记下来，转换层原样带到 sing-box 出站。
	if isTLS {
		out["tls"] = map[string]interface{}{"enabled": true, "server_name": u.Hostname()}
	}
	name := u.Fragment
	if name == "" {
		name = proto + "-" + u.Hostname()
	}
	return &ParsedB{Protocol: proto, Name: name, Outbound: out}, nil
}

func parseHy2(link string) (*ParsedB, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(u.Port())
	pass, _ := u.User.Password()
	if pass == "" {
		pass = u.User.Username()
	}
	if pass == "" || u.Hostname() == "" || port == 0 {
		return nil, fmt.Errorf("hysteria2 链接缺少密码/地址/端口")
	}
	q := u.Query()
	ob := map[string]interface{}{
		"type":        "hysteria2",
		"server":      u.Hostname(),
		"server_port": port,
		"password":    pass,
		"tls": map[string]interface{}{
			"enabled": true,
			"server_name": func() string {
				if v := q.Get("sni"); v != "" {
					return v
				}
				return u.Hostname()
			}(),
			"insecure": q.Get("insecure") == "1",
			"alpn":     []string{"h3"},
		},
	}
	if obfs := q.Get("obfs"); obfs != "" {
		ob["obfs"] = map[string]interface{}{"type": obfs, "password": q.Get("obfs-password")}
	}
	name := u.Fragment
	if name == "" {
		name = "hy2-" + u.Hostname()
	}
	return &ParsedB{Protocol: "hysteria2", Name: name, Outbound: ob}, nil
}
