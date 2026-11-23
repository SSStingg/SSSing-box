package proxy

// 回归测试：2026-10-30 全局检查修掉的几类问题。
// 链式 AND 规则、清单 catch-all、IPv6 链接缺方括号、B 节点转换与解析。

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func jsonMarshal(v interface{}) ([]byte, error) { return json.Marshal(v) }

func b64Encode(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestParseSSDecodesFragmentName(t *testing.T) {
	// SS 链接 #fragment 是手切字符串，百分号编码原样存成了名字，
	// 面板就显示乱码；解析时就要解码成中文，解不出来才原样保留。
	p, err := ParseBLink("ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206dGVzdHBhc3NAZXhhbXBsZS5jb206MTIzNA#%E6%B5%8B%E8%AF%95SS")
	if err != nil {
		t.Fatalf("SS 链接解析失败：%v", err)
	}
	if p.Name != "测试SS" {
		t.Errorf("SS 节点名应解码成中文，实际 %q", p.Name)
	}
	// 名字里有字面 % 时不许弄坏。
	p2, err := ParseBLink("ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206dGVzdHBhc3NAZXhhbXBsZS5jb206MTIzNA#100%节点")
	if err != nil {
		t.Fatalf("含字面 %% 的 SS 链接解析失败：%v", err)
	}
	if p2.Name != "100%节点" {
		t.Errorf("含字面 %% 的名字应原样保留，实际 %q", p2.Name)
	}
}

func TestParseChainListMixed(t *testing.T) {
	suffixes, cidrs, err := ParseChainList("https://example.com/path\n*.foo.org\n1.2.3.0/24\n# comment\n\n10.0.0.5\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suffixes) != 2 || suffixes[0] != "example.com" || suffixes[1] != "foo.org" {
		t.Fatalf("suffixes = %v", suffixes)
	}
	if len(cidrs) != 2 || cidrs[0] != "1.2.3.0/24" || cidrs[1] != "10.0.0.5" {
		t.Fatalf("cidrs = %v", cidrs)
	}
}

func TestParseChainListRejects(t *testing.T) {
	for _, list := range []string{
		"",
		"# only comments\n\n",
		"example.com\nnot a domain\n",
		"example.com:443:80\n",
	} {
		if _, _, err := ParseChainList(list); err == nil {
			t.Fatalf("list %q should be rejected", list)
		}
	}
}

func TestChainRulesSplitNoCatchAll(t *testing.T) {
	rules := SingBoxChainRules([]ChainInput{{InboundTag: "in-abc", OutboundTag: "chain-x", List: "example.com\n1.2.3.0/24"}})
	// sniff + 域名规则 + IP 规则 = 3 条，绝不能是一条同时带两个字段的 AND 规则。
	if len(rules) != 3 {
		t.Fatalf("want 3 rules, got %d: %v", len(rules), rules)
	}
	if _, ok := rules[1]["domain_suffix"]; !ok {
		t.Fatalf("rule 1 should carry domain_suffix only: %v", rules[1])
	}
	if _, ok := rules[1]["ip_cidr"]; ok {
		t.Fatalf("rule 1 must not carry ip_cidr: %v", rules[1])
	}
	if _, ok := rules[2]["ip_cidr"]; !ok {
		t.Fatalf("rule 2 should carry ip_cidr only: %v", rules[2])
	}
	// 空清单：只有 sniff，不生成无匹配条件的 catch-all。
	rules = SingBoxChainRules([]ChainInput{{InboundTag: "in-abc", OutboundTag: "chain-x", List: "# nothing\n"}})
	if len(rules) != 1 {
		t.Fatalf("empty list should yield only sniff, got %d: %v", len(rules), rules)
	}
}

func TestChainRulesDirectCatchAll(t *testing.T) {
	// 直接链式：用户明确选的“全部走 B”，一条只绑入站、无匹配条件的规则。
	rules := SingBoxChainRules([]ChainInput{{InboundTag: "in-abc", OutboundTag: "chain-x", Direct: true}})
	if len(rules) != 2 {
		t.Fatalf("want sniff + catch-all = 2 rules, got %d: %v", len(rules), rules)
	}
	r := rules[1]
	if r["action"] != "route" || r["outbound"] != "chain-x" {
		t.Fatalf("catch-all should route to chain-x: %v", r)
	}
	if _, ok := r["domain_suffix"]; ok {
		t.Fatalf("direct catch-all must not carry domain_suffix: %v", r)
	}
	if _, ok := r["ip_cidr"]; ok {
		t.Fatalf("direct catch-all must not carry ip_cidr: %v", r)
	}
	// 直接链式只绑自己的入站，不偷别的入站的流量。
	if got, _ := r["inbound"].([]string); len(got) != 1 || got[0] != "in-abc" {
		t.Fatalf("catch-all should bind only its own inbound: %v", r["inbound"])
	}
	// 直接 + 分流混用：分流规则照常生成，直接规则只影响自己的入站。
	rules = SingBoxChainRules([]ChainInput{
		{InboundTag: "in-a", OutboundTag: "chain-a", List: "example.com"},
		{InboundTag: "in-b", OutboundTag: "chain-b", Direct: true},
	})
	if len(rules) != 3 {
		t.Fatalf("want sniff + split + catch-all = 3 rules, got %d: %v", len(rules), rules)
	}
}

func TestHostPortBrackets(t *testing.T) {
	if got := hostPort("1.2.3.4", 443); got != "1.2.3.4:443" {
		t.Fatalf("ipv4: %s", got)
	}
	if got := hostPort("example.com", 443); got != "example.com:443" {
		t.Fatalf("domain: %s", got)
	}
	if got := hostPort("2603:c024:1:47ee::1", 443); got != "[2603:c024:1:47ee::1]:443" {
		t.Fatalf("ipv6: %s", got)
	}
	if got := hostPort("[2603:c024:1:47ee::1]", 443); got != "[2603:c024:1:47ee::1]:443" {
		t.Fatalf("pre-bracketed must not double-bracket: %s", got)
	}
}

func TestLinksIPv6Bracketed(t *testing.T) {
	v6 := "2603:c024:1:47ee::1"
	vless := VLESSLink("11111111-2222-3333-4444-555555555555", v6, 443, "www.microsoft.com", VLESSConfig{Mode: "reality", PublicKey: "pub", ShortID: "abcd"}, "n")
	if !strings.Contains(vless, "@["+v6+"]:443") {
		t.Fatalf("vless link missing brackets: %s", vless)
	}
	ss := SSLink(v6, 8388, SSConfig{Method: "2022-blake3-aes-128-gcm", Password: "pw"}, "n")
	// SIP002：userinfo 是 base64(方法:密码)，host:port 在 @ 外面、须带方括号。
	noFrag := strings.SplitN(ss, "#", 2)[0]
	rest := strings.TrimPrefix(noFrag, "ss://")
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		t.Fatalf("ss link missing @: %s", ss)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(rest[:at])
	if err != nil || string(decoded) != "2022-blake3-aes-128-gcm:pw" {
		t.Fatalf("ss link userinfo wrong: %s (decoded %s, err %v)", ss, string(decoded), err)
	}
	if rest[at+1:] != "["+v6+"]:8388" {
		t.Fatalf("ss link host:port missing brackets: %s", ss)
	}
	wg := WGClientConfig(v6, 51820, WGConfig{ClientPriv: "cpriv", ClientIP: "10.0.0.2/32", ServerPub: "spub"}, "n")
	if !strings.Contains(wg, "Endpoint = ["+v6+"]:51820") {
		t.Fatalf("wg endpoint missing brackets: %s", wg)
	}
}

func TestBOutboundNormalizationAndValidation(t *testing.T) {
	// hy2/ss 入站口径也要能转。
	obs, err := SingBoxBOutbound("hy2", `{"type":"hysteria2","server":"1.2.3.4","server_port":443,"password":"pw","tls":{"enabled":true,"server_name":"example.com"}}`, "chain-t")
	if err != nil {
		t.Fatalf("hy2 normalize: %v", err)
	}
	ob := obs[0]
	if ob["type"] != "hysteria2" {
		t.Fatalf("hy2 type: %v", ob["type"])
	}
	obs, err = SingBoxBOutbound("ss", `{"protocol":"shadowsocks","settings":{"servers":[{"address":"1.2.3.4","port":8388,"method":"aes-128-gcm","password":"pw"}]}}`, "chain-t")
	if err != nil {
		t.Fatalf("ss normalize: %v", err)
	}
	ob = obs[0]
	if ob["type"] != "shadowsocks" {
		t.Fatalf("ss type: %v", ob["type"])
	}
	// 空地址 / 非法端口必须报错，而不是进配置等 sing-box 校验失败。
	if _, err := SingBoxBOutbound("shadowsocks", `{"protocol":"shadowsocks","settings":{"servers":[{"address":"","port":8388,"method":"aes-128-gcm","password":"pw"}]}}`, "chain-t"); err == nil {
		t.Fatalf("empty server should error")
	}
	if _, err := SingBoxBOutbound("shadowsocks", `{"protocol":"shadowsocks","settings":{"servers":[{"address":"1.2.3.4","port":0,"method":"aes-128-gcm","password":"pw"}]}}`, "chain-t"); err == nil {
		t.Fatalf("port 0 should error")
	}
	// https B 节点：TLS 必须带到出站，不再降级成明文。
	parsed, err := parseSocksHTTP("https://user:pass@1.2.3.4:8443", "http", true)
	if err != nil {
		t.Fatalf("parse https: %v", err)
	}
	b, _ := jsonMarshal(parsed.Outbound)
	obs, err = SingBoxBOutbound("http", string(b), "chain-t")
	if err != nil {
		t.Fatalf("https convert: %v", err)
	}
	ob = obs[0]
	if _, ok := ob["tls"]; !ok {
		t.Fatalf("https outbound lost tls: %v", ob)
	}
}

func TestParseVMessRoundTrip(t *testing.T) {
	// 面板自产链接：port 是 JSON 数字 + 带 # 后缀，必须能粘贴回来。
	link := VMessLink("1.2.3.4", 443, VMessConfig{UUID: "11111111-2222-3333-4444-555555555555", Mode: "tcp"}, "n", "")
	parsed, err := ParseBLink(link + "#n")
	if err != nil {
		t.Fatalf("own vmess link should re-parse: %v (link=%s)", err, link)
	}
	if parsed.Protocol != "vmess" {
		t.Fatalf("protocol: %s", parsed.Protocol)
	}
	// 不支持的传输在创建时就拒绝，不等 Apply 炸全站。
	badJSON := `{"ps":"x","add":"1.2.3.4","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","net":"kcp","tls":"tls"}`
	bad := "vmess://" + b64Encode(badJSON)
	if _, err := ParseBLink(bad); err == nil {
		t.Fatalf("vmess kcp should be rejected at parse time")
	}
	// h2 现已支持：自产 h2 链接必须能粘贴回来。
	h2link := VMessLink("1.2.3.4", 443, VMessConfig{UUID: "11111111-2222-3333-4444-555555555555", Mode: "h2", Domain: "example.com"}, "n", "")
	if _, err := ParseBLink(h2link); err != nil {
		t.Fatalf("vmess h2 link should re-parse: %v (link=%s)", err, h2link)
	}
	// Reality 字段必须保留，不再丢成明文。
	realityJSON := `{"ps":"x","add":"1.2.3.4","port":443,"id":"11111111-2222-3333-4444-555555555555","aid":0,"net":"tcp","tls":"reality","sni":"example.com","pbk":"PUBKEY","sid":"abcd"}`
	parsed, err = ParseBLink("vmess://" + b64Encode(realityJSON))
	if err != nil {
		t.Fatalf("vmess reality parse: %v", err)
	}
	b, _ := jsonMarshal(parsed.Outbound)
	obs, err := SingBoxBOutbound("vmess", string(b), "chain-t")
	if err != nil {
		t.Fatalf("vmess reality convert: %v", err)
	}
	ob := obs[0]
	tlsMap, ok := ob["tls"].(map[string]interface{})
	if !ok {
		t.Fatalf("reality outbound missing tls: %v", ob)
	}
	realMap, ok := tlsMap["reality"].(map[string]interface{})
	if !ok || realMap["public_key"] != "PUBKEY" {
		t.Fatalf("reality public_key lost: %v", tlsMap)
	}
}

func TestLinkDomainSNIFallback(t *testing.T) {
	// VMess h2, Domain 为空时链接 add/sni 必须回退到 SNI，不能是空串。
	link := VMessLink("1.2.3.4", 443, VMessConfig{UUID: "11111111-2222-3333-4444-555555555555", Mode: "h2"}, "n", "sni.example.com")
	raw := strings.TrimPrefix(link, "vmess://")
	raw = strings.SplitN(raw, "#", 2)[0]
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("decode vmess link: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal vmess link: %v", err)
	}
	if m["add"] != "sni.example.com" || m["sni"] != "sni.example.com" {
		t.Errorf("vmess h2 fallback: add=%v sni=%v, want sni.example.com", m["add"], m["sni"])
	}
	// Trojan cf 同款回退。
	tl := TrojanLink("1.2.3.4", 2087, "cf.example.com", TrojanConfig{Password: "pw", Mode: "cf"}, "n")
	u, err := url.Parse(tl)
	if err != nil {
		t.Fatalf("parse trojan link: %v", err)
	}
	if u.Query().Get("sni") != "cf.example.com" {
		t.Errorf("trojan cf fallback: sni=%q, want cf.example.com", u.Query().Get("sni"))
	}
}

func TestTLSLinkEmptyDomainFallsBackToAddress(t *testing.T) {
	// TLS 档域名与 SNI 都空时（默认留空），链接地址必须回退到服务器地址，
	// 不能下发空地址或伪装域名的死链。
	vl := VLESSLink("11111111-2222-3333-4444-555555555555", "1.2.3.4", 8443, "", VLESSConfig{Mode: "ws", Path: "/x"}, "n")
	vu, err := url.Parse(vl)
	if err != nil {
		t.Fatalf("parse vless link: %v", err)
	}
	if vu.Host != "1.2.3.4:8443" || vu.Query().Get("sni") != "1.2.3.4" || vu.Query().Get("host") != "1.2.3.4" {
		t.Errorf("vless ws fallback: host=%q sni=%q host-param=%q", vu.Host, vu.Query().Get("sni"), vu.Query().Get("host"))
	}
	tl := TrojanLink("1.2.3.4", 8443, "", TrojanConfig{Password: "pw", Mode: "h2", Path: "/x"}, "n")
	tu, err := url.Parse(tl)
	if err != nil {
		t.Fatalf("parse trojan link: %v", err)
	}
	if tu.Host != "1.2.3.4:8443" || tu.Query().Get("sni") != "1.2.3.4" {
		t.Errorf("trojan h2 fallback: host=%q sni=%q", tu.Host, tu.Query().Get("sni"))
	}
	ml := VMessLink("1.2.3.4", 8443, VMessConfig{UUID: "11111111-2222-3333-4444-555555555555", Mode: "h2"}, "n", "")
	raw := strings.TrimPrefix(ml, "vmess://")
	raw = strings.SplitN(raw, "#", 2)[0]
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("decode vmess link: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal vmess link: %v", err)
	}
	if m["add"] != "1.2.3.4" || m["sni"] != "1.2.3.4" || m["host"] != "1.2.3.4" {
		t.Errorf("vmess h2 fallback: add=%v sni=%v host=%v", m["add"], m["sni"], m["host"])
	}
}

func TestWGEndpointListenPassthrough(t *testing.T) {
	ep := SingBoxWGEndpoint("wg-x", 51820, WGConfig{ServerPriv: "a", ClientPub: "b", ClientIP: "10.0.0.2/32", Listen: "127.0.0.1"})
	if ep["listen"] != "127.0.0.1" {
		t.Errorf("listen = %v, want 127.0.0.1", ep["listen"])
	}
	ep2 := SingBoxWGEndpoint("wg-x", 51820, WGConfig{ServerPriv: "a", ClientPub: "b", ClientIP: "10.0.0.2/32"})
	if _, ok := ep2["listen"]; ok {
		t.Errorf("empty Listen should omit listen key, got %v", ep2["listen"])
	}
}

func TestBNodeHostPortSSForms(t *testing.T) {
	// 整段 base64 形 SS（主机藏在密文里）：必须解出 127.0.0.1:39017，
	// 否则订阅过滤会把回环 B 链接漏放出去。
	whole := "ss://" + base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:secret@127.0.0.1:39017")) + "#R-B-SS"
	h, p, err := BNodeHostPort(whole)
	if err != nil || h != "127.0.0.1" || p != 39017 {
		t.Errorf("whole-base64 ss: host=%q port=%d err=%v", h, p, err)
	}
	// userinfo base64 形：通用路径本来就通，回归确认。
	part := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@8.8.8.8:8388#x"
	h, p, err = BNodeHostPort(part)
	if err != nil || h != "8.8.8.8" || p != 8388 {
		t.Errorf("userinfo-base64 ss: host=%q port=%d err=%v", h, p, err)
	}
}

func TestNaiveLinkEscapesCredentials(t *testing.T) {
	cfg := NaiveConfig{Username: "user@x", Password: "p@ss:word/a?b", Domain: "naive.test"}
	doc := NaiveLink(cfg, 443)
	// NaiveLink 返回的是 JSON 文档，proxy 字段里才是链接。
	var parsed struct {
		Proxy string `json:"proxy"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatalf("NaiveLink 返回的不是合法 JSON：%v", err)
	}
	link := parsed.Proxy
	// 密码里的 @ : / ? 必须转义，否则客户端会解析错 host 或截断密码。
	if strings.Contains(link, "p@ss") {
		t.Errorf("密码未转义，裸 @ 会截断 userinfo：%s", link)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("生成的链接本身解析失败：%v", err)
	}
	pw, _ := u.User.Password()
	if pw != "p@ss:word/a?b" {
		t.Errorf("解析回来的密码不对：%q", pw)
	}
	if u.Host != "naive.test:443" {
		t.Errorf("host 解析错：%q", u.Host)
	}
}

func TestGenSelfSignedCertIPSAN(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "c.key")
	if err := GenSelfSignedCert(certPath, keyPath, "203.0.113.7"); err != nil {
		t.Fatalf("生成失败：%v", err)
	}
	pemBytes, _ := os.ReadFile(certPath)
	block, _ := pem.Decode(pemBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "203.0.113.7" {
		t.Errorf("IP SAN 不对：%v（DNSNames=%v）", cert.IPAddresses, cert.DNSNames)
	}
}

func TestSingBoxFullConfigNilInbounds(t *testing.T) {
	cfg := SingBoxFullConfig(nil, nil, nil, nil)
	ins, ok := cfg["inbounds"].([]interface{})
	if !ok {
		t.Fatalf("inbounds 不是数组：%T", cfg["inbounds"])
	}
	if ins == nil {
		t.Errorf("inbounds 为 nil，JSON 会写成 null；应为空数组")
	}
}
