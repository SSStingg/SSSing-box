package server

// 回归测试：link6 只发给真双栈节点（2026-10-30 检查）。

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"sssingbox/internal/proxy"
	"sssingbox/internal/store"
)

func TestInboundListensV6(t *testing.T) {
	mk := func(proto, config string) *store.Inbound {
		return &store.Inbound{Protocol: proto, Config: config}
	}
	cases := []struct {
		in   *store.Inbound
		want bool
	}{
		// sing-box 入站：空 Listen = 默认 "::"（双栈）。
		{mk("vless", `{"listen":""}`), true},
		{mk("vless", `{"listen":"::"}`), true},
		{mk("vless", `{"listen":"0.0.0.0"}`), false},
		{mk("vless", `{"listen":"127.0.0.1"}`), false},
		{mk("vless", `{}`), true},
		// WireGuard endpoint 天然双 socket。
		{mk("wireguard", `{}`), true},
		// 未知协议不发。
		{mk("dokodemo", `{}`), false},
	}
	for i, c := range cases {
		if got := inboundListensV6(c.in); got != c.want {
			t.Fatalf("case %d (%s %s): got %v want %v", i, c.in.Protocol, c.in.Config, got, c.want)
		}
	}
	_ = proxy.VLESSConfig{}
}

func TestValidSNI(t *testing.T) {
	cases := []struct {
		sni  string
		want bool
	}{
		{"www.microsoft.com", true},
		{"example.com.", true},
		{"1.2.3.4", true},
		{"localhost", true},
		{"a b.com", false},
		{"中文.com", false},
		{"-bad.com", false},
		{"bad-.com", false},
		{"a_b.com", false},
		{"", false},
		{strings.Repeat("a", 300) + ".com", false},
		{"a..com", false},
	}
	for _, c := range cases {
		if got := validSNI(c.sni); got != c.want {
			t.Errorf("validSNI(%q) = %v, want %v", c.sni, got, c.want)
		}
	}
}

func TestCheckPortConflicts(t *testing.T) {
	mk := func(name, proto string, port int, listen string, enabled bool) *store.Inbound {
		// 监听地址以 Config 里的 listen 为准（生成器就读它）；
		// Inbound.Address 是对外地址，与监听无关。
		cfg := ""
		if listen != "" {
			cfg = `{"listen":` + strconv.Quote(listen) + `}`
		}
		return &store.Inbound{Name: name, Protocol: proto, Port: port, Config: cfg, Enabled: enabled}
	}
	cases := []struct {
		name string
		ins  []*store.Inbound
		want bool // true = 应当报错
	}{
		{"不同端口不冲突", []*store.Inbound{mk("a", "vless", 10001, "", true), mk("b", "vless", 10002, "", true)}, false},
		{"同端口同通配监听冲突", []*store.Inbound{mk("a", "vless", 10001, "", true), mk("b", "vless", 10001, "", true)}, true},
		{"通配与指定地址冲突", []*store.Inbound{mk("a", "vless", 10001, "", true), mk("b", "vless", 10001, "127.0.0.1", true)}, true},
		{"0.0.0.0 与指定地址冲突", []*store.Inbound{mk("a", "vless", 10001, "0.0.0.0", true), mk("b", "vless", 10001, "127.0.0.1", true)}, true},
		{"不同指定地址不冲突", []*store.Inbound{mk("a", "vless", 10001, "127.0.0.1", true), mk("b", "vless", 10001, "127.0.0.2", true)}, false},
		{"停用节点不占端口", []*store.Inbound{mk("a", "vless", 10001, "", true), mk("b", "vless", 10001, "", false)}, false},
		{"TCP 与 UDP 同端口不冲突", []*store.Inbound{mk("a", "vless", 443, "", true), mk("b", "hy2", 443, "", true)}, false},
		{"UDP 与 UDP 同端口冲突", []*store.Inbound{mk("a", "hy2", 443, "", true), mk("b", "tuic", 443, "", true)}, true},
		{"TCP 与 UDP 同端口、指定监听也不冲突", []*store.Inbound{mk("a", "vless", 443, "127.0.0.1", true), mk("b", "wireguard", 443, "127.0.0.1", true)}, false},
	}
	for _, c := range cases {
		err := checkPortConflicts(c.ins, "sing-box")
		if c.want && err == nil {
			t.Errorf("%s：应当报错却放行", c.name)
		}
		if !c.want && err != nil {
			t.Errorf("%s：不应报错却报 %v", c.name, err)
		}
	}
}

func TestCheckRealityDest(t *testing.T) {
	if err := checkRealityDest("n", "www.example.com:443"); err != nil {
		t.Errorf("合法 dest 不应报错：%v", err)
	}
	for _, bad := range []string{"", "www.example.com", "www.example.com:0", "www.example.com:65536", "www.example.com:abc", ":443"} {
		if err := checkRealityDest("n", bad); err == nil {
			t.Errorf("非法 dest %q 应当报错却放行", bad)
		}
	}
}

func TestInboundLinks6NameSuffix(t *testing.T) {
	// v6 链接名字必须带 -ipv6 后缀，否则订阅里 v4/v6 两行同名分不清。
	// publicIPv6Fetched 也要给当前时间，否则缓存判定会绕过去重查系统 IP。
	// v4 链接生成会查 Store 里的面板域名：给个空临时库，否则 effectiveAddress 空指针。
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("建临时 Store 失败：%v", err)
	}
	defer st.Close()
	s := &Server{app: &App{Store: st, publicIPv6Cache: "2603:c024:1:47ee:747e:949c:1989:6520", publicIPv6Fetched: time.Now()}}
	cases := []struct {
		name, proto, config string
		check               func(t *testing.T, link string)
	}{
		{"TEST-VLESS", "vless", `{"uuid":"11111111-2222-3333-4444-555555555555","mode":"reality","public_key":"abc","short_id":"1234"}`, func(t *testing.T, link string) {
			if !strings.Contains(link, "#TEST-VLESS-ipv6") {
				t.Errorf("VLESS link6 应以 #TEST-VLESS-ipv6 结尾：%s", link)
			}
		}},
		{"TEST-VMESS", "vmess", `{"uuid":"11111111-2222-3333-4444-555555555555","mode":"tcp"}`, func(t *testing.T, link string) {
			// VMess 链接是整段 base64 的 JSON，名字在 ps 字段里。
			raw := strings.TrimPrefix(link, "vmess://")
			raw += strings.Repeat("=", -len(raw)%4)
			dec, err := base64.StdEncoding.DecodeString(raw)
			if err != nil {
				t.Fatalf("VMess link6 解不开：%v", err)
			}
			var m map[string]interface{}
			if err := json.Unmarshal(dec, &m); err != nil {
				t.Fatalf("VMess link6 JSON 解析失败：%v", err)
			}
			if m["ps"] != "TEST-VMESS-ipv6" {
				t.Errorf("VMess link6 ps 应为 TEST-VMESS-ipv6，实际 %v", m["ps"])
			}
		}},
		{"TEST-SS", "ss", `{"method":"2022-blake3-aes-128-gcm","password":"pw123456"}`, func(t *testing.T, link string) {
			if !strings.Contains(link, "#TEST-SS-ipv6") {
				t.Errorf("SS link6 应含 #TEST-SS-ipv6：%s", link)
			}
		}},
	}
	for _, c := range cases {
		in := &store.Inbound{Name: c.name, Protocol: c.proto, Port: 39001, SNI: "www.example.com", Config: c.config, Enabled: true}
		link6, _ := s.inboundLinks6(in)
		if link6 == "" {
			t.Errorf("%s：link6 为空（应生成 v6 链接）", c.name)
			continue
		}
		c.check(t, link6)
		// v4 链接名字不动，不加后缀。
		link4, _ := s.inboundLinks(in)
		if strings.Contains(link4, "-ipv6") {
			t.Errorf("%s：v4 链接不应带 -ipv6：%s", c.name, link4)
		}
	}
}

func TestSubChainKeepsNodeAndAddsChainRow(t *testing.T) {
	// 链式入口在订阅里另起一行（链名），A 节点原样也保留：2026-11-03 用户要求
	// 订阅同时有 A 和链式（以前只剩链名、丢了 A）。
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("建临时 Store 失败：%v", err)
	}
	defer st.Close()
	if err := st.SetSetting("sub_token", "test-token-123"); err != nil {
		t.Fatalf("写 token 失败：%v", err)
	}
	vlessCfg := `{"uuid":"11111111-2222-3333-4444-555555555555","mode":"reality","public_key":"abc","short_id":"1234"}`
	for _, in := range []*store.Inbound{
		{ID: "in-chain", Name: "CHAINED-NODE", Protocol: "vless", Port: 8443, Address: "203.0.113.10", SNI: "www.example.com", Config: vlessCfg, Enabled: true},
		{ID: "in-plain", Name: "PLAIN-NODE", Protocol: "vless", Port: 8444, Address: "203.0.113.10", SNI: "www.example.com", Config: vlessCfg, Enabled: true},
	} {
		if err := st.UpsertInbound(in); err != nil {
			t.Fatalf("建节点失败：%v", err)
		}
	}
	ch := &store.Chain{ID: "ch-1", Name: "MY-LANDING-CHAIN", InboundID: "in-chain", BNodeID: "bn-dummy", List: "ifconfig.me", Enabled: true}
	if err := st.UpsertChain(ch); err != nil {
		t.Fatalf("建链式失败：%v", err)
	}
	s := &Server{app: &App{Store: st, publicIPv6Cache: "2603:c024:1:47ee:747e:949c:1989:6520", publicIPv6Fetched: time.Now()}}
	fetchSub := func(t *testing.T) string {
		req := httptest.NewRequest("GET", "/sub/test-token-123", nil)
		rec := httptest.NewRecorder()
		s.handleSub(rec, req)
		if rec.Code != 200 {
			t.Fatalf("订阅应返回 200，实际 %d：%s", rec.Code, rec.Body.String())
		}
		dec, err := base64.StdEncoding.DecodeString(rec.Body.String())
		if err != nil {
			t.Fatalf("订阅解不开：%v", err)
		}
		return string(dec)
	}
	body := fetchSub(t)
	if !strings.Contains(body, "#CHAINED-NODE") {
		t.Errorf("启用链式时订阅仍应有 A 节点原行，实际订阅：\n%s", body)
	}
	if !strings.Contains(body, "#MY-LANDING-CHAIN") {
		t.Errorf("启用链式时订阅应另有链名行，实际订阅：\n%s", body)
	}
	if !strings.Contains(body, "#CHAINED-NODE-ipv6") {
		t.Errorf("订阅 v6 行应有 A 节点原名 + -ipv6，实际订阅：\n%s", body)
	}
	if !strings.Contains(body, "#MY-LANDING-CHAIN-ipv6") {
		t.Errorf("订阅 v6 行应是链名 + -ipv6，实际订阅：\n%s", body)
	}
	if !strings.Contains(body, "#PLAIN-NODE") {
		t.Errorf("无链节点订阅应保持节点名，实际订阅：\n%s", body)
	}
	// 链停用后入口就是普通节点，用回节点名。
	ch.Enabled = false
	if err := st.UpsertChain(ch); err != nil {
		t.Fatalf("停用链式失败：%v", err)
	}
	body = fetchSub(t)
	if !strings.Contains(body, "#CHAINED-NODE") {
		t.Errorf("链停用后订阅应回落到节点名，实际订阅：\n%s", body)
	}
	if strings.Contains(body, "MY-LANDING-CHAIN") {
		t.Errorf("链停用后订阅不应再出现链名，实际订阅：\n%s", body)
	}
}

func TestBNodeListDecodesName(t *testing.T) {
	// 其他节点列表显示名要解码：老数据里 SS 节点名是 #fragment 原样
	// （百分号编码），不解码面板就显示乱码；存储的链接不动。
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("建临时 Store 失败：%v", err)
	}
	defer st.Close()
	link := "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206dGVzdHBhc3NAZXhhbXBsZS5jb206MTIzNA#%E6%B5%8B%E8%AF%95SS"
	if err := st.UpsertBNode(&store.BNode{ID: "bn-1", Name: "%E6%B5%8B%E8%AF%95SS", Protocol: "shadowsocks", Link: link}); err != nil {
		t.Fatalf("建其他节点失败：%v", err)
	}
	s := &Server{app: &App{Store: st}}
	req := httptest.NewRequest("GET", "/api/bnodes", nil)
	rec := httptest.NewRecorder()
	s.handleBNodes(rec, req)
	if rec.Code != 200 {
		t.Fatalf("其他节点列表应返回 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []struct {
			Name string `json:"name"`
			Link string `json:"link"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("列表解不开：%v", err)
	}
	if len(resp.Data) != 1 || resp.Data[0].Name != "测试SS" {
		t.Errorf("列表显示名应解码成中文，实际：%+v", resp.Data)
	}
	if len(resp.Data) == 1 && resp.Data[0].Link != link {
		t.Errorf("存储的链接不应被改动，实际：%s", resp.Data[0].Link)
	}
}

func TestChainPutEmptyNameRejected(t *testing.T) {
	// 与节点 PUT 一致：编辑链式时清空名字直接拒绝，不留无名链。
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("建临时 Store 失败：%v", err)
	}
	defer st.Close()
	if err := st.UpsertChain(&store.Chain{ID: "ch-1", Name: "OLD-NAME", InboundID: "in-x", BNodeID: "bn-y", List: "ifconfig.me", Enabled: true}); err != nil {
		t.Fatalf("建链式失败：%v", err)
	}
	s := &Server{app: &App{Store: st}}
	req := httptest.NewRequest("PUT", "/api/chains/ch-1", strings.NewReader(`{"name": "   "}`))
	rec := httptest.NewRecorder()
	s.handleChainAction(rec, req)
	if rec.Code != 400 {
		t.Errorf("空链名应返回 400，实际 %d：%s", rec.Code, rec.Body.String())
	}
	list, _ := st.ListChains()
	if len(list) != 1 || list[0].Name != "OLD-NAME" {
		t.Errorf("拒绝后链名应保持 OLD-NAME，实际 %v", list)
	}
}
