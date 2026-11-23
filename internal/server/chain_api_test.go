package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"sssingbox/internal/store"
)

func setupChainTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("打开测试库失败：%v", err)
	}
	t.Cleanup(func() { st.Close() })

	// 准备多种协议的本地入站节点：Hy2、ShadowTLS、WireGuard
	_ = st.UpsertInbound(&store.Inbound{ID: "in-hy2", Name: "HY2-8443", Protocol: "hy2", Port: 8443, Address: "1.2.3.4", SNI: "www.bing.com", Config: `{"password":"pw"}`, Enabled: true})
	_ = st.UpsertInbound(&store.Inbound{ID: "in-st", Name: "ST-443", Protocol: "shadowtls", Port: 443, Address: "1.2.3.4", Config: `{"version":3,"password":"pw","handshake":"gateway.icloud.com","ss_method":"2022-blake3-aes-128-gcm","ss_password":"AAAAAAAAAAAAAAAAAAAAAA==","inner_port":20001}`, Enabled: true})
	_ = st.UpsertInbound(&store.Inbound{ID: "in-wg", Name: "WG-51820", Protocol: "wireguard", Port: 51820, Address: "1.2.3.4", Config: `{"server_priv":"a","client_pub":"b","client_ip":"10.0.0.2/32"}`, Enabled: true})

	// 准备 3 个外部 B 节点
	bCfg := `{"type":"hysteria2","server":"203.0.113.1","server_port":443,"password":"pw","tls":{"enabled":true,"server_name":"example.com"}}`
	_ = st.UpsertBNode(&store.BNode{ID: "b1", Name: "B1-美国", Protocol: "hysteria2", Link: "hysteria2://pw@203.0.113.1:443", Config: bCfg})
	_ = st.UpsertBNode(&store.BNode{ID: "b2", Name: "B2-日本", Protocol: "hysteria2", Link: "hysteria2://pw@203.0.113.2:443", Config: strings.Replace(bCfg, "203.0.113.1", "203.0.113.2", 1)})
	_ = st.UpsertBNode(&store.BNode{ID: "b3", Name: "B3-新加坡", Protocol: "hysteria2", Link: "hysteria2://pw@203.0.113.3:443", Config: strings.Replace(bCfg, "203.0.113.1", "203.0.113.3", 1)})

	app := NewApp(st, dir)
	return &Server{app: app, sessions: map[string]session{}}, st
}

func TestMultiProtocolAndMultiBChainAPI(t *testing.T) {
	s, st := setupChainTestServer(t)

	// 1. WireGuard 做入口 A 应被拒绝
	reqWG := httptest.NewRequest("POST", "/api/chains", strings.NewReader(`{"inbound_id":"in-wg","mode":"direct","bnode_id":"b1"}`))
	recWG := httptest.NewRecorder()
	s.handleChains(recWG, reqWG)
	if recWG.Code != 400 {
		t.Fatalf("WireGuard 做入口 A 应返回 400，实际 %d：%s", recWG.Code, recWG.Body.String())
	}

	// 2. 非 VLESS 节点（如 Hy2）做入口 A + 多 B 分流（域名冲突时应 400 拦截）
	conflictPayload := `{
		"name": "Hy2多路分流",
		"inbound_id": "in-hy2",
		"mode": "split",
		"routes": [
			{"bnode_id": "b1", "list": "openai.com\n1.1.1.0/24"},
			{"bnode_id": "b2", "list": "api.openai.com"}
		]
	}`
	recConflict := httptest.NewRecorder()
	s.handleChains(recConflict, httptest.NewRequest("POST", "/api/chains", strings.NewReader(conflictPayload)))
	if recConflict.Code != 400 {
		t.Fatalf("子域名包含冲突应返回 400，实际 %d：%s", recConflict.Code, recConflict.Body.String())
	}

	// 3. 兜底 B 节点与分流组相同时应 400 拦截
	dupFallback := `{
		"inbound_id": "in-hy2",
		"mode": "split",
		"bnode_id": "b1",
		"routes": [{"bnode_id": "b1", "list": "openai.com"}]
	}`
	recDupFb := httptest.NewRecorder()
	s.handleChains(recDupFb, httptest.NewRequest("POST", "/api/chains", strings.NewReader(dupFallback)))
	if recDupFb.Code != 400 {
		t.Fatalf("兜底节点与分流组重复应返回 400，实际 %d：%s", recDupFb.Code, recDupFb.Body.String())
	}

	// 4. 合法的多 B 分流（B1 + B2 分流，其余走 B3 兜底）应创建成功，且 ApplySingBox 落盘成功
	validPayload := `{
		"name": "Hy2多路分流",
		"inbound_id": "in-hy2",
		"mode": "split",
		"bnode_id": "b3",
		"routes": [
			{"bnode_id": "b1", "list": "openai.com\n1.1.1.0/24"},
			{"bnode_id": "b2", "list": "netflix.com\n8.8.8.8"}
		]
	}`
	recOK := httptest.NewRecorder()
	s.handleChains(recOK, httptest.NewRequest("POST", "/api/chains", strings.NewReader(validPayload)))
	if recOK.Code != 200 {
		t.Fatalf("合法 Hy2 多 B 分流应返回 200，实际 %d：%s", recOK.Code, recOK.Body.String())
	}

	// 5. 删除 B1 节点时，该链不应整条被误删，而应自动剔除 B1 组、保留 B2 组和 B3 兜底
	if err := st.DeleteBNode("b1"); err != nil {
		t.Fatalf("删除 B1 失败：%v", err)
	}
	chains, _ := st.ListChains()
	if len(chains) != 1 {
		t.Fatalf("删掉其中一个 B 后分流链应仍在，实际链数量 %d", len(chains))
	}
	if len(chains[0].Routes) != 1 || chains[0].Routes[0].BNodeID != "b2" || chains[0].BNodeID != "b3" {
		t.Fatalf("删掉 B1 后应仅保留 B2 分流组和 B3 兜底，实际：%+v", chains[0])
	}
}

func TestCSRFProtectionBlocksCrossSitePost(t *testing.T) {
	s := newAuthTestServer(t, "admin1", "pass123456")
	c := loginCookie(t, s, `{"username":"admin1","password":"pass123456"}`)
	guarded := s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		okJSON(w, "passed")
	})

	// 跨站 Origin 发起 POST（模拟恶意站点诱导管理员提交表单）应被 403 拦截
	evilReq := httptest.NewRequest("POST", "http://panel.example.com:18081/api/settings/cert-manual", strings.NewReader("--boundary"))
	evilReq.Host = "panel.example.com:18081"
	evilReq.RemoteAddr = "203.0.113.50:54321"
	evilReq.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	evilReq.Header.Set("Origin", "https://evil.attacker.site")
	evilReq.AddCookie(c)
	recEvil := httptest.NewRecorder()
	guarded(recEvil, evilReq)
	if recEvil.Code != 403 {
		t.Fatalf("跨站 POST 应被 403 拦截，实际得到 %d", recEvil.Code)
	}

	// 同源 Origin 发起 POST 应正常放行
	goodReq := httptest.NewRequest("POST", "http://panel.example.com:18081/api/settings/cert-manual", strings.NewReader("--boundary"))
	goodReq.Host = "panel.example.com:18081"
	goodReq.RemoteAddr = "203.0.113.50:54321"
	goodReq.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	goodReq.Header.Set("Origin", "http://panel.example.com:18081")
	goodReq.AddCookie(c)
	recGood := httptest.NewRecorder()
	guarded(recGood, goodReq)
	if recGood.Code != 200 {
		t.Fatalf("同源 POST 应返回 200，实际得到 %d：%s", recGood.Code, recGood.Body.String())
	}
}
