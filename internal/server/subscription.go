package server

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	"sssingbox/internal/proxy"
	"sssingbox/internal/store"
)

// ---------- 订阅多格式 ----------
//
// 同一个订阅链接，三种输出，按客户端分：
//   - sing-box JSON：Hiddify / sing-box 官方客户端 / Karing / NekoBox。
//     完整客户端配置，13 个协议全在（ShadowTLS 双出站、Naive、
//     WireGuard 端点都在里面；Snell 出站 version 按 5→4 映射）。
//   - Clash YAML：mihomo / Clash Verge / FlClash / Stash。
//     mihomo 表示不了的跳过：Snell v6（mihomo 无 v6）、
//     其他节点全在；ShadowTLS 写成 ss + plugin shadow-tls，
//     Naive 写成 http + tls。
//   - base64 链接列表（默认）：v2rayN / Shadowrocket / Streisand 等。
//     一行一个链接，全是单行形式：ShadowTLS 与 WireGuard 不进列表
//     （ShadowTLS 的链接形态实测不通，WireGuard 没有可靠的单行链接），
//     Naive 写成 naive+https://，只在 JSON 与 YAML 里给。
//
// 格式选择：?format= 优先（别家面板的教训：导入器都用通用
// Dart/WebView UA，光靠 UA 猜分不出来，钉死格式才靠谱）；
// 没给 format 时按 User-Agent 猜——hiddify 必须先于 clash 检查，
// 因为 Hiddify 的 UA 里同时带 ClashMeta，顺序反了会错发 YAML。

// subFormat：本次订阅请求要出的格式：singbox | clash | base64。
func subFormat(r *http.Request) string {
	if f := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))); f != "" {
		switch f {
		case "singbox", "sing-box", "json", "sb":
			return "singbox"
		case "clash", "mihomo", "yaml", "yml":
			return "clash"
		case "base64", "links", "link", "plain", "uri", "v2ray":
			return "base64"
		}
	}
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	if strings.Contains(ua, "hiddify") {
		return "singbox"
	}
	if strings.Contains(ua, "sing-box") || strings.Contains(ua, "sfa") || strings.Contains(ua, "sfm") || strings.Contains(ua, "karing") || strings.Contains(ua, "nekobox") {
		return "singbox"
	}
	if strings.Contains(ua, "clash") || strings.Contains(ua, "mihomo") || strings.Contains(ua, "meta") || strings.Contains(ua, "stash") || strings.Contains(ua, "verge") || strings.Contains(ua, "flclash") {
		return "clash"
	}
	return "base64"
}

// subLocal：订阅里的一条本地节点。
type subLocal struct {
	in   *store.Inbound
	addr string // 订阅用的服务器地址（域名或公网 IP）
}

// collectSubNodes：订阅节点清单。本地启用节点（未取消勾选）+
// 其他节点（未取消勾选、非回环/内网地址）。链式不另起行：
// 链是服务端属性，走 A 节点本身就带链，JSON/YAML 里 A 出现
// 一次就够；链接列表里链名行保持原样（见 handleSub）。
func (s *Server) collectSubNodes(excluded map[string]bool) (locals []subLocal, bnodes []*store.BNode) {
	list, _ := s.app.Store.ListInbounds()
	for _, in := range list {
		if !in.Enabled {
			continue
		}
		if excluded["in:"+in.ID] {
			continue
		}
		locals = append(locals, subLocal{in: in, addr: s.effectiveAddress(in)})
	}
	bn, _ := s.app.Store.ListBNodes()
	for _, b := range bn {
		if excluded["bn:"+b.ID] {
			continue
		}
		if b.Link == "" {
			continue
		}
		if host, _, err := proxy.BNodeHostPort(b.Link); err == nil {
			if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
				continue
			}
		}
		bnodes = append(bnodes, b)
	}
	return locals, bnodes
}

// subLink：链接列表里的单行链接。"" 表示该节点不进链接列表
// （WireGuard 无单行形式；Naive 在这里给单行版；ShadowTLS 不进列表）。
func (s *Server) subLink(in *store.Inbound) string {
	switch in.Protocol {
	case "naive":
		var cfg proxy.NaiveConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.NaiveShareLink(cfg, in.Port, in.Name)
	case "shadowtls":
		// 链接列表里不发 ShadowTLS：实测 ss+plugin 形式在 sing-box 系
		// （plugin not found）与 mihomo（超时）都跑不通，留着就是个死节点。
		// ShadowTLS 只走 JSON（sing-box/Hiddify）与 YAML（mihomo）。
		return ""
	case "wireguard":
		return ""
	}
	link, _ := s.inboundLinks(in)
	return link
}

// subLink6：链接列表里的 v6 行。ShadowTLS/WireGuard 的 v6 内容是多行
// JSON/配置文本（弹窗里用 textarea 展示），不能进按行解析的链接列表——
// 双栈机器上不拦的话，base64 链接里会混进 25 行 JSON 碎行（2026-11-12
// 复查发现，RN 没 IPv6 所以一直没暴露）。
func (s *Server) subLink6(in *store.Inbound) string {
	if in.Protocol == "shadowtls" || in.Protocol == "wireguard" {
		return ""
	}
	link6, _ := s.inboundLinks6(in)
	return link6
}

// renderSubLinks：base64 链接列表（含链名行、v6 行，行为与旧版一致，
// 只是 Naive 换成单行版，ShadowTLS/WireGuard 不进列表）。
func (s *Server) renderSubLinks(locals []subLocal, bnodes []*store.BNode, excluded map[string]bool) string {
	chainNames := map[string]string{}
	if cl, _ := s.app.Store.ListChains(); cl != nil {
		for _, c := range cl {
			if c.Enabled && c.Name != "" {
				chainNames[c.InboundID] = c.Name
			}
		}
	}
	var links []string
	for _, ln := range locals {
		in := ln.in
		if link := s.subLink(in); link != "" {
			links = append(links, link)
		}
		if link6 := s.subLink6(in); link6 != "" {
			links = append(links, link6)
		}
		if cn, ok := chainNames[in.ID]; ok {
			cp := *in
			cp.Name = cn
			if clink := s.subLink(&cp); clink != "" {
				links = append(links, clink)
			}
			if clink6 := s.subLink6(&cp); clink6 != "" {
				links = append(links, clink6)
			}
		}
	}
	for _, b := range bnodes {
		links = append(links, b.Link)
	}
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
}

// renderSubSingBox：sing-box JSON 订阅。本地节点全转出站；
// 其他节点能转的也转（SingBoxBOutbound 覆盖 vless/vmess/trojan/
// hy2/ss/socks/http，解析失败的跳过，不拖垮整份订阅）。
func (s *Server) renderSubSingBox(locals []subLocal, bnodes []*store.BNode) ([]byte, error) {
	var outs []interface{}
	var endpoints []interface{}
	for _, ln := range locals {
		in := ln.in
		obs, eps, err := proxy.ClientOutbounds(in.Protocol, in.Config, ln.addr, in.Port, in.SNI, in.Name)
		if err != nil {
			continue
		}
		for _, ob := range obs {
			outs = append(outs, ob)
		}
		for _, ep := range eps {
			endpoints = append(endpoints, ep)
		}
	}
	for _, b := range bnodes {
		ob, err := proxy.SingBoxBOutbound(b.Protocol, b.Config, b.Name)
		if err != nil {
			continue
		}
		outs = append(outs, ob)
	}
	cfg := proxy.SingBoxClientConfig(outs, endpoints)
	return json.MarshalIndent(cfg, "", "  ")
}

// renderSubClash：Clash YAML 订阅。本地节点全转；
// 其他节点不转（xray 格式 → Clash 另需一层转换，本轮不做，
// 链接列表与 JSON 里仍有它们）。
func (s *Server) renderSubClash(locals []subLocal) ([]byte, error) {
	var proxies []map[string]interface{}
	for _, ln := range locals {
		in := ln.in
		p, err := proxy.ClashProxy(in.Protocol, in.Config, ln.addr, in.Port, in.SNI, in.Name)
		if err != nil {
			continue
		}
		proxies = append(proxies, p)
	}
	if proxies == nil {
		proxies = []map[string]interface{}{}
	}
	return yaml.Marshal(proxy.ClashConfig(proxies))
}

func (s *Server) handleSub(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.URL.Path, "/sub/")
	// token 必须是路径剩余部分的全部：以前 SplitN 取首段，
	// /sub/<真 token>/任意后缀 也能放行，白白放宽了口子。
	if tok == "" || strings.Contains(tok, "/") {
		http.NotFound(w, r)
		return
	}
	want := s.app.Store.GetSetting("sub_token")
	// 定长比较：普通 == 会在首个不同字节处提前返回，计时
	// 侧信道能逐字节磨出 token；长度不同直接判否。
	if len(tok) != len(want) || subtle.ConstantTimeCompare([]byte(tok), []byte(want)) != 1 {
		http.NotFound(w, r)
		return
	}
	// 订阅勾选：默认全包含；用户在订阅弹窗里取消勾选的，
	// 记在 sub_excluded 里（"in:<id>" / "bn:<id>"），新节点
	// 默认仍是包含的，不用每次手动再勾。
	excluded := map[string]bool{}
	var exList []string
	if raw := s.app.Store.GetSetting("sub_excluded"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &exList)
	}
	for _, k := range exList {
		excluded[k] = true
	}
	locals, bnodes := s.collectSubNodes(excluded)
	switch subFormat(r) {
	case "singbox":
		body, err := s.renderSubSingBox(locals, bnodes)
		if err != nil {
			http.Error(w, "生成 sing-box 订阅失败", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write(body)
	case "clash":
		body, err := s.renderSubClash(locals)
		if err != nil {
			http.Error(w, "生成 Clash 订阅失败", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		w.Write(body)
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(s.renderSubLinks(locals, bnodes, excluded)))
	}
}
