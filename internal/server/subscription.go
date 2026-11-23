package server

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	"sssingbox/internal/proxy"
	"sssingbox/internal/store"
)

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

type subLocal struct {
	in   *store.Inbound
	addr string
}

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

// chainNameByInbound：已启用链按入口 ID 取名（与 base64 订阅的链名逻辑一致）。
func (s *Server) chainNameByInbound() map[string]string {
	chainNames := map[string]string{}
	if cl, _ := s.app.Store.ListChains(); cl != nil {
		for _, c := range cl {
			if c.Enabled && c.Name != "" {
				chainNames[c.InboundID] = c.Name
			}
		}
	}
	return chainNames
}

func (s *Server) subLink(in *store.Inbound) string {
	switch in.Protocol {
	case "naive":
		var cfg proxy.NaiveConfig
		_ = json.Unmarshal([]byte(in.Config), &cfg)
		return proxy.NaiveShareLink(cfg, in.Port, in.Name)
	case "wireguard":
		return ""
	}
	link, _ := s.inboundLinks(in)
	return link
}

func (s *Server) subLink6(in *store.Inbound) string {
	if in.Protocol == "wireguard" {
		return ""
	}
	link6, _ := s.inboundLinks6(in)
	return link6
}

func (s *Server) renderSubLinks(locals []subLocal, bnodes []*store.BNode, excluded map[string]bool) string {
	chainNames := s.chainNameByInbound()
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

// uniqueSubName 确保 Sing-box JSON / Clash YAML 中的节点 tag/name 唯一，避免同名节点导致整个客户端配置加载失败。
func uniqueSubName(used map[string]bool, base string) string {
	if base == "" {
		base = "node"
	}
	if !used[base] && base != "direct" && base != "🚀 节点选择" && base != "♻️ 自动选择" {
		used[base] = true
		return base
	}
	for i := 2; ; i++ {
		cand := fmt.Sprintf("%s-%d", base, i)
		if !used[cand] {
			used[cand] = true
			return cand
		}
	}
}

func (s *Server) renderSubSingBox(locals []subLocal, bnodes []*store.BNode) ([]byte, error) {
	var outs []interface{}
	var endpoints []interface{}
	used := map[string]bool{}
	chainNames := s.chainNameByInbound()
	for _, ln := range locals {
		in := ln.in
		tag := uniqueSubName(used, in.Name)
		obs, eps, err := proxy.ClientOutbounds(in.Protocol, in.Config, ln.addr, in.Port, in.SNI, tag)
		if err != nil {
			continue
		}
		for _, ob := range obs {
			outs = append(outs, ob)
		}
		for _, ep := range eps {
			endpoints = append(endpoints, ep)
		}
		if cn, ok := chainNames[in.ID]; ok {
			ctag := uniqueSubName(used, cn)
			cobs, ceps, cerr := proxy.ClientOutbounds(in.Protocol, in.Config, ln.addr, in.Port, in.SNI, ctag)
			if cerr == nil {
				for _, ob := range cobs {
					outs = append(outs, ob)
				}
				for _, ep := range ceps {
					endpoints = append(endpoints, ep)
				}
			}
		}
	}
	for _, b := range bnodes {
		tag := uniqueSubName(used, proxy.DecodeFragment(b.Name))
		obs, err := proxy.SingBoxBOutbound(b.Protocol, b.Config, tag)
		if err != nil {
			continue
		}
		for _, ob := range obs {
			outs = append(outs, ob)
		}
	}
	cfg := proxy.SingBoxClientConfig(outs, endpoints)
	return json.MarshalIndent(cfg, "", "  ")
}

func (s *Server) renderSubClash(locals []subLocal, bnodes []*store.BNode) ([]byte, error) {
	var proxies []map[string]interface{}
	used := map[string]bool{}
	chainNames := s.chainNameByInbound()
	for _, ln := range locals {
		in := ln.in
		name := uniqueSubName(used, in.Name)
		p, err := proxy.ClashProxy(in.Protocol, in.Config, ln.addr, in.Port, in.SNI, name)
		if err != nil {
			continue
		}
		proxies = append(proxies, p)
		if cn, ok := chainNames[in.ID]; ok {
			cname := uniqueSubName(used, cn)
			cp, cerr := proxy.ClashProxy(in.Protocol, in.Config, ln.addr, in.Port, in.SNI, cname)
			if cerr == nil {
				proxies = append(proxies, cp)
			}
		}
	}
	for _, b := range bnodes {
		name := uniqueSubName(used, proxy.DecodeFragment(b.Name))
		p, err := proxy.ClashBProxy(b.Protocol, b.Config, name)
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
	if tok == "" || strings.Contains(tok, "/") {
		http.NotFound(w, r)
		return
	}
	want := s.app.Store.GetSetting("sub_token")
	if len(tok) != len(want) || subtle.ConstantTimeCompare([]byte(tok), []byte(want)) != 1 {
		http.NotFound(w, r)
		return
	}
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
		body, err := s.renderSubClash(locals, bnodes)
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
