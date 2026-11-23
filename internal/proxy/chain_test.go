package proxy

import (
	"strings"
	"testing"
)

func TestCanBeChainAAndInboundTag(t *testing.T) {
	supported := []string{"vless", "vmess", "trojan", "hy2", "tuic", "anytls", "naive", "snell", "ss", "socks", "http", "shadowtls"}
	for _, p := range supported {
		if !CanBeChainA(p) {
			t.Errorf("协议 %s 应当支持作为入口 A", p)
		}
	}
	for _, p := range []string{"wireguard", "dokodemo", "unknown", ""} {
		if CanBeChainA(p) {
			t.Errorf("协议 %s 不应支持作为入口 A", p)
		}
	}

	// ShadowTLS 外层 detour 到内层 SS，路由必须绑在 in-<id>-ss 上才能嗅探目标域名
	if got := ChainInboundTag("node1", "shadowtls"); got != "in-node1-ss" {
		t.Fatalf("shadowtls 入站 tag 应为 in-node1-ss，实际 %q", got)
	}
	if got := ChainInboundTag("node1", "hy2"); got != "in-node1" {
		t.Fatalf("普通协议入站 tag 应为 in-node1，实际 %q", got)
	}
}

func TestValidateAndNormalizeRoutes_SuccessAndDedup(t *testing.T) {
	// 同一组内的大小写重复域名、等价网段应自动去重合并，不同组互不重叠应放行
	routes := []ChainRouteSpec{
		{
			BNodeID: "b1",
			List:    "https://OpenAI.com/chat\n*.openai.com\n1.1.1.0/24\n1.1.1.0/24\n# 注释\n",
		},
		{
			BNodeID: "b2",
			List:    "netflix.com\n8.8.8.8\n2606:4700:4700::1111\n",
		},
		{
			BNodeID: "b3",
			List:    "youtube.com\n1.1.2.0/24\n",
		},
	}
	norm, err := ValidateAndNormalizeRoutes(routes)
	if err != nil {
		t.Fatalf("无冲突的多组路由应校验通过，却报错：%v", err)
	}
	if len(norm) != 3 {
		t.Fatalf("应返回 3 组归一化清单，实际 %d", len(norm))
	}
	if norm[0] != "openai.com\n1.1.1.0/24" {
		t.Errorf("第 1 组组内去重结果不对：%q", norm[0])
	}
	if norm[1] != "netflix.com\n8.8.8.8\n2606:4700:4700::1111" {
		t.Errorf("第 2 组归一化结果不对：%q", norm[1])
	}
}

func TestValidateAndNormalizeRoutes_Conflicts(t *testing.T) {
	cases := []struct {
		name    string
		routes  []ChainRouteSpec
		wantSub string
	}{
		{
			name:    "空分流组拦截",
			routes:  nil,
			wantSub: "至少需要添加 1 个",
		},
		{
			name: "跨组选择同一个 B 节点拦截",
			routes: []ChainRouteSpec{
				{BNodeID: "b1", List: "openai.com"},
				{BNodeID: "b1", List: "netflix.com"},
			},
			wantSub: "同一个 B 节点",
		},
		{
			name: "跨组完全相同域名冲突（忽略大小写）",
			routes: []ChainRouteSpec{
				{BNodeID: "b1", List: "Google.com"},
				{BNodeID: "b2", List: "google.com"},
			},
			wantSub: "分流冲突",
		},
		{
			name: "前组父域名、后组子域名包含冲突",
			routes: []ChainRouteSpec{
				{BNodeID: "b1", List: "google.com"},
				{BNodeID: "b2", List: "mail.google.com"},
			},
			wantSub: "子域名包含关系",
		},
		{
			name: "前组子域名、后组父域名包含冲突",
			routes: []ChainRouteSpec{
				{BNodeID: "b1", List: "api.openai.com"},
				{BNodeID: "b2", List: "openai.com"},
			},
			wantSub: "子域名包含关系",
		},
		{
			name: "非父子关系的相似后缀域名不应误判（如 mygoogle.com 与 google.com）",
			routes: []ChainRouteSpec{
				{BNodeID: "b1", List: "google.com"},
				{BNodeID: "b2", List: "mygoogle.com"},
			},
			wantSub: "", // 期望通过
		},
		{
			name: "CIDR 包含单 IP 重叠冲突",
			routes: []ChainRouteSpec{
				{BNodeID: "b1", List: "1.1.1.0/24"},
				{BNodeID: "b2", List: "1.1.1.1"},
			},
			wantSub: "存在重叠",
		},
		{
			name: "大网段与小网段重叠冲突",
			routes: []ChainRouteSpec{
				{BNodeID: "b1", List: "10.0.1.0/24"},
				{BNodeID: "b2", List: "10.0.0.0/16"},
			},
			wantSub: "存在重叠",
		},
		{
			name: "IPv6 网段与单 IP 重叠冲突",
			routes: []ChainRouteSpec{
				{BNodeID: "b1", List: "2606:4700::/32"},
				{BNodeID: "b2", List: "2606:4700:4700::1111"},
			},
			wantSub: "存在重叠",
		},
	}

	for _, tc := range cases {
		_, err := ValidateAndNormalizeRoutes(tc.routes)
		if tc.wantSub == "" {
			if err != nil {
				t.Errorf("[%s] 不应报错，却得到：%v", tc.name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("[%s] 应当报错拦截，却放行了", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("[%s] 报错信息不符：期望含 %q，实际得到 %q", tc.name, tc.wantSub, err.Error())
		}
	}
}

func TestSingBoxChainRules_MultiRoutesAndFallback(t *testing.T) {
	rules := SingBoxChainRules([]ChainInput{
		{
			InboundTag:  "in-hy2-a",
			OutboundTag: "chain-b-fallback", // 其余未命中流量兜底走 B3
			Routes: []ChainRouteInput{
				{OutboundTag: "chain-b1", List: "openai.com\n1.1.1.0/24"},
				{OutboundTag: "chain-b2", List: "netflix.com"},
			},
		},
	})
	// 预期顺序：
	// 0: sniff
	// 1: in-hy2-a + domain_suffix [openai.com] -> chain-b1
	// 2: in-hy2-a + ip_cidr [1.1.1.0/24] -> chain-b1
	// 3: in-hy2-a + domain_suffix [netflix.com] -> chain-b2
	// 4: in-hy2-a (无条件兜底) -> chain-b-fallback
	if len(rules) != 5 {
		t.Fatalf("应生成 5 条规则，实际 %d：%v", len(rules), rules)
	}
	if rules[0]["action"] != "sniff" {
		t.Fatalf("第 0 条必须是 sniff：%v", rules[0])
	}
	if rules[1]["outbound"] != "chain-b1" || rules[2]["outbound"] != "chain-b1" {
		t.Fatalf("B1 的域名与 IP 规则顺序或出站不对：%v / %v", rules[1], rules[2])
	}
	if rules[3]["outbound"] != "chain-b2" {
		t.Fatalf("B2 的域名规则不对：%v", rules[3])
	}
	if rules[4]["outbound"] != "chain-b-fallback" {
		t.Fatalf("末尾兜底规则出站不对：%v", rules[4])
	}
	if _, hasDom := rules[4]["domain_suffix"]; hasDom {
		t.Fatalf("兜底规则不应带域名限制：%v", rules[4])
	}
}
