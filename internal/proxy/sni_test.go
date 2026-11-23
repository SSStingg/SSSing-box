package proxy

import (
	"net"
	"testing"
)

func TestIsCloudflareIP(t *testing.T) {
	// 104.17.0.0/13 是 Cloudflare 段：speedtest.net 当时就解析到这段。
	if !IsCloudflareIP(net.ParseIP("104.17.147.22")) {
		t.Fatal("104.17.147.22 应判定为 Cloudflare")
	}
	if !IsCloudflareIP(net.ParseIP("2606:4700:4700::1111")) {
		t.Fatal("2606:4700::/32 应判定为 Cloudflare")
	}
	for _, ip := range []string{"1.1.1.1", "104.68.241.34", "151.101.1.19", "23.216.149.143"} {
		if IsCloudflareIP(net.ParseIP(ip)) {
			t.Fatalf("%s 不应判定为 Cloudflare", ip)
		}
	}
}

func TestIsRealityMode(t *testing.T) {
	if !IsRealityMode("vless", "") || !IsRealityMode("vless", "reality") {
		t.Fatal("VLESS 默认/现实档是 Reality")
	}
	if IsRealityMode("vless", "ws") || IsRealityMode("vless", "h2") || IsRealityMode("vless", "httpupgrade") {
		t.Fatal("VLESS TLS 档不是 Reality")
	}
	if !IsRealityMode("trojan", "reality") {
		t.Fatal("Trojan 现实档是 Reality")
	}
	if IsRealityMode("trojan", "cf") || IsRealityMode("trojan", "h2") {
		t.Fatal("Trojan CF/TLS 档不是 Reality")
	}
	if IsRealityMode("hy2", "reality") || IsRealityMode("vmess", "") {
		t.Fatal("HY2/VMess 的 SNI 不是 Reality 伪装目标，不受禁 CF 规则约束")
	}
}

func TestSNIListNoCloudflare(t *testing.T) {
	// 池子已用公开 DoH 逐个验过解析结果：2026-11-02 实测仅 speedtest.net
	// 落在 Cloudflare 段（104.17.x），已从池子里删掉；同日扩池审计又淘汰
	// 8 个 CF 站（epicgames、razer、seagate、kingston、corsair、broadcom、
	// qualcomm、teamviewer），均未入池；这里锁死不再加回来。
	for _, c := range SNIList {
		if c.Domain == "www.speedtest.net" {
			t.Fatal("池子里不应再有 speedtest.net（Cloudflare）")
		}
	}
	if len(SNIList) != 30 {
		t.Fatalf("池子应为 30 个，得到 %d", len(SNIList))
	}
}

func TestRecommendSNIExcluding(t *testing.T) {
	// 排除多个域名后，随机结果永不命中被排除的。
	for i := 0; i < 200; i++ {
		c := RecommendSNIExcluding("www.samsung.com", "www.intel.com", "bing.com", "www.bing.com")
		if c.Domain == "www.samsung.com" || c.Domain == "www.intel.com" || c.Domain == "bing.com" || c.Domain == "www.bing.com" {
			t.Fatalf("excluded domain returned: %s", c.Domain)
		}
	}
	// 全部排除时回退到 SNIList[0]，不 panic、不返回空。
	c := RecommendSNIExcluding(poolDomains()...)
	if c.Domain == "" {
		t.Fatal("empty domain when pool exhausted")
	}
}

func poolDomains() []string {
	ds := make([]string, 0, len(SNIList))
	for _, c := range SNIList {
		ds = append(ds, c.Domain)
	}
	return ds
}

func TestRandomSnellObfsHost(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		h := RandomSnellObfsHost()
		if h == "" || h == "bing.com" || h == "www.bing.com" {
			t.Fatalf("bad snell obfs host: %q", h)
		}
		found := false
		for _, c := range SNIList {
			if c.Domain == h {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("host not in SNI pool: %q", h)
		}
		seen[h] = true
	}
	if len(seen) < 2 {
		t.Fatal("random snell host never varies")
	}
}

func TestRandomHandshakeHost(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		h := RandomHandshakeHost()
		if h == "" || h == "gateway.icloud.com" || h == "bing.com" || h == "www.bing.com" {
			t.Fatalf("bad handshake host: %q", h)
		}
		seen[h] = true
	}
	if len(seen) < 2 {
		t.Fatal("random handshake host never varies")
	}
}
