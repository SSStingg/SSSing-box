package proxy

import (
	"strings"
	"testing"
)

func TestParseHopPorts(t *testing.T) {
	if s, e, err := ParseHopPorts("20000-40000"); err != nil || s != 20000 || e != 40000 {
		t.Fatalf("valid range rejected: %d-%d err=%v", s, e, err)
	}
	for _, bad := range []string{"", "20000", "40000-20000", "0-100", "100-70000", "abc-def", "20000-40000-50000", "20000-20000"} {
		if _, _, err := ParseHopPorts(bad); err == nil {
			t.Fatalf("invalid range %q accepted", bad)
		}
	}
}

func TestValidateHopPorts(t *testing.T) {
	bound := map[int]bool{30000: true}
	if err := ValidateHopPorts("20000-40000", bound); err == nil {
		t.Fatalf("range overlapping bound UDP port 30000 accepted")
	}
	if err := ValidateHopPorts("20000-40000", bound, 30000); err != nil {
		t.Fatalf("exempt own port rejected: %v", err)
	}
	if err := ValidateHopPorts("40001-50000", bound); err != nil {
		t.Fatalf("non-overlapping range rejected: %v", err)
	}
}

func TestRenderHopScript(t *testing.T) {
	script := RenderHopScript([]HopRule{{Start: 20000, End: 40000, ToPort: 24443}, {Start: 50000, End: 51000, ToPort: 24444}})
	for _, want := range []string{
		"table inet sssingbox-hop",
		"type nat hook prerouting priority dstnat",
		"type nat hook output priority -100",
		"prerouting ct state new udp dport 20000-40000 fib daddr type local counter redirect to :24443",
		"output ct state new udp dport 20000-40000 fib daddr type local counter redirect to :24443",
		"prerouting ct state new udp dport 50000-51000 fib daddr type local counter redirect to :24444",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
}

func TestHy2LinkHop(t *testing.T) {
	base := Hy2Config{Password: "pw"}
	with := base
	with.HopPorts = "20000-40000"
	link := Hy2Link("1.2.3.4", 24443, "www.example.com", with, "hop-node")
	if !strings.Contains(link, "mport=20000-40000") || !strings.Contains(link, "ports=20000-40000") {
		t.Fatalf("hop range missing from link: %s", link)
	}
	plain := Hy2Link("1.2.3.4", 24443, "www.example.com", base, "plain-node")
	if strings.Contains(plain, "mport=") || strings.Contains(plain, "ports=") {
		t.Fatalf("hop params leaked into plain link: %s", plain)
	}
	bad := base
	bad.HopPorts = "garbage"
	badLink := Hy2Link("1.2.3.4", 24443, "www.example.com", bad, "bad-node")
	if strings.Contains(badLink, "mport=") || strings.Contains(badLink, "ports=") {
		t.Fatalf("invalid hop range emitted into link: %s", badLink)
	}
}

// 跳端口 nft 脚本：output 链不能用符号优先级 dstnat（nft 只认它在
// prerouting 上），须用数字 -100，否则任何带跳端口的 HY2 节点都建不出来。
func TestRenderHopScriptPriorities(t *testing.T) {
	script := RenderHopScript([]HopRule{{Start: 20000, End: 20005, ToPort: 8445}})
	lines := strings.Split(strings.TrimSpace(script), "\n")
	if len(lines) != 5 {
		t.Fatalf("hop script should have 5 lines (table + 2 chains + 2 rules), got %d:\n%s", len(lines), script)
	}
	if !strings.Contains(lines[1], "hook prerouting priority dstnat") {
		t.Fatalf("prerouting chain should keep priority dstnat:\n%s", script)
	}
	if !strings.Contains(lines[2], "hook output priority -100") {
		t.Fatalf("output chain must use numeric priority -100, got:\n%s", script)
	}
	if strings.Contains(lines[2], "dstnat") {
		t.Fatalf("output chain must not use dstnat:\n%s", script)
	}
}
