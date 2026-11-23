package proxy

import (
	"fmt"
	"strconv"
	"strings"
)

// Hy2 port hopping (v1.2.5): the sing-box hysteria2 inbound itself only
// listens on ONE port — hopping is a kernel NAT redirect of a UDP range
// onto that port, plus the client hopping across the range. The panel
// therefore never touches the sing-box inbound for hopping; it manages
// nftables rules (dedicated table, rebuilt on every ApplyAll and on panel
// start) and puts the range into the share link. Clients that do not
// understand hopping ignore the extra parameter and still connect via
// the base listen port, so hopping is a pure optimization, never a
// requirement for the node to work.

// ParseHopPorts parses a "START-END" range. Both ends are UDP ports.
func ParseHopPorts(s string) (int, int, error) {
	parts := strings.Split(strings.TrimSpace(s), "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("端口段格式应为 起始-结束，如 20000-40000")
	}
	start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("端口段格式应为 起始-结束，如 20000-40000")
	}
	if start < 1 || end > 65535 || start >= end {
		return 0, 0, fmt.Errorf("端口段无效：需 1<=起始<结束<=65535")
	}
	return start, end, nil
}

// ValidateHopPorts checks a range against currently bound UDP ports.
// Exempt ports (the hy2 node's own listen port, old and/or new on edit)
// are skipped: redirecting onto itself is a no-op, not a conflict. Any
// other bound UDP port inside the range would have its traffic stolen
// by the redirect, so it is rejected.
func ValidateHopPorts(s string, boundUDP map[int]bool, exempt ...int) error {
	start, end, err := ParseHopPorts(s)
	if err != nil {
		return err
	}
	ex := map[int]bool{}
	for _, p := range exempt {
		ex[p] = true
	}
	for p := start; p <= end; p++ {
		if !ex[p] && boundUDP[p] {
			return fmt.Errorf("端口段 %s 与本机已占用的 UDP 端口 %d 重叠", s, p)
		}
	}
	return nil
}

// HopRule is one nft redirect: new inbound UDP to [Start, End] goes to ToPort.
type HopRule struct {
	Start  int
	End    int
	ToPort int
}

// HopTable is the panel's dedicated nftables table. Only this table is
// ever deleted/recreated by the panel — Guijia, Docker and anything else
// keep their own tables untouched.
const HopTable = "sssingbox-hop"

// RenderHopScript renders the nft script that rebuilds the hop table
// from scratch (idempotent: ApplyAll runs it on every apply and on
// panel start, so a reboot or an outside flush is repaired on next start).
// Two chains, both scoped to packets destined for THIS host:
//   - prerouting: remote clients (the real use case) — packets arriving
//     on the NIC for this host's IP.
//   - output: locally generated packets to this host's own IP — a client
//     running on the same machine (and the panel's own self-test).
//
// Without the output chain, a same-machine client would bypass the
// redirect entirely (local traffic never traverses prerouting).
// fib daddr type local is load-bearing on both: without it, the output
// chain would hijack locally generated UDP to ANY destination whose port
// falls in the range (DNS, QUIC, game traffic), and the prerouting chain
// would hijack transit traffic on a forwarding host.
// ct state new is load-bearing too: without it, replies to outbound UDP
// (DNS answers, QUIC replies) whose ephemeral port falls inside the range
// would be redirected into hy2 and break. With it, only NEW flows are
// redirected.
func RenderHopScript(rules []HopRule) string {
	var b strings.Builder
	b.WriteString("table inet " + HopTable + "\n")
	b.WriteString("chain inet " + HopTable + " prerouting { type nat hook prerouting priority dstnat; policy accept; }\n")
	b.WriteString("chain inet " + HopTable + " output { type nat hook output priority -100; policy accept; }\n")
	for _, r := range rules {
		fmt.Fprintf(&b, "add rule inet %s prerouting ct state new udp dport %d-%d fib daddr type local counter redirect to :%d\n", HopTable, r.Start, r.End, r.ToPort)
		fmt.Fprintf(&b, "add rule inet %s output ct state new udp dport %d-%d fib daddr type local counter redirect to :%d\n", HopTable, r.Start, r.End, r.ToPort)
	}
	return b.String()
}
