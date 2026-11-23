package stats

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const nftComment = "sssingbox-stats"

var nftTable = "sssingbox"

// SetDataDir fixes the stats table for this panel instance.
func SetDataDir(dir string) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	sum := sha256.Sum256([]byte(abs))
	nftTable = "sssingbox-" + hex.EncodeToString(sum[:])[:8]
}

// TableName reports the stats table this instance uses.
func TableName() string { return nftTable }

// ErrNoTable 表示 nft 统计表不存在。
var ErrNoTable = errors.New("nft 统计表不存在")

func nftRun(args ...string) (string, error) {
	cmd := exec.Command("nft", args...)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			msg := strings.TrimSpace(string(ee.Stderr))
			if msg != "" {
				return "", fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, msg)
			}
		}
		return "", fmt.Errorf("nft %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

func nftAvailable() bool {
	_, err := exec.LookPath("nft")
	return err == nil
}

// EnsureStatsTable：表或链缺失时创建，已存在则不动（不碰计数器）。
func EnsureStatsTable() error {
	if !nftAvailable() {
		return fmt.Errorf("系统没有 nft 命令，无法统计 sing-box 节点用量")
	}
	if _, err := nftRun("list", "table", "inet", nftTable); err != nil {
		return createStatsTable()
	}
	for _, chain := range []string{"in", "out"} {
		if _, err := nftRun("list", "chain", "inet", nftTable, chain); err != nil {
			hook := "input"
			if chain == "out" {
				hook = "output"
			}
			if _, err := nftRun("add", "chain", "inet", nftTable, chain, "{", "type", "filter", "hook", hook, "priority", "0;", "policy", "accept;", "}"); err != nil {
				return fmt.Errorf("补建 nft 链 %s 失败：%w", chain, err)
			}
		}
	}
	return nil
}

func createStatsTable() error {
	script := "table inet " + nftTable + " {\n" +
		"  chain in { type filter hook input priority 0; policy accept; }\n" +
		"  chain out { type filter hook output priority 0; policy accept; }\n" +
		"}\n"
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("创建 nft 表失败：%v %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

type nftRule struct {
	Chain    string
	Handle   int
	Protocol string // tcp | udp
	Field    string // dport | sport
	Port     int
	Bytes    int64
	Ours     bool
	NoLo     bool // 规则含 iifname/oifname != "lo"，不统计本机回环流量
}

func listChainRules(chain string) ([]nftRule, error) {
	out, err := nftRun("-j", "list", "chain", "inet", nftTable, chain)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "No such file") || strings.Contains(msg, "does not exist") {
			return nil, ErrNoTable
		}
		return nil, err
	}
	rules, err := parseNftRules([]byte(out))
	if err != nil {
		return nil, err
	}
	for i := range rules {
		rules[i].Chain = chain
	}
	return rules, nil
}

func listTableRules() ([]nftRule, error) {
	out, err := nftRun("-j", "list", "table", "inet", nftTable)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "No such file") || strings.Contains(msg, "does not exist") {
			return nil, ErrNoTable
		}
		return nil, err
	}
	return parseNftRules([]byte(out))
}

func parseNftRules(out []byte) ([]nftRule, error) {
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Chain   string `json:"chain"`
				Handle  int    `json:"handle"`
				Comment string `json:"comment"`
				Expr    []struct {
					Match *struct {
						Op   string `json:"op"`
						Left struct {
							Payload *struct {
								Protocol string `json:"protocol"`
								Field    string `json:"field"`
							} `json:"payload"`
							Meta *struct {
								Key string `json:"key"`
							} `json:"meta"`
						} `json:"left"`
						Right interface{} `json:"right"`
					} `json:"match"`
					Counter *struct {
						Bytes int64 `json:"bytes"`
					} `json:"counter"`
				} `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("解析 nft 规则失败：%w", err)
	}
	var rules []nftRule
	for _, item := range doc.Nftables {
		if item.Rule == nil {
			continue
		}
		r := nftRule{Chain: item.Rule.Chain, Handle: item.Rule.Handle, Ours: item.Rule.Comment == nftComment}
		for _, e := range item.Rule.Expr {
			if e.Match != nil {
				if e.Match.Left.Payload != nil {
					r.Protocol = e.Match.Left.Payload.Protocol
					r.Field = e.Match.Left.Payload.Field
					r.Port = toInt(e.Match.Right)
				}
				if e.Match.Op == "!=" && e.Match.Left.Meta != nil &&
					(e.Match.Left.Meta.Key == "iifname" || e.Match.Left.Meta.Key == "oifname") &&
					fmt.Sprint(e.Match.Right) == "lo" {
					r.NoLo = true
				}
			}
			if e.Counter != nil {
				r.Bytes = e.Counter.Bytes
			}
		}
		if (r.Field == "dport" || r.Field == "sport") && r.Port > 0 {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

func toInt(v interface{}) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}

// SyncStatsRules：让两条链的统计规则与 wantTCP/wantUDP 一致，并排除 lo 回环接口
// 防止本机流量虚增计数。TCP 与 UDP 节点同端口时按协议分别建规则，互不串台。
func SyncStatsRules(wantTCP, wantUDP map[int]bool) error {
	if err := EnsureStatsTable(); err != nil {
		return err
	}
	filterPorts := func(src map[int]bool) map[int]bool {
		out := map[int]bool{}
		for p := range src {
			if p >= 1 && p <= 65535 {
				out[p] = true
			}
		}
		return out
	}
	wantByProto := map[string]map[int]bool{
		"tcp": filterPorts(wantTCP),
		"udp": filterPorts(wantUDP),
	}
	for _, chain := range []string{"in", "out"} {
		rules, err := listChainRules(chain)
		if err != nil {
			return err
		}
		have := map[string]bool{}
		for _, r := range rules {
			if r.Ours && r.NoLo {
				have[r.Protocol+"|"+r.Field+"|"+strconv.Itoa(r.Port)] = true
			}
		}
		field := "dport"
		ifKey := "iifname"
		if chain == "out" {
			field = "sport"
			ifKey = "oifname"
		}
		for _, proto := range []string{"tcp", "udp"} {
			for port := range wantByProto[proto] {
				key := proto + "|" + field + "|" + strconv.Itoa(port)
				if have[key] {
					continue
				}
				if _, err := nftRun("add", "rule", "inet", nftTable, chain, ifKey, "!=", `"lo"`, proto, field, strconv.Itoa(port), "counter", "comment", `"sssingbox-stats"`); err != nil {
					return err
				}
			}
		}
		var delErr error
		for _, r := range rules {
			if !r.Ours || r.Protocol == "" || r.Field == "" {
				continue
			}
			if wantByProto[r.Protocol][r.Port] && r.NoLo {
				continue
			}
			if _, err := nftRun("delete", "rule", "inet", nftTable, chain, "handle", strconv.Itoa(r.Handle)); err != nil && delErr == nil {
				delErr = fmt.Errorf("删 %s 链 handle %d 失败：%w", chain, r.Handle, err)
			}
		}
		if delErr != nil {
			return delErr
		}
	}
	return nil
}

// Counters 读累计字节："tcp:443" / "udp:443" -> [up, down]。
func Counters() (map[string][2]int64, error) {
	res := map[string][2]int64{}
	rules, err := listTableRules()
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		if !r.Ours || (r.Protocol != "tcp" && r.Protocol != "udp") {
			continue
		}
		k := r.Protocol + ":" + strconv.Itoa(r.Port)
		cur := res[k]
		if r.Chain == "in" && r.Field == "dport" {
			cur[0] += r.Bytes
		} else if r.Chain == "out" && r.Field == "sport" {
			cur[1] += r.Bytes
		} else {
			continue
		}
		res[k] = cur
	}
	return res, nil
}
