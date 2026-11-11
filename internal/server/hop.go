package server

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"sssingbox/internal/proxy"
)

// ApplyHop reconciles the nftables hop table for enabled hy2 nodes that
// have hopping on. It runs inside every ApplyAll (so on panel start too),
// which means a reboot or an outside nft flush is repaired on the next
// apply. Only the panel's own table is ever deleted — Guijia, Docker and
// anything else keep their own tables untouched.
// If nft is missing and no node needs hopping, this is a silent no-op
// (nothing to do). If nft is missing and a node DOES need hopping, it
// errors visibly: the feature cannot work, while the node itself still
// runs fine on its base listen port.
func (a *App) ApplyHop() error {
	inbounds, _ := a.Store.ListInbounds()
	var rules []proxy.HopRule
	for _, in := range inbounds {
		if in.Protocol != "hy2" || !in.Enabled {
			continue
		}
		var cfg proxy.Hy2Config
		if err := json.Unmarshal([]byte(in.Config), &cfg); err != nil {
			continue
		}
		if cfg.HopPorts == "" {
			continue
		}
		start, end, err := proxy.ParseHopPorts(cfg.HopPorts)
		if err != nil {
			// Cannot happen for nodes created/edited through the panel
			// (validated at input), but a stale DB value must not
			// silently disable hopping for every other node either:
			// surface it instead of skipping.
			return fmt.Errorf("节点 %s 的端口段 %q 无效：%v", in.Name, cfg.HopPorts, err)
		}
		rules = append(rules, proxy.HopRule{Start: start, End: end, ToPort: in.Port})
	}
	return applyHopRules(rules)
}

func applyHopRules(rules []proxy.HopRule) error {
	if _, err := exec.LookPath("nft"); err != nil {
		if len(rules) == 0 {
			return nil
		}
		return fmt.Errorf("端口跳跃需要 nftables，本机没有 nft 命令")
	}
	// Delete our own table first (error ignored: it does not exist on
	// the first run). The delete-then-add gap is milliseconds and only
	// affects NEW flows, which retry or fall back to the base port.
	exec.Command("nft", "delete", "table", "inet", proxy.HopTable).Run()
	if len(rules) == 0 {
		return nil
	}
	f, err := os.CreateTemp("", "ssshop-*.nft")
	if err != nil {
		return fmt.Errorf("写 nft 规则失败：%v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(proxy.RenderHopScript(rules)); err != nil {
		f.Close()
		return fmt.Errorf("写 nft 规则失败：%v", err)
	}
	f.Close()
	out, err := exec.Command("nft", "-f", f.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("应用端口跳跃规则失败：%v（%s）", err, string(out))
	}
	return nil
}
