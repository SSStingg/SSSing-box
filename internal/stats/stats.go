package stats

import (
	"sync"
	"time"
)

// Poller queries nftables per-port counters and accumulates deltas into a sink.
// 旧版走 xray stats API；sing-box 没有按入站累计的接口，改走 nft（见 nft.go）。
// PortTags 由面板提供：端口 -> 入站 tag（"in-<id>"），因为 nft 只认端口不认 tag。
type Poller struct {
	PortTags func() map[int]string

	mu       sync.Mutex
	last     map[string][2]int64 // tag -> up, down
	seen     map[string]bool     // tag 已建过基线（见 PollOnce）
	lastPort map[string]int      // tag -> 建基线时的端口；端口一变就重建基线
	realtime map[string][2]int64 // tag -> current up/down rate (bytes/sec)
	lastPoll time.Time
	running  bool
}

func NewPoller(portTags func() map[int]string) *Poller {
	return &Poller{PortTags: portTags, last: map[string][2]int64{}, seen: map[string]bool{}, lastPort: map[string]int{}, realtime: map[string][2]int64{}}
}

// QueryAll 读 nft 计数器并按端口映射成 tag -> up/down。
func (p *Poller) QueryAll() (map[string][2]int64, error) {
	counters, err := Counters()
	if err != nil {
		return nil, err
	}
	tags := map[int]string{}
	if p.PortTags != nil {
		tags = p.PortTags()
	}
	res := map[string][2]int64{}
	for port, v := range counters {
		if tag, ok := tags[port]; ok {
			res[tag] = v
		}
	}
	return res, nil
}

// PollOnce queries and returns deltas per tag (handles core restarts).
// It also updates realtime rates.
func (p *Poller) PollOnce() (map[string][2]int64, error) {
	cur, err := p.QueryAll()
	if err != nil {
		return nil, err
	}
	// tag -> 当前端口：基线必须按 (tag, 端口) 认，节点改端口后
	// 旧端口计数器的值不能继续当新端口的基线。
	tagPort := map[string]int{}
	if p.PortTags != nil {
		for port, tag := range p.PortTags() {
			tagPort[tag] = port
		}
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	deltas := map[string][2]int64{}
	elapsed := now.Sub(p.lastPoll).Seconds()
	if p.lastPoll.IsZero() || elapsed <= 0 {
		elapsed = 1
	}
	for tag, v := range cur {
		if !p.seen[tag] || p.lastPort[tag] != tagPort[tag] {
			// 首次见到该 tag，或端口变了：只建基线，不产生增量。
			// 否则面板重启后首轮会把计数器里的全部历史流量再加
			// 一次（虚增、可误杀配额节点）；新节点的计数器本就
			// 从 0 起，基线只丢首轮 3 秒的量，可忽略。
			// 端口变了不断基线的话，旧端口的累计值会直接按新
			// 端口的增量算，同样是虚增。
			p.seen[tag] = true
			p.last[tag] = v
			p.lastPort[tag] = tagPort[tag]
			deltas[tag] = [2]int64{0, 0}
			p.realtime[tag] = [2]int64{0, 0}
			continue
		}
		prev := p.last[tag]
		var d [2]int64
		if v[0] >= prev[0] {
			d[0] = v[0] - prev[0]
		} else {
			d[0] = v[0] // core restarted: counters reset
		}
		if v[1] >= prev[1] {
			d[1] = v[1] - prev[1]
		} else {
			d[1] = v[1]
		}
		deltas[tag] = d
		p.realtime[tag] = [2]int64{int64(float64(d[0]) / elapsed), int64(float64(d[1]) / elapsed)}
		p.last[tag] = v
	}
	// tags that disappeared (inbound removed): drop from realtime only.
	// last 基线要保留：一轮 PortTags 瞬时为空不得清空全部基线，否则下轮
	// 所有 tag 都按“计数器重置”算，全量虚增。
	for tag := range p.realtime {
		if _, ok := cur[tag]; !ok {
			delete(p.realtime, tag)
		}
	}
	for tag := range p.lastPort {
		if _, ok := cur[tag]; !ok {
			delete(p.lastPort, tag)
		}
	}
	p.lastPoll = now
	return deltas, nil
}

// Realtime returns the last computed per-tag rates.
func (p *Poller) Realtime() map[string][2]int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string][2]int64, len(p.realtime))
	for k, v := range p.realtime {
		out[k] = v
	}
	return out
}

// Reset forgets last values (e.g. after core restart by panel).
// 下一轮各 tag 重新建基线，不产生虚增。
func (p *Poller) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.last = map[string][2]int64{}
	p.seen = map[string]bool{}
	p.lastPort = map[string]int{}
	p.lastPoll = time.Time{}
}

// ---------- hysteria2 trafficStats（已退役） ----------
//
// 旧版 Hy2Stats/Hy2Online 走 hysteria 二进制的 /traffic、/online 端点；
// 迁移后 Hy2 跑在 sing-box 里，没有这两个端点，用量统一走 nft，
// 在线数暂无来源（面板显示 0，见 SINGBOX-DESIGN.md 待核对清单）。
// 这两个函数已删除，别从 git 历史里捡回来。
