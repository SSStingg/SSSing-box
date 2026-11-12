package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"sssingbox/internal/cores"
	"sssingbox/internal/proxy"
	"sssingbox/internal/store"
	"sssingbox/internal/sysinfo"
)

// App wires store, cores and config generation.
type App struct {
	Store *store.Store
	Mgr   *cores.Manager
	Sup   *cores.Supervisor
	// applyMu 串行化 ApplyAll：用户操作与后台配额循环不得交错写配置、
	// 校验与重启，否则两份配置会互相覆盖。
	applyMu sync.Mutex
	Dir     string

	publicIPCache string

	// IPv6 cache is memory-only with a TTL: unlike the IPv4 address,
	// a DHCPv6 address can change, so a permanently cached value (or
	// a value persisted in settings) would go stale and the IPv6
	// node link would silently point at a dead address.
	publicIPv6Cache   string
	publicIPv6Fetched time.Time
}

func NewApp(st *store.Store, dir string) *App {
	mgr := cores.NewManager(dir)
	return &App{
		Store: st,
		Mgr:   mgr,
		Sup:   cores.NewSupervisor(mgr),
		Dir:   dir,
	}
}

func (a *App) ConfigDir() string {
	d := filepath.Join(a.Dir, "configs")
	os.MkdirAll(d, 0755)
	return d
}

func (a *App) CertDir() string {
	d := filepath.Join(a.Dir, "certs")
	os.MkdirAll(d, 0755)
	return d
}

func writeAtomic(path string, data []byte) error {
	// 唯一临时文件 + 原子重命名：并发 Apply 不会互相截断同一个 .tmp；
	// 0600：这里写的是含全部节点密钥的 singbox.json 与证书私钥，
	// 同机其他本地用户不应可读。
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// mustConfig：入站 Config 解析失败时按节点名报错，而不是吞掉错误继续
// 用零值生成配置（零值曾导致无认证代理等静默错配，且报错里没有节点名）。
func mustConfig(in *store.Inbound, target interface{}) error {
	if err := json.Unmarshal([]byte(in.Config), target); err != nil {
		return fmt.Errorf("节点 %s 配置解析失败：%w", in.Name, err)
	}
	return nil
}

func toJSON(v interface{}) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

// genRealityKeypair generates an X25519 keypair in xray's own format:
// base64url WITHOUT padding (43 chars), exactly like `xray x25519` output
// (verified on the real binary: keys contain - and _, never + / or =).
// sing-box Reality uses the same key format, so the generator is unchanged.
func genRealityKeypair() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	priv = base64.RawURLEncoding.EncodeToString(k.Bytes())
	pub = base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
	return priv, pub, nil
}

// tlsModeDomain：TLS 档的域名，配置里没填就用节点 SNI。
func tlsModeDomain(cfgDomain, sni string) string {
	if cfgDomain != "" {
		return cfgDomain
	}
	return sni
}

// ApplySingBox builds the ONE singbox.json for all sing-box nodes
// plus chain outbounds/rules, validates it
// with `sing-box check`, and restarts sing-box. Old xray/hysteria configs
// are no longer generated; retiring those processes is ApplyAll's job,
// AFTER this succeeds, so a failed apply never leaves nodes down.
// listenConflict：两个监听是否会抢同一个端口。空/::/0.0.0.0 都是
// 通配（生成器默认监听 ::），通配与任何监听都冲突；两个具体的
// 不同地址可以共存，同地址则冲突。
func listenConflict(a, b string) bool {
	wa := a == "" || a == "::" || a == "0.0.0.0"
	wb := b == "" || b == "::" || b == "0.0.0.0"
	if wa || wb {
		return true
	}
	return a == b
}

// checkRealityDest：Reality 握手目标必须是 host:port 且端口合法。
// 空 dest 也报错：归一化会从 SNI 补 dest，走到 Apply 时 dest
// 还空着说明这条记录根本没经过归一化，握手 server 为空必死。
func checkRealityDest(nodeName, dest string) error {
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil || host == "" {
		return fmt.Errorf("节点 %s：Reality 目标地址 %q 必须是 host:port 形式", nodeName, dest)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("节点 %s：Reality 目标端口 %q 不合法（1-65535）", nodeName, portStr)
	}
	return nil
}

// checkPortConflicts：启用的同传输入站之间，同端口 + 冲突监听
// 必须在生成前拦住——否则 sing-box 起不来，整个 Apply 白白回滚。
// 创建/编辑时已拦重复端口，这里防的是直接改库、克隆竞态等旁路。
// TCP 与 UDP 端口是两套编号（2026-11-12）：不同传输的节点同端口
// 不冲突，只拦同传输的。
func checkPortConflicts(inbounds []*store.Inbound, group string) error {
	type claim struct {
		name, listen, protocol string
	}
	claims := map[int][]claim{}
	for _, in := range inbounds {
		if !in.Enabled {
			continue
		}
		var raw struct {
			Listen string `json:"listen"`
		}
		_ = json.Unmarshal([]byte(in.Config), &raw)
		claims[in.Port] = append(claims[in.Port], claim{in.Name, raw.Listen, in.Protocol})
	}
	for port, cs := range claims {
		for i := 0; i < len(cs); i++ {
			for j := i + 1; j < len(cs); j++ {
				if store.UDPOnlyProtocol(cs[i].protocol) != store.UDPOnlyProtocol(cs[j].protocol) {
					continue
				}
				if listenConflict(cs[i].listen, cs[j].listen) {
					return fmt.Errorf("%s节点 %s 与 %s 端口冲突：同占 %d", group, cs[i].name, cs[j].name, port)
				}
			}
		}
	}
	return nil
}

func (a *App) ApplySingBox() error {
	inbounds, err := a.Store.ListInbounds()
	if err != nil {
		return err
	}
	chains, err := a.Store.ListChains()
	if err != nil {
		return err
	}
	if err := checkPortConflicts(inbounds, "sing-box"); err != nil {
		return err
	}
	var sbInbounds []interface{}
	var endpoints []interface{}
	enabledAny := false
	for _, in := range inbounds {
		if !in.Enabled {
			continue
		}
		switch in.Protocol {
		case "vless":
			var cfg proxy.VLESSConfig
			if err := mustConfig(in, &cfg); err != nil {
				return err
			}
			// 生成器对未知 Mode 会静默走证书分支：Apply 层按节点名拦住。
			switch cfg.Mode {
			case "", "reality", "ws", "h2", "httpupgrade":
			default:
				return fmt.Errorf("节点 %s：不支持的 VLESS 传输模式 %s", in.Name, cfg.Mode)
			}
			// Reality 目标地址必须是 host:port：生成器的 SplitHostPort
			// 失败时静默按 host 全名 + 443 处理，写错的 dest（如带
			// 错端口、缺端口）会变成指向错误目标的握手，排障极难。
			if cfg.Mode == "" || cfg.Mode == "reality" {
				if err := checkRealityDest(in.Name, cfg.Dest); err != nil {
					return err
				}
			}
			if cfg.Mode == "ws" || cfg.Mode == "h2" || cfg.Mode == "httpupgrade" {
				domain := tlsModeDomain(cfg.Domain, in.SNI)
				cert, key, err := proxy.EnsureWSCert(a.ConfigDir(), "vless", in.ID, domain)
				if err != nil {
					return err
				}
				cfg.Domain, cfg.CertFile, cfg.KeyFile = domain, cert, key
			}
			sbInbounds = append(sbInbounds, proxy.SingBoxVLESSInbound("in-"+in.ID, in.Port, in.SNI, cfg))
		case "vmess":
			var cfg proxy.VMessConfig
			if err := mustConfig(in, &cfg); err != nil {
				return err
			}
			switch cfg.Mode {
			case "", "tcp", "http", "quic", "h2", "httpupgrade", "cf":
			default:
				return fmt.Errorf("节点 %s：不支持的 VMess 传输模式 %s", in.Name, cfg.Mode)
			}
			switch cfg.Mode {
			case "cf":
				domain := tlsModeDomain(cfg.Domain, in.SNI)
				cert, key, err := proxy.EnsureVMessCFCert(a.ConfigDir(), in.ID, domain)
				if err != nil {
					return err
				}
				cfg.Domain, cfg.CertFile, cfg.KeyFile = domain, cert, key
			case "h2", "httpupgrade", "quic":
				domain := tlsModeDomain(cfg.Domain, in.SNI)
				cert, key, err := proxy.EnsureWSCert(a.ConfigDir(), "vmess", in.ID, domain)
				if err != nil {
					return err
				}
				cfg.Domain, cfg.CertFile, cfg.KeyFile = domain, cert, key
			}
			sbInbounds = append(sbInbounds, proxy.SingBoxVMessInbound("in-"+in.ID, in.Port, cfg))
		case "ss":
			var cfg proxy.SSConfig
			if err := mustConfig(in, &cfg); err != nil {
				return err
			}
			sbInbounds = append(sbInbounds, proxy.SingBoxSSInbound("in-"+in.ID, in.Port, cfg))
		case "socks":
			var cfg proxy.SocksConfig
			if err := mustConfig(in, &cfg); err != nil {
				return err
			}
			// 空凭证会变成无认证公开代理：Apply 层硬拦，不让它落盘。
			if cfg.User == "" || cfg.Pass == "" {
				return fmt.Errorf("节点 %s：SOCKS 必须设置用户名和密码，空凭证会变成无认证公开代理", in.Name)
			}
			sbInbounds = append(sbInbounds, proxy.SingBoxSocksInbound("in-"+in.ID, in.Port, cfg))
		case "http":
			var cfg proxy.HTTPConfig
			if err := mustConfig(in, &cfg); err != nil {
				return err
			}
			if cfg.User == "" || cfg.Pass == "" {
				return fmt.Errorf("节点 %s：HTTP 必须设置用户名和密码，空凭证会变成无认证公开代理", in.Name)
			}
			sbInbounds = append(sbInbounds, proxy.SingBoxHTTPInbound("in-"+in.ID, in.Port, cfg))
		case "trojan":
			var cfg proxy.TrojanConfig
			if err := mustConfig(in, &cfg); err != nil {
				return err
			}
			switch cfg.Mode {
			case "", "reality", "cf", "h2", "httpupgrade":
			default:
				return fmt.Errorf("节点 %s：不支持的 Trojan 传输模式 %s", in.Name, cfg.Mode)
			}
			if cfg.Mode == "" || cfg.Mode == "reality" {
				if err := checkRealityDest(in.Name, cfg.Dest); err != nil {
					return err
				}
			}
			switch cfg.Mode {
			case "cf":
				domain := tlsModeDomain(cfg.Domain, in.SNI)
				cert, key, err := proxy.EnsureWSCert(a.ConfigDir(), "trojancf", in.ID, domain)
				if err != nil {
					return err
				}
				cfg.Domain, cfg.CertFile, cfg.KeyFile = domain, cert, key
			case "h2", "httpupgrade":
				domain := tlsModeDomain(cfg.Domain, in.SNI)
				cert, key, err := proxy.EnsureWSCert(a.ConfigDir(), "trojan", in.ID, domain)
				if err != nil {
					return err
				}
				cfg.Domain, cfg.CertFile, cfg.KeyFile = domain, cert, key
			}
			sbInbounds = append(sbInbounds, proxy.SingBoxTrojanInbound("in-"+in.ID, in.Port, in.SNI, cfg))
		case "hy2":
			var cfg proxy.Hy2Config
			if err := mustConfig(in, &cfg); err != nil {
				return err
			}
			// 限速写错（如 "abc"、"-5"）时生成器静默丢掉该项，
			// 节点变成不限速——用户以为限了、实际没限。在此拦住。
			for _, field := range []struct {
				name, val string
			}{{"上行限速", cfg.UpMbps}, {"下行限速", cfg.DownMbps}} {
				if field.val == "" {
					continue
				}
				v, err := strconv.Atoi(field.val)
				if err != nil || v <= 0 {
					return fmt.Errorf("节点 %s：%s必须是正整数 Mbps，当前 %q", in.Name, field.name, field.val)
				}
			}
			certPath := filepath.Join(a.CertDir(), "hy2-"+in.ID+".pem")
			keyPath := filepath.Join(a.CertDir(), "hy2-"+in.ID+".key")
			// 证书与私钥必须配对才复用：只 Stat 证书时，换掉一边的错配对
			// 会让之后每次 Apply 都卡在 sing-box 校验，全部更新冻结。
			if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
				cn := in.SNI
				if cn == "" {
					cn = "localhost"
				}
				if err := proxy.GenSelfSignedCert(certPath, keyPath, cn); err != nil {
					return fmt.Errorf("生成 hy2 证书失败：%w", err)
				}
			}
			sbInbounds = append(sbInbounds, proxy.SingBoxHy2Inbound("in-"+in.ID, in.Port, in.SNI, certPath, keyPath, cfg))
		case "tuic":
			var cfg proxy.TUICConfig
			if err := mustConfig(in, &cfg); err != nil {
				return err
			}
			domain := in.SNI
			if domain == "" {
				domain = "localhost"
			}
			cert, key, err := proxy.EnsureWSCert(a.ConfigDir(), "tuic", in.ID, domain)
			if err != nil {
				return err
			}
			sbInbounds = append(sbInbounds, proxy.SingBoxTUICInbound("in-"+in.ID, in.Port, in.SNI, cert, key, cfg))
		case "anytls":
			var cfg proxy.AnyTLSConfig
			if err := mustConfig(in, &cfg); err != nil {
				return err
			}
			domain := in.SNI
			if domain == "" {
				domain = "localhost"
			}
			cert, key, err := proxy.EnsureWSCert(a.ConfigDir(), "anytls", in.ID, domain)
			if err != nil {
				return err
			}
			sbInbounds = append(sbInbounds, proxy.SingBoxAnyTLSInbound("in-"+in.ID, in.Port, in.SNI, cert, key, cfg))
		case "naive":
			var cfg proxy.NaiveConfig
			if err := mustConfig(in, &cfg); err != nil {
				return err
			}
			// Naive 必须用 CA 证书：自签会破坏它的设计目的，绝不偷偷自签。
			if cfg.CertFile == "" || cfg.KeyFile == "" {
				return fmt.Errorf("Naive 节点 %s 缺少 CA 证书，请先上传证书", in.Name)
			}
			if _, err := os.Stat(cfg.CertFile); err != nil {
				return fmt.Errorf("Naive 节点 %s 的证书文件不存在：%s", in.Name, cfg.CertFile)
			}
			if _, err := os.Stat(cfg.KeyFile); err != nil {
				return fmt.Errorf("Naive 节点 %s 的私钥文件不存在：%s", in.Name, cfg.KeyFile)
			}
			sbInbounds = append(sbInbounds, proxy.SingBoxNaiveInbound("in-"+in.ID, in.Port, cfg, cfg.CertFile, cfg.KeyFile))
		case "snell":
			var cfg proxy.SnellConfig
			if err := mustConfig(in, &cfg); err != nil {
				return err
			}
			// 版本与 PSK 在创建/编辑时已归一化，这里按节点名再拦一次
			// 非法值，免得脏数据让整站 Apply 冻结。
			if cfg.Version != 5 && cfg.Version != 6 {
				return fmt.Errorf("节点 %s：不支持的 Snell 版本 %d", in.Name, cfg.Version)
			}
			if cfg.PSK == "" {
				return fmt.Errorf("节点 %s：Snell 缺少 PSK", in.Name)
			}
			if cfg.Version == 6 && (len(cfg.PSK) < 12 || len(cfg.PSK) > 255) {
				return fmt.Errorf("节点 %s：Snell v6 的 PSK 必须是 12-255 字节", in.Name)
			}
			sbInbounds = append(sbInbounds, proxy.SingBoxSnellInbound("in-"+in.ID, in.Port, cfg))
		case "shadowtls":
			var cfg proxy.ShadowTLSConfig
			if err := mustConfig(in, &cfg); err != nil {
				return err
			}
			if cfg.Password == "" {
				return fmt.Errorf("节点 %s：ShadowTLS 缺少密码", in.Name)
			}
			if cfg.Handshake == "" {
				return fmt.Errorf("节点 %s：ShadowTLS 缺少握手站域名", in.Name)
			}
			if cfg.InnerPort < 1 || cfg.InnerPort > 65535 {
				return fmt.Errorf("节点 %s：ShadowTLS 内层端口无效", in.Name)
			}
			sbInbounds = append(sbInbounds, proxy.SingBoxShadowTLSInbound("in-"+in.ID, in.Port, cfg))
			sbInbounds = append(sbInbounds, proxy.SingBoxShadowTLSInnerSS("in-"+in.ID+"-ss", cfg))
		case "wireguard":
			var cfg proxy.WGConfig
			if err := mustConfig(in, &cfg); err != nil {
				return err
			}
			// ClientIP 必须是合法 CIDR：留空或写成裸 IP 时，
			// allowed_ips 非法或 peer 永远匹配不上（P1-26）。
			if cfg.ClientIP == "" {
				return fmt.Errorf("WireGuard 节点 %s 未设置客户端 IP", in.Name)
			}
			if _, _, err := net.ParseCIDR(cfg.ClientIP); err != nil {
				return fmt.Errorf("WireGuard 节点 %s 的客户端 IP %q 不是合法 CIDR（如 10.0.0.2/32）", in.Name, cfg.ClientIP)
			}
			endpoints = append(endpoints, proxy.SingBoxWGEndpoint("wg-"+in.ID, in.Port, cfg))
		case "dokodemo":
			// 退役协议：绝不能因单个历史节点冻结全量 Apply。直接停用落盘，
			// 列表里显示已停用（真实状态），而不是让所有更新都失败。
			in.Enabled = false
			if err := a.Store.UpsertInbound(in); err != nil {
				return err
			}
			continue
		default:
			continue
		}
		enabledAny = true
	}
	// chains: A must be an enabled vless inbound; B converts to a sing-box
	// outbound. A converter failure aborts BEFORE writing config: a chain
	// that silently doesn't route is worse than a loud failure.
	var chainOutbounds []interface{}
	var chainInputs []proxy.ChainInput
	for _, ch := range chains {
		if !ch.Enabled {
			continue
		}
		in, err := a.Store.GetInbound(ch.InboundID)
		if err != nil {
			// 引用已删：删 A/B 时本应级联，残留的孤儿链自动停用，
			// 免得列表里永远显示启用却永不生效（行为测试 2.5）。
			// 注意与下面区分：A 只是停用/改协议时链式保持启用，
			// 恢复 A 后路由自动回来，不在这里动它。
			ch.Enabled = false
			_ = a.Store.UpsertChain(ch)
			continue
		}
		if !in.Enabled || in.Protocol != "vless" {
			continue
		}
		bn, err := a.Store.GetBNode(ch.BNodeID)
		if err != nil {
			ch.Enabled = false
			_ = a.Store.UpsertChain(ch)
			continue
		}
		tag := "chain-" + ch.ID
		ob, err := proxy.SingBoxBOutbound(bn.Protocol, bn.Config, tag)
		if err != nil {
			return fmt.Errorf("链式 %s 的 B 节点转换失败：%w（配置未写入，旧配置继续跑）", ch.Name, err)
		}
		chainOutbounds = append(chainOutbounds, ob)
		chainInputs = append(chainInputs, proxy.ChainInput{InboundTag: "in-" + ch.InboundID, OutboundTag: tag, List: ch.List, Direct: ch.Mode == "direct"})
	}
	rules := proxy.SingBoxChainRules(chainInputs)
	cfg := proxy.SingBoxFullConfig(sbInbounds, endpoints, chainOutbounds, rules)
	cfgPath := filepath.Join(a.ConfigDir(), "singbox.json")
	// 先写临时文件、校验通过后再上岗：坏配置绝不覆盖盘上正在跑的那份。
	// 以前是先落盘后校验，校验失败时坏配置残留，下次重启直接起不来。
	staging := cfgPath + ".staging"
	if err := writeAtomic(staging, toJSON(cfg)); err != nil {
		return err
	}
	if !a.Mgr.Installed("sing-box") {
		// 核心还没下载：配置先落盘等安装，无二进制可校验。
		if err := os.Rename(staging, cfgPath); err != nil {
			return err
		}
		return nil
	}
	if !enabledAny {
		if err := os.Rename(staging, cfgPath); err != nil {
			return err
		}
		a.Sup.Stop("sing-box")
		return nil
	}
	// 先校验再上岗：配置有问题时老进程继续跑，不被坏配置掀翻；
	// sing-box 的具体报错要带回来，否则只剩 exit status 1 没法定位。
	if out, err := exec.Command(a.Mgr.BinPath("sing-box"), "check", "-c", staging).CombinedOutput(); err != nil {
		_ = os.Remove(staging)
		return fmt.Errorf("sing-box 配置校验失败：%v：%s", err, strings.TrimSpace(string(out)))
	}
	// 备份正在跑的配置：重启失败（check 验不出的运行时问题，如端口被占）
	// 时可回滚，不让节点掀翻后无处可回。
	prevPath := cfgPath + ".prev"
	if b, err := os.ReadFile(cfgPath); err == nil {
		_ = os.WriteFile(prevPath, b, 0600)
	}
	if err := os.Rename(staging, cfgPath); err != nil {
		return err
	}
	if err := a.Sup.Restart("sing-box", []string{"run", "-c", cfgPath}); err != nil {
		rollbackSingBox(a, cfgPath, prevPath)
		return fmt.Errorf("启动 sing-box 失败（已回滚上一份配置）：%w", err)
	}
	// check 只验语法不验运行：重启后确认进程真活着，否则回滚。
	alive := false
	for i := 0; i < 15; i++ {
		if a.Sup.Status("sing-box").Running {
			alive = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !alive {
		rollbackSingBox(a, cfgPath, prevPath)
		return fmt.Errorf("sing-box 重启后未存活（已回滚上一份配置）")
	}
	return nil
}

// rollbackSingBox 把上一份配置搬回来并重启（上一份不存在时不做任何事）。
func rollbackSingBox(a *App, cfgPath, prevPath string) {
	if _, err := os.Stat(prevPath); err != nil {
		return
	}
	_ = os.Rename(prevPath, cfgPath)
	_ = a.Sup.Restart("sing-box", []string{"run", "-c", cfgPath})
}

// stopRetiredCores stops xray and per-node hysteria processes. Binaries
// stay on disk until the user confirms deletion; the panel just never starts
// them again. Called only after ApplySingBox succeeds.
func (a *App) stopRetiredCores() {
	a.Sup.Stop("xray")
	for _, name := range a.Sup.Names() {
		if strings.HasPrefix(name, "hy2-") {
			a.Sup.Stop(name)
		}
	}
}

// ApplyAll regenerates the sing-box config and restarts what is needed.
// Order matters: sing-box first, then retire old cores —
// a failed sing-box apply leaves the old cores running as fallback.
// ApplyAll calls serialize on applyMu: user PUTs and the background
// quota loop must not interleave config writes and restarts.
func (a *App) ApplyAll() error {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	sbErr := a.ApplySingBox()
	if sbErr == nil {
		a.stopRetiredCores()
	}
	hopErr := a.ApplyHop()
	if sbErr != nil {
		return sbErr
	}
	return hopErr
}

// PublicIPv6 returns the public IPv6, refetching at most once an hour.
// Returns "" when the machine has no IPv6 egress.
func (a *App) PublicIPv6() string {
	if a.publicIPv6Cache != "" && time.Since(a.publicIPv6Fetched) < time.Hour {
		return a.publicIPv6Cache
	}
	if ip := sysinfo.PublicIPv6(); ip != "" {
		a.publicIPv6Cache = ip
		a.publicIPv6Fetched = time.Now()
		return ip
	}
	// Transient fetch failure: keep serving the last known address
	// rather than dropping the IPv6 row and links for an hour.
	return a.publicIPv6Cache
}

// PublicIP returns cached public IPv4, fetching once if needed.
func (a *App) PublicIP() string {
	if a.publicIPCache != "" {
		return a.publicIPCache
	}
	if v := a.Store.GetSetting("public_ip"); v != "" {
		a.publicIPCache = v
		return v
	}
	ip := sysinfo.PublicIPv4()
	if ip != "" {
		a.publicIPCache = ip
		_ = a.Store.SetSetting("public_ip", ip)
	}
	return ip
}
