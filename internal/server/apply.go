package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
	Store   *store.Store
	Mgr     *cores.Manager
	Sup     *cores.Supervisor
	applyMu sync.Mutex
	Dir     string

	ipMu          sync.Mutex
	publicIPCache string

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

func genRealityKeypair() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	priv = base64.RawURLEncoding.EncodeToString(k.Bytes())
	pub = base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
	return priv, pub, nil
}

func tlsModeDomain(cfgDomain, sni string) string {
	if cfgDomain != "" {
		return cfgDomain
	}
	return sni
}

func listenConflict(a, b string) bool {
	wa := a == "" || a == "::" || a == "0.0.0.0"
	wb := b == "" || b == "::" || b == "0.0.0.0"
	if wa || wb {
		return true
	}
	return a == b
}

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
		if in.Protocol == "shadowtls" {
			var stc proxy.ShadowTLSConfig
			if json.Unmarshal([]byte(in.Config), &stc) == nil && stc.InnerPort > 0 {
				claims[stc.InnerPort] = append(claims[stc.InnerPort], claim{in.Name + "(内层SS)", "127.0.0.1", "ss"})
			}
		}
	}
	for port, cs := range claims {
		for i := 0; i < len(cs); i++ {
			for j := i + 1; j < len(cs); j++ {
				if !store.ProtocolsShareTransport(cs[i].protocol, cs[j].protocol) {
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
			switch cfg.Mode {
			case "", "reality", "ws", "h2", "httpupgrade":
			default:
				return fmt.Errorf("节点 %s：不支持的 VLESS 传输模式 %s", in.Name, cfg.Mode)
			}
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
			cn := in.SNI
			if cn == "" {
				cn = "localhost"
			}
			needCert := true
			if b, err := os.ReadFile(certPath); err == nil {
				if block, _ := pem.Decode(b); block != nil {
					if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
						nameOK := false
						if ip := net.ParseIP(cn); ip != nil {
							for _, cip := range cert.IPAddresses {
								if cip.Equal(ip) {
									nameOK = true
									break
								}
							}
						} else {
							nameOK = cert.Subject.CommonName == cn
							for _, dn := range cert.DNSNames {
								if dn == cn {
									nameOK = true
									break
								}
							}
						}
						if nameOK && cert.NotAfter.After(time.Now().Add(7*24*time.Hour)) {
							if _, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
								needCert = false
							}
						}
					}
				}
			}
			if needCert {
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
			if cfg.ClientIP == "" {
				return fmt.Errorf("WireGuard 节点 %s 未设置客户端 IP", in.Name)
			}
			if _, _, err := net.ParseCIDR(cfg.ClientIP); err != nil {
				return fmt.Errorf("WireGuard 节点 %s 的客户端 IP %q 不是合法 CIDR（如 10.0.0.2/32）", in.Name, cfg.ClientIP)
			}
			endpoints = append(endpoints, proxy.SingBoxWGEndpoint("wg-"+in.ID, in.Port, cfg))
		case "dokodemo":
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

	// 链式与多节点分流：支持除 WireGuard 外全部入站协议做 A 节点，B 出站按 BNode ID 去重复用。
	var chainOutbounds []interface{}
	var chainInputs []proxy.ChainInput
	emittedB := map[string]string{} // bnodeID -> outbound tag

	ensureBOutbound := func(chainName string, bn *store.BNode) (string, error) {
		if tag, ok := emittedB[bn.ID]; ok {
			return tag, nil
		}
		tag := "chain-b-" + bn.ID
		obs, err := proxy.SingBoxBOutbound(bn.Protocol, bn.Config, tag)
		if err != nil {
			return "", fmt.Errorf("链式 %s 的 B 节点 %s 转换失败：%w（配置未写入，旧配置继续跑）", chainName, bn.Name, err)
		}
		emittedB[bn.ID] = tag
		// ShadowTLS 一个 B 节点出两个出站（SS 在前、detour 在后），路由指向 SS 的 tag；
		// 其余协议只有一个出站，循环照样成立。
		for _, ob := range obs {
			chainOutbounds = append(chainOutbounds, ob)
		}
		return tag, nil
	}

	for _, ch := range chains {
		if !ch.Enabled {
			continue
		}
		in, err := a.Store.GetInbound(ch.InboundID)
		if err != nil {
			return fmt.Errorf("链式 %s 的入口 A 节点不存在（可能已被删除），请删除该链式或重新选择入口", ch.Name)
		}
		if !in.Enabled || !proxy.CanBeChainA(in.Protocol) {
			continue
		}
		inTag := proxy.ChainInboundTag(in.ID, in.Protocol)

		if ch.Mode == "direct" {
			bn, err := a.Store.GetBNode(ch.BNodeID)
			if err != nil {
				return fmt.Errorf("链式 %s 的落地 B 节点不存在（可能已被删除），请重新选择 B 节点", ch.Name)
			}
			outTag, err := ensureBOutbound(ch.Name, bn)
			if err != nil {
				return err
			}
			chainInputs = append(chainInputs, proxy.ChainInput{
				InboundTag:  inTag,
				OutboundTag: outTag,
				Direct:      true,
			})
			continue
		}

		// 多路分流模式
		var rtInputs []proxy.ChainRouteInput
		for i, r := range ch.Routes {
			bn, err := a.Store.GetBNode(r.BNodeID)
			if err != nil {
				return fmt.Errorf("链式 %s 第 %d 组的 B 节点不存在（可能已被删除），请删除该组或重新选择 B 节点", ch.Name, i+1)
			}
			outTag, err := ensureBOutbound(ch.Name, bn)
			if err != nil {
				return err
			}
			rtInputs = append(rtInputs, proxy.ChainRouteInput{
				OutboundTag: outTag,
				List:        r.List,
			})
		}
		fbTag := ""
		if ch.BNodeID != "" {
			bn, err := a.Store.GetBNode(ch.BNodeID)
			if err != nil {
				return fmt.Errorf("链式 %s 的兜底 B 节点不存在（可能已被删除），请重新选择或清空兜底", ch.Name)
			}
			fbTag, err = ensureBOutbound(ch.Name, bn)
			if err != nil {
				return err
			}
		}
		if len(rtInputs) == 0 {
			if fbTag == "" {
				return fmt.Errorf("链式 %s 没有可用的分流组且未设置兜底 B 节点，无法生效，请检查分流组与 B 节点", ch.Name)
			}
			return fmt.Errorf("链式 %s 未配置任何分流组，请添加分流组或改为全局直通模式", ch.Name)
		}
		chainInputs = append(chainInputs, proxy.ChainInput{
			InboundTag:  inTag,
			OutboundTag: fbTag,
			Routes:      rtInputs,
			Direct:      false,
		})
	}

	rules := proxy.SingBoxChainRules(chainInputs)
	cfg := proxy.SingBoxFullConfig(sbInbounds, endpoints, chainOutbounds, rules)
	cfgPath := filepath.Join(a.ConfigDir(), "singbox.json")
	staging := cfgPath + ".staging"
	if err := writeAtomic(staging, toJSON(cfg)); err != nil {
		return err
	}
	if !a.Mgr.Installed("sing-box") {
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
	if out, err := exec.Command(a.Mgr.BinPath("sing-box"), "check", "-c", staging).CombinedOutput(); err != nil {
		_ = os.Remove(staging)
		return fmt.Errorf("sing-box 配置校验失败：%v：%s", err, strings.TrimSpace(string(out)))
	}
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

func rollbackSingBox(a *App, cfgPath, prevPath string) {
	if _, err := os.Stat(prevPath); err != nil {
		return
	}
	_ = os.Rename(prevPath, cfgPath)
	_ = a.Sup.Restart("sing-box", []string{"run", "-c", cfgPath})
}

func (a *App) stopRetiredCores() {
	a.Sup.Stop("xray")
	for _, name := range a.Sup.Names() {
		if strings.HasPrefix(name, "hy2-") {
			a.Sup.Stop(name)
		}
	}
}

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

func (a *App) PublicIPv6() string {
	a.ipMu.Lock()
	if a.publicIPv6Cache != "" && time.Since(a.publicIPv6Fetched) < time.Hour {
		ip := a.publicIPv6Cache
		a.ipMu.Unlock()
		return ip
	}
	cached := a.publicIPv6Cache
	a.ipMu.Unlock()

	if ip := sysinfo.PublicIPv6(); ip != "" {
		a.ipMu.Lock()
		a.publicIPv6Cache = ip
		a.publicIPv6Fetched = time.Now()
		a.ipMu.Unlock()
		return ip
	}
	return cached
}

func (a *App) PublicIP() string {
	a.ipMu.Lock()
	if a.publicIPCache != "" {
		ip := a.publicIPCache
		a.ipMu.Unlock()
		return ip
	}
	a.ipMu.Unlock()

	if v := a.Store.GetSetting("public_ip"); v != "" {
		a.ipMu.Lock()
		a.publicIPCache = v
		a.ipMu.Unlock()
		return v
	}
	ip := sysinfo.PublicIPv4()
	if ip != "" {
		a.ipMu.Lock()
		a.publicIPCache = ip
		a.ipMu.Unlock()
		_ = a.Store.SetSetting("public_ip", ip)
	}
	return ip
}
