package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// ---------- Hysteria2 ----------

type Hy2Config struct {
	Password     string `json:"password"`
	ObfsType     string `json:"obfs_type"` // "" or "salamander"
	ObfsPassword string `json:"obfs_password"`
	UpMbps       string `json:"up_mbps"`       // "" = auto
	DownMbps     string `json:"down_mbps"`     // "" = auto
	IgnoreClient bool   `json:"ignore_client"` // ignore client bandwidth
	Listen       string `json:"listen"`        // "" = all interfaces
	StatsPort    int    `json:"stats_port"`    // loopback trafficStats port (internal)
	StatsSecret  string `json:"stats_secret"`  // trafficStats secret (internal)
	HopPorts     string `json:"hop_ports"`     // "" = off, else "START-END" (port hopping, default off)
}

func DefaultHy2() Hy2Config {
	return Hy2Config{Password: randHex(8)}
}

// Hy2ServerYAML renders hysteria2 server config.
func Hy2ServerYAML(port int, certPath, keyPath string, cfg Hy2Config) string {
	var b strings.Builder
	listen := cfg.Listen
	if listen == "" {
		fmt.Fprintf(&b, "listen: :%d\n\n", port)
	} else {
		fmt.Fprintf(&b, "listen: %s:%d\n\n", listen, port)
	}
	b.WriteString("auth:\n  type: password\n  password: " + cfg.Password + "\n\n")
	b.WriteString("tls:\n  cert: " + certPath + "\n  key: " + keyPath + "\n\n")
	if cfg.ObfsType != "" {
		b.WriteString("obfs:\n  type: " + cfg.ObfsType + "\n")
		if cfg.ObfsPassword != "" {
			b.WriteString("  salamander:\n    password: " + cfg.ObfsPassword + "\n")
		}
		b.WriteString("\n")
	}
	if cfg.UpMbps != "" || cfg.DownMbps != "" {
		b.WriteString("bandwidth:\n")
		if cfg.UpMbps != "" {
			b.WriteString("  up: " + cfg.UpMbps + " mbps\n")
		}
		if cfg.DownMbps != "" {
			b.WriteString("  down: " + cfg.DownMbps + " mbps\n")
		}
		b.WriteString("\n")
	}
	if cfg.IgnoreClient {
		b.WriteString("ignoreClientBandwidth: true\n")
	}
	if cfg.StatsPort > 0 && cfg.StatsSecret != "" {
		fmt.Fprintf(&b, "\ntrafficStats:\n  listen: 127.0.0.1:%d\n  secret: %s\n", cfg.StatsPort, cfg.StatsSecret)
	}
	return b.String()
}

func Hy2Link(address string, port int, sni string, cfg Hy2Config, name string) string {
	// security=tls：HY2 本来就是全程 TLS，但官方 URI 方案里没有 security
	// 参数，有些客户端靠它决定要不要生成 TLS 块，缺了就下发无 TLS 的出站、
	// 连不上；带上对 sing-box/mihomo 等解析器无害（未知参数直接忽略，
	// HiddifyCli 与 mihomo 实测通过）。
	v := "security=tls&sni=" + qesc(sni) + "&insecure=1"
	if cfg.ObfsType != "" {
		v += "&obfs=" + qesc(cfg.ObfsType)
		if cfg.ObfsPassword != "" {
			v += "&obfs-password=" + qesc(cfg.ObfsPassword)
		}
	}
	// Port hopping: both spellings, same range. Different clients read
	// different keys (sing-box reads mport and ports; mihomo reads ports;
	// Shadowrocket reads mport); a client that reads neither still
	// connects via the base listen port, so this degrades gracefully.
	// Invalid ranges are omitted, never emitted broken.
	if _, _, err := ParseHopPorts(cfg.HopPorts); err == nil {
		v += "&mport=" + qesc(cfg.HopPorts) + "&ports=" + qesc(cfg.HopPorts)
	}
	return fmt.Sprintf("hysteria2://%s@%s?%s#%s", qesc(cfg.Password), hostPort(address, port), v, url.PathEscape(name))
}

// GenSelfSignedCert creates a self-signed cert/key pair (for hy2).
// ECDSA P-256：和 ACME 证书同算法，低配小鸡上生成快、握手包小，
// 现代客户端全支持。RSA 2048 已退役（生成慢、握手包大）。
func GenSelfSignedCert(certPath, keyPath, commonName string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature, // ECDSA 没有 KeyEncipherment（那是 RSA 的）
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{commonName},
	}
	// CN 是 IP 时必须放 IP SAN：现代 TLS 校验只看 SAN、不看 CN，
	// DNSNames 里写个 IP 字符串等于没写，按 IP 验就握手失败。
	if ip := net.ParseIP(commonName); ip != nil {
		tmpl.DNSNames = nil
		tmpl.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	certOut.Close()
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	ecDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	_ = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDer})
	keyOut.Close()
	// verify pair loads
	_, err = tls.LoadX509KeyPair(certPath, keyPath)
	return err
}
