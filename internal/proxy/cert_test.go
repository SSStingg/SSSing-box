package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// GenSelfSignedCert 用 ECDSA P-256：算法、曲线、SAN 行为、配对加载。
func TestGenSelfSignedCertECDSA(t *testing.T) {
	dir := t.TempDir()
	for _, cn := range []string{"example.com", "10.0.0.1"} {
		certPath := filepath.Join(dir, "c-"+cn+".crt")
		keyPath := filepath.Join(dir, "c-"+cn+".key")
		if err := GenSelfSignedCert(certPath, keyPath, cn); err != nil {
			t.Fatalf("GenSelfSignedCert(%s): %v", cn, err)
		}
		b, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			t.Fatalf("no PEM block for %s", cn)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if cert.PublicKeyAlgorithm != x509.ECDSA {
			t.Fatalf("CN %s: PublicKeyAlgorithm = %v, want ECDSA", cn, cert.PublicKeyAlgorithm)
		}
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			t.Fatalf("CN %s: not P-256 ECDSA key", cn)
		}
		if ip := net.ParseIP(cn); ip != nil {
			if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(ip) {
				t.Fatalf("CN %s: IP SAN = %v, want [%s]", cn, cert.IPAddresses, cn)
			}
			if len(cert.DNSNames) != 0 {
				t.Fatalf("CN %s: DNSNames should be empty for IP, got %v", cn, cert.DNSNames)
			}
		} else {
			found := false
			for _, n := range cert.DNSNames {
				if n == cn {
					found = true
				}
			}
			if !found {
				t.Fatalf("CN %s: DNS SAN missing: %v", cn, cert.DNSNames)
			}
		}
		kb, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		kblock, _ := pem.Decode(kb)
		if kblock == nil || kblock.Type != "EC PRIVATE KEY" {
			t.Fatalf("CN %s: key PEM type = %v, want EC PRIVATE KEY", cn, kblock.Type)
		}
		if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
			t.Fatalf("CN %s: key pair does not load: %v", cn, err)
		}
	}
}
