package server

// ---------- 二次验证（2FA，龟甲模式） ----------
// TOTP（RFC 6238，SHA1，30 秒一步，6 位），只要标准验证器 App 就能用。
// 行为对齐龟甲：开通时必须输对一次动态码才生效；生效后只有新 IP 才要
// 再次验证动态码（同 IP 直接登录）；恢复码 10 个、一次性、用一次少一个。
// 本机回环（SSH 菜单、安装器）不走 2FA：能登本机的人已经有 root，
// 挡他没有意义；丢了 2FA 时菜单里的“关闭二次验证”就是恢复口。
// 全部标准库实现，不引新依赖；二维码用已有的 go-qrcode。

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var totpB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// randTOTPSecret：16 位 base32 密钥（A-Z2-7），验证器 App 直接能扫。
func randTOTPSecret() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return totpB32.EncodeToString(b)
}

func totpCodeAt(secret string, t time.Time) (string, error) {
	key, err := totpB32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		// 容忍带 = 填充的旧格式。
		key, err = base32.StdEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
		if err != nil {
			return "", err
		}
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(t.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (int(sum[off]&0x7f) << 24) | (int(sum[off+1]) << 16) | (int(sum[off+2]) << 8) | int(sum[off+3])
	return fmt.Sprintf("%06d", code%1000000), nil
}

// verifyTOTP：前后各容忍一步（手机时钟差 30 秒内都能过）。
func verifyTOTP(secret, code string, t time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	for _, d := range []int64{-1, 0, 1} {
		if c, err := totpCodeAt(secret, t.Add(time.Duration(d)*30*time.Second)); err == nil && c == code {
			return true
		}
	}
	return false
}

func totpOTPAuthURL(username, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", "SSSing-box")
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/SSSing-box:" + url.PathEscape(username) + "?" + v.Encode()
}

// 恢复码：10 个 XXXX-XXXX，去掉易混淆的 0/O/1/I，一次性。
const recoveryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func genRecoveryCodes() []string {
	codes := make([]string, 0, 10)
	for len(codes) < 10 {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		var sb strings.Builder
		for i, x := range b {
			if i == 4 {
				sb.WriteByte('-')
			}
			sb.WriteByte(recoveryAlphabet[int(x)%len(recoveryAlphabet)])
		}
		codes = append(codes, sb.String())
	}
	return codes
}

func hashRecoveryCodes(codes []string) string {
	hashes := make([]string, 0, len(codes))
	for _, c := range codes {
		h, _ := bcrypt.GenerateFromPassword([]byte(c), bcrypt.DefaultCost)
		hashes = append(hashes, string(h))
	}
	b, _ := json.Marshal(hashes)
	return string(b)
}

// tryRecoveryCode：命中则把这条从库里删掉（一次性），返回是否命中。
func (s *Server) tryRecoveryCode(code string) bool {
	raw := s.app.Store.GetSetting("totp_recovery")
	if raw == "" {
		return false
	}
	var hashes []string
	if err := json.Unmarshal([]byte(raw), &hashes); err != nil {
		return false
	}
	for i, h := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(strings.TrimSpace(code))) == nil {
			hashes = append(hashes[:i], hashes[i+1:]...)
			b, _ := json.Marshal(hashes)
			_ = s.app.Store.SetSetting("totp_recovery", string(b))
			return true
		}
	}
	return false
}

func (s *Server) recoveryLeft() int {
	raw := s.app.Store.GetSetting("totp_recovery")
	if raw == "" {
		return 0
	}
	var hashes []string
	if err := json.Unmarshal([]byte(raw), &hashes); err != nil {
		return 0
	}
	return len(hashes)
}

// ---------- TOTP 密钥加密 ----------
// totp_secret/totp_pending 是 TOTP 的根密钥：拿到它就能无限生成动态码，
// 以前是明文躺在 settings 表里（库文件一泄就等于 2FA 白开）。
// 用 AES-256-GCM 加密后入库，密钥存在数据目录的 .totp_key
// （0600，32 字节随机，首次使用时生成）。密文格式 "v1:"+base64(nonce‖密文)。
// 读到旧明文时懒迁移：读一次就地重写成密文（老面板升级后第一次读自动转）。
// 注意：.totp_key 丢了，已开通的 2FA 就解不开——登录会直接拒绝（fail-closed，
// 绝不跳过 2FA 放行），只能走本机 SSH 菜单的“关闭二次验证”恢复；密钥文件
// 与库文件是分开管的，别一起删。备份时两个都要备。
const totpKeyFile = ".totp_key"

func (s *Server) totpKey() ([]byte, error) {
	if s.app.Dir == "" {
		return nil, fmt.Errorf("数据目录未设置，无法读写 TOTP 密钥文件")
	}
	path := filepath.Join(s.app.Dir, totpKeyFile)
	if raw, err := os.ReadFile(path); err == nil {
		if key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw))); err == nil && len(key) == 32 {
			return key, nil
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0600); err != nil {
		return nil, err
	}
	return key, nil
}

func (s *Server) encryptTOTPSecret(plain string) (string, error) {
	key, err := s.totpKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return "v1:" + base64.StdEncoding.EncodeToString(sealed), nil
}

func (s *Server) decryptTOTPSecret(stored string) (string, error) {
	key, err := s.totpKey()
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, "v1:"))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("密文过短")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// totpSecretState：TOTP 密钥的读取状态。none=库里没值（没开通）；
// ok=有值且已解出明文；broken=库里有 v1: 密文但解不开（.totp_key
// 丢了或值损坏）。broken 与 none 必须区分开：以前 getTOTPSecretValue
// 解密失败也返回 ""，登录判断 secret != "" 就把 2FA 整个跳过，密钥
// 一丢等于 2FA 白开——注释写的是“宁可 2FA 暂时验不过”，实际却是放行。
type totpSecretState int

const (
	totpSecretNone   totpSecretState = iota // 库里没值：没开通
	totpSecretOK                            // 有值，已解出明文
	totpSecretBroken                        // 库里有值但解不开
)

// totpSecretRead：读 TOTP 密钥类设置（totp_secret / totp_pending），
// 返回状态与明文。旧明文读到就地升级成密文。broken 时明文为空，调用方
// 必须按“已开通但不可用”处理（登录拒绝、状态报 broken），绝不能当成
// 没开通。注意 totpKey() 在密钥文件缺失时会自动生成一把新密钥，旧密文
// 从此永久解不开——broken 不是临时状态，恢复只能走 SSH 菜单关 2FA。
func (s *Server) totpSecretRead(name string) (totpSecretState, string) {
	stored := s.app.Store.GetSetting(name)
	if stored == "" {
		return totpSecretNone, ""
	}
	if !strings.HasPrefix(stored, "v1:") {
		if enc, err := s.encryptTOTPSecret(stored); err == nil {
			_ = s.app.Store.SetSetting(name, enc)
		}
		return totpSecretOK, stored
	}
	plain, err := s.decryptTOTPSecret(stored)
	if err != nil {
		log.Printf("TOTP 密钥解密失败（%s）：%v", name, err)
		return totpSecretBroken, ""
	}
	return totpSecretOK, plain
}

// getTOTPSecretValue：只返回明文的旧读法，保留给测试与不需要区分状态
// 的内部读取。注意：解密失败返回 ""，与“没开通”无法区分——凡是安全判断
// （登录、2FA 状态）一律用 totpSecretRead，不要用这个。
func (s *Server) getTOTPSecretValue(name string) string {
	_, plain := s.totpSecretRead(name)
	return plain
}

// setTOTPSecretValue：加密后写 TOTP 密钥类设置。空值直接清掉。
func (s *Server) setTOTPSecretValue(name, plain string) {
	if plain == "" {
		_ = s.app.Store.SetSetting(name, "")
		return
	}
	enc, err := s.encryptTOTPSecret(plain)
	if err != nil {
		log.Printf("TOTP 密钥加密失败（%s）：%v", name, err)
		return
	}
	_ = s.app.Store.SetSetting(name, enc)
}

// ---------- 已验证 IP ----------

// 已验证 IP：30 天过期。以前是永久信任，IP 一换主人就等于 2FA 白开。
// 新格式 [{"ip":"1.2.3.4","exp":1730000000}]；旧格式 ["1.2.3.4"]（纯字符串
// 列表）读到按已过期处理——不信任，但也不报错，下次登录重新验证即可。
const totpIPTrustDays = 30

type totpIPEntry struct {
	IP  string `json:"ip"`
	Exp int64  `json:"exp"`
}

func (s *Server) totpIPVerified(ip string) bool {
	raw := s.app.Store.GetSetting("totp_ips")
	if raw == "" {
		return false
	}
	var entries []totpIPEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return false // 旧格式是 []string，解不进 struct，整体按过期处理
	}
	now := time.Now().Unix()
	for _, e := range entries {
		if e.IP == ip && e.Exp > now {
			return true
		}
	}
	return false
}

func (s *Server) totpMarkIP(ip string) {
	if ip == "" {
		return
	}
	var entries []totpIPEntry
	_ = json.Unmarshal([]byte(s.app.Store.GetSetting("totp_ips")), &entries)
	now := time.Now().Unix()
	kept := entries[:0]
	for _, e := range entries {
		if e.Exp > now && e.IP != ip {
			kept = append(kept, e)
		}
	}
	kept = append(kept, totpIPEntry{IP: ip, Exp: now + int64(totpIPTrustDays)*24*3600})
	if len(kept) > 100 { // 只留最近 100 个，防无限长。
		kept = kept[len(kept)-100:]
	}
	b, _ := json.Marshal(kept)
	_ = s.app.Store.SetSetting("totp_ips", string(b))
}

func (s *Server) totpClear() {
	_ = s.app.Store.SetSetting("totp_secret", "")
	_ = s.app.Store.SetSetting("totp_pending", "")
	_ = s.app.Store.SetSetting("totp_recovery", "")
	_ = s.app.Store.SetSetting("totp_ips", "")
}

// ---------- 登录第二步的临时凭证 ----------

type totpChallenge struct {
	username string
	remember bool
	exp      time.Time
}

func (s *Server) totpChallengePut(tok string, ch totpChallenge) {
	s.totpTmpMu.Lock()
	if s.totpTmp == nil {
		s.totpTmp = map[string]totpChallenge{}
	}
	s.totpTmp[tok] = ch
	s.totpTmpMu.Unlock()
}

// totpChallengeTake：一次性凭证。取走即删——输错码也不能复用同一个凭证
// 反复试；要试就重新登录领新凭证（登录限流在那一层拦着）。
func (s *Server) totpChallengeTake(tok string) (totpChallenge, bool) {
	s.totpTmpMu.Lock()
	defer s.totpTmpMu.Unlock()
	ch, ok := s.totpTmp[tok]
	delete(s.totpTmp, tok)
	if !ok || time.Now().After(ch.exp) {
		return totpChallenge{}, false
	}
	return ch, true
}

// totpQR：验证器扫码用的二维码 PNG（data URL，前端直接当 img src）。
func totpQR(otpauth string) (string, error) {
	png, err := qrcodeEncode(otpauth)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}
