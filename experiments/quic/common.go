package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const applicationVersion = "1.0.0"
const maxBody = 1024

type clientConfig struct {
	Target    string    `json:"target"`
	Pin       string    `json:"probe_pin"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type requestBody struct {
	Nonce string `json:"nonce"`
	Token string `json:"token"`
}

type receipt struct {
	Nonce      string    `json:"nonce"`
	SNI        string    `json:"observed_sni"`
	SourceIP   string    `json:"source_ip"`
	ObservedAt time.Time `json:"observed_at"`
}

type result struct {
	SNI        string    `json:"sni"`
	Round      int       `json:"round"`
	Nonce      string    `json:"nonce"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	Outcome    string    `json:"outcome"`
	Error      string    `json:"error,omitempty"`
	Receipt    *receipt  `json:"receipt,omitempty"`
}

var limitations = []string{
	"独立 QUIC/SNI 实验：仅测试 QUIC over UDP，不代表普通 TCP/TLS 或真实网站访问的出口。",
	"仅短期凭证认证、单次随机数和观测端公钥校验成功、回执 SNI 与计划一致时，计入有效出口；否则出口为“未观测”。",
	"使用固定目标、QUIC v1、TLS 1.3、ALPN h3；关闭连接复用、会话恢复、0-RTT，不读取环境代理，不回退 TCP。",
	"观测端使用 QUIC Retry 验证来源地址；单观测端、样本有限，不判定封锁，不评价线路质量。",
	"没有回执不能说明观测端网卡没有收到 UDP 数据；需要结合抓包、监听和防火墙排查。",
	"本程序不改写或分片 QUIC CRYPTO 帧；不保证某个 SNI 一定位于单个 Initial 数据包中。",
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func isHex(s string, n int) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == n
}

func spkiPin(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(hash[:])
}

func newIdentity(target string, expiry time.Time) (clientConfig, tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return clientConfig{}, tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return clientConfig{}, tls.Certificate{}, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "SniRoute QUIC experiment"},
		NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: expiry.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return clientConfig{}, tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return clientConfig{}, tls.Certificate{}, err
	}
	token, err := randomHex(32)
	if err != nil {
		return clientConfig{}, tls.Certificate{}, err
	}
	return clientConfig{Target: target, Pin: spkiPin(leaf), Token: token, ExpiresAt: expiry},
		tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func validateConfig(c clientConfig) error {
	if target, err := netip.ParseAddrPort(c.Target); err != nil || target.Port() == 0 || target.Addr().IsUnspecified() || target.Addr().IsMulticast() {
		return errors.New("target 必须是观测端 IP:端口，IPv6 使用 [IP]:端口")
	}
	if !isHex(c.Pin, 32) || !isHex(c.Token, 32) || c.ExpiresAt.IsZero() {
		return errors.New("实验配置无效，请从观测端重新复制 client.json")
	}
	if !time.Now().Before(c.ExpiresAt) {
		return errors.New("实验凭证已过期，请重启实验观测端并重新复制 client.json")
	}
	return nil
}

func decodeOne(r io.Reader, v any) error {
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("JSON 必须只含一个对象")
	}
	return nil
}

func loadConfig(path string) (clientConfig, error) {
	var c clientConfig
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return c, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 4096 {
		return c, errors.New("实验配置须为不超过 4 KiB 的普通文件，权限 0600")
	}
	if err := decodeOne(io.LimitReader(f, 4097), &c); err != nil {
		return c, errors.New("无法解析实验配置")
	}
	return c, validateConfig(c)
}

func writePrivateJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".quic-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func privateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("目录 %s 权限须为 0700", path)
	}
	return nil
}

func cleanSNI(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if len(s) == 0 || len(s) > 253 {
		return "", errors.New("SNI 长度无效")
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", errors.New("SNI 不能是 IP 地址")
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("SNI 主机名格式无效")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("SNI 仅支持 ASCII 主机名")
			}
		}
	}
	return s, nil
}
