package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"time"
)

// CertPin returns the hex SHA-256 of a certificate's DER encoding. It is what
// clients pin for the control service.
func CertPin(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// SPKIPin returns the hex SHA-256 of a certificate's SubjectPublicKeyInfo.
// It is what clients pin for the probe endpoint: pinning the key (not the
// certificate) lets the certificate be reissued without breaking clients.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// LoadOrCreateCert loads a PEM certificate+key pair from path, or generates a
// self-signed ECDSA certificate valid for hosts (plus localhost/loopback) and
// saves it there with mode 0600. The file holds the key, so it must stay
// private.
func LoadOrCreateCert(path, commonName string, hosts []string, validity time.Duration) (tls.Certificate, error) {
	if b, err := os.ReadFile(path); err == nil {
		return tls.X509KeyPair(b, b)
	} else if !errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if h != "" {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	pemBytes := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(pemBytes, pemBytes)
}

// LeafOf parses the leaf certificate of c.
func LeafOf(c tls.Certificate) (*x509.Certificate, error) {
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	if len(c.Certificate) == 0 {
		return nil, errors.New("server: certificate has no leaf")
	}
	return x509.ParseCertificate(c.Certificate[0])
}

// ControlPinFromFile returns the certificate pin of a PEM file written by
// LoadOrCreateCert, without creating anything.
func ControlPinFromFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	c, err := tls.X509KeyPair(b, b)
	if err != nil {
		return "", err
	}
	leaf, err := LeafOf(c)
	if err != nil {
		return "", err
	}
	return CertPin(leaf.Raw), nil
}
