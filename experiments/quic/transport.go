package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func quicConfig(timeout time.Duration) *quic.Config {
	return &quic.Config{Versions: []quic.Version{quic.Version1}, HandshakeIdleTimeout: timeout, MaxIdleTimeout: timeout,
		MaxIncomingStreams: 1, MaxIncomingUniStreams: 3, InitialStreamReceiveWindow: 16 << 10, MaxStreamReceiveWindow: 16 << 10,
		InitialConnectionReceiveWindow: 64 << 10, MaxConnectionReceiveWindow: 64 << 10, Allow0RTT: false}
}

type observer struct {
	cfg  clientConfig
	mu   sync.Mutex
	seen map[string]bool
	log  io.Writer
}

func (o *observer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/probe" || r.URL.RawQuery != "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	defer r.Body.Close()
	var body requestBody
	if decodeOne(r.Body, &body) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !time.Now().Before(o.cfg.ExpiresAt) || !isHex(body.Nonce, 16) || subtle.ConstantTimeCompare([]byte(body.Token), []byte(o.cfg.Token)) != 1 {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	if r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.NegotiatedProtocol != "h3" {
		http.Error(w, "handshake required", http.StatusBadRequest)
		return
	}
	source, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "invalid peer", http.StatusInternalServerError)
		return
	}
	rec := receipt{Nonce: body.Nonce, SNI: r.TLS.ServerName, SourceIP: source.Addr().Unmap().String(), ObservedAt: time.Now().UTC()}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.seen[body.Nonce] || len(o.seen) >= 4096 {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	o.seen[body.Nonce] = true
	if err := json.NewEncoder(o.log).Encode(rec); err != nil {
		http.Error(w, "observation write failed", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(rec)
}

func listenObserver(pc net.PacketConn, cert tls.Certificate, handler http.Handler) (*http3.Server, *quic.Transport, *quic.EarlyListener, error) {
	active := make(chan struct{}, 64)
	tr := &quic.Transport{Conn: pc, VerifySourceAddress: func(net.Addr) bool { return true },
		ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
			select {
			case active <- struct{}{}:
				context.AfterFunc(ctx, func() { <-active })
				return ctx, nil
			default:
				return nil, errors.New("experiment connection limit")
			}
		}}
	tlsCfg := http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true})
	ln, err := tr.ListenEarly(tlsCfg, quicConfig(8*time.Second))
	if err != nil {
		tr.Close()
		return nil, nil, nil, err
	}
	srv := &http3.Server{Handler: handler, MaxHeaderBytes: 8192, IdleTimeout: 8 * time.Second}
	return srv, tr, ln, nil
}

func probeQUIC(parent context.Context, cfg clientConfig, sni string, round int, timeout time.Duration) (out result) {
	start := time.Now()
	out = result{SNI: sni, Round: round, StartedAt: start.UTC(), Outcome: "quic_failed"}
	defer func() { out.DurationMS = time.Since(start).Milliseconds() }()
	nonce, err := randomHex(16)
	if err != nil {
		out.Error = "无法生成探测随机数"
		return
	}
	out.Nonce = nonce
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	var identityFailed atomic.Bool
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{ServerName: sni, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			SessionTicketsDisabled: true, InsecureSkipVerify: true, // replaced by SPKI verification
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 || subtle.ConstantTimeCompare([]byte(spkiPin(state.PeerCertificates[0])), []byte(cfg.Pin)) != 1 {
					identityFailed.Store(true)
					return errors.New("观测端公钥不匹配；未发送实验凭证")
				}
				return nil
			}},
		QUICConfig: quicConfig(timeout),
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			// Fully finish the pinned handshake before HTTP/3 can send the body.
			return quic.DialAddr(ctx, cfg.Target, tlsCfg, qcfg)
		},
	}
	defer tr.Close()
	data, err := json.Marshal(requestBody{Nonce: nonce, Token: cfg.Token})
	if err != nil {
		out.Error = "无法构造探测请求"
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+cfg.Target+"/probe", bytes.NewReader(data))
	if err != nil {
		out.Error = "无法构造探测请求"
		return
	}
	req.Host = sni
	req.Header.Set("Content-Type", "application/json")
	resp, err := tr.RoundTrip(req) // direct QUIC only: no proxy, redirect or TCP fallback
	if err != nil {
		switch {
		case identityFailed.Load():
			out.Outcome = "identity_mismatch"
		case parent.Err() != nil:
			out.Outcome = "cancelled"
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			out.Outcome = "timeout"
		default:
			var timeoutError net.Error
			if errors.As(err, &timeoutError) && timeoutError.Timeout() {
				out.Outcome = "timeout"
			}
		}
		out.Error = err.Error()
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		out.Outcome, out.Error = "http_failed", fmt.Sprintf("观测端返回 HTTP %d", resp.StatusCode)
		if resp.StatusCode == http.StatusUnauthorized {
			out.Outcome, out.Error = "auth_failed", "实验凭证失效或认证被拒绝，请重新复制观测端生成的 client.json"
		}
		return
	}
	var rec receipt
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(b) > 4096 || decodeOne(bytes.NewReader(b), &rec) != nil || rec.Nonce != nonce || rec.ObservedAt.IsZero() {
		out.Outcome, out.Error = "invalid_receipt", "QUIC 回执无效，出口未观测"
		return
	}
	if ip, err := netip.ParseAddr(rec.SourceIP); err != nil || ip.IsUnspecified() || ip.IsMulticast() {
		out.Outcome, out.Error = "invalid_receipt", "回执来源 IP 无效"
		return
	}
	out.Receipt = &rec
	if rec.SNI != sni {
		out.Outcome, out.Error = "sni_mismatch", "观测端收到的 SNI 与计划不同，不纳入域名出口统计"
		return
	}
	out.Outcome = "receipt"
	return
}

// Ensure a failed local file open never silently switches to stdout logging.
func observationLog(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
