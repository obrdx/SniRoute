package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func localObserver(t *testing.T, custom http.Handler) (clientConfig, *observer) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg, cert, err := newIdentity(pc.LocalAddr().String(), time.Now().Add(time.Hour))
	if err != nil {
		pc.Close()
		t.Fatal(err)
	}
	obs := &observer{cfg: cfg, seen: map[string]bool{}, log: new(bytes.Buffer)}
	if custom == nil {
		custom = obs
	}
	srv, tr, ln, err := listenObserver(pc, cert, custom)
	if err != nil {
		pc.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.ServeListener(ln) }()
	t.Cleanup(func() {
		srv.Close()
		ln.Close()
		tr.Close()
		pc.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("QUIC server leaked")
		}
	})
	return cfg, obs
}

func TestQUICReceiptPerSNIAndFreshConnections(t *testing.T) {
	var count atomic.Int64
	var secrets = make(chan string, 3)
	var actual atomic.Pointer[observer]
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		if r.TLS.DidResume || r.TLS.NegotiatedProtocol != "h3" || r.ProtoMajor != 3 {
			t.Error("not a fresh HTTP/3 connection")
		}
		exporter, err := r.TLS.ExportKeyingMaterial("sniroute-test", nil, 16)
		if err != nil {
			t.Error(err)
		}
		secrets <- string(exporter)
		actual.Load().ServeHTTP(w, r)
	})
	cfg, o := localObserver(t, handler)
	actual.Store(o)
	for _, sni := range []string{"www.google.com", "github.com", "self.invalid"} {
		got := probeQUIC(context.Background(), cfg, sni, 1, 3*time.Second)
		if got.Outcome != "receipt" || got.Receipt == nil || got.Receipt.SourceIP != "127.0.0.1" || got.Receipt.SNI != sni || got.Receipt.Nonce != got.Nonce {
			t.Fatalf("bad QUIC receipt: %+v", got)
		}
	}
	seen := map[string]bool{}
	for range 3 {
		secret := <-secrets
		if seen[secret] {
			t.Fatal("connection was reused")
		}
		seen[secret] = true
	}
	if count.Load() != 3 {
		t.Fatal("unexpected request count")
	}
}

func TestWrongPinSendsNoRequestOrCredential(t *testing.T) {
	var count atomic.Int64
	cfg, _ := localObserver(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { count.Add(1) }))
	cfg.Pin = strings.Repeat("00", 32)
	got := probeQUIC(context.Background(), cfg, "www.google.com", 1, 3*time.Second)
	if got.Outcome != "identity_mismatch" || got.Receipt != nil || count.Load() != 0 {
		t.Fatalf("credential exposed or wrong outcome: %+v; requests=%d", got, count.Load())
	}
}

func TestUDPFailureDoesNotFallBackToTCP(t *testing.T) {
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := udp.LocalAddr().String()
	tcp, err := net.Listen("tcp4", target)
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	udp.Close()
	defer tcp.Close()
	var count atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			c.Close()
		}
	}()
	cfg, _, _ := newIdentity(target, time.Now().Add(time.Hour))
	got := probeQUIC(context.Background(), cfg, "www.google.com", 1, 200*time.Millisecond)
	tcp.Close()
	<-done
	if got.Outcome == "receipt" || got.Receipt != nil || count.Load() != 0 {
		t.Fatalf("UDP failure fabricated a receipt or used TCP: %+v", got)
	}
}

func TestObserverAuthenticationReplayBoundsAndActualPeer(t *testing.T) {
	cfg, _, err := newIdentity("127.0.0.1:443", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	o := &observer{cfg: cfg, seen: map[string]bool{}, log: &log}
	call := func(data string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "https://observer/probe", strings.NewReader(data))
		r.RemoteAddr = "198.51.100.9:12345"
		r.Header.Set("X-Forwarded-For", "203.0.113.1")
		r.TLS = &tls.ConnectionState{HandshakeComplete: true, NegotiatedProtocol: "h3", ServerName: "www.google.com"}
		w := httptest.NewRecorder()
		o.ServeHTTP(w, r)
		return w
	}
	valid, _ := json.Marshal(requestBody{Nonce: strings.Repeat("ab", 16), Token: cfg.Token})
	if w := call(string(valid)); w.Code != 200 || !strings.Contains(w.Body.String(), "198.51.100.9") || strings.Contains(w.Body.String(), "203.0.113.1") {
		t.Fatalf("actual UDP peer was not used: %d %s", w.Code, w.Body)
	}
	if w := call(string(valid)); w.Code != 401 {
		t.Fatal("replay accepted")
	}
	if strings.Contains(log.String(), cfg.Token) {
		t.Fatal("credential entered observation log")
	}
	for _, bad := range []string{
		`{"nonce":"` + strings.Repeat("cd", 16) + `","token":"wrong"}`,
		`{"nonce":"x","token":"` + cfg.Token + `"}`,
		`{"nonce":"` + strings.Repeat("ef", 16) + `","token":"` + cfg.Token + `","extra":true}`,
		string(valid) + `{}`,
		`{"nonce":"` + strings.Repeat("a", maxBody) + `"}`,
	} {
		if w := call(bad); w.Code == 200 {
			t.Fatal("invalid input accepted")
		}
	}
	o.cfg.ExpiresAt = time.Now().Add(-time.Second)
	if w := call(strings.ReplaceAll(string(valid), strings.Repeat("ab", 16), strings.Repeat("aa", 16))); w.Code != 401 {
		t.Fatal("expired credential accepted")
	}
}

func TestClientRejectsUnboundOrMismatchedReceipts(t *testing.T) {
	for _, wrongSNI := range []bool{false, true} {
		t.Run(map[bool]string{true: "sni", false: "nonce"}[wrongSNI], func(t *testing.T) {
			cfg, _ := localObserver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body requestBody
				decodeOne(io.LimitReader(r.Body, maxBody), &body)
				rec := receipt{Nonce: body.Nonce, SNI: r.TLS.ServerName, SourceIP: "198.51.100.20", ObservedAt: time.Now()}
				if wrongSNI {
					rec.SNI = "other.example"
				} else {
					rec.Nonce = strings.Repeat("00", 16)
				}
				json.NewEncoder(w).Encode(rec)
			}))
			got := probeQUIC(context.Background(), cfg, "www.google.com", 1, 3*time.Second)
			if got.Outcome == "receipt" {
				t.Fatal("unbound receipt counted as an exit")
			}
			var summary bytes.Buffer
			writeSummary(&summary, experimentReport{SNIs: []string{got.SNI}, Results: []result{got}, Planned: 1})
			if strings.Contains(summary.String(), "198.51.100.20") {
				t.Fatal("mismatched receipt counted in summary")
			}
		})
	}
}

func TestClientReportAndCancelledCoverageNeverContainCredentials(t *testing.T) {
	cfg, _ := localObserver(t, nil)
	base := t.TempDir()
	config := filepath.Join(base, "client.json")
	if err := writePrivateJSON(config, cfg); err != nil {
		t.Fatal(err)
	}
	for _, cancelled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if cancelled {
			cancel()
		}
		path := filepath.Join(base, "report.json")
		var output bytes.Buffer
		err := runClient(ctx, []string{"-config", config, "-sni", "www.google.com", "-sni", "github.com", "-rounds", "1", "-out", path}, &output)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(cfg.Token)) || strings.Contains(output.String(), cfg.Token) {
			t.Fatal("credential exposed")
		}
		var report experimentReport
		if json.Unmarshal(data, &report) != nil || report.Planned != 2 || report.Cancelled != cancelled {
			t.Fatal("bad report coverage")
		}
		if cancelled && len(report.Results) != 0 {
			t.Fatal("unstarted attempts were recorded as failures")
		}
		if !cancelled && len(report.Results) != 2 {
			t.Fatal("missing probe results")
		}
	}
	if err := os.Chmod(config, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(config); err == nil {
		t.Fatal("publicly readable credentials accepted")
	}
}

func TestAuthenticationFailureStopsNewAttempts(t *testing.T) {
	var calls atomic.Int64
	cfg, _ := localObserver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
	}))
	base := t.TempDir()
	path := filepath.Join(base, "client.json")
	if err := writePrivateJSON(path, cfg); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(base, "report.json")
	if err := runClient(context.Background(), []string{"-config", path, "-sni", "www.google.com", "-sni", "github.com", "-rounds", "3", "-out", out}, io.Discard); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var report experimentReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Planned != 6 || len(report.Results) != 1 || report.Results[0].Outcome != "auth_failed" || calls.Load() != 1 {
		t.Fatalf("authentication failure turned into domain failures: %+v", report)
	}
}
