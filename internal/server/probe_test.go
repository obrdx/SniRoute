package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type probeRig struct {
	ps       *ProbeServer
	events   chan Event
	mu       sync.Mutex
	requests []ReceiptRequest
	observed []Observed
}

// startProbe runs a ProbeServer whose receipt hook is a fake: it returns a
// receipt unless the credential is "bad".
func startProbe(t *testing.T, cfg ProbeConfig) *probeRig {
	t.Helper()
	cfg.Addr = "127.0.0.1:0"
	rig := &probeRig{events: make(chan Event, 64)}
	rig.ps = NewProbeServer(cfg, newProbeCert(t), ProbeHooks{
		OnEvent: func(ev Event) { rig.events <- ev },
		OnReceipt: func(rr ReceiptRequest, o Observed) (*Receipt, Outcome, error) {
			rig.mu.Lock()
			rig.requests = append(rig.requests, rr)
			rig.observed = append(rig.observed, o)
			rig.mu.Unlock()
			if rr.Credential == "bad" {
				return nil, OutcomeUnknownCredential, nil
			}
			return &Receipt{AttemptID: rr.AttemptID, SourceIP: o.Remote.Addr().String(), ObservedSNI: o.SNI, SNIMatch: true, ObservedAt: o.At}, OutcomeAccepted, nil
		},
	})
	if err := rig.ps.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { rig.ps.Serve(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after cancel")
		}
	})
	return rig
}

func (r *probeRig) waitStatus(t *testing.T, want Status) Event {
	t.Helper()
	timeout := time.After(3 * time.Second)
	for {
		select {
		case ev := <-r.events:
			if ev.Status == want {
				return ev
			}
		case <-timeout:
			t.Fatalf("timed out waiting for status %s", want)
		}
	}
}

// dialTLS connects with the given SNI. Certificate checks are skipped here;
// pinning is the client package's job and is tested there.
func dialTLS(t *testing.T, addr, sni string) *tls.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	tc := tls.Client(conn, &tls.Config{ServerName: sni, NextProtos: []string{"http/1.1"}, InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return tc
}

func post(t *testing.T, tc *tls.Conn, path, body string) (*http.Response, map[string]any) {
	t.Helper()
	fmt.Fprintf(tc, "POST %s HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", path, len(body), body)
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func TestProbeReceipt(t *testing.T) {
	rig := startProbe(t, ProbeConfig{})
	tc := dialTLS(t, rig.ps.Addr().String(), "www.cloudflare.com")
	if got := tc.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Errorf("ALPN = %q", got)
	}

	resp, out := post(t, tc, "/probe", `{"path":"p","attempt_id":"att_1","credential":"c"}`)
	if resp.StatusCode != 200 || out["source_ip"] != "127.0.0.1" || out["observed_sni"] != "www.cloudflare.com" || out["attempt_id"] != "att_1" {
		t.Fatalf("receipt: %d %v", resp.StatusCode, out)
	}
	if want := tc.LocalAddr().(*net.TCPAddr).AddrPort(); rig.observed[0].Remote != want {
		t.Errorf("observed remote %v, want %v", rig.observed[0].Remote, want)
	}

	// The pre-handshake event carries the SNI and the ClientHello digest.
	ev := rig.waitStatus(t, StatusReceived)
	if ev.SNI != "www.cloudflare.com" || ev.Digest == [32]byte{} {
		t.Errorf("event: %+v", ev)
	}
}

func TestProbeRejections(t *testing.T) {
	rig := startProbe(t, ProbeConfig{})
	addr := rig.ps.Addr().String()

	if resp, out := post(t, dialTLS(t, addr, "a.com"), "/probe", `{"path":"p","attempt_id":"a","credential":"bad"}`); resp.StatusCode != 401 || out["error"] != "unauthorized" {
		t.Errorf("bad credential: %d %v", resp.StatusCode, out)
	}
	if resp, _ := post(t, dialTLS(t, addr, "a.com"), "/other", `{}`); resp.StatusCode != 404 {
		t.Errorf("wrong path: %d", resp.StatusCode)
	}
	if resp, _ := post(t, dialTLS(t, addr, "a.com"), "/probe", `{"path":"p","bogus":1}`); resp.StatusCode != 400 {
		t.Errorf("unknown field: %d", resp.StatusCode)
	}
	if resp, _ := post(t, dialTLS(t, addr, "a.com"), "/probe", strings.Repeat("x", maxProbeBody+1)); resp.StatusCode != 413 {
		t.Errorf("big body: %d", resp.StatusCode)
	}
	rig.mu.Lock()
	n := len(rig.requests)
	rig.mu.Unlock()
	if n != 1 { // only the "bad credential" request reached the hook
		t.Errorf("hook called %d times, want 1", n)
	}

	// Garbage after a good handshake: connection dropped, diagnostic event.
	tc := dialTLS(t, addr, "a.com")
	tc.Write([]byte("\x00\x01garbage\r\n\r\n"))
	rig.waitStatus(t, StatusBadRequest)
}

func TestProbeInvalidAndTimeout(t *testing.T) {
	rig := startProbe(t, ProbeConfig{ReadTimeout: 200 * time.Millisecond})
	addr := rig.ps.Addr().String()

	c1, _ := net.Dial("tcp", addr)
	defer c1.Close()
	c1.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	if ev := rig.waitStatus(t, StatusInvalid); ev.Err == nil {
		t.Error("invalid event without error")
	}

	c2, _ := net.Dial("tcp", addr)
	defer c2.Close()
	c2.Write([]byte{0x16, 0x03}) // partial header, then silence
	rig.waitStatus(t, StatusTimeout)
}

func TestProbePerIPLimit(t *testing.T) {
	rig := startProbe(t, ProbeConfig{MaxConnsPerIP: 2, ReadTimeout: 2 * time.Second})
	addr := rig.ps.Addr().String()

	var held []net.Conn
	for range 2 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c) // idle: occupies a slot until it times out
	}
	time.Sleep(100 * time.Millisecond)

	c3, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	c3.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c3.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("third connection should be closed by the server, got %v", err)
	}
	if rig.ps.Rejected() != 1 {
		t.Errorf("Rejected = %d, want 1", rig.ps.Rejected())
	}

	for _, c := range held {
		c.Close()
	}
	rig.waitStatus(t, StatusInvalid)
	rig.waitStatus(t, StatusInvalid)
	time.Sleep(50 * time.Millisecond)
	rig.ps.mu.Lock()
	defer rig.ps.mu.Unlock()
	if rig.ps.active != 0 || len(rig.ps.perIP) != 0 {
		t.Errorf("leaked slots: active=%d perIP=%v", rig.ps.active, rig.ps.perIP)
	}
}
