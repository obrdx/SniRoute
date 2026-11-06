// Package server implements SniRoute's central (observer) components.
package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nyktios/sniroute/internal/probe"
)

// Status describes what the probe listener observed on one connection before
// any authentication. These events are diagnostics only: they are never
// attributed to a node.
type Status string

const (
	StatusReceived        Status = "received"         // a valid ClientHello was read
	StatusTimeout         Status = "timeout"          // no complete ClientHello in time
	StatusInvalid         Status = "invalid"          // not a usable ClientHello
	StatusHandshakeFailed Status = "handshake_failed" // ClientHello fine, TLS handshake failed
	StatusBadRequest      Status = "bad_request"      // TLS fine, HTTP request unusable
)

// Event is one unauthenticated observation.
type Event struct {
	Time   time.Time
	Remote netip.AddrPort // real TCP peer address (IPv4-mapped IPv6 unmapped)
	Status Status
	SNI    string            // set when a ClientHello was read
	Digest [sha256.Size]byte // SHA-256 of the full ClientHello message
	Err    error
}

// ProbeConfig configures a ProbeServer. Zero values select defaults.
type ProbeConfig struct {
	Addr          string        // listen address, default ":443"
	ReadTimeout   time.Duration // time allowed to deliver a ClientHello, default 5s
	ConnTimeout   time.Duration // total time for handshake + request, default 10s
	MaxHelloBytes int           // ClientHello body limit, default probe.DefaultMaxHello
	MaxConnsPerIP int           // concurrent connections per source IP, default 16
	MaxConns      int           // concurrent connections overall, default 1024
}

func (c *ProbeConfig) setDefaults() {
	if c.Addr == "" {
		c.Addr = ":443"
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = 5 * time.Second
	}
	if c.ConnTimeout <= 0 {
		c.ConnTimeout = 10 * time.Second
	}
	if c.MaxHelloBytes <= 0 {
		c.MaxHelloBytes = probe.DefaultMaxHello
	}
	if c.MaxConnsPerIP <= 0 {
		c.MaxConnsPerIP = 16
	}
	if c.MaxConns <= 0 {
		c.MaxConns = 1024
	}
}

const (
	maxRequestBytes = 8 << 10 // headers + body of the single request
	maxProbeBody    = 1 << 10
)

// ProbeHooks connect the listener to the rest of the server. Both are called
// from connection goroutines, possibly concurrently, and must return quickly.
type ProbeHooks struct {
	// OnEvent receives unauthenticated diagnostics. May be nil.
	OnEvent func(Event)
	// OnReceipt authenticates a receipt request and records the observation.
	OnReceipt func(ReceiptRequest, Observed) (*Receipt, Outcome, error)
}

// ProbeServer accepts TCP connections, reads the ClientHello, completes a TLS
// handshake with a fixed probe certificate (whatever the SNI), and serves one
// authenticated POST /probe request that returns the observed source address.
//
// The probe certificate is not meant to validate for the SNI; clients pin its
// public key instead.
type ProbeServer struct {
	cfg   ProbeConfig
	tls   *tls.Config
	hooks ProbeHooks

	ln       net.Listener
	rejected atomic.Uint64

	mu     sync.Mutex
	active int
	perIP  map[netip.Addr]int
}

// NewProbeServer creates a server using cert for every connection.
func NewProbeServer(cfg ProbeConfig, cert tls.Certificate, hooks ProbeHooks) *ProbeServer {
	cfg.setDefaults()
	return &ProbeServer{
		cfg:   cfg,
		hooks: hooks,
		tls: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1"},
		},
		perIP: make(map[netip.Addr]int),
	}
}

// Listen binds the TCP listener so callers can fail fast and discover the
// chosen port when using ":0".
func (s *ProbeServer) Listen() error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	s.ln = ln
	return nil
}

// Addr returns the bound address; valid after Listen.
func (s *ProbeServer) Addr() net.Addr { return s.ln.Addr() }

// Rejected returns how many connections were dropped for exceeding limits.
func (s *ProbeServer) Rejected() uint64 { return s.rejected.Load() }

// Serve accepts connections until ctx is cancelled, then closes the listener
// and waits for in-flight connections (bounded by ConnTimeout).
func (s *ProbeServer) Serve(ctx context.Context) error {
	if s.ln == nil {
		return errors.New("server: Serve called before Listen")
	}
	go func() {
		<-ctx.Done()
		s.ln.Close()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()

	var backoff time.Duration
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// Transient failure (e.g. EMFILE): back off instead of spinning.
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff *= 2; backoff > time.Second {
				backoff = time.Second
			}
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil
			}
			continue
		}
		backoff = 0

		ip := remoteAddrPort(conn).Addr()
		if !s.acquire(ip) {
			s.rejected.Add(1)
			conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.release(ip)
			s.handle(conn)
		}()
	}
}

func (s *ProbeServer) acquire(ip netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active >= s.cfg.MaxConns || s.perIP[ip] >= s.cfg.MaxConnsPerIP {
		return false
	}
	s.active++
	s.perIP[ip]++
	return true
}

func (s *ProbeServer) release(ip netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active--
	if s.perIP[ip]--; s.perIP[ip] <= 0 {
		delete(s.perIP, ip)
	}
}

func (s *ProbeServer) emit(ev Event) {
	if s.hooks.OnEvent != nil {
		s.hooks.OnEvent(ev)
	}
}

func (s *ProbeServer) handle(conn net.Conn) {
	defer conn.Close()
	start := time.Now()
	remote := remoteAddrPort(conn)
	ev := Event{Time: start, Remote: remote}

	// 1. Read the ClientHello ourselves: it gives us the SNI and digest even
	// when the handshake later fails, and bounds the size before TLS sees it.
	conn.SetReadDeadline(start.Add(s.cfg.ReadTimeout))
	ch, err := probe.ReadClientHello(conn, s.cfg.MaxHelloBytes)
	if err != nil {
		ev.Err = err
		ev.Status = StatusInvalid
		if isTimeout(err) {
			ev.Status = StatusTimeout
		}
		s.emit(ev)
		return
	}
	ev.SNI, ev.Digest, ev.Status = ch.SNI, ch.Digest, StatusReceived
	s.emit(ev)

	// 2. Replay the consumed bytes into a normal TLS server handshake.
	conn.SetDeadline(start.Add(s.cfg.ConnTimeout))
	tc := tls.Server(&replayConn{Conn: conn, r: bytes.NewReader(ch.Raw)}, s.tls)
	if err := tc.Handshake(); err != nil {
		ev.Status, ev.Err = StatusHandshakeFailed, err
		s.emit(ev)
		return
	}
	defer tc.Close()

	// 3. One bounded request: POST /probe.
	br := bufio.NewReader(&io.LimitedReader{R: tc, N: maxRequestBytes})
	req, err := http.ReadRequest(br)
	if err != nil {
		ev.Status, ev.Err = StatusBadRequest, err
		s.emit(ev)
		return
	}
	if req.Method != http.MethodPost || req.URL.Path != "/probe" {
		writeProbeJSON(tc, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxProbeBody+1))
	if err != nil || len(body) > maxProbeBody {
		writeProbeJSON(tc, http.StatusRequestEntityTooLarge, map[string]string{"error": "bad body"})
		return
	}
	var rr ReceiptRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rr); err != nil {
		writeProbeJSON(tc, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}

	rec, _, err := s.hooks.OnReceipt(rr, Observed{Remote: remote, SNI: ch.SNI, At: time.Now()})
	switch {
	case err != nil:
		writeProbeJSON(tc, http.StatusInternalServerError, map[string]string{"error": "internal error"})
	case rec == nil:
		// Same answer for every failure: do not tell a scanner why.
		writeProbeJSON(tc, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	default:
		writeProbeJSON(tc, http.StatusOK, rec)
	}
}

func writeProbeJSON(w io.Writer, code int, v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(b), b)
}

// replayConn feeds already-consumed bytes back to the TLS stack, then reads
// from the underlying connection.
type replayConn struct {
	net.Conn
	r *bytes.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	if c.r.Len() > 0 {
		return c.r.Read(p)
	}
	return c.Conn.Read(p)
}

func remoteAddrPort(conn net.Conn) netip.AddrPort {
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ap := ta.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
