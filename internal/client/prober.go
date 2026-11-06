// Package client implements the probing side of SniRoute: the pinned-TLS
// prober, the control-API client and the task runner.
package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nyktios/sniroute/internal/probe"
	"github.com/nyktios/sniroute/internal/server"
)

// ProbeSpec describes one controlled probe: connect to Target, send SNI,
// verify the observer by its pinned public key, then present the attempt
// credential inside the encrypted channel.
type ProbeSpec struct {
	Target           string // observer ip:port
	SNI              string
	Pin              string // hex SHA-256 of the observer's SubjectPublicKeyInfo
	Path             string // node path
	AttemptID        string
	Credential       string
	Timeout          time.Duration
	TLSRecordSplit   bool   // experimental: split the first ClientHello inside SNI
	TLSRecordSplitAt string // explicit experiment position; empty keeps boolean compatibility
	TCPWriteSplitAt  string
	TCPWriteDelay    time.Duration
}

// Probe outcomes reported to the observer as client events.
const (
	OutcomeReceipt          = "receipt"
	OutcomeDialFailed       = "dial_failed"
	OutcomeTimeout          = "timeout"
	OutcomeTLSFailed        = "tls_failed"
	OutcomeIdentityMismatch = "identity_mismatch"
	OutcomeHTTPFailed       = "http_failed"
	OutcomeCancelled        = "cancelled"
)

// ProbeResult is the client's view of one attempt. Durations come from the
// local monotonic clock only.
type ProbeResult struct {
	Stage     string // tcp | tls | http: the stage reached (or failed in)
	Outcome   string
	Error     string
	StartedAt time.Time
	Duration  time.Duration
	Receipt   *server.Receipt
	// HelloSHA256 is the hex SHA-256 of the complete first ClientHello message
	// this probe sent ("" if the connection never got that far). The observer
	// uses it to recognise the connection even when the handshake fails.
	HelloSHA256 string
}

const maxResponseBytes = 16 << 10

// Probe runs one controlled probe. It never sends the credential unless the
// observer's public key matches Pin.
func Probe(ctx context.Context, spec ProbeSpec) (res ProbeResult) {
	t0 := time.Now()
	res = ProbeResult{Stage: "tcp", StartedAt: t0}
	var rec *recordConn
	defer func() {
		res.Duration = time.Since(t0)
		if rec != nil {
			res.HelloSHA256 = rec.helloDigest()
		}
	}()
	position, positionErr := ResolveSplitPosition(spec.TLSRecordSplit, spec.TLSRecordSplitAt)
	if positionErr == nil {
		positionErr = ValidateTCPWriteSplit(position, spec.TCPWriteSplitAt, spec.TCPWriteDelay)
	}
	if positionErr != nil {
		res.Stage, res.Outcome, res.Error = "tls", OutcomeTLSFailed, positionErr.Error()
		return res
	}

	if spec.Timeout <= 0 {
		spec.Timeout = 5 * time.Second
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, spec.Timeout)
	defer cancel()

	fail := func(outcome string, err error) ProbeResult {
		switch {
		case parent.Err() != nil: // the caller cancelled (not our own timeout)
			outcome = OutcomeCancelled
		case errors.Is(ctx.Err(), context.DeadlineExceeded) || isTimeout(err):
			outcome = OutcomeTimeout
		}
		res.Outcome, res.Error = outcome, err.Error()
		return res
	}

	// No proxy: net.Dialer ignores HTTP_PROXY and friends by design.
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", spec.Target)
	if err != nil {
		return fail(OutcomeDialFailed, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}

	res.Stage = "tls"
	pinFailed := false
	rec = &recordConn{Conn: conn}
	var tlsConn net.Conn = rec
	if position != SplitStandard {
		tlsConn = &helloSplitConn{Conn: rec, position: position}
	}
	if spec.TCPWriteSplitAt != "" {
		if tcp, ok := conn.(*net.TCPConn); ok {
			if err := tcp.SetNoDelay(true); err != nil {
				return fail(OutcomeTLSFailed, err)
			}
		}
		tlsConn = &helloTCPWriteConn{Conn: rec, ctx: ctx, position: spec.TCPWriteSplitAt, delay: spec.TCPWriteDelay}
	}
	tc := tls.Client(tlsConn, &tls.Config{
		ServerName:         spec.SNI,
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // replaced by VerifyConnection below: public-key pinning
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || !pinMatches(cs.PeerCertificates[0].RawSubjectPublicKeyInfo, spec.Pin) {
				pinFailed = true
				return errors.New("observer public key does not match the pinned key")
			}
			return nil
		},
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		if pinFailed {
			return fail(OutcomeIdentityMismatch, err)
		}
		return fail(OutcomeTLSFailed, err)
	}

	res.Stage = "http"
	body, _ := json.Marshal(server.ReceiptRequest{Path: spec.Path, AttemptID: spec.AttemptID, Credential: spec.Credential})
	var req bytes.Buffer
	fmt.Fprintf(&req, "POST /probe HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", spec.SNI, len(body))
	req.Write(body)
	if _, err := tc.Write(req.Bytes()); err != nil {
		return fail(OutcomeHTTPFailed, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(io.LimitReader(tc, maxResponseBytes)), nil)
	if err != nil {
		return fail(OutcomeHTTPFailed, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fail(OutcomeHTTPFailed, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fail(OutcomeHTTPFailed, fmt.Errorf("observer answered %s", resp.Status))
	}
	var rc server.Receipt
	if err := json.Unmarshal(data, &rc); err != nil {
		return fail(OutcomeHTTPFailed, fmt.Errorf("bad receipt: %w", err))
	}
	res.Outcome, res.Receipt = OutcomeReceipt, &rc
	return res
}

// recordConn keeps a copy of the first bytes written, which are the
// ClientHello, without altering anything on the wire.
type recordConn struct {
	net.Conn
	buf []byte
}

const maxRecorded = 32 << 10

func (c *recordConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if room := maxRecorded - len(c.buf); room > 0 {
		c.buf = append(c.buf, p[:min(n, room)]...)
	}
	return n, err
}

// helloDigest parses the recorded bytes as a ClientHello (reassembling TLS
// records) and returns the hex digest of the full handshake message.
func (c *recordConn) helloDigest() string {
	ch, err := probe.ReadClientHello(bytes.NewReader(c.buf), 0)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(ch.Digest[:])
}

func pinMatches(spki []byte, pin string) bool {
	want, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(pin)))
	if err != nil || len(want) != sha256.Size {
		return false
	}
	got := sha256.Sum256(spki)
	return subtle.ConstantTimeCompare(got[:], want) == 1
}

func isTimeout(err error) bool {
	var ne net.Error
	return err != nil && errors.As(err, &ne) && ne.Timeout()
}
