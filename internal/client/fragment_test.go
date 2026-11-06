package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nyktios/sniroute/internal/probe"
	"github.com/nyktios/sniroute/internal/server"
)

func capturedHello(t *testing.T, sni string) []byte {
	t.Helper()
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer a.Close()
		tls.Client(a, &tls.Config{ServerName: sni, NextProtos: []string{"http/1.1"}}).Handshake()
	}()
	b.SetDeadline(time.Now().Add(3 * time.Second))
	ch, err := probe.ReadClientHello(b, 0)
	b.Close()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	return ch.Raw
}

func TestSplitPositionsHaveExactBoundariesAndIdenticalHandshake(t *testing.T) {
	const host = "www.google.com"
	raw := capturedHello(t, host)
	original, _ := probe.ReadClientHello(bytes.NewReader(raw), 0)
	n := int(binary.BigEndian.Uint16(raw[3:5]))
	if n+5 != len(raw) {
		t.Fatal("fixture needs one initial record")
	}
	payload := raw[5:]
	nameStart := bytes.Index(payload, []byte(host))
	if nameStart < 9 {
		t.Fatal("fixture has no server_name extension")
	}
	for position, expected := range map[string]int{
		SplitBeforeSNI: nameStart - 9, // type, length, list length, name type, name length
		SplitInsideSNI: nameStart + len(host)/2,
		SplitAfterSNI:  nameStart + len(host),
	} {
		t.Run(position, func(t *testing.T) {
			wire, err := splitHelloAt(raw, position)
			if err != nil {
				t.Fatal(err)
			}
			if cut := int(binary.BigEndian.Uint16(wire[3:5])); cut != expected {
				t.Fatalf("boundary %d, want %d", cut, expected)
			}
			var joined []byte
			for offset := 0; offset < len(wire); {
				size := int(binary.BigEndian.Uint16(wire[offset+3 : offset+5]))
				joined = append(joined, wire[offset+5:offset+5+size]...)
				offset += 5 + size
			}
			ch, err := probe.ReadClientHello(bytes.NewReader(wire), 0)
			if err != nil || !bytes.Equal(joined, payload) || ch.Digest != original.Digest || len(wire) != len(raw)+5 {
				t.Fatalf("variant changed the handshake: %+v %v", ch, err)
			}
		})
	}
	// When SNI is the last extension there is no legal nonempty remainder.
	end := nameStart + len(host)
	last := append([]byte(nil), payload[:end]...)
	extLengthPos := 4 + 2 + 32
	extLengthPos += 1 + int(payload[extLengthPos])
	extLengthPos += 2 + int(binary.BigEndian.Uint16(payload[extLengthPos:extLengthPos+2]))
	extLengthPos += 1 + int(payload[extLengthPos])
	binary.BigEndian.PutUint16(last[extLengthPos:extLengthPos+2], uint16(end-extLengthPos-2))
	bodyLen := len(last) - 4
	last[1], last[2], last[3] = byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen)
	lastWire := append([]byte{22, 3, 1, byte(len(last) >> 8), byte(len(last))}, last...)
	if _, err := probe.ReadClientHello(bytes.NewReader(lastWire), 0); err != nil {
		t.Fatal("invalid final-SNI fixture:", err)
	}
	if _, err := splitHelloAt(lastWire, SplitAfterSNI); err == nil {
		t.Fatal("after-sni silently used a different boundary")
	}
}

func TestSplitPositionValidationBeforeNetworkOrTaskCreation(t *testing.T) {
	for _, test := range []struct {
		enabled     bool
		input, want string
	}{
		{false, "", SplitStandard}, {true, "", SplitInsideSNI},
		{false, SplitStandard, SplitStandard}, {false, SplitBeforeSNI, SplitBeforeSNI},
		{false, SplitInsideSNI, SplitInsideSNI}, {false, SplitAfterSNI, SplitAfterSNI},
	} {
		if got, err := ResolveSplitPosition(test.enabled, test.input); err != nil || got != test.want {
			t.Fatalf("resolve %+v: %s %v", test, got, err)
		}
	}
	if _, err := ResolveSplitPosition(true, SplitStandard); err == nil {
		t.Fatal("conflicting ordinary/fragment options accepted")
	}
	if _, err := (&Runner{}).Run(context.Background(), RunOptions{TLSRecordSplitAt: "unknown"}, nil); err == nil {
		t.Fatal("invalid position reached task creation")
	}
}

type fragmentSink struct {
	net.Conn
	bytes.Buffer
	chunk int
	err   error
}

func (c *fragmentSink) Read([]byte) (int, error) { return 0, io.EOF }

func (c *fragmentSink) Write(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if c.chunk > 0 {
		p = p[:min(c.chunk, len(p))]
	}
	return c.Buffer.Write(p)
}

func TestRecordSplitPreservesHelloAndOnlyChangesFirstMessage(t *testing.T) {
	raw := capturedHello(t, "chatgpt.com")
	want, _ := probe.ReadClientHello(bytes.NewReader(raw), 0)
	sink := &fragmentSink{chunk: 7} // exercise underlying partial writes
	recorded := &recordConn{Conn: sink}
	c := &helloSplitConn{Conn: recorded}
	for pos := 0; pos < len(raw); {
		next := min(pos+13, len(raw)) // exercise partial caller writes/headers
		n, err := c.Write(raw[pos:next])
		if err != nil || n != next-pos {
			t.Fatalf("write: %d %v", n, err)
		}
		pos = next
	}
	wire := append([]byte(nil), sink.Bytes()...)
	got, err := probe.ReadClientHello(bytes.NewReader(wire), 0)
	if err != nil || got.Digest != want.Digest || got.SNI != want.SNI || strings.Join(got.ALPN, ",") != "http/1.1" {
		t.Fatalf("ClientHello changed: %+v %v", got, err)
	}
	if len(wire) != len(raw)+5 || recorded.helloDigest() == "" || len(got.Raw) != len(wire) {
		t.Fatal("expected one extra record header and a complete digest of bytes written")
	}
	for pos := 0; pos < len(wire); {
		n := int(binary.BigEndian.Uint16(wire[pos+3 : pos+5]))
		if bytes.Contains(wire[pos+5:pos+5+n], []byte("chatgpt.com")) {
			t.Fatal("SNI is still contained in a single record")
		}
		pos += 5 + n
	}
	sink.chunk = 0
	if _, err := c.Write(raw); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sink.Bytes()[len(wire):], raw) {
		t.Fatal("later handshake bytes were modified")
	}
}

func TestRecordSplitPreservesExistingRecordsAndTrailingData(t *testing.T) {
	raw := capturedHello(t, "example.com")
	n := int(binary.BigEndian.Uint16(raw[3:5]))
	// The handshake header itself may already straddle records.
	input := append([]byte{raw[0], raw[1], raw[2], 0, 2}, raw[5:7]...)
	input = append(input, raw[0], raw[1], raw[2], byte((n-2)>>8), byte(n-2))
	input = append(input, raw[7:]...)
	tail := []byte{20, 3, 3, 0, 1, 1}
	input = append(input, tail...)
	wire, err := splitHelloSNI(input)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := probe.ReadClientHello(bytes.NewReader(raw), 0)
	got, err := probe.ReadClientHello(bytes.NewReader(wire), 0)
	if err != nil || got.Digest != want.Digest || !bytes.Equal(wire[len(got.Raw):], tail) {
		t.Fatalf("record replay changed: %+v %v", got, err)
	}
}

func TestRecordSplitFailsClosedAndRecordsOnlyWrittenBytes(t *testing.T) {
	raw := capturedHello(t, "example.com")
	for _, input := range [][]byte{bytes.Repeat([]byte{1}, maxRecorded+1), {23, 3, 3, 0, 1, 0}} {
		sink := &fragmentSink{}
		c := &helloSplitConn{Conn: sink}
		if _, err := c.Write(input); err == nil || sink.Len() != 0 {
			t.Fatal("invalid input was emitted")
		}
		if _, err := c.Write(raw); err == nil {
			t.Fatal("failed fragmentation silently fell back to a normal handshake")
		}
	}
	sink := &fragmentSink{err: io.ErrClosedPipe}
	rec := &recordConn{Conn: sink}
	c := &helloSplitConn{Conn: rec}
	if _, err := c.Write(raw); !errors.Is(err, io.ErrClosedPipe) || rec.helloDigest() != "" {
		t.Fatal("failed write must not claim a ClientHello was sent")
	}
}

func TestFragmentedProbeAuthenticatesAndMatchesHelloWithoutCredentialsOnWrongPin(t *testing.T) {
	for _, badPin := range []bool{false, true} {
		t.Run(map[bool]string{false: "receipt", true: "identity_mismatch"}[badPin], func(t *testing.T) {
			var r *rig
			if badPin {
				r = newRigPin(t, strings.Repeat("00", 32))
			} else {
				r = newRig(t)
			}
			v, err := r.runner.Run(context.Background(), RunOptions{
				Plan:           PlanSpec{Targets: []string{r.probeAddr}, Domains: []string{"chatgpt.com"}, Rounds: 1},
				TLSRecordSplit: true, Timeout: 3 * time.Second,
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			var params map[string]any
			if json.Unmarshal(v.Params, &params) != nil || params["client_hello_variant"] != "tls-record-sni-split" {
				t.Fatalf("variant missing from frozen snapshot: %s", v.Params)
			}
			a := v.Attempts[0]
			if a.Observation == nil || a.Observation.SourceIP != "127.0.0.1" || !a.Client[0].HelloSent {
				t.Fatalf("fragmented ClientHello evidence lost: %+v", a)
			}
			if badPin {
				if r.receipts.Load() != 0 || a.State != server.StateHelloMatched || a.Client[0].Outcome != OutcomeIdentityMismatch {
					t.Fatalf("credentials sent or wrong failure evidence: %+v", a)
				}
			} else if a.State != server.StateAuthenticated || a.Client[0].Outcome != OutcomeReceipt {
				t.Fatalf("fragmented probe could not authenticate: %+v", a)
			}
		})
	}
}

func TestAllPositionsAuthenticateOrKeepMatchedHelloOnWrongIdentity(t *testing.T) {
	for _, position := range []string{SplitBeforeSNI, SplitInsideSNI, SplitAfterSNI} {
		for _, wrongPin := range []bool{false, true} {
			name := position + "/receipt"
			if wrongPin {
				name = position + "/wrong-pin"
			}
			t.Run(name, func(t *testing.T) {
				pin := ""
				if wrongPin {
					pin = strings.Repeat("00", 32)
				}
				r := newRigPin(t, pin)
				v, err := r.runner.Run(context.Background(), RunOptions{
					Plan:             PlanSpec{Targets: []string{r.probeAddr}, Domains: []string{"www.google.com"}, Rounds: 1},
					TLSRecordSplitAt: position, Timeout: 3 * time.Second,
				}, nil)
				if err != nil {
					t.Fatal(err)
				}
				var params map[string]any
				if json.Unmarshal(v.Params, &params) != nil || params["client_hello_variant"] != splitVariant(position) || params["tls_record_split_at"] != position {
					t.Fatalf("position is not frozen: %s", v.Params)
				}
				a := v.Attempts[0]
				want := server.StateAuthenticated
				if wrongPin {
					want = server.StateHelloMatched
					if r.receipts.Load() != 0 {
						t.Fatal("credential sent to untrusted endpoint")
					}
				}
				if a.State != want || a.Observation == nil || a.Observation.SourceIP != "127.0.0.1" || !a.Client[0].HelloSent {
					t.Fatalf("lost fragmented evidence: %+v", a)
				}
			})
		}
	}
}
func TestRecordSplitAgainstSingleRecordSniffingProxy(t *testing.T) {
	// Model one possible implementation, not all transparent proxies: sniff
	// only the first TLS record, redirect recognised SNI, otherwise preserve IP.
	r := newRig(t)
	var leaked atomic.Int64
	wrong := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Add(1) }))
	defer wrong.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				var header [5]byte
				if _, err := io.ReadFull(conn, header[:]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(header[3:5]))
				if n == 0 || n > 1<<14 {
					return
				}
				first := make([]byte, 5+n)
				copy(first, header[:])
				if _, err := io.ReadFull(conn, first[5:]); err != nil {
					return
				}
				target := r.probeAddr
				if hello, err := probe.ReadClientHello(bytes.NewReader(first), 0); err == nil && hello.SNI == "chatgpt.com" {
					target = strings.TrimPrefix(wrong.URL, "https://")
				}
				upstream, err := net.DialTimeout("tcp", target, time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				upstream.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.Copy(upstream, bytes.NewReader(first)); err != nil {
					return
				}
				done := make(chan struct{})
				go func() {
					io.Copy(upstream, conn)
					upstream.Close()
					close(done)
				}()
				io.Copy(conn, upstream)
				conn.Close()
				<-done
			}()
		}
	}()
	for _, split := range []bool{false, true} {
		v, err := r.runner.Run(context.Background(), RunOptions{
			Plan:           PlanSpec{Targets: []string{ln.Addr().String()}, Domains: []string{"chatgpt.com"}, Rounds: 1},
			TLSRecordSplit: split, Timeout: 3 * time.Second,
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		a := v.Attempts[0]
		if split {
			if a.State != server.StateAuthenticated || a.Observation == nil {
				t.Fatalf("fragmented hello did not reach observer: %+v", a)
			}
		} else if a.Client[0].Outcome != OutcomeIdentityMismatch || a.Observation != nil {
			t.Fatalf("normal hello was not redirected as expected: %+v", a)
		}
	}
	if leaked.Load() != 0 {
		t.Fatal("probe credential reached the simulated redirected endpoint")
	}
}
