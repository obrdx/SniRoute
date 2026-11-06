package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nyktios/sniroute/internal/server"
)

type tcpWriteSink struct {
	fragmentSink
	writes [][]byte
	cancel context.CancelFunc
}

func (s *tcpWriteSink) Write(p []byte) (int, error) {
	n, err := s.fragmentSink.Write(p)
	s.writes = append(s.writes, append([]byte(nil), p[:n]...))
	if s.cancel != nil {
		s.cancel()
	}
	return n, err
}

func TestTCPWritesPreserveWireAndLaterMessages(t *testing.T) {
	raw := capturedHello(t, "www.google.com")
	fragmented, err := splitHelloAt(raw, SplitInsideSNI)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{raw, fragmented} {
		for _, position := range []string{SplitBeforeSNI, SplitInsideSNI, SplitAfterSNI} {
			for _, chunk := range []int{0, 7} {
				sink := &tcpWriteSink{}
				sink.chunk = chunk
				rec := &recordConn{Conn: sink}
				c := &helloTCPWriteConn{Conn: rec, ctx: context.Background(), position: position}
				for offset := 0; offset < len(input); {
					next := min(offset+13, len(input))
					n, err := c.Write(input[offset:next])
					if err != nil || n != next-offset {
						t.Fatalf("write %d %v", n, err)
					}
					offset = next
				}
				if !bytes.Equal(sink.Bytes(), input) || rec.helloDigest() == "" {
					t.Fatal("TLS wire bytes or evidence changed")
				}
				if chunk == 0 && len(sink.writes) != 2 {
					t.Fatal("expected exactly two writes")
				}
				tail := []byte{23, 3, 3, 0, 2, 42, 43}
				if _, err := c.Write(tail); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(sink.Bytes(), append(append([]byte(nil), input...), tail...)) {
					t.Fatal("later bytes changed")
				}
			}
		}
	}
}

func TestTCPWriteCancellationBetweenPartsKeepsOnlySentBytes(t *testing.T) {
	raw := capturedHello(t, "www.google.com")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink := &tcpWriteSink{cancel: cancel}
	rec := &recordConn{Conn: sink}
	c := &helloTCPWriteConn{Conn: rec, ctx: ctx, position: SplitInsideSNI, delay: time.Second}
	start := time.Now()
	if _, err := c.Write(raw); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("cancellation did not interrupt delay")
	}
	cut, _ := tcpHelloCut(raw, SplitInsideSNI)
	if !bytes.Equal(sink.Bytes(), raw[:cut]) || rec.helloDigest() != "" {
		t.Fatal("unsent bytes included in evidence")
	}
	if _, err := c.Write(raw); !errors.Is(err, context.Canceled) {
		t.Fatal("failed connection retried")
	}
}

func TestTCPWriteDelayAndFailure(t *testing.T) {
	raw := capturedHello(t, "www.google.com")
	sink := &tcpWriteSink{}
	c := &helloTCPWriteConn{Conn: sink, ctx: context.Background(), position: SplitAfterSNI, delay: 20 * time.Millisecond}
	start := time.Now()
	if _, err := c.Write(raw); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < c.delay {
		t.Fatal("missing write delay")
	}
	failed := &fragmentSink{err: io.ErrClosedPipe}
	rec := &recordConn{Conn: failed}
	c = &helloTCPWriteConn{Conn: rec, ctx: context.Background(), position: SplitInsideSNI}
	if _, err := c.Write(raw); !errors.Is(err, io.ErrClosedPipe) || rec.helloDigest() != "" {
		t.Fatal("failed write created evidence")
	}
	c = &helloTCPWriteConn{Conn: sink, ctx: context.Background(), position: SplitInsideSNI}
	if _, err := c.Write(bytes.Repeat([]byte{0}, maxRecorded+1)); err == nil {
		t.Fatal("oversize accepted")
	}
}

func TestTCPWriteOptionsRejectMixedExperiments(t *testing.T) {
	for _, tc := range []struct {
		record, tcp string
		delay       time.Duration
	}{
		{SplitInsideSNI, SplitInsideSNI, 0}, {SplitStandard, "invalid", 0}, {SplitStandard, "", time.Millisecond},
		{SplitStandard, SplitAfterSNI, -1}, {SplitStandard, SplitAfterSNI, 2 * time.Second}, {SplitStandard, SplitAfterSNI, time.Microsecond},
	} {
		if ValidateTCPWriteSplit(tc.record, tc.tcp, tc.delay) == nil {
			t.Fatal("invalid option accepted", tc)
		}
	}
}

func TestTCPWriteAuthenticatesAndNeverSendsCredentialsToWrongPin(t *testing.T) {
	for _, position := range []string{SplitBeforeSNI, SplitInsideSNI, SplitAfterSNI} {
		for _, wrongPin := range []bool{false, true} {
			t.Run(position+map[bool]string{false: "/receipt", true: "/wrong-pin"}[wrongPin], func(t *testing.T) {
				pin := ""
				if wrongPin {
					pin = strings.Repeat("00", 32)
				}
				r := newRigPin(t, pin)
				v, err := r.runner.Run(context.Background(), RunOptions{
					Plan:            PlanSpec{Targets: []string{r.probeAddr}, Domains: []string{"www.google.com"}, Rounds: 1},
					TCPWriteSplitAt: position, TCPWriteDelay: 20 * time.Millisecond, Timeout: 3 * time.Second,
				}, nil)
				if err != nil {
					t.Fatal(err)
				}
				var params map[string]any
				if json.Unmarshal(v.Params, &params) != nil || params["client_hello_variant"] != "tcp-write-split" || params["tcp_write_split_at"] != position || params["tcp_write_delay_ms"] != float64(20) {
					t.Fatalf("snapshot missing: %s", v.Params)
				}
				a := v.Attempts[0]
				want := server.StateAuthenticated
				if wrongPin {
					want = server.StateHelloMatched
					if r.receipts.Load() != 0 || a.Client[0].Outcome != OutcomeIdentityMismatch {
						t.Fatal("credentials sent or wrong error")
					}
				}
				if a.State != want || a.Observation == nil || a.Observation.SourceIP != "127.0.0.1" || !a.Client[0].HelloSent {
					t.Fatalf("lost evidence: %+v", a)
				}
			})
		}
	}
}
