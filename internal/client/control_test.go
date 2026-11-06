package client

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/nyktios/sniroute/internal/server"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestControlHealthHonorsCancelledContext(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := r.reqs.Load()
	if err := r.runner.CC.Probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("health: %v", err)
	}
	if _, err := r.runner.CC.Discover(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("discover: %v", err)
	}
	if r.reqs.Load() != before {
		t.Fatal("cancelled health request reached server")
	}
}

func TestControlTransportErrorGivesAdviceAndPreservesCause(t *testing.T) {
	err := transportError(io.EOF)
	if !errors.Is(err, io.EOF) || !strings.Contains(err.Error(), "地址、控制端口") || !strings.Contains(err.Error(), "不表示域名被阻断") {
		t.Fatalf("transport advice: %v", err)
	}
}

func TestDiscoverProtocolVersionIsInternalAndValidated(t *testing.T) {
	for _, protocol := range []string{"v1", "", "unsupported"} {
		t.Run(protocol, func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"service": "sniroute-control", "api": 1, "protocol_version": protocol})
			}))
			defer ts.Close()
			cc, err := NewControlClient(ts.URL, server.CertPin(ts.Certificate().Raw))
			if err != nil {
				t.Fatal(err)
			}
			got, err := cc.Discover(context.Background())
			if protocol == "unsupported" {
				if err == nil || strings.Contains(err.Error(), protocol) {
					t.Fatalf("incompatible protocol: %v", err)
				}
			} else if err != nil || got.ProtocolVersion != protocol {
				t.Fatalf("protocol health: %+v %v", got, err)
			}
		})
	}
}
