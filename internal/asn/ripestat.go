package asn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// RIPEstat uses the RIPEstat Data API: network-info gives the announced
// prefix and Origin ASN(s) of an address, as-overview gives the holder name.
// Terms: more than ~1000 requests a day need registration, and at most 8
// concurrent requests per client IP are allowed, so concurrency is bounded.
type RIPEstat struct {
	BaseURL   string // default https://stat.ripe.net
	SourceApp string // identifies this tool to RIPE (optional but recommended)
	Client    *http.Client
	sem       chan struct{}
}

// NewRIPEstat creates a client with a short timeout and at most 4 concurrent
// requests.
func NewRIPEstat(sourceApp string) *RIPEstat {
	return &RIPEstat{
		BaseURL: "https://stat.ripe.net", SourceApp: sourceApp,
		Client: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, TLSHandshakeTimeout: 5 * time.Second}},
		sem:    make(chan struct{}, 4),
	}
}

// Name implements Provider.
func (r *RIPEstat) Name() string { return "ripestat" }

const maxBody = 64 << 10

func (r *RIPEstat) get(ctx context.Context, endpoint, resource string, out any) error {
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return &LookupError{KindTimeout, "waiting for a request slot"}
	}
	q := url.Values{"resource": {resource}}
	if r.SourceApp != "" {
		q.Set("sourceapp", r.SourceApp)
	}
	u := strings.TrimRight(r.BaseURL, "/") + "/data/" + endpoint + "/data.json?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return &LookupError{KindUnavailable, err.Error()}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.Client.Do(req)
	if err != nil {
		if ctx.Err() != nil || strings.Contains(err.Error(), "timeout") {
			return &LookupError{KindTimeout, endpoint}
		}
		return &LookupError{KindUnavailable, endpoint + ": " + clamp(err.Error(), 120)}
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return &LookupError{KindRateLimited, endpoint}
	case resp.StatusCode != http.StatusOK:
		return &LookupError{KindHTTP, fmt.Sprintf("%s: HTTP %d", endpoint, resp.StatusCode)}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out); err != nil {
		return &LookupError{KindBadResponse, endpoint + ": " + clamp(err.Error(), 120)}
	}
	return nil
}

// Lookup implements Provider.
func (r *RIPEstat) Lookup(ctx context.Context, ip netip.Addr) (*Info, error) {
	var ni struct {
		Status string `json:"status"`
		Data   struct {
			ASNs   []json.RawMessage `json:"asns"`
			Prefix string            `json:"prefix"`
		} `json:"data"`
	}
	if err := r.get(ctx, "network-info", ip.String(), &ni); err != nil {
		return nil, err
	}
	if ni.Status != "ok" {
		return nil, &LookupError{KindBadResponse, "network-info status " + clamp(ni.Status, 40)}
	}
	info := &Info{IP: ip.String(), Source: r.Name(), Status: StatusOK, ASNs: []Number{}, Prefix: clamp(ni.Data.Prefix, 64)}
	for _, raw := range ni.Data.ASNs {
		if len(info.ASNs) == 4 { // multi-origin lists are kept, but bounded
			break
		}
		n, ok := parseASN(raw)
		if !ok {
			return nil, &LookupError{KindBadResponse, "unparseable ASN in network-info"}
		}
		info.ASNs = append(info.ASNs, Number{ASN: n})
	}
	if len(info.ASNs) == 0 {
		info.Status = StatusNoData
		return info, nil
	}
	// Holder names are a second call per ASN; a failure there keeps the ASN
	// and notes the gap instead of discarding the lookup.
	for i := range info.ASNs {
		var ov struct {
			Data struct {
				Holder string `json:"holder"`
			} `json:"data"`
		}
		if err := r.get(ctx, "as-overview", "AS"+strconv.Itoa(info.ASNs[i].ASN), &ov); err != nil {
			info.Error = "holder lookup: " + kindOf(err)
			continue
		}
		info.ASNs[i].Name = clamp(ov.Data.Holder, 200)
	}
	return info, nil
}

// parseASN accepts 3333, "3333" and "AS3333".
func parseASN(raw json.RawMessage) (int, bool) {
	s := strings.TrimPrefix(strings.ToUpper(strings.Trim(string(raw), `" `)), "AS")
	n, err := strconv.Atoi(s)
	return n, err == nil && n > 0 && n < 1<<32
}
