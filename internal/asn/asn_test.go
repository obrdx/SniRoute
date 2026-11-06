package asn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// ---- RIPEstat --------------------------------------------------------------

type ripeFake struct {
	netInfo, overview func(w http.ResponseWriter, r *http.Request)
	mu                sync.Mutex
	apps              []string
	inflight, peak    atomic.Int32
}

func (f *ripeFake) handler(w http.ResponseWriter, r *http.Request) {
	n := f.inflight.Add(1)
	defer f.inflight.Add(-1)
	for {
		p := f.peak.Load()
		if n <= p || f.peak.CompareAndSwap(p, n) {
			break
		}
	}
	f.mu.Lock()
	f.apps = append(f.apps, r.URL.Query().Get("sourceapp"))
	f.mu.Unlock()
	switch {
	case strings.Contains(r.URL.Path, "network-info"):
		f.netInfo(w, r)
	case strings.Contains(r.URL.Path, "as-overview"):
		f.overview(w, r)
	default:
		http.NotFound(w, r)
	}
}

func newRipe(t *testing.T, f *ripeFake) *RIPEstat {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(ts.Close)
	r := NewRIPEstat("sniroute-test")
	r.BaseURL = ts.URL
	return r
}

func okInfo(asns string, prefix string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := json.Marshal(prefix)
		fmt.Fprintf(w, `{"status":"ok","data":{"asns":%s,"prefix":%s}}`, asns, p)
	}
}

func holder(h string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(h)
		fmt.Fprintf(w, `{"status":"ok","data":{"holder":%s}}`, b)
	}
}

func TestRIPEstatResolvesPrefixASNAndHolder(t *testing.T) {
	f := &ripeFake{netInfo: okInfo(`["3333"]`, "198.51.100.0/24"), overview: holder("RIPE-NCC-AS RIPE NCC")}
	info, err := newRipe(t, f).Lookup(context.Background(), ip("198.51.100.10"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Status != StatusOK || info.Prefix != "198.51.100.0/24" || len(info.ASNs) != 1 || info.ASNs[0].ASN != 3333 || info.ASNs[0].Name != "RIPE-NCC-AS RIPE NCC" {
		t.Errorf("%+v", info)
	}
	if info.ASNs[0].Label() != "AS3333 RIPE-NCC-AS RIPE NCC" {
		t.Errorf("label: %s", info.ASNs[0].Label())
	}
	if len(f.apps) == 0 || f.apps[0] != "sniroute-test" {
		t.Errorf("sourceapp not sent: %v", f.apps)
	}
}

func TestRIPEstatKeepsEveryOriginASN(t *testing.T) {
	f := &ripeFake{netInfo: okInfo(`["64500", 64501, "AS64502"]`, "203.0.113.0/24"), overview: func(w http.ResponseWriter, r *http.Request) {
		holder("holder of "+r.URL.Query().Get("resource"))(w, r)
	}}
	info, err := newRipe(t, f).Lookup(context.Background(), ip("203.0.113.5"))
	if err != nil || len(info.ASNs) != 3 {
		t.Fatalf("%+v %v", info, err)
	}
	if info.ASNs[1].ASN != 64501 || info.ASNs[1].Name != "holder of AS64501" {
		t.Errorf("multi-origin result collapsed or mislabelled: %+v", info.ASNs)
	}
}

func TestRIPEstatNoAnnouncementIsNoDataNotFailure(t *testing.T) {
	f := &ripeFake{netInfo: okInfo(`[]`, ""), overview: holder("x")}
	info, err := newRipe(t, f).Lookup(context.Background(), ip("198.51.100.1"))
	if err != nil || info.Status != StatusNoData || len(info.ASNs) != 0 {
		t.Errorf("%+v %v", info, err)
	}
}

func TestRIPEstatHolderFailureKeepsTheASN(t *testing.T) {
	f := &ripeFake{netInfo: okInfo(`["64500"]`, "203.0.113.0/24"), overview: func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", 500) }}
	info, err := newRipe(t, f).Lookup(context.Background(), ip("203.0.113.5"))
	if err != nil || info.Status != StatusOK || info.ASNs[0].ASN != 64500 || info.ASNs[0].Name != "" || !strings.Contains(info.Error, "holder lookup") {
		t.Errorf("%+v %v", info, err)
	}
}

func TestRIPEstatFailureKinds(t *testing.T) {
	cases := map[string]struct {
		h    func(http.ResponseWriter, *http.Request)
		kind string
	}{
		"rate limited": {func(w http.ResponseWriter, r *http.Request) { http.Error(w, "slow down", 429) }, KindRateLimited},
		"server error": {func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", 503) }, KindHTTP},
		"not json":     {func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "<html>") }, KindBadResponse},
		"status error": {func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"status":"error","data":{}}`) }, KindBadResponse},
		"bad asn":      {okInfo(`["not-a-number"]`, "x"), KindBadResponse},
	}
	for name, c := range cases {
		f := &ripeFake{netInfo: c.h, overview: holder("x")}
		_, err := newRipe(t, f).Lookup(context.Background(), ip("203.0.113.5"))
		var le *LookupError
		if !errors.As(err, &le) || le.Kind != c.kind {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRIPEstatTimeoutAndSanitising(t *testing.T) {
	slow := &ripeFake{netInfo: func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) }, overview: holder("x")}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := newRipe(t, slow).Lookup(ctx, ip("203.0.113.5"))
	var le *LookupError
	if !errors.As(err, &le) || le.Kind != KindTimeout {
		t.Errorf("timeout: %v", err)
	}

	evil := &ripeFake{netInfo: okInfo(`["64500"]`, "203.0.113.0/24\x1b[31m"), overview: holder("Evil\x1b[2J\x00 Corp " + strings.Repeat("x", 500))}
	info, err := newRipe(t, evil).Lookup(context.Background(), ip("203.0.113.5"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(info.ASNs[0].Name+info.Prefix, "\x1b\x00") || len(info.ASNs[0].Name) > 200 {
		t.Errorf("unsanitised provider output: %q %q", info.ASNs[0].Name, info.Prefix)
	}
}

func TestRIPEstatConcurrencyIsBounded(t *testing.T) {
	f := &ripeFake{netInfo: func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(40 * time.Millisecond)
		okInfo(`[]`, "")(w, r)
	}, overview: holder("x")}
	r := newRipe(t, f)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Lookup(context.Background(), ip("203.0.113.5"))
		}()
	}
	wg.Wait()
	if p := f.peak.Load(); p > 4 {
		t.Errorf("peak concurrent requests = %d, want <= 4 (RIPE allows 8 per IP)", p)
	}
}

// ---- Team Cymru ------------------------------------------------------------

func TestCymruQueryNames(t *testing.T) {
	if got := originName(ip("8.8.4.4")); got != "4.4.8.8.origin.asn.cymru.com" {
		t.Errorf("v4: %s", got)
	}
	got := originName(ip("2001:db8::1"))
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com"
	if got != want {
		t.Errorf("v6: %s", got)
	}
	if originName(ip("::ffff:8.8.4.4")) != "4.4.8.8.origin.asn.cymru.com" {
		t.Error("IPv4-mapped address must use the IPv4 zone")
	}
}

func cymruWith(m map[string][]string) *Cymru {
	return &Cymru{LookupTXT: func(ctx context.Context, name string) ([]string, error) {
		if v, ok := m[name]; ok {
			return v, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}, Timeout: time.Second}
}

func TestCymruParsesOriginAndName(t *testing.T) {
	c := cymruWith(map[string][]string{
		"4.4.8.8.origin.asn.cymru.com": {"15169 | 8.8.4.0/24 | US | arin | 1992-12-01"},
		"AS15169.asn.cymru.com":        {"15169 | US | arin | 2000-03-30 | GOOGLE, US"},
	})
	info, err := c.Lookup(context.Background(), ip("8.8.4.4"))
	if err != nil || info.Status != StatusOK || info.Prefix != "8.8.4.0/24" || len(info.ASNs) != 1 || info.ASNs[0].Name != "GOOGLE, US" {
		t.Errorf("%+v %v", info, err)
	}
	if info.Source != "cymru" {
		t.Errorf("source %s", info.Source)
	}
}

func TestCymruMultiOriginNoDataAndPartial(t *testing.T) {
	c := cymruWith(map[string][]string{
		"5.113.0.203.origin.asn.cymru.com": {"64500 64501 | 203.0.113.0/24 | ZZ | x | 2000-01-01"},
		"AS64500.asn.cymru.com":            {"64500 | ZZ | x | 2000-01-01 | ONE"},
		// AS64501 has no name record: the ASN is kept, a note is added.
	})
	info, err := c.Lookup(context.Background(), ip("203.0.113.5"))
	if err != nil || len(info.ASNs) != 2 || info.ASNs[0].Name != "ONE" || info.ASNs[1].Name != "" || info.Error == "" {
		t.Fatalf("%+v %v", info, err)
	}
	// NXDOMAIN on the origin zone: nobody announces it.
	nd, err := cymruWith(nil).Lookup(context.Background(), ip("203.0.113.9"))
	if err != nil || nd.Status != StatusNoData {
		t.Errorf("no data: %+v %v", nd, err)
	}
}

func TestCymruFailures(t *testing.T) {
	timeout := &Cymru{LookupTXT: func(ctx context.Context, n string) ([]string, error) {
		return nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	}}
	var le *LookupError
	if _, err := timeout.Lookup(context.Background(), ip("8.8.8.8")); !errors.As(err, &le) || le.Kind != KindTimeout {
		t.Errorf("timeout: %v", err)
	}
	broken := cymruWith(map[string][]string{"8.8.8.8.origin.asn.cymru.com": {"garbage"}})
	if _, err := broken.Lookup(context.Background(), ip("8.8.8.8")); !errors.As(err, &le) || le.Kind != KindBadResponse {
		t.Errorf("bad record: %v", err)
	}
	badASN := cymruWith(map[string][]string{"8.8.8.8.origin.asn.cymru.com": {"abc | 8.8.8.0/24 | US | arin | x"}})
	if _, err := badASN.Lookup(context.Background(), ip("8.8.8.8")); err == nil {
		t.Error("unparseable ASN accepted")
	}
}

// ---- Service ----------------------------------------------------------------

type memCache struct {
	mu sync.Mutex
	m  map[string]Info
}

func newMem() *memCache { return &memCache{m: map[string]Info{}} }
func (c *memCache) Get(source, ip string) (Info, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	i, ok := c.m[source+"/"+ip]
	return i, ok, nil
}
func (c *memCache) Put(i Info) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[i.Source+"/"+i.IP] = i
	return nil
}

type fakeProv struct {
	name  string
	calls atomic.Int32
	fail  atomic.Bool
	seen  sync.Map
	delay time.Duration
	peak  atomic.Int32
	cur   atomic.Int32
}

func (p *fakeProv) Name() string { return p.name }
func (p *fakeProv) Lookup(ctx context.Context, a netip.Addr) (*Info, error) {
	p.calls.Add(1)
	p.seen.Store(a.String(), true)
	c := p.cur.Add(1)
	defer p.cur.Add(-1)
	for {
		pk := p.peak.Load()
		if c <= pk || p.peak.CompareAndSwap(pk, c) {
			break
		}
	}
	time.Sleep(p.delay)
	if p.fail.Load() {
		return nil, &LookupError{KindHTTP, "boom"}
	}
	return &Info{ASNs: []Number{{ASN: 64500, Name: "Net " + a.String()}}, Prefix: "203.0.113.0/24", Status: StatusOK}, nil
}

func TestServiceDedupesOrdersAndSkipsNonPublic(t *testing.T) {
	p := &fakeProv{name: "fake"}
	s := NewService(p, newMem(), Config{})
	got := s.LookupMany(context.Background(), []netip.Addr{ip("8.8.8.8"), ip("10.0.0.1"), ip("8.8.8.8"), ip("::ffff:8.8.4.4"), ip("169.254.169.254"), ip("127.0.0.1")})
	if len(got) != 5 {
		t.Fatalf("len = %d: %+v", len(got), got)
	}
	if got[0].IP != "8.8.8.8" || got[1].IP != "10.0.0.1" || got[2].IP != "8.8.4.4" {
		t.Errorf("order/normalisation: %v", got)
	}
	for _, i := range []int{1, 3, 4} {
		if got[i].Status != StatusSkipped || len(got[i].ASNs) != 0 {
			t.Errorf("non-public %s: %+v", got[i].IP, got[i])
		}
	}
	for _, private := range []string{"10.0.0.1", "169.254.169.254", "127.0.0.1"} {
		if _, sent := p.seen.Load(private); sent {
			t.Errorf("private address %s was sent to the provider", private)
		}
	}
	if p.calls.Load() != 2 {
		t.Errorf("provider calls = %d", p.calls.Load())
	}
}

func TestServiceCachesForTTLAndKeysBySource(t *testing.T) {
	mem := newMem()
	p := &fakeProv{name: "srcA"}
	s := NewService(p, mem, Config{})
	now := time.Now()
	s.now = func() time.Time { return now }

	s.LookupMany(context.Background(), []netip.Addr{ip("8.8.8.8")})
	s.LookupMany(context.Background(), []netip.Addr{ip("8.8.8.8")})
	if p.calls.Load() != 1 {
		t.Fatalf("second lookup should hit the cache: %d calls", p.calls.Load())
	}
	now = now.Add(23 * time.Hour)
	s.LookupMany(context.Background(), []netip.Addr{ip("8.8.8.8")})
	if p.calls.Load() != 1 {
		t.Errorf("still fresh at 23h: %d calls", p.calls.Load())
	}
	now = now.Add(2 * time.Hour)
	s.LookupMany(context.Background(), []netip.Addr{ip("8.8.8.8")})
	if p.calls.Load() != 2 {
		t.Errorf("expired entry not refreshed: %d calls", p.calls.Load())
	}

	// Another source sharing the same cache must not see srcA's answer.
	other := &fakeProv{name: "srcB"}
	NewService(other, mem, Config{}).LookupMany(context.Background(), []netip.Addr{ip("8.8.8.8")})
	if other.calls.Load() != 1 {
		t.Errorf("cache leaked across sources: %d calls", other.calls.Load())
	}
}

func TestServiceNoCacheBypassesEverything(t *testing.T) {
	mem := newMem()
	p := &fakeProv{name: "fake"}
	s := NewService(p, mem, Config{NoCache: true})
	s.LookupMany(context.Background(), []netip.Addr{ip("8.8.8.8")})
	s.LookupMany(context.Background(), []netip.Addr{ip("8.8.8.8")})
	if p.calls.Load() != 2 || len(mem.m) != 0 || s.Caching() {
		t.Errorf("calls=%d cached=%d caching=%v", p.calls.Load(), len(mem.m), s.Caching())
	}
}

func TestServiceFailuresAreRecordedAndRetriedSoon(t *testing.T) {
	p := &fakeProv{name: "fake"}
	p.fail.Store(true)
	s := NewService(p, newMem(), Config{})
	now := time.Now()
	s.now = func() time.Time { return now }

	got := s.LookupMany(context.Background(), []netip.Addr{ip("8.8.8.8"), ip("1.1.1.1")})
	for _, g := range got {
		if g.Status != StatusFailed || g.Error != KindHTTP || len(g.ASNs) != 0 || g.IP == "" {
			t.Errorf("failure must keep the IP and say why: %+v", g)
		}
	}
	s.LookupMany(context.Background(), []netip.Addr{ip("8.8.8.8")})
	if p.calls.Load() != 2 {
		t.Errorf("a fresh failure should not hammer the source: %d calls", p.calls.Load())
	}
	now = now.Add(3 * time.Minute)
	p.fail.Store(false)
	got = s.LookupMany(context.Background(), []netip.Addr{ip("8.8.8.8")})
	if got[0].Status != StatusOK || p.calls.Load() != 3 {
		t.Errorf("failure should be retried after the negative TTL: %+v (%d calls)", got[0], p.calls.Load())
	}
}

func TestServiceConcurrencyIsBounded(t *testing.T) {
	p := &fakeProv{name: "fake", delay: 30 * time.Millisecond}
	s := NewService(p, nil, Config{Concurrency: 3})
	var ips []netip.Addr
	for i := 1; i <= 12; i++ {
		ips = append(ips, ip(fmt.Sprintf("8.8.8.%d", i)))
	}
	got := s.LookupMany(context.Background(), ips)
	if len(got) != 12 || p.peak.Load() > 3 {
		t.Errorf("results=%d peak=%d", len(got), p.peak.Load())
	}
	if s.Caching() {
		t.Error("nil cache must not report caching")
	}
}
