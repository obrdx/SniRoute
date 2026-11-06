package asn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GeoAPI adapts the keyless IPinfo Legacy and GeoJS endpoints. Neither reads
// proxy environment variables. Source-specific results use separate cache keys.
type GeoAPI struct {
	Source  string
	BaseURL string
	Client  *http.Client
	mu      sync.Mutex
	retryAt time.Time
}

func NewIPinfo() *GeoAPI { return newGeoAPI("ipinfo", "https://ipinfo.io") }
func NewGeoJS() *GeoAPI  { return newGeoAPI("geojs", "https://get.geojs.io") }
func newGeoAPI(source, base string) *GeoAPI {
	return &GeoAPI{Source: source, BaseURL: base, Client: &http.Client{
		Timeout:       8 * time.Second,
		Transport:     &http.Transport{Proxy: nil, TLSHandshakeTimeout: 5 * time.Second},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}}
}
func (g *GeoAPI) Name() string { return g.Source }

func (g *GeoAPI) Lookup(ctx context.Context, ip netip.Addr) (*Info, error) {
	ip = ip.Unmap()
	if !isPublic(ip) {
		return &Info{IP: ip.String(), Source: g.Name(), Status: StatusSkipped}, nil
	}
	g.mu.Lock()
	limited := time.Now().Before(g.retryAt)
	g.mu.Unlock()
	if limited {
		return nil, &LookupError{KindRateLimited, "source cooling down"}
	}
	path := "/" + ip.String() + "/json"
	if g.Source == "geojs" {
		path = "/v1/ip/geo/" + ip.String() + ".json"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(g.BaseURL, "/")+path, nil)
	if err != nil {
		return nil, &LookupError{KindUnavailable, "invalid endpoint"}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := g.Client.Do(req)
	if err != nil {
		if ctx.Err() != nil || strings.Contains(err.Error(), "timeout") {
			return nil, &LookupError{KindTimeout, g.Source}
		}
		return nil, &LookupError{KindUnavailable, g.Source}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		delay := time.Minute
		if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && seconds > 0 {
			delay = time.Duration(min(seconds, 86400)) * time.Second
		} else if when, err := http.ParseTime(resp.Header.Get("Retry-After")); err == nil {
			delay = min(24*time.Hour, max(time.Minute, time.Until(when)))
		}
		g.mu.Lock()
		g.retryAt = time.Now().Add(delay)
		g.mu.Unlock()
		return nil, &LookupError{KindRateLimited, g.Source}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &LookupError{KindHTTP, fmt.Sprintf("%s: HTTP %d", g.Source, resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return nil, &LookupError{KindBadResponse, "invalid response size"}
	}
	var data struct {
		IP          string `json:"ip"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		Region      string `json:"region"`
		City        string `json:"city"`
		Bogon       bool   `json:"bogon"`
	}
	if json.Unmarshal(body, &data) != nil {
		return nil, &LookupError{KindBadResponse, "invalid JSON"}
	}
	returned, err := netip.ParseAddr(data.IP)
	if err != nil || returned.Unmap() != ip {
		return nil, &LookupError{KindBadResponse, "response IP mismatch"}
	}
	loc := Location{Source: g.Source, Status: StatusNoData}
	if !data.Bogon {
		loc.CountryCode = strings.ToUpper(clamp(data.CountryCode, 2))
		loc.Country = clamp(data.Country, 100)
		if g.Source == "ipinfo" {
			loc.CountryCode = strings.ToUpper(clamp(data.Country, 2))
			loc.Country = ""
		}
		loc.Region = clamp(data.Region, 160)
		loc.City = clamp(data.City, 160)
		if loc.CountryCode != "" || loc.Country != "" || loc.Region != "" || loc.City != "" {
			loc.Status = StatusOK
		}
	}
	return &Info{IP: ip.String(), Source: g.Source, ASNs: []Number{}, Status: loc.Status, Locations: []Location{loc}}, nil
}
