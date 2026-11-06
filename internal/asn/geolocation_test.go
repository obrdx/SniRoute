package asn

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestKeylessGeoAPIs(t *testing.T) {
	for _, source := range []string{"ipinfo", "geojs"} {
		t.Run(source, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" {
					t.Error("unexpected credentials")
				}
				want := "/8.8.8.8/json"
				response := `{"ip":"8.8.8.8","country":"US","region":"California","city":"Mountain View","org":"AS15169 Google LLC"}`
				if source == "geojs" {
					want = "/v1/ip/geo/8.8.8.8.json"
					response = `{"ip":"8.8.8.8","country":"United States","country_code":"US","city":"Mountain View"}`
				}
				if r.URL.Path != want {
					t.Errorf("path: %s", r.URL.Path)
				}
				fmt.Fprint(w, response)
			}))
			defer srv.Close()
			p := newGeoAPI(source, srv.URL)
			svc := NewService(p, newMem(), Config{})
			first := svc.LookupMany(context.Background(), []netip.Addr{ip("8.8.8.8"), ip("8.8.8.8"), ip("127.0.0.1"), ip("::1")})
			second := svc.LookupMany(context.Background(), []netip.Addr{ip("8.8.8.8")})
			if calls.Load() != 1 || len(first) != 3 || first[1].Status != StatusSkipped || first[2].Status != StatusSkipped {
				t.Fatalf("calls=%d results=%+v", calls.Load(), first)
			}
			loc := second[0].Locations[0]
			if loc.Source != source || loc.CountryCode != "US" || loc.City != "Mountain View" || loc.QueriedAt.IsZero() {
				t.Fatalf("%+v", loc)
			}
		})
	}
}

func TestGeoValidationAndCooldown(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		kind       string
	}{
		{"wrong_ip", `{"ip":"1.1.1.1","country":"US"}`, 200, KindBadResponse},
		{"bad_json", `{`, 200, KindBadResponse},
		{"oversize", strings.Repeat(" ", maxBody) + `{}`, 200, KindBadResponse},
		{"redirect", "", 302, KindHTTP},
		{"limited", "", 429, KindRateLimited},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Retry-After", "120")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			p := newGeoAPI("ipinfo", srv.URL)
			_, err := p.Lookup(context.Background(), ip("8.8.8.8"))
			if err == nil || kindOf(err) != tc.kind {
				t.Fatalf("%v", err)
			}
			if tc.status == 429 {
				_, err = p.Lookup(context.Background(), ip("1.1.1.1"))
				if kindOf(err) != KindRateLimited || calls.Load() != 1 {
					t.Fatal("cooldown did not suppress requests")
				}
			}
		})
	}
}

func TestGeoIPv6AndCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/2001:4860:4860::8888/json" {
			t.Errorf("%s", r.URL.Path)
		}
		fmt.Fprint(w, `{"ip":"2001:4860:4860::8888","country":"US"}`)
	}))
	defer srv.Close()
	p := newGeoAPI("ipinfo", srv.URL)
	if _, err := p.Lookup(context.Background(), ip("2001:4860:4860::8888")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Lookup(ctx, ip("8.8.8.8")); kindOf(err) != KindTimeout {
		t.Fatalf("%v", err)
	}
}

func TestGeoEnrichmentPreservesASNAndSourceCaches(t *testing.T) {
	var geoCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		geoCalls.Add(1)
		fmt.Fprint(w, `{"ip":"8.8.8.8","country":"US","city":"Test City"}`)
	}))
	defer srv.Close()
	p := &fakeProv{name: "origin"}
	cache := newMem()
	svc := NewService(p, cache, Config{}).WithLocations(NewService(newGeoAPI("ipinfo", srv.URL), cache, Config{}))
	addrs := []netip.Addr{ip("8.8.8.8"), ip("10.0.0.1")}
	first := svc.LookupMany(context.Background(), addrs)
	second := svc.LookupMany(context.Background(), addrs)
	if p.calls.Load() != 1 || geoCalls.Load() != 1 || len(second[0].Locations) != 1 || second[0].ASNs[0].ASN != 64500 {
		t.Fatalf("%+v", second)
	}
	if second[1].Locations[0].Status != StatusSkipped {
		t.Fatal("private location was queried")
	}
	// Geo data failures remain independent from valid Origin ASN facts.
	p2 := &fakeProv{name: "origin2"}
	failed := NewService(newGeoAPI("ipinfo", srv.URL), nil, Config{})
	failed.prov.(*GeoAPI).retryAt = time.Now().Add(time.Hour)
	result := NewService(p2, nil, Config{}).WithLocations(failed).LookupMany(context.Background(), addrs[:1])[0]
	if result.Status != StatusOK || result.ASNs[0].ASN != 64500 || result.Locations[0].Status != StatusFailed {
		t.Fatalf("%+v", result)
	}
	if len(first[0].Locations) != 1 {
		t.Fatal("previous result changed")
	}
}

func TestLocationPreferenceConflictAndFill(t *testing.T) {
	loc := func(source, code, region, city string) Location {
		return Location{Source: source, Status: StatusOK, CountryCode: code, Region: region, City: city}
	}
	for _, tc := range []struct {
		name      string
		locations []Location
		want      string
	}{
		{"agreement", []Location{loc("geojs", "US", "California", "Mountain View"), loc("ipinfo", "US", "California", "Mountain View")}, "US / California / Mountain View"},
		{"conflict", []Location{loc("ipinfo", "US", "California", "Mountain View"), loc("geojs", "DE", "Hesse", "Frankfurt")}, "US / California / Mountain View（其他可能：DE / Hesse / Frankfurt，GeoJS）"},
		{"missing_city", []Location{loc("ipinfo", "US", "California", ""), loc("geojs", "US", "California", "Mountain View")}, "US / California / Mountain View（城市由 GeoJS 补充）"},
		{"no_mixed_place", []Location{loc("ipinfo", "US", "California", ""), loc("geojs", "DE", "Hesse", "Frankfurt")}, "US / California（其他可能：DE / Hesse / Frankfurt，GeoJS）"},
		{"ipinfo_failed", []Location{{Source: "ipinfo", Status: StatusFailed, Error: "debug-detail"}, loc("geojs", "US", "California", "Mountain View")}, "US / California / Mountain View（由 GeoJS 补充）"},
		{"unknown", nil, "未知"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := LocationText(tc.locations); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
