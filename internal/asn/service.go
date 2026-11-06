package asn

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// Cache persists lookups. Keys include the source, so switching sources never
// mixes their answers.
type Cache interface {
	Get(source, ip string) (Info, bool, error)
	Put(Info) error
}

// Config tunes a Service. Zero values select defaults.
type Config struct {
	TTL         time.Duration // freshness of successful answers, default 24h
	NegativeTTL time.Duration // freshness of failures, default 2m (so an outage is retried soon)
	NoCache     bool          // bypass the cache entirely
	Concurrency int           // parallel lookups, default 4
}

// Service looks up many addresses with caching, de-duplication, bounded
// concurrency and a public-address filter.
type Service struct {
	cfg       Config
	prov      Provider
	cache     Cache
	now       func() time.Time
	locations []*Service
}

// WithLocations attaches independently cached geolocation sources, ordered by
// preference. All are queried so disagreements can be shown to the user.
func (s *Service) WithLocations(sources ...*Service) *Service {
	s.locations = sources
	return s
}

// NewService wraps a provider. cache may be nil.
func NewService(p Provider, cache Cache, cfg Config) *Service {
	if cfg.TTL <= 0 {
		cfg.TTL = 24 * time.Hour
	}
	if cfg.NegativeTTL <= 0 {
		cfg.NegativeTTL = 2 * time.Minute
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}
	return &Service{cfg: cfg, prov: p, cache: cache, now: time.Now}
}

// Source is the provider name.
func (s *Service) Source() string { return s.prov.Name() }

// Caching reports whether the cache is in use.
func (s *Service) Caching() bool { return s.cache != nil && !s.cfg.NoCache }

func (s *Service) fresh(i Info) bool {
	age := s.now().Sub(i.QueriedAt)
	if i.Status == StatusFailed {
		return age < s.cfg.NegativeTTL
	}
	return age < s.cfg.TTL
}

// LookupMany returns one Info per distinct input address, in first-seen
// order. It never returns an error: failures are recorded per address, and
// non-public addresses are skipped without being sent anywhere.
func (s *Service) LookupMany(ctx context.Context, ips []netip.Addr) []Info {
	var order []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, ip := range ips {
		if ip = ip.Unmap(); ip.IsValid() && !seen[ip] {
			seen[ip] = true
			order = append(order, ip)
		}
	}
	out := make([]Info, len(order))
	locationResults := make([][]Info, len(s.locations))
	var locationWG sync.WaitGroup
	for i, source := range s.locations {
		locationWG.Add(1)
		go func() {
			defer locationWG.Done()
			locationResults[i] = source.LookupMany(ctx, order)
		}()
	}
	var todo []int
	for i, ip := range order {
		if !isPublic(ip) {
			out[i] = Info{IP: ip.String(), ASNs: []Number{}, Source: s.prov.Name(), QueriedAt: s.now(), Status: StatusSkipped}
			continue
		}
		if s.Caching() {
			if c, ok, err := s.cache.Get(s.prov.Name(), ip.String()); err == nil && ok && s.fresh(c) {
				out[i] = c
				continue
			}
		}
		todo = append(todo, i)
	}

	sem := make(chan struct{}, s.cfg.Concurrency)
	var wg sync.WaitGroup
	for _, i := range todo {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = s.lookupOne(ctx, order[i])
		}()
	}
	wg.Wait()
	locationWG.Wait()
	for _, results := range locationResults {
		for i, result := range results {
			if len(result.Locations) == 0 {
				out[i].Locations = append(out[i].Locations, Location{Source: result.Source, QueriedAt: result.QueriedAt, Status: result.Status, Error: result.Error})
			} else {
				out[i].Locations = append(out[i].Locations, result.Locations...)
			}
		}
	}
	return out
}

func (s *Service) lookupOne(ctx context.Context, ip netip.Addr) Info {
	lctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	info, err := s.prov.Lookup(lctx, ip)
	if err != nil || info == nil {
		return s.store(Info{IP: ip.String(), ASNs: []Number{}, Source: s.prov.Name(), QueriedAt: s.now(), Status: StatusFailed, Error: kindOf(err)})
	}
	info.IP, info.Source, info.QueriedAt = ip.String(), s.prov.Name(), s.now()
	for i := range info.Locations {
		info.Locations[i].Source, info.Locations[i].QueriedAt = info.Source, info.QueriedAt
	}
	if info.ASNs == nil {
		info.ASNs = []Number{}
	}
	return s.store(*info)
}

func (s *Service) store(i Info) Info {
	if s.Caching() {
		s.cache.Put(i) // a cache write failure must not fail the lookup
	}
	return i
}
