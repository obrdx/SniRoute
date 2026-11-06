// Package asn maps egress IP addresses to their Origin ASN(s), prefix and
// network name using public data sources (RIPEstat, Team Cymru).
//
// What it can say is narrow: which network announces the address. It cannot
// identify the retail provider the user bought a line from, nor transit
// operators or peers along the path. Lookups run on the observer, so whether
// the network under test can reach these services never affects probing. A
// failed lookup never invalidates the observed IP.
package asn

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Status of one lookup.
type Status string

const (
	StatusOK      Status = "ok"                // at least one Origin ASN found
	StatusNoData  Status = "no_data"           // the source knows no announcement for the address
	StatusFailed  Status = "failed"            // the lookup itself failed; the IP stays valid
	StatusSkipped Status = "skipped_nonpublic" // not a public address; never sent to a third party
)

// Number is one Origin ASN with its holder / AS name. Several can be
// returned for one prefix (multi-origin announcements); they are kept as a
// list and never collapsed into a single answer.
type Number struct {
	ASN  int    `json:"asn"`
	Name string `json:"name,omitempty"`
}

// Info is the outcome of looking up one IP.
type Info struct {
	IP        string     `json:"ip"`
	ASNs      []Number   `json:"asns"`
	Prefix    string     `json:"prefix,omitempty"`
	Source    string     `json:"source"`
	QueriedAt time.Time  `json:"queried_at"`
	Status    Status     `json:"status"`
	Error     string     `json:"error,omitempty"` // failure kind, or a note about a partial result
	Locations []Location `json:"locations,omitempty"`
}

// Location keeps each geolocation source separate, including missing fields,
// failures and query time. It is an estimate, not the physical server location.
type Location struct {
	Source      string    `json:"source"`
	QueriedAt   time.Time `json:"queried_at"`
	Status      Status    `json:"status"`
	Error       string    `json:"error,omitempty"`
	CountryCode string    `json:"country_code,omitempty"`
	Country     string    `json:"country,omitempty"`
	Region      string    `json:"region,omitempty"`
	City        string    `json:"city,omitempty"`
}

// Provider looks up one address in one data source.
type Provider interface {
	// Name is the source identifier ("ripestat", "cymru"); it keys the cache.
	Name() string
	// Lookup returns StatusOK or StatusNoData; any error is turned into
	// StatusFailed by the Service.
	Lookup(ctx context.Context, ip netip.Addr) (*Info, error)
}

// Failure kinds.
const (
	KindTimeout     = "timeout"
	KindRateLimited = "rate_limited"
	KindHTTP        = "http_error"
	KindBadResponse = "bad_response"
	KindUnavailable = "unavailable"
)

// LookupError carries a failure kind.
type LookupError struct {
	Kind string
	Msg  string
}

func (e *LookupError) Error() string { return e.Kind + ": " + e.Msg }

func kindOf(err error) string {
	var le *LookupError
	switch {
	case errors.As(err, &le):
		return le.Kind
	case errors.Is(err, context.DeadlineExceeded):
		return KindTimeout
	}
	return KindUnavailable
}

// Label formats an ASN for display: "AS15169 GOOGLE".
func (n Number) Label() string {
	s := "AS" + strconv.Itoa(n.ASN)
	if n.Name != "" {
		s += " " + n.Name
	}
	return s
}

// clamp makes externally supplied text safe to store and print.
func clamp(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}
