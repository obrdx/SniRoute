// Package analysis derives conclusions from recorded facts. Facts are never
// modified; everything here can be recomputed from a task view.
//
// This file implements only the "egress observation" dimension (what source
// IPs were observed for a domain compared with the baseline). Intervention
// and access judgments arrive with the web-access tests.
package analysis

import (
	"sort"

	"github.com/nyktios/sniroute/internal/server"
)

// Egress is the egress observation for one domain within one comparison group.
type Egress string

const (
	// SameAsBaseline: every observed IP is the baseline's only IP.
	SameAsBaseline Egress = "same_as_baseline"
	// DynamicPool: the baseline itself uses several IPs and the domain stays
	// inside that set, so no domain-specific egress is demonstrated.
	DynamicPool Egress = "dynamic_pool"
	// DifferentFromBaseline: the domain was only seen on IPs the baseline never used.
	DifferentFromBaseline Egress = "different_from_baseline"
	// Mixed: the domain was seen both on baseline IPs and on others.
	Mixed Egress = "mixed"
	// NoBaseline: the domain was observed but nothing was available to compare with.
	NoBaseline Egress = "no_baseline"
	// Unobserved: no usable observation. This is "not observed", never "no egress".
	Unobserved Egress = "unobserved"
)

// Evidence counts observations by strength.
type Evidence struct {
	Authenticated int `json:"authenticated"`
	HelloMatched  int `json:"hello_matched"`
}

// DomainEgress summarises one domain in one group.
type DomainEgress struct {
	SNI      string         `json:"sni"`
	Planned  int            `json:"planned"`
	Observed int            `json:"observed"` // usable observations (see usable)
	IPs      map[string]int `json:"ips"`
	Evidence Evidence       `json:"evidence"`
	Result   Egress         `json:"result"`
}

// Group is one comparison group: a single observer target (so IPv4 and IPv6,
// or different observers, are never mixed).
type Group struct {
	Target           string         `json:"target"`
	BaselineIPs      map[string]int `json:"baseline_ips"`
	BaselinePlanned  int            `json:"baseline_planned"`
	BaselineObserved int            `json:"baseline_observed"`
	Domains          []DomainEgress `json:"domains"`
}

// usable reports whether an attempt gives an observed source IP for the SNI
// that was planned. Mismatched SNIs and ambiguous matches are not used: they
// say nothing reliable about what happens to the planned name.
func usable(a server.AttemptView) bool {
	o := a.Observation
	if o == nil || o.SourceIP == "" || !o.SNIMatch {
		return false
	}
	return a.State == server.StateAuthenticated || a.State == server.StateHelloMatched
}

// EgressByGroup groups a task's attempts by target and compares each domain
// with the baseline of the same group. Domains keep first-seen order.
func EgressByGroup(v server.TaskView) []Group {
	var groups []*Group
	byTarget := map[string]*Group{}
	domIdx := map[string]map[string]int{} // target -> sni -> index into Group.Domains
	for _, a := range v.Attempts {
		g := byTarget[a.Target]
		if g == nil {
			g = &Group{Target: a.Target, BaselineIPs: map[string]int{}}
			byTarget[a.Target] = g
			domIdx[a.Target] = map[string]int{}
			groups = append(groups, g)
		}
		if a.Kind == "baseline" {
			g.BaselinePlanned++
			if usable(a) {
				g.BaselineObserved++
				g.BaselineIPs[a.Observation.SourceIP]++
			}
			continue
		}
		i, seen := domIdx[a.Target][a.SNI]
		if !seen {
			g.Domains = append(g.Domains, DomainEgress{SNI: a.SNI, IPs: map[string]int{}})
			i = len(g.Domains) - 1
			domIdx[a.Target][a.SNI] = i
		}
		d := &g.Domains[i]
		d.Planned++
		if usable(a) {
			d.Observed++
			d.IPs[a.Observation.SourceIP]++
			if a.State == server.StateAuthenticated {
				d.Evidence.Authenticated++
			} else {
				d.Evidence.HelloMatched++
			}
		}
	}
	out := make([]Group, len(groups))
	for i, g := range groups {
		for j := range g.Domains {
			g.Domains[j].Result = classify(g.BaselineIPs, g.Domains[j].IPs)
		}
		out[i] = *g
	}
	return out
}

func classify(baseline, domain map[string]int) Egress {
	if len(domain) == 0 {
		return Unobserved
	}
	if len(baseline) == 0 {
		return NoBaseline
	}
	inside := 0
	for ip := range domain {
		if _, ok := baseline[ip]; ok {
			inside++
		}
	}
	switch {
	case inside == len(domain) && len(baseline) == 1:
		return SameAsBaseline
	case inside == len(domain):
		return DynamicPool
	case inside == 0:
		return DifferentFromBaseline
	default:
		return Mixed
	}
}

// SortedIPs returns the keys of an IP count map, most frequent first.
func SortedIPs(m map[string]int) []string {
	ips := make([]string, 0, len(m))
	for ip := range m {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		if m[ips[i]] != m[ips[j]] {
			return m[ips[i]] > m[ips[j]]
		}
		return ips[i] < ips[j]
	})
	return ips
}
