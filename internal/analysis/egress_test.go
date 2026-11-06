package analysis

import (
	"testing"

	"github.com/nyktios/sniroute/internal/server"
)

// att builds an attempt view. ip=="" means the observer saw nothing.
func att(target, sni, kind, ip string, state server.AttemptState) server.AttemptView {
	a := server.AttemptView{Target: target, SNI: sni, Kind: kind, State: state}
	if ip != "" {
		a.Observation = &server.Observation{SourceIP: ip, ObservedSNI: sni, SNIMatch: true}
	}
	return a
}

func find(t *testing.T, g Group, sni string) DomainEgress {
	t.Helper()
	for _, d := range g.Domains {
		if d.SNI == sni {
			return d
		}
	}
	t.Fatalf("domain %s missing in %+v", sni, g)
	return DomainEgress{}
}

const (
	v4 = "198.51.100.1:443"
	v6 = "[2001:db8::1]:443"
	au = server.StateAuthenticated
)

func TestEgressClassification(t *testing.T) {
	v := server.TaskView{Attempts: []server.AttemptView{
		att(v4, "b1.invalid", "baseline", "10.0.0.1", au),
		att(v4, "b2.invalid", "baseline", "10.0.0.1", au),
		att(v4, "same.com", "domain", "10.0.0.1", au),
		att(v4, "same.com", "domain", "10.0.0.1", au),
		att(v4, "other.com", "domain", "10.0.0.9", au),
		att(v4, "other.com", "domain", "10.0.0.9", au),
		att(v4, "mixed.com", "domain", "10.0.0.1", au),
		att(v4, "mixed.com", "domain", "10.0.0.9", au),
		att(v4, "gone.com", "domain", "", server.StateUnobserved),
	}}
	g := EgressByGroup(v)
	if len(g) != 1 || g[0].BaselineObserved != 2 || len(g[0].BaselineIPs) != 1 {
		t.Fatalf("group: %+v", g)
	}
	for sni, want := range map[string]Egress{
		"same.com": SameAsBaseline, "other.com": DifferentFromBaseline, "mixed.com": Mixed, "gone.com": Unobserved,
	} {
		if got := find(t, g[0], sni).Result; got != want {
			t.Errorf("%s = %s, want %s", sni, got, want)
		}
	}
	if d := find(t, g[0], "other.com"); d.Observed != 2 || d.IPs["10.0.0.9"] != 2 || d.Evidence.Authenticated != 2 {
		t.Errorf("other.com details: %+v", d)
	}
}

func TestDynamicPoolIsNotDomainSpecific(t *testing.T) {
	// The baseline itself rotates between two IPs; a domain seen on those
	// same IPs must not be reported as having its own egress.
	v := server.TaskView{Attempts: []server.AttemptView{
		att(v4, "b.invalid", "baseline", "10.0.0.1", au),
		att(v4, "b.invalid", "baseline", "10.0.0.2", au),
		att(v4, "a.com", "domain", "10.0.0.1", au),
		att(v4, "a.com", "domain", "10.0.0.2", au),
	}}
	if got := find(t, EgressByGroup(v)[0], "a.com").Result; got != DynamicPool {
		t.Errorf("result = %s", got)
	}
}

func TestNoBaselineAndUnobservedNeverInvented(t *testing.T) {
	v := server.TaskView{Attempts: []server.AttemptView{
		att(v4, "a.com", "domain", "10.0.0.1", au),
		att(v4, "b.com", "domain", "", server.StateTimeout),
	}}
	g := EgressByGroup(v)[0]
	if find(t, g, "a.com").Result != NoBaseline || find(t, g, "b.com").Result != Unobserved {
		t.Errorf("groups: %+v", g)
	}
	// A baseline that was planned but never observed is not "same as baseline".
	v.Attempts = append(v.Attempts, att(v4, "b.invalid", "baseline", "", server.StateUnobserved))
	g = EgressByGroup(v)[0]
	if g.BaselinePlanned != 1 || g.BaselineObserved != 0 || find(t, g, "a.com").Result != NoBaseline {
		t.Errorf("baseline unobserved: %+v", g)
	}
}

func TestGroupsAreSeparatedByTarget(t *testing.T) {
	// The same IP string in different groups must not leak across: IPv4 and
	// IPv6 targets are compared only with their own baseline.
	v := server.TaskView{Attempts: []server.AttemptView{
		att(v4, "b.invalid", "baseline", "10.0.0.1", au),
		att(v4, "a.com", "domain", "10.0.0.1", au),
		att(v6, "b.invalid", "baseline", "2001:db8::a", au),
		att(v6, "a.com", "domain", "2001:db8::b", au),
	}}
	g := EgressByGroup(v)
	if len(g) != 2 || g[0].Target != v4 || g[1].Target != v6 {
		t.Fatalf("groups: %+v", g)
	}
	if find(t, g[0], "a.com").Result != SameAsBaseline || find(t, g[1], "a.com").Result != DifferentFromBaseline {
		t.Errorf("v4=%s v6=%s", find(t, g[0], "a.com").Result, find(t, g[1], "a.com").Result)
	}
}

func TestUnreliableObservationsAreNotUsed(t *testing.T) {
	mismatch := att(v4, "a.com", "domain", "10.0.0.9", server.StateSNIMismatch)
	mismatch.Observation.SNIMatch = false
	ambiguous := att(v4, "a.com", "domain", "", server.StateHelloAmbig)
	ambiguous.Observation = &server.Observation{} // observation row exists but has no source
	hello := att(v4, "a.com", "domain", "10.0.0.1", server.StateHelloMatched)

	v := server.TaskView{Attempts: []server.AttemptView{
		att(v4, "b.invalid", "baseline", "10.0.0.1", au), mismatch, ambiguous, hello,
	}}
	d := find(t, EgressByGroup(v)[0], "a.com")
	if d.Planned != 3 || d.Observed != 1 || d.Evidence.HelloMatched != 1 || d.Evidence.Authenticated != 0 || d.Result != SameAsBaseline {
		t.Errorf("domain: %+v", d)
	}
}

func TestSortedIPs(t *testing.T) {
	got := SortedIPs(map[string]int{"b": 1, "a": 1, "c": 5})
	if got[0] != "c" || got[1] != "a" || got[2] != "b" {
		t.Errorf("order: %v", got)
	}
}
