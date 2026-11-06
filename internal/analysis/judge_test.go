package analysis

import (
	"strings"
	"testing"

	"github.com/nyktios/sniroute/internal/asn"
	"github.com/nyktios/sniroute/internal/server"
)

// ---- fixtures ---------------------------------------------------------

type attOpt struct {
	kind, sni, target string
}

// one builds a single attempt from a compact outcome code:
//
//	ok:IP     authenticated receipt from IP
//	hello:IP  ClientHello matched at the observer, client failed afterwards
//	after     ClientHello sent, observer saw nothing, client timed out in TLS
//	afterhttp same, but failing in a different stage
//	pre       dial failed before any ClientHello
//	ident     public key did not match the pin
//	none      no record
func one(o attOpt, code string) server.AttemptView {
	a := server.AttemptView{Kind: o.kind, SNI: o.sni, Target: o.target}
	ev := func(outcome, stage string, hello bool) server.ClientEventView {
		return server.ClientEventView{Outcome: outcome, Stage: stage, HelloSent: hello}
	}
	obs := func(ip string) *server.Observation {
		return &server.Observation{SourceIP: ip, ObservedSNI: o.sni, SNIMatch: true}
	}
	switch {
	case strings.HasPrefix(code, "ok:"):
		a.State, a.Observation = server.StateAuthenticated, obs(code[3:])
		a.Client = []server.ClientEventView{ev("receipt", "http", true)}
	case strings.HasPrefix(code, "hello:"):
		a.State, a.Observation = server.StateHelloMatched, obs(code[6:])
		a.Client = []server.ClientEventView{ev("timeout", "tls", true)}
	case code == "after":
		a.State, a.Client = server.StateUnobserved, []server.ClientEventView{ev("timeout", "tls", true)}
	case code == "afterhttp":
		a.State, a.Client = server.StateUnobserved, []server.ClientEventView{ev("http_failed", "http", true)}
	case code == "pre":
		a.State, a.Client = server.StateUnobserved, []server.ClientEventView{ev("dial_failed", "tcp", false)}
	case code == "ident":
		a.State, a.Client = server.StateUnobserved, []server.ClientEventView{ev("identity_mismatch", "tls", true)}
	default:
		a.State = server.StateTimeout
	}
	return a
}

const (
	T4 = "198.51.100.1:443"
	T6 = "[2001:db8::1]:443"
)

func attempts(target, sni, kind string, codes ...string) []server.AttemptView {
	var out []server.AttemptView
	for _, c := range codes {
		out = append(out, one(attOpt{kind, sni, target}, c))
	}
	return out
}

func cat(parts ...[]server.AttemptView) []server.AttemptView {
	var out []server.AttemptView
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func view(parts ...[]server.AttemptView) server.TaskView {
	return server.TaskView{Attempts: cat(parts...)}
}

func get(t *testing.T, r Report, sni string) Judgment {
	t.Helper()
	for _, g := range r.Groups {
		for _, d := range g.Domains {
			if d.SNI == sni {
				return d
			}
		}
	}
	t.Fatalf("no judgment for %s", sni)
	return Judgment{}
}

func rule(j Judgment, id string) (RuleHit, bool) {
	for _, h := range j.Rules {
		if h.ID == id {
			return h, true
		}
	}
	return RuleHit{}, false
}

func need(t *testing.T, j Judgment, id string) RuleHit {
	t.Helper()
	h, ok := rule(j, id)
	if !ok {
		t.Fatalf("rule %s did not fire; rules=%+v", id, j.Rules)
	}
	return h
}

func mustNot(t *testing.T, j Judgment, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if _, ok := rule(j, id); ok {
			t.Errorf("rule %s fired but must not: %+v", id, j.Rules)
		}
	}
}

var goodBase = attempts(T4, "b.invalid", "baseline", "ok:10.0.0.1", "ok:10.0.0.1", "ok:10.0.0.1")

// ---- egress rules -----------------------------------------------------

func TestR01StableDifference(t *testing.T) {
	v := view(goodBase, attempts(T4, "d.com", "domain", "ok:10.0.0.9", "ok:10.0.0.9", "ok:10.0.0.9"))
	j := get(t, Judge(v), "d.com")
	need(t, j, "R01")
	// Egress observations and probe outcomes remain separate dimensions.
	if j.Egress != DifferentFromBaseline || j.Probe != ProbeFull {
		t.Errorf("dimensions: %+v", j)
	}
	if j.Intervention != LevelNone {
		t.Errorf("an egress difference must not be read as intervention: %s", j.Intervention)
	}
	if j.CauseConfidence != ConfMedium || j.FactConfidence != ConfHigh {
		t.Errorf("confidence: fact=%s cause=%s", j.FactConfidence, j.CauseConfidence)
	}
	lim := strings.Join(need(t, j, "R01").Limits, " ")
	if !strings.Contains(lim, "不代表真实网站") || !strings.Contains(lim, "不能证明上游仅以 SNI") {
		t.Errorf("R01 must carry its limits: %s", lim)
	}
}

func TestR01WeakWhenUnstable(t *testing.T) {
	v := view(goodBase, attempts(T4, "d.com", "domain", "ok:10.0.0.9"))
	h := need(t, get(t, Judge(v), "d.com"), "R01")
	if !strings.Contains(h.Conclusion, "迹象") || strings.Contains(h.Conclusion, "观测到与 SNI 相关的出口差异") {
		t.Errorf("single sample must not be reported as an established difference: %s", h.Conclusion)
	}
	v = view(goodBase, attempts(T4, "d.com", "domain", "ok:10.0.0.8", "ok:10.0.0.9", "ok:10.0.0.9"))
	h = need(t, get(t, Judge(v), "d.com"), "R01")
	if !strings.Contains(h.Conclusion, "迹象") {
		t.Errorf("two different IPs for the domain is not a stable difference: %s", h.Conclusion)
	}
}

func TestR02DynamicPoolIsNotDomainSpecific(t *testing.T) {
	base := attempts(T4, "b.invalid", "baseline", "ok:10.0.0.1", "ok:10.0.0.2", "ok:10.0.0.1")
	v := view(base, attempts(T4, "d.com", "domain", "ok:10.0.0.2", "ok:10.0.0.1", "ok:10.0.0.2"))
	j := get(t, Judge(v), "d.com")
	need(t, j, "R02")
	mustNot(t, j, "R01")
	if j.CauseConfidence != ConfNone {
		t.Errorf("no cause is claimed for a dynamic pool, got %s", j.CauseConfidence)
	}
}

// ---- controlled-probe failure rules ---------------------------------------

func TestR03FailureBeforeHelloIsNotAttributedToSNI(t *testing.T) {
	v := view(goodBase, attempts(T4, "d.com", "domain", "pre", "pre", "pre"))
	j := get(t, Judge(v), "d.com")
	need(t, j, "R03")
	mustNot(t, j, "R04")
	if j.Probe != ProbePreHello || j.Intervention != LevelNone || j.Egress != Unobserved {
		t.Errorf("%+v", j)
	}
}

func TestR04RepeatedFailureIsSuspected(t *testing.T) {
	failing := attempts(T4, "d.com", "domain", "after", "after", "after")
	j := get(t, Judge(view(goodBase, failing)), "d.com")
	need(t, j, "R04")
	if j.Intervention != LevelSuspected || j.CauseConfidence != ConfLow || j.Probe != ProbeHandshakeErr || j.Egress != Unobserved {
		t.Errorf("suspected: %+v", j)
	}
	h := need(t, j, "R04")
	if !strings.Contains(strings.Join(h.Limits, " "), "不能区分") {
		t.Errorf("R04 must state what it cannot distinguish: %v", h.Limits)
	}

}

func TestR04NeedsRepetitionAndMajority(t *testing.T) {
	// One failure is noise.
	j := get(t, Judge(view(goodBase, attempts(T4, "d.com", "domain", "after", "ok:10.0.0.1", "ok:10.0.0.1"))), "d.com")
	mustNot(t, j, "R04")
	if j.Intervention != LevelNone || j.Probe != ProbeMixed {
		t.Errorf("single failure: %+v", j)
	}
	// Two failures out of five is not a majority.
	j = get(t, Judge(view(goodBase, attempts(T4, "d.com", "domain", "after", "after", "ok:10.0.0.1", "ok:10.0.0.1", "ok:10.0.0.1"))), "d.com")
	mustNot(t, j, "R04")
}

func TestR09UnhealthyBaselineSuppressesDomainConclusions(t *testing.T) {
	badBase := attempts(T4, "b.invalid", "baseline", "ok:10.0.0.1", "after", "pre")
	v := view(badBase,
		attempts(T4, "d.com", "domain", "after", "after", "after"),
		attempts(T4, "e.com", "domain", "pre", "pre", "pre"))
	r := Judge(v)
	for _, sni := range []string{"d.com", "e.com"} {
		j := get(t, r, sni)
		need(t, j, "R09")
		mustNot(t, j, "R03", "R04")
		if j.Intervention != LevelNone {
			t.Errorf("%s: intervention %s despite an unhealthy baseline", sni, j.Intervention)
		}
	}
}

func TestR05HelloReachedButHandshakeFailed(t *testing.T) {
	v := view(goodBase, attempts(T4, "d.com", "domain", "hello:10.0.0.9", "hello:10.0.0.9", "ok:10.0.0.9"))
	j := get(t, Judge(v), "d.com")
	h := need(t, j, "R05")
	if !strings.Contains(h.Conclusion, "已到达") || j.Probe != ProbeMixed || j.Intervention != LevelNone {
		t.Errorf("%+v", j)
	}
	// The observed egress is kept even though nothing was authenticated.
	if j.Egress != DifferentFromBaseline {
		t.Errorf("egress from hello-matched evidence lost: %s", j.Egress)
	}
}

func TestR08IdentityMismatchIsNotABlock(t *testing.T) {
	v := view(goodBase, attempts(T4, "d.com", "domain", "ident", "ident", "ident"))
	j := get(t, Judge(v), "d.com")
	h := need(t, j, "R08")
	if j.Probe != ProbeIdentity || j.Intervention != LevelNone {
		t.Errorf("%+v", j)
	}
	if !strings.Contains(h.Conclusion, "不判定为域名封锁") || !strings.Contains(h.Conclusion, "未发送任何凭证") {
		t.Errorf("conclusion: %s", h.Conclusion)
	}
}

// ---- real-site access rules ----------------------------------------------

func TestR10NothingExecutedIsNotAFailure(t *testing.T) {
	v := view(goodBase, attempts(T4, "d.com", "domain", "none", "none", "none"))
	j := get(t, Judge(v), "d.com")
	need(t, j, "R10")
	if j.Probe != ProbeNone || j.Intervention != LevelNone || j.Completeness != Partial || j.Egress != Unobserved {
		t.Errorf("%+v", j)
	}
}

func TestCompletenessDimension(t *testing.T) {
	// Some planned attempts have no record: partial.
	j := get(t, Judge(view(goodBase, attempts(T4, "d.com", "domain", "ok:10.0.0.1", "none"))), "d.com")
	if j.Completeness != Partial {
		t.Errorf("partial: %s", j.Completeness)
	}
	// Observer facts without the client's report: missing control data.
	a := attempts(T4, "d.com", "domain", "ok:10.0.0.1")
	a[0].Client = nil
	j = get(t, Judge(view(goodBase, a)), "d.com")
	if j.Completeness != MissingControl {
		t.Errorf("missing control: %s", j.Completeness)
	}
	if j := get(t, Judge(view(goodBase, attempts(T4, "d.com", "domain", "ok:10.0.0.1"))), "d.com"); j.Completeness != Complete {
		t.Errorf("complete: %s", j.Completeness)
	}
}

func TestGroupsAreJudgedIndependently(t *testing.T) {
	badV6 := attempts(T6, "b.invalid", "baseline", "after", "after", "ok:2001:db8::a")
	v := view(
		goodBase, attempts(T4, "d.com", "domain", "after", "after", "after"),
		badV6, attempts(T6, "d.com", "domain", "after", "after", "after"))
	r := Judge(v)
	var v4, v6 Judgment
	for _, g := range r.Groups {
		if g.Group.Target == T4 {
			v4 = g.Domains[0]
		} else {
			v6 = g.Domains[0]
		}
	}
	need(t, v4, "R04") // IPv4 baseline is healthy
	need(t, v6, "R09") // IPv6 baseline is not: environment doubt, no domain conclusion
	mustNot(t, v6, "R04")
}

func TestJudgmentsStayWithinTheirBounds(t *testing.T) {
	// Across a spread of scenarios no judgment may claim explicit blocking or
	// high-confidence causes, and every judgment must carry the rule version.
	scenarios := []server.TaskView{
		view(goodBase, attempts(T4, "d.com", "domain", "after", "after", "after")),
		view(goodBase, attempts(T4, "d.com", "domain", "ok:10.0.0.9", "ok:10.0.0.9", "ok:10.0.0.9")),
		view(goodBase, attempts(T4, "d.com", "domain", "ok:10.0.0.9", "ok:10.0.0.9", "ok:10.0.0.9")),
	}
	for i, v := range scenarios {
		r := Judge(v)
		if r.RulesVersion != RulesVersion {
			t.Errorf("scenario %d: version %q", i, r.RulesVersion)
		}
		for _, g := range r.Groups {
			for _, j := range g.Domains {
				if j.Intervention == LevelExplicit || j.CauseConfidence == ConfHigh {
					t.Errorf("scenario %d: overclaim %+v", i, j)
				}
			}
		}
	}
}

func TestCancelledTaskDoesNotTurnUnrunAttemptsIntoFailures(t *testing.T) {
	cancelled := func(sni string) []server.AttemptView {
		return []server.AttemptView{
			{Kind: "domain", SNI: sni, Target: T4, State: server.StateCancelled},
			{Kind: "domain", SNI: sni, Target: T4, State: server.StateCancelled},
		}
	}
	v := view(goodBase, cat(attempts(T4, "ran.com", "domain", "ok:10.0.0.1", "ok:10.0.0.1"), cancelled("ran.com")), cancelled("never.com"))
	v.Status = server.TaskAborted
	r := Judge(v)

	ran, never := get(t, r, "ran.com"), get(t, r, "never.com")
	if ran.Completeness != Cancelled || ran.Probe != ProbeFull || ran.Intervention != LevelNone {
		t.Errorf("partly run domain: %+v", ran)
	}
	need(t, never, "R10")
	if never.Probe != ProbeNone || never.Completeness != Cancelled || never.Intervention != LevelNone ||
		!strings.Contains(need(t, never, "R10").Conclusion, "取消") {
		t.Errorf("never-run domain: %+v", never)
	}
	// The baseline is judged on what ran; unrun baseline attempts are not failures.
	for _, g := range r.Groups {
		if g.Baseline.Failed != 0 {
			t.Errorf("baseline failures = %d", g.Baseline.Failed)
		}
	}
}

// ---- egress networks (ASN) as context ------------------------------------------

func withNets(v server.TaskView, items ...asn.Info) server.TaskView {
	v.ASN = &server.ASNView{Snapshot: 1, Snapshots: 1, Source: "ripestat", Items: items}
	return v
}

func netInfo(ip string, n int, name string) asn.Info {
	return asn.Info{IP: ip, Status: asn.StatusOK, Source: "ripestat", ASNs: []asn.Number{{ASN: n, Name: name}}}
}

func diverted() server.TaskView {
	return view(goodBase, attempts(T4, "d.com", "domain", "ok:10.0.0.9", "ok:10.0.0.9", "ok:10.0.0.9"))
}

func TestDifferentIPsInOneASNAreOnlyWeakEvidenceOfADifferentNetwork(t *testing.T) {
	v := withNets(diverted(), netInfo("10.0.0.1", 64500, "ExampleNet"), netInfo("10.0.0.9", 64500, "ExampleNet"))
	j := get(t, Judge(v), "d.com")
	h := need(t, j, "R01")
	if !strings.Contains(strings.Join(h.Limits, " "), "同一 ASN") {
		t.Errorf("the same-ASN caveat is missing: %v", h.Limits)
	}
	if j.CauseConfidence != ConfLow {
		t.Errorf("same-ASN difference must not keep medium confidence: %s", j.CauseConfidence)
	}
	if len(j.Networks) != 1 || !strings.HasPrefix(j.Networks[0], "AS64500") {
		t.Errorf("networks: %v", j.Networks)
	}
}

func TestDifferentASNsAreReportedAsContext(t *testing.T) {
	v := withNets(diverted(), netInfo("10.0.0.1", 64500, "BaseNet"), netInfo("10.0.0.9", 64501, "OtherNet"))
	j := get(t, Judge(v), "d.com")
	h := need(t, j, "R01")
	joined := strings.Join(h.Basis, " ")
	if !strings.Contains(joined, "AS64501 OtherNet") || !strings.Contains(joined, "AS64500 BaseNet") {
		t.Errorf("basis: %v", h.Basis)
	}
	if strings.Contains(strings.Join(h.Limits, " "), "同一 ASN") {
		t.Errorf("wrongly claims the same ASN: %v", h.Limits)
	}
	if j.CauseConfidence != ConfMedium {
		t.Errorf("a clean, repeated, cross-ASN difference keeps medium: %s", j.CauseConfidence)
	}
	// The cause is never read from the ASN names; the rule fired from the IPs.
	if j.Egress != DifferentFromBaseline {
		t.Errorf("egress: %s", j.Egress)
	}
}

func TestMissingLookupsNeverCountAsDifferentNetworks(t *testing.T) {
	// One side failed or was never queried: no comparison is made at all.
	failedLookup := asn.Info{IP: "10.0.0.1", Status: asn.StatusFailed, Error: asn.KindTimeout}
	for name, v := range map[string]server.TaskView{
		"baseline lookup failed": withNets(diverted(), failedLookup, netInfo("10.0.0.9", 64501, "OtherNet")),
		"domain lookup missing":  withNets(diverted(), netInfo("10.0.0.1", 64500, "BaseNet")),
		"no snapshot at all":     diverted(),
	} {
		j := get(t, Judge(v), "d.com")
		h := need(t, j, "R01")
		joined := strings.Join(h.Basis, " ") + strings.Join(h.Limits, " ")
		if strings.Contains(joined, "出口网络：") || strings.Contains(joined, "同一 ASN") {
			t.Errorf("%s: compared networks despite a gap: %v %v", name, h.Basis, h.Limits)
		}
		if j.CauseConfidence != ConfMedium {
			t.Errorf("%s: confidence changed to %s", name, j.CauseConfidence)
		}
	}
}
