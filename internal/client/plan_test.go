package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nyktios/sniroute/internal/pack"
	"slices"
	"strings"
	"testing"
)

func TestBuildPlanStructure(t *testing.T) {
	spec := PlanSpec{
		Targets: []string{"198.51.100.1:443", "[2001:db8::1]:443"}, Domains: []string{"a.com", "b.com", "c.com"},
		Baseline: []string{"x.invalid", "y.invalid"}, Rounds: 3, Seed: 5,
	}
	plan, seed, err := BuildPlan(spec)
	if err != nil || seed != 5 {
		t.Fatalf("plan: %v seed=%d", err, seed)
	}
	// 3 domains x 3 rounds x 2 targets + baseline (2 names x 2 targets) x 3 slots.
	if want := 3*3*2 + 2*2*3; len(plan) != want {
		t.Fatalf("len = %d, want %d", len(plan), want)
	}

	counts := map[[3]string]int{} // (target, sni, kind)
	roundOf := map[int][]int{}    // baseline slot -> positions
	var lastDomainPos int
	for i, a := range plan {
		counts[[3]string{a.Target, a.SNI, a.Kind}]++
		if a.Kind == "baseline" {
			roundOf[a.Round] = append(roundOf[a.Round], i)
		} else {
			lastDomainPos = i
		}
	}
	// Every (target, domain) pair is visited once per round; every
	// (target, baseline) once per slot. IPv4 and IPv6 are separate groups.
	for _, tg := range spec.Targets {
		for _, d := range spec.Domains {
			if n := counts[[3]string{tg, d, "domain"}]; n != 3 {
				t.Errorf("%s %s: %d attempts", tg, d, n)
			}
		}
		for _, b := range spec.Baseline {
			if n := counts[[3]string{tg, b, "baseline"}]; n != 3 {
				t.Errorf("%s %s baseline: %d attempts", tg, b, n)
			}
		}
	}
	// Baseline is interleaved: slots at round 0, 2 (middle), 3 (end); the first
	// precedes every domain attempt and the last follows all of them.
	if len(roundOf) != 3 || len(roundOf[0]) == 0 || len(roundOf[2]) == 0 || len(roundOf[3]) == 0 {
		t.Fatalf("baseline slots: %v", roundOf)
	}
	if roundOf[0][0] != 0 || roundOf[3][len(roundOf[3])-1] != len(plan)-1 || roundOf[3][0] < lastDomainPos {
		t.Errorf("baseline not at start/end: %v last domain at %d", roundOf, lastDomainPos)
	}
	if mid := roundOf[2][0]; mid <= roundOf[0][len(roundOf[0])-1] || mid >= roundOf[3][0] {
		t.Errorf("middle slot misplaced: %v", roundOf[2])
	}
}

func TestBuildPlanDeterministicAndShuffled(t *testing.T) {
	spec := PlanSpec{Targets: []string{"198.51.100.1:443"}, Domains: []string{"a", "b", "c", "d", "e", "f"}, Rounds: 4, Seed: 11}
	p1, _, _ := BuildPlan(spec)
	p2, _, _ := BuildPlan(spec)
	if !slices.Equal(p1, p2) {
		t.Error("same seed must give the same plan")
	}
	spec.Seed = 12
	if p3, _, _ := BuildPlan(spec); slices.Equal(p1, p3) {
		t.Error("different seeds gave identical plans")
	}
	// Rounds are shuffled independently: not every round has the same order.
	order := func(round int) []string {
		var o []string
		for _, a := range p1 {
			if a.Kind == "domain" && a.Round == round {
				o = append(o, a.SNI)
			}
		}
		return o
	}
	same := true
	for r := 2; r <= 4; r++ {
		if !slices.Equal(order(1), order(r)) {
			same = false
		}
	}
	if same {
		t.Error("all rounds visited domains in the same order")
	}
	// Random seed when none is given, and it is reported back.
	spec.Seed = 0
	if _, seed, _ := BuildPlan(spec); seed == 0 {
		t.Error("no seed reported")
	}
}

func TestBuildPlanShortRunsAndNoBaseline(t *testing.T) {
	one, _, err := BuildPlan(PlanSpec{Targets: []string{"198.51.100.1:443"}, Domains: []string{"a"}, Baseline: []string{"x.invalid"}, Rounds: 1, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	// One round: baseline before and after, no separate middle slot.
	if len(one) != 3 || one[0].Kind != "baseline" || one[1].Kind != "domain" || one[2].Kind != "baseline" {
		t.Errorf("one round: %+v", one)
	}
	none, _, _ := BuildPlan(PlanSpec{Targets: []string{"198.51.100.1:443"}, Domains: []string{"a", "b"}, Rounds: 2, Seed: 1})
	if len(none) != 4 {
		t.Errorf("no baseline: %d attempts", len(none))
	}
	for _, a := range none {
		if a.Kind != "domain" {
			t.Errorf("unexpected %+v", a)
		}
	}
}

func TestBuildPlanValidation(t *testing.T) {
	ok := PlanSpec{Targets: []string{"198.51.100.1:443"}, Domains: []string{"a"}}
	for name, mod := range map[string]func(*PlanSpec){
		"no targets": func(s *PlanSpec) { s.Targets = nil },
		"hostname":   func(s *PlanSpec) { s.Targets = []string{"example.com:443"} },
		"port zero":  func(s *PlanSpec) { s.Targets = []string{"198.51.100.1:0"} },
		"too many": func(s *PlanSpec) {
			s.Targets = []string{"1.1.1.1:1", "192.0.2.12:1", "192.0.2.13:1", "192.0.2.14:1", "192.0.2.15:1"}
		},
		"no domains":    func(s *PlanSpec) { s.Domains = nil },
		"too many rnds": func(s *PlanSpec) { s.Rounds = MaxRounds + 1 },
	} {
		spec := ok
		mod(&spec)
		if _, _, err := BuildPlan(spec); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCleanDomains(t *testing.T) {
	good, bad := CleanDomains([]string{" a.com ", "", "# note", "A.COM", "b.com", "192.0.2.1", "has space.com", "::1", "c.org"})
	if !slices.Equal(good, []string{"a.com", "b.com", "c.org"}) {
		t.Errorf("good = %v", good)
	}
	if !slices.Equal(bad, []string{"192.0.2.1", "has space.com", "::1"}) {
		t.Errorf("bad = %v", bad)
	}
}

// A plan the observer would refuse must be rejected with advice the user can
// act on, before a request is made. The full library at three rounds is the
// case that actually occurs: it fits, a doubled round count does not.
func TestPlanTooLargeExplainsTheChoices(t *testing.T) {
	lib := make([]string, 1100)
	for i := range lib {
		lib[i] = fmt.Sprintf("h%d.example.com", i)
	}
	if _, _, err := BuildPlan(PlanSpec{Targets: []string{"198.51.100.1:443"}, Domains: lib, Rounds: 3}); err != nil {
		t.Fatalf("the full library at 3 rounds should fit: %v", err)
	}

	_, _, err := BuildPlan(PlanSpec{Targets: []string{"198.51.100.1:443"}, Domains: lib[:600], Rounds: 20})
	if err == nil {
		t.Fatal("an oversized plan was accepted")
	}
	var too PlanTooLargeError
	if !errors.As(err, &too) {
		t.Fatalf("error type %T: %v", err, err)
	}
	if too.Cost <= too.Limit {
		t.Errorf("cost %d limit %d", too.Cost, too.Limit)
	}
	msg := err.Error()
	for _, want := range []string{"600 个域名", "12000 次探测", "上限"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q: %s", want, msg)
		}
	}
	// It must not suggest a round count below the minimum.
	for _, bad := range []string{"降到 0 次", "次数降到 -"} {
		if strings.Contains(msg, bad) {
			t.Errorf("impossible suggestion in: %s", msg)
		}
	}

	// Too many domains for even one round: say so rather than divide to zero.
	e := PlanTooLargeError{Domains: 5000, Targets: 1, Rounds: 1, Cost: 5000, Limit: 4000}
	if s := e.Error(); !strings.Contains(s, "即使只做 1 轮") {
		t.Errorf("single-round case: %s", s)
	}
}

func TestFullLibraryCategorySnapshotFitsControlLimit(t *testing.T) {
	lib, err := pack.EmbeddedLibrary()
	if err != nil {
		t.Fatal(err)
	}
	show := false
	b := ParamsJSON(PlanSpec{Domains: lib.Full, ShowFullIP: &show}, 7, RunOptions{})
	if len(b) > 16<<10 {
		t.Fatalf("snapshot too large: %d", len(b))
	}
	var p struct {
		Categories []pack.ReportCategory `json:"domain_categories"`
		ShowFullIP *bool                 `json:"show_full_ip"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, c := range p.Categories {
		count += len(c.Domains)
	}
	if count != len(pack.SortedDomains(lib.Full)) || p.ShowFullIP == nil || *p.ShowFullIP {
		t.Fatalf("incomplete snapshot: %d", count)
	}
}
