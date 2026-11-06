package client

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net/netip"
	"strings"

	"github.com/nyktios/sniroute/internal/pack"
	"github.com/nyktios/sniroute/internal/probe"
	"github.com/nyktios/sniroute/internal/server"
	"github.com/nyktios/sniroute/internal/version"
)

// DefaultBaseline are neutral SNIs for the baseline. The .invalid TLD is
// reserved (RFC 6761) and can never be a real site, so no per-site rule
// should match it. Users may prefer domains they own.
var DefaultBaseline = []string{"baseline-a.sniroute.invalid", "baseline-b.sniroute.invalid"}

// MaxRounds bounds repetition.
const MaxRounds = 20

// MaxAttempts is the observer's per-task attempt limit (server.TasksConfig
// default). A plan is built before the task is created, so the limit is
// checked here: otherwise the request is simply too large and the server
// answers 413, which says nothing about which choice caused it. The value
// covers the whole library at the full round count (1100 domains × 3), because
// "test everything" is a legitimate choice.
const MaxAttempts = 4000

// PlanSpec describes what to measure.
type PlanSpec struct {
	ShowFullIP *bool                 // nil preserves legacy display; false masks exported egress IPs
	Categories []pack.ReportCategory // optional categories from the selected disk library
	Targets    []string              // observer ip:port; each is its own comparison group (e.g. one IPv4, one IPv6)
	Domains    []string              // SNIs under test
	Baseline   []string              // neutral SNIs; nil disables the baseline
	Rounds     int                   // independent connections per domain, default 3
	Seed       uint64                // shuffle seed; 0 picks a random one
}

// CleanDomains trims, drops blanks and comments, validates and de-duplicates
// (case-insensitively, keeping the first spelling). Invalid entries are
// returned separately so the caller can show them.
func CleanDomains(in []string) (ok, rejected []string) {
	seen := map[string]bool{}
	for _, d := range in {
		d = strings.TrimSpace(d)
		if d == "" || strings.HasPrefix(d, "#") {
			continue
		}
		if _, err := netip.ParseAddr(d); err == nil || probe.ValidateSNI(d) != nil {
			rejected = append(rejected, d)
			continue
		}
		if k := strings.ToLower(d); !seen[k] {
			seen[k] = true
			ok = append(ok, d)
		}
	}
	return ok, rejected
}

// PlanTooLargeError explains a plan the observer would refuse, in terms of the
// choices that caused it rather than as a bare size limit.
type PlanTooLargeError struct {
	Domains, Targets, Rounds, Cost, Limit int
}

func (e PlanTooLargeError) Error() string {
	// Offer the reachable ceiling on each axis instead of one number that may
	// be impossible to honour: a full-library run cannot fit even a single
	// round when the limit is small.
	perRound := e.Domains * e.Targets
	msg := fmt.Sprintf("%d 个域名 × %d 个目标 × %d 轮 = %d 次探测，超过单次测试上限 %d 次。",
		e.Domains, e.Targets, e.Rounds, e.Cost, e.Limit)
	if maxRounds := e.Limit / perRound; maxRounds >= 1 {
		msg += fmt.Sprintf("可以把每域名连接次数降到 %d 次，", maxRounds)
	} else {
		msg += "即使只做 1 轮也超出上限，请少选一些域名，"
	}
	if maxDomains := e.Limit / (e.Targets * e.Rounds); maxDomains >= 1 {
		msg += fmt.Sprintf("或把域名数控制在 %d 个以内（当前 %d 个）。", maxDomains, e.Domains)
	} else {
		msg += "或减少同时比较的目标数。"
	}
	return msg
}

// BuildPlan expands a spec into the ordered attempt list.
//
// Order: a baseline slot at the start, after the middle round and at the end
// (baseline connections are interleaved, not measured once); each round
// visits every (domain, target) pair once in a freshly shuffled order. Every
// attempt is its own TCP/TLS connection.
func BuildPlan(spec PlanSpec) ([]server.PlannedAttempt, uint64, error) {
	if len(spec.Targets) == 0 || len(spec.Targets) > 4 {
		return nil, 0, errors.New("need 1 to 4 targets")
	}
	for _, t := range spec.Targets {
		if ap, err := netip.ParseAddrPort(t); err != nil || ap.Port() == 0 {
			return nil, 0, fmt.Errorf("target %q must be ip:port", t)
		}
	}
	if len(spec.Domains) == 0 {
		return nil, 0, errors.New("no domains to test")
	}
	if spec.Rounds <= 0 {
		spec.Rounds = 3
	}
	if spec.Rounds > MaxRounds {
		return nil, 0, fmt.Errorf("at most %d rounds", MaxRounds)
	}
	seed := spec.Seed
	if seed == 0 {
		var b [8]byte
		rand.Read(b[:])
		seed = binary.LittleEndian.Uint64(b[:]) | 1
	}
	rng := mrand.New(mrand.NewPCG(seed, seed^0x9e3779b97f4a7c15))

	// Baseline slots: start, middle, end (deduplicated for short runs).
	slots := []int{0}
	if mid := (spec.Rounds + 1) / 2; len(spec.Baseline) > 0 && mid > 0 && mid < spec.Rounds {
		slots = append(slots, mid)
	}
	slots = append(slots, spec.Rounds)

	var plan []server.PlannedAttempt
	baselineSlot := func(round int) {
		var b []server.PlannedAttempt
		for _, t := range spec.Targets {
			for _, sni := range spec.Baseline {
				b = append(b, server.PlannedAttempt{Target: t, SNI: sni, Kind: "baseline", Round: round})
			}
		}
		rng.Shuffle(len(b), func(i, j int) { b[i], b[j] = b[j], b[i] })
		plan = append(plan, b...)
	}
	// One round costs every (domain, target) pair plus the baseline slots.
	cost := len(spec.Domains) * len(spec.Targets) * spec.Rounds
	if len(spec.Baseline) > 0 {
		cost += len(slots) * len(spec.Baseline) * len(spec.Targets)
	}
	if cost > MaxAttempts {
		return nil, 0, PlanTooLargeError{
			Domains: len(spec.Domains), Targets: len(spec.Targets), Rounds: spec.Rounds,
			Cost: cost, Limit: MaxAttempts,
		}
	}
	next := 0
	slotAt := func(r int) {
		for next < len(slots) && slots[next] == r {
			if len(spec.Baseline) > 0 {
				baselineSlot(r)
			}
			next++
		}
	}
	slotAt(0)
	for r := 1; r <= spec.Rounds; r++ {
		var round []server.PlannedAttempt
		for _, t := range spec.Targets {
			for _, d := range spec.Domains {
				round = append(round, server.PlannedAttempt{Target: t, SNI: d, Kind: "domain", Round: r})
			}
		}
		rng.Shuffle(len(round), func(i, j int) { round[i], round[j] = round[j], round[i] })
		plan = append(plan, round...)
		slotAt(r)
	}
	return plan, seed, nil
}

// ParamsJSON freezes the test conditions for the task snapshot.
func ParamsJSON(spec PlanSpec, seed uint64, opt RunOptions) json.RawMessage {
	// The domain list itself is not repeated here: every attempt already
	// carries its SNI, and a full-library run would push the frozen conditions
	// past the observer's size limit for no extra information. The count is the
	// part a report needs.
	categories := spec.Categories
	if categories == nil {
		lib, _ := pack.EmbeddedLibrary()
		categories = lib.ReportCategories(spec.Domains)
	}
	b, _ := json.Marshal(map[string]any{
		"domain_categories": categories, "show_full_ip": spec.ShowFullIP,
		"client_version": opt.Version, "protocol_version": version.Protocol, "targets": spec.Targets, "domain_count": len(spec.Domains), "baseline": spec.Baseline,
		"rounds": spec.Rounds, "seed": seed, "concurrency": opt.Concurrency, "timeout_ms": opt.Timeout.Milliseconds(), "sni_interval_ms": SNIProbeInterval.Milliseconds(),
		"provider_label": opt.ProviderLabel, "env_note": opt.EnvNote, "proxy": "none (environment proxies ignored)",
		"alpn": "http/1.1", "connection_reuse": false, "session_resumption": false,
	})
	return b
}
