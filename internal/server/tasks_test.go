package server

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nyktios/sniroute/internal/store"
)

func (e *testEnv) receipt(a IssuedAttempt, sni, src string) (*Receipt, Outcome) {
	e.tasksT.Helper()
	rec, out, err := e.tasks.HandleReceipt(
		ReceiptRequest{Path: e.creds.Path, AttemptID: a.ID, Credential: a.Credential},
		Observed{Remote: netip.MustParseAddrPort(src + ":40000"), SNI: sni, At: e.clock},
	)
	if err != nil {
		e.tasksT.Fatal(err)
	}
	return rec, out
}

func plan(target string, snis ...string) CreateRequest {
	req := CreateRequest{}
	for _, sni := range snis {
		req.Attempts = append(req.Attempts, PlannedAttempt{Target: target, SNI: sni, Kind: "domain", Round: 1})
	}
	return req
}

func mkTask(t *testing.T, e *testEnv, snis ...string) (TaskView, []IssuedAttempt) {
	t.Helper()
	e.tasksT = t
	v, iss, err := e.tasks.Create(e.creds.NodeID, plan("198.51.100.1:443", snis...))
	if err != nil {
		t.Fatal(err)
	}
	return v, iss
}

func (e *testEnv) get(t *testing.T, id string) TaskView {
	t.Helper()
	v, ok, err := e.tasks.Get(e.creds.NodeID, id)
	if err != nil || !ok {
		t.Fatalf("get: %v %v", ok, err)
	}
	return v
}

func TestTaskFlow(t *testing.T) {
	e := newEnv(t, TasksConfig{})
	view, att := mkTask(t, e, "a.com", "b.com")
	if view.Status != TaskPending || len(att) != 2 || att[0].Credential == att[1].Credential {
		t.Fatalf("create: %+v", view)
	}

	rec, out := e.receipt(att[0], "a.com", "192.0.2.10")
	if out != OutcomeAccepted || rec == nil || rec.SourceIP != "192.0.2.10" || !rec.SNIMatch {
		t.Fatalf("receipt: %+v %s", rec, out)
	}
	v := e.get(t, view.ID)
	a0 := v.Attempts[0]
	if v.Status != TaskRunning || a0.State != StateAuthenticated || a0.Observation.SourceIP != "192.0.2.10" || a0.Observation.Evidence != "authenticated" {
		t.Fatalf("after first: %+v", v)
	}

	// Credentials are one-time and a replay must not change the stored fact.
	if rec, out := e.receipt(att[0], "a.com", "192.0.2.99"); rec != nil || out != OutcomeReused {
		t.Errorf("replay: %+v %s", rec, out)
	}
	if e.get(t, view.ID).Attempts[0].Observation.SourceIP != "192.0.2.10" {
		t.Error("replay overwrote the observation")
	}

	// A valid credential used with a different SNI is recorded, flagged.
	rec, out = e.receipt(att[1], "other.com", "192.0.2.11")
	if out != OutcomeMismatch || rec == nil || rec.SNIMatch {
		t.Fatalf("mismatch: %+v %s", rec, out)
	}
	v = e.get(t, view.ID)
	if v.Status != TaskCompleted || v.Attempts[1].State != StateSNIMismatch || v.Attempts[1].Observation.ObservedSNI != "other.com" {
		t.Fatalf("final: %+v", v)
	}
}

func TestCredentialBinding(t *testing.T) {
	e := newEnv(t, TasksConfig{})
	_, att := mkTask(t, e, "a.com", "b.com")

	// Right credential, wrong attempt id or node path: rejected without burning it.
	for name, rr := range map[string]ReceiptRequest{
		"other attempt": {Path: e.creds.Path, AttemptID: att[1].ID, Credential: att[0].Credential},
		"wrong path":    {Path: "nope", AttemptID: att[0].ID, Credential: att[0].Credential},
		"forged":        {Path: e.creds.Path, AttemptID: att[0].ID, Credential: "cr1-forged"},
		"empty":         {},
	} {
		rec, out, err := e.tasks.HandleReceipt(rr, Observed{Remote: netip.MustParseAddrPort("192.0.2.1:1"), SNI: "a.com", At: e.clock})
		if err != nil || rec != nil || out != OutcomeUnknownCredential {
			t.Errorf("%s: %+v %s %v", name, rec, out, err)
		}
	}
	if _, out := e.receipt(att[0], "a.com", "192.0.2.1"); out != OutcomeAccepted {
		t.Errorf("credential burned by rejected requests: %s", out)
	}
}

func TestExpiryAndRevocation(t *testing.T) {
	e := newEnv(t, TasksConfig{TaskTTL: time.Minute})
	view, att := mkTask(t, e, "a.com", "b.com")
	e.receipt(att[0], "a.com", "192.0.2.10")

	e.clock = e.clock.Add(2 * time.Minute)
	if rec, out := e.receipt(att[1], "b.com", "192.0.2.10"); rec != nil || out != OutcomeExpired {
		t.Errorf("late: %+v %s", rec, out)
	}
	v := e.get(t, view.ID)
	if v.Status != TaskCompleted || v.Attempts[0].State != StateAuthenticated || v.Attempts[1].State != StateTimeout {
		t.Fatalf("view: %+v", v)
	}

	e2 := newEnv(t, TasksConfig{})
	_, att2 := mkTask(t, e2, "a.com")
	if err := e2.reg.Revoke(e2.creds.NodeID); err != nil {
		t.Fatal(err)
	}
	if rec, out := e2.receipt(att2[0], "a.com", "192.0.2.1"); rec != nil || out != OutcomeRevoked {
		t.Errorf("revoked: %+v %s", rec, out)
	}
}

func TestClientEvents(t *testing.T) {
	e := newEnv(t, TasksConfig{})
	view, att := mkTask(t, e, "a.com", "b.com")
	ev := func(a IssuedAttempt, id, stage, outcome string) ClientEventIn {
		return ClientEventIn{AttemptID: a.ID, EventID: id, Stage: stage, Outcome: outcome, Error: "boom", StartedAt: time.Now(), DurationMS: 12}
	}

	// Client failed before reaching the observer: observer saw nothing.
	if err := e.tasks.RecordClientEvent(e.creds.NodeID, view.ID, ev(att[0], "e1", "tls", "tls_failed")); err != nil {
		t.Fatal(err)
	}
	// Idempotent redelivery.
	if err := e.tasks.RecordClientEvent(e.creds.NodeID, view.ID, ev(att[0], "e1", "tls", "tls_failed")); err != nil {
		t.Fatal(err)
	}
	v := e.get(t, view.ID)
	if v.Attempts[0].State != StateUnobserved || len(v.Attempts[0].Client) != 1 || v.Attempts[0].Observation != nil {
		t.Fatalf("unobserved: %+v", v.Attempts[0])
	}
	if v.Status != TaskRunning {
		t.Errorf("status = %s", v.Status)
	}

	// The client gave up, but the probe did reach the observer later: the
	// observer fact wins and both facts stay visible (no mutual exclusion).
	e.receipt(att[0], "a.com", "192.0.2.77")
	a0 := e.get(t, view.ID).Attempts[0]
	if a0.State != StateAuthenticated || a0.Observation.SourceIP != "192.0.2.77" || len(a0.Client) != 1 {
		t.Fatalf("late receipt: %+v", a0)
	}

	bad := map[string]ClientEventIn{
		"no event id":   ev(att[1], "", "tcp", "dial_failed"),
		"bad stage":     ev(att[1], "e2", "dns", "dial_failed"),
		"bad outcome":   ev(att[1], "e3", "tcp", "banana"),
		"unknown att":   ev(IssuedAttempt{ID: "att_nope"}, "e4", "tcp", "dial_failed"),
		"zero start":    {AttemptID: att[1].ID, EventID: "e5", Stage: "tcp", Outcome: "dial_failed"},
		"negative time": {AttemptID: att[1].ID, EventID: "e6", Stage: "tcp", Outcome: "dial_failed", StartedAt: time.Now(), DurationMS: -1},
	}
	for name, in := range bad {
		var bre BadRequestError
		if err := e.tasks.RecordClientEvent(e.creds.NodeID, view.ID, in); !errors.As(err, &bre) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Another node cannot report on this task's attempts.
	var bre BadRequestError
	if err := e.tasks.RecordClientEvent("node_other", view.ID, ev(att[1], "e7", "tcp", "dial_failed")); !errors.As(err, &bre) {
		t.Errorf("foreign node: %v", err)
	}
}

func TestTaskValidationAndOwnership(t *testing.T) {
	e := newEnv(t, TasksConfig{MaxAttempts: 2})
	view, _ := mkTask(t, e, "a.com")
	if _, ok, _ := e.tasks.Get("node_other", view.ID); ok {
		t.Error("task visible to another node")
	}
	ok := PlannedAttempt{Target: "198.51.100.1:443", SNI: "a.com", Kind: "domain", Round: 1}
	with := func(f func(*PlannedAttempt)) CreateRequest {
		a := ok
		f(&a)
		return CreateRequest{Attempts: []PlannedAttempt{a}}
	}
	for name, req := range map[string]CreateRequest{
		"hostname target": with(func(a *PlannedAttempt) { a.Target = "example.com:443" }),
		"no port":         with(func(a *PlannedAttempt) { a.Target = "198.51.100.1" }),
		"port zero":       with(func(a *PlannedAttempt) { a.Target = "198.51.100.1:0" }),
		"unspecified":     with(func(a *PlannedAttempt) { a.Target = "0.0.0.0:443" }),
		"no attempts":     {},
		"too many":        {Attempts: []PlannedAttempt{ok, ok, ok}},
		"space in sni":    with(func(a *PlannedAttempt) { a.SNI = "a b" }),
		"long sni":        with(func(a *PlannedAttempt) { a.SNI = strings.Repeat("a", 256) }),
		"ip as sni":       with(func(a *PlannedAttempt) { a.SNI = "192.0.2.1" }),
		"bad kind":        with(func(a *PlannedAttempt) { a.Kind = "other" }),
		"bad round":       with(func(a *PlannedAttempt) { a.Round = -1 }),
		"params not obj":  {Attempts: []PlannedAttempt{ok}, Params: json.RawMessage(`[1]`)},
		"params null":     {Attempts: []PlannedAttempt{ok}, Params: json.RawMessage(`null`)},
		"params too big":  {Attempts: []PlannedAttempt{ok}, Params: json.RawMessage(`{"x":"` + strings.Repeat("a", maxParamsBytes) + `"}`)},
	} {
		_, _, err := e.tasks.Create(e.creds.NodeID, req)
		var bre BadRequestError
		if !errors.As(err, &bre) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestPlanMetadataAndTTL(t *testing.T) {
	e := newEnv(t, TasksConfig{TaskTTL: time.Minute, MaxTaskTTL: 10 * time.Minute})
	req := CreateRequest{
		Attempts: []PlannedAttempt{
			{Target: "198.51.100.1:443", SNI: "base.invalid", Kind: "baseline", Round: 0},
			{Target: "[2001:db8::1]:443", SNI: "a.com", Kind: "domain", Round: 2},
		},
		Params:     json.RawMessage(`{"seed":42,"env_note":"direct"}`),
		TTLSeconds: 100000, // clamped to MaxTaskTTL
	}
	view, issued, err := e.tasks.Create(e.creds.NodeID, req)
	if err != nil {
		t.Fatal(err)
	}
	if got := view.ExpiresAt.Sub(view.CreatedAt); got != 10*time.Minute {
		t.Errorf("ttl = %v", got)
	}
	a1 := view.Attempts[1]
	if a1.Target != "[2001:db8::1]:443" || a1.Kind != "domain" || a1.Round != 2 || issued[1].Round != 2 || view.Attempts[0].Kind != "baseline" {
		t.Errorf("metadata lost: %+v", view.Attempts)
	}
	var p map[string]any
	if err := json.Unmarshal(view.Params, &p); err != nil || p["seed"].(float64) != 42 {
		t.Errorf("params: %s", view.Params)
	}
}

func hexOf(d [32]byte) string { return hex.EncodeToString(d[:]) }

func TestHelloMatching(t *testing.T) {
	e := newEnv(t, TasksConfig{})
	view, att := mkTask(t, e, "a.com", "b.com", "c.com", "d.com")
	digest := func(b byte) [32]byte { var d [32]byte; d[0] = b; return d }
	hello := func(d [32]byte, sni, src string, at time.Time) {
		e.tasks.NoteHello(Event{Status: StatusReceived, Time: at, Remote: netip.MustParseAddrPort(src + ":50000"), SNI: sni, Digest: d})
	}
	report := func(a IssuedAttempt, id string, d [32]byte) error {
		return e.tasks.RecordClientEvent(e.creds.NodeID, view.ID, ClientEventIn{
			AttemptID: a.ID, EventID: id, Stage: "tls", Outcome: "tls_failed", StartedAt: time.Now(), HelloSHA256: hexOf(d),
		})
	}

	// 1. Observer saw the ClientHello; the handshake failed afterwards.
	hello(digest(1), "a.com", "192.0.2.10", e.clock)
	if err := report(att[0], "e1", digest(1)); err != nil {
		t.Fatal(err)
	}
	v := e.get(t, view.ID)
	a := v.Attempts[0]
	if a.State != StateHelloMatched || a.Observation == nil || a.Observation.SourceIP != "192.0.2.10" || a.Observation.Evidence != "hello_match" || !a.Observation.SNIMatch {
		t.Fatalf("hello match: %+v %+v", a, a.Observation)
	}

	// 2. The observer never saw it: no evidence is invented.
	if err := report(att[1], "e2", digest(2)); err != nil {
		t.Fatal(err)
	}
	if a := e.get(t, view.ID).Attempts[1]; a.State != StateUnobserved || a.Observation != nil {
		t.Errorf("unseen hello: %+v", a)
	}

	// 3. Same digest seen on two connections (replay): ambiguous, not attributed.
	hello(digest(3), "c.com", "192.0.2.30", e.clock)
	hello(digest(3), "c.com", "203.0.113.99", e.clock)
	if err := report(att[2], "e3", digest(3)); err != nil {
		t.Fatal(err)
	}
	a = e.get(t, view.ID).Attempts[2]
	if a.State != StateHelloAmbig || a.Observation == nil || a.Observation.SourceIP != "" || a.Observation.Evidence != "ambiguous" {
		t.Errorf("ambiguous: %+v %+v", a, a.Observation)
	}

	// 4. A hello that predates the task cannot be claimed by it.
	hello(digest(4), "d.com", "192.0.2.40", e.clock.Add(-time.Hour))
	if err := report(att[3], "e4", digest(4)); err != nil {
		t.Fatal(err)
	}
	if a := e.get(t, view.ID).Attempts[3]; a.State != StateUnobserved {
		t.Errorf("stale hello matched: %+v", a)
	}
}

func TestHelloNeverDowngradesAuthenticated(t *testing.T) {
	e := newEnv(t, TasksConfig{})
	view, att := mkTask(t, e, "a.com")
	var d [32]byte
	d[0] = 9
	e.tasks.NoteHello(Event{Status: StatusReceived, Time: e.clock, Remote: netip.MustParseAddrPort("192.0.2.5:1"), SNI: "a.com", Digest: d})
	e.receipt(att[0], "a.com", "192.0.2.5")
	err := e.tasks.RecordClientEvent(e.creds.NodeID, view.ID, ClientEventIn{
		AttemptID: att[0].ID, EventID: "e1", Stage: "http", Outcome: "receipt", StartedAt: time.Now(), HelloSHA256: hexOf(d),
	})
	if err != nil {
		t.Fatal(err)
	}
	if a := e.get(t, view.ID).Attempts[0]; a.State != StateAuthenticated || a.Observation.Evidence != "authenticated" {
		t.Errorf("downgraded: %+v", a)
	}
	// A malformed digest is a bad request and stores nothing.
	var bre BadRequestError
	if err := e.tasks.RecordClientEvent(e.creds.NodeID, view.ID, ClientEventIn{
		AttemptID: att[0].ID, EventID: "e2", Stage: "http", Outcome: "receipt", StartedAt: time.Now(), HelloSHA256: "xyz",
	}); !errors.As(err, &bre) {
		t.Errorf("bad digest: %v", err)
	}
}

func TestHelloRingIsBounded(t *testing.T) {
	r := newHelloRing(8)
	for i := 0; i < 100; i++ {
		var d [32]byte
		d[0] = byte(i)
		r.add(helloEntry{at: time.Now(), digest: d})
	}
	if r.n != 8 || len(r.buf) != 8 {
		t.Fatalf("ring grew: n=%d len=%d", r.n, len(r.buf))
	}
	var old, recent [32]byte
	old[0], recent[0] = 0, 99
	if len(r.find(old, time.Time{})) != 0 || len(r.find(recent, time.Time{})) != 1 {
		t.Error("ring should keep only the newest entries")
	}
}

func TestTaskLimits(t *testing.T) {
	e := newEnv(t, TasksConfig{MaxActivePerNode: 2, MaxActive: 3, TaskTTL: time.Minute})
	// Foreign keys require real nodes.
	mk := func(name string) string {
		_, k, _ := e.reg.NewRegToken(time.Hour)
		c, err := e.reg.Register(k, name, "")
		if err != nil {
			t.Fatal(err)
		}
		return c.NodeID
	}
	b, c := mk("b"), mk("c")
	create := func(id string) (TaskView, []IssuedAttempt, error) {
		return e.tasks.Create(id, plan("198.51.100.1:443", "a.com"))
	}
	v1, a1, err1 := create(e.creds.NodeID)
	_, _, err2 := create(e.creds.NodeID)
	if err1 != nil || err2 != nil {
		t.Fatal("first two should succeed")
	}
	if _, _, err := create(e.creds.NodeID); !errors.Is(err, ErrTooMany) {
		t.Errorf("per-node limit: %v", err)
	}
	if _, _, err := create(b); err != nil {
		t.Fatalf("other node should succeed: %v", err)
	}
	if _, _, err := create(c); !errors.Is(err, ErrTooMany) {
		t.Errorf("global limit: %v", err)
	}

	// A task stops counting once its attempts are resolved (here: observed).
	e.tasksT = t
	e.receipt(a1[0], "a.com", "192.0.2.1")
	_ = v1
	if _, _, err := create(e.creds.NodeID); err != nil {
		t.Errorf("after resolve: %v", err)
	}
	// ...or once the task expires.
	e.clock = e.clock.Add(2 * time.Minute)
	if _, _, err := create(c); err != nil {
		t.Errorf("after expiry: %v", err)
	}
}

// Creating a task must survive the largest plan the client will build: the
// whole library at the full round count. The body-size limit and the attempt
// limit have to agree with each other, or a legitimate run fails with a bare
// 413 before the plan is even looked at.
// maxClientPlanAttempts mirrors client.MaxAttempts; it is repeated here because
// the client package imports this one and an import cycle is not allowed.
const maxClientPlanAttempts = 4000

func TestCreateAcceptsTheLargestClientPlan(t *testing.T) {
	e := newEnv(t, TasksConfig{})
	plan := make([]PlannedAttempt, maxClientPlanAttempts)
	for i := range plan {
		plan[i] = PlannedAttempt{Target: "198.51.100.1:443", SNI: fmt.Sprintf("host-%04d.example.com", i), Kind: "domain", Round: 3}
	}
	req, err := json.Marshal(CreateRequest{Attempts: plan, Params: json.RawMessage(`{"rounds":3}`), TTLSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	if len(req) > maxBodyBytes {
		t.Fatalf("the largest plan is %d bytes but the body limit is %d: a legitimate run would be refused", len(req), maxBodyBytes)
	}
	if _, _, err := e.tasks.Create(e.creds.NodeID, CreateRequest{Attempts: plan, Params: json.RawMessage(`{"rounds":3}`), TTLSeconds: 60}); err != nil {
		t.Fatalf("the largest client plan was refused: %v", err)
	}
	// One more than the limit is still refused, by the attempt count rather
	// than by the body size.
	over := append(plan, plan[0])
	if _, _, err := e.tasks.Create(e.creds.NodeID, CreateRequest{Attempts: over}); err == nil {
		t.Error("an over-limit plan was accepted")
	}
}

func TestCleanupExpiresHandshakeBuffer(t *testing.T) {
	e := newEnv(t, TasksConfig{})
	oldDigest := [32]byte{1}
	newDigest := [32]byte{2}
	e.tasks.NoteHello(Event{Status: StatusReceived, Time: e.clock.Add(-store.NodeOfflineTTL), Digest: oldDigest})
	e.tasks.NoteHello(Event{Status: StatusReceived, Time: e.clock, Digest: newDigest})
	if _, err := e.tasks.Cleanup(e.clock); err != nil {
		t.Fatal(err)
	}
	if matches := e.tasks.hellos.find(oldDigest, e.clock.Add(-time.Hour)); len(matches) != 0 {
		t.Fatal("old handshake retained")
	}
	if matches := e.tasks.hellos.find(newDigest, e.clock.Add(-time.Hour)); len(matches) != 1 {
		t.Fatal("recent handshake removed")
	}
}
