package client

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nyktios/sniroute/internal/analysis"
	"github.com/nyktios/sniroute/internal/asn"
	"github.com/nyktios/sniroute/internal/auth"
	"github.com/nyktios/sniroute/internal/report"
	"github.com/nyktios/sniroute/internal/server"
	"github.com/nyktios/sniroute/internal/store"
)

const adminKey = "0123456789abcdef0123456789abcdef-admin"

type rig struct {
	runner    *Runner
	probeAddr string
	probePin  string
	ctlCert   string // control certificate pin
	receipts  atomic.Int32
	tasks     *server.Tasks

	// Control-link fault injection: after failAfter requests (when >= 0) every
	// control request is answered by dropping the connection.
	reqs      atomic.Int32
	failAfter atomic.Int32
	st        *store.Store
	registry  *auth.Registry
}

// linkDownAfterNextRequests lets n more control requests through, then drops all.
func (r *rig) linkDownAfterNextRequests(n int32) { r.failAfter.Store(r.reqs.Load() + n) }
func (r *rig) linkUp()                           { r.failAfter.Store(-1) }

// newRig starts a real control service (TLS, pinned) and probe listener over
// a temp database, and enrolls one node.
func newRig(t *testing.T) *rig { return newRigPin(t, "") }

// newRigPin is newRig, but the control service advertises controlPin as the
// probe key when it is non-empty (simulating an observer whose key differs).
func newRigPin(t *testing.T, controlPin string) *rig {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	reg, _ := auth.NewRegistry(adminKey, st)
	tasks := server.NewTasks(server.TasksConfig{}, reg, st, "collector-1")

	cert, err := server.LoadOrCreateCert(filepath.Join(t.TempDir(), "probe.pem"), "probe", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := server.LeafOf(cert)
	r := &rig{probePin: server.SPKIPin(leaf), tasks: tasks, st: st, registry: reg}
	r.failAfter.Store(-1)

	ps := server.NewProbeServer(server.ProbeConfig{Addr: "127.0.0.1:0"}, cert, server.ProbeHooks{
		OnEvent: tasks.NoteHello,
		OnReceipt: func(rr server.ReceiptRequest, o server.Observed) (*server.Receipt, server.Outcome, error) {
			r.receipts.Add(1)
			return tasks.HandleReceipt(rr, o)
		},
	})
	if err := ps.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ps.Serve(ctx)
	r.probeAddr = ps.Addr().String()

	advertised := r.probePin
	if controlPin != "" {
		advertised = controlPin
	}
	control := server.NewControl(reg, tasks, advertised, nil).Handler()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		n := r.reqs.Add(1)
		if fa := r.failAfter.Load(); fa >= 0 && n > fa {
			if hj, ok := w.(http.Hijacker); ok {
				if c, _, err := hj.Hijack(); err == nil {
					c.Close()
				}
			}
			return
		}
		control.ServeHTTP(w, req)
	}))
	t.Cleanup(ts.Close)
	r.ctlCert = server.CertPin(ts.Certificate().Raw)

	_, k, _ := reg.NewRegToken(time.Hour)
	cc, err := NewControlClient(ts.URL, r.ctlCert)
	if err != nil {
		t.Fatal(err)
	}
	reg1, err := cc.Register(ctx, k, "vps", "ProviderX")
	if err != nil {
		t.Fatal(err)
	}
	if reg1.ProbePin != advertised {
		t.Fatalf("probe pin over control channel = %q", reg1.ProbePin)
	}
	r.runner = &Runner{CC: cc, State: Enrollment{Server: ts.URL, ControlPin: r.ctlCert, NodeID: reg1.NodeID, Path: reg1.Path, NodeKey: reg1.NodeKey, ProbePin: reg1.ProbePin}}
	return r
}

func TestRunSuccess(t *testing.T) {
	r := newRig(t)
	var seen atomic.Int32
	view, err := r.runner.Run(context.Background(), RunOptions{
		Plan:        PlanSpec{Targets: []string{r.probeAddr}, Domains: []string{"www.google.com", "www.cloudflare.com"}, Baseline: []string{"base-a.invalid"}, Rounds: 2, Seed: 7},
		Concurrency: 2, Timeout: 3 * time.Second, ProviderLabel: "ProviderX", EnvNote: "no vpn", Version: "test",
	}, func(rep AttemptReport) {
		seen.Add(1)
		if rep.Result.Outcome != OutcomeReceipt || rep.EventErr != nil {
			t.Errorf("attempt %d: %+v %v", rep.Attempt.Index, rep.Result, rep.EventErr)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	// 3 baseline slots (start, middle, end) + 2 domains x 2 rounds.
	if seen.Load() != 7 || view.Status != server.TaskCompleted || len(view.Attempts) != 7 {
		t.Fatalf("view: %+v", view)
	}
	base, dom := 0, 0
	for _, a := range view.Attempts {
		o := a.Observation
		if a.State != server.StateAuthenticated || o == nil || o.SourceIP != "127.0.0.1" || o.ObservedSNI != a.SNI || !o.SNIMatch {
			t.Errorf("attempt %d: %+v", a.Index, a)
		}
		if len(a.Client) != 1 || a.Client[0].Outcome != OutcomeReceipt || a.Client[0].Stage != "http" || !a.Client[0].HelloSent {
			t.Errorf("attempt %d client events: %+v", a.Index, a.Client)
		}
		if a.Kind == "baseline" {
			base++
		} else {
			dom++
		}
	}
	if base != 3 || dom != 4 {
		t.Errorf("baseline=%d domain=%d", base, dom)
	}
	// The frozen test conditions come back with the task.
	var params map[string]any
	if err := json.Unmarshal(view.Params, &params); err != nil || params["seed"].(float64) != 7 || params["env_note"] != "no vpn" || params["provider_label"] != "ProviderX" {
		t.Errorf("params: %s (%v)", view.Params, err)
	}
}

func TestHandshakeObservation(t *testing.T) {
	// The advertised key is wrong, so every probe aborts after the server's
	// hello: the ClientHello reaches the observer but nothing is authenticated.
	r := newRigPin(t, "00"+strings.Repeat("ab", 31))
	view, err := r.runner.Run(context.Background(), RunOptions{
		Plan: PlanSpec{Targets: []string{r.probeAddr}, Domains: []string{"a.com", "b.com"}, Rounds: 1, Seed: 3}, Timeout: 3 * time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.receipts.Load() != 0 {
		t.Fatal("credential was sent to an endpoint with the wrong key")
	}
	for _, a := range view.Attempts {
		o := a.Observation
		if a.State != server.StateHelloMatched || o == nil || o.Evidence != "hello_match" || o.SourceIP != "127.0.0.1" || o.ObservedSNI != a.SNI || !o.SNIMatch {
			t.Errorf("attempt %d: %+v %+v", a.Index, a, o)
		}
		if len(a.Client) != 1 || a.Client[0].Outcome != OutcomeIdentityMismatch || !a.Client[0].HelloSent {
			t.Errorf("attempt %d client: %+v", a.Index, a.Client)
		}
	}
}

func TestRunIdentityMismatchSendsNoCredential(t *testing.T) {
	r := newRig(t)
	st := r.runner.State
	// The control channel hands out a wrong pin: the prober must refuse the
	// probe endpoint before sending anything.
	spec := ProbeSpec{Target: r.probeAddr, SNI: "a.com", Pin: "00" + r.probePin[2:], Path: st.Path, AttemptID: "att_x", Credential: "cr1-secret", Timeout: 3 * time.Second}
	res := Probe(context.Background(), spec)
	if res.Outcome != OutcomeIdentityMismatch || res.Stage != "tls" || res.Receipt != nil {
		t.Fatalf("result: %+v", res)
	}
	time.Sleep(100 * time.Millisecond)
	if n := r.receipts.Load(); n != 0 {
		t.Fatalf("credential reached the endpoint (%d requests)", n)
	}
	// Malformed pins never match.
	for _, pin := range []string{"", "zz", "00"} {
		spec.Pin = pin
		if res := Probe(context.Background(), spec); res.Outcome != OutcomeIdentityMismatch {
			t.Errorf("pin %q: %+v", pin, res)
		}
	}
}

func TestRunFailureOutcomes(t *testing.T) {
	r := newRig(t)

	// Closed port: dial failure, nothing observed.
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedAddr := closed.Addr().String()
	closed.Close()
	view, err := r.runner.Run(context.Background(), RunOptions{Plan: PlanSpec{Targets: []string{closedAddr}, Domains: []string{"a.com"}, Rounds: 1}, Timeout: time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := view.Attempts[0]
	if a.State != server.StateUnobserved || a.Observation != nil || a.Client[0].Outcome != OutcomeDialFailed || a.Client[0].Stage != "tcp" {
		t.Errorf("closed port: %+v", a)
	}

	// Black hole: TCP connects, nobody answers. The probe times out in the
	// TLS stage and the observer, which never saw it, records nothing.
	hole, _ := net.Listen("tcp", "127.0.0.1:0")
	defer hole.Close()
	go func() {
		for {
			c, err := hole.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	view, err = r.runner.Run(context.Background(), RunOptions{Plan: PlanSpec{Targets: []string{hole.Addr().String()}, Domains: []string{"a.com"}, Rounds: 1}, Timeout: 300 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	a = view.Attempts[0]
	if a.State != server.StateUnobserved || a.Client[0].Outcome != OutcomeTimeout || a.Client[0].Stage != "tls" {
		t.Errorf("black hole: %+v", a)
	}
}

func TestRunCancelLeavesUnstartedAttemptsUncounted(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	view, err := r.runner.Run(ctx, RunOptions{
		Plan: PlanSpec{Targets: []string{r.probeAddr}, Domains: []string{"a.com", "b.com", "c.com", "d.com"}, Rounds: 1, Seed: 1}, Concurrency: 1, Timeout: 3 * time.Second,
	}, func(rep AttemptReport) {
		if rep.Attempt.Index == 0 {
			cancel() // user interrupts after the first attempt
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Attempts[0].State != server.StateAuthenticated {
		t.Errorf("finished attempt lost: %+v", view.Attempts[0])
	}
	for _, a := range view.Attempts[1:] {
		if len(a.Client) != 0 || a.Observation != nil || a.State == server.StateUnobserved {
			t.Errorf("unstarted attempt %d must carry no failure facts: %+v", a.Index, a)
		}
	}
}

func TestControlPin(t *testing.T) {
	r := newRig(t)
	wrong := "00" + r.ctlCert[2:]
	cc, err := NewControlClient(r.runner.State.Server, wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cc.Register(context.Background(), "reg_x", "n", ""); err == nil {
		t.Error("connected despite wrong control pin")
	}
	// Without a pin the self-signed certificate is not trusted either.
	cc, _ = NewControlClient(r.runner.State.Server, "")
	if _, err := cc.Register(context.Background(), "reg_x", "n", ""); err == nil {
		t.Error("connected to an untrusted certificate without a pin")
	}
	if _, err := NewControlClient("http://x", ""); err == nil {
		t.Error("plain http accepted")
	}
	if _, err := NewControlClient("https://x", "nothex"); err == nil {
		t.Error("malformed pin accepted")
	}
}

func TestConfigPermissionsAndDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "client.yaml")
	if _, err := LoadConfig(p); !errors.Is(err, ErrNoConfig) {
		t.Fatalf("missing file: %v", err)
	}
	c := Config{Enrollment: Enrollment{Server: "https://x", Path: "p", NodeKey: "k"}, NodeName: "n", Targets: []string{"192.0.2.4:443"}}
	if err := c.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(p)
	if err != nil || got.NodeKey != "k" || !got.Enrolled() || got.Rounds != 3 || got.Concurrency != DefaultConcurrency || got.Timeout() != 5*time.Second ||
		len(got.Baseline) != 2 || filepath.Base(got.DomainsFile) != "domains.txt" {
		t.Fatalf("load: %+v %v", got, err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err == nil || errors.Is(err, ErrNoConfig) {
		t.Errorf("loaded a world-readable config: %v", err)
	}
}

func TestLegacyAccessSettingsAreIgnoredAndNotSaved(t *testing.T) {
	p := filepath.Join(t.TempDir(), "client.yaml")
	legacy := "server: https://observer.example\nnode_path: p\nnode_key: k\nno_web_check: false\nno_reference: false\n"
	if err := os.WriteFile(p, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil || !cfg.Enrolled() {
		t.Fatalf("legacy config: %+v %v", cfg, err)
	}
	if err := cfg.Save(p); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "no_web_check") || strings.Contains(string(b), "no_reference") {
		t.Fatalf("saved retired settings: %s", b)
	}
}

func TestDomainFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d", "domains.txt")
	if got, err := LoadDomains(p); err != nil || got != nil {
		t.Fatalf("missing: %v %v", got, err)
	}
	if err := SaveDomains(p, []string{"a.com", "b.com"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := LoadDomains(p); len(got) != 2 || got[1] != "b.com" {
		t.Errorf("roundtrip: %v", got)
	}
}

func newOutbox(t *testing.T) *Outbox {
	t.Helper()
	ob, err := OpenOutbox(filepath.Join(t.TempDir(), "sub", "client.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ob.Close() })
	return ob
}

func TestLegacyWebsiteQueueIsRetiredWithoutNetwork(t *testing.T) {
	ob := newOutbox(t)
	const payload = `{"historical":true}`
	it, err := ob.Enqueue("old-task", "webcheck", "old-web", []byte(payload), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// No control client: any network operation here would panic.
	r := Runner{Outbox: ob}
	delivered, remaining, err := r.Flush(context.Background(), "")
	if err != nil || delivered != 0 || remaining != 0 {
		t.Fatalf("legacy queue: delivered=%d remaining=%d err=%v", delivered, remaining, err)
	}
	var stored, reason string
	if err := ob.db.QueryRow(`SELECT payload, last_error FROM outbox WHERE id = ?`, it.ID).Scan(&stored, &reason); err != nil {
		t.Fatal(err)
	}
	if stored != payload || !strings.Contains(reason, "已移除") {
		t.Fatalf("legacy result not retained with explanation: %q %q", stored, reason)
	}
}

func TestDroppedControlLinkLosesNothing(t *testing.T) {
	r := newRig(t)
	ob := newOutbox(t)
	r.runner.Outbox = ob

	// The task is created, then the control link dies for the rest of the run:
	// probes still reach the observer, but no client report can be delivered.
	r.linkDownAfterNextRequests(1)
	_, err := r.runner.Run(context.Background(), RunOptions{
		Plan:        PlanSpec{Targets: []string{r.probeAddr}, Domains: []string{"a.example.com", "b.example.com"}, Baseline: []string{"x.invalid"}, Rounds: 1, Seed: 4},
		Concurrency: 2, Timeout: 3 * time.Second,
	}, nil)
	if err == nil {
		t.Fatal("the final fetch should have failed while the link is down")
	}
	pending, _ := ob.Pending("")
	var events int
	for _, it := range pending {
		switch it.Kind {
		case KindEvent:
			events++
		}
	}
	if events != 4 { // 2 baseline + 2 domain attempts
		t.Fatalf("queued: %d events (%d items)", events, len(pending))
	}

	// What the observer saw on its own is still there, but nothing is judged
	// from the missing client reports.
	var task string
	for _, it := range pending {
		task = it.TaskID
	}
	r.linkUp()
	before, _ := r.runner.CC.GetTask(context.Background(), r.runner.State.Path, r.runner.State.NodeKey, task)
	for _, a := range before.Attempts {
		if a.State != server.StateAuthenticated || len(a.Client) != 0 {
			t.Errorf("before flush: %+v", a)
		}
	}
	rep := analysis.Judge(before)
	for _, g := range rep.Groups {
		for _, d := range g.Domains {
			if d.Completeness != analysis.MissingControl {
				t.Errorf("%s: completeness %s, want missing control data", d.SNI, d.Completeness)
			}
		}
	}

	// The link is back: everything is re-sent, once.
	delivered, remaining, err := r.runner.Flush(context.Background(), "")
	if err != nil || delivered != events || remaining != 0 {
		t.Fatalf("flush: delivered=%d remaining=%d err=%v", delivered, remaining, err)
	}
	after, err := r.runner.CC.GetTask(context.Background(), r.runner.State.Path, r.runner.State.NodeKey, task)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range after.Attempts {
		if len(a.Client) != 1 || a.Client[0].Outcome != OutcomeReceipt {
			t.Errorf("after flush: %+v", a)
		}
	}

	// Idempotent: nothing left to send, and re-delivering stored items changes nothing.
	if d, rem, _ := r.runner.Flush(context.Background(), ""); d != 0 || rem != 0 {
		t.Errorf("second flush: %d %d", d, rem)
	}
	for _, it := range pending {
		if err := r.runner.send(context.Background(), it); err != nil {
			t.Errorf("redelivery of %s refused: %v", it.Kind, err)
		}
	}
	again, _ := r.runner.CC.GetTask(context.Background(), r.runner.State.Path, r.runner.State.NodeKey, task)
	for _, a := range again.Attempts {
		if len(a.Client) != 1 {
			t.Errorf("duplicate client facts after redelivery: %+v", a)
		}
	}
}

func TestInterruptionCancelsTaskAndKeepsFinishedResults(t *testing.T) {
	r := newRig(t)
	ob := newOutbox(t)
	r.runner.Outbox = ob
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	view, err := r.runner.Run(ctx, RunOptions{
		Plan:        PlanSpec{Targets: []string{r.probeAddr}, Domains: []string{"a.com", "b.com", "c.com", "d.com"}, Rounds: 1, Seed: 1},
		Concurrency: 1, Timeout: 3 * time.Second,
	}, func(rep AttemptReport) {
		if rep.Done == 1 {
			cancel() // the user presses Ctrl+C after the first attempt
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != server.TaskAborted || view.CancelledAt == nil {
		t.Fatalf("status %s", view.Status)
	}
	done, cancelled := 0, 0
	for _, a := range view.Attempts {
		switch a.State {
		case server.StateAuthenticated:
			done++
		case server.StateCancelled:
			cancelled++
			if a.Observation != nil {
				t.Errorf("cancelled attempt with an observation: %+v", a)
			}
		default:
			t.Errorf("unexpected state %s", a.State)
		}
	}
	if done != 1 || cancelled != 3 {
		t.Errorf("done=%d cancelled=%d", done, cancelled)
	}
	// Nothing is read as failure, so the judgments call it cancelled, not blocked.
	for _, g := range analysis.Judge(view).Groups {
		for _, d := range g.Domains {
			if d.Intervention != analysis.LevelNone || d.Completeness == analysis.Complete && d.Probe == analysis.ProbeNone {
				t.Errorf("%s: %+v", d.SNI, d)
			}
		}
	}
	if p, _ := ob.Pending(""); len(p) != 0 {
		t.Errorf("%d items left undelivered", len(p))
	}
	if ids, _ := ob.Interrupted(); len(ids) != 0 {
		t.Errorf("a cancelled run is not 'interrupted': %v", ids)
	}
}

func TestCancelNoticeSurvivesADeadLink(t *testing.T) {
	r := newRig(t)
	ob := newOutbox(t)
	r.runner.Outbox = ob
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r.linkDownAfterNextRequests(1) // create the task, then the link dies
	_, err := r.runner.Run(ctx, RunOptions{
		Plan:        PlanSpec{Targets: []string{r.probeAddr}, Domains: []string{"a.com", "b.com"}, Rounds: 1, Seed: 1},
		Concurrency: 1, Timeout: 3 * time.Second,
	}, func(AttemptReport) { cancel() })
	if err == nil {
		t.Fatal("expected the final fetch to fail")
	}
	pending, _ := ob.Pending("")
	hasCancel := false
	var task string
	for _, it := range pending {
		task = it.TaskID
		hasCancel = hasCancel || it.Kind == KindCancel
	}
	if !hasCancel {
		t.Fatalf("the cancel notice was not queued: %+v", pending)
	}
	r.linkUp()
	if _, rem, err := r.runner.Flush(context.Background(), ""); err != nil || rem != 0 {
		t.Fatalf("flush: %d %v", rem, err)
	}
	v, _ := r.runner.CC.GetTask(context.Background(), r.runner.State.Path, r.runner.State.NodeKey, task)
	if v.Status != server.TaskAborted {
		t.Errorf("status after the notice was finally delivered: %s", v.Status)
	}
}

func TestInterruptedRunsAreRecovered(t *testing.T) {
	ob := newOutbox(t)
	now := time.Now()
	ob.StartRun("task_died", now) // the process died: never finished
	ob.StartRun("task_ok", now)
	ob.FinishRun("task_ok", "finished", now)
	r := &Runner{Outbox: ob}
	ids, err := r.RecoverInterrupted()
	if err != nil || len(ids) != 1 || ids[0] != "task_died" {
		t.Fatalf("recovered: %v %v", ids, err)
	}
	if again, _ := r.RecoverInterrupted(); len(again) != 0 {
		t.Errorf("recovered twice: %v", again)
	}
}

func TestWatchPollsUntilTheTaskFinishes(t *testing.T) {
	r := newRig(t)
	created, err := r.runner.CC.CreateTask(context.Background(), r.runner.State.Path, r.runner.State.NodeKey, server.CreateRequest{
		Attempts: []server.PlannedAttempt{{Target: r.probeAddr, SNI: "a.com", Kind: "domain", Round: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var polls atomic.Int32
	done := make(chan server.TaskView, 1)
	go func() {
		v, _ := r.runner.Watch(context.Background(), created.Task.ID, 20*time.Millisecond, func(server.TaskView) { polls.Add(1) })
		done <- v
	}()
	time.Sleep(120 * time.Millisecond)
	if polls.Load() < 2 {
		t.Fatalf("not polling: %d", polls.Load())
	}
	a := created.Attempts[0]
	Probe(context.Background(), ProbeSpec{Target: r.probeAddr, SNI: a.SNI, Pin: created.ProbePin, Path: r.runner.State.Path, AttemptID: a.ID, Credential: a.Credential, Timeout: 3 * time.Second})
	select {
	case v := <-done:
		if v.Status != server.TaskCompleted {
			t.Errorf("status %s", v.Status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Watch did not return after the task finished")
	}

	// A cancelled context ends the watch.
	created2, _ := r.runner.CC.CreateTask(context.Background(), r.runner.State.Path, r.runner.State.NodeKey, server.CreateRequest{
		Attempts: []server.PlannedAttempt{{Target: r.probeAddr, SNI: "b.com", Kind: "domain", Round: 1}},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := r.runner.Watch(ctx, created2.Task.ID, 20*time.Millisecond, nil); err == nil {
		t.Error("watch should end with the context error")
	}
}

func TestOutboxDeliveryRules(t *testing.T) {
	ob := newOutbox(t)
	now := func() time.Time { return time.Now() }
	for i, id := range []string{"e1", "e2", "e3"} {
		if _, err := ob.Enqueue("task_1", KindEvent, id, []byte(`{"n":`+string(rune('1'+i))+`}`), now()); err != nil {
			t.Fatal(err)
		}
	}
	// Enqueue is idempotent.
	if it, _ := ob.Enqueue("task_1", KindEvent, "e1", []byte(`{"other":true}`), now()); string(it.Payload) != `{"n":1}` {
		t.Errorf("re-enqueue replaced the stored payload: %s", it.Payload)
	}
	if p, _ := ob.Pending("task_1"); len(p) != 3 {
		t.Fatalf("pending: %d", len(p))
	}
	if p, _ := ob.Pending("task_other"); len(p) != 0 {
		t.Errorf("filter: %d", len(p))
	}

	// A transport failure stops delivery and keeps the rest queued.
	calls := 0
	d, rem, _ := ob.Deliver(context.Background(), "", func(ctx context.Context, it Item) error {
		calls++
		if it.EventID == "e2" {
			return errors.New("connection reset")
		}
		return nil
	}, now)
	if d != 1 || rem != 2 || calls != 2 {
		t.Errorf("transport failure: delivered=%d remaining=%d calls=%d", d, rem, calls)
	}
	p, _ := ob.Pending("")
	if p[0].EventID != "e2" || p[0].Attempts != 1 || p[0].LastError == "" {
		t.Errorf("failure not recorded: %+v", p[0])
	}

	// A refusal by the server is retired (retrying cannot help) and does not block the queue.
	d, rem, _ = ob.Deliver(context.Background(), "", func(ctx context.Context, it Item) error {
		if it.EventID == "e2" {
			return &APIError{Status: 400, Message: "unknown attempt"}
		}
		return nil
	}, now)
	if d != 1 || rem != 0 {
		t.Errorf("after refusal: delivered=%d remaining=%d", d, rem)
	}
	// 401/429 and 5xx are transient: they stay queued.
	ob.Enqueue("task_1", KindEvent, "e4", []byte(`{}`), now())
	for _, st := range []int{401, 429, 503} {
		_, rem, _ = ob.Deliver(context.Background(), "", func(context.Context, Item) error { return &APIError{Status: st} }, now)
		if rem != 1 {
			t.Errorf("status %d dropped the item", st)
		}
	}
}

type countingProv struct{ calls atomic.Int32 }

func (c *countingProv) Name() string { return "fake" }
func (c *countingProv) Lookup(ctx context.Context, a netip.Addr) (*asn.Info, error) {
	c.calls.Add(1)
	return &asn.Info{Status: asn.StatusOK, ASNs: []asn.Number{{ASN: 64500, Name: "Net"}}}, nil
}

func TestRunRequestsEgressNetworkLookupBestEffort(t *testing.T) {
	r := newRig(t)
	prov := &countingProv{}
	r.tasks.ASN = asn.NewService(prov, nil, asn.Config{})

	var gotEnabled atomic.Bool
	var gotItems atomic.Int32
	view, err := r.runner.Run(context.Background(), RunOptions{
		Plan:        PlanSpec{Targets: []string{r.probeAddr}, Domains: []string{"a.com"}, Rounds: 1, Seed: 1},
		Concurrency: 1, Timeout: 3 * time.Second,
		OnASN: func(enabled bool, v *server.ASNView, err error) {
			gotEnabled.Store(enabled)
			if v != nil {
				gotItems.Store(int32(len(v.Items)))
			}
			if err != nil {
				t.Errorf("lookup call failed: %v", err)
			}
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The observed egress here is loopback: recorded as skipped, never sent to the source.
	if !gotEnabled.Load() || gotItems.Load() != 1 || prov.calls.Load() != 0 {
		t.Errorf("enabled=%v items=%d provider calls=%d", gotEnabled.Load(), gotItems.Load(), prov.calls.Load())
	}
	if view.ASN == nil || view.ASN.Items[0].Status != asn.StatusSkipped || view.ASN.Items[0].IP != "127.0.0.1" {
		t.Fatalf("view.ASN: %+v", view.ASN)
	}
	rep := report.Build(view, time.Now())
	if rep.ASN.Skipped != 1 || rep.Egress[0].Rows[0].ASNStatus != "skipped_nonpublic" || rep.Egress[0].Rows[0].IP != "127.0.0.1" {
		t.Errorf("report: %+v %+v", rep.ASN, rep.Egress[0].Rows[0])
	}

	// A refresh straight away is refused (no snapshot loops), without harming anything.
	_, _, err = r.runner.CC.ASN(context.Background(), r.runner.State.Path, r.runner.State.NodeKey, view.ID, true)
	var api *APIError
	if !errors.As(err, &api) || api.Status != 429 {
		t.Errorf("immediate refresh: %v", err)
	}
	// Reading without refresh returns the same snapshot.
	again, enabled, err := r.runner.CC.ASN(context.Background(), r.runner.State.Path, r.runner.State.NodeKey, view.ID, false)
	if err != nil || !enabled || again.Snapshot != 1 {
		t.Errorf("repeat: %+v %v %v", again, enabled, err)
	}
}

func TestRunWithLookupsDisabledStillCompletes(t *testing.T) {
	r := newRig(t) // the observer has no ASN service
	var enabled atomic.Bool
	enabled.Store(true)
	view, err := r.runner.Run(context.Background(), RunOptions{
		Plan:        PlanSpec{Targets: []string{r.probeAddr}, Domains: []string{"a.com"}, Rounds: 1, Seed: 1},
		Concurrency: 1, Timeout: 3 * time.Second,
		OnASN: func(e bool, v *server.ASNView, err error) { enabled.Store(e) },
	}, nil)
	if err != nil || view.Status != server.TaskCompleted || view.ASN != nil || enabled.Load() {
		t.Fatalf("status=%s asn=%v enabled=%v err=%v", view.Status, view.ASN, enabled.Load(), err)
	}
	if rep := report.Build(view, time.Now()); rep.Overview.ASN != report.ASNNote {
		t.Errorf("report should say the networks were not queried: %s", rep.Overview.ASN)
	}
}

// TestControlHealthAndShortTokenEnrol is the flow the menu relies on: a client
// that only has the link (server + pin + token) can enrol, and the token id
// the server menu displays works on its own.
func TestControlHealthAndShortTokenEnrol(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	cc, err := NewControlClient(r.runner.CC.base, r.ctlCert)
	if err != nil {
		t.Fatal(err)
	}
	h, err := cc.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h.Service != "sniroute-control" || h.ProbePin != r.probePin || h.Collector != "collector-1" {
		t.Fatalf("health = %+v", h)
	}
	// The control service is pinned, so a wrong pin must fail with advice, not
	// with a raw TLS error.
	wrong, err := NewControlClient(r.runner.CC.base, strings.Repeat("00", 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Discover(ctx); err == nil || !strings.Contains(err.Error(), "注册链接") {
		t.Errorf("wrong pin: %v", err)
	}

	_, full, err := r.reg(t)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.runner.CC.Register(ctx, full, "other", ""); err != nil {
		t.Fatalf("full token: %v", err)
	}
	if _, err := r.runner.CC.Register(ctx, full, "again", ""); err == nil {
		t.Error("a token was accepted twice")
	}
	// A token id alone is enough: the server menu shows ids next to links.
	id, _, err := r.reg(t)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.runner.CC.Register(ctx, id, "short", ""); err != nil {
		t.Fatalf("short token id: %v", err)
	}
	if _, err := r.runner.CC.Register(ctx, "reg_bogus", "x", ""); err == nil {
		t.Error("a bogus token was accepted")
	}
}

// reg issues a registration token straight from the registry the rig uses.
func (r *rig) reg(t *testing.T) (id, token string, err error) {
	t.Helper()
	tok, token, err := r.registry.NewRegToken(time.Hour)
	return tok.ID, token, err
}

func TestRunUsesAuthenticatedTaskPinInsteadOfCachedPin(t *testing.T) {
	r := newRig(t)
	r.runner.State.ProbePin = strings.Repeat("00", 32)
	refreshed := false
	view, err := r.runner.Run(context.Background(), RunOptions{
		Plan:              PlanSpec{Targets: []string{r.probeAddr}, Domains: []string{"example.com"}, Rounds: 1, Seed: 1},
		Timeout:           3 * time.Second,
		OnProbePinRefresh: func() { refreshed = true },
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !refreshed || r.receipts.Load() != 1 || view.Attempts[0].State != server.StateAuthenticated {
		t.Fatalf("refresh=%v receipts=%d attempts=%+v", refreshed, r.receipts.Load(), view.Attempts)
	}
}

func TestLocalReportSurvivesObserverCleanup(t *testing.T) {
	r := newRig(t)
	path := filepath.Join(t.TempDir(), "client.db")
	ob, err := OpenOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	r.runner.Outbox = ob
	view, err := r.runner.Run(context.Background(), RunOptions{Plan: PlanSpec{Targets: []string{r.probeAddr}, Domains: []string{"a.example"}, Rounds: 1}, Concurrency: 2}, nil)
	if err != nil {
		ob.Close()
		t.Fatal(err)
	}
	if count, err := r.st.PruneOfflineNodes(time.Now().Add(store.NodeOfflineTTL + time.Second)); err != nil || count != 1 {
		ob.Close()
		t.Fatalf("cleanup: %d %v", count, err)
	}
	if _, err := r.runner.CC.GetTask(context.Background(), r.runner.State.Path, r.runner.State.NodeKey, view.ID); err == nil {
		ob.Close()
		t.Fatal("removed identity authenticated")
	}
	ob.Close()
	ob, err = OpenOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ob.Close()
	local, ok, err := ob.LoadTask(view.ID)
	if err != nil || !ok || local.ID != view.ID || len(local.Attempts) != 1 || local.Attempts[0].Observation == nil || local.Attempts[0].Observation.SourceIP == "" {
		t.Fatalf("local evidence lost: %+v %v", local, err)
	}
	rows, err := ob.LocalTasks()
	if err != nil || len(rows) != 1 || rows[0].Recorded != 1 {
		t.Fatalf("local history lost: %+v %v", rows, err)
	}
}
