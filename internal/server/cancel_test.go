package server

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func (e *testEnv) receiptAt(a IssuedAttempt, sni string, at time.Time) (*Receipt, Outcome) {
	rec, out, err := e.tasks.HandleReceipt(
		ReceiptRequest{Path: e.creds.Path, AttemptID: a.ID, Credential: a.Credential},
		Observed{Remote: netip.MustParseAddrPort("192.0.2.10:40000"), SNI: sni, At: at},
	)
	if err != nil {
		panic(err)
	}
	return rec, out
}

func TestCancelKeepsFactsAndDoesNotCountUnrunAttemptsAsFailures(t *testing.T) {
	e := newEnv(t, TasksConfig{})
	view, att := mkTask(t, e, "a.com", "b.com", "c.com")
	e.receipt(att[0], "a.com", "192.0.2.10") // finished before the cancel

	if err := e.tasks.Cancel(e.creds.NodeID, view.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.tasks.Cancel(e.creds.NodeID, view.ID); err != nil { // idempotent
		t.Fatal(err)
	}
	v := e.get(t, view.ID)
	if v.Status != TaskAborted || v.CancelledAt == nil {
		t.Fatalf("status = %s cancelled=%v", v.Status, v.CancelledAt)
	}
	if v.Attempts[0].State != StateAuthenticated || v.Attempts[0].Observation == nil {
		t.Errorf("a result obtained before the cancel must survive: %+v", v.Attempts[0])
	}
	for _, a := range v.Attempts[1:] {
		if a.State != StateCancelled || a.Observation != nil || len(a.Client) != 0 {
			t.Errorf("unrun attempt must read as cancelled with no facts: %+v", a)
		}
	}
}

func TestCancelledTaskRefusesLateProbesButHonoursInFlightOnes(t *testing.T) {
	e := newEnv(t, TasksConfig{})
	view, att := mkTask(t, e, "a.com", "b.com")
	if err := e.tasks.Cancel(e.creds.NodeID, view.ID); err != nil {
		t.Fatal(err)
	}
	// A connection already on the wire when the cancel arrived is still recorded...
	if rec, out := e.receiptAt(att[0], "a.com", e.clock.Add(time.Second)); rec == nil || out != OutcomeAccepted {
		t.Errorf("in-flight probe: %+v %s", rec, out)
	}
	// ...a new one well after it is not.
	if rec, out := e.receiptAt(att[1], "b.com", e.clock.Add(time.Minute)); rec != nil || out != OutcomeCancelled {
		t.Errorf("late probe: %+v %s", rec, out)
	}
	if v := e.get(t, view.ID); v.Attempts[1].State != StateCancelled {
		t.Errorf("refused probe left state %s", v.Attempts[1].State)
	}
}

func TestCancelledTaskStillAcceptsClientEvents(t *testing.T) {
	e := newEnv(t, TasksConfig{})
	view, att := mkTask(t, e, "a.com")
	e.tasks.Cancel(e.creds.NodeID, view.ID)
	// The client flushes what it has after cancelling: that is the point of the
	// independent cancel request.
	err := e.tasks.RecordClientEvent(e.creds.NodeID, view.ID, ClientEventIn{
		AttemptID: att[0].ID, EventID: "e1", Stage: "tls", Outcome: "cancelled", StartedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if a := e.get(t, view.ID).Attempts[0]; len(a.Client) != 1 || a.Client[0].Outcome != "cancelled" {
		t.Errorf("event lost: %+v", a)
	}
}

func TestCancelOwnershipAndActiveCount(t *testing.T) {
	e := newEnv(t, TasksConfig{MaxActivePerNode: 1})
	view, _ := mkTask(t, e, "a.com")
	var bre BadRequestError
	if err := e.tasks.Cancel("node_other", view.ID); !errors.As(err, &bre) {
		t.Errorf("foreign cancel: %v", err)
	}
	if err := e.tasks.Cancel(e.creds.NodeID, "task_nope"); !errors.As(err, &bre) {
		t.Errorf("unknown task: %v", err)
	}
	if _, _, err := e.tasks.Create(e.creds.NodeID, plan("198.51.100.1:443", "b.com")); !errors.Is(err, ErrTooMany) {
		t.Fatalf("limit: %v", err)
	}
	e.tasks.Cancel(e.creds.NodeID, view.ID)
	if _, _, err := e.tasks.Create(e.creds.NodeID, plan("198.51.100.1:443", "b.com")); err != nil {
		t.Errorf("a cancelled task must free its slot: %v", err)
	}
}

func TestListAndGetAny(t *testing.T) {
	e := newEnv(t, TasksConfig{MaxActivePerNode: 10})
	v1, att := mkTask(t, e, "a.com", "b.com")
	e.receipt(att[0], "a.com", "192.0.2.10")
	v2, _ := mkTask(t, e, "c.com")
	e.tasks.Cancel(e.creds.NodeID, v2.ID)

	items, err := e.tasks.List(e.creds.NodeID, 10)
	if err != nil || len(items) != 2 {
		t.Fatalf("list: %+v %v", items, err)
	}
	byID := map[string]TaskListItem{}
	for _, it := range items {
		byID[it.ID] = it
	}
	if it := byID[v1.ID]; it.Planned != 2 || it.Recorded != 1 || it.Cancelled || it.Status != TaskRunning {
		t.Errorf("task 1: %+v", it)
	}
	if it := byID[v2.ID]; !it.Cancelled || it.Status != TaskAborted {
		t.Errorf("task 2: %+v", it)
	}
	if other, _ := e.tasks.List("node_other", 10); len(other) != 0 {
		t.Errorf("another node sees %d tasks", len(other))
	}

	// The operator view ignores ownership and carries the node's identity.
	v, ok, err := e.tasks.GetAny(v1.ID)
	if err != nil || !ok || v.Node.Name != "n1" || v.Node.ProviderLabel != "ProviderX" {
		t.Errorf("GetAny: %+v %v %v", v.Node, ok, err)
	}
	if _, ok, _ := e.tasks.GetAny("task_nope"); ok {
		t.Error("unknown task found")
	}
}
