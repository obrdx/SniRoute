package server

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nyktios/sniroute/internal/asn"
)

type asnFake struct {
	calls atomic.Int32
	fail  atomic.Bool
	label atomic.Value // string: changes between "rounds" to show snapshots do not mutate
}

func (f *asnFake) Name() string { return "fake" }
func (f *asnFake) Lookup(ctx context.Context, ip netip.Addr) (*asn.Info, error) {
	f.calls.Add(1)
	if f.fail.Load() {
		return nil, &asn.LookupError{Kind: asn.KindHTTP, Msg: "boom"}
	}
	name, _ := f.label.Load().(string)
	return &asn.Info{ASNs: []asn.Number{{ASN: 64500, Name: name}}, Prefix: "8.8.8.0/24", Status: asn.StatusOK}, nil
}

// asnTask makes a task whose attempts were observed from public IPs.
func asnTask(t *testing.T, e *testEnv) (TaskView, *asnFake) {
	t.Helper()
	f := &asnFake{}
	f.label.Store("Round One Net")
	e.tasks.ASN = asn.NewService(f, asn.NewStoreCache(e.st), asn.Config{})
	view, att := mkTask(t, e, "a.com", "b.com", "c.com")
	for i, ip := range []string{"8.8.8.8", "8.8.8.8", "1.1.1.1"} {
		e.receiptFrom(att[i], []string{"a.com", "b.com", "c.com"}[i], ip)
	}
	return view, f
}

func (e *testEnv) receiptFrom(a IssuedAttempt, sni, src string) {
	_, _, err := e.tasks.HandleReceipt(
		ReceiptRequest{Path: e.creds.Path, AttemptID: a.ID, Credential: a.Credential},
		Observed{Remote: netip.MustParseAddrPort(src + ":40000"), SNI: sni, At: e.clock},
	)
	if err != nil {
		panic(err)
	}
}

func TestEnsureASNCreatesAFrozenSnapshotOfObservedIPs(t *testing.T) {
	e := newEnv(t, TasksConfig{})
	view, f := asnTask(t, e)

	if v := e.get(t, view.ID); v.ASN != nil {
		t.Fatalf("no lookups happen on a plain read: %+v", v.ASN)
	}
	got, err := e.tasks.EnsureASN(context.Background(), e.creds.NodeID, view.ID, false)
	if err != nil || got == nil {
		t.Fatalf("ensure: %+v %v", got, err)
	}
	if got.Snapshot != 1 || got.Snapshots != 1 || got.Source != "fake" || len(got.Items) != 2 || f.calls.Load() != 2 {
		t.Errorf("snapshot: %+v (%d provider calls for 2 distinct IPs)", got, f.calls.Load())
	}
	for _, it := range got.Items {
		if it.Status != asn.StatusOK || len(it.ASNs) != 1 || it.ASNs[0].Name != "Round One Net" {
			t.Errorf("item: %+v", it)
		}
	}
	// The task view now carries it, and asking again is free.
	if v := e.get(t, view.ID); v.ASN == nil || v.ASN.Snapshot != 1 {
		t.Errorf("view: %+v", v.ASN)
	}
	if again, _ := e.tasks.EnsureASN(context.Background(), e.creds.NodeID, view.ID, false); again.Snapshot != 1 || f.calls.Load() != 2 {
		t.Errorf("a repeat without refresh must not look up again: %+v / %d", again, f.calls.Load())
	}
}

func TestRefreshAddsASnapshotAndNeverRewritesTheOldOne(t *testing.T) {
	e := newEnv(t, TasksConfig{})
	view, f := asnTask(t, e)
	first, _ := e.tasks.EnsureASN(context.Background(), e.creds.NodeID, view.ID, false)

	// Too soon: refused rather than creating snapshots in a loop.
	if _, err := e.tasks.EnsureASN(context.Background(), e.creds.NodeID, view.ID, true); !errors.Is(err, ErrTooMany) {
		t.Fatalf("immediate refresh: %v", err)
	}
	// The holder renamed itself and the cache has expired: a new snapshot shows it...
	e.clock = e.clock.Add(time.Minute)
	f.label.Store("Round Two Net")
	e.tasks.ASN = asn.NewService(f, nil, asn.Config{}) // no cache: fresh answers
	second, err := e.tasks.EnsureASN(context.Background(), e.creds.NodeID, view.ID, true)
	if err != nil || second.Snapshot != 2 || second.Snapshots != 2 || second.Items[0].ASNs[0].Name != "Round Two Net" {
		t.Fatalf("refresh: %+v %v", second, err)
	}
	// ...while snapshot 1 still reads exactly as it did.
	old, ok, _ := e.tasks.GetAt(e.creds.NodeID, view.ID, 1)
	if !ok || old.ASN == nil || old.ASN.Snapshot != 1 || old.ASN.Items[0].ASNs[0].Name != "Round One Net" || !old.ASN.QueriedAt.Equal(first.QueriedAt) {
		t.Errorf("snapshot 1 changed: %+v", old.ASN)
	}
	if latest := e.get(t, view.ID); latest.ASN.Snapshot != 2 {
		t.Errorf("default view should be the latest: %d", latest.ASN.Snapshot)
	}
}

func TestFailedLookupsKeepTheObservedIPs(t *testing.T) {
	e := newEnv(t, TasksConfig{})
	view, f := asnTask(t, e)
	f.fail.Store(true)

	got, err := e.tasks.EnsureASN(context.Background(), e.creds.NodeID, view.ID, false)
	if err != nil || got == nil || len(got.Items) != 2 {
		t.Fatalf("a failing source must still give a snapshot, not an error: %+v %v", got, err)
	}
	for _, it := range got.Items {
		if it.Status != asn.StatusFailed || it.Error != asn.KindHTTP || len(it.ASNs) != 0 || it.IP == "" {
			t.Errorf("failure not recorded per IP: %+v", it)
		}
	}
	// The measurement itself is untouched.
	v := e.get(t, view.ID)
	if v.Attempts[0].Observation == nil || v.Attempts[0].Observation.SourceIP != "8.8.8.8" || v.Status != TaskCompleted {
		t.Errorf("egress facts changed by a failed lookup: %+v", v.Attempts[0])
	}
	// Once the source is back, a refresh produces a complete snapshot 2; snapshot 1 keeps its failures.
	f.fail.Store(false)
	e.clock = e.clock.Add(time.Minute)
	e.tasks.ASN = asn.NewService(f, nil, asn.Config{})
	second, _ := e.tasks.EnsureASN(context.Background(), e.creds.NodeID, view.ID, true)
	old, _, _ := e.tasks.GetAt(e.creds.NodeID, view.ID, 1)
	if second.Items[0].Status != asn.StatusOK || old.ASN.Items[0].Status != asn.StatusFailed {
		t.Errorf("second=%+v old=%+v", second.Items[0], old.ASN.Items[0])
	}
}

func TestASNEdgeCases(t *testing.T) {
	e := newEnv(t, TasksConfig{})
	view, _ := mkTask(t, e, "a.com")

	if _, err := e.tasks.EnsureASN(context.Background(), e.creds.NodeID, view.ID, false); !errors.Is(err, ErrASNDisabled) {
		t.Errorf("disabled: %v", err)
	}
	f := &asnFake{}
	e.tasks.ASN = asn.NewService(f, nil, asn.Config{})
	// Nothing observed yet: nothing to look up, no empty snapshot is stored.
	if v, err := e.tasks.EnsureASN(context.Background(), e.creds.NodeID, view.ID, false); err != nil || v != nil || f.calls.Load() != 0 {
		t.Errorf("no observations: %+v %v %d", v, err, f.calls.Load())
	}
	var bre BadRequestError
	if _, err := e.tasks.EnsureASN(context.Background(), "node_other", view.ID, false); !errors.As(err, &bre) {
		t.Errorf("foreign node: %v", err)
	}
	if _, err := e.tasks.EnsureASN(context.Background(), e.creds.NodeID, "task_nope", false); !errors.As(err, &bre) {
		t.Errorf("unknown task: %v", err)
	}
	if _, err := e.tasks.EnsureASNAny(context.Background(), "task_nope", false); !errors.As(err, &bre) {
		t.Errorf("unknown task (operator): %v", err)
	}
}

func TestPrivateEgressAddressesAreRecordedAsSkippedNotSent(t *testing.T) {
	e := newEnv(t, TasksConfig{})
	f := &asnFake{}
	e.tasks.ASN = asn.NewService(f, nil, asn.Config{})
	view, att := mkTask(t, e, "a.com")
	e.receiptFrom(att[0], "a.com", "10.9.8.7") // e.g. the observer is behind a private network in a lab
	got, err := e.tasks.EnsureASN(context.Background(), e.creds.NodeID, view.ID, false)
	if err != nil || len(got.Items) != 1 || got.Items[0].Status != asn.StatusSkipped || f.calls.Load() != 0 {
		t.Errorf("%+v %v (%d provider calls)", got, err, f.calls.Load())
	}
}
