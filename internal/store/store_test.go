package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func seed(t *testing.T, s *Store) (*Node, *Task, []Attempt) {
	t.Helper()
	now := time.Now().Truncate(time.Millisecond)
	n := &Node{ID: "node_1", Name: "n", Path: "path1", KeyHash: []byte("k"), CreatedAt: now}
	if err := s.InsertNode(n); err != nil {
		t.Fatal(err)
	}
	task := &Task{ID: "task_1", NodeID: n.ID, CollectorID: "c1", Target: "192.0.2.4:443", CreatedAt: now, ExpiresAt: now.Add(time.Minute), Snapshot: "{}"}
	atts := []Attempt{
		{ID: "att_1", Index: 0, SNI: "a.com", CredHash: []byte("h1")},
		{ID: "att_2", Index: 1, SNI: "b.com", CredHash: []byte("h2")},
	}
	if err := s.InsertTask(task, atts); err != nil {
		t.Fatal(err)
	}
	return n, task, atts
}

func TestMigrateIsIdempotentAndRejectsNewer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.db.Exec("PRAGMA user_version = 99")
	s.Close()
	if _, err := Open(path); err == nil {
		t.Error("opened a database from a newer schema")
	}
}

func TestRetiredWebsiteFactsSurviveReopen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "legacy.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	_, task, _ := seed(t, s)
	const result = `{"host":"a.com","historical":true}`
	_, err = s.db.Exec(`INSERT INTO web_checks(task_id,side,mode,host,event_id,received_at,result) VALUES(?,?,?,?,?,?,?)`,
		task.ID, "node", "system_dns", "a.com", "legacy-event", 1, result)
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var stored string
	if err := s.db.QueryRow(`SELECT result FROM web_checks WHERE event_id = 'legacy-event'`).Scan(&stored); err != nil || stored != result {
		t.Fatalf("historical facts changed: %q %v", stored, err)
	}
	if _, err := s.GetTask(task.ID); err != nil {
		t.Fatalf("controlled task no longer readable: %v", err)
	}
}

func TestOneTimeObservation(t *testing.T) {
	s := open(t)
	_, task, _ := seed(t, s)

	ref, err := s.AttemptByCred([]byte("h1"))
	if err != nil || ref.ID != "att_1" || ref.NodePath != "path1" || ref.NodeRevoked {
		t.Fatalf("ref: %+v %v", ref, err)
	}
	obs := Observation{AttemptID: "att_1", ObservedAt: time.Now(), RemoteIP: "192.0.2.99", RemotePort: 5, ObservedSNI: "a.com", Evidence: EvidenceAuthenticated, SNIMatch: true}
	if ok, err := s.RecordObservation(obs, AttemptAuthenticated); !ok || err != nil {
		t.Fatalf("first: %v %v", ok, err)
	}
	obs.RemoteIP = "192.0.2.8"
	if ok, err := s.RecordObservation(obs, AttemptAuthenticated); ok || err != nil {
		t.Fatalf("second must be refused: %v %v", ok, err)
	}
	got, _ := s.TaskObservations(task.ID)
	if len(got) != 1 || got["att_1"].RemoteIP != "192.0.2.99" || !got["att_1"].SNIMatch {
		t.Errorf("observations: %+v", got)
	}
}

func TestClientEventsAreIdempotent(t *testing.T) {
	s := open(t)
	_, task, _ := seed(t, s)
	e := ClientEvent{AttemptID: "att_1", EventID: "e1", ReceivedAt: time.Now(), Stage: "tcp", Outcome: "dial_failed", StartedAt: time.Now(), DurationMS: 5}
	if ok, err := s.InsertClientEvent(e); !ok || err != nil {
		t.Fatalf("first: %v %v", ok, err)
	}
	if ok, err := s.InsertClientEvent(e); ok || err != nil {
		t.Fatalf("duplicate: %v %v", ok, err)
	}
	evs, _ := s.TaskClientEvents(task.ID)
	if len(evs) != 1 {
		t.Errorf("events: %d", len(evs))
	}
	if _, err := s.InsertClientEvent(ClientEvent{AttemptID: "att_nope", EventID: "x", Stage: "tcp", Outcome: "o"}); err == nil {
		t.Error("event for unknown attempt accepted (foreign key)")
	}
}

func TestCountActive(t *testing.T) {
	s := open(t)
	n, task, _ := seed(t, s)
	now := task.CreatedAt

	if all, node, _ := s.CountActive(now, n.ID); all != 1 || node != 1 {
		t.Errorf("fresh: %d %d", all, node)
	}
	// One attempt observed, one reported by the client: nothing left open.
	s.RecordObservation(Observation{AttemptID: "att_1", ObservedAt: now, RemoteIP: "192.0.2.11", ObservedSNI: "a.com", Evidence: EvidenceAuthenticated, SNIMatch: true}, AttemptAuthenticated)
	s.InsertClientEvent(ClientEvent{AttemptID: "att_2", EventID: "e", ReceivedAt: now, Stage: "tcp", Outcome: "dial_failed", StartedAt: now})
	if all, _, _ := s.CountActive(now, n.ID); all != 0 {
		t.Errorf("resolved task still active: %d", all)
	}
}

func TestRegTokens(t *testing.T) {
	s := open(t)
	now := time.Now()
	live := &RegToken{ID: "live", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	dead := &RegToken{ID: "dead", CreatedAt: now, ExpiresAt: now.Add(-time.Minute)}
	s.InsertRegToken(live)
	s.InsertRegToken(dead)
	ts, err := s.ListRegTokens(now)
	if err != nil || len(ts) != 1 || ts[0].ID != "live" {
		t.Fatalf("outstanding = %+v %v", ts, err)
	}
	if ok, _ := s.ConsumeRegToken("dead", now); ok {
		t.Error("consumed an expired token")
	}
	if ok, _ := s.ConsumeRegToken("live", now); !ok {
		t.Error("live token not consumed")
	}
	if ok, _ := s.ConsumeRegToken("live", now); ok {
		t.Error("token consumed twice")
	}
	if n, _ := s.PruneRegTokens(now, now.Add(-7*24*time.Hour)); n != 0 {
		t.Errorf("remaining = %d", n)
	}
	// Revoking an outstanding token removes it from the list.
	keep := &RegToken{ID: "keep", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	s.InsertRegToken(keep)
	if err := s.DeleteRegToken("keep"); err != nil {
		t.Fatal(err)
	}
	if ts, _ := s.ListRegTokens(now); len(ts) != 0 {
		t.Errorf("revoked token still listed: %+v", ts)
	}
}

func TestMigrateV1ToV2KeepsData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.db")
	// Build a genuine v1 database by hand.
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	raw.SetMaxOpenConns(1)
	if _, err := raw.Exec(schemaV1); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO nodes(id,name,path,key_hash,created_at) VALUES('n1','n','p',x'01',1)`,
		`INSERT INTO tasks(id,node_id,collector_id,target,created_at,expires_at,snapshot) VALUES('t1','n1','c','192.0.2.99:443',1,2,'{}')`,
		`INSERT INTO attempts(id,task_id,idx,sni,cred_hash,state) VALUES('a1','t1',0,'a.com',x'02','pending')`,
		`PRAGMA user_version = 1`,
	} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	raw.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	atts, err := s.TaskAttempts("t1")
	if err != nil || len(atts) != 1 {
		t.Fatalf("attempts: %v %v", atts, err)
	}
	// Existing attempts inherit their task's target; new columns have defaults.
	if a := atts[0]; a.Target != "192.0.2.99:443" || a.Kind != "domain" || a.Round != 0 {
		t.Errorf("backfill: %+v", a)
	}
	var v int
	s.db.QueryRow("PRAGMA user_version").Scan(&v)
	if v != len(migrations) {
		t.Errorf("version = %d", v)
	}
}

func TestCancelTaskAndNodeFilteredListing(t *testing.T) {
	s := open(t)
	n, task, _ := seed(t, s)
	if ok, err := s.CancelTask(task.ID, task.CreatedAt.Add(time.Second)); !ok || err != nil {
		t.Fatalf("first cancel: %v %v", ok, err)
	}
	if ok, _ := s.CancelTask(task.ID, task.CreatedAt.Add(time.Hour)); ok {
		t.Error("second cancel must not change the recorded time")
	}
	got, _ := s.GetTask(task.ID)
	if got.CancelledAt == nil || !got.CancelledAt.Equal(task.CreatedAt.Add(time.Second)) {
		t.Errorf("cancelled_at: %v", got.CancelledAt)
	}
	if all, _, _ := s.CountActive(task.CreatedAt, n.ID); all != 0 {
		t.Errorf("a cancelled task is still active: %d", all)
	}
	ref, _ := s.AttemptByID("att_1")
	if ref.TaskCancel == nil {
		t.Error("AttemptRef lost the cancel time")
	}
	if rows, _ := s.RecentTasks(n.ID, 10); len(rows) != 1 || !rows[0].Cancelled {
		t.Errorf("listing: %+v", rows)
	}
	if rows, _ := s.RecentTasks("node_other", 10); len(rows) != 0 {
		t.Errorf("filter ignored: %+v", rows)
	}
	if rows, _ := s.RecentTasks("", 10); len(rows) != 1 {
		t.Errorf("unfiltered: %+v", rows)
	}
}

func TestASNCacheIsKeyedBySourceAndReplaced(t *testing.T) {
	s := open(t)
	now := time.Now().Truncate(time.Millisecond)
	a := ASNRow{IP: "192.0.2.8", Source: "ripestat", QueriedAt: now, Status: "ok", Result: `{"v":1}`}
	if err := s.PutASNCache(a); err != nil {
		t.Fatal(err)
	}
	b := a
	b.Source, b.Result = "cymru", `{"v":"cymru"}`
	s.PutASNCache(b)
	got, ok, err := s.GetASNCache("ripestat", "192.0.2.8")
	if err != nil || !ok || got.Result != `{"v":1}` || !got.QueriedAt.Equal(now) {
		t.Fatalf("ripestat: %+v %v %v", got, ok, err)
	}
	if got, _, _ := s.GetASNCache("cymru", "192.0.2.8"); got.Result != `{"v":"cymru"}` {
		t.Errorf("sources share a key: %+v", got)
	}
	// Re-putting replaces rather than duplicates.
	a.Result, a.QueriedAt = `{"v":2}`, now.Add(time.Hour)
	s.PutASNCache(a)
	if got, _, _ := s.GetASNCache("ripestat", "192.0.2.8"); got.Result != `{"v":2}` {
		t.Errorf("not replaced: %+v", got)
	}
	if _, ok, _ := s.GetASNCache("ripestat", "192.0.2.11"); ok {
		t.Error("found a missing entry")
	}
	s.PurgeASNCache(now.Add(30 * time.Minute))
	if _, ok, _ := s.GetASNCache("cymru", "192.0.2.8"); ok {
		t.Error("old entry survived the purge")
	}
	if _, ok, _ := s.GetASNCache("ripestat", "192.0.2.8"); !ok {
		t.Error("fresh entry was purged")
	}
}

func TestASNSnapshotsAreAppendOnly(t *testing.T) {
	s := open(t)
	_, task, _ := seed(t, s)
	now := time.Now().Truncate(time.Millisecond)

	if rows, n, err := s.TaskASN(task.ID, 0); err != nil || n != 0 || rows != nil {
		t.Fatalf("empty: %v %d %v", rows, n, err)
	}
	n1, err := s.InsertASNSnapshot(task.ID, []ASNRow{{IP: "192.0.2.11", Source: "ripestat", QueriedAt: now, Status: "failed", Result: `{"x":1}`}})
	if err != nil || n1 != 1 {
		t.Fatalf("first: %d %v", n1, err)
	}
	n2, _ := s.InsertASNSnapshot(task.ID, []ASNRow{
		{IP: "192.0.2.11", Source: "ripestat", QueriedAt: now.Add(time.Hour), Status: "ok", Result: `{"x":2}`},
		{IP: "192.0.2.22", Source: "ripestat", QueriedAt: now.Add(time.Hour), Status: "ok", Result: `{"x":3}`},
	})
	if n2 != 2 {
		t.Fatalf("second: %d", n2)
	}

	// The old snapshot is untouched by the refresh; the default view is the latest.
	old, n, _ := s.TaskASN(task.ID, 1)
	if n != 1 || len(old) != 1 || old[0].Status != "failed" || old[0].Result != `{"x":1}` {
		t.Errorf("snapshot 1 was altered: %+v", old)
	}
	latest, n, _ := s.TaskASN(task.ID, 0)
	if n != 2 || len(latest) != 2 || latest[0].Status != "ok" {
		t.Errorf("latest: %d %+v", n, latest)
	}
	if rows, n, _ := s.TaskASN(task.ID, 9); n != 0 || rows != nil {
		t.Errorf("missing snapshot: %v %d", rows, n)
	}
	infos, _ := s.ASNSnapshots(task.ID)
	if len(infos) != 2 || infos[0].Rows != 1 || infos[1].Rows != 2 || !infos[1].QueriedAt.Equal(now.Add(time.Hour)) {
		t.Errorf("snapshot list: %+v", infos)
	}
	if _, err := s.InsertASNSnapshot("task_nope", []ASNRow{{IP: "192.0.2.11", Source: "x", QueriedAt: now, Status: "ok", Result: "{}"}}); err == nil {
		t.Error("snapshot for an unknown task accepted (foreign key)")
	}
}
