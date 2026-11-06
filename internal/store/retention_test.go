package store

import (
	"testing"
	"time"
)

func TestOfflineCleanupRemovesAllNodeFactsAtBoundary(t *testing.T) {
	s := open(t)
	n, task, _ := seed(t, s)
	now := n.CreatedAt
	if err := s.TouchNode(n.ID, now, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	live := &Node{ID: "live", Name: "live", Path: "live-path", KeyHash: []byte("live-key"), CreatedAt: now.Add(time.Minute)}
	if err := s.InsertNode(live); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO observations(attempt_id,observed_at,remote_ip,remote_port,observed_sni,evidence,sni_match) VALUES('att_1',1,'192.0.2.1',1,'a.com','authenticated',1)`,
		`INSERT INTO client_events(attempt_id,event_id,received_at,stage,outcome,started_at,duration_ms) VALUES('att_1','event',1,'http','receipt',1,1)`,
		`INSERT INTO web_checks(task_id,side,mode,host,event_id,received_at,result) VALUES('task_1','node','old','a.com','old',1,'{}')`,
		`INSERT INTO task_asn(task_id,snapshot,ip,source,queried_at,status,result) VALUES('task_1',1,'192.0.2.1','test',1,'ok','{}')`,
		`INSERT INTO asn_cache(source,ip,queried_at,status,result) VALUES('test','192.0.2.1',1,'ok','{}')`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if count, err := s.PruneOfflineNodes(now.Add(NodeOfflineTTL - time.Millisecond)); err != nil || count != 0 {
		t.Fatalf("early cleanup: %d %v", count, err)
	}
	if count, err := s.PruneOfflineNodes(now.Add(NodeOfflineTTL)); err != nil || count != 1 {
		t.Fatalf("cleanup: %d %v", count, err)
	}
	if _, err := s.NodeByID(live.ID); err != nil {
		t.Fatal("live node removed", err)
	}
	if _, err := s.GetTask(task.ID); err != ErrNotFound {
		t.Fatalf("task retained: %v", err)
	}
	for _, table := range []string{"tasks", "attempts", "observations", "client_events", "web_checks", "task_asn", "asn_cache"} {
		var count int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s: %d %v", table, count, err)
		}
	}
	if count, err := s.PruneOfflineNodes(now.Add(NodeOfflineTTL)); err != nil || count != 0 {
		t.Fatalf("not idempotent: %d %v", count, err)
	}
}

func TestCleanupRollsBackOnFailure(t *testing.T) {
	s := open(t)
	n, task, _ := seed(t, s)
	_, err := s.db.Exec(`CREATE TRIGGER prevent_task_delete BEFORE DELETE ON tasks BEGIN SELECT RAISE(ABORT,'simulated failure'); END;`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PruneOfflineNodes(n.CreatedAt.Add(NodeOfflineTTL)); err == nil {
		t.Fatal("cleanup should fail")
	}
	if _, err := s.GetTask(task.ID); err != nil {
		t.Fatal("task lost on rollback", err)
	}
	var count int
	s.db.QueryRow(`SELECT COUNT(*) FROM attempts`).Scan(&count)
	if count != 2 {
		t.Fatal("attempts lost on rollback")
	}
}

func TestLiveClientsOnlyShowsFreshUnfinishedTasks(t *testing.T) {
	s := open(t)
	n, _, _ := seed(t, s)
	now := n.CreatedAt
	if err := s.TouchNode(n.ID, now, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	s.db.Exec(`UPDATE tasks SET expires_at=?`, ms(now.Add(time.Hour)))
	rows, err := s.LiveClients(now)
	if err != nil || len(rows) != 1 || rows[0].Planned != 2 || rows[0].Recorded != 0 {
		t.Fatalf("live: %+v %v", rows, err)
	}
	rows, err = s.LiveClients(now.Add(LiveWindow))
	if err != nil || len(rows) != 0 {
		t.Fatalf("stale: %+v %v", rows, err)
	}
	s.db.Exec(`UPDATE tasks SET cancelled_at=?`, ms(now))
	rows, err = s.LiveClients(now)
	if err != nil || len(rows) != 0 {
		t.Fatalf("cancelled: %+v %v", rows, err)
	}
	s.db.Exec(`UPDATE tasks SET cancelled_at=NULL`)
	for _, id := range []string{"att_1", "att_2"} {
		s.db.Exec(`INSERT INTO client_events(attempt_id,event_id,received_at,stage,outcome,started_at,duration_ms) VALUES(?,'e',1,'http','receipt',1,1)`, id)
	}
	rows, err = s.LiveClients(now)
	if err != nil || len(rows) != 0 {
		t.Fatalf("completed: %+v %v", rows, err)
	}
}
