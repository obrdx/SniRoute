package store

import "time"

const NodeOfflineTTL = 15 * time.Minute
const LiveWindow = 90 * time.Second

// TouchLiveNode cannot revive an expired identity, even before the sweeper runs.
func (s *Store) TouchLiveNode(id string, now time.Time, ip string) error {
	return s.mustAffect(s.db.Exec(`UPDATE nodes SET last_seen=?, last_ip=CASE WHEN ?='' THEN last_ip ELSE ? END WHERE id=? AND revoked=0 AND COALESCE(last_seen,created_at)>?`, ms(now), ip, ip, id, ms(now.Add(-NodeOfflineTTL))))
}

// PruneOfflineNodes removes identities and every dependent fact in one
// transaction. Registered but never connected nodes expire from created_at.
func (s *Store) PruneOfflineNodes(now time.Time) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`CREATE TEMP TABLE IF NOT EXISTS expired_nodes(id TEXT PRIMARY KEY); DELETE FROM expired_nodes; INSERT INTO expired_nodes SELECT id FROM nodes WHERE COALESCE(last_seen,created_at)<=?`, ms(now.Add(-NodeOfflineTTL))); err != nil {
		return 0, err
	}
	for _, q := range []string{
		`DELETE FROM observations WHERE attempt_id IN (SELECT a.id FROM attempts a JOIN tasks t ON t.id=a.task_id JOIN expired_nodes n ON n.id=t.node_id)`,
		`DELETE FROM client_events WHERE attempt_id IN (SELECT a.id FROM attempts a JOIN tasks t ON t.id=a.task_id JOIN expired_nodes n ON n.id=t.node_id)`,
		`DELETE FROM web_checks WHERE task_id IN (SELECT t.id FROM tasks t JOIN expired_nodes n ON n.id=t.node_id)`,
		`DELETE FROM task_asn WHERE task_id IN (SELECT t.id FROM tasks t JOIN expired_nodes n ON n.id=t.node_id)`,
		`DELETE FROM attempts WHERE task_id IN (SELECT t.id FROM tasks t JOIN expired_nodes n ON n.id=t.node_id)`,
		`DELETE FROM tasks WHERE node_id IN (SELECT id FROM expired_nodes)`,
	} {
		if _, err = tx.Exec(q); err != nil {
			return 0, err
		}
	}
	res, err := tx.Exec(`DELETE FROM nodes WHERE id IN (SELECT id FROM expired_nodes)`)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n > 0 {
		if _, err = tx.Exec(`DELETE FROM asn_cache WHERE ip NOT IN (SELECT ip FROM task_asn)`); err != nil {
			return 0, err
		}
	}
	if _, err = tx.Exec(`DELETE FROM reg_tokens WHERE used_at IS NOT NULL OR expires_at<=?`, ms(now)); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

type LiveClient struct {
	Name      string
	IP        string
	TaskID    string
	StartedAt time.Time
	LastSeen  time.Time
	Planned   int
	Recorded  int
}

// LiveClients excludes finished/cancelled/expired tasks and stale clients.
func (s *Store) LiveClients(now time.Time) ([]LiveClient, error) {
	rows, err := s.db.Query(`SELECT n.name,n.last_ip,t.id,t.created_at,n.last_seen,
 (SELECT COUNT(*) FROM attempts a WHERE a.task_id=t.id),
 (SELECT COUNT(*) FROM attempts a WHERE a.task_id=t.id AND EXISTS(SELECT 1 FROM client_events e WHERE e.attempt_id=a.id))
 FROM nodes n JOIN tasks t ON t.node_id=n.id
 WHERE n.revoked=0 AND n.last_seen>? AND t.expires_at>? AND t.cancelled_at IS NULL
 AND EXISTS(SELECT 1 FROM attempts a WHERE a.task_id=t.id AND NOT EXISTS(SELECT 1 FROM client_events e WHERE e.attempt_id=a.id))
 ORDER BY t.created_at,t.id`, ms(now.Add(-LiveWindow)), ms(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LiveClient
	for rows.Next() {
		var r LiveClient
		var start, seen int64
		if err := rows.Scan(&r.Name, &r.IP, &r.TaskID, &start, &seen, &r.Planned, &r.Recorded); err != nil {
			return nil, err
		}
		r.StartedAt = fromMS(start)
		r.LastSeen = fromMS(seen)
		out = append(out, r)
	}
	return out, rows.Err()
}
