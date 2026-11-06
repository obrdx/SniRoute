package store

import (
	"database/sql"
	"errors"
	"time"
)

// ASNRow is one stored lookup result (JSON in Result).
type ASNRow struct {
	IP        string
	Source    string
	QueriedAt time.Time
	Status    string
	Result    string
}

// PutASNCache stores or replaces a cache entry.
func (s *Store) PutASNCache(r ASNRow) error {
	_, err := s.db.Exec(`INSERT INTO asn_cache(source,ip,queried_at,status,result) VALUES(?,?,?,?,?)
ON CONFLICT(source,ip) DO UPDATE SET queried_at=excluded.queried_at, status=excluded.status, result=excluded.result`,
		r.Source, r.IP, ms(r.QueriedAt), r.Status, r.Result)
	return err
}

// GetASNCache returns a cache entry for (source, ip).
func (s *Store) GetASNCache(source, ip string) (ASNRow, bool, error) {
	var (
		r  ASNRow
		at int64
	)
	err := s.db.QueryRow(`SELECT source,ip,queried_at,status,result FROM asn_cache WHERE source = ? AND ip = ?`, source, ip).
		Scan(&r.Source, &r.IP, &at, &r.Status, &r.Result)
	if errors.Is(err, sql.ErrNoRows) {
		return ASNRow{}, false, nil
	}
	if err != nil {
		return ASNRow{}, false, err
	}
	r.QueriedAt = fromMS(at)
	return r, true, nil
}

// PurgeASNCache deletes cache entries older than the cutoff.
func (s *Store) PurgeASNCache(before time.Time) error {
	_, err := s.db.Exec(`DELETE FROM asn_cache WHERE queried_at < ?`, ms(before))
	return err
}

// InsertASNSnapshot stores rows as the next snapshot of a task and returns
// its number (1, 2, ...). Snapshots are append-only.
func (s *Store) InsertASNSnapshot(taskID string, rows []ASNRow) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT COALESCE(MAX(snapshot),0)+1 FROM task_asn WHERE task_id = ?`, taskID).Scan(&n); err != nil {
		return 0, err
	}
	for _, r := range rows {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO task_asn(task_id,snapshot,ip,source,queried_at,status,result) VALUES(?,?,?,?,?,?,?)`,
			taskID, n, r.IP, r.Source, ms(r.QueriedAt), r.Status, r.Result); err != nil {
			return 0, err
		}
	}
	return n, tx.Commit()
}

// ASNSnapshotInfo describes one snapshot.
type ASNSnapshotInfo struct {
	Snapshot  int
	QueriedAt time.Time // latest lookup time in the snapshot
	Source    string
	Rows      int
}

// ASNSnapshots lists a task's snapshots, oldest first.
func (s *Store) ASNSnapshots(taskID string) ([]ASNSnapshotInfo, error) {
	rows, err := s.db.Query(`SELECT snapshot, MAX(queried_at), MIN(source), COUNT(*) FROM task_asn WHERE task_id = ? GROUP BY snapshot ORDER BY snapshot`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ASNSnapshotInfo
	for rows.Next() {
		var (
			i  ASNSnapshotInfo
			at int64
		)
		if err := rows.Scan(&i.Snapshot, &at, &i.Source, &i.Rows); err != nil {
			return nil, err
		}
		i.QueriedAt = fromMS(at)
		out = append(out, i)
	}
	return out, rows.Err()
}

// TaskASN returns the rows of one snapshot (0 = the latest) and its number;
// number 0 means the task has no snapshot.
func (s *Store) TaskASN(taskID string, snapshot int) ([]ASNRow, int, error) {
	if snapshot <= 0 {
		if err := s.db.QueryRow(`SELECT COALESCE(MAX(snapshot),0) FROM task_asn WHERE task_id = ?`, taskID).Scan(&snapshot); err != nil {
			return nil, 0, err
		}
		if snapshot == 0 {
			return nil, 0, nil
		}
	}
	rows, err := s.db.Query(`SELECT ip,source,queried_at,status,result FROM task_asn WHERE task_id = ? AND snapshot = ? ORDER BY ip`, taskID, snapshot)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []ASNRow
	for rows.Next() {
		var (
			r  ASNRow
			at int64
		)
		if err := rows.Scan(&r.IP, &r.Source, &at, &r.Status, &r.Result); err != nil {
			return nil, 0, err
		}
		r.QueriedAt = fromMS(at)
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, 0, nil
	}
	return out, snapshot, rows.Err()
}
