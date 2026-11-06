// Package store persists SniRoute state in SQLite (pure Go driver, no CGO).
//
// Raw facts (observations, client events) are append-only; derived status is
// computed by callers from facts plus the clock, so analysis can be redone.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a looked-up row does not exist.
var ErrNotFound = errors.New("store: not found")

// Store is a SQLite-backed store. It is safe for concurrent use; all access
// is serialized through a single connection, which keeps transactions simple.
type Store struct{ db *sql.DB }

// migrations[i] upgrades a database from schema version i to i+1.
var migrations = []string{schemaV1, schemaV2, schemaV3, schemaV4, schemaV5, schemaV6}

const schemaV1 = `
CREATE TABLE nodes(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  provider_label TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL UNIQUE,
  key_hash BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen INTEGER,
  last_ip TEXT NOT NULL DEFAULT '',
  tasks INTEGER NOT NULL DEFAULT 0,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE reg_keys(
  hash BLOB PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE TABLE tasks(
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES nodes(id),
  collector_id TEXT NOT NULL,
  target TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  snapshot TEXT NOT NULL
);
CREATE INDEX tasks_node ON tasks(node_id);
CREATE TABLE attempts(
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(id),
  idx INTEGER NOT NULL,
  sni TEXT NOT NULL,
  cred_hash BLOB NOT NULL UNIQUE,
  state TEXT NOT NULL DEFAULT 'pending'
);
CREATE INDEX attempts_task ON attempts(task_id, idx);
CREATE TABLE observations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts(id),
  observed_at INTEGER NOT NULL,
  remote_ip TEXT NOT NULL,
  remote_port INTEGER NOT NULL,
  observed_sni TEXT NOT NULL,
  evidence TEXT NOT NULL,
  sni_match INTEGER NOT NULL
);
CREATE TABLE client_events(
  attempt_id TEXT NOT NULL REFERENCES attempts(id),
  event_id TEXT NOT NULL,
  received_at INTEGER NOT NULL,
  stage TEXT NOT NULL,
  outcome TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT '',
  started_at INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL,
  PRIMARY KEY(attempt_id, event_id)
);
`

const schemaV2 = `
ALTER TABLE attempts ADD COLUMN target TEXT NOT NULL DEFAULT '';
ALTER TABLE attempts ADD COLUMN kind TEXT NOT NULL DEFAULT 'domain';
ALTER TABLE attempts ADD COLUMN round INTEGER NOT NULL DEFAULT 0;
UPDATE attempts SET target = (SELECT t.target FROM tasks t WHERE t.id = attempts.task_id);
ALTER TABLE client_events ADD COLUMN hello_sha256 TEXT NOT NULL DEFAULT '';
`

// Retired web-check schema. Keep this migration and any existing rows intact
// so upgrades preserve historical raw facts. Current tasks do not use it.
const schemaV3 = `
CREATE TABLE web_checks(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL REFERENCES tasks(id),
  side TEXT NOT NULL,
  mode TEXT NOT NULL,
  host TEXT NOT NULL,
  event_id TEXT NOT NULL,
  received_at INTEGER NOT NULL,
  result TEXT NOT NULL,
  UNIQUE(task_id, side, mode, host, event_id)
);
CREATE INDEX web_checks_task ON web_checks(task_id);
`

// A task the node has cancelled stops accepting new probes (after a short
// grace for connections already in flight).
const schemaV4 = `
ALTER TABLE tasks ADD COLUMN cancelled_at INTEGER;
`

// ASN data. asn_cache is a shared, expiring cache keyed by (source, ip).
// task_asn holds frozen per-task snapshots: each lookup round for a task is a
// new, never-modified snapshot, so a report built from snapshot N stays the
// same even after a later refresh adds snapshot N+1.
const schemaV5 = `
CREATE TABLE asn_cache(
  source TEXT NOT NULL,
  ip TEXT NOT NULL,
  queried_at INTEGER NOT NULL,
  status TEXT NOT NULL,
  result TEXT NOT NULL,
  PRIMARY KEY(source, ip)
);
CREATE TABLE task_asn(
  task_id TEXT NOT NULL REFERENCES tasks(id),
  snapshot INTEGER NOT NULL,
  ip TEXT NOT NULL,
  source TEXT NOT NULL,
  queried_at INTEGER NOT NULL,
  status TEXT NOT NULL,
  result TEXT NOT NULL,
  PRIMARY KEY(task_id, snapshot, ip)
);
`

// Registration tokens replace registration keys (v6). The token itself is
// never stored: it is derived from the admin key with HMAC-SHA256, so this
// table holds only an id, a validity window and whether it was used. That
// keeps the "no secrets at rest" rule while letting the operator re-display
// an outstanding link. Old reg_keys hashes expire within a day, so the table
// is dropped.
const schemaV6 = `
DROP TABLE IF EXISTS reg_keys;
CREATE TABLE reg_tokens(
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);
`

// Open opens (creating if needed) the database at path and migrates it.
func Open(path string) (*Store, error) {
	// Create the file privately first; SQLite's -wal/-shm files inherit its mode.
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600); err != nil {
		return nil, err
	} else {
		f.Close()
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=secure_delete(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	var v int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	if v > len(migrations) {
		return fmt.Errorf("store: database schema v%d is newer than this binary (v%d)", v, len(migrations))
	}
	for ; v < len(migrations); v++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: migrate to v%d: %w", v+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", v+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v int64) time.Time { return time.UnixMilli(v).UTC() }

func fromMSPtr(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromMS(v.Int64)
	return &t
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
