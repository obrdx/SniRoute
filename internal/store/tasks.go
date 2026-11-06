package store

import (
	"database/sql"
	"errors"
	"time"
)

// Attempt states recorded by the observer. A pending attempt past its task's
// expiry is a timeout; that is derived by callers, never stored.
const (
	AttemptPending       = "pending"
	AttemptAuthenticated = "authenticated" // receipt issued, SNI as planned
	AttemptSNIMismatch   = "sni_mismatch"  // receipt issued, different SNI observed
	AttemptHelloMatched  = "hello_matched" // ClientHello digest matched; never authenticated
	AttemptHelloAmbig    = "hello_ambiguous"
)

// Evidence levels for observations, strongest first.
const (
	EvidenceAuthenticated = "authenticated" // pinned TLS + one-time credential
	EvidenceHelloMatch    = "hello_match"   // observer saw the ClientHello the client reported
	EvidenceAmbiguous     = "ambiguous"     // several connections carried that ClientHello digest
)

// Task is a planned set of attempts from one node against one target.
type Task struct {
	ID          string
	NodeID      string
	CollectorID string
	Target      string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	CancelledAt *time.Time // set when the node cancelled the task
	Snapshot    string     // JSON of the test conditions at creation time
}

// Attempt is one planned probe (one SNI, one connection).
type Attempt struct {
	ID       string
	TaskID   string
	Index    int
	SNI      string
	Target   string // observer ip:port this attempt connects to
	Kind     string // "baseline" or "domain"
	Round    int
	CredHash []byte
	State    string
}

// Observation is what the observer saw for an attempt (append-only fact).
type Observation struct {
	AttemptID   string
	ObservedAt  time.Time
	RemoteIP    string
	RemotePort  int
	ObservedSNI string
	Evidence    string
	SNIMatch    bool
}

// ClientEvent is the client's own report about an attempt (append-only fact).
type ClientEvent struct {
	AttemptID   string
	EventID     string
	ReceivedAt  time.Time
	Stage       string
	Outcome     string
	Error       string
	StartedAt   time.Time
	DurationMS  int64
	HelloSHA256 string // hex digest of the ClientHello the client sent ("" if none was sent)
}

// InsertTask stores a task with its attempts and bumps the node's counter.
func (s *Store) InsertTask(t *Task, atts []Attempt) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO tasks(id,node_id,collector_id,target,created_at,expires_at,snapshot) VALUES(?,?,?,?,?,?,?)`,
		t.ID, t.NodeID, t.CollectorID, t.Target, ms(t.CreatedAt), ms(t.ExpiresAt), t.Snapshot); err != nil {
		return err
	}
	for _, a := range atts {
		if _, err := tx.Exec(`INSERT INTO attempts(id,task_id,idx,sni,target,kind,round,cred_hash,state) VALUES(?,?,?,?,?,?,?,?,?)`,
			a.ID, t.ID, a.Index, a.SNI, a.Target, a.Kind, a.Round, a.CredHash, AttemptPending); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE nodes SET tasks = tasks + 1 WHERE id = ?`, t.NodeID); err != nil {
		return err
	}
	return tx.Commit()
}

// CountActive returns the number of unfinished tasks overall and for nodeID.
// A task is unfinished while it is unexpired and has an attempt that is
// neither observed nor reported by the client.
func (s *Store) CountActive(now time.Time, nodeID string) (all, node int, err error) {
	err = s.db.QueryRow(`
SELECT COUNT(*), COALESCE(SUM(node_id = ?), 0) FROM tasks t
WHERE expires_at > ? AND cancelled_at IS NULL AND EXISTS (SELECT 1 FROM attempts a WHERE a.task_id = t.id AND a.state = 'pending'
  AND NOT EXISTS (SELECT 1 FROM client_events e WHERE e.attempt_id = a.id))`,
		nodeID, ms(now)).Scan(&all, &node)
	return
}

// GetTask returns a task, or ErrNotFound.
func (s *Store) GetTask(id string) (*Task, error) {
	var (
		t               Task
		created, expiry int64
		cancelled       sql.NullInt64
	)
	err := s.db.QueryRow(`SELECT id,node_id,collector_id,target,created_at,expires_at,cancelled_at,snapshot FROM tasks WHERE id = ?`, id).
		Scan(&t.ID, &t.NodeID, &t.CollectorID, &t.Target, &created, &expiry, &cancelled, &t.Snapshot)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.CreatedAt, t.ExpiresAt, t.CancelledAt = fromMS(created), fromMS(expiry), fromMSPtr(cancelled)
	return &t, nil
}

// CancelTask marks a task cancelled at the given time. It reports whether
// this call did it; a second call changes nothing.
func (s *Store) CancelTask(id string, at time.Time) (bool, error) {
	res, err := s.db.Exec(`UPDATE tasks SET cancelled_at = ? WHERE id = ? AND cancelled_at IS NULL`, ms(at), id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// TaskAttempts returns a task's attempts in order.
func (s *Store) TaskAttempts(taskID string) ([]Attempt, error) {
	rows, err := s.db.Query(`SELECT id,task_id,idx,sni,target,kind,round,cred_hash,state FROM attempts WHERE task_id = ? ORDER BY idx`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Attempt
	for rows.Next() {
		var a Attempt
		if err := rows.Scan(&a.ID, &a.TaskID, &a.Index, &a.SNI, &a.Target, &a.Kind, &a.Round, &a.CredHash, &a.State); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AttemptRef is an attempt together with what is needed to authorize it.
type AttemptRef struct {
	Attempt
	TaskCreated time.Time
	TaskExpires time.Time
	TaskCancel  *time.Time // when the task was cancelled, if it was
	NodeID      string
	NodePath    string
	NodeRevoked bool
}

func (s *Store) attemptRef(where string, arg any) (*AttemptRef, error) {
	var (
		r                AttemptRef
		created, expires int64
		cancelled        sql.NullInt64
		revoked          int
	)
	err := s.db.QueryRow(`
SELECT a.id,a.task_id,a.idx,a.sni,a.target,a.kind,a.round,a.cred_hash,a.state, t.created_at, t.expires_at, t.cancelled_at, n.id, n.path, n.revoked
FROM attempts a JOIN tasks t ON t.id = a.task_id JOIN nodes n ON n.id = t.node_id
WHERE `+where, arg).Scan(&r.ID, &r.TaskID, &r.Index, &r.SNI, &r.Target, &r.Kind, &r.Round, &r.CredHash, &r.State, &created, &expires, &cancelled, &r.NodeID, &r.NodePath, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.TaskCreated, r.TaskExpires, r.TaskCancel, r.NodeRevoked = fromMS(created), fromMS(expires), fromMSPtr(cancelled), revoked != 0
	return &r, nil
}

// AttemptByCred finds an attempt by the hash of its one-time credential.
func (s *Store) AttemptByCred(hash []byte) (*AttemptRef, error) {
	return s.attemptRef(`a.cred_hash = ?`, hash)
}

// AttemptByID finds an attempt by id.
func (s *Store) AttemptByID(id string) (*AttemptRef, error) {
	return s.attemptRef(`a.id = ?`, id)
}

// RecordObservation atomically moves a pending attempt to newState and stores
// the observation. It returns false (and stores nothing) if the attempt was no
// longer pending, which is what makes credentials one-time.
func (s *Store) RecordObservation(o Observation, newState string) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE attempts SET state = ? WHERE id = ? AND state = 'pending'`, newState, o.AttemptID)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	if _, err := tx.Exec(`INSERT INTO observations(attempt_id,observed_at,remote_ip,remote_port,observed_sni,evidence,sni_match) VALUES(?,?,?,?,?,?,?)`,
		o.AttemptID, ms(o.ObservedAt), o.RemoteIP, o.RemotePort, o.ObservedSNI, o.Evidence, b2i(o.SNIMatch)); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// TaskObservations returns the observations of a task's attempts by attempt id.
func (s *Store) TaskObservations(taskID string) (map[string]Observation, error) {
	rows, err := s.db.Query(`
SELECT o.attempt_id,o.observed_at,o.remote_ip,o.remote_port,o.observed_sni,o.evidence,o.sni_match
FROM observations o JOIN attempts a ON a.id = o.attempt_id WHERE a.task_id = ?`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]Observation)
	for rows.Next() {
		var (
			o     Observation
			at    int64
			match int
		)
		if err := rows.Scan(&o.AttemptID, &at, &o.RemoteIP, &o.RemotePort, &o.ObservedSNI, &o.Evidence, &match); err != nil {
			return nil, err
		}
		o.ObservedAt, o.SNIMatch = fromMS(at), match != 0
		out[o.AttemptID] = o
	}
	return out, rows.Err()
}

// InsertClientEvent stores a client event idempotently on (attempt, event id).
// It reports whether a new row was written.
func (s *Store) InsertClientEvent(e ClientEvent) (bool, error) {
	res, err := s.db.Exec(`INSERT OR IGNORE INTO client_events(attempt_id,event_id,received_at,stage,outcome,error,started_at,duration_ms,hello_sha256) VALUES(?,?,?,?,?,?,?,?,?)`,
		e.AttemptID, e.EventID, ms(e.ReceivedAt), e.Stage, e.Outcome, e.Error, ms(e.StartedAt), e.DurationMS, e.HelloSHA256)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// TaskClientEvents returns client events of a task's attempts, oldest first.
func (s *Store) TaskClientEvents(taskID string) ([]ClientEvent, error) {
	rows, err := s.db.Query(`
SELECT e.attempt_id,e.event_id,e.received_at,e.stage,e.outcome,e.error,e.started_at,e.duration_ms,e.hello_sha256
FROM client_events e JOIN attempts a ON a.id = e.attempt_id WHERE a.task_id = ? ORDER BY e.started_at, e.event_id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClientEvent
	for rows.Next() {
		var (
			e         ClientEvent
			rcv, strt int64
		)
		if err := rows.Scan(&e.AttemptID, &e.EventID, &rcv, &e.Stage, &e.Outcome, &e.Error, &strt, &e.DurationMS, &e.HelloSHA256); err != nil {
			return nil, err
		}
		e.ReceivedAt, e.StartedAt = fromMS(rcv), fromMS(strt)
		out = append(out, e)
	}
	return out, rows.Err()
}

// TaskSummary is one row of a task listing.
type TaskSummary struct {
	ID        string
	NodeName  string
	Target    string
	CreatedAt time.Time
	ExpiresAt time.Time
	Attempts  int
	Observed  int // attempts with an observation
	Reported  int // attempts the client reported on
	Cancelled bool
	NodeID    string
}

// RecentTasks lists the newest tasks first, for one node or (nodeID == "") all.
func (s *Store) RecentTasks(nodeID string, limit int) ([]TaskSummary, error) {
	rows, err := s.db.Query(`
SELECT t.id, n.name, t.target, t.created_at, t.expires_at, t.cancelled_at IS NOT NULL, n.id,
  (SELECT COUNT(*) FROM attempts a WHERE a.task_id = t.id),
  (SELECT COUNT(*) FROM attempts a JOIN observations o ON o.attempt_id = a.id WHERE a.task_id = t.id),
  (SELECT COUNT(DISTINCT e.attempt_id) FROM attempts a JOIN client_events e ON e.attempt_id = a.id WHERE a.task_id = t.id)
FROM tasks t JOIN nodes n ON n.id = t.node_id WHERE (? = '' OR t.node_id = ?) ORDER BY t.created_at DESC, t.id LIMIT ?`, nodeID, nodeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskSummary
	for rows.Next() {
		var (
			r        TaskSummary
			cr, expr int64
		)
		if err := rows.Scan(&r.ID, &r.NodeName, &r.Target, &cr, &expr, &r.Cancelled, &r.NodeID, &r.Attempts, &r.Observed, &r.Reported); err != nil {
			return nil, err
		}
		r.CreatedAt, r.ExpiresAt = fromMS(cr), fromMS(expr)
		out = append(out, r)
	}
	return out, rows.Err()
}
