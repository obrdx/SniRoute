package client

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Outbox is a small local SQLite queue of events that must reach the server.
// Every client event is written here BEFORE it is sent and marked delivered
// only after the server accepted it, so a dropped control connection loses
// nothing: undelivered rows are re-sent later. The server stores events
// idempotently by event id, so re-sending is always safe.
type Outbox struct{ db *sql.DB }

// Kinds of queued item. They map to control API calls.
const (
	KindEvent  = "event"  // attempt event
	KindCancel = "cancel" // task cancellation notice
)

// Item is one queued delivery.
type Item struct {
	ID        int64
	TaskID    string
	Kind      string
	EventID   string
	Payload   []byte
	CreatedAt time.Time
	Attempts  int
	LastError string
}

const outboxSchema = `
CREATE TABLE IF NOT EXISTS outbox(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  event_id TEXT NOT NULL,
  payload BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  delivered_at INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  UNIQUE(task_id, kind, event_id)
);
CREATE TABLE IF NOT EXISTS local_reports(task_id TEXT PRIMARY KEY,created_at INTEGER NOT NULL,payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS runs(
  task_id TEXT PRIMARY KEY,
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  status TEXT NOT NULL
);
`

// DefaultOutboxPath sits next to the client config.
func DefaultOutboxPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "client.db")
}

// OpenOutbox opens (creating privately) the local queue.
func OpenOutbox(path string) (*Outbox, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(outboxSchema); err != nil {
		db.Close()
		return nil, err
	}
	return &Outbox{db: db}, nil
}

// Close closes the queue.
func (o *Outbox) Close() error { return o.db.Close() }

// Enqueue stores an item (idempotent on task, kind and event id) and returns it.
func (o *Outbox) Enqueue(taskID, kind, eventID string, payload []byte, now time.Time) (Item, error) {
	_, err := o.db.Exec(`INSERT OR IGNORE INTO outbox(task_id,kind,event_id,payload,created_at) VALUES(?,?,?,?,?)`,
		taskID, kind, eventID, payload, now.UnixMilli())
	if err != nil {
		return Item{}, err
	}
	var it Item
	var created int64
	err = o.db.QueryRow(`SELECT id,task_id,kind,event_id,payload,created_at,attempts,last_error FROM outbox WHERE task_id=? AND kind=? AND event_id=?`,
		taskID, kind, eventID).Scan(&it.ID, &it.TaskID, &it.Kind, &it.EventID, &it.Payload, &created, &it.Attempts, &it.LastError)
	it.CreatedAt = time.UnixMilli(created)
	return it, err
}

// MarkDelivered records that the server accepted the item.
func (o *Outbox) MarkDelivered(id int64, now time.Time) error {
	_, err := o.db.Exec(`UPDATE outbox SET delivered_at = ?, last_error = '' WHERE id = ?`, now.UnixMilli(), id)
	return err
}

// MarkFailed records a failed delivery attempt; the item stays queued.
func (o *Outbox) MarkFailed(id int64, cause error) error {
	msg := ""
	if cause != nil {
		msg = cause.Error()
		if len(msg) > 300 {
			msg = msg[:300]
		}
	}
	_, err := o.db.Exec(`UPDATE outbox SET attempts = attempts + 1, last_error = ? WHERE id = ?`, msg, id)
	return err
}

// Pending lists undelivered items, oldest first. taskID "" means every task.
func (o *Outbox) Pending(taskID string) ([]Item, error) {
	rows, err := o.db.Query(`SELECT id,task_id,kind,event_id,payload,created_at,attempts,last_error FROM outbox
WHERE delivered_at IS NULL AND (? = '' OR task_id = ?) ORDER BY id`, taskID, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var (
			it      Item
			created int64
		)
		if err := rows.Scan(&it.ID, &it.TaskID, &it.Kind, &it.EventID, &it.Payload, &created, &it.Attempts, &it.LastError); err != nil {
			return nil, err
		}
		it.CreatedAt = time.UnixMilli(created)
		out = append(out, it)
	}
	return out, rows.Err()
}

// SendFunc delivers one item to the server. A nil error means it was accepted.
type SendFunc func(ctx context.Context, it Item) error

// Deliver tries to send items in order. It stops at the first transport
// failure (the link is probably down) but skips items the server rejects as
// invalid, which would otherwise block the queue forever. It returns how many
// items were delivered and how many remain queued.
func (o *Outbox) Deliver(ctx context.Context, taskID string, send SendFunc, now func() time.Time) (delivered, remaining int, err error) {
	items, err := o.Pending(taskID)
	if err != nil {
		return 0, 0, err
	}
	for _, it := range items {
		if ctx.Err() != nil {
			return delivered, len(items) - delivered, ctx.Err()
		}
		serr := send(ctx, it)
		var api *APIError
		switch {
		case serr == nil:
			if err := o.MarkDelivered(it.ID, now()); err != nil {
				return delivered, len(items) - delivered, err
			}
			delivered++
		case errors.As(serr, &api) && api.Status >= 400 && api.Status < 500 && api.Status != 429 && api.Status != 401:
			// The server understood and refused (e.g. unknown task): retrying cannot help.
			o.markRejected(it.ID, serr, now())
		default:
			o.MarkFailed(it.ID, serr)
			rem, _ := o.Pending(taskID)
			return delivered, len(rem), nil
		}
	}
	rem, _ := o.Pending(taskID)
	return delivered, len(rem), nil
}

// markRejected retires an item the server refused, keeping the reason.
func (o *Outbox) markRejected(id int64, cause error, now time.Time) {
	msg := "rejected: " + cause.Error()
	if len(msg) > 300 {
		msg = msg[:300]
	}
	o.db.Exec(`UPDATE outbox SET delivered_at = ?, attempts = attempts + 1, last_error = ? WHERE id = ?`, now.UnixMilli(), msg, id)
}

// StartRun records that a task run began; FinishRun records how it ended.
func (o *Outbox) StartRun(taskID string, now time.Time) error {
	_, err := o.db.Exec(`INSERT OR IGNORE INTO runs(task_id, started_at, status) VALUES(?,?,'running')`, taskID, now.UnixMilli())
	return err
}

// FinishRun sets the final status ("finished" or "cancelled").
func (o *Outbox) FinishRun(taskID, status string, now time.Time) error {
	_, err := o.db.Exec(`UPDATE runs SET status = ?, finished_at = ? WHERE task_id = ?`, status, now.UnixMilli(), taskID)
	return err
}

// Interrupted lists runs that never finished (the process died or SSH
// dropped mid-run), newest first.
func (o *Outbox) Interrupted() ([]string, error) {
	rows, err := o.db.Query(`SELECT task_id FROM runs WHERE status = 'running' ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// MarkInterrupted flags a lingering 'running' run as interrupted.
func (o *Outbox) MarkInterrupted(taskID string, now time.Time) error {
	_, err := o.db.Exec(`UPDATE runs SET status = 'interrupted', finished_at = ? WHERE task_id = ? AND status = 'running'`, now.UnixMilli(), taskID)
	return err
}
