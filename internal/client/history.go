package client

import (
	"database/sql"
	"encoding/json"
	"errors"
	"sort"

	"github.com/nyktios/sniroute/internal/server"
)

// SaveTask stores evidence locally, independent of observer retention.
func (o *Outbox) SaveTask(v server.TaskView) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = o.db.Exec(`INSERT INTO local_reports(task_id,created_at,payload) VALUES(?,?,?) ON CONFLICT(task_id) DO UPDATE SET payload=excluded.payload`, v.ID, v.CreatedAt.UnixMilli(), b)
	return err
}
func (o *Outbox) LoadTask(id string) (server.TaskView, bool, error) {
	var b []byte
	var v server.TaskView
	err := o.db.QueryRow(`SELECT payload FROM local_reports WHERE task_id=?`, id).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return v, false, nil
	}
	if err != nil {
		return v, false, err
	}
	err = json.Unmarshal(b, &v)
	return v, err == nil, err
}
func (o *Outbox) LocalTasks() (out []server.TaskListItem, err error) {
	rows, err := o.db.Query(`SELECT payload FROM local_reports ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b []byte
		var v server.TaskView
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, err
		}
		recorded := 0
		for _, a := range v.Attempts {
			if a.Observation != nil || len(a.Client) > 0 {
				recorded++
			}
		}
		out = append(out, server.TaskListItem{ID: v.ID, CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt, Status: v.Status, Target: v.Target, Planned: len(v.Attempts), Recorded: recorded, Cancelled: v.CancelledAt != nil})
	}
	return out, rows.Err()
}
func MergeTaskLists(local, remote []server.TaskListItem) []server.TaskListItem {
	byID := map[string]server.TaskListItem{}
	for _, x := range local {
		byID[x.ID] = x
	}
	for _, x := range remote {
		byID[x.ID] = x
	}
	out := make([]server.TaskListItem, 0, len(byID))
	for _, x := range byID {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}
