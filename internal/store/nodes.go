package store

import (
	"database/sql"
	"errors"
	"time"
)

// Node is a registered probing client.
type Node struct {
	ID            string
	Name          string
	ProviderLabel string
	Path          string
	KeyHash       []byte
	CreatedAt     time.Time
	LastSeen      *time.Time
	LastIP        string
	Tasks         int
	Revoked       bool
}

const nodeCols = "id, name, provider_label, path, key_hash, created_at, last_seen, last_ip, tasks, revoked"

func scanNode(row interface{ Scan(...any) error }) (*Node, error) {
	var (
		n       Node
		created int64
		seen    sql.NullInt64
		revoked int
	)
	err := row.Scan(&n.ID, &n.Name, &n.ProviderLabel, &n.Path, &n.KeyHash, &created, &seen, &n.LastIP, &n.Tasks, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	n.CreatedAt, n.LastSeen, n.Revoked = fromMS(created), fromMSPtr(seen), revoked != 0
	return &n, nil
}

// InsertNode adds a node.
func (s *Store) InsertNode(n *Node) error {
	_, err := s.db.Exec(`INSERT INTO nodes(`+nodeCols+`) VALUES(?,?,?,?,?,?,NULL,'',0,0)`,
		n.ID, n.Name, n.ProviderLabel, n.Path, n.KeyHash, ms(n.CreatedAt))
	return err
}

// NodeByPath returns the node at path, or ErrNotFound.
func (s *Store) NodeByPath(path string) (*Node, error) {
	return scanNode(s.db.QueryRow(`SELECT `+nodeCols+` FROM nodes WHERE path = ?`, path))
}

// NodeByID returns the node with id, or ErrNotFound.
func (s *Store) NodeByID(id string) (*Node, error) {
	return scanNode(s.db.QueryRow(`SELECT `+nodeCols+` FROM nodes WHERE id = ?`, id))
}

// ListNodes returns all nodes, oldest first.
func (s *Store) ListNodes() ([]*Node, error) {
	rows, err := s.db.Query(`SELECT ` + nodeCols + ` FROM nodes ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// CountNodes returns the number of registered nodes.
func (s *Store) CountNodes() (n int, err error) {
	err = s.db.QueryRow(`SELECT COUNT(*) FROM nodes`).Scan(&n)
	return
}

// TouchNode records activity from a node.
func (s *Store) TouchNode(id string, at time.Time, ip string) error {
	if ip == "" {
		_, err := s.db.Exec(`UPDATE nodes SET last_seen = ? WHERE id = ?`, ms(at), id)
		return err
	}
	_, err := s.db.Exec(`UPDATE nodes SET last_seen = ?, last_ip = ? WHERE id = ?`, ms(at), ip, id)
	return err
}

// SetNodeKeyHash replaces a node's key hash.
func (s *Store) SetNodeKeyHash(id string, h []byte) error {
	return s.mustAffect(s.db.Exec(`UPDATE nodes SET key_hash = ? WHERE id = ? AND revoked = 0`, h, id))
}

// RevokeNode permanently disables a node.
func (s *Store) RevokeNode(id string) error {
	return s.mustAffect(s.db.Exec(`UPDATE nodes SET revoked = 1 WHERE id = ?`, id))
}

func (s *Store) mustAffect(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RegToken is one outstanding (or consumed) registration token. The token
// string itself is not stored; see auth.Registration.
type RegToken struct {
	ID        string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// InsertRegToken stores a registration token's metadata.
func (s *Store) InsertRegToken(t *RegToken) error {
	_, err := s.db.Exec(`INSERT INTO reg_tokens(id, created_at, expires_at) VALUES(?,?,?)`, t.ID, ms(t.CreatedAt), ms(t.ExpiresAt))
	return err
}

// ListRegTokens returns outstanding tokens (unused and unexpired), newest first.
func (s *Store) ListRegTokens(now time.Time) ([]RegToken, error) {
	rows, err := s.db.Query(`SELECT id, created_at, expires_at FROM reg_tokens WHERE used_at IS NULL AND expires_at > ? ORDER BY created_at DESC`, ms(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RegToken
	for rows.Next() {
		var (
			t               RegToken
			created, expiry int64
		)
		if err := rows.Scan(&t.ID, &created, &expiry); err != nil {
			return nil, err
		}
		t.CreatedAt, t.ExpiresAt = fromMS(created), fromMS(expiry)
		out = append(out, t)
	}
	return out, rows.Err()
}

// PruneRegTokens deletes tokens that expired before cutoff and returns how
// many outstanding ones remain.
func (s *Store) PruneRegTokens(now, cutoff time.Time) (remaining int, err error) {
	if _, err = s.db.Exec(`DELETE FROM reg_tokens WHERE expires_at <= ?`, ms(cutoff)); err != nil {
		return
	}
	err = s.db.QueryRow(`SELECT COUNT(*) FROM reg_tokens WHERE used_at IS NULL AND expires_at > ?`, ms(now)).Scan(&remaining)
	return
}

// ConsumeRegToken marks a token used. It reports false when the token is
// unknown, already used or expired.
func (s *Store) ConsumeRegToken(id string, now time.Time) (bool, error) {
	res, err := s.db.Exec(`UPDATE reg_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?`, ms(now), id, ms(now))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// DeleteRegToken removes one token (operator action).
func (s *Store) DeleteRegToken(id string) error {
	if _, err := s.db.Exec(`DELETE FROM reg_tokens WHERE id = ?`, id); err != nil {
		return err
	}
	return nil
}
