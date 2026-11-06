// Package auth handles SniRoute identities: the admin key, one-time
// registration keys, node identities (random path + independent node key) and
// one-time probe tokens.
//
// The random path only LOCATES a node; authentication is the node key.
// Secrets are never stored in clear: only SHA-256 hashes are kept, which is
// sufficient because every secret is 128+ bits of crypto/rand output.
// State lives in the SQLite store.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/nyktios/sniroute/internal/store"
)

const (
	// MinAdminKeyLen is the shortest admin key accepted at startup
	// (`sniroute genkey` produces 43 characters).
	MinAdminKeyLen = 32

	pathBytes  = 20 // 160-bit node path
	keyBytes   = 32 // node key
	maxNodes   = 1000
	maxRegKeys = 100
	maxNameLen = 64
	// MaxRegKeyTTL bounds how long a registration token stays valid.
	MaxRegKeyTTL = 30 * 24 * time.Hour
)

var (
	ErrUnauthorized = errors.New("auth: unauthorized")
	ErrNotFound     = errors.New("auth: node not found")
	ErrLimit        = errors.New("auth: limit reached")
	ErrInvalidName  = errors.New("auth: invalid node name")
	ErrShortKey     = errors.New("auth: admin key too short")
)

// RandomString returns n random bytes, base64url-encoded without padding.
func RandomString(n int) string {
	b := make([]byte, n)
	rand.Read(b) // never returns an error (Go 1.24+: crashes the program instead)
	return base64.RawURLEncoding.EncodeToString(b)
}

// GenerateKey returns a new 256-bit key suitable for admin use.
func GenerateKey() string { return RandomString(keyBytes) }

type hash = [sha256.Size]byte

func hashOf(s string) hash { return sha256.Sum256([]byte(s)) }

func equal(a, b hash) bool { return subtle.ConstantTimeCompare(a[:], b[:]) == 1 }

// NodeInfo is a read-only snapshot of a node.
type NodeInfo struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	ProviderLabel string     `json:"provider_label"`
	Path          string     `json:"path"`
	CreatedAt     time.Time  `json:"created_at"`
	LastSeen      *time.Time `json:"last_seen,omitempty"`
	LastIP        string     `json:"last_ip,omitempty"`
	Tasks         int        `json:"tasks"`
	Revoked       bool       `json:"revoked"`
}

func infoOf(n *store.Node) NodeInfo {
	return NodeInfo{
		ID: n.ID, Name: n.Name, ProviderLabel: n.ProviderLabel, Path: n.Path,
		CreatedAt: n.CreatedAt, LastSeen: n.LastSeen, LastIP: n.LastIP, Tasks: n.Tasks, Revoked: n.Revoked,
	}
}

// Credentials are returned exactly once, at registration or key rotation.
type Credentials struct {
	NodeID  string `json:"node_id"`
	Path    string `json:"path"`
	NodeKey string `json:"node_key"`
}

// Registry manages registration keys and nodes on top of the store. It is
// safe for concurrent use.
type Registry struct {
	now       func() time.Time
	adminHash hash
	adminKey  []byte // kept only to derive registration tokens; never printed
	st        *store.Store

	mu sync.Mutex // serializes check-then-act sequences
}

// NewRegistry creates a registry guarded by adminKey.
func NewRegistry(adminKey string, st *store.Store) (*Registry, error) {
	if len(adminKey) < MinAdminKeyLen {
		return nil, ErrShortKey
	}
	return &Registry{now: time.Now, adminHash: hashOf(adminKey), adminKey: []byte(adminKey), st: st}, nil
}

// CheckAdmin reports whether key is the admin key.
func (r *Registry) CheckAdmin(key string) bool { return equal(hashOf(key), r.adminHash) }

// NewRegToken issues a registration token valid for ttl and returns its
// record plus the token string. The token is derived from the admin key with
// HMAC-SHA256, so only its id is stored: the database holds no usable secret
// and the operator can still re-display an outstanding link later.
func (r *Registry) NewRegToken(ttl time.Duration) (store.RegToken, string, error) {
	if ttl <= 0 || ttl > MaxRegKeyTTL {
		ttl = time.Hour
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	n, err := r.st.PruneRegTokens(now, now.Add(-7*24*time.Hour))
	if err != nil {
		return store.RegToken{}, "", err
	}
	if n >= maxRegKeys {
		return store.RegToken{}, "", ErrLimit
	}
	id := RandomString(9) // 72 bits; the id is a lookup handle, not a secret
	t := store.RegToken{ID: id, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	if err := r.st.InsertRegToken(&t); err != nil {
		return store.RegToken{}, "", err
	}
	return t, r.regToken(id), nil
}

// regToken derives the secret token for id. Changing the admin key
// invalidates every outstanding token, which is the intended behaviour.
func (r *Registry) regToken(id string) string {
	mac := hmac.New(sha256.New, r.adminKey)
	mac.Write([]byte("sniroute reg " + id))
	return "reg_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// RegTokenFor returns the token string of an outstanding record.
func (r *Registry) RegTokenFor(t store.RegToken) string { return r.regToken(t.ID) }

// RegTokens lists outstanding registration tokens, newest first.
func (r *Registry) RegTokens() ([]store.RegToken, error) { return r.st.ListRegTokens(r.now()) }

// DeleteRegToken revokes one outstanding token.
func (r *Registry) DeleteRegToken(id string) error { return r.st.DeleteRegToken(id) }

// resolveRegToken finds the outstanding record a presented token refers to.
// Both the derived form (reg_<43 chars>) and a bare short id are accepted, so
// the operator can hand-type the id when reading it out loud.
func (r *Registry) resolveRegToken(token string, outstanding []store.RegToken) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	for _, t := range outstanding {
		if subtle.ConstantTimeCompare([]byte(r.regToken(t.ID)), []byte(token)) == 1 {
			return t.ID
		}
	}
	for _, t := range outstanding {
		if t.ID == token {
			return t.ID
		}
	}
	return ""
}

func validLabel(s string, max int) bool {
	return len(s) <= max && !strings.ContainsFunc(s, func(c rune) bool { return c < 0x20 || c == 0x7f })
}

// Register consumes a registration token and creates a node. The token is
// burned only when input validation passed and the token was valid.
func (r *Registry) Register(regToken, name, providerLabel string) (Credentials, error) {
	name, providerLabel = strings.TrimSpace(name), strings.TrimSpace(providerLabel)
	if !validLabel(name, maxNameLen) || !validLabel(providerLabel, maxNameLen) {
		return Credentials{}, ErrInvalidName
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	count, err := r.st.CountNodes()
	if err != nil {
		return Credentials{}, err
	}
	if count >= maxNodes {
		return Credentials{}, ErrLimit
	}
	outstanding, err := r.st.ListRegTokens(now)
	if err != nil {
		return Credentials{}, err
	}
	if r.resolveRegToken(regToken, outstanding) == "" {
		return Credentials{}, ErrUnauthorized
	}
	ok, err := r.st.ConsumeRegToken(r.resolveRegToken(regToken, outstanding), now)
	if err != nil {
		return Credentials{}, err
	}
	if !ok {
		return Credentials{}, ErrUnauthorized
	}

	idb := make([]byte, 6)
	rand.Read(idb)
	key := RandomString(keyBytes)
	kh := hashOf(key)
	n := &store.Node{
		ID: "node_" + hex.EncodeToString(idb), Name: name, ProviderLabel: providerLabel,
		Path: RandomString(pathBytes), KeyHash: kh[:], CreatedAt: now,
	}
	if err := r.st.InsertNode(n); err != nil {
		return Credentials{}, err
	}
	return Credentials{NodeID: n.ID, Path: n.Path, NodeKey: key}, nil
}

var dummyHash = hashOf("sniroute-no-such-node")

// Authenticate checks the node key for the node at path and, on success,
// records activity. Every failure (unknown path, wrong key, revoked) returns
// ErrUnauthorized and takes comparable time.
func (r *Registry) Authenticate(path, key string, from netip.Addr) (NodeInfo, error) {
	n, err := r.st.NodeByPath(path)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return NodeInfo{}, err
	}
	want := dummyHash
	if n != nil {
		copy(want[:], n.KeyHash)
	}
	if !equal(hashOf(key), want) || n == nil || n.Revoked {
		return NodeInfo{}, ErrUnauthorized
	}
	now := r.now()
	ip := ""
	if from.IsValid() {
		ip = from.String()
	}
	if err := r.st.TouchLiveNode(n.ID, now, ip); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return NodeInfo{}, ErrUnauthorized
		}
		return NodeInfo{}, err
	}
	n.LastSeen = &now
	if ip != "" {
		n.LastIP = ip
	}
	return infoOf(n), nil
}

// Active reports whether the node exists and is not revoked.
func (r *Registry) Active(id string) bool {
	n, err := r.st.NodeByID(id)
	return err == nil && !n.Revoked && r.now().Before(nodeLastActivity(n).Add(store.NodeOfflineTTL))
}

func nodeLastActivity(n *store.Node) time.Time {
	if n.LastSeen != nil {
		return *n.LastSeen
	}
	return n.CreatedAt
}

// Revoke permanently disables a node.
func (r *Registry) Revoke(id string) error {
	if err := r.st.RevokeNode(id); errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	} else {
		return err
	}
}

// RotateKey replaces a node's key; the old key stops working immediately.
func (r *Registry) RotateKey(id string) (Credentials, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, err := r.st.NodeByID(id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && n.Revoked) {
		return Credentials{}, ErrNotFound
	}
	if err != nil {
		return Credentials{}, err
	}
	key := RandomString(keyBytes)
	kh := hashOf(key)
	if err := r.st.SetNodeKeyHash(id, kh[:]); err != nil {
		return Credentials{}, err
	}
	return Credentials{NodeID: n.ID, Path: n.Path, NodeKey: key}, nil
}

// List returns all nodes, oldest first.
func (r *Registry) List() ([]NodeInfo, error) {
	ns, err := r.st.ListNodes()
	if err != nil {
		return nil, err
	}
	out := make([]NodeInfo, len(ns))
	for i, n := range ns {
		out[i] = infoOf(n)
	}
	return out, nil
}
