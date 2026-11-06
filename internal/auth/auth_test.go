package auth

import (
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nyktios/sniroute/internal/store"
)

const testAdmin = "0123456789abcdef0123456789abcdef-admin"

func newReg(t *testing.T) (*Registry, *time.Time) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	r, err := NewRegistry(testAdmin, st)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return clock }
	return r, &clock
}

func register(t *testing.T, r *Registry) Credentials {
	t.Helper()
	_, k, err := r.NewRegToken(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c, err := r.Register(k, "vps-1", "ProviderX")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAdminKey(t *testing.T) {
	if _, err := NewRegistry("short", nil); !errors.Is(err, ErrShortKey) {
		t.Fatalf("short key: %v", err)
	}
	r, _ := newReg(t)
	if !r.CheckAdmin(testAdmin) || r.CheckAdmin("") || r.CheckAdmin(testAdmin+"x") {
		t.Fatal("admin key check wrong")
	}
	if k := GenerateKey(); len(k) < MinAdminKeyLen {
		t.Fatalf("generated key too short: %d", len(k))
	}
}

func TestRegisterAndAuthenticate(t *testing.T) {
	r, _ := newReg(t)
	c := register(t, r)
	if len(c.Path) < 22 { // >= 128 bits of base64url
		t.Errorf("path too short: %q", c.Path)
	}
	ip := netip.MustParseAddr("203.0.113.9")

	n, err := r.Authenticate(c.Path, c.NodeKey, ip)
	if err != nil || n.ID != c.NodeID || n.LastIP != "203.0.113.9" || n.LastSeen == nil {
		t.Fatalf("authenticate: %+v %v", n, err)
	}
	// The path alone is not a credential, and neither is another node's key.
	other := register(t, r)
	for _, tc := range []struct{ path, key string }{
		{c.Path, ""}, {c.Path, "wrong"}, {c.Path, other.NodeKey}, {"nope", c.NodeKey}, {"", ""},
	} {
		if _, err := r.Authenticate(tc.path, tc.key, ip); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("%+v: err = %v", tc, err)
		}
	}
}

func TestRegTokenOneTimeAndExpiry(t *testing.T) {
	r, clock := newReg(t)
	_, k, _ := r.NewRegToken(time.Minute)
	if _, err := r.Register(k, "a", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(k, "b", ""); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("reuse: %v", err)
	}
	_, k2, _ := r.NewRegToken(time.Minute)
	*clock = clock.Add(2 * time.Minute)
	if _, err := r.Register(k2, "c", ""); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("expired: %v", err)
	}
	if _, err := r.Register("reg_bogus", "d", ""); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("bogus: %v", err)
	}
}

func TestRegisterNameValidation(t *testing.T) {
	r, _ := newReg(t)
	_, k, _ := r.NewRegToken(time.Minute)
	for _, name := range []string{strings.Repeat("a", 65), "bad\nname"} {
		if _, err := r.Register(k, name, ""); !errors.Is(err, ErrInvalidName) {
			t.Errorf("%q: %v", name, err)
		}
	}
	// A rejected name must not burn the registration key.
	if _, err := r.Register(k, "ok", ""); err != nil {
		t.Errorf("key burned by invalid name: %v", err)
	}
}

func TestRevokeAndRotate(t *testing.T) {
	r, _ := newReg(t)
	c := register(t, r)
	ip := netip.Addr{}

	nc, err := r.RotateKey(c.NodeID)
	if err != nil || nc.NodeKey == c.NodeKey || nc.Path != c.Path {
		t.Fatalf("rotate: %+v %v", nc, err)
	}
	if _, err := r.Authenticate(c.Path, c.NodeKey, ip); err == nil {
		t.Error("old key still works")
	}
	if _, err := r.Authenticate(c.Path, nc.NodeKey, ip); err != nil {
		t.Errorf("new key: %v", err)
	}

	if err := r.Revoke(c.NodeID); err != nil {
		t.Fatal(err)
	}
	if r.Active(c.NodeID) {
		t.Error("revoked node still active")
	}
	if _, err := r.Authenticate(c.Path, nc.NodeKey, ip); err == nil {
		t.Error("revoked node authenticates")
	}
	if _, err := r.RotateKey(c.NodeID); !errors.Is(err, ErrNotFound) {
		t.Errorf("rotate revoked: %v", err)
	}
	if err := r.Revoke("node_missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoke missing: %v", err)
	}
	if l, err := r.List(); err != nil || len(l) != 1 || !l[0].Revoked || l[0].ProviderLabel != "ProviderX" {
		t.Errorf("list: %+v %v", l, err)
	}
}

func TestRegTokenLimit(t *testing.T) {
	r, _ := newReg(t)
	for range maxRegKeys {
		if _, _, err := r.NewRegToken(time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := r.NewRegToken(time.Hour); !errors.Is(err, ErrLimit) {
		t.Errorf("over limit: %v", err)
	}
}

func TestAttemptCredential(t *testing.T) {
	a, b := NewAttemptCredential(), NewAttemptCredential()
	if a == b || !strings.HasPrefix(a, "cr1-") {
		t.Fatalf("bad credentials %q %q", a, b)
	}
	if string(HashCredential(a)) == string(HashCredential(b)) || len(HashCredential(a)) != 32 {
		t.Error("hash collision or wrong size")
	}
	if id1, id2 := NewAttemptID(), NewAttemptID(); id1 == id2 {
		t.Error("duplicate attempt ids")
	}
}

func TestStatePersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.db")
	st, _ := store.Open(path)
	r, _ := NewRegistry(testAdmin, st)
	_, k, _ := r.NewRegToken(time.Hour)
	c, err := r.Register(k, "vps", "X")
	if err != nil {
		t.Fatal(err)
	}
	st.Close()

	st2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	r2, _ := NewRegistry(testAdmin, st2)
	if _, err := r2.Authenticate(c.Path, c.NodeKey, netip.Addr{}); err != nil {
		t.Errorf("node lost after restart: %v", err)
	}
}

func TestOfflineKeyExpiresBeforeCleanupAndCannotRevive(t *testing.T) {
	r, clock := newReg(t)
	c := register(t, r)
	*clock = clock.Add(store.NodeOfflineTTL - time.Second)
	if _, err := r.Authenticate(c.Path, c.NodeKey, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	// A valid heartbeat extends the deadline; a failed one cannot revive it.
	*clock = clock.Add(store.NodeOfflineTTL)
	if _, err := r.Authenticate(c.Path, c.NodeKey, netip.Addr{}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired key: %v", err)
	}
	if r.Active(c.NodeID) {
		t.Fatal("expired node still active")
	}
	if count, err := r.st.PruneOfflineNodes(*clock); err != nil || count != 1 {
		t.Fatalf("cleanup: %d %v", count, err)
	}
	if _, err := r.Authenticate(c.Path, c.NodeKey, netip.Addr{}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("removed key: %v", err)
	}
	if _, err := r.Register("used-token", "old", ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old token: %v", err)
	}
}
