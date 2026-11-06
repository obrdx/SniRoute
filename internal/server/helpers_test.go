package server

import (
	"crypto/tls"
	"path/filepath"
	"testing"
	"time"

	"github.com/nyktios/sniroute/internal/auth"
	"github.com/nyktios/sniroute/internal/store"
)

const adminKey = "0123456789abcdef0123456789abcdef-admin"

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func newProbeCert(t *testing.T) tls.Certificate {
	t.Helper()
	c, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "probe.pem"), "test probe", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// testEnv is a registry + task manager + one registered node.
type testEnv struct {
	st     *store.Store
	reg    *auth.Registry
	tasks  *Tasks
	creds  auth.Credentials
	clock  time.Time
	tasksT *testing.T
}

func newEnv(t *testing.T, cfg TasksConfig) *testEnv {
	t.Helper()
	st := newStore(t)
	reg, err := auth.NewRegistry(adminKey, st)
	if err != nil {
		t.Fatal(err)
	}
	_, k, _ := reg.NewRegToken(time.Hour)
	creds, err := reg.Register(k, "n1", "ProviderX")
	if err != nil {
		t.Fatal(err)
	}
	e := &testEnv{st: st, reg: reg, creds: creds, clock: time.Now()}
	e.tasks = NewTasks(cfg, reg, st, "collector-1")
	e.tasks.now = func() time.Time { return e.clock }
	return e
}
