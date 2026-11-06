package server

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigDefaultsAndPermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "etc", "server.yaml")
	c, err := LoadConfig(p)
	if !errors.Is(err, ErrNoConfig) || c.ProbeAddr != ":443" || c.ControlAddr != ":8443" || c.CollectorID != "collector-1" {
		t.Fatalf("missing file: %+v %v", c, err)
	}
	// A relative data dir is anchored next to the config, not the cwd.
	if c.DataDir != filepath.Join(filepath.Dir(p), "data") {
		t.Errorf("data dir = %q", c.DataDir)
	}

	c.AdminKey, c.TLSSelfSigned, c.TLSHosts = "secret-key-value", true, []string{"h.example"}
	if err := c.Save(p); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", st.Mode().Perm())
	}
	got, err := LoadConfig(p)
	if err != nil || got.AdminKey != "secret-key-value" || !got.TLSSelfSigned || got.TLSHosts[0] != "h.example" {
		t.Fatalf("roundtrip: %+v %v", got, err)
	}

	os.Chmod(p, 0o644)
	if _, err := LoadConfig(p); err == nil || errors.Is(err, ErrNoConfig) {
		t.Errorf("accepted a world-readable config holding the admin key: %v", err)
	}
}

func TestDaemonStatusHandlesStalePid(t *testing.T) {
	dir := t.TempDir()
	if pid, err := DaemonStatus(dir); pid != 0 || err != nil {
		t.Fatalf("no pid file: %d %v", pid, err)
	}
	// A pid that cannot exist: the file is treated as stale and removed.
	os.WriteFile(pidPath(dir), []byte("999999999\n"), 0o600)
	if pid, _ := DaemonStatus(dir); pid != 0 {
		t.Errorf("stale pid reported as running: %d", pid)
	}
	if _, err := os.Stat(pidPath(dir)); !os.IsNotExist(err) {
		t.Error("stale pid file not removed")
	}
	// Our own pid is alive.
	os.WriteFile(pidPath(dir), []byte(itoa(os.Getpid())+"\n"), 0o600)
	if pid, _ := DaemonStatus(dir); pid != os.Getpid() {
		t.Errorf("live pid not detected: %d", pid)
	}
	if err := StopDaemon(t.TempDir()); err == nil {
		t.Error("stopping a service that is not running should fail")
	}
}

func itoa(n int) string {
	b := []byte{}
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
