package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstalledMenuUsesSystemdForOwnConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "server.yaml")
	log := filepath.Join(dir, "calls")
	tool := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SERVICE_TEST_LOG\"\nif [ \"$1\" = show ]; then echo 12345; fi\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(tool), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SERVICE_TEST_LOG", log)
	t.Setenv("SNIROUTE_SYSTEMD_UNIT", "sniroute.service")
	t.Setenv("SNIROUTE_SYSTEMD_CONFIG", cfg)
	pid, err := serverMenuPID(cfg, dir)
	if err != nil || pid != 12345 {
		t.Fatalf("pid=%d, err=%v", pid, err)
	}
	if err := controlSystemd("stop", systemdUnit(cfg)); err != nil {
		t.Fatal(err)
	}
	if systemdUnit(filepath.Join(dir, "other.yaml")) != "" {
		t.Fatal("another config must not control the installed service")
	}
	calls, err := os.ReadFile(log)
	if err != nil || !strings.Contains(string(calls), "stop sniroute.service") {
		t.Fatalf("calls=%s, err=%v", calls, err)
	}
}
