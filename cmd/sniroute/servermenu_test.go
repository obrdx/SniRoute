package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nyktios/sniroute/internal/link"
	"github.com/nyktios/sniroute/internal/server"
	"github.com/nyktios/sniroute/internal/tui"
)

func TestClientBootstrapCommandPreservesLinkAsLiteralArgument(t *testing.T) {
	dir := t.TempDir()
	// Return a tiny offline script instead of downloading or registering.
	fakeCurl := "#!/bin/sh\ncat <<'SCRIPT'\nprintf '%s\\n' \"$@\"\nSCRIPT\n"
	if err := os.WriteFile(filepath.Join(dir, "curl"), []byte(fakeCurl), 0o700); err != nil {
		t.Fatal(err)
	}
	regLink := "https://example.com:8443/join#token.pin.name'$(touch " + filepath.Join(dir, "injected") + ")"
	cmd := exec.Command("sh", "-c", clientBootstrapCommand(regLink))
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != "--link\n"+regLink+"\n" {
		t.Fatalf("link changed: %v, %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "injected")); !os.IsNotExist(err) {
		t.Fatal("link contents executed as shell code")
	}
}

func TestServerRegLinkShowsCommandBeforeConnectionInfo(t *testing.T) {
	cfg := server.Config{ControlAddr: "192.0.2.10:8443", DataDir: t.TempDir(), AdminKey: strings.Repeat("a", 64)}
	ui, out := newTestUI("\n")
	if err := serverRegLink(ui, cfg); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	commandAt, infoAt := strings.Index(s, "sh -c"), strings.Index(s, "连接信息")
	if commandAt < 0 || infoAt < commandAt || !strings.Contains(s, "-- --link '") {
		t.Fatal(s)
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "注册链接：") {
			raw := strings.TrimPrefix(line, "注册链接：")
			parsed, err := link.Parse(raw)
			if err != nil || parsed.Token == "" || parsed.Server != "https://192.0.2.10:8443" || !strings.Contains(s, clientBootstrapCommand(raw)) {
				t.Fatalf("command and connection info differ: %v", err)
			}
			return
		}
	}
	t.Fatal("missing connection link")
}

func newTestUI(in string) (*tui.UI, *bytes.Buffer) {
	var out bytes.Buffer
	return tui.New(strings.NewReader(in), &out), &out
}

// Initialising the service must be one question with working defaults: a
// self-signed certificate and a generated admin key, no certificate hosts and
// no other prompts to answer.
func TestServerInitAsksOneQuestion(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "server.yaml")
	cfg, err := server.LoadConfig(cfgPath)
	if !errors.Is(err, server.ErrNoConfig) {
		t.Fatalf("expected an uninitialised config: %v", err)
	}
	// "y" accepts the recommended settings, "n" declines starting the daemon.
	ui, out := newTestUI("y\nn\n")
	if err := serverInit(ui, cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	got, err := server.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !got.TLSSelfSigned || got.TLSCert != "" || got.TLSKey != "" {
		t.Errorf("recommended setup should be self-signed: %+v", got)
	}
	if len(got.TLSHosts) != 0 {
		t.Errorf("self-signed hosts are irrelevant to pinning, should not be asked: %v", got.TLSHosts)
	}
	if got.AdminKey == "" {
		t.Error("admin key was not generated")
	}
	if st, err := os.Stat(cfgPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("config permissions: %v %v", st, err)
	}
	if s := out.String(); !strings.Contains(s, "首次初始化") || !strings.Contains(s, "现在启动服务") {
		t.Errorf("unexpected output:\n%s", s)
	}
}

// Custom setup still offers the ports, and only the certificate choice beyond
// that — the generated admin key is not a question.
func TestServerInitCustomKeepsDeviations(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "server.yaml")
	cfg, err := server.LoadConfig(cfgPath)
	if err != nil && !errors.Is(err, server.ErrNoConfig) {
		t.Fatal(err)
	}
	// decline recommended, accept custom, then three defaults, self-signed, decline start
	ui, _ := newTestUI("n\ny\n:8443\n:9443\n\n1\nn\n")
	if err := serverInit(ui, cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := server.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProbeAddr != ":8443" || got.ControlAddr != ":9443" || !got.TLSSelfSigned || got.AdminKey == "" {
		t.Errorf("custom setup: %+v", got)
	}
}

// Choosing the source that is already active reports "nothing changed" so the
// caller does not rewrite the file and warn about a restart for no reason.
func TestServerASNReportsOnlyRealChanges(t *testing.T) {
	cfg := server.Config{ASNSource: "ripestat"}

	ui, out := newTestUI("1\n")
	next, changed, err := serverASNChoice(ui, cfg)
	if err != nil || changed || next.ASNSource != "ripestat" {
		t.Fatalf("same source: changed=%v src=%q err=%v", changed, next.ASNSource, err)
	}
	if !strings.Contains(out.String(), "已经使用 RIPEstat") {
		t.Errorf("expected a note that nothing changed:\n%s", out.String())
	}

	ui, _ = newTestUI("2\n")
	next, changed, err = serverASNChoice(ui, cfg)
	if err != nil || !changed || next.ASNSource != "cymru" {
		t.Fatalf("switch source: changed=%v src=%q err=%v", changed, next.ASNSource, err)
	}

	ui, _ = newTestUI("0\n")
	if _, changed, err = serverASNChoice(ui, cfg); err != nil || changed {
		t.Errorf("back leaves the config alone: changed=%v err=%v", changed, err)
	}
}

func TestServerGeolocationSelection(t *testing.T) {
	cfg := server.Config{ASNSource: "ripestat"}
	for _, tc := range []struct {
		key, want string
		changed   bool
	}{
		{"5", "ipinfo,geojs", false},
		{"6", "ipinfo", true},
		{"7", "none", true},
	} {
		ui, _ := newTestUI(tc.key + "\n")
		next, changed, err := serverASNChoice(ui, cfg)
		if err != nil || changed != tc.changed || strings.Join(next.GeoSources, ",") != tc.want || next.ASNSource != "ripestat" {
			t.Fatalf("choice %s: %+v changed=%v err=%v", tc.key, next, changed, err)
		}
	}
}
