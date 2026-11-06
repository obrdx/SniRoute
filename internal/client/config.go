package client

import (
	"bufio"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nyktios/sniroute/internal/pack"
	"gopkg.in/yaml.v3"
)

// Enrollment is the identity obtained at registration. It contains the node
// key, which is why the config file must stay private.
type Enrollment struct {
	Server      string `yaml:"server"`
	ControlPin  string `yaml:"control_pin,omitempty"`
	NodeID      string `yaml:"node_id"`
	Path        string `yaml:"node_path"`
	NodeKey     string `yaml:"node_key"`
	CollectorID string `yaml:"collector_id,omitempty"`
	// ProbePin caches the enrolment pin; each task uses the pin delivered over authenticated control TLS.
	ProbePin string `yaml:"probe_pin,omitempty"`
	// ProbePort is the observer's probe listener port as reported at enrolment,
	// so the default probe target is right without any typing.
	ProbePort string `yaml:"probe_port,omitempty"`
}

// Config is everything the client remembers between runs (client.yaml, 0600).
// It holds only what the four-step flow needs; the tunables that used to live
// here (targets, baseline, rounds, concurrency) now have defaults that suit a
// one-shot test and are still settable in client.yaml or on the command line.
type Config struct {
	Enrollment    `yaml:",inline"`
	NodeName      string `yaml:"node_name,omitempty"`
	ProviderLabel string `yaml:"provider_label,omitempty"`
	// PackDir is an optional domain library on disk; empty uses the built-in copy.
	ExternalURL     string                `yaml:"external_url,omitempty"`
	ExternalDomains []pack.ExternalDomain `yaml:"external_domains,omitempty"`
	PackDir         string                `yaml:"pack_dir,omitempty"`
	PackChoice      []string              `yaml:"pack_choice,omitempty"` // last chosen categories, remembered as the default
	Targets         []string              `yaml:"targets,omitempty"`     // observer probe addresses; defaults to the control host on 443
	Baseline        []string              `yaml:"baseline,omitempty"`
	Rounds          int                   `yaml:"rounds,omitempty"`
	Concurrency     int                   `yaml:"concurrency,omitempty"`
	TimeoutSeconds  int                   `yaml:"timeout_seconds,omitempty"`
	EnvNote         string                `yaml:"env_note,omitempty"`
	DomainsFile     string                `yaml:"domains_file,omitempty"`
	// ReportDir is where the Markdown report goes at the end of a run.
	// Empty means the working directory the client was started in.
	ReportDir string `yaml:"report_dir,omitempty"`
}

// Enrolled reports whether the config holds a usable identity.
func (c Config) Enrolled() bool { return c.Server != "" && c.Path != "" && c.NodeKey != "" }

// WithDefaults fills unset settings.
func (c Config) WithDefaults(path string) Config {
	if c.Rounds <= 0 {
		c.Rounds = 3
	}
	if c.Concurrency <= 0 {
		c.Concurrency = DefaultConcurrency
	}
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = 5
	}
	if len(c.Baseline) == 0 {
		c.Baseline = append([]string(nil), DefaultBaseline...)
	}
	if c.DomainsFile == "" {
		c.DomainsFile = filepath.Join(filepath.Dir(path), "domains.txt")
	}
	return c
}

// ProbeTargets returns the observer probe addresses to use. When none were
// set, the control host on port 443 is the natural default: it is the same
// machine the client already trusts.
func (c Config) ProbeTargets() []string {
	if len(c.Targets) > 0 {
		return c.Targets
	}
	h := HostOf(c.Server)
	if h == "" {
		return nil
	}
	port := c.ProbePort
	if port == "" {
		port = "443"
	}
	return []string{net.JoinHostPort(h, port)}
}

// HostOf extracts the host from a control URL.
func HostOf(server string) string {
	u, err := url.Parse(server)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// Timeout returns the per-probe timeout.
func (c Config) Timeout() time.Duration { return time.Duration(c.TimeoutSeconds) * time.Second }

// DefaultConfigPath is where the client config lives unless overridden.
func DefaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "sniroute", "client.yaml")
}

// ErrNoConfig means the file does not exist yet.
var ErrNoConfig = errors.New("client config not found")

// LoadConfig reads the config, refusing a file readable by group/others.
// A missing file returns ErrNoConfig together with a defaulted Config.
func LoadConfig(path string) (Config, error) {
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}.WithDefaults(path), ErrNoConfig
	}
	if err != nil {
		return Config{}, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return Config{}, errors.New(path + " is accessible by group/others; run: chmod 600 " + path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Config{}, err
	}
	return c.WithDefaults(path), nil
}

// Save writes the config atomically with mode 0600.
func (c Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadDomains reads one domain per line (blank lines and # comments ignored).
// A missing file is an empty list.
func LoadDomains(path string) ([]string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

// SaveDomains writes the list, one per line.
func SaveDomains(path string, domains []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.Join(domains, "\n")+"\n"), 0o600)
}

// ReportDirOr returns the directory the Markdown report is written to. An unset
// value means "where the client was started", which is what a user who ran the
// tool from a directory expects.
func (c Config) ReportDirOr(fallback string) string {
	if c.ReportDir != "" {
		return c.ReportDir
	}
	return fallback
}
