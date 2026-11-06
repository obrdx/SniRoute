package server

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/nyktios/sniroute/internal/asn"
	"github.com/nyktios/sniroute/internal/store"
)

// Config is the server's persistent configuration (server.yaml). It holds
// the admin key, so the file must be private (0600).
type Config struct {
	ProbeAddr       string   `yaml:"probe_addr"`
	ControlAddr     string   `yaml:"control_addr"`
	DataDir         string   `yaml:"data_dir"`
	CollectorID     string   `yaml:"collector_id"`
	AdminKey        string   `yaml:"admin_key,omitempty"`
	TLSSelfSigned   bool     `yaml:"tls_self_signed,omitempty"`
	TLSCert         string   `yaml:"tls_cert,omitempty"`
	TLSKey          string   `yaml:"tls_key,omitempty"`
	TLSHosts        []string `yaml:"tls_hosts,omitempty"`
	TaskTTLSeconds  int      `yaml:"task_ttl_seconds,omitempty"`
	MaxTasksPerNode int      `yaml:"max_tasks_per_node,omitempty"`
	MaxTasks        int      `yaml:"max_tasks,omitempty"`

	// Egress-network lookups (run on the observer). Source is "ripestat"
	// (default), "cymru" or "none". The IPs sent are the egress addresses seen
	// by the observer; private addresses are never sent. Neither source needs
	// an API key; ASNSourceApp only identifies this tool to RIPEstat.
	ASNSource     string `yaml:"asn_source,omitempty"`
	ASNSourceApp  string `yaml:"asn_sourceapp,omitempty"`
	ASNNoCache    bool   `yaml:"asn_no_cache,omitempty"`
	ASNCacheHours int    `yaml:"asn_cache_hours,omitempty"`
	// IPinfo is primary; GeoJS supplies missing fields and alternative locations.
	// Use [none] to disable geolocation; asn_source: none disables all lookups.
	GeoSources []string `yaml:"geo_sources,omitempty"`
}

// ErrNoConfig means the config file does not exist.
var ErrNoConfig = errors.New("server config not found")

// WithDefaults fills unset fields. Relative data_dir is resolved against the
// config file's directory so the service works from any working directory.
func (c Config) WithDefaults(path string) Config {
	if c.ProbeAddr == "" {
		c.ProbeAddr = ":443"
	}
	if c.ControlAddr == "" {
		c.ControlAddr = ":8443"
	}
	if c.CollectorID == "" {
		c.CollectorID = "collector-1"
	}
	if c.DataDir == "" {
		c.DataDir = "data"
	}
	if !filepath.IsAbs(c.DataDir) {
		c.DataDir = filepath.Join(filepath.Dir(path), c.DataDir)
	}
	return c
}

// DefaultConfigPath is where the server config lives unless overridden.
func DefaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "sniroute", "server.yaml")
}

// LoadConfig reads the config, refusing a file readable by group/others. A
// missing file returns ErrNoConfig with a defaulted Config.
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

// ASNSources are the accepted values of asn_source.
var ASNSources = []string{"ripestat", "cymru", "none"}

// NewASNService builds the lookup service described by the config, or nil
// when lookups are disabled.
func NewASNService(c Config, st *store.Store) *asn.Service {
	var p asn.Provider
	switch c.ASNSource {
	case "", "ripestat":
		app := c.ASNSourceApp
		if app == "" {
			app = "sniroute"
		}
		p = asn.NewRIPEstat(app)
	case "cymru":
		p = asn.NewCymru()
	default:
		return nil
	}
	ttl := time.Duration(c.ASNCacheHours) * time.Hour
	cache := asn.NewStoreCache(st)
	config := asn.Config{TTL: ttl, NoCache: c.ASNNoCache}
	svc := asn.NewService(p, cache, config)
	sources := c.GeoSources
	if len(sources) == 0 {
		sources = []string{"ipinfo", "geojs"}
	}
	// Preference is fixed, regardless of config ordering.
	enabled := map[string]bool{}
	for _, source := range sources {
		enabled[source] = true
	}
	if enabled["none"] {
		return svc
	}
	config.Concurrency = 2
	var locations []*asn.Service
	if enabled["ipinfo"] {
		locations = append(locations, asn.NewService(asn.NewIPinfo(), cache, config))
	}
	if enabled["geojs"] {
		locations = append(locations, asn.NewService(asn.NewGeoJS(), cache, config))
	}
	return svc.WithLocations(locations...)
}
