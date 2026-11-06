package main

import (
	"errors"
	"flag"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nyktios/sniroute/internal/client"
)

func TestRoleMenuFlagsAndHelp(t *testing.T) {
	for name, run := range map[string]func([]string) error{"client": runClient, "server": runServer} {
		t.Run(name, func(t *testing.T) {
			for _, args := range [][]string{{"-h"}, {"--help"}, {"help"}, {"-config", filepath.Join(t.TempDir(), "custom.yaml"), "-h"}} {
				if err := run(args); !errors.Is(err, flag.ErrHelp) {
					t.Fatalf("%v: %v", args, err)
				}
			}
			// Both menu forms parse the custom config flag and reject stray arguments
			// before entering an interactive menu or touching the config.
			for _, args := range [][]string{{"-config", "custom.yaml", "stray"}, {"menu", "-config", "custom.yaml", "stray"}} {
				if err := run(args); err == nil || !strings.Contains(err.Error(), "菜单不接受位置参数") {
					t.Fatalf("%v: %v", args, err)
				}
			}
		})
	}
}

func TestReportDirectorySharedByHistoryAndRun(t *testing.T) {
	for _, dir := range []string{"", "relative-reports", t.TempDir()} {
		cfg := client.Config{ReportDir: dir}
		s := clientSession{cfgPath: filepath.Join(t.TempDir(), "client.yaml"), cfg: cfg}
		got := s.reportsDir()
		if got != reportDir(cfg) || !filepath.IsAbs(got) {
			t.Fatalf("report directory: %q", got)
		}
	}
}

func TestFragmentExperimentNeedsExplicitDomainSelection(t *testing.T) {
	if err := runClient([]string{"probe", "-tls-record-split"}); err == nil || !strings.Contains(err.Error(), "显式选择域名") {
		t.Fatalf("fragmentation unexpectedly uses the default library: %v", err)
	}
	if err := runClient([]string{"probe", "-sni", "chatgpt.com", "-tls-record-split", "-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("fragmentation flag is not accepted: %v", err)
	}
}
