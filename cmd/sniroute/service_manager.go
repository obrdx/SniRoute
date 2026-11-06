package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nyktios/sniroute/internal/server"
)

// The installed launcher selects systemd only for its own configuration.
// Standalone binaries and explicitly selected other configs retain pid mode.
func systemdUnit(cfgPath string) string {
	unit := os.Getenv("SNIROUTE_SYSTEMD_UNIT")
	managed := os.Getenv("SNIROUTE_SYSTEMD_CONFIG")
	if unit != "sniroute.service" || managed == "" {
		return ""
	}
	a, err := filepath.Abs(cfgPath)
	if err != nil {
		return ""
	}
	b, err := filepath.Abs(managed)
	if err != nil || a != b {
		return ""
	}
	return unit
}

func serverMenuPID(cfgPath, dataDir string) (int, error) {
	unit := systemdUnit(cfgPath)
	if unit == "" {
		return server.DaemonStatus(dataDir)
	}
	out, err := exec.Command("systemctl", "show", "--property=MainPID", "--value", unit).Output()
	if err != nil {
		return 0, fmt.Errorf("读取 systemd 服务状态失败：%w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid < 0 {
		return 0, fmt.Errorf("systemd 返回无效的 MainPID")
	}
	return pid, nil
}

func controlSystemd(action, unit string) error {
	cmd := exec.Command("systemctl", action, unit)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemd %s 失败，请查看 sniroute logs：%w", action, err)
	}
	return nil
}
