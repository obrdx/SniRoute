package server

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The service runs as a detached process so that closing the management
// menu (or the SSH session) does not stop it. State is a pid file plus a log
// file in the data directory.

func pidPath(dataDir string) string { return filepath.Join(dataDir, "server.pid") }

// LogPath is the service log file.
func LogPath(dataDir string) string { return filepath.Join(dataDir, "server.log") }

// DaemonStatus returns the pid of the running service, or 0.
func DaemonStatus(dataDir string) (int, error) {
	b, err := os.ReadFile(pidPath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, nil
	}
	if err := syscall.Kill(pid, 0); err != nil && !errors.Is(err, syscall.EPERM) {
		os.Remove(pidPath(dataDir)) // stale
		return 0, nil
	}
	return pid, nil
}

// StartDaemon launches `exe server run -config cfgPath` detached, logging to
// the data directory. It waits briefly and reports an early exit.
func StartDaemon(exe, cfgPath, dataDir string) (int, error) {
	if pid, err := DaemonStatus(dataDir); err != nil {
		return 0, err
	} else if pid != 0 {
		return pid, fmt.Errorf("already running (pid %d)", pid)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return 0, err
	}
	logf, err := os.OpenFile(LogPath(dataDir), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, err
	}
	defer logf.Close()

	cmd := exec.Command(exe, "server", "run", "-config", cfgPath)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	if err := os.WriteFile(pidPath(dataDir), []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		return pid, err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case <-exited:
		os.Remove(pidPath(dataDir))
		return 0, errors.New("service exited right after starting; see the log")
	case <-time.After(1500 * time.Millisecond):
		return pid, nil
	}
}

// StopDaemon asks the service to stop (SIGTERM) and waits for it.
func StopDaemon(dataDir string) error {
	pid, err := DaemonStatus(dataDir)
	if err != nil {
		return err
	}
	if pid == 0 {
		return errors.New("not running")
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return err
	}
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		if err := syscall.Kill(pid, 0); err != nil && !errors.Is(err, syscall.EPERM) {
			os.Remove(pidPath(dataDir))
			return nil
		}
	}
	return fmt.Errorf("pid %d did not exit within 10s", pid)
}

// TailLog returns the last n lines of the service log.
func TailLog(dataDir string, n int) ([]string, error) {
	b, err := os.ReadFile(LogPath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}
