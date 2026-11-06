package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nyktios/sniroute/internal/auth"
	"github.com/nyktios/sniroute/internal/server"
	"github.com/nyktios/sniroute/internal/store"
)

const adminKeyEnv = "SNIROUTE_ADMIN_KEY"

// runServer dispatches `sniroute server ...`.
func runServer(args []string) error {
	if len(args) == 0 {
		return serverMenu(server.DefaultConfigPath())
	}
	if strings.HasPrefix(args[0], "-") {
		args = append([]string{"menu"}, args...)
	}
	switch args[0] {
	case "help":
		return runServer([]string{"menu", "-h"})
	case "menu":
		fs := flag.NewFlagSet("server menu", flag.ContinueOnError)
		cfgPath := fs.String("config", server.DefaultConfigPath(), "server config file")
		fs.Usage = func() {
			fmt.Fprintln(fs.Output(), "用法：sniroute server [-config path] 或 sniroute server menu [-config path]")
			fmt.Fprintln(fs.Output(), "子命令：run, start, stop, restart, status；使用 <子命令> -h 查看参数。")
			fs.PrintDefaults()
		}
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("菜单不接受位置参数：%s", strings.Join(fs.Args(), " "))
		}
		return serverMenu(*cfgPath)
	case "run":
		return serverRun(args[1:])
	case "reports":
		return errors.New("观测端不再提供历史报告，请在客户端查看本地报告")
	case "start", "stop", "restart", "status":
		fs := flag.NewFlagSet("server "+args[0], flag.ContinueOnError)
		cfgPath := fs.String("config", server.DefaultConfigPath(), "server config file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return serverDaemonCmd(args[0], *cfgPath)
	}
	return fmt.Errorf("unknown server command %q (want run, start, stop, restart, status or menu)", args[0])
}

func serverDaemonCmd(cmd, cfgPath string) error {
	cfg, err := server.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	if unit := systemdUnit(cfgPath); unit != "" {
		return controlSystemd(cmd, unit)
	}
	switch cmd {
	case "status":
		pid, err := server.DaemonStatus(cfg.DataDir)
		if err != nil {
			return err
		}
		if pid == 0 {
			fmt.Println("stopped")
		} else {
			fmt.Printf("running (pid %d)\n", pid)
		}
	case "stop":
		return server.StopDaemon(cfg.DataDir)
	case "start", "restart":
		if cmd == "restart" {
			if pid, _ := server.DaemonStatus(cfg.DataDir); pid != 0 {
				if err := server.StopDaemon(cfg.DataDir); err != nil {
					return err
				}
			}
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		pid, err := server.StartDaemon(exe, cfgPath, cfg.DataDir)
		if err != nil {
			return err
		}
		fmt.Printf("started (pid %d), log: %s\n", pid, server.LogPath(cfg.DataDir))
	}
	return nil
}

// loadAdminKey resolves the admin key: $SNIROUTE_ADMIN_KEY, then a key file,
// then the config file. Command-line values are deliberately unsupported
// (visible in `ps`). Key files must not be readable by group/others.
func loadAdminKey(file, fromConfig string) (string, error) {
	env := os.Getenv(adminKeyEnv)
	switch {
	case env != "" && file != "":
		return "", fmt.Errorf("set either $%s or -admin-key-file, not both", adminKeyEnv)
	case env != "":
		return strings.TrimSpace(env), nil
	case file != "":
		st, err := os.Stat(file)
		if err != nil {
			return "", err
		}
		if st.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("%s is accessible by group/others; run: chmod 600 %s", file, file)
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	case fromConfig != "":
		return fromConfig, nil
	}
	return "", fmt.Errorf("admin key required: run the server menu to initialise, set $%s, or use -admin-key-file (generate one with `sniroute genkey`)", adminKeyEnv)
}

// serverRun is the foreground service: control API (HTTPS) + probe listener.
// Config-file values are defaults; flags override them.
func serverRun(args []string) error {
	// Find -config first so its values can seed the other flags' defaults.
	cfgPath := server.DefaultConfigPath()
	for i, a := range args {
		if (a == "-config" || a == "--config") && i+1 < len(args) {
			cfgPath = args[i+1]
		} else if v, ok := strings.CutPrefix(a, "-config="); ok {
			cfgPath = v
		}
	}
	cfg, err := server.LoadConfig(cfgPath)
	if err != nil && !errors.Is(err, server.ErrNoConfig) {
		return err
	}

	fs := flag.NewFlagSet("server run", flag.ContinueOnError)
	var (
		probeCfg   server.ProbeConfig
		tasksCfg   server.TasksConfig
		_          = fs.String("config", cfgPath, "server config file (flags below override it)")
		controlAdr = fs.String("control-addr", cfg.ControlAddr, "control service (HTTPS) listen address")
		certFile   = fs.String("tls-cert", cfg.TLSCert, "TLS certificate file for the control service")
		keyFile    = fs.String("tls-key", cfg.TLSKey, "TLS private key file for the control service")
		selfSigned = fs.Bool("tls-self-signed", cfg.TLSSelfSigned, "use a persistent self-signed control certificate (dev/private use)")
		tlsHosts   = fs.String("tls-hosts", strings.Join(cfg.TLSHosts, ","), "extra comma-separated DNS names/IPs for the self-signed certificate")
		adminFile  = fs.String("admin-key-file", "", "file containing the admin key (mode 0600)")
		dataDir    = fs.String("data-dir", cfg.DataDir, "directory for the database and generated certificates")
		collector  = fs.String("collector-id", cfg.CollectorID, "identifier of this observer")
	)
	fs.StringVar(&probeCfg.Addr, "probe-addr", cfg.ProbeAddr, "SNI probe listen address")
	fs.DurationVar(&probeCfg.ReadTimeout, "read-timeout", 5*time.Second, "time allowed to deliver a ClientHello")
	fs.IntVar(&probeCfg.MaxHelloBytes, "max-hello", 16*1024, "max ClientHello body size in bytes")
	fs.IntVar(&probeCfg.MaxConnsPerIP, "max-per-ip", 16, "max concurrent probe connections per source IP")
	fs.IntVar(&probeCfg.MaxConns, "max-conns", 1024, "max concurrent probe connections")
	fs.DurationVar(&tasksCfg.TaskTTL, "task-ttl", time.Duration(cfg.TaskTTLSeconds)*time.Second, "default lifetime of a task's attempt credentials")
	fs.IntVar(&tasksCfg.MaxActivePerNode, "max-tasks-per-node", cfg.MaxTasksPerNode, "max unfinished tasks per node")
	fs.IntVar(&tasksCfg.MaxActive, "max-tasks", cfg.MaxTasks, "max unfinished tasks overall")
	if err := fs.Parse(args); err != nil {
		return err
	}

	adminKey, err := loadAdminKey(*adminFile, cfg.AdminKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(*dataDir, "sniroute.db"))
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()
	reg, err := auth.NewRegistry(adminKey, st)
	if err != nil {
		return fmt.Errorf("admin key must be at least %d characters (generate one with `sniroute genkey`)", auth.MinAdminKeyLen)
	}

	if _, err := st.PruneOfflineNodes(time.Now()); err != nil {
		return fmt.Errorf("清理离线客户端数据失败：%w", err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Control service certificate.
	var ctrlCert tls.Certificate
	switch {
	case *selfSigned && (*certFile != "" || *keyFile != ""):
		return errors.New("use either -tls-self-signed or -tls-cert/-tls-key")
	case *selfSigned:
		ctrlCert, err = server.LoadOrCreateCert(filepath.Join(*dataDir, "control.pem"), "SniRoute control",
			strings.Split(*tlsHosts, ","), 365*24*time.Hour)
		if err != nil {
			return err
		}
		leaf, _ := server.LeafOf(ctrlCert)
		log.Warn("using a self-signed control certificate; give clients this pin", "control_pin", server.CertPin(leaf.Raw))
	case *certFile != "" && *keyFile != "":
		if ctrlCert, err = tls.LoadX509KeyPair(*certFile, *keyFile); err != nil {
			return err
		}
	default:
		return errors.New("control service needs TLS: set tls_cert/tls_key (or tls_self_signed) in the config, or pass -tls-cert and -tls-key, or -tls-self-signed")
	}

	// Probe endpoint certificate: persistent, never validated for the SNI;
	// clients pin its public key (delivered over the control channel).
	probeCert, err := server.LoadOrCreateCert(filepath.Join(*dataDir, "probe.pem"), "SniRoute probe", nil, 10*365*24*time.Hour)
	if err != nil {
		return err
	}
	probeLeaf, err := server.LeafOf(probeCert)
	if err != nil {
		return err
	}
	probePin := server.SPKIPin(probeLeaf)
	log.Info("probe endpoint key", "probe_pin", probePin)

	tasks := server.NewTasks(tasksCfg, reg, st, *collector)
	if tasks.ASN = server.NewASNService(cfg, st); tasks.ASN != nil {
		log.Info("egress-network lookups enabled", "source", tasks.ASN.Source(), "cache", tasks.ASN.Caching())
	} else {
		log.Info("egress-network lookups disabled")
	}
	ps := server.NewProbeServer(probeCfg, probeCert, server.ProbeHooks{
		OnEvent: func(ev server.Event) {
			// Unauthenticated noise: kept in a bounded ring for ClientHello
			// matching and logged at debug only; never attributed on its own.
			tasks.NoteHello(ev)
			log.Debug("probe event", "src", ev.Remote.Addr().String(), "status", string(ev.Status), "sni", ev.SNI, "err", ev.Err)
		},
		OnReceipt: func(rr server.ReceiptRequest, o server.Observed) (*server.Receipt, server.Outcome, error) {
			rec, out, err := tasks.HandleReceipt(rr, o)
			if err != nil {
				log.Error("receipt", "err", err)
			} else {
				log.Debug("receipt", "src", o.Remote.Addr().String(), "sni", o.SNI, "outcome", string(out)) // never the credential
			}
			return rec, out, err
		},
	})
	if err := ps.Listen(); err != nil {
		return fmt.Errorf("probe listen: %w", err)
	}

	hs := &http.Server{
		Addr:              *controlAdr,
		Handler:           server.NewControl(reg, tasks, probePin, log).WithProbeAddr(ps.Addr().String()).Handler(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{ctrlCert}},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var retentionWG sync.WaitGroup
	retentionWG.Add(1)
	defer retentionWG.Wait()
	defer stop()
	go func() {
		defer retentionWG.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if _, err := tasks.Cleanup(now); err != nil {
					log.Error("清理离线客户端数据失败", "err", err)
				}
			}
		}
	}()

	errc := make(chan error, 2)
	go func() { errc <- ps.Serve(ctx) }()
	go func() {
		log.Info("control service starting", "addr", *controlAdr)
		if err := hs.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("control: %w", err)
			return
		}
		errc <- nil
	}()
	log.Info("probe listener started", "addr", ps.Addr().String())

	var first error
	pending := 2
	select {
	case first = <-errc:
		pending--
		stop()
	case <-ctx.Done():
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hs.Shutdown(shutCtx)
	for ; pending > 0; pending-- {
		<-errc
	}
	log.Info("stopped", "probe_rejected", ps.Rejected())
	return first
}
