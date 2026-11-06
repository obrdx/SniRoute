package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nyktios/sniroute/internal/analysis"
	"github.com/nyktios/sniroute/internal/client"
	"github.com/nyktios/sniroute/internal/link"
	"github.com/nyktios/sniroute/internal/report"
	"github.com/nyktios/sniroute/internal/server"
	"github.com/nyktios/sniroute/internal/tui"
)

const regKeyEnv = "SNIROUTE_REG_LINK"

func runClient(args []string) error {
	if len(args) == 0 {
		return clientMenu(client.DefaultConfigPath())
	}
	if strings.HasPrefix(args[0], "-") {
		args = append([]string{"menu"}, args...)
	}
	switch args[0] {
	case "help":
		return runClient([]string{"menu", "-h"})
	case "menu":
		fs := flag.NewFlagSet("client menu", flag.ContinueOnError)
		cfgPath := fs.String("config", client.DefaultConfigPath(), "client config file")
		fs.Usage = func() {
			fmt.Fprintln(fs.Output(), "用法：sniroute client [-config path] 或 sniroute client menu [-config path]")
			fmt.Fprintln(fs.Output(), "子命令：enroll, probe, reports；使用 <子命令> -h 查看参数。")
			fs.PrintDefaults()
		}
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("菜单不接受位置参数：%s", strings.Join(fs.Args(), " "))
		}
		return clientMenu(*cfgPath)
	case "enroll":
		return clientEnroll(args[1:])
	case "probe":
		return clientProbe(args[1:])
	case "reports":
		return clientReports(args[1:])
	}
	return fmt.Errorf("unknown client command %q (want menu, enroll, probe or reports)", args[0])
}

// joinLink enrols from a single link string (the same one the menu pastes),
// which is the supported non-interactive path.
func joinLink(ctx context.Context, cfg client.Config, raw, name, label string) (client.Config, error) {
	l, err := link.Parse(raw)
	if err != nil {
		return cfg, err
	}
	if l.Token == "" {
		return cfg, errors.New("the link carries no registration token; generate a new one in the server menu (1)")
	}
	if name == "" {
		name = l.Name
	}
	if name == "" {
		if h, err := os.Hostname(); err == nil {
			name = h
		}
	}
	if label == "" {
		label = l.Label
	}
	l.Label = label
	return enrollLink(ctx, cfg, l, name)
}

func clientEnroll(args []string) error {
	fs := flag.NewFlagSet("client enroll", flag.ContinueOnError)
	var (
		join    = fs.String("link", "", "registration link from the server menu (or $"+regKeyEnv+")")
		srv     = fs.String("server", "", "control service URL, when registering by hand instead of a link")
		pin     = fs.String("control-pin", "", "SHA-256 fingerprint of the control certificate (needed for self-signed)")
		regKey  = fs.String("reg-token", "", "one-time registration token (or use -link)")
		label   = fs.String("label", "", "provider label of the network under test")
		name    = fs.String("name", "", "node name (default: the one in the link, else the host name)")
		cfgPath = fs.String("config", client.DefaultConfigPath(), "client config file (mode 0600)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *join == "" {
		*join = os.Getenv(regKeyEnv)
	}
	cfg, err := client.LoadConfig(*cfgPath)
	if err != nil && !errors.Is(err, client.ErrNoConfig) {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch {
	case *join != "":
		cfg, err = joinLink(ctx, cfg, *join, *name, *label)
	case *srv != "" && *regKey != "":
		l := link.Link{Server: *srv, Pin: *pin, Token: *regKey, Name: *name, Label: *label}
		cfg, err = enrollLink(ctx, cfg, l, *name)
	default:
		return errors.New("pass -link with the registration link from the server menu (or -server with -reg-token)")
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfg.NodeName) == "" {
		return errors.New("a node name is required")
	}
	if err := cfg.Save(*cfgPath); err != nil {
		return err
	}
	fmt.Printf("enrolled as %s (collector %s)\nconfig saved to %s\n", cfg.NodeID, cfg.CollectorID, *cfgPath)
	return nil
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func clientProbe(args []string) error {
	fs := flag.NewFlagSet("client probe", flag.ContinueOnError)
	var targets, snis, baseline multiFlag
	var (
		sniFile     = fs.String("sni-file", "", "file with one SNI per line (default: the domain list saved by the menu)")
		recordSplit = fs.Bool("tls-record-split", false, "experimental: split the first ClientHello into TLS records inside SNI; results do not prove the ordinary connection's egress")
		showFullIP  = fs.Bool("show-full-ip", false, "show complete egress IPs in terminal and exports (default: masked)")
		noBase      = fs.Bool("no-baseline", false, "skip the baseline")
		rounds      = fs.Int("rounds", 0, "independent connections per domain (default: config, else 3)")
		seed        = fs.Uint64("seed", 0, "shuffle seed (default: random; recorded in the task)")
		conc        = fs.Int("concurrency", 0, "parallel probes (default: config, else 6)")
		timeout     = fs.Duration("timeout", 0, "per-probe timeout (default: config, else 5s)")
		envNote     = fs.String("env-note", "", "note about VPN/TUN/proxy on this machine, stored with the task")
		exportDir   = fs.String("export", "", "also write report.txt/json/CSV into this directory (the .md goes to the working directory)")
		cfgPath     = fs.String("config", client.DefaultConfigPath(), "client config written by `client enroll`")
	)
	fs.Var(&targets, "target", "observer ip:port to probe (repeatable, e.g. one IPv4 and one IPv6; each is compared separately)")
	fs.Var(&snis, "sni", "SNI to test (repeatable)")
	fs.Var(&baseline, "baseline", "neutral baseline SNI (repeatable; default from config)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *recordSplit && len(snis) == 0 && *sniFile == "" {
		return errors.New("分片实验请用 -sni 或 -sni-file 显式选择域名，避免直接测试整个默认清单")
	}
	cfg, err := client.LoadConfig(*cfgPath)
	if err != nil {
		if errors.Is(err, client.ErrNoConfig) {
			return errors.New("not enrolled yet: run `sniroute client enroll` (or the client menu) first")
		}
		return err
	}
	if !cfg.Enrolled() {
		return errors.New("config is not enrolled; run `sniroute client enroll`")
	}

	domains := []string(snis)
	if len(domains) == 0 {
		path := cfg.DomainsFile
		if *sniFile != "" {
			path = *sniFile
		}
		if domains, err = client.LoadDomains(path); err != nil {
			return err
		}
		if len(domains) == 0 {
			// No -sni and no domain file: use the selection the menu remembers,
			// so `sniroute client probe` is a complete one-line test.
			lib, _, lerr := loadLibrary(tui.New(os.Stdin, os.Stdout), cfg)
			if lerr != nil {
				return lerr
			}
			choice := cfg.PackChoice
			if len(choice) == 0 {
				choice = []string{"quick"}
			}
			if domains, _, err = lib.Select(choice); err != nil {
				return err
			}
		}
	}
	domains, rejected := client.CleanDomains(domains)
	for _, r := range rejected {
		fmt.Fprintf(os.Stderr, "ignored invalid domain %q\n", r)
	}
	selectedLib, _, lerr := loadLibrary(tui.New(os.Stdin, os.Stdout), cfg)
	if lerr != nil {
		return lerr
	}
	tg := []string(targets)
	if len(tg) == 0 {
		tg = cfg.ProbeTargets()
	}
	base := []string(baseline)
	if len(base) == 0 {
		base = cfg.Baseline
	}
	if *noBase {
		base = nil
	}
	opt := client.RunOptions{
		Plan:        client.PlanSpec{ShowFullIP: showFullIP, Targets: tg, Domains: domains, Categories: selectedLib.ReportCategories(domains), Baseline: base, Rounds: firstNonZero(*rounds, cfg.Rounds), Seed: *seed},
		Concurrency: firstNonZero(*conc, cfg.Concurrency), Timeout: cfg.Timeout(),
		ProviderLabel: cfg.ProviderLabel, EnvNote: firstNonEmpty(*envNote, cfg.EnvNote), Version: version,
		TLSRecordSplit: *recordSplit,
	}
	if *timeout > 0 {
		opt.Timeout = *timeout
	}

	ui := tui.New(os.Stdin, os.Stdout)
	sess, err := openSession(*cfgPath, cfg)
	if err != nil {
		return err
	}
	defer sess.close()
	sess.recover(ui)
	view, interrupted, err := runTask(ui, sess, opt)
	if err != nil {
		return err
	}
	rep := report.Build(view, time.Now())
	report.WriteResults(ui.Writer(), rep)
	if interrupted {
		ui.Println("\n测试已中断：未执行的尝试不计为网络失败；任务已在观测端标记为中断，以上为部分结果。")
	}
	if mdPath, err := report.ExportMarkdown(cfg.ReportDirOr(""), rep); err != nil {
		fmt.Fprintf(os.Stderr, "report markdown: %v\n", err)
	} else {
		ui.Println("\nMarkdown 报告：", mdPath)
	}
	if *exportDir != "" {
		files, err := report.Export(*exportDir, rep)
		if err != nil {
			return err
		}
		ui.Println("\n已导出：")
		for _, f := range files {
			ui.Println("  " + f)
		}
	}
	return nil
}

func firstNonZero(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// runTask executes a task with live progress. The first Ctrl+C stops new
// attempts, tells the server the task was cancelled and collects what exists;
// a second one kills the process. Everything the client reports goes through
// the local outbox, so a dropped control connection loses nothing.
func runTask(ui *tui.UI, sess *clientSession, opt client.RunOptions) (server.TaskView, bool, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { // after the first signal restore default behaviour: the next one kills us
		<-ctx.Done()
		stop()
	}()

	if opt.OnProbePinRefresh == nil {
		opt.OnProbePinRefresh = func() {
			ui.Println("探测公钥指纹与注册时的缓存不同：本次使用已验证控制连接下发的任务指纹；探测端仍须通过公钥校验后才会发送凭证。")
		}
	}
	if opt.OnASN == nil {
		opt.OnASN = func(enabled bool, v *server.ASNView, err error) {
			switch {
			case err != nil:
				ui.Printf("[出口网络归属] 查询未完成：%s（出口 IP 不受影响，可稍后在报告菜单里刷新）\n", shorten(err.Error(), 60))
			case !enabled:
				ui.Println("[出口网络归属] 观测端未启用查询")
			case v == nil:
				ui.Println("[出口网络归属] 没有可查询的出口 IP")
			default:
				ui.Printf("[出口网络归属] 来源 %s，%d 个出口 IP\n", v.Source, len(v.Items))
			}
		}
	}
	if opt.TLSRecordSplit {
		ui.Styled("warning", report.FragmentExperimentNotice)
	}
	ui.Println("开始测试…（Ctrl+C 停止并保留已有结果，再按一次强制退出）")
	var identityNotice sync.Once
	view, err := sess.runner.Run(ctx, opt, func(rep client.AttemptReport) {
		kind := "域名"
		if rep.Attempt.Kind == "baseline" {
			kind = "基线"
		}
		line := fmt.Sprintf("[%d/%d] %s %-28s 轮%d  %s", rep.Done, rep.Total, kind, rep.Attempt.SNI, rep.Attempt.Round,
			rep.Result.Outcome)
		if rep.Result.Error != "" {
			line += "  (" + rep.Result.Stage + ": " + shorten(rep.Result.Error, 70) + ")"
		}
		if rep.EventErr != nil {
			line += "  [暂未上报，已存本地]"
		}
		role := "warning"
		if rep.Result.Outcome == client.OutcomeReceipt && rep.EventErr == nil {
			role = "success"
		}
		if rep.Result.Outcome == client.OutcomeIdentityMismatch {
			role = "danger"
		}
		ui.Styled(role, line)
		if rep.Result.Outcome == client.OutcomeIdentityMismatch {
			identityNotice.Do(func() {
				ui.Styled("warning", analysis.EndpointIdentityNotice)
			})
		}
	})
	if err != nil {
		if pending := sess.pendingCount(); pending > 0 {
			err = fmt.Errorf("%w（控制连接不可用：%d 条记录已保存在本地，连接恢复后下次进入客户端时自动补交）", err, pending)
		}
	}
	return view, ctx.Err() != nil, err
}
