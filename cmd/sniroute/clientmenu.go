package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nyktios/sniroute/internal/client"
	"github.com/nyktios/sniroute/internal/link"
	"github.com/nyktios/sniroute/internal/pack"
	"github.com/nyktios/sniroute/internal/report"
	"github.com/nyktios/sniroute/internal/tui"
)

// clientMenu is the four-step flow the tool is meant to be used with:
//
//  1. paste the one-line link the observer gave you
//  2. pick what to test
//  3. let it run
//  4. read the result, which is also written to a Markdown file
//
// Everything else (history, domain lists, credentials) exists but stays out of
// the way of those four steps.
func clientMenu(cfgPath string) error {
	ui := tui.New(os.Stdin, os.Stdout)
	cfg, err := client.LoadConfig(cfgPath)
	if err != nil && !errors.Is(err, client.ErrNoConfig) {
		return err
	}
	if !cfg.Enrolled() {
		ui.Println()
		ui.Println("第一次使用：把你的注册链接粘贴进来。")
		ui.Println("（在观测端菜单选 1「生成注册链接」，把整行发过来即可。）")
		if cfg, err = joinFlow(ui, cfgPath, cfg); err != nil {
			return quitOnCancel(err)
		}
		if !cfg.Enrolled() {
			return nil
		}
	}

	sess, err := openSession(cfgPath, cfg)
	if err != nil {
		return err
	}
	defer sess.close()
	sess.recover(ui)

	lib, libSource, libErr := loadLibrary(ui, cfg)
	if libErr != nil {
		ui.Printf("读取域名库失败：%v\n", libErr)
	}

	for {
		choice := cfg.PackChoice
		if len(choice) == 0 {
			choice = []string{"quick"}
		}
		n, _, _ := lib.Select(choice)
		key, err := ui.Menu("SniRoute 客户端", []string{
			"https://github.com/obrdx/SniRoute",
			fmt.Sprintf("节点：%s    观测端：%s", cfg.NodeName, cfg.Server),
			fmt.Sprintf("上次选择：%s · %d 个域名", describeChoice(lib, choice), len(n)),
		}, []tui.Item{
			tui.Opt("1", "开始测试"),
			tui.Opt("2", "选择要测试的域名"),
			tui.Opt("3", "历史报告"),
			tui.Opt("4", "设置"),
			tui.Opt("0", "退出"),
		})
		if err != nil {
			return quitOnCancel(err)
		}
		switch key {
		case "1":
			err = clientStartTest(ui, sess, lib, libSource)
		case "2":
			if cfg, err = choosePack(ui, cfgPath, cfg, lib); err == nil {
				err = sess.setConfig(cfg)
				if err == nil {
					lib, libSource, err = loadLibrary(ui, cfg)
				}
			}
		case "3":
			err = clientHistory(ui, sess)
		case "4":
			if cfg, err = clientSettings(ui, cfgPath, cfg, lib); err == nil {
				err = sess.setConfig(cfg)
				if err == nil {
					lib, libSource, err = loadLibrary(ui, cfg)
				}
			}
		case "0":
			return nil
		}
		if err != nil {
			if errors.Is(err, tui.ErrCancel) {
				return nil
			}
			ui.Printf("出错：%v\n", err)
		}
	}
}

// joinFlow turns one pasted line into an enrolled node. A link carries the
// server, the certificate pin and a one-time token, so this is the only step
// that needs anything from the observer.
func joinFlow(ui *tui.UI, cfgPath string, cfg client.Config) (client.Config, error) {
	raw, err := ui.Prompt("注册链接（或直接输入 https://主机:端口）", cfg.Server)
	if err != nil {
		return cfg, err
	}
	if strings.TrimSpace(raw) == "" {
		return cfg, nil
	}
	l, err := link.Parse(raw)
	if err != nil {
		ui.Printf("链接格式不对：%v\n", err)
		return cfg, nil
	}
	if l.Token == "" {
		// No token: either the node is already registered (only the address is
		// being updated) or the operator pasted a bare address.
		if !cfg.Enrolled() {
			ui.Println("这个链接里没有注册凭证。请让观测端重新生成一个注册链接（菜单 1）。")
			return cfg, nil
		}
		cfg.Enrollment.Server = l.Server
		if l.Pin != "" {
			cfg.Enrollment.ControlPin = l.Pin
		}
		if err := cfg.Save(cfgPath); err != nil {
			return cfg, err
		}
		ui.Printf("观测端地址已更新为 %s。\n", l.Server)
		return cfg, nil
	}
	name := l.Name
	if name == "" {
		name = localHostname()
	}
	if name, err = ui.Prompt("节点名称", name); err != nil {
		return cfg, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	next, err := enrollLink(ctx, cfg, l, name)
	if err != nil {
		ui.Printf("注册失败：%v\n", err)
		return cfg, nil
	}
	if err := next.Save(cfgPath); err != nil {
		return cfg, err
	}
	ui.Printf("注册成功：%s。\n", next.NodeName)
	return next, nil
}

// enrollLink registers with the observer. The certificate pin is known up
// front when the link carries one; otherwise it is fetched from /api/health
// over a connection that was already validated by the system roots.
func enrollLink(ctx context.Context, cfg client.Config, l link.Link, name string) (client.Config, error) {
	pin := l.Pin
	if pin == "" {
		// Discovery needs a verified connection, so it runs without a pin. If
		// the certificate is self-signed this fails here with a clear message
		// rather than silently trusting it.
		probeCC, err := client.NewControlClient(l.Server, "")
		if err != nil {
			return cfg, err
		}
		h, err := probeCC.Discover(ctx)
		if err != nil {
			return cfg, fmt.Errorf("%w\n自签名证书的控制接口需要链接里带指纹；请让观测端生成完整的注册链接", err)
		}
		pin = h.ProbePin
	}
	cc, err := client.NewControlClient(l.Server, pin)
	if err != nil {
		return cfg, err
	}
	r, err := cc.Register(ctx, l.Token, name, l.Label)
	if err != nil {
		if api, ok := err.(*client.APIError); ok && api.Status == 401 {
			return cfg, errors.New("注册凭证无效或已被使用：请让观测端重新生成一个注册链接")
		}
		return cfg, err
	}
	out := cfg
	out.Enrollment = client.Enrollment{
		Server: l.Server, ControlPin: pin, NodeID: r.NodeID, Path: r.Path, NodeKey: r.NodeKey,
		CollectorID: r.CollectorID, ProbePin: r.ProbePin, ProbePort: r.ProbePort,
	}
	out.NodeName = name
	if l.Label != "" {
		out.ProviderLabel = l.Label
	}
	return out, nil
}

// loadLibrary prefers a directory on disk (so the lists can be edited without
// rebuilding) and falls back to the copy compiled into the binary.
func loadLibrary(ui *tui.UI, cfg client.Config) (pack.Library, string, error) {
	dir := cfg.PackDir
	if dir == "" {
		if exe, err := os.Executable(); err == nil {
			cand := filepath.Join(filepath.Dir(exe), "domains")
			if _, err := os.Stat(filepath.Join(cand, "categories")); err == nil {
				dir = cand
			}
		}
	}
	if dir == "" {
		if _, err := os.Stat("domains/categories"); err == nil {
			dir = "domains"
		}
	}
	lib, origin, err := pack.Load(dir)
	if containsChoice(cfg.PackChoice, "external") {
		lib = lib.WithExternal(cfg.ExternalDomains)
	}
	return lib, origin, err
}

func describeChoice(lib pack.Library, choice []string) string {
	var parts []string
	for _, c := range choice {
		switch strings.ToLower(c) {
		case "quick":
			parts = append(parts, "快速清单")
		case "external":
			parts = append(parts, "自定义外置清单")
		case "full":
			parts = append(parts, "完整清单")
		default:
			if cat, ok := lib.Find(c); ok {
				parts = append(parts, cat.Short())
				continue
			}
			parts = append(parts, c)
		}
	}
	if len(parts) == 0 {
		return "未选择"
	}
	return strings.Join(parts, " + ")
}

// choosePack is the "what do you want to test" step: a numbered list of the
// library's categories plus the two ready-made lists, with a remembered
// default so a repeat run is one keystroke.
func choosePack(ui *tui.UI, cfgPath string, cfg client.Config, lib pack.Library) (client.Config, error) {
	return choosePackWithFetcher(ui, cfgPath, cfg, lib, pack.FetchExternal)
}
func choosePackWithFetcher(ui *tui.UI, cfgPath string, cfg client.Config, lib pack.Library, fetch func(context.Context, string) (pack.ExternalImport, error)) (client.Config, error) {
	cur := cfg.PackChoice
	if len(cur) == 0 {
		cur = []string{"quick"}
	}
	ui.Println()
	ui.Println("选择要测试的清单")
	ui.Table([][]string{{"编号", "清单", "域名数"}, {"1", "默认清单（快速）", strconv.Itoa(len(lib.Quick))}, {"2", "完整清单", strconv.Itoa(len(lib.Full))}, {"3", "按内置分类选择", "进入分类界面"}, {"4", "自定义外置清单（JSON）", "进入链接界面"}})
	ui.Printf("上次选择：%s\n", describeChoice(lib, cur))
	ui.Println("输入编号，可组合（如 1 4）；回车沿用上次选择。")
	input, err := ui.Prompt("要测试", "")
	if err != nil {
		return cfg, err
	}
	names := append([]string(nil), cur...)
	if strings.TrimSpace(input) != "" {
		names = nil
		for _, tok := range splitPackInput(input) {
			switch strings.ToLower(tok) {
			case "1", "q", "quick", "快速":
				names = append(names, "quick")
			case "2", "f", "full", "全部", "all":
				names = append(names, "full")
			case "3":
				categories, err := chooseBuiltinCategories(ui, lib)
				if err != nil {
					return cfg, err
				}
				names = append(names, categories...)
			case "4", "external", "自定义":
				names = append(names, "external")
			default:
				if c, ok := lib.Find(tok); ok && !c.External {
					names = append(names, c.Name)
				} else {
					ui.Printf("无法识别：%s\n", tok)
				}
			}
		}
	}
	next := cfg
	if containsChoice(names, "external") && (strings.TrimSpace(input) != "" || len(next.ExternalDomains) == 0) {
		ui.Println()
		ui.Println("自定义外置清单")
		ui.Println("输入直接返回 JSON 文件内容的 HTTPS 链接；未写分类的域名归入“其他”。")
		raw, err := ui.Prompt("外置 JSON 链接", cfg.ExternalURL)
		if err != nil {
			return cfg, err
		}
		if raw == "" {
			ui.Println("未提供链接，原有配置未更改。")
			return cfg, nil
		}
		ui.Println("正在抓取并校验外置清单…")
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		imported, err := fetch(ctx, raw)
		cancel()
		if err != nil {
			ui.Printf("导入失败：%v（原有配置未更改）\n", err)
			return cfg, nil
		}
		ui.Printf("已导入 %d 个域名 · 跳过无效条目 %d · 去重 %d\n", len(imported.Domains), imported.Skipped, imported.Duplicates)
		for _, issue := range imported.Issues {
			ui.Printf("  第 %d 项：%s\n", issue.Index, issue.Reason)
		}
		next.ExternalURL = raw
		next.ExternalDomains = imported.Domains
		lib = lib.WithExternal(imported.Domains)
	}
	if containsChoice(names, "external") {
		lib = lib.WithExternal(next.ExternalDomains)
	}
	domains, unknown, err := lib.Select(names)
	if err != nil {
		return cfg, err
	}
	if len(unknown) > 0 {
		ui.Printf("无法识别：%s\n", strings.Join(unknown, "、"))
	}
	if len(domains) == 0 {
		ui.Println("没有选中任何域名，原有配置未更改。")
		return cfg, nil
	}
	next.PackChoice = canonChoice(lib, names)
	if err := next.Save(cfgPath); err != nil {
		return cfg, err
	}
	ui.Printf("已选择 %d 个域名（%s）。\n", len(domains), describeChoice(lib, next.PackChoice))
	return next, nil
}

func splitPackInput(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' || r == '，' || r == '+' })
}
func containsChoice(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}
func chooseBuiltinCategories(ui *tui.UI, lib pack.Library) ([]string, error) {
	var categories []pack.Category
	rows := [][]string{{"编号", "分类", "域名数"}}
	for _, c := range lib.Categories {
		if !c.External {
			categories = append(categories, c)
			rows = append(rows, []string{strconv.Itoa(len(categories)), c.Display(), strconv.Itoa(c.Count())})
		}
	}
	ui.Println()
	ui.Println("选择内置分类")
	ui.Table(rows)
	input, err := ui.Prompt("分类编号（可多选；回车不添加）", "")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, tok := range splitPackInput(input) {
		if i, err := strconv.Atoi(tok); err == nil && i >= 1 && i <= len(categories) {
			names = append(names, categories[i-1].Name)
			continue
		}
		if c, ok := lib.Find(tok); ok && !c.External {
			names = append(names, c.Name)
		} else {
			ui.Printf("无法识别分类：%s\n", tok)
		}
	}
	return names, nil
}

// canonChoice stores category names rather than the numbers the user typed, so
// the remembered choice survives a change in the library.
func canonChoice(lib pack.Library, names []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "quick" || n == "full" || n == "external" {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
			continue
		}
		if c, ok := lib.Find(n); ok && !seen[c.Name] {
			seen[c.Name] = true
			out = append(out, c.Name)
		}
	}
	return out
}

// clientStartTest runs the test with the current selection and then goes
// straight into the result, which is also written to a Markdown file.
func clientStartTest(ui *tui.UI, sess *clientSession, lib pack.Library, libSource string) error {
	cfg := sess.cfg
	choice := cfg.PackChoice
	if len(choice) == 0 {
		choice = []string{"quick"}
	}
	domains, unknown, err := lib.Select(choice)
	if err != nil {
		return err
	}
	if len(unknown) > 0 {
		ui.Printf("域名库里没有：%s\n", strings.Join(unknown, "、"))
	}
	if len(domains) == 0 {
		ui.Println("还没有可测的域名：请先在「选择要测试的域名」里选一个分类。")
		return nil
	}
	targets := cfg.ProbeTargets()
	if len(targets) == 0 {
		ui.Println("缺少观测端地址：请在「设置」里重新登记。")
		return nil
	}

	showFullIP, err := askIPDisplay(ui)
	if err != nil {
		return err
	}
	spec := client.PlanSpec{ShowFullIP: &showFullIP, Targets: targets, Domains: domains, Baseline: cfg.Baseline, Rounds: cfg.Rounds, Categories: lib.ReportCategories(domains)}
	plan, _, err := client.BuildPlan(spec)
	if err != nil {
		ui.Printf("无法生成测试计划：%v\n", err)
		return nil
	}
	ui.Println()
	ui.Rule()
	ui.Printf("测试内容：%s · %d 个域名\n", describeChoice(lib, choice), len(domains))
	ui.Printf("观测端：%s\n", strings.Join(targets, "  "))
	if showFullIP {
		ui.Println("出口 IP：完整展示（终端与导出报告）")
	} else {
		ui.Println("出口 IP：脱敏展示（终端与导出报告）")
	}
	ui.Printf("规模：每个域名 %d 次独立连接，共 %d 次探测\n", cfg.Rounds, len(plan))
	ui.Printf("调度：并发 %d · 同一 SNI 探测间隔至少 %s\n", cfg.Concurrency, client.SNIProbeInterval)
	ui.Printf("报告：测试结束后自动写成 %s\n", filepath.Join(reportDir(cfg), "<任务>-report.md"))
	ui.Rule()
	ok, err := ui.Confirm("开始测试？", true)
	if err != nil || !ok {
		return err
	}

	view, interrupted, err := runTask(ui, sess, client.RunOptions{
		Plan: spec, Concurrency: cfg.Concurrency, Timeout: cfg.Timeout(),
		ProviderLabel: cfg.ProviderLabel, EnvNote: cfg.EnvNote, Version: version,
	})
	if err != nil {
		ui.Printf("测试未能完成：%v\n", err)
		if view.ID == "" {
			return nil
		}
	}
	rep := report.Build(view, time.Now())
	if interrupted {
		ui.Println("\n已中断：未执行的尝试不计为网络失败，以下为部分结果。")
	}

	// The report is the point of the run, so write it without asking. A file
	// that cannot be written must not hide the result already on screen.
	dir := reportDir(cfg)
	mdPath, werr := report.ExportMarkdown(dir, rep)
	report.WriteResults(ui.Writer(), rep)
	if werr != nil {
		ui.Printf("\n报告文件写入失败：%v\n（结果仍在上面；可在「历史报告」里重新导出）\n", werr)
	} else {
		ui.Println()
		ui.Printf("Markdown 报告：%s\n", mdPath)
	}
	ui.Println("（完整报告、导出与刷新出口归属在「历史报告」里）")

	id := view.ID
	return reportMenuActions(ui, rep, dir, func(ctx context.Context) (report.Report, error) { return sess.refreshASN(ctx, id) })
}

// clientSettings is the short list of things worth changing, kept out of the
// main path. Defaults are what the tool uses unless someone asks otherwise.
func clientSettings(ui *tui.UI, cfgPath string, cfg client.Config, lib pack.Library) (client.Config, error) {
	key, err := ui.Menu("设置", []string{
		fmt.Sprintf("节点：%s（%s）", cfg.NodeName, orDash(cfg.ProviderLabel)),
		fmt.Sprintf("观测端：%s", cfg.Server),
		fmt.Sprintf("探测目标：%s", strings.Join(cfg.ProbeTargets(), "  ")),
		fmt.Sprintf("每域名连接 %d 次 · 并发 %d · 超时 %ds", cfg.Rounds, cfg.Concurrency, cfg.TimeoutSeconds),
		fmt.Sprintf("报告目录：%s", cfg.ReportDirOr("（当前目录）")),
	}, []tui.Item{
		tui.Opt("1", "服务商标签 / 环境说明"),
		tui.Opt("2", "探测目标（观测端 ip:port）"),
		tui.Opt("3", "测试强度（次数 / 并发 / 超时）"),
		tui.Opt("4", "报告保存目录"),
		tui.Opt("5", "域名库位置"),
		tui.Opt("6", "重新登记（换一个注册链接）"),
		tui.Opt("0", "返回"),
	})
	if err != nil || key == "0" {
		return cfg, err
	}
	next := cfg
	switch key {
	case "1":
		if next.ProviderLabel, err = ui.Prompt("服务商标签（被测网络的服务商名称）", cfg.ProviderLabel); err != nil {
			return cfg, err
		}
		if next.EnvNote, err = ui.Prompt("环境说明（本机是否有系统级 VPN / TUN / 透明代理）", cfg.EnvNote); err != nil {
			return cfg, err
		}
	case "2":
		s, err := ui.Prompt("探测目标（可多个，用逗号分隔；默认是观测端的 443）", strings.Join(cfg.ProbeTargets(), ","))
		if err != nil {
			return cfg, err
		}
		next.Targets = splitList(s)
		if _, _, err := client.BuildPlan(client.PlanSpec{Targets: next.Targets, Domains: []string{"a.example.com"}}); err != nil && len(next.Targets) > 0 {
			ui.Printf("目标无效：%v（保留原值）\n", err)
			next.Targets = cfg.Targets
		}
	case "3":
		for _, f := range []struct {
			label string
			dst   *int
			min   int
			max   int
		}{
			{"每个域名的独立连接次数（1–20，越大越稳但越慢）", &next.Rounds, 1, client.MaxRounds},
			{"并发数（1–32）", &next.Concurrency, 1, 32},
			{"单次探测超时（秒）", &next.TimeoutSeconds, 1, 120},
		} {
			s, err := ui.Prompt(f.label, strconv.Itoa(*f.dst))
			if err != nil {
				return cfg, err
			}
			if n, err := strconv.Atoi(s); err != nil || n < f.min || n > f.max {
				ui.Printf("  %q 无效（范围 %d–%d），保留原值。\n", s, f.min, f.max)
			} else {
				*f.dst = n
			}
		}
	case "4":
		s, err := ui.Prompt("报告保存目录（回车沿用，输入 - 恢复为当前目录）", cfg.ReportDir)
		if err != nil {
			return cfg, err
		}
		next.ReportDir = clearable(s)
	case "5":
		s, err := ui.Prompt("域名库目录（回车沿用，输入 - 用内置清单）", cfg.PackDir)
		if err != nil {
			return cfg, err
		}
		next.PackDir = clearable(s)
	case "6":
		return joinFlow(ui, cfgPath, cfg)
	}
	if err := next.Save(cfgPath); err != nil {
		return cfg, err
	}
	ui.Println("已保存。")
	return next, nil
}

// clearable turns "-" into "unset": Prompt keeps the default on an empty line,
// so this is the only way to go back to the built-in behaviour.
func clearable(s string) string {
	if strings.TrimSpace(s) == "-" {
		return ""
	}
	return strings.TrimSpace(s)
}

// reportDir is the directory the Markdown report goes to, made absolute so the
// end-of-run message can be pasted into another shell.
func reportDir(cfg client.Config) string {
	if cfg.ReportDir != "" {
		if abs, err := filepath.Abs(cfg.ReportDir); err == nil {
			return abs
		}
		return cfg.ReportDir
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// quitOnCancel treats end of input as a normal exit.
func quitOnCancel(err error) error {
	if errors.Is(err, tui.ErrCancel) {
		return nil
	}
	return err
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '，' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func onOff(b bool) string {
	if b {
		return "开"
	}
	return "关"
}

// askIPDisplay is asked before the final start confirmation, once per run.
func askIPDisplay(ui *tui.UI) (bool, error) {
	return ui.Confirm("是否展示完整出口 IP？（同时用于 SSH 输出与导出报告，选否则脱敏）", false)
}
