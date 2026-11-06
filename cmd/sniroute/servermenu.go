package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nyktios/sniroute/internal/asn"
	"github.com/nyktios/sniroute/internal/auth"
	"github.com/nyktios/sniroute/internal/link"
	"github.com/nyktios/sniroute/internal/server"
	"github.com/nyktios/sniroute/internal/store"
	"github.com/nyktios/sniroute/internal/tui"
)

func maskKey(k string) string {
	if k == "" {
		return "未设置"
	}
	if len(k) <= 8 {
		return "********"
	}
	return k[:4] + strings.Repeat("*", 8) + k[len(k)-2:]
}

// openRegistry opens the service's database for management actions. The menu
// runs in a separate process from the service; SQLite serialises access.
func openRegistry(cfg server.Config) (*store.Store, *auth.Registry, error) {
	if cfg.AdminKey == "" {
		return nil, nil, errors.New("还没有管理密钥：请先在菜单 1 初始化配置")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, nil, err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "sniroute.db"))
	if err != nil {
		return nil, nil, err
	}
	reg, err := auth.NewRegistry(cfg.AdminKey, st)
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	return st, reg, nil
}

func serverMenu(cfgPath string) error {
	ui := tui.New(os.Stdin, os.Stdout)
	for {
		cfg, err := server.LoadConfig(cfgPath)
		initialised := err == nil
		if err != nil && !errors.Is(err, server.ErrNoConfig) {
			return err
		}
		// Before setup there is exactly one useful action, so the menu says only
		// that. Everything configurable has a working default.
		if !initialised {
			key, err := ui.Menu("服务端管理", []string{
				fmt.Sprintf("配置文件：%s", cfgPath),
				"尚未初始化。推荐配置一步完成，之后随时可以改。",
			}, []tui.Item{
				tui.Opt("1", "初始化服务（推荐配置）"), tui.Opt("0", "返回"),
			})
			if err != nil {
				return quitOnCancel(err)
			}
			if key == "0" {
				return nil
			}
			if err := serverInit(ui, cfgPath, cfg); err != nil {
				if errors.Is(err, tui.ErrCancel) {
					return nil
				}
				ui.Printf("出错：%v\n", err)
			}
			continue
		}

		running := false
		state := "已停止"
		if pid, _ := serverMenuPID(cfgPath, cfg.DataDir); pid != 0 {
			running = true
			state = fmt.Sprintf("运行中（pid %d）", pid)
		}
		startStop := "启动服务"
		if running {
			startStop = "停止 / 重启服务"
		}
		key, err := ui.Menu("服务端管理", []string{
			state + "    控制接口：" + cfg.ControlAddr + "    探测监听：" + cfg.ProbeAddr,
			"给被测机器的只有一样东西：注册链接。",
		}, []tui.Item{
			tui.Opt("1", "生成注册链接（发给被测机器）"),
			tui.Opt("2", "查看 / 管理注册链接"),
			tui.Opt("3", "实时连接"),
			tui.Opt("4", startStop),
			tui.Opt("5", "服务设置"),
			tui.Opt("6", "运行日志"),
			tui.Opt("0", "返回"),
		})
		if err != nil {
			return quitOnCancel(err)
		}
		switch key {
		case "1":
			err = serverRegLink(ui, cfg)
		case "2":
			err = serverTokenAdmin(ui, cfg)
		case "3":
			err = serverLiveConnections(ui, cfg)
		case "4":
			err = serverControl(ui, cfgPath, cfg, running)
		case "5":
			err = serverSettings(ui, cfgPath, cfg)
		case "6":
			err = serverLog(ui, cfg)
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

// serverInit sets the service up on first use. The recommended path asks a
// single yes/no question and then offers to start; everything it decides is a
// working default that can be changed later under 服务设置.
//
// The self-signed certificate is pinned by fingerprint, so its host names are
// irrelevant to clients and are not asked for.
func serverInit(ui *tui.UI, cfgPath string, cfg server.Config) error {
	ui.Println("\n首次初始化 · 推荐配置")
	ui.Rule()
	ui.Printf("探测监听：%s    （需直接暴露公网，不要放在 CDN / 反向代理后）\n", cfg.ProbeAddr)
	ui.Printf("控制接口：%s    （HTTPS，自签名证书自动生成）\n", cfg.ControlAddr)
	ui.Printf("数据目录：%s\n", cfg.DataDir)
	ui.Println("管理密钥：自动生成并保存在配置文件里（权限 0600）")
	ui.Rule()
	ok, err := ui.Confirm("用这些配置初始化？", true)
	if err != nil {
		return err
	}
	if !ok {
		if ok, err := ui.Confirm("改用自定义配置？", false); err != nil {
			return err
		} else if !ok {
			return nil
		}
		return serverInitCustom(ui, cfgPath, cfg)
	}
	next := cfg
	next.TLSSelfSigned = true
	next.AdminKey = auth.GenerateKey()
	if err := next.Save(cfgPath); err != nil {
		return err
	}
	ui.Printf("已初始化，配置写入 %s（权限 0600）。管理密钥：%s\n", cfgPath, maskKey(next.AdminKey))
	return startAfterInit(ui, cfgPath, next)
}

// serverInitCustom is the optional path for other ports or an existing
// certificate. It still needs nothing that has a sane default.
func serverInitCustom(ui *tui.UI, cfgPath string, cfg server.Config) error {
	ui.Println("\n自定义配置（直接回车保留方括号内的值）")
	next := cfg
	var err error
	if next.ProbeAddr, err = ui.Prompt("探测监听地址（:443 需要 root）", cfg.ProbeAddr); err != nil {
		return err
	}
	if next.ControlAddr, err = ui.Prompt("控制接口监听地址（HTTPS）", cfg.ControlAddr); err != nil {
		return err
	}
	if next.DataDir, err = ui.Prompt("数据目录（数据库与证书）", cfg.DataDir); err != nil {
		return err
	}
	if next, err = promptCert(ui, next); err != nil {
		return err
	}
	next.AdminKey = auth.GenerateKey()
	if err := next.Save(cfgPath); err != nil {
		return err
	}
	ui.Printf("已初始化，配置写入 %s（权限 0600）。管理密钥：%s\n", cfgPath, maskKey(next.AdminKey))
	return startAfterInit(ui, cfgPath, next)
}

// startAfterInit saves a trip through the menu: initialisation usually means
// the user wants the service running right away.
func startAfterInit(ui *tui.UI, cfgPath string, cfg server.Config) error {
	if pid, _ := serverMenuPID(cfgPath, cfg.DataDir); pid != 0 {
		return nil
	}
	ok, err := ui.Confirm("现在启动服务？", true)
	if err != nil || !ok {
		return err
	}
	if err := serverDaemonCmd("start", cfgPath); err != nil {
		ui.Printf("启动失败：%v\n提示：:443 通常需要 root 权限；也可以把探测端口改大（服务设置 1），再选主菜单 4 启动。\n", err)
		return nil
	}
	ui.Println("服务已启动。下一步：选 1 生成注册链接，发到被测机器上。")
	return nil
}

// promptCert picks the control certificate. Self-signed is the default; a
// certificate file is only needed when clients can verify it via system roots.
func promptCert(ui *tui.UI, cfg server.Config) (server.Config, error) {
	mode := "1"
	if cfg.TLSCert != "" {
		mode = "2"
	}
	ui.Println("控制接口证书：1 = 自签名（推荐，自动生成，客户端用指纹固定）  2 = 已有的证书文件")
	m, err := ui.Prompt("选择", mode)
	if err != nil {
		return cfg, err
	}
	if m == "2" {
		if cfg.TLSCert, err = ui.Prompt("证书文件路径", cfg.TLSCert); err != nil {
			return cfg, err
		}
		if cfg.TLSKey, err = ui.Prompt("私钥文件路径", cfg.TLSKey); err != nil {
			return cfg, err
		}
		if cfg.TLSCert != "" && cfg.TLSKey != "" {
			cfg.TLSSelfSigned = false
			return cfg, nil
		}
		ui.Println("证书路径不完整，将使用自签名证书。")
	}
	cfg.TLSSelfSigned, cfg.TLSCert, cfg.TLSKey = true, "", ""
	return cfg, nil
}

// serverControl offers only the actions that apply to the current state.
func serverControl(ui *tui.UI, cfgPath string, cfg server.Config, running bool) error {
	items := []tui.Item{tui.Opt("1", "启动服务"), tui.Opt("0", "返回")}
	if running {
		items = []tui.Item{tui.Opt("1", "停止服务"), tui.Opt("2", "重启服务"), tui.Opt("0", "返回")}
	}
	key, err := ui.Menu("服务", nil, items)
	if err != nil || key == "0" {
		return err
	}
	switch key {
	case "2":
		return serverDaemonCmd("restart", cfgPath)
	case "1":
		if running {
			return serverDaemonCmd("stop", cfgPath)
		}
		return serverDaemonCmd("start", cfgPath)
	}
	return nil
}

// serverBaseURL decides the control URL to put in an onboarding link. A
// listener on a wildcard address is not reachable by name, so the guess is
// only a default the operator confirms.
func serverBaseURL(ui *tui.UI, cfg server.Config) (string, error) {
	host, port, err := net.SplitHostPort(cfg.ControlAddr)
	if err != nil {
		host, port = "", "8443"
	}
	if port == "" {
		port = "8443"
	}
	suggest := ""
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		if out, err := guessAddr(); err == nil {
			suggest = "https://" + net.JoinHostPort(out, port)
		}
	} else {
		suggest = "https://" + net.JoinHostPort(host, port)
	}
	s, err := ui.Prompt("被测机器访问控制接口的地址（https://主机:端口）", suggest)
	if err != nil {
		return "", err
	}
	base, err := link.NormalizeServer(s)
	if err != nil {
		ui.Printf("地址无效：%v\n", err)
		return "", nil
	}
	return base, nil
}

// guessAddr finds a non-loopback IPv4 address for the link suggestion.
func guessAddr() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip4 := ipn.IP.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() {
				return ip4.String(), nil
			}
		}
	}
	return "", errors.New("no non-loopback address")
}

// serverRegLink creates one token and prints the single-string onboarding
// link. The link carries the control URL, the certificate pin (self-signed
// only), the token and the node name; the token and pin ride in the URL
// fragment, which a browser never sends.
func serverRegLink(ui *tui.UI, cfg server.Config) error {
	base, err := serverBaseURL(ui, cfg)
	if err != nil || base == "" {
		return err
	}
	pin := ""
	if cfg.TLSSelfSigned {
		if pin, err = server.ControlPinFromFile(filepath.Join(cfg.DataDir, "control.pem")); err != nil {
			ui.Println("控制证书还没生成（服务从未启动过）：请先启动服务，再生成注册链接。")
			return nil
		}
	}
	st, reg, err := openRegistry(cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	tok, token, err := reg.NewRegToken(7 * 24 * time.Hour)
	switch {
	case errors.Is(err, auth.ErrLimit):
		ui.Println("未使用的注册链接太多了。请先在「查看 / 管理注册链接」里清理旧的。")
		return nil
	case err != nil:
		return err
	}
	l, err := link.Build(link.Link{Server: base, Pin: pin, Token: token, Name: localHostname()})
	if err != nil {
		return err
	}
	ui.Println()
	ui.Rule()
	ui.Println("在被测机器上执行下面的一键命令，自动注册并打开客户端：")
	ui.Println()
	ui.Println("  " + clientBootstrapCommand(l))
	ui.Println()
	ui.Println("连接信息")
	ui.Println("控制地址：" + base)
	ui.Println("注册链接：" + l)
	ui.Printf("凭证 ID：%s    有效至：%s（用一次即失效）\n", tok.ID, tok.ExpiresAt.Local().Format("2006-01-02 15:04"))
	ui.Rule()
	ui.Println("客户端临时运行，报告保存在客户端；离线满 15 分钟后观测端清理数据，节点密钥失效。")
	ui.Println("测试结束会自动在客户端当前目录生成 Markdown 报告。")
	return nil
}

func clientBootstrapCommand(regLink string) string {
	// Quote the complete link as one literal shell argument, including any
	// external host characters; never allow its contents to become shell code.
	quoted := "'" + strings.ReplaceAll(regLink, "'", "'\"'\"'") + "'"
	return `sh -c "$(curl -fsSL https://raw.githubusercontent.com/obrdx/SniRoute/main/scripts/sniroute-client.sh)" -- --link ` + quoted
}

func localHostname() string {
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return ""
}

// serverTokenAdmin lists outstanding tokens, re-displays their links and
// revokes them. Tokens are derived from the admin key, so a link can be shown
// again later instead of only once.
func serverTokenAdmin(ui *tui.UI, cfg server.Config) error {
	st, reg, err := openRegistry(cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	toks, err := reg.RegTokens()
	if err != nil {
		return err
	}
	if len(toks) == 0 {
		ui.Println("没有未使用的注册链接。在主菜单选 1 可以生成一个。")
		return nil
	}
	ui.Println()
	rows := [][]string{{"#", "凭证 ID", "创建时间", "有效至"}}
	for i, t := range toks {
		rows = append(rows, []string{strconv.Itoa(i + 1), t.ID, t.CreatedAt.Local().Format("01-02 15:04"), t.ExpiresAt.Local().Format("01-02 15:04")})
	}
	ui.Table(rows)
	s, err := ui.Prompt("输入编号查看链接（回车返回）", "")
	if err != nil || s == "" {
		return err
	}
	i, err := strconv.Atoi(s)
	if err != nil || i < 1 || i > len(toks) {
		ui.Println("无效编号。")
		return nil
	}
	t := toks[i-1]
	base, err := serverBaseURL(ui, cfg)
	if err != nil || base == "" {
		return err
	}
	pin := ""
	if cfg.TLSSelfSigned {
		pin, _ = server.ControlPinFromFile(filepath.Join(cfg.DataDir, "control.pem"))
	}
	l, err := link.Build(link.Link{Server: base, Pin: pin, Token: reg.RegTokenFor(t)})
	if err != nil {
		return err
	}
	ui.Println()
	ui.Println("  " + l)
	ui.Println()
	if ok, err := ui.Confirm("撤销这个凭证？（已用过的凭证会自行失效）", false); err != nil || !ok {
		return err
	}
	if err := reg.DeleteRegToken(t.ID); err != nil {
		return err
	}
	ui.Println("已撤销。")
	return nil
}

// serverLiveConnections reads the same temporary database as the service.
func serverLiveConnections(ui *tui.UI, cfg server.Config) error {
	st, _, err := openRegistry(cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	ui.Println("实时连接（每 2 秒刷新；回车返回）")
	render := func() {
		rows, err := st.LiveClients(time.Now())
		if err != nil {
			ui.Printf("读取实时连接失败：%v\n", err)
			return
		}
		ui.Rule()
		ui.Printf("%s · 正在测试的客户端：%d\n", time.Now().Format("15:04:05"), len(rows))
		if len(rows) == 0 {
			ui.Println("当前没有正在测试的客户端。")
			return
		}
		table := [][]string{{"客户端", "控制连接来源 IP", "进度", "已运行", "最近活动"}}
		for _, r := range rows {
			table = append(table, []string{r.Name, r.IP, fmt.Sprintf("%d/%d", r.Recorded, r.Planned), time.Since(r.StartedAt).Truncate(time.Second).String(), time.Since(r.LastSeen).Truncate(time.Second).String() + "前"})
		}
		ui.Table(table)
	}
	render()
	done := make(chan struct{})
	go func() { ui.WaitLine(); close(done) }()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return nil
		case <-ticker.C:
			render()
		}
	}
}

func serverSettings(ui *tui.UI, cfgPath string, cfg server.Config) error {
	ui.Println()
	ui.Printf("探测监听：%s\n控制接口：%s\n", cfg.ProbeAddr, cfg.ControlAddr)
	key, err := ui.Menu("服务设置", nil, []tui.Item{
		tui.Opt("1", "修改监听地址"),
		tui.Opt("2", "重新生成管理密钥"),
		tui.Opt("0", "返回"),
	})
	if err != nil || key == "0" {
		return err
	}
	next := cfg
	switch key {
	case "1":
		if next.ProbeAddr, err = ui.Prompt("探测监听地址（:443 需要 root）", cfg.ProbeAddr); err != nil {
			return err
		}
		if next.ControlAddr, err = ui.Prompt("控制接口监听地址（HTTPS）", cfg.ControlAddr); err != nil {
			return err
		}
	case "2":
		ok, err := ui.Confirm("重新生成管理密钥？（旧密钥与所有未使用的注册链接立即失效，需重启服务）", false)
		if err != nil || !ok {
			return err
		}
		next.AdminKey = auth.GenerateKey()
	}
	if err := next.Save(cfgPath); err != nil {
		return err
	}
	ui.Println("已保存。")
	if pid, _ := serverMenuPID(cfgPath, cfg.DataDir); pid != 0 {
		ui.Println("服务正在运行：修改需重启后生效（主菜单 4 → 重启）。")
	}
	return nil
}

func serverLog(ui *tui.UI, cfg server.Config) error {
	lines, err := server.TailLog(cfg.DataDir, 40)
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		ui.Println("日志为空（服务尚未以后台方式运行过）。")
		return nil
	}
	for _, l := range lines {
		ui.Println(l)
	}
	return nil
}

// newTasks builds a task manager for operator tools, with the configured
// egress-network lookups attached.
func newTasks(cfg server.Config, reg *auth.Registry, st *store.Store) *server.Tasks {
	t := server.NewTasks(server.TasksConfig{}, reg, st, cfg.CollectorID)
	t.ASN = server.NewASNService(cfg, st)
	return t
}

// serverASNChoice picks the egress-network data source. Caching (24 h) and
// the RIPEstat sourceapp keep their defaults; both stay adjustable in
// server.yaml. changed is false when nothing was edited, so the caller does
// not rewrite the config file.
func serverASNChoice(ui *tui.UI, cfg server.Config) (server.Config, bool, error) {
	src := cfg.ASNSource
	if src == "" {
		src = "ripestat"
	}
	name := map[string]string{"ripestat": "RIPEstat", "cymru": "Team Cymru", "none": "已关闭"}[src]
	if name == "" {
		name = src
	}
	cache := "缓存 24 小时"
	if cfg.ASNNoCache {
		cache = "不缓存"
	} else if cfg.ASNCacheHours > 0 {
		cache = fmt.Sprintf("缓存 %d 小时", cfg.ASNCacheHours)
	}
	ui.Println()
	ui.Printf("当前：%s（%s）\n", name, cache)
	ui.Println("查询只发送观测到的公网出口 IP，私网地址永不发送；所有数据源均无需 API Key。")
	geoSources := cfg.GeoSources
	if len(geoSources) == 0 {
		geoSources = []string{"ipinfo", "geojs"}
	}
	ui.Printf("归属地来源：%s（IPinfo 优先，其他来源补缺并提示差异）\n", strings.Join(geoSources, "、"))
	ui.Println("缓存时长、sourceapp 等可用配置文件 server.yaml 调整。")
	key, err := ui.Menu("出口网络（ASN）查询", nil, []tui.Item{
		tui.Opt("1", "使用 RIPEstat（推荐）"),
		tui.Opt("2", "使用 Team Cymru"),
		tui.Opt("3", "关闭查询"),
		tui.Opt("4", "测试查询一个 IP"),
		tui.Opt("5", "归属地：IPinfo + GeoJS 对照（推荐）"),
		tui.Opt("6", "归属地：仅 IPinfo"),
		tui.Opt("7", "关闭归属地查询（保留 ASN）"),
		tui.Opt("0", "返回"),
	})
	if err != nil || key == "0" {
		return cfg, false, err
	}
	next := cfg
	switch key {
	case "1":
		next.ASNSource = "ripestat"
		if src == "ripestat" {
			ui.Println("已经使用 RIPEstat。")
			return next, false, nil
		}
	case "2":
		next.ASNSource = "cymru"
		if src == "cymru" {
			ui.Println("已经使用 Team Cymru。")
			return next, false, nil
		}
	case "3":
		next.ASNSource = "none"
		if src == "none" {
			ui.Println("查询已经关闭。")
			return next, false, nil
		}
	case "4":
		return next, false, serverASNTest(ui, cfg)
	case "5":
		next.GeoSources = []string{"ipinfo", "geojs"}
	case "6":
		next.GeoSources = []string{"ipinfo"}
	case "7":
		next.GeoSources = []string{"none"}
	}
	if key == "5" || key == "6" || key == "7" {
		if strings.Join(geoSources, ",") == strings.Join(next.GeoSources, ",") {
			return next, false, nil
		}
	}
	return next, true, nil
}

func serverASNTest(ui *tui.UI, cfg server.Config) error {
	st, _, err := openRegistry(cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	svc := server.NewASNService(cfg, st)
	if svc == nil {
		ui.Println("查询已关闭。")
		return nil
	}
	s, err := ui.Prompt("要查询的公网 IP（留空返回）", "")
	if err != nil {
		return err
	}
	if strings.TrimSpace(s) == "" {
		return nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		ui.Println("不是有效的 IP。")
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	for _, i := range svc.LookupMany(ctx, []netip.Addr{addr}) {
		var nets []string
		for _, n := range i.ASNs {
			nets = append(nets, n.Label())
		}
		ui.Printf("来源 %s · 状态 %s · 前缀 %s · %s %s\n", i.Source, i.Status, orDash(i.Prefix), orDash(strings.Join(nets, "；")), i.Error)
		ui.Printf("归属地：%s\n", asn.LocationText(i.Locations))
	}
	return nil
}
