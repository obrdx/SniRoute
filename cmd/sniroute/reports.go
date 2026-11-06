package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/nyktios/sniroute/internal/client"
	"github.com/nyktios/sniroute/internal/report"
	"github.com/nyktios/sniroute/internal/server"
	"github.com/nyktios/sniroute/internal/tui"
)

// clientSession bundles the control client, the local outbox and the runner
// for one client invocation.
type clientSession struct {
	cfgPath       string
	cfg           client.Config
	ob            *client.Outbox
	runner        *client.Runner
	stopHeartbeat func()
}

func openSession(cfgPath string, cfg client.Config) (*clientSession, error) {
	ob, err := client.OpenOutbox(client.DefaultOutboxPath(cfgPath))
	if err != nil {
		return nil, fmt.Errorf("open local queue: %w", err)
	}
	s := &clientSession{cfgPath: cfgPath, ob: ob}
	if err := s.setConfig(cfg); err != nil {
		ob.Close()
		return nil, err
	}
	return s, nil
}

// setConfig rebuilds the control client after settings or enrolment changed.
func (s *clientSession) setConfig(cfg client.Config) error {
	cc, err := client.NewControlClient(cfg.Server, cfg.ControlPin)
	if err != nil {
		return err
	}
	if s.stopHeartbeat != nil {
		s.stopHeartbeat()
	}
	s.cfg = cfg
	s.runner = &client.Runner{CC: cc, State: cfg.Enrollment, Outbox: s.ob}
	s.stopHeartbeat = s.runner.KeepAlive(context.Background())
	return nil
}

func (s *clientSession) close() {
	if s.stopHeartbeat != nil {
		s.stopHeartbeat()
	}
	s.ob.Close()
}

func (s *clientSession) pendingCount() int {
	p, _ := s.ob.Pending("")
	return len(p)
}

func (s *clientSession) reportsDir() string { return reportDir(s.cfg) }

// recover re-sends anything queued by an earlier run (a dropped connection or
// a dead SSH session) and tells the user about runs that never finished.
func (s *clientSession) recover(ui *tui.UI) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if ids, err := s.runner.RecoverInterrupted(); err == nil {
		for _, id := range ids {
			ui.Printf("上次测试 %s 没有正常结束（可能 SSH 断开）。可在“历史报告”中查看它的不完整结果；未执行的项目不计为失败。\n", id)
		}
	}
	if s.pendingCount() == 0 {
		return
	}
	delivered, remaining, err := s.runner.Flush(ctx, "")
	switch {
	case err != nil || remaining > 0:
		ui.Printf("本地还有 %d 条记录未能上报（控制连接不可用），稍后会再次尝试。\n", remaining)
	case delivered > 0:
		ui.Printf("已补交 %d 条先前未能上报的本地记录。\n", delivered)
	}
}

// loadReport fetches a task from the server and builds its report.
func (s *clientSession) loadReport(ctx context.Context, taskID string) (report.Report, error) {
	s.runner.CC.ASN(ctx, s.cfg.Path, s.cfg.NodeKey, taskID, false)
	v, err := s.runner.CC.GetTask(ctx, s.cfg.Path, s.cfg.NodeKey, taskID)
	if err != nil {
		if local, ok, lerr := s.ob.LoadTask(taskID); lerr == nil && ok {
			return report.Build(local, time.Now()), nil
		}
		return report.Report{}, err
	}
	if err := s.ob.SaveTask(v); err != nil {
		return report.Report{}, err
	}
	return report.Build(v, time.Now()), nil
}

func (s *clientSession) listReports(ctx context.Context) ([]server.TaskListItem, error) {
	local, err := s.ob.LocalTasks()
	if err != nil {
		return nil, err
	}
	remote, rerr := s.runner.CC.ListTasks(ctx, s.cfg.Path, s.cfg.NodeKey, 30)
	if rerr != nil && len(local) == 0 {
		return nil, rerr
	}
	return client.MergeTaskLists(local, remote), nil
}

var statusText = map[server.TaskStatus]string{
	server.TaskPending: "等待中", server.TaskRunning: "进行中", server.TaskCompleted: "已完成", server.TaskAborted: "已中断", server.TaskFailed: "失败",
}

func taskRows(items []server.TaskListItem, nodeCol []string) [][]string {
	head := []string{"#", "任务", "创建时间", "状态", "尝试", "已有记录", "首个目标"}
	if nodeCol != nil {
		head = append(head, "节点")
	}
	rows := [][]string{head}
	for i, it := range items {
		r := []string{strconv.Itoa(i + 1), it.ID, it.CreatedAt.Local().Format("01-02 15:04:05"), statusText[it.Status], strconv.Itoa(it.Planned), strconv.Itoa(it.Recorded), it.Target}
		if nodeCol != nil {
			r = append(r, nodeCol[i])
		}
		rows = append(rows, r)
	}
	return rows
}

// reportMenu is the reading menu for one report: the full text, focused views,
// per-domain evidence and export.
func reportMenu(ui *tui.UI, rep report.Report, defaultDir string, refreshASN func(ctx context.Context) (report.Report, error)) error {
	report.WriteResults(ui.Writer(), rep)
	return reportMenuActions(ui, rep, defaultDir, refreshASN)
}

func reportMenuActions(ui *tui.UI, rep report.Report, defaultDir string, refreshASN func(ctx context.Context) (report.Report, error)) error {
	w := ui.Writer()
	for {
		key, err := ui.Menu("报告 "+rep.Task.ID, nil, []tui.Item{
			tui.Opt("1", "查看完整报告"), tui.Opt("2", "查看域名综合结果"), tui.Opt("3", "按出口 IP 分组查看"),
			tui.Opt("4", "只查看探测异常"), tui.Opt("5", "查看单个域名的详细证据"),
			tui.Opt("6", "导出报告（TXT / JSON / CSV / MD）"),
			tui.Opt("7", "刷新出口网络归属（新建一份 ASN 快照）"), tui.Opt("0", "返回"),
		})
		if err != nil || key == "0" {
			return err
		}
		switch key {
		case "1":
			report.WriteText(w, rep)
		case "2":
			report.WriteDomainTable(w, rep)
		case "3":
			report.WriteGroups(w, rep)
		case "4":
			report.WriteAnomalies(w, rep)
		case "5":
			d, err := ui.Prompt("域名", "")
			if err != nil {
				return err
			}
			if d == "" {
				continue
			}
			if ok, _ := report.WriteDomain(w, rep, d); !ok {
				ui.Println("没有这个域名的记录。")
			}
		case "7":
			if refreshASN == nil {
				ui.Println("当前入口不支持刷新。")
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			next, err := refreshASN(ctx)
			cancel()
			if err != nil {
				ui.Printf("刷新失败：%v\n（已有的快照和出口 IP 不受影响）\n", err)
				continue
			}
			rep = next
			ui.Printf("已新建快照 %d。之前的快照保持不变；此后导出的报告使用快照 %d。\n", rep.ASN.Snapshot, rep.ASN.Snapshot)
			report.WriteGroups(w, rep)
		case "6":
			dir, err := ui.Prompt("导出目录", defaultDir)
			if err != nil {
				return err
			}
			files, err := report.Export(dir, rep)
			if err != nil {
				ui.Printf("导出失败：%v\n", err)
				continue
			}
			if md, err := report.ExportMarkdown(dir, rep); err == nil {
				files = append(files, md)
			}
			ui.Println("已导出（文件权限 0600）：")
			for _, f := range files {
				ui.Println("  " + f)
			}
		}
	}
}

// clientHistory lists this node's tasks and opens one.
func clientHistory(ui *tui.UI, sess *clientSession) error {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		items, err := sess.listReports(ctx)
		cancel()
		if err != nil {
			ui.Printf("无法获取历史任务：%v\n", err)
			return nil
		}
		if len(items) == 0 {
			ui.Println("还没有历史任务。")
			return nil
		}
		ui.Println()
		ui.Table(taskRows(items, nil))
		s, err := ui.Prompt("输入编号查看报告（回车返回）", "")
		if err != nil || s == "" {
			return err
		}
		i, err := strconv.Atoi(s)
		if err != nil || i < 1 || i > len(items) {
			ui.Println("无效编号。")
			continue
		}
		it := items[i-1]
		if (it.Status == server.TaskPending || it.Status == server.TaskRunning) && time.Now().Before(it.ExpiresAt) {
			if watch, err := ui.Confirm("该任务仍在进行（可能是另一个会话在运行）。先实时查看进度？", true); err != nil {
				return err
			} else if watch {
				watchTask(ui, sess, it.ID)
			}
		}
		ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
		rep, err := sess.loadReport(ctx, it.ID)
		cancel()
		if err != nil {
			ui.Printf("读取报告失败：%v\n", err)
			continue
		}
		id := it.ID
		if err := reportMenu(ui, rep, sess.reportsDir(), func(ctx context.Context) (report.Report, error) { return sess.refreshASN(ctx, id) }); err != nil {
			return err
		}
	}
}

// watchTask polls a running task every two seconds until it ends or Ctrl+C.
func watchTask(ui *tui.UI, sess *clientSession, taskID string) {
	ctx, stop := notifyInterrupt()
	defer stop()
	ui.Println("每 2 秒刷新一次，Ctrl+C 停止查看（不会中断任务）。")
	last := ""
	_, err := sess.runner.Watch(ctx, taskID, 2*time.Second, func(v server.TaskView) {
		rec := 0
		for _, a := range v.Attempts {
			if a.Observation != nil || len(a.Client) > 0 {
				rec++
			}
		}
		line := fmt.Sprintf("状态：%s   已有记录 %d / %d", statusText[v.Status], rec, len(v.Attempts))
		if line != last {
			ui.Println(line)
			last = line
		}
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		ui.Printf("停止查看：%v\n", err)
	}
}

// clientReports implements `sniroute client reports [list|show|export|flush]`.
func clientReports(args []string) error {
	sub := "list"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		sub, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("client reports "+sub, flag.ContinueOnError)
	cfgPath := fs.String("config", client.DefaultConfigPath(), "client config file")
	dir := fs.String("dir", "", "export directory (default: report_dir, or current directory)")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	cfg, err := client.LoadConfig(*cfgPath)
	if err != nil {
		if errors.Is(err, client.ErrNoConfig) {
			return errors.New("not enrolled yet: run `sniroute client` first")
		}
		return err
	}
	sess, err := openSession(*cfgPath, cfg)
	if err != nil {
		return err
	}
	defer sess.close()
	ui := tui.New(os.Stdin, os.Stdout)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	switch sub {
	case "list":
		items, err := sess.listReports(ctx)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			ui.Println("还没有历史任务。")
			return nil
		}
		ui.Table(taskRows(items, nil))
	case "asn":
		if fs.NArg() != 1 {
			return errors.New("usage: sniroute client reports asn TASK_ID")
		}
		rep, err := sess.refreshASN(ctx, fs.Arg(0))
		if err != nil {
			return err
		}
		ui.Printf("快照 %d/%d：%s\n", rep.ASN.Snapshot, rep.ASN.Snapshots, rep.Overview.ASN)
		return report.WriteGroups(ui.Writer(), rep)
	case "flush":
		d, rem, err := sess.runner.Flush(ctx, "")
		ui.Printf("已补交 %d 条，剩余 %d 条\n", d, rem)
		return err
	case "show", "export":
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: sniroute client reports %s TASK_ID", sub)
		}
		rep, err := sess.loadReport(ctx, fs.Arg(0))
		if err != nil {
			return err
		}
		if sub == "show" {
			return report.WriteText(ui.Writer(), rep)
		}
		out := *dir
		if out == "" {
			out = sess.reportsDir()
		}
		files, err := report.Export(out, rep)
		if err != nil {
			return err
		}
		if md, err := report.ExportMarkdown(out, rep); err == nil {
			files = append(files, md)
		}
		for _, f := range files {
			ui.Println(f)
		}
	default:
		return fmt.Errorf("unknown reports command %q (want list, show, export, asn or flush)", sub)
	}
	return nil
}

// reorderFlags moves flags before positional arguments so `show ID -config X`
// works with the standard flag package.
func reorderFlags(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			if !containsEq(a) && i+1 < len(args) && len(args[i+1]) > 0 && args[i+1][0] != '-' {
				i++
				flags = append(flags, args[i])
			}
		} else {
			pos = append(pos, a)
		}
	}
	return append(flags, pos...)
}

func containsEq(s string) bool {
	for _, c := range s {
		if c == '=' {
			return true
		}
	}
	return false
}

func notifyInterrupt() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// refreshASN creates a NEW egress-network snapshot (older ones stay as they
// were) and rebuilds the report.
func (s *clientSession) refreshASN(ctx context.Context, taskID string) (report.Report, error) {
	_, enabled, err := s.runner.CC.ASN(ctx, s.cfg.Path, s.cfg.NodeKey, taskID, true)
	if err != nil {
		return report.Report{}, err
	}
	if !enabled {
		return report.Report{}, errors.New("观测端未启用出口网络查询")
	}
	return s.loadReport(ctx, taskID)
}
