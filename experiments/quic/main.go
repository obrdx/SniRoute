// Standalone QUIC experiment. This nested module never changes the production
// sniroute dependency graph, listener configuration, task store or reports.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const usage = `SniRoute 独立 QUIC/SNI 实验
  sniroute-quic server -target IP:443 [-listen :443] [-dir DIR] [-ttl 30m]
  sniroute-quic client -config client.json -sni DOMAIN [-sni DOMAIN ...] [-sni-file FILE] [-rounds 3] [-timeout 8s] [-out REPORT.json]
  sniroute-quic version
UDP 443 与正式版 TCP 443 可同时监听；须单独放行 UDP。结果不能替代普通 TCP/TLS 的出口。
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); stop() }() // a second signal restores normal forced exit
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "实验未完成：", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(output, usage)
		return nil
	}
	switch args[0] {
	case "server":
		return runServer(ctx, args[1:], output)
	case "client":
		return runClient(ctx, args[1:], output)
	case "version":
		fmt.Fprintln(output, applicationVersion)
		return nil
	case "help", "-h", "--help":
		fmt.Fprint(output, usage)
		return nil
	default:
		return errors.New("未知实验命令，请使用 server、client 或 -h")
	}
}

func runServer(ctx context.Context, args []string, output io.Writer) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(output)
	target := fs.String("target", "", "观测端公网 IP:端口，用于生成客户端配置")
	listen := fs.String("listen", ":443", "UDP 监听地址")
	dir := fs.String("dir", "./quic-state", "实验目录（权限 0700），与正式版目录分开")
	ttl := fs.Duration("ttl", 30*time.Minute, "实验凭证有效期，1 分钟到 2 小时")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *ttl < time.Minute || *ttl > 2*time.Hour {
		return errors.New("参数无效：ttl 须在 1 分钟到 2 小时之间")
	}
	cfg, cert, err := newIdentity(*target, time.Now().UTC().Add(*ttl))
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if err := privateDir(*dir); err != nil {
		return err
	}
	pc, err := net.ListenPacket("udp", *listen)
	if err != nil {
		return fmt.Errorf("无法监听 UDP：%w；请检查端口占用、权限及地址", err)
	}
	defer pc.Close()
	log, err := observationLog(filepath.Join(*dir, "observations.jsonl"))
	if err != nil {
		return err
	}
	defer log.Close()
	obs := &observer{cfg: cfg, seen: map[string]bool{}, log: log}
	srv, tr, ln, err := listenObserver(pc, cert, obs)
	if err != nil {
		return err
	}
	defer tr.Close()
	defer ln.Close()
	defer srv.Close()
	configPath := filepath.Join(*dir, "client.json")
	if err := writePrivateJSON(configPath, cfg); err != nil {
		return err
	}
	fmt.Fprintf(output, "QUIC 观测端运行中：UDP %s\n客户端配置：%s（含短期凭证，请私下复制到被测端，勿发送给助手）\n凭证有效至：%s\n保持本窗口运行；退出只停止本实验，不影响正式版 TCP 服务。\n", pc.LocalAddr(), configPath, cfg.ExpiresAt.Local().Format(time.RFC3339))
	serveCtx, cancel := context.WithDeadline(ctx, cfg.ExpiresAt)
	defer cancel()
	stop := context.AfterFunc(serveCtx, func() { srv.Close(); ln.Close(); tr.Close() })
	defer stop()
	err = srv.ServeListener(ln)
	if serveCtx.Err() != nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type sniFlags []string

func (s *sniFlags) String() string         { return strings.Join(*s, ",") }
func (s *sniFlags) Set(value string) error { *s = append(*s, value); return nil }

type experimentReport struct {
	ApplicationVersion string    `json:"application_version"`
	Experiment         string    `json:"experiment"`
	Protocol           string    `json:"protocol"`
	ALPN               string    `json:"alpn"`
	ServerRetry        bool      `json:"server_retry"`
	ConnectionReuse    bool      `json:"connection_reuse"`
	SessionResumption  bool      `json:"session_resumption"`
	TCPFallback        bool      `json:"tcp_fallback"`
	StartedAt          time.Time `json:"started_at"`
	Target             string    `json:"target"`
	SNIs               []string  `json:"snis"`
	Rounds             int       `json:"rounds"`
	Seed               uint64    `json:"seed"`
	TimeoutMS          int64     `json:"timeout_ms"`
	Planned            int       `json:"planned"`
	Cancelled          bool      `json:"cancelled"`
	Results            []result  `json:"results"`
	Limitations        []string  `json:"limitations"`
}

func runClient(ctx context.Context, args []string, output io.Writer) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.SetOutput(output)
	config := fs.String("config", "./client.json", "从实验观测端复制的配置文件，权限 0600")
	file := fs.String("sni-file", "", "一行一个域名的清单")
	rounds := fs.Int("rounds", 3, "独立连接轮数，1 到 10；总尝试数不超过 4000")
	timeout := fs.Duration("timeout", 8*time.Second, "每次探测超时，1 到 30 秒")
	out := fs.String("out", "", "JSON 报告，默认当前目录自动命名")
	var snis sniFlags
	fs.Var(&snis, "sni", "目标 SNI，可重复；只连接配置中的固定观测端")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *rounds < 1 || *rounds > 10 || *timeout < time.Second || *timeout > 30*time.Second {
		return errors.New("轮数或超时无效，请查看 client -h")
	}
	if *file != "" {
		f, err := os.Open(*file)
		if err != nil {
			return err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || st.Size() > 1<<20 {
			return errors.New("域名文件不能超过 1 MiB")
		}
		scanner := bufio.NewScanner(io.LimitReader(f, 1<<20))
		for scanner.Scan() {
			snis = append(snis, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return errors.New("无法读取域名清单")
		}
	}
	var domains []string
	seen := map[string]bool{}
	for _, entry := range snis {
		if strings.TrimSpace(entry) == "" || strings.HasPrefix(strings.TrimSpace(entry), "#") {
			continue
		}
		sni, err := cleanSNI(entry)
		if err != nil {
			return fmt.Errorf("域名清单含无效 SNI：%w", err)
		}
		if !seen[sni] {
			seen[sni] = true
			domains = append(domains, sni)
		}
	}
	if len(domains) == 0 || len(domains)**rounds > 4000 {
		return errors.New("请显式指定 SNI；总尝试数须为 1 到 4000")
	}
	cfg, err := loadConfig(*config)
	if err != nil {
		return err
	}
	var seedBytes [8]byte
	if _, err := rand.Read(seedBytes[:]); err != nil {
		return err
	}
	seed := binary.LittleEndian.Uint64(seedBytes[:])
	shuffle := mrand.New(mrand.NewPCG(seed, seed^0xd1b54a32d192ed03))
	rep := experimentReport{ApplicationVersion: applicationVersion, Experiment: "quic-sni", Protocol: "QUIC v1 / TLS 1.3 / UDP", ALPN: "h3", ServerRetry: true, StartedAt: time.Now().UTC(),
		Target: cfg.Target, SNIs: domains, Rounds: *rounds, Seed: seed, TimeoutMS: timeout.Milliseconds(),
		Planned: len(domains) * *rounds, Results: []result{}, Limitations: limitations}
	last := map[string]time.Time{}
	fmt.Fprintf(output, "QUIC/SNI 独立实验：%d 个域名 × %d 轮；只使用 UDP，无 TCP 回退。\n", len(domains), *rounds)
testing:
	for round := 1; round <= *rounds; round++ {
		order := append([]string(nil), domains...)
		shuffle.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		for _, sni := range order {
			if ctx.Err() != nil {
				break testing
			}
			if gap := time.Until(last[sni].Add(2 * time.Second)); gap > 0 {
				timer := time.NewTimer(gap)
				select {
				case <-ctx.Done():
					timer.Stop()
					break testing
				case <-timer.C:
				}
			}
			last[sni] = time.Now()
			res := probeQUIC(ctx, cfg, sni, round, *timeout)
			rep.Results = append(rep.Results, res)
			ip := "未观测"
			if res.Outcome == "receipt" {
				ip = res.Receipt.SourceIP
			}
			fmt.Fprintf(output, "[%d/%d] 轮%d %-30s %-18s %s\n", len(rep.Results), rep.Planned, round, sni, res.Outcome, ip)
			if res.Error != "" {
				fmt.Fprintf(output, "  %s\n", strings.Map(func(r rune) rune {
					if r < 32 || r == 127 || (r >= 128 && r < 160) {
						return '.'
					}
					return r
				}, res.Error))
			}
			if res.Outcome == "auth_failed" {
				fmt.Fprintln(output, "实验认证失败，停止新增尝试；剩余项为未执行，不作网络异常判定。")
				break testing
			}
		}
	}
	rep.Cancelled = ctx.Err() != nil
	writeSummary(output, rep)
	if *out == "" {
		id, err := randomHex(6)
		if err != nil {
			return err
		}
		*out = "quic-" + id + "-report.json"
	}
	if err := writePrivateJSON(*out, rep); err != nil {
		return fmt.Errorf("结果已显示，但报告保存失败：%w", err)
	}
	fmt.Fprintln(output, "JSON 报告：", *out)
	return nil
}

func writeSummary(w io.Writer, rep experimentReport) {
	fmt.Fprintln(w, "\nQUIC 认证出口汇总（不代表 TCP 或真实网站出口）")
	for _, sni := range rep.SNIs {
		ips := map[string]int{}
		for _, r := range rep.Results {
			if r.SNI == sni && r.Outcome == "receipt" && r.Receipt != nil {
				ips[r.Receipt.SourceIP]++
			}
		}
		keys := make([]string, 0, len(ips))
		for ip := range ips {
			keys = append(keys, ip)
		}
		sort.Strings(keys)
		var counts []string
		for _, ip := range keys {
			counts = append(counts, fmt.Sprintf("%s × %d", ip, ips[ip]))
		}
		if len(counts) == 0 {
			counts = []string{"未观测"}
		}
		fmt.Fprintf(w, "%s：%s\n", sni, strings.Join(counts, "；"))
	}
	fmt.Fprintf(w, "计划 %d · 已有结果 %d · 未执行 %d · 已中断 %t\n", rep.Planned, len(rep.Results), rep.Planned-len(rep.Results), rep.Cancelled)
	for _, note := range rep.Limitations {
		fmt.Fprintln(w, "说明：", note)
	}
}
