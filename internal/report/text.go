package report

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nyktios/sniroute/internal/analysis"
	"github.com/nyktios/sniroute/internal/server"
)

// Labels (Chinese) for the enumerations.
var (
	EgressLabel = map[analysis.Egress]string{
		analysis.SameAsBaseline:        "与基线一致",
		analysis.DynamicPool:           "动态出口池（未证明域名关联）",
		analysis.DifferentFromBaseline: "其他出口（与基线不同）",
		analysis.Mixed:                 "出口混合（部分与基线相同）",
		analysis.NoBaseline:            "无基线可比",
		analysis.Unobserved:            "未观测",
	}
	StateLabel = map[server.AttemptState]string{
		server.StatePending:       "等待中",
		server.StateAuthenticated: "认证回执",
		server.StateSNIMismatch:   "SNI 不符",
		server.StateHelloMatched:  "仅握手匹配",
		server.StateHelloAmbig:    "握手匹配有歧义",
		server.StateUnobserved:    "观测端未收到",
		server.StateTimeout:       "无记录",
		server.StateCancelled:     "已取消（未执行）",
	}
	ProbeLabel = map[analysis.ProbeStatus]string{
		analysis.ProbeNone:         "未执行",
		analysis.ProbeFull:         "完整成功",
		analysis.ProbeMixed:        "部分成功",
		analysis.ProbeHelloOnly:    "仅 ClientHello 到达",
		analysis.ProbeHandshakeErr: "握手异常（观测端未见）",
		analysis.ProbeIdentity:     "身份不匹配",
		analysis.ProbePreHello:     "发出 ClientHello 前失败",
	}
	LevelLabel = map[analysis.Level]string{
		analysis.LevelNone: "无足够迹象", analysis.LevelSuspected: "疑似", analysis.LevelStrong: "较强迹象", analysis.LevelExplicit: "明确阻断响应",
	}
	CompleteLabel = map[analysis.Completeness]string{
		analysis.Complete: "完整", analysis.Partial: "部分完成", analysis.MissingControl: "控制数据缺失", analysis.Cancelled: "已取消",
	}
	ConfLabel = map[analysis.Confidence]string{
		analysis.ConfNone: "—", analysis.ConfLow: "低", analysis.ConfMedium: "中", analysis.ConfHigh: "高",
	}
	StatusLabel = map[string]string{
		"pending": "等待中", "running": "进行中", "completed": "已完成", "aborted": "已中断（部分结果）", "failed": "失败",
	}
)

// clean makes any externally supplied string safe to print: control and
// non-ASCII-control characters become '.', and the length is bounded.
func clean(s string) string {
	if len(s) > 400 {
		// Cut on a rune boundary: slicing bytes would leave a partial UTF-8
		// sequence, which shows up as a replacement character in the output.
		cut := 400
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return '.'
		}
		return r
	}, s)
}

func ts(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05") }

func tsp(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return ts(*t)
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

type tw struct {
	w   io.Writer
	err error
}

func (t *tw) printf(format string, a ...any) {
	if t.err == nil {
		_, t.err = fmt.Fprintf(t.w, format, a...)
	}
}

func (t *tw) rule() { t.printf("%s\n", strings.Repeat("─", 46)) }

// cellWidth counts CJK wide characters and ignores combining marks.
func cellWidth(s string) int {
	n := 0
	for _, r := range s {
		if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) {
			continue
		}
		n++
		if r >= 0x1100 && (r <= 0x115f || r == 0x2329 || r == 0x232a || r >= 0x2e80 && r <= 0xa4cf && r != 0x303f || r >= 0xac00 && r <= 0xd7a3 || r >= 0xf900 && r <= 0xfaff || r >= 0xfe10 && r <= 0xfe19 || r >= 0xfe30 && r <= 0xfe6f || r >= 0xff00 && r <= 0xff60 || r >= 0xffe0 && r <= 0xffe6 || r >= 0x20000 && r <= 0x3fffd) {
			n++
		}
	}
	return n
}

func (t *tw) table(rows [][]string) {
	if len(rows) == 0 {
		return
	}
	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for i, cell := range row {
			if i >= len(widths) {
				widths = append(widths, 0)
			}
			widths[i] = max(widths[i], cellWidth(clean(cell)))
		}
	}
	for _, row := range rows {
		for i, cell := range row {
			cell = clean(cell)
			t.printf("%s", cell)
			if i < len(row)-1 {
				t.printf("%s", strings.Repeat(" ", widths[i]-cellWidth(cell)+2))
			}
		}
		t.printf("\n")
	}
}

// ASNStatusLabel explains why an egress IP has no network name.
var ASNStatusLabel = map[string]string{
	"ok": "", "no_data": "无公告数据", "failed": "查询失败", "skipped_nonpublic": "非公网地址，未查询", "not_queried": "未查询",
}

func networkText(nets []string, status string) string {
	if len(nets) > 0 {
		return strings.Join(nets, "；")
	}
	if s := ASNStatusLabel[status]; s != "" {
		return s
	}
	return "—"
}

// IPList renders "ip×count" pairs, most frequent first.
func IPList(m map[string]int) string {
	var parts []string
	for _, ip := range analysis.SortedIPs(m) {
		parts = append(parts, fmt.Sprintf("%s×%d", ip, m[ip]))
	}
	return dash(strings.Join(parts, "  "))
}

// WriteText writes the full report: overview, egress groups, per-domain
// judgments with their basis and limits, incomplete attempts and the notes.
func WriteText(w io.Writer, r Report) error {
	if err := WriteResults(w, r); err != nil {
		return err
	}
	t := &tw{w: w}
	writeOverview(t, r)
	writeEgress(t, r)
	writeRules(t, r)
	writeIncomplete(t, r)
	writeNotes(t, r)
	return t.err
}

func writeOverview(t *tw, r Report) {
	o, k := r.Overview, r.Task
	t.printf("\n测试报告\n")
	if r.IPDisplay == "masked" {
		t.printf("出口 IP：脱敏展示；出口编号用于区分不同 IP，完整证据保留在数据库。\n")
	}
	t.rule()
	t.printf("任务 %s   状态：%s   规则版本：%s\n", clean(k.ID), StatusLabel[k.Status], clean(r.RulesVersion))
	t.printf("节点：%s   服务商标签：%s   生成时间：%s\n", dash(clean(k.NodeName)), dash(clean(k.ProviderLabel)), ts(r.GeneratedAt))
	t.printf("创建：%s   取消：%s\n", ts(k.CreatedAt), tsp(k.CancelledAt))
	if p := paramsOf(r); p != nil {
		t.printf("测试条件：轮数 %v  并发 %v  超时 %vms  种子 %v  环境说明：%s\n",
			p["rounds"], p["concurrency"], p["timeout_ms"], p["seed"], dash(clean(fmt.Sprint(p["env_note"]))))
	}
	t.printf("\n覆盖：计划 %d   已有记录 %d   无记录 %d   已取消 %d\n", o.Planned, o.Executed, o.Unrun, o.Cancelled)
	t.printf("证据：认证回执 %d   仅握手匹配 %d   握手有歧义 %d   SNI 不符 %d   观测端未收到 %d\n", o.Authenticated, o.HelloMatched, o.HelloAmbiguous, o.SNIMismatch, o.Unobserved)
	t.printf("完整性：%s    出口 IP 数：%d\n", CompleteLabel[o.Completeness], o.DistinctEgressIPs)
	t.printf("出口差异的域名：%s\n", clean(dash(strings.Join(o.DifferentEgress, "、"))))
	t.printf("动态出口 / 出口混合：%s\n", clean(dash(strings.Join(o.DynamicPool, "、"))))
	t.printf("干预判断 — 疑似：%s；较强迹象：%s\n", clean(dash(strings.Join(o.Suspected, "、"))), clean(dash(strings.Join(o.Strong, "、"))))
	if len(o.Uncertain) > 0 {
		t.printf("不确定项：\n")
		for _, u := range o.Uncertain {
			t.printf("  · %s\n", clean(u))
		}
	}
	t.printf("出口网络：%s\n", clean(dash(strings.Join(o.Networks, "；"))))
	t.printf("出口网络归属查询：%s\n", o.ASN)
}

func writeEgress(t *tw, r Report) {
	for _, g := range r.Egress {
		t.printf("\n出口汇总（%s）\n", g.Family)
		rows := [][]string{{"出口 IP", "Origin ASN / 组织", "归属地", "观测次数"}}
		for _, e := range g.Rows {
			rows = append(rows, []string{e.IP, networkText(e.Networks, e.ASNStatus), locationOrUnknown(e.Location), fmt.Sprint(e.Count)})
		}
		if len(g.Rows) == 0 {
			t.printf("  没有可用的出口观测。\n")
			continue
		}
		t.table(rows)
	}
}

func writeDomains(t *tw, r Report) {
	if t.err != nil {
		return
	}
	l := newResultsLayout(t.w)
	l.domains(r)
	t.err = l.err
}

func writeRules(t *tw, r Report) {
	first := true
	for _, gr := range r.Judgments.Groups {
		for _, j := range gr.Domains {
			if len(j.Rules) == 0 {
				continue
			}
			if first {
				t.printf("\n判断依据与限制\n")
				t.rule()
				first = false
			}
			t.printf("%s（%s）  事实可信度：%s   原因判断可信度：%s\n", clean(j.SNI), Family(j.Target), ConfLabel[j.FactConfidence], ConfLabel[j.CauseConfidence])
			for _, h := range j.Rules {
				t.printf("  [%s] %s\n", clean(h.ID), clean(h.Conclusion))
				for _, b := range h.Basis {
					t.printf("      依据：%s\n", clean(b))
				}
				for _, l := range h.Limits {
					t.printf("      限制：%s\n", clean(l))
				}
			}
		}
	}
}

func lastClient(a server.AttemptView) (server.ClientEventView, bool) {
	if n := len(a.Client); n > 0 {
		return a.Client[n-1], true
	}
	return server.ClientEventView{}, false
}

func writeIncomplete(t *tw, r Report) {
	var bad [][]string
	for _, a := range r.Evidence {
		c, ok := lastClient(a)
		if !ok || c.Outcome == "receipt" {
			continue
		}
		kind := "域名"
		if a.Kind == "baseline" {
			kind = "基线"
		}
		bad = append(bad, []string{kind, a.SNI, fmt.Sprint(a.Round), c.Outcome + "@" + c.Stage, StateLabel[a.State]})
	}
	if len(bad) == 0 {
		return
	}
	t.printf("\n未完成认证回执的尝试（%d）：\n", len(bad))
	shown := bad
	if len(shown) > 30 {
		shown = shown[:30]
	}
	t.table(append([][]string{{"类型", "域名", "轮", "客户端结果", "探测状态"}}, shown...))
	if len(bad) > len(shown) {
		t.printf("…另有 %d 条，见单域名详细证据或 JSON 导出。\n", len(bad)-len(shown))
	}
}

func writeNotes(t *tw, r Report) {
	t.printf("\n说明：\n")
	for _, n := range r.Notes {
		t.printf(" · %s\n", n)
	}
}

// WriteGroups writes only the egress groups ("按出口 IP 分组查看").
func WriteGroups(w io.Writer, r Report) error {
	t := &tw{w: w}
	writeEgress(t, r)
	t.printf("\n出口网络归属查询：%s\n", r.Overview.ASN)
	return t.err
}

// WriteDomainTable writes only the per-domain judgment tables.
func WriteDomainTable(w io.Writer, r Report) error {
	t := &tw{w: w}
	writeDomains(t, r)
	t.printf("\n干预判断见完整报告的判断依据与限制。\n")
	return t.err
}

// WriteAnomalies writes domains whose controlled probes are abnormal,
// with the rules that explain them.
func WriteAnomalies(w io.Writer, r Report) error {
	t := &tw{w: w}
	n := 0
	for _, gr := range r.Judgments.Groups {
		for _, j := range gr.Domains {
			if j.Probe == analysis.ProbeFull || j.Probe == analysis.ProbeNone {
				continue
			}
			n++
			t.printf("\n%s（%s）  受控探测：%s   干预判断：%s\n", clean(j.SNI), Family(j.Target), ProbeLabel[j.Probe], LevelLabel[j.Intervention])
			for _, h := range j.Rules {
				t.printf("  [%s] %s\n", clean(h.ID), clean(h.Conclusion))
				for _, l := range h.Limits {
					t.printf("      限制：%s\n", clean(l))
				}
			}
		}
	}
	if n == 0 {
		t.printf("没有受控探测异常的域名。\n")
	}
	return t.err
}

// WriteDomain writes every recorded fact about one domain. It reports whether
// the domain exists in the report.
func WriteDomain(w io.Writer, r Report, sni string) (bool, error) {
	t := &tw{w: w}
	rows := [][]string{{"轮", "类型", "客户端结果", "耗时(ms)", "观测端状态", "来源 IP", "证据", "握手摘要已报", "错误"}}
	for _, a := range r.Evidence {
		if !strings.EqualFold(a.SNI, sni) {
			continue
		}
		cl, dur, hello, msg := "—", "—", "否", ""
		if c, ok := lastClient(a); ok {
			cl, dur, msg = c.Outcome+"@"+c.Stage, fmt.Sprint(c.DurationMS), hideObserverText(r, c.Error)
			if c.HelloSent {
				hello = "是"
			}
		}
		ip, ev := "未观测", "—"
		if o := a.Observation; o != nil {
			ev = o.Evidence
			if o.SourceIP != "" {
				ip = o.SourceIP
			}
		}
		rows = append(rows, []string{fmt.Sprint(a.Round), a.Kind, cl, dur, StateLabel[a.State], ip, ev, hello, msg})
	}
	if len(rows) == 1 {
		return false, nil
	}
	t.table(rows)

	for _, gr := range r.Judgments.Groups {
		for _, j := range gr.Domains {
			if !strings.EqualFold(j.SNI, sni) || len(j.Rules) == 0 {
				continue
			}
			t.printf("\n采用的规则（%s，%s）：\n", Family(j.Target), r.RulesVersion)
			for _, h := range j.Rules {
				t.printf("  [%s] %s\n", clean(h.ID), clean(h.Conclusion))
			}
		}
	}
	return true, t.err
}

// WriteOverview writes only the first reading layer.
func WriteOverview(w io.Writer, r Report) error {
	t := &tw{w: w}
	writeOverview(t, r)
	return t.err
}
