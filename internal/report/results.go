package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nyktios/sniroute/internal/analysis"
	"github.com/nyktios/sniroute/internal/server"
	"github.com/nyktios/sniroute/internal/tui"
	"golang.org/x/term"
)

// resultsLayout uses terminal styling only on an interactive output. Files and
// redirected output remain plain text, with the same labels and evidence.
type resultsLayout struct {
	*tw
	width int
	color bool
}

func newResultsLayout(w io.Writer) *resultsLayout {
	l := &resultsLayout{tw: &tw{w: w}, width: 100}
	if f, ok := w.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		if width, _, err := term.GetSize(int(f.Fd())); err == nil && width > 0 {
			l.width = width
		}
		l.color = tui.ColorEnabled(w)
	}
	return l
}

func (l *resultsLayout) paint(s, role string) string {
	if !l.color {
		return s
	}
	code := map[string]string{"title": "1;36", "muted": "90", "success": "32", "warning": "33"}[role]
	if code == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// wrapCells preserves all text, including full IPv6 addresses and long hosts.
func wrapCells(s string, width int) []string {
	width = max(width, 1)
	var out []string
	var line strings.Builder
	n := 0
	for _, r := range s {
		size := cellWidth(string(r))
		if n+size > width && n > 0 {
			out = append(out, line.String())
			line.Reset()
			n = 0
		}
		line.WriteRune(r)
		n += size
	}
	if line.Len() > 0 {
		out = append(out, line.String())
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

func (l *resultsLayout) line(s, role string) {
	for _, line := range wrapCells(clean(s), l.width) {
		l.printf("%s\n", l.paint(line, role))
	}
}

func (l *resultsLayout) section(s string) { l.printf("\n"); l.line("▌ "+s, "title") }

func (l *resultsLayout) centered(s, role string) {
	for _, line := range wrapCells(clean(s), l.width) {
		l.printf("%s%s\n", strings.Repeat(" ", max(0, (l.width-cellWidth(line))/2)), l.paint(line, role))
	}
}

func conditionLine(r Report) string {
	privacy := "完整 IP"
	if r.IPDisplay == "masked" {
		privacy = "IP 脱敏"
	}
	parts := []string{familyList(r.Overview.Targets)}
	if fragmentExperiment(r) {
		parts = append(parts, "实验：TLS record 分片（"+fragmentPosition(r)+"）")
	}
	p := paramsOf(r)
	if proxy, ok := p["proxy"].(string); ok && strings.HasPrefix(proxy, "none") {
		parts = append(parts, "无显式代理")
	}
	parts = append(parts, fmt.Sprintf("%d 次计划探测", r.Overview.Planned))
	if workers := anyString(p["concurrency"]); workers != "" {
		parts = append(parts, workers+" 并发")
	}
	return strings.Join(append(parts, privacy), " · ")
}

func domainNetworks(j analysis.Judgment) string {
	var names []string
	for _, name := range j.Networks {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "ASN 暂缺"
	}
	return strings.Join(names, " / ")
}

func (l *resultsLayout) domainRow(symbol, host, ip, meta string, hostWidth, ipWidth int) {
	left := symbol + " " + clean(host)
	ip, meta = clean(ip), clean(meta)
	role := "warning"
	if symbol == "●" {
		role = "success"
	} else if symbol == "○" {
		role = "muted"
	}
	// One shared grid for the entire comparison group; stack when a row does
	// not fit, rather than truncating an address or shifting later categories.
	if hostWidth+ipWidth+6+cellWidth(meta) <= l.width {
		l.printf("%s%s  %s%s  %s\n", l.paint(left, role), strings.Repeat(" ", hostWidth-cellWidth(left)), ip, strings.Repeat(" ", ipWidth-cellWidth(ip)), l.paint(meta, "muted"))
		return
	}
	l.line(left, role)
	l.indent("出口 "+ip, "")
	l.indent(meta, "muted")
}

func (l *resultsLayout) indent(s, role string) {
	for _, line := range wrapCells(clean(s), max(1, l.width-2)) {
		l.printf("  %s\n", l.paint(line, role))
	}
}

func (l *resultsLayout) domains(r Report) {
	for _, gr := range r.Judgments.Groups {
		g := gr.Group
		l.section("分类探测结果 · " + Family(g.Target))
		if g.BaselinePlanned == 0 {
			l.line("基线未测试，无法比较出口。", "warning")
		} else {
			l.line(fmt.Sprintf("基线 %s · 观测 %d/%d · 失败 %d", IPList(g.BaselineIPs), g.BaselineObserved, g.BaselinePlanned, gr.Baseline.Failed), "muted")
		}
		hostWidth, ipWidth := 0, 0
		for _, d := range g.Domains {
			hostWidth = max(hostWidth, cellWidth("● "+clean(d.SNI)))
			for _, ip := range analysis.SortedIPs(d.IPs) {
				ipWidth = max(ipWidth, cellWidth(clean(ip)))
			}
		}
		ipWidth = max(ipWidth, cellWidth("连通失败"))
		for _, category := range categoriesFor(r, gr) {
			l.printf("\n")
			l.line(fmt.Sprintf("%s（%d）", category.Name, len(category.Indices)), "muted")
			for _, i := range category.Indices {
				d, j := g.Domains[i], gr.Domains[i]
				ips := analysis.SortedIPs(d.IPs)
				if len(ips) == 0 && j.Probe != analysis.ProbeNone {
					l.domainRow(domainSymbol(j, d), d.SNI, "连通失败", "- · -", hostWidth, ipWidth)
					continue
				}
				if len(ips) == 0 {
					ips = []string{"未观测"}
				}
				for k, ip := range ips {
					if k == 0 {
						l.domainRow(domainSymbol(j, d), d.SNI, ip, domainNetworks(j), hostWidth, ipWidth)
					} else {
						l.domainRow("↳", "", ip, "同一域名的其他出口", hostWidth, ipWidth)
					}
				}
			}
		}
	}
	l.printf("\n")
	l.line("● 受控探测完整成功 · ◆ 探测成功但多次出口不一致 · △ 异常/部分证据 · ○ 探测未执行", "muted")
}

func (l *resultsLayout) summary(r Report) {
	o := r.Overview
	l.section("结果摘要")
	l.line(fmt.Sprintf("探测成功 %d · 探测失败 %d · 出口 IP 数 %d", o.Authenticated, incompleteAuthentication(r), o.DistinctEgressIPs), "title")
}

func (l *resultsLayout) distribution(r Report) {
	l.section("受控探测出口分布")
	for _, g := range r.Egress {
		total := 0
		for _, e := range g.Rows {
			total += e.Count
		}
		if total == 0 {
			l.line("未观测到可用出口；不推定默认出口。", "muted")
			continue
		}
		for _, e := range g.Rows {
			pct := 100 * float64(e.Count) / float64(total)
			bar := strings.Repeat("█", max(1, 12*e.Count/total))
			meta := clean(fmt.Sprintf("%d 次 · %.1f%% · %s · %s", e.Count, pct, e.IP, networkText(e.Networks, e.ASNStatus)))
			if cellWidth(meta)+16 <= l.width {
				l.printf("%s%s  %s\n", l.paint(bar, "success"), strings.Repeat(" ", 12-cellWidth(bar)), meta)
			} else {
				l.line(meta, "")
			}
		}
	}
}

// WriteResults is the concise first reading layer for SSH and report previews.
func WriteResults(w io.Writer, r Report) error {
	l := newResultsLayout(w)
	l.centered("SniRoute · 服务商出口分流探测", "title")
	l.centered("https://github.com/obrdx/SniRoute", "muted")
	l.printf("\n")
	l.line(conditionLine(r), "muted")
	if fragmentExperiment(r) {
		l.line(FragmentExperimentNotice, "warning")
	}
	if identityMismatchCount(r) > 0 {
		l.section("端点身份异常提示")
		l.line(analysis.EndpointIdentityNotice, "warning")
	}
	l.egressSummary(r)
	l.domains(r)
	l.summary(r)
	l.distribution(r)
	return l.err
}

func identityMismatchCount(r Report) int {
	n := 0
	for _, a := range r.Evidence {
		for _, c := range a.Client {
			if c.Outcome == "identity_mismatch" {
				n++
				break
			}
		}
	}
	return n
}

func incompleteAuthentication(r Report) int {
	n := 0
	for _, a := range r.Evidence {
		if hasFact(a) && a.State != server.StateAuthenticated && a.State != server.StateCancelled {
			n++
		}
	}
	return n
}
