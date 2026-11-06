package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/nyktios/sniroute/internal/analysis"
)

// A narrow reading layer precedes the archival details. It uses ordinary
// Markdown so reports work in terminal viewers and on small screens.
func writeMarkdownResults(w io.Writer, r Report) {
	fmt.Fprintf(w, "> %s\n\n", mdText(conditionLine(r)))
	s := summarizeEgress(r)
	fmt.Fprintf(w, "## 出口整理\n\n**分流判断：**%s\n\n**SNI 出口一致性：**%s\n\n**出口 IP：共 %d 个**\n\n", mdText(s.Split), mdText(s.Consistency), s.IPCount)
	for i, e := range s.Exits {
		fmt.Fprintf(w, "### 出口 %d · %s\n\n", i+1, mdText(e.IP))
		categories := strings.Join(e.Categories, "、")
		if categories == "" {
			categories = "未在域名分类中观测到"
		}
		fmt.Fprintf(w, "- **ASN：**%s\n- **归属地：**%s\n- **观测分类：**%s\n\n", mdText(e.Networks), mdText(e.Location), mdText(categories))
	}
	fmt.Fprint(w, "## 分类探测结果\n\n")
	for _, gr := range r.Judgments.Groups {
		g := gr.Group
		for _, c := range categoriesFor(r, gr) {
			fmt.Fprintf(w, "#### %s（%d）\n\n", mdText(c.Name), len(c.Indices))
			var rows [][]string
			for _, i := range c.Indices {
				d, j := g.Domains[i], gr.Domains[i]
				ips := analysis.SortedIPs(d.IPs)
				if len(ips) == 0 && j.Probe != analysis.ProbeNone {
					rows = append(rows, []string{domainSymbol(j, d) + " " + d.SNI + " · 连通失败", "-", "-"})
					continue
				}
				if len(ips) == 0 {
					ips = []string{"未观测"}
				}
				rows = append(rows, []string{domainSymbol(j, d) + " " + d.SNI, strings.Join(ips, "；"), domainNetworks(j)})
			}
			mdTable(w, []string{"域名", "受控探测出口", "Origin ASN / 组织"}, rows)
			fmt.Fprint(w, "\n")
		}
	}
	fmt.Fprint(w, "● 受控探测完整成功 · ◆ 探测成功但多次出口不一致 · △ 异常 / 部分证据 · ○ 探测未执行。\n\n")
	o := r.Overview
	fmt.Fprintf(w, "## 结果摘要\n\n**探测成功 %d · 探测失败 %d · 出口 IP 数 %d**\n\n", o.Authenticated, incompleteAuthentication(r), o.DistinctEgressIPs)
	fmt.Fprint(w, "## 受控探测出口分布\n\n")
	for _, g := range r.Egress {
		total := 0
		for _, e := range g.Rows {
			total += e.Count
		}
		if total == 0 {
			fmt.Fprint(w, "未观测到可用出口。\n\n")
			continue
		}
		var rows [][]string
		for _, e := range g.Rows {
			rows = append(rows, []string{e.IP, networkText(e.Networks, e.ASNStatus), fmt.Sprint(e.Count), fmt.Sprintf("%.1f%%", 100*float64(e.Count)/float64(total))})
		}
		mdTable(w, []string{"出口 IP", "Origin ASN / 组织", "观测次数", "占比"}, rows)
	}
}
