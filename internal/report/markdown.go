package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nyktios/sniroute/internal/server"
)

// mdEsc escapes the characters that would otherwise be read as Markdown or
// HTML: the report is written to a file people open in a viewer, and a domain
// name or error message is not trusted markup.
func mdEsc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "|", "\\|").Replace(s)
}

// mdCell makes a value safe inside a Markdown table cell: newlines flattened,
// control characters (including terminal escapes) removed, then Markdown and
// HTML metacharacters escaped. It shares clean() with the text report.
func mdCell(s string) string {
	s = clean(strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " "))
	if s == "" {
		return "—"
	}
	return mdEsc(s)
}

// mdText escapes a value used in running text rather than a table cell.
func mdText(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return mdEsc(clean(strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " ")))
}

func mdTable(w io.Writer, head []string, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	fmt.Fprint(w, "|")
	for _, h := range head {
		fmt.Fprintf(w, " %s |", mdCell(h))
	}
	fmt.Fprint(w, "\n|")
	for range head {
		fmt.Fprint(w, " --- |")
	}
	fmt.Fprint(w, "\n")
	for _, r := range rows {
		fmt.Fprint(w, "|")
		for i := range head {
			c := ""
			if i < len(r) {
				c = r[i]
			}
			fmt.Fprintf(w, " %s |", mdCell(c))
		}
		fmt.Fprint(w, "\n")
	}
	fmt.Fprint(w, "\n")
}

func mdBullets(w io.Writer, items []string) {
	for _, it := range items {
		fmt.Fprintf(w, "- %s\n", mdText(it))
	}
	fmt.Fprint(w, "\n")
}

func mdList(items []string) string {
	if len(items) == 0 {
		return "—"
	}
	return strings.Join(items, "、")
}

// paramsOf decodes the frozen test conditions.
func paramsOf(r Report) map[string]any {
	var p map[string]any
	dec := json.NewDecoder(bytes.NewReader(r.Task.Params))
	dec.UseNumber()
	if dec.Decode(&p) != nil {
		return nil
	}
	return p
}

func anyString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		// Keep integral floats readable for callers with legacy decoded values.
		if t == math.Trunc(t) && math.Abs(t) > 1e15 {
			return strconv.FormatFloat(t, 'f', -1, 64)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	case bool:
		if t {
			return "是"
		}
		return "否"
	case []any:
		var out []string
		for _, x := range t {
			out = append(out, fmt.Sprint(x))
		}
		return strings.Join(out, "、")
	}
	return fmt.Sprint(v)
}

// WriteMarkdown writes the whole report as GitHub-flavoured Markdown: the same
// facts and caveats as the text report, in a form meant to be filed away.
// Every externally supplied string passes through mdCell/mdText, so a hostile
// SNI or error message cannot break the layout or inject HTML.
func WriteMarkdown(w io.Writer, r Report) error {
	o, k := r.Overview, r.Task

	fmt.Fprintf(w, "# SniRoute 测试报告 · %s\n\n", mdText(k.ID))
	fmt.Fprint(w, "[出口整理](#出口整理) · [分类结果](#分类探测结果) · [结果摘要](#结果摘要) · [出口分布](#受控探测出口分布) · [出口汇总](#二出口汇总) · [判断依据](#三判断依据与限制) · [说明](#四说明)\n\n")
	fmt.Fprintf(w, "> 生成时间 %s · 规则版本 `%s` · 报告格式 `%s`\n\n", ts(r.GeneratedAt), mdText(r.RulesVersion), mdText(r.Version))

	if r.IPDisplay == "masked" {
		fmt.Fprint(w, "> 出口 IP 已脱敏；出口编号用于区分不同 IP，完整证据保留在数据库。\n\n")
	}

	writeMarkdownResults(w, r)
	fmt.Fprint(w, "---\n\n## 详细报告\n\n")

	// ---------------------------------------------------------- evidence summary
	fmt.Fprint(w, "## 一、证据摘要\n\n")
	fmt.Fprint(w, "### 覆盖与证据\n\n")
	mdTable(w, []string{"指标", "数量"}, [][]string{
		{"计划尝试", fmt.Sprint(o.Planned)},
		{"已有记录", fmt.Sprint(o.Executed)},
		{"无记录", fmt.Sprint(o.Unrun)},
		{"已取消（未执行）", fmt.Sprint(o.Cancelled)},
		{"认证回执", fmt.Sprint(o.Authenticated)},
		{"仅 ClientHello 匹配", fmt.Sprint(o.HelloMatched)},
		{"握手匹配有歧义", fmt.Sprint(o.HelloAmbiguous)},
		{"SNI 与计划不符", fmt.Sprint(o.SNIMismatch)},
		{"观测端未收到", fmt.Sprint(o.Unobserved)},
		{"不同出口 IP 数", fmt.Sprint(o.DistinctEgressIPs)},
		{"完整性", CompleteLabel[o.Completeness]},
	})

	fmt.Fprint(w, "### 结论摘要\n\n")
	fmt.Fprintf(w, "- **与基线不同出口的域名**：%s\n", mdText(mdList(o.DifferentEgress)))
	fmt.Fprintf(w, "- **动态出口池 / 出口混合**：%s\n", mdText(mdList(o.DynamicPool)))
	fmt.Fprintf(w, "- **干预判断 · 疑似**：%s\n", mdText(mdList(o.Suspected)))
	fmt.Fprintf(w, "- **干预判断 · 较强迹象**：%s\n", mdText(mdList(o.Strong)))
	fmt.Fprintf(w, "- **出口网络（Origin ASN）**：%s\n", mdText(mdList(o.Networks)))
	fmt.Fprintf(w, "- **出口网络归属查询**：%s\n\n", mdText(o.ASN))
	if len(o.Uncertain) > 0 {
		fmt.Fprint(w, "不确定项：\n\n")
		mdBullets(w, o.Uncertain)
	}

	// ------------------------------------------------------------------ egress
	fmt.Fprint(w, "## 二、出口汇总\n\n")
	if len(r.Egress) == 0 {
		fmt.Fprint(w, "没有可用的出口观测。\n\n")
	}
	for _, g := range r.Egress {
		fmt.Fprintf(w, "### %s\n\n", g.Family)
		if len(g.Rows) == 0 {
			fmt.Fprint(w, "没有可用的出口观测。\n\n")
			continue
		}
		var rows [][]string
		for _, e := range g.Rows {
			rows = append(rows, []string{e.IP, networkText(e.Networks, e.ASNStatus), locationOrUnknown(e.Location), fmt.Sprint(e.Count)})
		}
		mdTable(w, []string{"出口 IP", "Origin ASN / 组织", "归属地", "观测次数"}, rows)
	}

	// ---------------------------------------------------------------- reasons
	fmt.Fprint(w, "## 三、判断依据与限制\n\n")
	hits := 0
	for _, gr := range r.Judgments.Groups {
		for _, j := range gr.Domains {
			if len(j.Rules) == 0 {
				continue
			}
			hits++
			fmt.Fprintf(w, "### %s（%s）\n\n", mdText(j.SNI), Family(j.Target))
			fmt.Fprintf(w, "事实可信度：**%s** · 原因判断可信度：**%s**\n\n", ConfLabel[j.FactConfidence], ConfLabel[j.CauseConfidence])
			for _, h := range j.Rules {
				fmt.Fprintf(w, "- `%s` %s\n", mdText(h.ID), mdText(h.Conclusion))
				for _, b := range h.Basis {
					fmt.Fprintf(w, "  - 依据：%s\n", mdText(b))
				}
				for _, l := range h.Limits {
					fmt.Fprintf(w, "  - 限制：%s\n", mdText(l))
				}
			}
			fmt.Fprint(w, "\n")
		}
	}
	if hits == 0 {
		fmt.Fprint(w, "没有任何规则命中：本次数据不足以支持任何结论。\n\n")
	}

	// ------------------------------------------------------------------- notes
	fmt.Fprint(w, "## 四、说明\n\n")
	mdBullets(w, r.Notes)
	fmt.Fprintf(w, "---\n\n导出文件本身即为定格的副本：测试条件在任务创建时冻结，事实只追加，规则版本为 `%s`。\n", mdText(r.RulesVersion))
	return nil
}

func familyList(targets []string) string {
	seen := map[string]bool{}
	var out []string
	for _, t := range targets {
		f := Family(t)
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return mdList(out)
}

// ExportMarkdown writes <task>-report.md into dir (created 0700, file 0600)
// and returns its path.
func ExportMarkdown(dir string, r Report) (string, error) {
	if strings.TrimSpace(dir) == "" {
		// An empty directory means "wherever the tool was started", which is
		// what a user who ran it from their working directory expects.
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(dir, safeName(r.Task.ID)+"-report.md")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	if err := WriteMarkdown(f, r); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	os.Chmod(p, 0o600) // also tighten a file that already existed
	if abs, err := filepath.Abs(p); err == nil {
		return abs, nil
	}
	return p, nil
}

// AttemptCount is the number of recorded attempts, used by callers that size
// their output.
func AttemptCount(r Report) int { return len(r.Evidence) }

var _ = server.StateAuthenticated
var _ = time.Time{}
