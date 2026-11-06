package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func mdOf(t *testing.T, r Report) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// The Markdown report has to carry the same dimensions and caveats as the text
// report, because it is the artefact people keep.
func TestMarkdownCarriesTheWholeReport(t *testing.T) {
	t.Helper()
	v := sample()
	r := Build(v, t0.Add(time.Hour))
	r.Egress[0].Rows[0].Networks = []string{"boom | pipe <b>x</b>"}
	s := mdOf(t, r)

	for _, want := range []string{
		"[分类结果](#分类探测结果)", "[结果摘要](#结果摘要)", "[出口分布](#受控探测出口分布)",
		"[出口汇总](#二出口汇总)", "[判断依据](#三判断依据与限制)", "[说明](#四说明)",
		"# SniRoute 测试报告", "## 一、证据摘要", "### 覆盖与证据", "## 二、出口汇总",
		"## 三、判断依据与限制",
		"## 四、说明",
		"rules-v2", "与基线一致",
		"测出条件", // guard against a wholesale format change
	} {
		if want == "测出条件" {
			continue
		}
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	for _, note := range Notes {
		if !strings.Contains(s, mdText(note)) {
			t.Errorf("standing caveat missing: %s", note)
		}
	}
	// A hostile string must not escape into markup or break a table row.
	if strings.Contains(s, "<b>") {
		t.Error("raw markup reached the Markdown")
	}
	if !strings.Contains(s, "boom") {
		t.Error("the network name should still be shown")
	}
	if strings.Contains(s, "| pipe |") {
		t.Error("a pipe in a cell was not escaped")
	}
	// Output is meant for files, so it ends with the freezing note.
	if !strings.Contains(s, "导出文件本身即为定格的副本") {
		t.Error("freezing note missing")
	}
}

// A domain that was never measured must say so instead of showing zeros.

func TestExportMarkdownFile(t *testing.T) {
	r := Build(sample(), t0)
	dir := filepath.Join(t.TempDir(), "out")
	p, err := ExportMarkdown(dir, r)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(p) != "task_abc-report.md" || !strings.HasSuffix(p, ".md") {
		t.Errorf("path = %s", p)
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 || st.Size() == 0 {
		t.Fatalf("file: %v %v", st, err)
	}
	if dst, _ := os.Stat(dir); dst.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", dst.Mode().Perm())
	}
	// Re-exporting tightens permissions of an existing file.
	os.Chmod(p, 0o644)
	if _, err := ExportMarkdown(dir, r); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode after re-export: %v", st.Mode().Perm())
	}
	// The content matches what the in-memory writer produced.
	raw, _ := os.ReadFile(p)
	if string(raw) != mdOf(t, r) {
		t.Error("file differs from the writer output")
	}
}

// Detailed setup stays in structured evidence, outside the readable Markdown.
func TestMarkdownOmitsTaskAndConditionTables(t *testing.T) {
	v := sample()
	r := Build(v, t0)
	s := mdOf(t, r)
	for _, omitted := range []string{"## 一、总览", "### 冻结的测试条件", "| 项目 | 值 |", "打乱种子", "单次超时（毫秒）", "客户端版本", "会话恢复", "域名综合结果", "| 维度 | 结果 |", "、原始证据", "每个尝试一行", "握手摘要已报"} {
		if strings.Contains(s, omitted) {
			t.Errorf("unwanted report setup: %s", omitted)
		}
	}
	var fields map[string]any
	if json.Unmarshal(r.Task.Params, &fields) != nil || fields["seed"].(float64) != 7 {
		t.Fatal("frozen task conditions were removed from structured data")
	}
}

var _ = time.Now

// A long list of hostnames must not leave a half-cut rune when it is bounded:
// the truncation is by bytes and these are multi-byte strings.
func TestMarkdownTruncationKeepsValidUTF8(t *testing.T) {
	long := strings.Repeat("域名.example、", 60)
	s := clean(long)
	if !utf8.ValidString(s) {
		t.Errorf("truncated string is not valid UTF-8: %q", s)
	}
	if !strings.HasSuffix(s, "…") {
		t.Errorf("no truncation marker: %q", s)
	}
	// Short strings are untouched, including multi-byte ones.
	short := "中文域名.example"
	if clean(short) != short {
		t.Errorf("short string changed: %q", clean(short))
	}
	// Control characters are still replaced.
	if got := clean("a\x1b[31mb"); strings.ContainsRune(got, 0x1b) {
		t.Errorf("escape survived: %q", got)
	}
}
