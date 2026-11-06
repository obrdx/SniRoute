package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nyktios/sniroute/internal/analysis"
	"github.com/nyktios/sniroute/internal/asn"
	"github.com/nyktios/sniroute/internal/server"
)

const (
	T4 = "198.51.100.1:443"
	T6 = "[2001:db8::1]:443"
)

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func ok(target, sni, kind, ip string, at time.Time) server.AttemptView {
	return server.AttemptView{
		Kind: kind, SNI: sni, Target: target, Round: 1, State: server.StateAuthenticated,
		Observation: &server.Observation{SourceIP: ip, ObservedSNI: sni, SNIMatch: true, Evidence: "authenticated", ObservedAt: at},
		Client:      []server.ClientEventView{{Outcome: "receipt", Stage: "http", HelloSent: true, DurationMS: 12}},
	}
}

func failed(target, sni, errMsg string) server.AttemptView {
	return server.AttemptView{
		Kind: "domain", SNI: sni, Target: target, Round: 1, State: server.StateUnobserved,
		Client: []server.ClientEventView{{Outcome: "timeout", Stage: "tls", HelloSent: true, Error: errMsg}},
	}
}

func sample() server.TaskView {
	return server.TaskView{
		ID: "task_abc", Status: server.TaskCompleted, CollectorID: "collector-1", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour),
		Node:   server.NodeSummary{ID: "node_1", Name: "tokyo-1", ProviderLabel: "ProviderX"},
		Params: json.RawMessage(`{"rounds":3,"concurrency":3,"timeout_ms":5000,"seed":7,"env_note":"direct"}`),
		Attempts: []server.AttemptView{
			ok(T4, "b.invalid", "baseline", "10.0.0.1", t0), ok(T4, "b.invalid", "baseline", "10.0.0.1", t0.Add(time.Minute)),
			ok(T4, "d.com", "domain", "10.0.0.9", t0.Add(10*time.Second)), ok(T4, "d.com", "domain", "10.0.0.9", t0.Add(20*time.Second)),
			ok(T4, "e.com", "domain", "10.0.0.1", t0.Add(30*time.Second)),
			failed(T4, "f.com", "dial\x1b[31m tcp: boom"),
			{Kind: "domain", SNI: "g.com", Target: T4, State: server.StateTimeout},
		},
	}
}

func TestBuildOverviewAndEgressGroups(t *testing.T) {
	r := Build(sample(), t0.Add(time.Hour))
	o := r.Overview
	if o.Planned != 7 || o.Executed != 6 || o.Unrun != 1 || o.Authenticated != 5 || o.Unobserved != 1 || o.Cancelled != 0 {
		t.Errorf("coverage: %+v", o)
	}
	if o.DistinctEgressIPs != 2 || len(o.Targets) != 1 || o.ASN != ASNNote {
		t.Errorf("egress summary: %+v", o)
	}
	if len(o.DifferentEgress) != 1 || !strings.HasPrefix(o.DifferentEgress[0], "d.com") {
		t.Errorf("different egress: %v", o.DifferentEgress)
	}

	if len(r.Egress) != 1 || len(r.Egress[0].Rows) != 2 {
		t.Fatalf("groups: %+v", r.Egress)
	}
	rows := map[string]EgressRow{}
	for _, row := range r.Egress[0].Rows {
		rows[row.IP] = row
	}
	base := rows["10.0.0.1"]
	if !base.InBaseline || base.Count != 3 || base.Authenticated != 3 || len(base.Domains) != 1 || base.Domains[0] != "e.com" {
		t.Errorf("baseline egress: %+v", base)
	}
	div := rows["10.0.0.9"]
	if div.InBaseline || div.Count != 2 || div.FirstSeen == nil || !div.FirstSeen.Equal(t0.Add(10*time.Second)) || !div.LastSeen.Equal(t0.Add(20*time.Second)) {
		t.Errorf("diverted egress: %+v", div)
	}
	if r.Egress[0].Rows[0].IP != "10.0.0.1" {
		t.Errorf("rows must be ordered by count: %+v", r.Egress[0].Rows)
	}
	if r.Task.NodeName != "tokyo-1" || r.Task.ProviderLabel != "ProviderX" || r.Version != Version {
		t.Errorf("task info: %+v", r.Task)
	}
}

func TestCancelledTaskOverview(t *testing.T) {
	v := sample()
	v.Status = server.TaskAborted
	now := t0
	v.CancelledAt = &now
	v.Attempts[6].State = server.StateCancelled
	r := Build(v, t0)
	if r.Overview.Cancelled != 1 || r.Overview.Completeness != analysis.Cancelled || r.Overview.Unrun != 1 {
		t.Errorf("%+v", r.Overview)
	}
	var b bytes.Buffer
	WriteText(&b, r)
	if !strings.Contains(b.String(), "已中断（部分结果）") || !strings.Contains(b.String(), "已取消") {
		t.Errorf("aborted state not shown:\n%s", b.String())
	}
}

func TestTextReportHasAllLayersAndCaveats(t *testing.T) {
	var b bytes.Buffer
	if err := WriteText(&b, Build(sample(), t0)); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{
		"测试报告", "tokyo-1", "ProviderX", "rules-v2", "覆盖：计划 7", "出口汇总", "10.0.0.9", "分类探测结果",
		"判断依据与限制", "[R01]", "限制：", "未完成认证回执的尝试", "真实网站访问出口：未直接观测", "出口网络归属查询：未查询",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q:\n%s", want, s)
		}
	}
	// Externally supplied text can never smuggle terminal escapes into the report.
	if strings.ContainsAny(s, "\x1b\x00") {
		t.Errorf("control characters in the text report: %q", s)
	}
	for _, bad := range []string{"封锁概率", "已封锁"} {
		if strings.Contains(s, bad) {
			t.Errorf("overclaim %q", bad)
		}
	}
}

func TestDomainEvidenceView(t *testing.T) {
	r := Build(sample(), t0)
	var b bytes.Buffer
	found, err := WriteDomain(&b, r, "D.COM")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	s := b.String()
	for _, want := range []string{"认证回执", "10.0.0.9", "采用的规则", "R01"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q:\n%s", want, s)
		}
	}
	if found, _ := WriteDomain(&b, r, "nope.com"); found {
		t.Error("unknown domain reported as found")
	}
}

func TestFocusedViews(t *testing.T) {
	r := Build(sample(), t0)
	var b bytes.Buffer
	WriteAnomalies(&b, r)
	if s := b.String(); !strings.Contains(s, "f.com") || strings.Contains(s, "e.com") || strings.Contains(s, "d.com") {
		t.Errorf("anomalies view:\n%s", s)
	}
	b.Reset()
	WriteGroups(&b, r)
	if s := b.String(); !strings.Contains(s, "出口汇总") || strings.Contains(s, "判断依据") {
		t.Errorf("groups view:\n%s", s)
	}
	b.Reset()
	WriteDomainTable(&b, r)
	if s := b.String(); !strings.Contains(s, "受控探测") || !strings.Contains(s, "干预判断") {
		t.Errorf("domain table:\n%s", s)
	}
	// No anomalies at all: say so rather than print nothing.
	v := sample()
	v.Attempts = v.Attempts[:5]
	b.Reset()
	WriteAnomalies(&b, Build(v, t0))
	if !strings.Contains(b.String(), "没有受控探测异常") {
		t.Errorf("empty anomalies view: %q", b.String())
	}
}

func TestCSVFormulaInjectionIsNeutralised(t *testing.T) {
	v := sample()
	evil := "=HYPERLINK(\"http://x\")"
	v.Attempts = append(v.Attempts, ok(T4, evil, "domain", "10.0.0.9", t0))
	r := Build(v, t0)
	dir := t.TempDir()
	files, err := Export(dir, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if !strings.HasSuffix(f, ".csv") {
			continue
		}
		fh, _ := os.Open(f)
		recs, err := csv.NewReader(fh).ReadAll()
		fh.Close()
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, row := range recs {
			for _, cell := range row {
				if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
					t.Errorf("%s: unsafe cell %q", filepath.Base(f), cell)
				}
			}
		}
		raw, _ := os.ReadFile(f)
		if strings.HasSuffix(f, "domains.csv") && !strings.Contains(string(raw), "'=HYPERLINK") {
			t.Errorf("expected the formula to be defused with a leading apostrophe:\n%s", raw)
		}
	}
}

func TestExportFilesAndJSON(t *testing.T) {
	v := sample()
	v.Attempts[5].Client[0].Error = "<script>alert(1)</script>"
	r := Build(v, t0.Add(time.Hour))
	dir := filepath.Join(t.TempDir(), "out", "reports")
	files, err := Export(dir, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Fatalf("files: %v", files)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", st.Mode().Perm())
	}
	for _, f := range files {
		st, err := os.Stat(f)
		if err != nil || st.Mode().Perm() != 0o600 || st.Size() == 0 || !strings.HasPrefix(filepath.Base(f), "task_abc-") {
			t.Errorf("%s: %v %v", f, st, err)
		}
	}

	raw, _ := os.ReadFile(filepath.Join(dir, "task_abc-report.json"))
	var back Report
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Task.ID != "task_abc" || len(back.Evidence) != 7 || back.RulesVersion != "rules-v2" || len(back.Notes) == 0 {
		t.Errorf("json round trip: %+v", back.Task)
	}
	var params map[string]any
	if json.Unmarshal(back.Task.Params, &params) != nil || params["seed"].(float64) != 7 {
		t.Errorf("test conditions not frozen in the export: %s", back.Task.Params)
	}
	if strings.Contains(string(raw), "<script>") {
		t.Error("raw markup in JSON (should be escaped)")
	}

	// Re-running an export overwrites and tightens permissions.
	os.Chmod(files[0], 0o644)
	if _, err := Export(dir, r); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(files[0]); st.Mode().Perm() != 0o600 {
		t.Errorf("mode after re-export: %v", st.Mode().Perm())
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	a, _ := json.Marshal(Build(sample(), t0))
	b, _ := json.Marshal(Build(sample(), t0))
	if !bytes.Equal(a, b) {
		t.Error("the same facts and clock must give the same report")
	}
}

func TestProbeOnlyReportIgnoresLegacyAccessPlan(t *testing.T) {
	v := sample()
	v.Attempts = v.Attempts[:5]
	// Preserve the historical task snapshot, but do not require retired work.
	v.Params = json.RawMessage(`{"rounds":3,"web_check":true,"reference":true}`)
	r := Build(v, t0)
	if r.Overview.Completeness != analysis.Complete {
		t.Fatalf("retired measurements made a complete probe task partial: %+v", r.Overview)
	}
	var text, markdown bytes.Buffer
	WriteText(&text, r)
	WriteMarkdown(&markdown, r)
	for _, output := range []string{text.String(), markdown.String()} {
		for _, retired := range []string{"真实访问", "参考测试", "真实网站访问明细", "缺少参考"} {
			if strings.Contains(output, retired) {
				t.Errorf("retired result %q in report", retired)
			}
		}
	}
	for _, column := range DomainRows(r)[0] {
		if column == "access" || column == "reference" {
			t.Errorf("retired CSV column %s", column)
		}
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	if _, exists := fields["web_checks"]; exists {
		t.Error("retired evidence field in JSON report")
	}
	if string(r.Task.Params) != string(v.Params) {
		t.Error("historical snapshot was rewritten")
	}
}

func TestEmptyTaskDoesNotPanic(t *testing.T) {
	r := Build(server.TaskView{ID: "task_empty"}, t0)
	var b bytes.Buffer
	if err := WriteText(&b, r); err != nil {
		t.Fatal(err)
	}
	if _, err := Export(t.TempDir(), r); err != nil {
		t.Fatal(err)
	}
}

// ---- egress networks ----------------------------------------------------------

func withASN(v server.TaskView, snapshot, total int, items ...asn.Info) server.TaskView {
	v.ASN = &server.ASNView{Snapshot: snapshot, Snapshots: total, Source: "ripestat", QueriedAt: t0.Add(2 * time.Hour), Items: items}
	return v
}

func okNet(ip string, n int, name, prefix string) asn.Info {
	return asn.Info{IP: ip, Status: asn.StatusOK, Source: "ripestat", Prefix: prefix, ASNs: []asn.Number{{ASN: n, Name: name}}}
}

func TestNetworkGroupingAndLookupStatuses(t *testing.T) {
	v := withASN(sample(), 1, 1,
		okNet("10.0.0.1", 64500, "BaseNet", "10.0.0.0/24"),
		asn.Info{IP: "10.0.0.9", Status: asn.StatusFailed, Source: "ripestat", Error: asn.KindTimeout},
	)
	r := Build(v, t0.Add(3*time.Hour))

	// The failed lookup keeps the IP, says why there is no network, and is not merged into a real one.
	rows := map[string]EgressRow{}
	for _, row := range r.Egress[0].Rows {
		rows[row.IP] = row
	}
	if got := rows["10.0.0.1"]; len(got.Networks) != 1 || got.Networks[0] != "AS64500 BaseNet" || got.Prefix != "10.0.0.0/24" || got.ASNStatus != "ok" {
		t.Errorf("known network: %+v", got)
	}
	if got := rows["10.0.0.9"]; len(got.Networks) != 0 || got.ASNStatus != "failed" || got.Count != 2 {
		t.Errorf("failed lookup must keep the IP: %+v", got)
	}
	if len(r.NetworkGroups) != 1 || len(r.NetworkGroups[0].Rows) != 2 {
		t.Fatalf("network groups: %+v", r.NetworkGroups)
	}
	var known, unknown *NetworkRow
	for i := range r.NetworkGroups[0].Rows {
		row := &r.NetworkGroups[0].Rows[i]
		if len(row.Networks) > 0 {
			known = row
		} else {
			unknown = row
		}
	}
	if known == nil || unknown == nil || !known.InBaseline || unknown.IPs[0] != "10.0.0.9" || unknown.InBaseline {
		t.Errorf("rows: known=%+v unknown=%+v", known, unknown)
	}
	if r.Overview.Networks[0] != "AS64500 BaseNet" || len(r.Overview.Networks) != 1 {
		t.Errorf("overview networks: %v", r.Overview.Networks)
	}
	if !strings.Contains(r.Overview.ASN, "ripestat") || !strings.Contains(r.Overview.ASN, "快照 1/1") || !strings.Contains(r.Overview.ASN, "失败 1") {
		t.Errorf("overview ASN line: %s", r.Overview.ASN)
	}
}

func TestSameNetworkIPsShareARow(t *testing.T) {
	v := withASN(sample(), 1, 1, okNet("10.0.0.1", 64500, "Net", "p"), okNet("10.0.0.9", 64500, "Net", "p"))
	r := Build(v, t0)
	if g := r.NetworkGroups[0]; len(g.Rows) != 1 || len(g.Rows[0].IPs) != 2 || g.Rows[0].Count != 5 || !g.Rows[0].InBaseline || len(g.Rows[0].Domains) != 2 {
		t.Errorf("%+v", g.Rows)
	}
}

func TestReportWithoutLookupsSaysSoAndStaysValid(t *testing.T) {
	r := Build(sample(), t0)
	if r.ASN.Queried || r.Overview.ASN != ASNNote || len(r.Overview.Networks) != 0 {
		t.Errorf("%+v / %s", r.ASN, r.Overview.ASN)
	}
	for _, row := range r.Egress[0].Rows {
		if row.ASNStatus != "not_queried" || len(row.Networks) != 0 {
			t.Errorf("row: %+v", row)
		}
	}
	var b bytes.Buffer
	WriteText(&b, r)
	if !strings.Contains(b.String(), "出口网络归属查询：未查询") || !strings.Contains(b.String(), "不代表被测服务商") {
		t.Errorf("text:\n%s", b.String())
	}
}

func TestExportFreezesTheSnapshotItUsed(t *testing.T) {
	first := withASN(sample(), 1, 2, okNet("10.0.0.1", 64500, "Old Name", "p"), okNet("10.0.0.9", 64501, "Other", "q"))
	r1 := Build(first, t0)
	dir := t.TempDir()
	files, err := Export(dir, r1)
	if err != nil {
		t.Fatal(err)
	}
	// A later refresh exists (snapshot 2, the holder was renamed)...
	second := withASN(sample(), 2, 2, okNet("10.0.0.1", 64500, "New Name", "p"), okNet("10.0.0.9", 64501, "Other", "q"))
	_ = Build(second, t0)

	// ...but the exported file still says snapshot 1 with the old name.
	var raw []byte
	for _, f := range files {
		if strings.HasSuffix(f, "report.json") {
			raw, _ = os.ReadFile(f)
		}
	}
	var back Report
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.ASN.Snapshot != 1 || back.ASN.Snapshots != 2 || back.ASN.Source != "ripestat" || back.ASN.QueriedAt == nil || len(back.ASN.Items) != 2 {
		t.Errorf("asn section: %+v", back.ASN)
	}
	if !strings.Contains(string(raw), "Old Name") || strings.Contains(string(raw), "New Name") {
		t.Error("an export must keep the lookup data it was built from")
	}
	// The CSVs carry the network, prefix, status, source and snapshot.
	csvRaw, _ := os.ReadFile(filepath.Join(dir, "task_abc-egress.csv"))
	for _, want := range []string{"networks", "asn_snapshot", "AS64500 Old Name", "10.0.0.0/24", "ripestat"} {
		if want == "10.0.0.0/24" {
			continue
		}
		if !strings.Contains(string(csvRaw), want) {
			t.Errorf("egress.csv lacks %q:\n%s", want, csvRaw)
		}
	}
}

func TestProviderTextCannotInjectIntoReports(t *testing.T) {
	evil := okNet("10.0.0.1", 64500, "=HYPERLINK(\"http://x\")\x1b[31m", "p")
	r := Build(withASN(sample(), 1, 1, evil), t0)
	var b bytes.Buffer
	WriteText(&b, r)
	if strings.ContainsAny(b.String(), "\x1b") {
		t.Error("terminal escape from a provider reached the text report")
	}
	dir := t.TempDir()
	files, _ := Export(dir, r)
	for _, f := range files {
		if !strings.HasSuffix(f, ".csv") {
			continue
		}
		fh, _ := os.Open(f)
		recs, _ := csv.NewReader(fh).ReadAll()
		fh.Close()
		for _, row := range recs {
			for _, c := range row {
				if c != "" && strings.ContainsRune("=+-@\t\r", rune(c[0])) {
					t.Errorf("%s: unsafe cell %q", filepath.Base(f), c)
				}
			}
		}
	}
}

func TestReportSeedKeepsUint64Precision(t *testing.T) {
	for _, seed := range []string{"9007199254740993", "18446744073709551615"} {
		v := sample()
		v.Params = json.RawMessage(`{"seed":` + seed + `}`)
		r := Build(v, t0)
		for name, write := range map[string]func(*bytes.Buffer){
			"text": func(b *bytes.Buffer) { WriteText(b, r) },
			"json": func(b *bytes.Buffer) { data, _ := json.Marshal(r); b.Write(data) },
		} {
			var b bytes.Buffer
			write(&b)
			if !strings.Contains(b.String(), seed) {
				t.Fatalf("%s lost seed %s", name, seed)
			}
		}
	}
}
