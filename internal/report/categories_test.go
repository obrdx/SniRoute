package report

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/nyktios/sniroute/internal/analysis"
	"github.com/nyktios/sniroute/internal/server"
)

func TestCategorySnapshot(t *testing.T) {
	v := sample()
	// Indices refer to sorted unique domains: d.com, e.com, f.com, g.com.
	v.Params = json.RawMessage(`{"domain_categories":[{"name":"金融","domains":[1,0]},{"name":"AI 服务","domains":[2]}]}`)
	v.Attempts = append(v.Attempts, server.AttemptView{SNI: "d.com", Target: T6, Kind: "domain", Client: []server.ClientEventView{{Outcome: "receipt", DurationMS: 999}}})
	r := Build(v, t0)
	if len(r.Categories) != 3 || r.Categories[0].Name != "金融" || r.Categories[0].Domains[0] != "e.com" || r.Categories[2].Domains[0] != "g.com" {
		t.Fatalf("categories: %+v", r.Categories)
	}
	for _, write := range []func(*bytes.Buffer){func(b *bytes.Buffer) { WriteText(b, r) }, func(b *bytes.Buffer) { WriteMarkdown(b, r) }} {
		var b bytes.Buffer
		write(&b)
		s := b.String()
		if !strings.Contains(s, "金融（2）") || !strings.Contains(s, "AI 服务（1）") || !strings.Contains(s, "自定义 / 未分类（1）") || !strings.Contains(s, "未观测") {
			t.Fatal(s)
		}
	}
	if domainSymbol(analysis.Judgment{Probe: analysis.ProbeMixed, Completeness: analysis.Complete}, analysis.DomainEgress{}) == "●" {
		t.Fatal("mixed probe results rendered as full success")
	}
}

func TestSuccessfulDomainWithChangingExits(t *testing.T) {
	v := sample()
	v.Attempts = append(v.Attempts, ok(T4, "d.com", "domain", "10.0.0.8", t0))
	r := Build(v, t0)
	for _, write := range []func(*bytes.Buffer){
		func(b *bytes.Buffer) { WriteResults(b, r) },
		func(b *bytes.Buffer) { WriteMarkdown(b, r) },
	} {
		var b bytes.Buffer
		write(&b)
		if !strings.Contains(b.String(), "◆ d.com") || !strings.Contains(b.String(), "◆ 探测成功但多次出口不一致") {
			t.Fatal(b.String())
		}
	}
}

func TestMaskedReportAllExportsPreserveEvidenceAndDistinctIPs(t *testing.T) {
	v := sample()
	v.Params = json.RawMessage(`{"show_full_ip":false}`)
	r := Build(v, t0)
	if r.IPDisplay != "masked" || r.Overview.DistinctEgressIPs != 2 {
		t.Fatalf("privacy: %+v", r.Overview)
	}
	if v.Attempts[0].Observation.SourceIP != "10.0.0.1" {
		t.Fatal("original task was modified")
	}
	// Both IPs share the visible prefix; aliases must keep them distinct.
	if r.Egress[0].Rows[0].IP == r.Egress[0].Rows[1].IP {
		t.Fatal("masked exits collapsed")
	}
	paths, err := Export(t.TempDir(), r)
	if err != nil {
		t.Fatal(err)
	}
	md, err := ExportMarkdown(t.TempDir(), r)
	if err != nil {
		t.Fatal(err)
	}
	paths = append(paths, md)
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, ip := range []string{"10.0.0.1", "10.0.0.9"} {
			if bytes.Contains(b, []byte(ip)) {
				t.Fatalf("%s leaked %s", p, ip)
			}
		}
		if !bytes.Contains(b, []byte("出口1")) {
			t.Fatalf("%s missing alias", p)
		}
	}
	v.Params = json.RawMessage(`{"show_full_ip":true}`)
	if Build(v, t0).Evidence[0].Observation.SourceIP != "10.0.0.1" {
		t.Fatal("full display lost IP")
	}
}

func TestChineseColumnAlignment(t *testing.T) {
	var b bytes.Buffer
	tw := &tw{w: &b}
	tw.table([][]string{{"域名", "IP"}, {"a.com", "x"}})
	lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	if cellWidth(strings.Split(lines[0], "IP")[0]) != cellWidth(strings.Split(lines[1], "x")[0]) {
		t.Fatal(b.String())
	}
}
