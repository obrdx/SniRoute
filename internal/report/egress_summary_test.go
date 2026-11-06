package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nyktios/sniroute/internal/asn"
	"github.com/nyktios/sniroute/internal/server"
)

func TestEgressSummaryFirstWithoutDomainsOrGeoDiagnostics(t *testing.T) {
	info := okNet("10.0.0.1", 64500, "Example Network", "")
	info.Error = "private-origin-diagnostic"
	info.Locations = []asn.Location{
		{Source: "ipinfo", Status: asn.StatusOK, CountryCode: "US", Region: "California", City: "Mountain View", QueriedAt: t0},
		{Source: "geojs", Status: asn.StatusOK, CountryCode: "DE", Region: "Hesse", City: "Frankfurt", Error: "private-api-diagnostic", QueriedAt: t0},
	}
	v := withASN(sample(), 1, 1, info)
	v.Attempts[5].Client[0].Error = "private-probe-diagnostic"
	v.Params = json.RawMessage(`{"domain_categories":[{"name":"AI 服务","domains":[0,1]},{"name":"金融","domains":[2,3]}]}`)
	r := Build(v, t0)
	for _, write := range []func(*bytes.Buffer){
		func(b *bytes.Buffer) { WriteText(b, r) },
		func(b *bytes.Buffer) { WriteMarkdown(b, r) },
	} {
		var b bytes.Buffer
		write(&b)
		output := b.String()
		for _, diagnostic := range []string{"private-api-diagnostic", "private-origin-diagnostic", "private-probe-diagnostic"} {
			if strings.Contains(output, diagnostic) {
				t.Errorf("report contains %q", diagnostic)
			}
		}
		start, end := strings.Index(output, "出口整理"), strings.Index(output, "分类探测结果")
		// Markdown navigation precedes the actual sections.
		if strings.Contains(output, "## 出口整理") {
			start = strings.Index(output, "## 出口整理")
			end = strings.Index(output, "## 分类探测结果")
		}
		if start < 0 || end < start {
			t.Fatalf("summary order:\n%s", output)
		}
		summary := output[start:end]
		for _, want := range []string{"共 2 个", "归属地", "Mountain View", "其他可能：DE / Hesse / Frankfurt，GeoJS", "AI 服务"} {
			if !strings.Contains(summary, want) {
				t.Errorf("summary missing %q:\n%s", want, summary)
			}
		}
		for _, unwanted := range []string{"d.com", "e.com", "基线出口", "private-api-diagnostic"} {
			if strings.Contains(summary, unwanted) {
				t.Errorf("summary includes %q", unwanted)
			}
		}
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("private-api-diagnostic")) || bytes.Contains(b, []byte(`"locations"`)) {
		t.Fatal("geo query diagnostics reached the report")
	}
	if bytes.Contains(b, []byte(`"error"`)) {
		t.Fatal("diagnostic errors reached JSON report")
	}
	if !bytes.Contains(b, []byte(`"egress_summary"`)) || !bytes.Contains(b, []byte("Mountain View")) {
		t.Fatal("JSON omitted formatted summary")
	}
	// New source results do not change the report's formatted location.
	v.ASN.Items[0].Locations[0].City = "New City"
	if strings.Contains(summarizeEgress(r).Exits[0].Location, "New City") {
		t.Fatal("report attribution was not frozen")
	}
}

func TestSNIConsistencyWithinComparisonGroup(t *testing.T) {
	v := sample()
	v.Attempts = nil
	for _, target := range []string{T4, T6} {
		exit := "192.0.2.1"
		if target == T6 {
			exit = "2001:db8::2"
		}
		for n := 0; n < 3; n++ {
			a := ok(target, "a.example", "domain", exit, t0)
			a.Round = n + 1
			v.Attempts = append(v.Attempts, a)
		}
	}
	summary := summarizeEgress(Build(v, t0))
	if summary.Consistency != "一致" || summary.IPCount != 2 || summary.Split != "证据不足，无法判断" {
		t.Fatalf("%+v", summary)
	}
	v.Attempts = append(v.Attempts, ok(T4, "a.example", "domain", "192.0.2.2", t0))
	if got := summarizeEgress(Build(v, t0)).Consistency; got != "不一致" {
		t.Fatal(got)
	}
	v.Attempts = []server.AttemptView{ok(T4, "a.example", "domain", "192.0.2.1", t0)}
	if got := summarizeEgress(Build(v, t0)).Consistency; got != "证据不足" {
		t.Fatal(got)
	}
	v.Attempts = append(v.Attempts, server.AttemptView{SNI: "a.example", Kind: "domain", Target: T4, State: server.StateCancelled})
	if got := summarizeEgress(Build(v, t0)).Consistency; got != "证据不足" {
		t.Fatal(got)
	}
}
