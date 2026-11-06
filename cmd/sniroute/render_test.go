package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nyktios/sniroute/internal/server"
	"github.com/nyktios/sniroute/internal/tui"
)

func TestRenderResultsKeepsDimensionsAndCaveatsSeparate(t *testing.T) {
	att := func(sni, kind, ip string) server.AttemptView {
		return server.AttemptView{
			Kind: kind, SNI: sni, Target: "198.51.100.1:443", State: server.StateAuthenticated,
			Observation: &server.Observation{SourceIP: ip, ObservedSNI: sni, SNIMatch: true, Evidence: "authenticated"},
			Client:      []server.ClientEventView{{Outcome: "receipt", Stage: "http", HelloSent: true}},
		}
	}
	v := server.TaskView{
		ID: "task_x", Status: server.TaskCompleted, CollectorID: "collector-1", Params: json.RawMessage(`{"web_check":true}`),
		Attempts: []server.AttemptView{
			att("b.invalid", "baseline", "10.0.0.1"), att("b.invalid", "baseline", "10.0.0.1"),
			att("d.com", "domain", "10.0.0.9"), att("d.com", "domain", "10.0.0.9"),
		},
	}
	var out bytes.Buffer
	ui := tui.New(strings.NewReader(""), &out)
	renderResults(ui, v)
	s := out.String()

	for _, want := range []string{
		"规则版本：rules-v2", "分类探测结果",
		"[R01]", "限制：", "真实网站访问出口：未直接观测", "不等于确定没有分流",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("report is missing %q:\n%s", want, s)
		}
	}
	for _, bad := range []string{"封锁概率", "已封锁", "被封"} {
		if strings.Contains(s, bad) {
			t.Errorf("report overclaims with %q", bad)
		}
	}

	out.Reset()
	if !renderDomain(ui, v, "D.COM") || !strings.Contains(out.String(), "认证回执") {
		t.Errorf("domain evidence should include the controlled probe receipt:\n%s", out.String())
	}
	if renderDomain(ui, v, "nope.com") {
		t.Error("unknown domain reported as found")
	}
}

func TestReorderFlagsAllowsFlagsAfterTheTaskID(t *testing.T) {
	got := reorderFlags([]string{"task_1", "-config", "/x/c.yaml", "-dir=/out"})
	want := []string{"-config", "/x/c.yaml", "-dir=/out", "task_1"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
			break
		}
	}
	if got := reorderFlags(nil); len(got) != 0 {
		t.Errorf("empty: %v", got)
	}
}
