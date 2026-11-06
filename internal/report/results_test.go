package report

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/nyktios/sniroute/internal/server"
)

func TestResultsWidthsPreserveIPv6AndLongHosts(t *testing.T) {
	v := sample()
	host := strings.Repeat("long-", 10) + "example.com"
	ip := "2001:db8:1234:5678:9abc:def0:1234:5678"
	organization := "Example Network With A Long Organization Name"
	v.Attempts = append(v.Attempts, ok(T6, host, "domain", ip, t0))
	v = withASN(v, 1, 1, okNet(ip, 64500, organization, ""))
	r := Build(v, t0)
	for _, width := range []int{32, 40, 60, 80, 100, 140} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			var b bytes.Buffer
			l := &resultsLayout{tw: &tw{w: &b}, width: width}
			l.domains(r)
			l.summary(r)
			l.distribution(r)
			if l.err != nil {
				t.Fatal(l.err)
			}
			for _, line := range strings.Split(b.String(), "\n") {
				if cellWidth(line) > width {
					t.Fatalf("line exceeds %d: %q", width, line)
				}
			}
			flat := strings.NewReplacer("\n", "", " ", "").Replace(b.String())
			for _, s := range []string{host, ip, "AS64500 " + organization} {
				if !strings.Contains(flat, strings.ReplaceAll(s, " ", "")) {
					t.Fatalf("lost %q:\n%s", s, b.String())
				}
			}
			if !utf8.ValidString(b.String()) {
				t.Fatal("invalid UTF-8")
			}
		})
	}
}

func TestResultsSummaryHasExplicitDenominatorAndNoFalseFailures(t *testing.T) {
	v := sample()
	v.Attempts = append(v.Attempts, server.AttemptView{SNI: "cancel.example", Target: T4, Kind: "domain", State: server.StateCancelled})
	r := Build(v, t0)
	var b bytes.Buffer
	if err := WriteResults(&b, r); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{"分类探测结果", "结果摘要", "受控探测出口分布", "60.0%", "40.0%", "探测成功 5 · 探测失败 1 · 出口 IP 数 2", "未观测"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "\x1b") || strings.Contains(s, "<nil>") || strings.Contains(s, "封锁概率") {
		t.Fatal(s)
	}
	if !(strings.Index(s, "分类探测结果") < strings.Index(s, "结果摘要") && strings.Index(s, "结果摘要") < strings.Index(s, "受控探测出口分布")) {
		t.Fatal("reading order")
	}
}

func TestResultsCommonColumnWidthsAcrossCategories(t *testing.T) {
	var b bytes.Buffer
	l := &resultsLayout{tw: &tw{w: &b}, width: 100}
	l.domainRow("●", "a.com", "203.0.113.1", "AS64500 Example Network", 25, 20)
	l.domainRow("△", "longer.example", "198.51.100.1", "ASN 暂缺", 25, 20)
	lines := strings.Split(b.String(), "\n")
	for _, line := range lines[:2] {
		ipAt := strings.Index(line, "203.0.113.1")
		if ipAt < 0 {
			ipAt = strings.Index(line, "198.51.100.1")
		}
		if cellWidth(line[:ipAt]) != 27 {
			t.Fatal(line)
		}
	}
}

type brokenResultsWriter struct{}

func (brokenResultsWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestResultsPropagatesOutputError(t *testing.T) {
	if err := WriteResults(brokenResultsWriter{}, Build(sample(), t0)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}
