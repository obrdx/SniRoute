package report

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

func TestReportsOmitObserverDetails(t *testing.T) {
	v := sample()
	v.Params = json.RawMessage(`{"targets":["192.0.2.77:443"],"collector_id":"private-observer","seed":18446744073709551615}`)
	v.CollectorID = "private-observer"
	v.Attempts = append(v.Attempts, failed(T4, "failed.example", "dial tcp "+T4+": timeout"))
	r := Build(v, t0)
	outputs := map[string]string{}
	for name, write := range map[string]func(*bytes.Buffer){
		"text":     func(b *bytes.Buffer) { WriteText(b, r) },
		"markdown": func(b *bytes.Buffer) { WriteMarkdown(b, r) },
		"results":  func(b *bytes.Buffer) { WriteResults(b, r) },
		"domain":   func(b *bytes.Buffer) { WriteDomain(b, r, "failed.example") },
		"json": func(b *bytes.Buffer) {
			data, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			b.Write(data)
		},
	} {
		var b bytes.Buffer
		write(&b)
		outputs[name] = b.String()
	}
	for name, rows := range map[string][][]string{"domains.csv": DomainRows(r), "egress.csv": EgressRows(r)} {
		for _, row := range rows {
			outputs[name] += strings.Join(row, ",") + "\n"
		}
	}
	host, _, _ := net.SplitHostPort(T4)
	for name, output := range outputs {
		for _, private := range []string{host, "private-observer", "192.0.2.77", `"collector_id"`, `"target"`, `"targets"`} {
			if strings.Contains(output, private) {
				t.Errorf("%s exposes %q", name, private)
			}
		}
	}
	if !strings.Contains(outputs["json"], "18446744073709551615") {
		t.Fatal("JSON changed seed precision")
	}
	if v.CollectorID != "private-observer" || r.Evidence[len(r.Evidence)-1].Target != T4 || !strings.Contains(string(v.Params), "192.0.2.77") {
		t.Fatal("presentation changed underlying facts")
	}
}
