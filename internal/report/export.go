package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nyktios/sniroute/internal/analysis"
)

// csvCell neutralises spreadsheet formula injection: a cell that would start
// a formula gets a leading apostrophe. Control characters are removed.
func csvCell(s string) string {
	s = clean(s)
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func writeCSV(path string, rows [][]string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	for _, r := range rows {
		out := make([]string, len(r))
		for i, c := range r {
			out[i] = csvCell(c)
		}
		if err := w.Write(out); err != nil {
			f.Close()
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func tsOrEmpty(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// DomainRows is the CSV of per-domain results (one row per comparison group
// and domain), for sorting and comparing in a spreadsheet.
func DomainRows(r Report) [][]string {
	category := map[string]string{}
	for _, c := range r.Categories {
		for _, h := range c.Domains {
			category[strings.ToLower(h)] = c.Name
		}
	}
	rows := [][]string{{"task_id", "family", "domain", "planned", "observed", "egress_ips", "egress_result", "probe_status",
		"intervention", "completeness", "fact_confidence", "cause_confidence", "rules", "rules_version", "networks", "category"}}
	for _, gr := range r.Judgments.Groups {
		for i, d := range gr.Group.Domains {
			j := gr.Domains[i]
			var ids []string
			for _, h := range j.Rules {
				ids = append(ids, h.ID)
			}
			ips := []string{}
			for _, ip := range analysis.SortedIPs(d.IPs) {
				ips = append(ips, fmt.Sprintf("%s x%d", ip, d.IPs[ip]))
			}
			rows = append(rows, []string{r.Task.ID, Family(gr.Group.Target), d.SNI, fmt.Sprint(d.Planned), fmt.Sprint(d.Observed),
				strings.Join(ips, " | "), string(d.Result), string(j.Probe), string(j.Intervention),
				string(j.Completeness), string(j.FactConfidence), string(j.CauseConfidence), strings.Join(ids, " "), r.RulesVersion,
				strings.Join(j.Networks, " | "), category[strings.ToLower(d.SNI)]})
		}
	}
	return rows
}

// EgressRows is the CSV of egress IPs per comparison group.
func EgressRows(r Report) [][]string {
	rows := [][]string{{"task_id", "family", "egress_ip", "count", "authenticated", "hello_matched", "in_baseline", "domains", "first_seen", "last_seen",
		"networks", "prefix", "asn_status", "asn_source", "asn_snapshot", "location"}}
	for _, g := range r.Egress {
		for _, e := range g.Rows {
			rows = append(rows, []string{r.Task.ID, g.Family, e.IP, fmt.Sprint(e.Count), fmt.Sprint(e.Authenticated), fmt.Sprint(e.HelloMatched),
				fmt.Sprint(e.InBaseline), strings.Join(e.Domains, " | "), tsOrEmpty(e.FirstSeen), tsOrEmpty(e.LastSeen),
				strings.Join(e.Networks, " | "), e.Prefix, e.ASNStatus, r.ASN.Source, snapshotText(r.ASN), locationOrUnknown(e.Location)})
		}
	}
	return rows
}

// Export writes report.txt, report.json, domains.csv and egress.csv into dir
// (created 0700; files 0600) and returns their paths. File names carry the
// task id. The JSON holds the complete evidence and the frozen task conditions.
func Export(dir string, r Report) ([]string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	dir = abs
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	id := safeName(r.Task.ID)
	var files []string
	add := func(name string, write func(path string) error) error {
		p := filepath.Join(dir, id+"-"+name)
		if err := write(p); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		os.Chmod(p, 0o600) // also tighten files that already existed
		files = append(files, p)
		return nil
	}
	if err := add("report.txt", func(p string) error {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		if err := WriteText(f, r); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}); err != nil {
		return files, err
	}
	if err := add("report.json", func(p string) error {
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(p, append(b, '\n'), 0o600)
	}); err != nil {
		return files, err
	}
	if err := add("domains.csv", func(p string) error { return writeCSV(p, DomainRows(r)) }); err != nil {
		return files, err
	}
	if err := add("egress.csv", func(p string) error { return writeCSV(p, EgressRows(r)) }); err != nil {
		return files, err
	}
	return files, nil
}

func safeName(s string) string {
	out := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, s)
	if out == "" {
		return "task"
	}
	return out
}

func snapshotText(a ASNSection) string {
	if !a.Queried {
		return ""
	}
	return fmt.Sprint(a.Snapshot)
}
