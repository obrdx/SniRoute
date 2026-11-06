package report

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// redactEgress makes a presentation copy after analysis. Database facts stay
// intact. Distinct aliases prevent masked IPs from collapsing an egress pool.
func redactEgress(r Report) Report {
	var p struct {
		ShowFullIP *bool `json:"show_full_ip"`
	}
	if json.Unmarshal(r.Task.Params, &p) != nil || p.ShowFullIP == nil || *p.ShowFullIP {
		return r
	}
	r.IPDisplay = "masked"
	ips := map[string]bool{}
	for _, g := range r.Egress {
		for _, e := range g.Rows {
			ips[e.IP] = true
		}
	}
	// Include sources in diagnostic evidence, even when ineligible for analysis.
	for _, a := range r.Evidence {
		if a.Observation != nil && a.Observation.SourceIP != "" {
			ips[a.Observation.SourceIP] = true
		}
	}
	ordered := make([]string, 0, len(ips))
	for ip := range ips {
		ordered = append(ordered, ip)
	}
	sort.Strings(ordered)
	var pairs []string
	for i, ip := range ordered {
		label := "已隐藏"
		if addr, err := netip.ParseAddr(ip); err == nil {
			if addr.Is4() {
				parts := strings.Split(addr.String(), ".")
				label = strings.Join(parts[:2], ".") + ".*.*"
			} else {
				parts := strings.Split(addr.String(), ":")
				label = strings.Join(parts[:2], ":") + ":*:*"
			}
		}
		pairs = append(pairs, ip, fmt.Sprintf("%s [出口%d]", label, i+1))
	}
	// Replace longer IPs first to avoid matching an IPv4 suffix inside another IP.
	type pair struct{ from, to string }
	var sorted []pair
	for i := 0; i < len(pairs); i += 2 {
		sorted = append(sorted, pair{pairs[i], pairs[i+1]})
	}
	sort.SliceStable(sorted, func(i, j int) bool { return len(sorted[i].from) > len(sorted[j].from) })
	pairs = nil
	for _, p := range sorted {
		pairs = append(pairs, p.from, p.to)
	}
	b, err := json.Marshal(reportJSON(r))
	if err != nil {
		return Report{Version: r.Version, IPDisplay: "masked", Notes: []string{"报告脱敏失败，已隐藏报告内容；请从已保存的任务重新生成报告。"}}
	}
	b = []byte(strings.NewReplacer(pairs...).Replace(string(b)))
	var copy Report
	if json.Unmarshal(b, &copy) != nil {
		return Report{Version: r.Version, IPDisplay: "masked", Notes: []string{"报告脱敏失败，已隐藏报告内容；请从已保存的任务重新生成报告。"}}
	}
	return copy
}
