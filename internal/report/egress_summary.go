package report

import (
	"fmt"
	"sort"
	"strings"
)

// EgressSummary is the first reading layer, with categories but no domains or
// query diagnostics. Comparisons remain separate inside the judgment engine.
type EgressSummary struct {
	Split       string        `json:"split"`
	Consistency string        `json:"sni_consistency"`
	IPCount     int           `json:"ip_count"`
	Exits       []ExitSummary `json:"exits"`
}
type ExitSummary struct {
	IP         string   `json:"ip"`
	Networks   string   `json:"networks"`
	Location   string   `json:"location"`
	Categories []string `json:"categories"`
}

func locationOrUnknown(s string) string {
	if s == "" {
		return "未知"
	}
	return s
}

func summarizeEgress(r Report) EgressSummary {
	s := EgressSummary{Split: "证据不足，无法判断", Consistency: "证据不足", Exits: []ExitSummary{}}
	byIP := map[string]*ExitSummary{}
	hosts := map[string]map[string]bool{}
	for _, g := range r.Egress {
		for _, e := range g.Rows {
			if byIP[e.IP] == nil {
				byIP[e.IP] = &ExitSummary{IP: e.IP, Networks: networkText(e.Networks, e.ASNStatus), Location: locationOrUnknown(e.Location), Categories: []string{}}
				hosts[e.IP] = map[string]bool{}
			}
			for _, h := range e.Domains {
				hosts[e.IP][strings.ToLower(h)] = true
			}
		}
	}
	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		row := byIP[ip]
		for _, c := range r.Categories {
			for _, h := range c.Domains {
				if hosts[ip][strings.ToLower(h)] {
					row.Categories = append(row.Categories, c.Name)
					break
				}
			}
		}
		s.Exits = append(s.Exits, *row)
	}
	s.IPCount = len(s.Exits)
	count, missing, changed, split := 0, false, false, false
	comparisonMissing := false
	for _, gr := range r.Judgments.Groups {
		if gr.Group.BaselineObserved == 0 || gr.Group.BaselineObserved < gr.Group.BaselinePlanned || gr.Baseline.Failed > 0 {
			comparisonMissing = true
		}
		for i, d := range gr.Group.Domains {
			count++
			if len(d.IPs) > 1 {
				changed = true
			}
			if d.Observed < 2 || d.Observed < d.Planned {
				missing = true
			}
			for _, rule := range gr.Domains[i].Rules {
				if rule.ID == "R01" && strings.HasPrefix(rule.Conclusion, "观测到与 SNI 相关的出口差异") {
					split = true
				}
			}
		}
	}
	if changed {
		s.Consistency = "不一致"
	} else if count > 0 && !missing {
		s.Consistency = "一致"
	}
	switch {
	case split:
		s.Split = "观测到与 SNI 相关的出口差异"
	case len(r.Overview.DifferentEgress) > 0:
		s.Split = "存在出口差异迹象，证据不足以确认 SNI 关联"
	case len(r.Overview.DynamicPool) > 0:
		s.Split = "动态出口池，未确认域名关联"
	case count > 0 && !missing && !comparisonMissing:
		s.Split = "本次未观测到出口差异"
	}
	return s
}

func (l *resultsLayout) egressSummary(r Report) {
	s := summarizeEgress(r)
	l.section("出口整理")
	l.line("分流判断："+s.Split, "")
	l.line("SNI 出口一致性："+s.Consistency, "")
	l.line(fmt.Sprintf("出口 IP：共 %d 个", s.IPCount), "title")
	for i, e := range s.Exits {
		l.printf("\n")
		l.line(fmt.Sprintf("出口 %d · %s", i+1, e.IP), "title")
		l.line("ASN："+e.Networks, "")
		l.line("归属地："+e.Location, "")
		categories := strings.Join(e.Categories, "、")
		if categories == "" {
			categories = "未在域名分类中观测到"
		}
		l.line("观测分类："+categories, "")
	}
}
