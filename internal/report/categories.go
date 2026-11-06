package report

import (
	"encoding/json"
	"strings"

	"github.com/nyktios/sniroute/internal/analysis"
	"github.com/nyktios/sniroute/internal/pack"
)

// DomainCategory is a display category, frozen with the report, independent
// of the network conclusions and comparison groups.
type DomainCategory struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

func buildCategories(r Report) []DomainCategory {
	var hosts []string
	for _, g := range r.Judgments.Groups {
		for _, d := range g.Domains {
			hosts = append(hosts, d.SNI)
		}
	}
	hosts = pack.SortedDomains(hosts)
	var params struct {
		Categories []pack.ReportCategory `json:"domain_categories"`
	}
	_ = json.Unmarshal(r.Task.Params, &params)
	if params.Categories == nil {
		lib, _ := pack.EmbeddedLibrary()
		params.Categories = lib.ReportCategories(hosts)
	}
	seen := map[int]bool{}
	var out []DomainCategory
	for _, c := range params.Categories {
		row := DomainCategory{Name: c.Name}
		for _, i := range c.Domains {
			if i >= 0 && i < len(hosts) && !seen[i] {
				row.Domains = append(row.Domains, hosts[i])
				seen[i] = true
			}
		}
		if len(row.Domains) > 0 {
			out = append(out, row)
		}
	}
	missing := DomainCategory{Name: "自定义 / 未分类"}
	for i, h := range hosts {
		if !seen[i] {
			missing.Domains = append(missing.Domains, h)
		}
	}
	if len(missing.Domains) > 0 {
		out = append(out, missing)
	}
	return out
}

type categoryIndices struct {
	Name    string
	Indices []int
}

func categoriesFor(r Report, gr analysis.GroupReport) []categoryIndices {
	categories := r.Categories
	if categories == nil {
		categories = buildCategories(r)
	}
	byHost := map[string]int{}
	for i, d := range gr.Group.Domains {
		byHost[strings.ToLower(d.SNI)] = i
	}
	var out []categoryIndices
	for _, c := range categories {
		row := categoryIndices{Name: c.Name}
		for _, h := range c.Domains {
			if i, ok := byHost[strings.ToLower(h)]; ok {
				row.Indices = append(row.Indices, i)
			}
		}
		if len(row.Indices) > 0 {
			out = append(out, row)
		}
	}
	return out
}

func domainSymbol(j analysis.Judgment, d analysis.DomainEgress) string {
	if j.Probe == analysis.ProbeFull && j.Completeness == analysis.Complete {
		if len(d.IPs) > 1 {
			return "◆"
		}
		return "●"
	}
	if j.Probe == analysis.ProbeNone {
		return "○"
	}
	return "△"
}

func domainIPs(d analysis.DomainEgress) string {
	if len(d.IPs) == 0 {
		return "未观测"
	}
	return IPList(d.IPs)
}
