// Package report turns a task's recorded facts into a three-layer report
// (overview, per-domain judgments, raw evidence) and exports it as TXT, JSON
// and CSV. It only reads facts; nothing here changes what was observed.
package report

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/nyktios/sniroute/internal/analysis"
	"github.com/nyktios/sniroute/internal/asn"
	"github.com/nyktios/sniroute/internal/server"
)

// Version identifies the report layout.
const Version = "report-v3"

const FragmentExperimentNotice = "分片实验：仅调整首个 ClientHello 的 TLS record 边界，完整握手内容不变，后续握手不改写。分片可能改变上游识别及出口选择；本结果只代表该握手变体，不能证明与普通访问同一域名的出口等价。"

// ASNNote is shown when no egress-network lookup has been made for the task.
const ASNNote = "未查询（尚未执行出口网络归属查询）"

// Notes are the standing caveats printed with every report.
var Notes = []string{
	"出口 IP 来自受控探测（连接本工具的观测端），不代表真实网站看到的来源 IP；真实网站访问出口：未直接观测。",
	"“未观测”表示本次没有观测到，不等于没有出口；“与基线一致”不等于确定没有分流。",
	"本次只有一个观测端；“干预判断”是基于有限样本的迹象，不是对原因的认定。",
	"未执行、已取消或上报丢失的尝试不计为网络失败。",
	"出口网络（ASN / 组织）只说明出口 IP 由谁宣告，不代表被测服务商，也不能说明路径上的转接运营商或对等方；查询失败时出口 IP 仍然有效。",
}

// TaskInfo identifies the measured task and freezes its conditions.
type TaskInfo struct {
	ID            string          `json:"id"`
	Status        string          `json:"status"`
	CollectorID   string          `json:"collector_id"`
	NodeName      string          `json:"node_name"`
	ProviderLabel string          `json:"provider_label"`
	CreatedAt     time.Time       `json:"created_at"`
	ExpiresAt     time.Time       `json:"expires_at"`
	CancelledAt   *time.Time      `json:"cancelled_at,omitempty"`
	Params        json.RawMessage `json:"params,omitempty"` // test conditions, frozen at task creation
}

// Overview is the first reading layer.
type Overview struct {
	Planned        int `json:"planned"`
	Executed       int `json:"executed"` // attempts with any observer or client fact
	Unrun          int `json:"unrun"`    // no fact at all (not run, or reports lost)
	Cancelled      int `json:"cancelled"`
	Authenticated  int `json:"authenticated"`
	HelloMatched   int `json:"hello_matched"`
	HelloAmbiguous int `json:"hello_ambiguous"`
	SNIMismatch    int `json:"sni_mismatch"`
	Unobserved     int `json:"unobserved"` // client reported, observer saw nothing

	Networks          []string `json:"networks"` // distinct Origin ASNs of the observed egress IPs
	Targets           []string `json:"targets"`
	DistinctEgressIPs int      `json:"distinct_egress_ips"`
	DifferentEgress   []string `json:"different_egress"` // "domain @ target"
	DynamicPool       []string `json:"dynamic_pool"`
	Suspected         []string `json:"suspected"`
	Strong            []string `json:"strong"`

	Uncertain    []string              `json:"uncertain"`
	Completeness analysis.Completeness `json:"completeness"`
	ASN          string                `json:"asn"`
}

// EgressRow is one egress IP within a comparison group.
type EgressRow struct {
	IP            string     `json:"ip"`
	Location      string     `json:"location"`
	Domains       []string   `json:"domains"`
	Count         int        `json:"count"`
	Authenticated int        `json:"authenticated"`
	HelloMatched  int        `json:"hello_matched"`
	InBaseline    bool       `json:"in_baseline"`
	FirstSeen     *time.Time `json:"first_seen,omitempty"`
	LastSeen      *time.Time `json:"last_seen,omitempty"`
	Networks      []string   `json:"networks"` // "AS64500 Name"; empty when unknown
	Prefix        string     `json:"prefix,omitempty"`
	ASNStatus     string     `json:"asn_status"` // ok | no_data | failed | skipped_nonpublic | not_queried
}

// NetworkRow groups egress IPs that share the same Origin ASN set.
type NetworkRow struct {
	Networks   []string `json:"networks"` // empty: network unknown (not queried / failed / non-public / no data)
	IPs        []string `json:"ips"`
	Domains    []string `json:"domains"`
	Count      int      `json:"count"`
	InBaseline bool     `json:"in_baseline"`
}

// NetworkGroup lists egress networks for one comparison group.
type NetworkGroup struct {
	Target string       `json:"target"`
	Family string       `json:"family"`
	Rows   []NetworkRow `json:"rows"`
}

// ASNSection freezes the egress-network lookups the report was built from.
// Snapshots are append-only; a later refresh is a new snapshot, and this
// section says which one was used.
type ASNSection struct {
	Queried   bool       `json:"queried"`
	Source    string     `json:"source,omitempty"`
	Snapshot  int        `json:"snapshot,omitempty"`
	Snapshots int        `json:"snapshots,omitempty"`
	QueriedAt *time.Time `json:"queried_at,omitempty"`
	OK        int        `json:"ok"`
	NoData    int        `json:"no_data"`
	Failed    int        `json:"failed"`
	Skipped   int        `json:"skipped"`
	Items     []asn.Info `json:"items"`
}

// EgressGroup lists the egress IPs observed through one observer target.
type EgressGroup struct {
	Target string      `json:"target"`
	Family string      `json:"family"`
	Rows   []EgressRow `json:"rows"`
}

// Report is the full, exportable result of a task.
type Report struct {
	IPDisplay     string               `json:"ip_display"`
	Categories    []DomainCategory     `json:"domain_categories"`
	Version       string               `json:"version"`
	GeneratedAt   time.Time            `json:"generated_at"`
	RulesVersion  string               `json:"rules_version"`
	Task          TaskInfo             `json:"task"`
	Overview      Overview             `json:"overview"`
	Egress        []EgressGroup        `json:"egress_groups"`
	NetworkGroups []NetworkGroup       `json:"network_groups"`
	ASN           ASNSection           `json:"asn"`
	Judgments     analysis.Report      `json:"judgments"`
	Evidence      []server.AttemptView `json:"evidence"`
	Notes         []string             `json:"notes"`
}

// Family names the address family of an ip:port target.
func Family(target string) string {
	if ap, err := netip.ParseAddrPort(target); err == nil && ap.Addr().Is6() {
		return "IPv6"
	}
	return "IPv4"
}

// Build assembles the report for a task view. It is a pure function of the
// recorded facts, the rules and the clock.
func Build(v server.TaskView, now time.Time) Report {
	j := analysis.Judge(v)
	r := Report{
		IPDisplay: "full", Version: Version, GeneratedAt: now, RulesVersion: j.RulesVersion, Judgments: j,
		Task: TaskInfo{
			ID: v.ID, Status: string(v.Status), CollectorID: v.CollectorID, NodeName: v.Node.Name, ProviderLabel: v.Node.ProviderLabel,
			CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt, CancelledAt: v.CancelledAt, Params: v.Params,
		},
		Evidence: v.Attempts, Notes: Notes,
	}
	if r.Evidence == nil {
		r.Evidence = []server.AttemptView{}
	}
	infos := map[string]asn.Info{}
	if v.ASN != nil {
		for _, it := range v.ASN.Items {
			infos[it.IP] = it
		}
	}
	r.ASN = buildASN(v.ASN)
	r.Egress = buildEgress(v, infos)
	r.NetworkGroups = buildNetworks(r.Egress)
	r.Overview = buildOverview(v, j, r.Egress)
	r.Overview.ASN = describeASN(r.ASN)
	r.Overview.Networks = distinctNetworks(r.Egress)
	r.Categories = buildCategories(r)
	if fragmentExperiment(r) {
		r.Notes = append(append([]string(nil), r.Notes...), FragmentExperimentNotice)
	}
	return redactEgress(r)
}

func fragmentExperiment(r Report) bool {
	return fragmentPosition(r) != ""
}

func fragmentPosition(r Report) string {
	switch paramsOf(r)["client_hello_variant"] {
	case "tls-record-before-sni":
		return "SNI 扩展前"
	case "tls-record-sni-split":
		return "SNI 主机名内"
	case "tls-record-after-sni":
		return "SNI 扩展后"
	}
	return ""
}

func hasFact(a server.AttemptView) bool { return a.Observation != nil || len(a.Client) > 0 }

func buildOverview(v server.TaskView, j analysis.Report, eg []EgressGroup) Overview {
	o := Overview{Planned: len(v.Attempts), ASN: ASNNote, Targets: []string{}}
	seenTarget := map[string]bool{}
	for _, a := range v.Attempts {
		if !seenTarget[a.Target] {
			seenTarget[a.Target] = true
			o.Targets = append(o.Targets, a.Target)
		}
		if hasFact(a) {
			o.Executed++
		} else {
			o.Unrun++
		}
		switch a.State {
		case server.StateCancelled:
			o.Cancelled++
		case server.StateAuthenticated:
			o.Authenticated++
		case server.StateHelloMatched:
			o.HelloMatched++
		case server.StateHelloAmbig:
			o.HelloAmbiguous++
		case server.StateSNIMismatch:
			o.SNIMismatch++
		case server.StateUnobserved:
			o.Unobserved++
		}
	}
	ips := map[string]bool{}
	for _, g := range eg {
		for _, row := range g.Rows {
			ips[row.IP] = true
		}
	}
	o.DistinctEgressIPs = len(ips)

	worst := analysis.Complete
	rank := map[analysis.Completeness]int{analysis.Complete: 0, analysis.MissingControl: 1, analysis.Partial: 2, analysis.Cancelled: 3}
	for _, gr := range j.Groups {
		for _, d := range gr.Domains {
			tag := d.SNI + "（" + Family(gr.Group.Target) + "）"
			switch d.Egress {
			case analysis.DifferentFromBaseline:
				o.DifferentEgress = append(o.DifferentEgress, tag)
			case analysis.DynamicPool, analysis.Mixed:
				o.DynamicPool = append(o.DynamicPool, tag)
			}
			switch d.Intervention {
			case analysis.LevelSuspected:
				o.Suspected = append(o.Suspected, tag)
			case analysis.LevelStrong:
				o.Strong = append(o.Strong, tag)
			}
			if rank[d.Completeness] > rank[worst] {
				worst = d.Completeness
			}
			if d.Probe == analysis.ProbeIdentity {
				o.Uncertain = append(o.Uncertain, tag+"：受控探测端点身份不匹配")
			}
			if d.Egress == analysis.NoBaseline {
				o.Uncertain = append(o.Uncertain, tag+"：无基线可比")
			}
		}
		if gr.Baseline.Failed > 0 {
			o.Uncertain = append(o.Uncertain, fmt.Sprintf("%s：基线 %d 次中失败 %d 次，域名失败证据不足", Family(gr.Group.Target), gr.Baseline.Executed, gr.Baseline.Failed))
		}
	}
	if o.HelloAmbiguous > 0 {
		o.Uncertain = append(o.Uncertain, fmt.Sprintf("%d 次握手匹配有歧义，未归属来源", o.HelloAmbiguous))
	}
	if o.SNIMismatch > 0 {
		o.Uncertain = append(o.Uncertain, fmt.Sprintf("%d 次回执中观测到的 SNI 与计划不符", o.SNIMismatch))
	}
	o.Completeness = worst
	if v.Status == server.TaskAborted {
		o.Completeness = analysis.Cancelled
	}
	return o
}

func buildEgress(v server.TaskView, infos map[string]asn.Info) []EgressGroup {
	type key struct{ target, ip string }
	rows := map[key]*EgressRow{}
	doms := map[key]map[string]bool{}
	var order []string
	seen := map[string]bool{}
	for _, a := range v.Attempts {
		if !seen[a.Target] {
			seen[a.Target] = true
			order = append(order, a.Target)
		}
		o := a.Observation
		if o == nil || o.SourceIP == "" || !o.SNIMatch || (a.State != server.StateAuthenticated && a.State != server.StateHelloMatched) {
			continue
		}
		k := key{a.Target, o.SourceIP}
		row := rows[k]
		if row == nil {
			row = &EgressRow{IP: o.SourceIP, Domains: []string{}, Networks: []string{}, ASNStatus: "not_queried"}
			if inf, ok := infos[o.SourceIP]; ok {
				row.ASNStatus, row.Prefix = string(inf.Status), inf.Prefix
				row.Location = asn.LocationText(inf.Locations)
				for _, n := range inf.ASNs {
					row.Networks = append(row.Networks, n.Label())
				}
			}
			rows[k] = row
			doms[k] = map[string]bool{}
		}
		row.Count++
		if a.State == server.StateAuthenticated {
			row.Authenticated++
		} else {
			row.HelloMatched++
		}
		if a.Kind == "baseline" {
			row.InBaseline = true
		} else if !doms[k][strings.ToLower(a.SNI)] {
			doms[k][strings.ToLower(a.SNI)] = true
			row.Domains = append(row.Domains, a.SNI)
		}
		t := o.ObservedAt
		if !t.IsZero() {
			if row.FirstSeen == nil || t.Before(*row.FirstSeen) {
				row.FirstSeen = &t
			}
			if row.LastSeen == nil || t.After(*row.LastSeen) {
				row.LastSeen = &t
			}
		}
	}
	out := make([]EgressGroup, 0, len(order))
	for _, target := range order {
		g := EgressGroup{Target: target, Family: Family(target), Rows: []EgressRow{}}
		for k, row := range rows {
			if k.target == target {
				sort.Strings(row.Domains)
				g.Rows = append(g.Rows, *row)
			}
		}
		sort.Slice(g.Rows, func(i, j int) bool {
			if g.Rows[i].Count != g.Rows[j].Count {
				return g.Rows[i].Count > g.Rows[j].Count
			}
			return g.Rows[i].IP < g.Rows[j].IP
		})
		out = append(out, g)
	}
	return out
}

func buildASN(v *server.ASNView) ASNSection {
	a := ASNSection{Items: []asn.Info{}}
	if v == nil {
		return a
	}
	a.Queried, a.Source, a.Snapshot, a.Snapshots = true, v.Source, v.Snapshot, v.Snapshots
	t := v.QueriedAt
	a.QueriedAt = &t
	a.Items = v.Items
	for _, it := range v.Items {
		switch it.Status {
		case asn.StatusOK:
			a.OK++
		case asn.StatusNoData:
			a.NoData++
		case asn.StatusFailed:
			a.Failed++
		case asn.StatusSkipped:
			a.Skipped++
		}
	}
	return a
}

func describeASN(a ASNSection) string {
	if !a.Queried {
		return ASNNote
	}
	return fmt.Sprintf("%s · 快照 %d/%d · 查询于 %s · 成功 %d / 无数据 %d / 失败 %d / 非公网跳过 %d",
		a.Source, a.Snapshot, a.Snapshots, a.QueriedAt.Local().Format("2006-01-02 15:04:05"), a.OK, a.NoData, a.Failed, a.Skipped)
}

func distinctNetworks(eg []EgressGroup) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, g := range eg {
		for _, row := range g.Rows {
			for _, n := range row.Networks {
				if !seen[n] {
					seen[n] = true
					out = append(out, n)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// buildNetworks groups each comparison group's egress IPs by Origin ASN set.
// IPs without a usable lookup are kept together as "unknown", never merged
// into a real network.
func buildNetworks(eg []EgressGroup) []NetworkGroup {
	out := make([]NetworkGroup, 0, len(eg))
	for _, g := range eg {
		byKey := map[string]*NetworkRow{}
		var keys []string
		for _, e := range g.Rows {
			key := strings.Join(e.Networks, "|")
			row := byKey[key]
			if row == nil {
				row = &NetworkRow{Networks: e.Networks, IPs: []string{}, Domains: []string{}}
				byKey[key] = row
				keys = append(keys, key)
			}
			row.IPs = append(row.IPs, e.IP)
			row.Count += e.Count
			row.InBaseline = row.InBaseline || e.InBaseline
			for _, d := range e.Domains {
				dup := false
				for _, x := range row.Domains {
					if strings.EqualFold(x, d) {
						dup = true
					}
				}
				if !dup {
					row.Domains = append(row.Domains, d)
				}
			}
		}
		ng := NetworkGroup{Target: g.Target, Family: g.Family, Rows: []NetworkRow{}}
		for _, k := range keys {
			row := byKey[k]
			sort.Strings(row.Domains)
			ng.Rows = append(ng.Rows, *row)
		}
		sort.SliceStable(ng.Rows, func(i, j int) bool { return ng.Rows[i].Count > ng.Rows[j].Count })
		out = append(out, ng)
	}
	return out
}
