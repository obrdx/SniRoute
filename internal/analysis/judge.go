package analysis

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/nyktios/sniroute/internal/asn"
	"github.com/nyktios/sniroute/internal/server"
)

// RulesVersion is written into reports so conclusions can be traced to the
// rule set that produced them. Bump it whenever a rule changes.
const RulesVersion = "rules-v2"

// EndpointIdentityNotice explains an existing identity failure without claiming
// that its cause, the proxy location or a real website's egress has been proved.
const EndpointIdentityNotice = "探测端公钥不匹配：上游可能存在代理嗅探 SNI 并改写目的地（透明转发/劫持），也可能是目标地址、端口或观测端配置不一致。原因及位置未确定，不判封锁；未取得观测端匹配证据时，出口为“未观测”，不能用基线或 IP 检测网站的出口替代。"

// ProbeStatus is the controlled-probe dimension (SNI probes to the observer).
type ProbeStatus string

const (
	ProbeNone         ProbeStatus = "none"              // nothing executed
	ProbeFull         ProbeStatus = "full_success"      // authenticated receipts only
	ProbeMixed        ProbeStatus = "mixed"             // some succeeded, some failed
	ProbeHelloOnly    ProbeStatus = "hello_only"        // ClientHello reached the observer, nothing authenticated
	ProbeHandshakeErr ProbeStatus = "handshake_error"   // ClientHello sent, observer saw nothing, then failure
	ProbeIdentity     ProbeStatus = "identity_mismatch" // observer key did not match the pin
	ProbePreHello     ProbeStatus = "pre_hello_failure" // failed before any ClientHello was sent
)

// Level is the intervention dimension. Controlled-probe rules only emit none
// or suspected. Strong and explicit remain as historical report values.
type Level string

const (
	LevelNone      Level = "none"      // no sufficient sign
	LevelSuspected Level = "suspected" // 疑似
	LevelStrong    Level = "strong"    // 较强迹象
	LevelExplicit  Level = "explicit"  // 明确阻断响应 (unused)
)

// Completeness describes how much of the planned evidence exists.
type Completeness string

const (
	Complete       Completeness = "complete"
	Partial        Completeness = "partial"         // planned attempts without any record
	Cancelled      Completeness = "cancelled"       // the task was cancelled; unrun attempts are not failures
	MissingControl Completeness = "missing_control" // observer facts without the client's report
)

// Confidence is deliberately coarse. Cause confidence never exceeds medium
// while there is a single observer.
type Confidence string

const (
	ConfNone   Confidence = ""
	ConfLow    Confidence = "low"
	ConfMedium Confidence = "medium"
	ConfHigh   Confidence = "high"
)

// RuleHit is one rule that fired, with what it rests on and what it cannot say.
type RuleHit struct {
	ID         string   `json:"id"`
	Conclusion string   `json:"conclusion"`
	Basis      []string `json:"basis,omitempty"`
	Limits     []string `json:"limits,omitempty"`
}

// Judgment describes controlled egress evidence for one domain and comparison group.
type Judgment struct {
	Target string `json:"target"`
	SNI    string `json:"sni"`

	Egress       Egress       `json:"egress"`
	Probe        ProbeStatus  `json:"probe"`
	Intervention Level        `json:"intervention"`
	Completeness Completeness `json:"completeness"`

	// FactConfidence rates the observed facts; CauseConfidence rates any
	// causal reading (egress difference, intervention). Empty when no cause is claimed.
	FactConfidence  Confidence `json:"fact_confidence"`
	CauseConfidence Confidence `json:"cause_confidence"`

	// Networks are the Origin ASNs of the domain's observed egress IPs (when a
	// lookup snapshot exists). They name who announces the address, not the
	// retail provider and not any transit operator on the path.
	Networks []string `json:"networks,omitempty"`

	Rules []RuleHit `json:"rules"`
}

// GroupReport is one comparison group (one observer target).
type GroupReport struct {
	Group    Group      `json:"group"`
	Domains  []Judgment `json:"domains"`
	Baseline BaseStats  `json:"baseline_stats"`
}

// BaseStats summarises the group's baseline attempts.
type BaseStats struct {
	Executed int `json:"executed"`
	Failed   int `json:"failed"`
}

// Report is the full judgment of a task.
type Report struct {
	RulesVersion string        `json:"rules_version"`
	Groups       []GroupReport `json:"groups"`
}

type kind int

const (
	kNone kind = iota // not executed / cancelled / no record
	kSuccess
	kHelloOnly
	kIdentity
	kPreHello
	kAfterHello
	kMismatch // receipt issued but a different SNI was seen
)

type tally struct {
	n        [kMismatch + 1]int
	failStg  map[string]int // "outcome@stage" of failures after the hello was sent
	planned  int
	noClient int // observed attempts the client never reported on
}

func (t tally) executed() int {
	return t.n[kSuccess] + t.n[kHelloOnly] + t.n[kIdentity] + t.n[kPreHello] + t.n[kAfterHello] + t.n[kMismatch]
}
func (t tally) failures() int {
	return t.n[kHelloOnly] + t.n[kIdentity] + t.n[kPreHello] + t.n[kAfterHello]
}

func classifyAttempt(a server.AttemptView) (kind, string) {
	last := ""
	hello := false
	if n := len(a.Client); n > 0 {
		c := a.Client[n-1]
		last, hello = c.Outcome+"@"+c.Stage, c.HelloSent
		if c.Outcome == "cancelled" && a.Observation == nil {
			return kNone, ""
		}
	}
	switch a.State {
	case server.StateAuthenticated:
		return kSuccess, last
	case server.StateHelloMatched:
		return kHelloOnly, last
	case server.StateSNIMismatch:
		return kMismatch, last
	case server.StateHelloAmbig:
		return kAfterHello, last
	case server.StateUnobserved:
		switch {
		case strings.HasPrefix(last, "identity_mismatch"):
			return kIdentity, last
		case !hello:
			return kPreHello, last
		default:
			return kAfterHello, last
		}
	}
	return kNone, ""
}

func tallyAttempts(as []server.AttemptView) tally {
	t := tally{failStg: map[string]int{}}
	for _, a := range as {
		t.planned++
		k, stage := classifyAttempt(a)
		t.n[k]++
		if k == kAfterHello || k == kHelloOnly {
			t.failStg[stage]++
		}
		if a.Observation != nil && len(a.Client) == 0 {
			t.noClient++
		}
	}
	return t
}

// Judge evaluates every (group, domain) of a task view.
func Judge(v server.TaskView) Report {
	rep := Report{RulesVersion: RulesVersion}
	aborted := v.Status == server.TaskAborted
	nets := netsOf(v)

	for _, g := range EgressByGroup(v) {
		var base []server.AttemptView
		byDomain := map[string][]server.AttemptView{}
		for _, a := range v.Attempts {
			if a.Target != g.Target {
				continue
			}
			if a.Kind == "baseline" {
				base = append(base, a)
			} else {
				k := strings.ToLower(a.SNI)
				byDomain[k] = append(byDomain[k], a)
			}
		}
		bt := tallyAttempts(base)
		gr := GroupReport{Group: g, Baseline: BaseStats{Executed: bt.executed(), Failed: bt.failures()}}

		// First pass: classify each domain so group-wide rules can see how many fail.
		type pre struct {
			d DomainEgress
			t tally
		}
		pres := make([]pre, len(g.Domains))
		failing := 0
		for i, d := range g.Domains {
			pres[i] = pre{d, tallyAttempts(byDomain[strings.ToLower(d.SNI)])}
			if pres[i].t.failures() > 0 {
				failing++
			}
		}
		for _, p := range pres {
			gr.Domains = append(gr.Domains, judgeDomain(g, p.d, p.t, bt, failing, aborted, nets))
		}
		rep.Groups = append(rep.Groups, gr)
	}
	return rep
}

func judgeDomain(g Group, d DomainEgress, t, bt tally, failingDomains int, aborted bool, nets netMap) Judgment {
	j := Judgment{Target: g.Target, SNI: d.SNI, Egress: d.Result, Intervention: LevelNone, Rules: []RuleHit{}}

	// ---- dimension: controlled probe
	succ, fail := t.n[kSuccess], t.failures()
	switch {
	case t.executed() == 0:
		j.Probe = ProbeNone
	case fail == 0:
		j.Probe = ProbeFull
	case succ > 0:
		j.Probe = ProbeMixed
	case t.n[kIdentity] > 0:
		j.Probe = ProbeIdentity
	case t.n[kAfterHello] > 0:
		j.Probe = ProbeHandshakeErr
	case t.n[kHelloOnly] > 0:
		j.Probe = ProbeHelloOnly
	default:
		j.Probe = ProbePreHello
	}

	// ---- completeness and fact confidence
	j.Completeness = Complete
	switch {
	case aborted && t.executed() < t.planned:
		j.Completeness = Cancelled
	case t.noClient > 0:
		// Observer facts without the client's report: the root cause of any
		// gaps, so it is named in preference to "partial".
		j.Completeness = MissingControl
	case t.executed() < t.planned:
		j.Completeness = Partial
	}
	j.FactConfidence = factConfidence(d)
	if set, _ := nets.asns(d.IPs); len(set) > 0 {
		j.Networks = labelsOf(set)
	}

	baselineSeen, baselineBad := bt.executed() > 0, bt.failures() > 0
	hit := func(id, conclusion string, basis, limits []string) {
		j.Rules = append(j.Rules, RuleHit{ID: id, Conclusion: conclusion, Basis: basis, Limits: limits})
	}
	const (
		limSingle  = "只有一个观测端，样本有限。"
		limNotReal = "受控探测出口不代表真实网站看到的来源 IP。"
	)

	// R10: nothing to judge.
	if t.executed() == 0 {
		concl := "没有可用记录（未执行或上报丢失），不作网络失败判定。"
		if aborted {
			concl = "任务已被取消，该域名没有可用记录；未执行的尝试不作网络失败判定。"
		}
		hit("R10", concl, nil, nil)
		return j
	}

	// R09: the baseline is unhealthy in the same window — environment first.
	envDoubt := baselineBad && fail > 0
	if envDoubt {
		hit("R09", "基线在同一测试中也出现失败：先怀疑测试环境、观测端或整体路径，域名失败证据不足。",
			[]string{fmt.Sprintf("基线 %d 次中失败 %d 次", bt.executed(), bt.failures()), fmt.Sprintf("本组共有 %d 个域名出现失败", failingDomains)},
			[]string{"在基线恢复正常前不对该域名的失败作干预判断。"})
	}

	// ---- egress rules
	ips := SortedIPs(d.IPs)
	switch d.Result {
	case DifferentFromBaseline:
		stable := len(d.IPs) == 1 && len(g.BaselineIPs) == 1 && d.Observed >= 2 && !baselineBad
		basis := []string{fmt.Sprintf("该域名 %d 次观测来自 %s", d.Observed, strings.Join(ips, "、")),
			fmt.Sprintf("基线 %d 次观测来自 %s", g.BaselineObserved, strings.Join(SortedIPs(g.BaselineIPs), "、"))}
		if stable {
			limits := []string{limNotReal, limSingle, "只能说明观测到的差异，不能证明上游仅以 SNI 作为分流条件。"}
			j.CauseConfidence = ConfLow
			if d.Evidence.Authenticated >= 3 && g.BaselineObserved >= 3 {
				j.CauseConfidence = ConfMedium
			}
			// Egress IPs are the fact; their networks add context. Different
			// IPs inside the same ASN are weaker evidence of a different route.
			if dset, dok := nets.asns(d.IPs); dok {
				if bset, bok := nets.asns(g.BaselineIPs); bok {
					basis = append(basis, "出口网络：该域名 "+strings.Join(labelsOf(dset), "、")+"；基线 "+strings.Join(labelsOf(bset), "、"))
					for n := range dset {
						if _, same := bset[n]; same {
							limits = append(limits, "两组出口 IP 属于同一 ASN（AS"+strconv.Itoa(n)+"）：差异可能只是同一网络内的不同出口，尚不能说明经由不同网络。")
							j.CauseConfidence = ConfLow
							break
						}
					}
				}
			}
			hit("R01", "观测到与 SNI 相关的出口差异（在本组固定目标 IP 与 ALPN 的条件下）。", basis, limits)
		} else {
			hit("R01", "出口差异迹象，但样本不足或不稳定，尚不能确认与 SNI 相关。", basis, []string{limNotReal, limSingle})
			j.CauseConfidence = ConfLow
		}
	case DynamicPool, Mixed:
		hit("R02", "基线与该域名使用多个出口或动态出口，未确认出口与域名相关。",
			[]string{fmt.Sprintf("该域名出口：%s；基线出口：%s", strings.Join(ips, "、"), strings.Join(SortedIPs(g.BaselineIPs), "、"))},
			[]string{"没有稳定的域名关联不等于确定没有分流。"})
	}

	// ---- controlled-probe failure rules (suppressed when the baseline is unhealthy)
	if !envDoubt {
		if t.n[kPreHello] > 0 && t.n[kAfterHello] == 0 && t.n[kIdentity] == 0 {
			hit("R03", "TCP 在发送 ClientHello 之前就失败：属于 TCP / 目标路径异常，不归因于 SNI。",
				[]string{fmt.Sprintf("%d 次尝试在发出 ClientHello 前失败", t.n[kPreHello])}, []string{limSingle})
		}
		if t.n[kHelloOnly] > 0 {
			hit("R05", "观测端收到了与该次尝试匹配的 ClientHello，但客户端后续握手未完成：请求已到达，保留观测出口，标记后续握手或回程异常。",
				[]string{fmt.Sprintf("%d 次仅握手匹配（未认证）", t.n[kHelloOnly])},
				[]string{"仅握手匹配的证据弱于认证回执。", limNotReal})
		}
		if a := t.n[kAfterHello]; a >= 2 && a*2 >= t.executed() && baselineSeen {
			basis := []string{
				fmt.Sprintf("该域名 %d 次中有 %d 次在 ClientHello 发出后失败且观测端未见到", t.executed(), a),
				fmt.Sprintf("基线 %d 次均正常", bt.executed()),
			}
			consistent := len(t.failStg) == 1
			if consistent {
				for s := range t.failStg {
					basis = append(basis, "失败阶段一致："+s)
				}
			}
			j.Intervention, j.CauseConfidence = LevelSuspected, ConfLow
			concl := "疑似 SNI 相关干预或分流路径异常。"
			hit("R04", concl, basis, []string{"仍不能区分服务商主动拒绝、上游干预，或该域名被分到了故障线路。", limSingle})
		}
		if t.n[kIdentity] > 0 {
			hit("R08", "受控探测遇到的端点公钥与固定公钥不一致：可能存在上游代理嗅探 SNI 后改写目的地（透明转发或劫持），或 TLS 中间设备。该次探测已停止并未发送任何凭证；不判定为域名封锁。",
				[]string{fmt.Sprintf("%d 次身份不匹配", t.n[kIdentity])},
				[]string{"也可能是探测目标地址、端口或观测端实例配置不一致，或任务期间探测密钥发生变化；仅凭公钥不匹配不能确定原因及代理位置。", "未取得观测端匹配证据时，出口为“未观测”；不能以基线或 IP 检测网站的出口替代该域名的出口。"})
		}
	}

	return j
}

func factConfidence(d DomainEgress) Confidence {
	switch {
	case d.Evidence.Authenticated >= 3:
		return ConfHigh
	case d.Evidence.Authenticated == 2:
		return ConfMedium
	case d.Observed > 0:
		return ConfLow
	}
	return ConfNone
}

// ---- egress networks -----------------------------------------------------

// netMap maps an egress IP to its Origin ASNs, for IPs with a usable lookup.
type netMap map[string][]asn.Number

func netsOf(v server.TaskView) netMap {
	if v.ASN == nil {
		return nil
	}
	m := netMap{}
	for _, it := range v.ASN.Items {
		if it.Status == asn.StatusOK && len(it.ASNs) > 0 {
			m[it.IP] = it.ASNs
		}
	}
	return m
}

// asns returns the distinct ASNs of ips and whether EVERY ip had a lookup.
// With any gap the comparison is not made: an unknown is not "different".
func (m netMap) asns(ips map[string]int) (map[int]asn.Number, bool) {
	out := map[int]asn.Number{}
	complete := len(ips) > 0
	for ip := range ips {
		list, ok := m[ip]
		if !ok {
			complete = false
			continue
		}
		for _, n := range list {
			if cur, seen := out[n.ASN]; !seen || cur.Name == "" {
				out[n.ASN] = n
			}
		}
	}
	return out, complete && m != nil
}

func labelsOf(set map[int]asn.Number) []string {
	nums := make([]int, 0, len(set))
	for n := range set {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	out := make([]string, len(nums))
	for i, n := range nums {
		out[i] = set[n].Label()
	}
	return out
}
