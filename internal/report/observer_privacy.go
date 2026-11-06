package report

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
)

// Keep comparison targets internally for analysis, but omit observer details
// from the exported report. Stored task snapshots and raw facts are unchanged.
type reportJSON Report

func (r Report) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(reportJSON(r))
	if err != nil {
		return nil, err
	}
	var value any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	var strip func(any)
	strip = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			if target, ok := v["target"].(string); ok && target != "" {
				v["family"] = Family(target)
			}
			for key, child := range v {
				switch key {
				case "target", "targets", "collector_id", "probe_pin", "control_pin", "server_url", "locations", "error":
					delete(v, key)
				default:
					strip(child)
				}
			}
		case []any:
			for _, child := range v {
				strip(child)
			}
		}
	}
	strip(value)
	if object, ok := value.(map[string]any); ok {
		object["egress_summary"] = summarizeEgress(r)
	}
	return json.Marshal(value)
}

func hideObserverText(r Report, s string) string {
	for _, target := range r.Overview.Targets {
		s = strings.ReplaceAll(s, target, "[观测端地址已隐藏]")
		if host, _, err := net.SplitHostPort(target); err == nil {
			s = strings.ReplaceAll(s, host, "[观测端地址已隐藏]")
		}
	}
	return s
}
