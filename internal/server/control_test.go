package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nyktios/sniroute/internal/asn"
	"github.com/nyktios/sniroute/internal/store"
)

type api struct {
	t   *testing.T
	url string
}

func (a api) do(method, path, key string, body any) (int, map[string]any) {
	a.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, a.url+path, rd)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func planBody(target string, snis ...string) map[string]any {
	var att []map[string]any
	for _, s := range snis {
		att = append(att, map[string]any{"target": target, "sni": s, "kind": "domain", "round": 1})
	}
	return map[string]any{"attempts": att}
}

func newAPI(t *testing.T) (api, *testEnv) {
	t.Helper()
	e := newEnv(t, TasksConfig{})
	ts := httptest.NewServer(NewControl(e.reg, e.tasks, "pin-abc", nil).Handler())
	t.Cleanup(ts.Close)
	return api{t, ts.URL}, e
}

func (a api) register(name, label string) map[string]any {
	a.t.Helper()
	_, tok := a.do("POST", "/api/admin/reg-tokens", adminKey, nil)
	code, b := a.do("POST", "/api/register", "", map[string]string{"reg_token": tok["token"].(string), "name": name, "provider_label": label})
	if code != 201 {
		a.t.Fatalf("register: %d %v", code, b)
	}
	return b
}

func TestControlAuthAndRegistration(t *testing.T) {
	a, _ := newAPI(t)

	if code, _ := a.do("POST", "/api/admin/reg-tokens", "", nil); code != 401 {
		t.Errorf("no admin key: %d", code)
	}
	if code, _ := a.do("GET", "/api/admin/connections", "wrong", nil); code != 401 {
		t.Errorf("wrong admin key: %d", code)
	}

	_, rk := a.do("POST", "/api/admin/reg-tokens", adminKey, nil)
	code, b := a.do("POST", "/api/register", "", map[string]string{"reg_token": rk["token"].(string), "name": "vps-1", "provider_label": "ProviderX"})
	if code != 201 || b["probe_pin"] != "pin-abc" || b["collector_id"] != "collector-1" {
		t.Fatalf("register: %d %v", code, b)
	}
	if code, _ := a.do("POST", "/api/register", "", map[string]string{"reg_token": rk["token"].(string), "name": "again"}); code != 401 {
		t.Errorf("reg token reuse: %d", code)
	}

	path, key := b["path"].(string), b["node_key"].(string)
	tasksURL := "/n/" + path + "/tasks"
	req := planBody("127.0.0.1:443", "www.google.com")
	for _, k := range []string{"", "wrong", adminKey} {
		if code, _ := a.do("POST", tasksURL, k, req); code != 401 {
			t.Errorf("key %q: %d", k, code)
		}
	}
	if code, _ := a.do("POST", "/n/unknown/tasks", key, req); code != 401 {
		t.Errorf("unknown path: %d", code)
	}
	if code, _ := a.do("POST", tasksURL, key, planBody("x", "a")); code != 400 {
		t.Errorf("bad target: %d", code)
	}
	if code, _ := a.do("POST", tasksURL, key, map[string]any{"bogus": 1}); code != 400 {
		t.Errorf("unknown field: %d", code)
	}
}

func TestControlTaskAndEvents(t *testing.T) {
	a, e := newAPI(t)
	n := a.register("vps-1", "ProviderX")
	path, key := n["path"].(string), n["node_key"].(string)

	code, b := a.do("POST", "/n/"+path+"/tasks", key, planBody("127.0.0.1:443", "a.com", "b.com"))
	if code != 201 || b["probe_pin"] != "pin-abc" {
		t.Fatalf("create: %d %v", code, b)
	}
	taskID := b["task"].(map[string]any)["id"].(string)
	att := b["attempts"].([]any)
	if len(att) != 2 || att[0].(map[string]any)["credential"] == "" {
		t.Fatalf("attempts: %v", att)
	}
	attID := att[0].(map[string]any)["id"].(string)

	// Report a client-side failure; the task view merges it.
	ev := map[string]any{"attempt_id": attID, "event_id": "e1", "stage": "tcp", "outcome": "dial_failed", "error": "refused",
		"started_at": time.Now().Format(time.RFC3339Nano), "duration_ms": 3}
	for range 2 { // idempotent
		if code, _ := a.do("POST", "/n/"+path+"/tasks/"+taskID+"/events", key, ev); code != 204 {
			t.Fatalf("event: %d", code)
		}
	}
	code, view := a.do("GET", "/n/"+path+"/tasks/"+taskID, key, nil)
	a0 := view["attempts"].([]any)[0].(map[string]any)
	if code != 200 || a0["state"] != "unobserved" || len(a0["client_events"].([]any)) != 1 {
		t.Fatalf("view: %d %v", code, view)
	}

	// Rejected event.
	ev["event_id"], ev["stage"] = "e2", "dns"
	if code, _ := a.do("POST", "/n/"+path+"/tasks/"+taskID+"/events", key, ev); code != 400 {
		t.Errorf("bad stage: %d", code)
	}

	// Another node cannot read or report on it.
	o := a.register("other", "")
	if code, _ := a.do("GET", "/n/"+o["path"].(string)+"/tasks/"+taskID, o["node_key"].(string), nil); code != 404 {
		t.Errorf("cross-node read: %d", code)
	}
	if code, _ := a.do("POST", "/n/"+o["path"].(string)+"/tasks/"+taskID+"/events", o["node_key"].(string), ev); code != 400 {
		t.Errorf("cross-node event: %d", code)
	}

	// Retired node administration endpoints cannot access identities.
	for _, endpoint := range []struct{ method, path string }{
		{"GET", "/api/admin/nodes"},
		{"POST", "/api/admin/nodes/" + n["node_id"].(string) + "/revoke"},
		{"POST", "/api/admin/nodes/" + n["node_id"].(string) + "/rotate-key"},
	} {
		if code, _ := a.do(endpoint.method, endpoint.path, adminKey, nil); code != 404 {
			t.Errorf("retired endpoint: %s %d", endpoint.path, code)
		}
	}
	_ = e
}

func TestControlCancelAndListEndpoints(t *testing.T) {
	a, _ := newAPI(t)
	n := a.register("vps", "")
	path, key := n["path"].(string), n["node_key"].(string)
	_, b := a.do("POST", "/n/"+path+"/tasks", key, planBody("127.0.0.1:443", "a.com", "b.com"))
	taskID := b["task"].(map[string]any)["id"].(string)

	if code, _ := a.do("POST", "/n/"+path+"/tasks/"+taskID+"/cancel", "", nil); code != 401 {
		t.Errorf("cancel without key: %d", code)
	}
	if code, _ := a.do("POST", "/n/"+path+"/tasks/"+taskID+"/cancel", key, nil); code != 204 {
		t.Fatalf("cancel: %d", code)
	}
	if code, _ := a.do("POST", "/n/"+path+"/tasks/task_nope/cancel", key, nil); code != 400 {
		t.Errorf("cancel unknown: %d", code)
	}
	_, view := a.do("GET", "/n/"+path+"/tasks/"+taskID, key, nil)
	if view["status"] != "aborted" || view["cancelled_at"] == nil {
		t.Errorf("view: %v", view["status"])
	}
	if node := view["node"].(map[string]any); node["name"] != "vps" {
		t.Errorf("node: %v", node)
	}

	code, list := a.do("GET", "/n/"+path+"/tasks?limit=5", key, nil)
	items := list["tasks"].([]any)
	if code != 200 || len(items) != 1 || items[0].(map[string]any)["status"] != "aborted" {
		t.Errorf("list: %d %v", code, list)
	}
	if code, _ := a.do("GET", "/n/"+path+"/tasks", "wrong", nil); code != 401 {
		t.Errorf("list without key: %d", code)
	}
}

func TestWebsiteMeasurementEndpointsAreRemoved(t *testing.T) {
	a, _ := newAPI(t)
	n := a.register("vps", "")
	path, key := n["path"].(string), n["node_key"].(string)
	_, created := a.do("POST", "/n/"+path+"/tasks", key, planBody("127.0.0.1:443", "a.com"))
	taskID := created["task"].(map[string]any)["id"].(string)
	base := "/n/" + path + "/tasks/" + taskID
	for _, endpoint := range []string{"webchecks", "reference"} {
		code, _ := a.do("POST", base+"/"+endpoint, key, map[string]any{"host": "a.com"})
		if code != http.StatusNotFound {
			t.Errorf("retired endpoint %s: status %d", endpoint, code)
		}
	}
	code, view := a.do("GET", base, key, nil)
	if code != http.StatusOK {
		t.Fatalf("get task: %d", code)
	}
	if _, exists := view["web_checks"]; exists {
		t.Error("task still exposes retired website measurements")
	}
}

func TestControlASNEndpoint(t *testing.T) {
	a, e := newAPI(t)
	n := a.register("vps", "")
	path, key := n["path"].(string), n["node_key"].(string)
	_, b := a.do("POST", "/n/"+path+"/tasks", key, planBody("127.0.0.1:443", "a.com"))
	taskID := b["task"].(map[string]any)["id"].(string)
	url := "/n/" + path + "/tasks/" + taskID + "/asn"

	if code, _ := a.do("POST", url, "", nil); code != 401 {
		t.Errorf("no key: %d", code)
	}
	// Lookups switched off: a clear answer, not an error.
	if code, body := a.do("POST", url, key, nil); code != 200 || body["enabled"] != false {
		t.Errorf("disabled: %d %v", code, body)
	}
	if code, _ := a.do("POST", "/n/"+path+"/tasks/task_nope/asn", key, nil); code != 400 {
		t.Errorf("unknown task: %d", code)
	}

	// Enabled, with one observed public IP.
	f := &asnFake{}
	f.label.Store("Net")
	e.tasks.ASN = asn.NewService(f, nil, asn.Config{})
	att := b["attempts"].([]any)[0].(map[string]any)
	e.creds.Path = path // the receipt is authenticated against the task owner's path
	e.receiptFrom(IssuedAttempt{ID: att["id"].(string), Credential: att["credential"].(string)}, "a.com", "192.0.2.44")
	code, body := a.do("POST", url, key, map[string]any{"refresh": false})
	if code != 200 || body["enabled"] != true {
		t.Fatalf("enabled: %d %v", code, body)
	}
	code, view := a.do("GET", "/n/"+path+"/tasks/"+taskID, key, nil)
	if code != 200 || view["asn"] == nil {
		t.Errorf("task view lacks the snapshot: %d %v", code, view["asn"])
	}
	if code, _ := a.do("GET", "/n/"+path+"/tasks/"+taskID+"?asn=7", key, nil); code != 200 {
		t.Errorf("unknown snapshot number should read as no snapshot, not fail: %d", code)
	}
	if code, _ := a.do("POST", url, key, map[string]any{"refresh": true, "bogus": 1}); code != 400 {
		t.Errorf("unknown field: %d", code)
	}
}

// TestJoinPageAndHealth covers the two unauthenticated endpoints. Neither may
// leak a token, and /join must not be cached or refer its URL onward.
func TestJoinPageAndHealth(t *testing.T) {
	e := newEnv(t, TasksConfig{})
	ts := httptest.NewServer(NewControl(e.reg, e.tasks, "pin-abc", nil).WithProbeAddr("0.0.0.0:8443").Handler())
	defer ts.Close()

	res, err := http.Get(ts.URL + "/join")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), "sniroute client") {
		t.Fatalf("join page: %d %s", res.StatusCode, body)
	}
	if strings.Contains(string(body), "reg_") {
		t.Error("the join page must not contain a token")
	}
	if res.Header.Get("Referrer-Policy") != "no-referrer" || res.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("headers: %v", res.Header)
	}

	res, err = http.Get(ts.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	var h struct {
		Service   string `json:"service"`
		ProbePin  string `json:"probe_pin"`
		ProbePort string `json:"probe_port"`
	}
	json.NewDecoder(res.Body).Decode(&h)
	res.Body.Close()
	if h.Service != "sniroute-control" || h.ProbePin != "pin-abc" || h.ProbePort != "8443" {
		t.Errorf("health = %+v", h)
	}
}

func TestHeartbeatAndRealTimeConnections(t *testing.T) {
	a, e := newAPI(t)
	n := a.register("live-client", "")
	path, key, id := n["path"].(string), n["node_key"].(string), n["node_id"].(string)
	if code, _ := a.do("POST", "/n/"+path+"/heartbeat", "wrong", nil); code != 401 {
		t.Fatalf("unauthenticated heartbeat: %d", code)
	}
	before, _ := e.st.NodeByID(id)
	if before.LastSeen != nil {
		t.Fatal("invalid heartbeat refreshed identity")
	}
	if code, _ := a.do("POST", "/n/"+path+"/heartbeat", key, nil); code != 204 {
		t.Fatalf("heartbeat: %d", code)
	}
	after, _ := e.st.NodeByID(id)
	if after.LastSeen == nil {
		t.Fatal("valid heartbeat not recorded")
	}
	if code, _ := a.do("GET", "/api/admin/connections", "wrong", nil); code != 401 {
		t.Fatalf("connections leaked: %d", code)
	}
	a.do("POST", "/n/"+path+"/tasks", key, planBody("127.0.0.1:443", "a.example"))
	req, _ := http.NewRequest("GET", a.url+"/api/admin/connections", nil)
	req.Header.Set("Authorization", "Bearer "+adminKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rows []store.LiveClient
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || len(rows) != 1 || rows[0].Name != "live-client" || rows[0].Planned != 1 {
		t.Fatalf("live clients: %+v", rows)
	}
	e.st.TouchNode(id, time.Now().Add(-store.NodeOfflineTTL), "")
	if code, _ := a.do("POST", "/n/"+path+"/heartbeat", key, nil); code != 401 {
		t.Fatalf("expired identity revived: %d", code)
	}
}
