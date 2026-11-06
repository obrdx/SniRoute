package pack

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestExternalImportSkipsBadEntriesAndPreservesCategories(t *testing.T) {
	data := []byte(`{"version":"v1","domains":[
 {"domain":" EXAMPLE.COM. ","category":"AI 服务"},
 {"domain":"other.example"},
 {"domain":"1,2.3.4"},
 {"domain":"192.0.2.1"},
 {"domain":"999.1.2.3"},
 {"domain":"https://bad.example/path"},
 "wrong-entry-type",
 {"domain":"type.example","category":3},
 {"domain":"example.com","category":"重复"},
 {"domain":"null.example","category":null},
 {"domain":"xn--bcher-kva.example","category":" "},
 {"domain":"unknown.example","categories":["AI"]}
 ]}`)
	got, err := ParseExternal(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Domains) != 3 || got.Skipped != 8 || got.Duplicates != 1 || len(got.Issues) != 5 {
		t.Fatalf("unexpected import: %+v", got)
	}
	if got.Domains[0].Domain != "example.com" || got.Domains[0].Category != "AI 服务" || got.Domains[1].Category != "其他" || got.Domains[2].Category != "其他" {
		t.Fatalf("lost classifications: %+v", got.Domains)
	}
}

func TestExternalEnvelopeAndLimits(t *testing.T) {
	for _, data := range []string{
		`{"version":"v1","domains":[]}`,
		`{"version":"v2","domains":[{"domain":"a.example"}]}`,
		`{"version":"v1","domains":[{"domain":"a.example"}],"unknown":true}`,
		`{"version":"v1","domains":[{"domain":"a.example"}],}`,
		`{"version":"v1","domains":[{"domain":"a.example"}]} {}`,
		`{"version":"v1","domains":[{"domain":"1,2.3.4"}]}`,
	} {
		if _, err := ParseExternal([]byte(data)); err == nil {
			t.Errorf("accepted invalid envelope: %s", data)
		}
	}
	if _, err := ParseExternal([]byte(strings.Repeat(" ", MaxExternalBytes+1))); err == nil {
		t.Fatal("oversized payload accepted")
	}
	var entries []ExternalDomain
	for i := 0; i < MaxExternalCategories+1; i++ {
		entries = append(entries, ExternalDomain{Domain: string(rune('a'+i/26)) + string(rune('a'+i%26)) + ".example", Category: "分类" + string(rune('一'+i))})
	}
	data, _ := json.Marshal(map[string]any{"version": "v1", "domains": entries})
	got, err := ParseExternal(data)
	if err != nil || len(got.Domains) != 64 || got.Skipped != 1 {
		t.Fatalf("category limit: %+v %v", got, err)
	}
}

func TestExternalHostnameSyntax(t *testing.T) {
	for _, host := range []string{"example.com", "a-b.example", "1a.example", "xn--bcher-kva.example"} {
		if !ValidExternalDomain(host) {
			t.Errorf("rejected %s", host)
		}
	}
	for _, host := range []string{"1,2.3.4", "192.0.2.4", "999.1.2.3", "example.123", "*.example.com", "a_b.example", "-a.example", "a-.example", "a..example", "https://a.example", "a.example:443", "a.example/x", "中文.example", strings.Repeat("a", 64) + ".example"} {
		if ValidExternalDomain(host) {
			t.Errorf("accepted %s", host)
		}
	}
}

func TestExternalCategoriesOverrideOnlyWhenMerged(t *testing.T) {
	base := Library{Quick: []string{"a.example"}, Categories: []Category{{Name: "ai", Domains: []string{"a.example"}}}}
	merged := base.WithExternal([]ExternalDomain{{Domain: "a.example"}, {Domain: "b.example", Category: "我的分类"}})
	domains, unknown, err := merged.Select([]string{"quick", "external"})
	if err != nil || len(unknown) != 0 || len(domains) != 2 {
		t.Fatalf("merge: %v %v %v", domains, unknown, err)
	}
	categories := merged.ReportCategories(domains)
	if len(categories) != 2 || categories[0].Name != "其他" || categories[1].Name != "我的分类" {
		t.Fatalf("categories: %+v", categories)
	}
	if len(base.Categories) != 1 || base.ReportCategories(base.Quick)[0].Name != "AI 服务" {
		t.Fatal("base library modified")
	}
	replaced := merged.WithExternal([]ExternalDomain{{Domain: "c.example", Category: "新分类"}})
	if len(replaced.External) != 1 || len(replaced.Categories) != 2 {
		t.Fatal("old external cache was appended instead of replaced")
	}
}

type externalTransport func(*http.Request) (*http.Response, error)

func (f externalTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestFetchExternalBoundsAndRedirects(t *testing.T) {
	good := `{"version":"v1","domains":[{"domain":"a.example"}]}`
	for _, tc := range []struct {
		name, body, location string
		status               int
		wantError            bool
	}{
		{name: "valid raw JSON", body: good, status: 200},
		{name: "preview page", body: "<html>preview</html>", status: 200, wantError: true},
		{name: "HTTP error", status: 404, wantError: true},
		{name: "oversized", body: strings.Repeat(" ", MaxExternalBytes+1), status: 200, wantError: true},
		{name: "insecure redirect", status: 302, location: "http://list.example/file.json", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			tr := externalTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Scheme != "https" {
					t.Fatal("followed insecure redirect")
				}
				h := make(http.Header)
				if tc.location != "" {
					h.Set("Location", tc.location)
				}
				return &http.Response{StatusCode: tc.status, Header: h, Body: io.NopCloser(strings.NewReader(tc.body)), Request: r}, nil
			})
			got, err := fetchExternal(context.Background(), "https://list.example/file.json", tr)
			if (err != nil) != tc.wantError {
				t.Fatalf("fetch: %+v %v", got, err)
			}
			if calls != 1 {
				t.Fatalf("unexpected requests: %d", calls)
			}
		})
	}
	for _, raw := range []string{"http://example.com/list.json", "file:///tmp/list.json", "https://u:p@example.com/list.json", "https://example.com/list.json#fragment"} {
		if _, err := FetchExternal(context.Background(), raw); err == nil {
			t.Fatal("accepted unsupported link", raw)
		}
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, good) }))
	defer ts.Close()
	got, err := fetchExternal(context.Background(), ts.URL, ts.Client().Transport)
	if err != nil || len(got.Domains) != 1 {
		t.Fatalf("verified HTTPS fetch: %+v %v", got, err)
	}
}

func TestExternalExampleMatchesParser(t *testing.T) {
	data, err := os.ReadFile("../../docs/examples/external-domains.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseExternal(data)
	if err != nil || len(got.Domains) != 4 || got.Skipped != 0 {
		t.Fatalf("example invalid: %+v %v", got, err)
	}
}
