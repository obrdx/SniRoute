package pack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const ExternalVersion = "v1"
const MaxExternalBytes = 2 << 20
const MaxExternalEntries = 10000
const MaxExternalCategories = 64

// ExternalDomain is validated data, never a target address or executable rule.
type ExternalDomain struct {
	Domain   string `json:"domain" yaml:"domain"`
	Category string `json:"category,omitempty" yaml:"category,omitempty"`
}
type ImportIssue struct {
	Index  int
	Reason string
}
type ExternalImport struct {
	Name       string
	Domains    []ExternalDomain
	Skipped    int
	Duplicates int
	Issues     []ImportIssue
}

func decodeExternalJSON(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("JSON 后存在多余内容")
	}
	return nil
}

// ParseExternal rejects a broken envelope, but validates array items separately
// so a malformed entry cannot discard the good entries alongside it.
func ParseExternal(data []byte) (ExternalImport, error) {
	var result ExternalImport
	if len(data) > MaxExternalBytes {
		return result, errors.New("外置文件超过 2 MiB")
	}
	if !utf8.Valid(data) {
		return result, errors.New("外置文件必须使用 UTF-8 编码")
	}
	var doc struct {
		Version string            `json:"version"`
		Name    string            `json:"name"`
		Domains []json.RawMessage `json:"domains"`
	}
	if err := decodeExternalJSON(data, &doc); err != nil {
		return result, fmt.Errorf("外置文件格式错误：%w", err)
	}
	if doc.Version != ExternalVersion {
		return result, errors.New("外置文件 version 必须为 v1")
	}
	if len(doc.Domains) == 0 || len(doc.Domains) > MaxExternalEntries {
		return result, errors.New("domains 必须为含 1–10000 个条目的数组")
	}
	if utf8.RuneCountInString(doc.Name) > 80 || strings.ContainsFunc(doc.Name, unicode.IsControl) {
		return result, errors.New("清单名称过长或包含控制字符")
	}
	var envelope map[string]json.RawMessage
	_ = json.Unmarshal(data, &envelope)
	if raw, ok := envelope["name"]; ok && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return result, errors.New("name 必须为字符串，或省略该字段")
	}
	result.Name = strings.TrimSpace(doc.Name)
	seen := map[string]bool{}
	categories := map[string]bool{}
	skip := func(index int, reason string) {
		result.Skipped++
		if len(result.Issues) < 5 {
			result.Issues = append(result.Issues, ImportIssue{index, reason})
		}
	}
	for i, raw := range doc.Domains {
		var entry ExternalDomain
		if err := decodeExternalJSON(raw, &entry); err != nil {
			skip(i+1, "条目必须为仅含 domain、category 字段的对象，字段值必须是字符串")
			continue
		}
		entry.Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(entry.Domain)), ".")
		if !ValidExternalDomain(entry.Domain) {
			skip(i+1, "domain 不是合法域名（不能包含 IP、网址、端口、路径或通配符）")
			continue
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		if value, ok := fields["category"]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			skip(i+1, "category 必须是字符串，或省略该字段")
			continue
		}
		entry.Category = strings.TrimSpace(entry.Category)
		if entry.Category == "" {
			entry.Category = "其他"
		}
		if utf8.RuneCountInString(entry.Category) > 64 || strings.ContainsFunc(entry.Category, unicode.IsControl) {
			skip(i+1, "category 超过 64 个字符或包含控制字符")
			continue
		}
		if seen[entry.Domain] {
			result.Duplicates++
			continue
		}
		if !categories[entry.Category] && len(categories) >= MaxExternalCategories {
			skip(i+1, "分类数超过 64 个")
			continue
		}
		seen[entry.Domain] = true
		categories[entry.Category] = true
		result.Domains = append(result.Domains, entry)
	}
	if len(result.Domains) == 0 {
		return result, errors.New("外置文件中没有有效域名，原有配置未更改")
	}
	return result, nil
}

// ValidExternalDomain enforces hostname syntax rather than the probe parser's
// deliberately permissive SNI syntax. It does not query DNS or visit websites.
func ValidExternalDomain(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	// This also rejects malformed numeric IP addresses.
	return strings.ContainsAny(labels[len(labels)-1], "abcdefghijklmnopqrstuvwxyz")
}

func externalURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 4096 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("请输入直接返回 JSON 文件的 HTTPS 链接，不支持用户名、密码或 URL fragment")
	}
	return u, nil
}

// FetchExternal uses verified HTTPS with no environment proxy, bounded reads,
// redirects and total time. The response is parsed solely as data.
func FetchExternal(ctx context.Context, rawURL string) (ExternalImport, error) {
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	defer tr.CloseIdleConnections()
	return fetchExternal(ctx, rawURL, tr)
}

func fetchExternal(ctx context.Context, rawURL string, tr http.RoundTripper) (ExternalImport, error) {
	var result ExternalImport
	if _, err := externalURL(rawURL); err != nil {
		return result, err
	}
	hc := &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return errors.New("重定向次数过多")
		}
		_, err := externalURL(req.URL.String())
		return err
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return result, errors.New("无法创建外置清单请求")
	}
	req.Header.Set("Accept", "application/json, text/plain")
	resp, err := hc.Do(req)
	if err != nil {
		return result, errors.New("外置清单抓取失败，请检查 HTTPS 链接、证书和网络后重试")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("外置清单下载返回 HTTP %d，请使用文件原始内容链接", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxExternalBytes+1))
	if err != nil {
		return result, errors.New("读取外置清单失败，请重试")
	}
	return ParseExternal(data)
}

// WithExternal combines imported data with the library without mutating it.
func (l Library) WithExternal(entries []ExternalDomain) Library {
	categories := make([]Category, 0, len(l.Categories))
	for _, c := range l.Categories {
		if !c.External {
			categories = append(categories, c)
		}
	}
	l.Categories = categories
	l.External = nil
	groups := map[string]int{}
	seen := map[string]bool{}
	for _, entry := range entries {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(entry.Domain)), ".")
		if !ValidExternalDomain(host) || seen[host] {
			continue
		}
		seen[host] = true
		name := strings.TrimSpace(entry.Category)
		if name == "" {
			name = "其他"
		}
		if utf8.RuneCountInString(name) > 64 || strings.ContainsFunc(name, unicode.IsControl) {
			continue
		}
		l.External = append(l.External, host)
		idx, ok := groups[name]
		if !ok {
			idx = len(l.Categories)
			groups[name] = idx
			l.Categories = append(l.Categories, Category{ID: "external-" + fmt.Sprint(len(groups)), Name: name, Title: name, External: true})
		}
		l.Categories[idx].Domains = append(l.Categories[idx].Domains, host)
	}
	return l
}
