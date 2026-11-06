package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/nyktios/sniroute/internal/tui"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nyktios/sniroute/internal/client"
	"github.com/nyktios/sniroute/internal/pack"
)

// The point of the client menu is that choosing what to test is one line of
// input, remembered for next time. This pins that behaviour, including that
// the remembered value is a category name rather than the number typed.
func TestChoosePackRemembersCategoriesNotNumbers(t *testing.T) {
	lib, err := pack.EmbeddedLibrary()
	if err != nil {
		t.Fatal(err)
	}
	if len(lib.Categories) < 3 {
		t.Skip("library too small")
	}
	cfgPath := filepath.Join(t.TempDir(), "client.yaml")
	cfg := client.Config{}.WithDefaults(cfgPath)

	// "3" opens the category page; "2 3" picks its second and third entries.
	ui, out := newTestUI("3\n2 3\n")
	next, err := choosePack(ui, cfgPath, cfg, lib)
	if err != nil {
		t.Fatal(err)
	}
	c2, c3 := lib.Categories[1].Name, lib.Categories[2].Name
	if len(next.PackChoice) != 2 || next.PackChoice[0] != c2 || next.PackChoice[1] != c3 {
		t.Fatalf("remembered %v, want [%s %s]", next.PackChoice, c2, c3)
	}
	if !strings.Contains(out.String(), "已选择") {
		t.Errorf("no confirmation printed:\n%s", out.String())
	}
	// The file must carry the choice, otherwise the next run forgets it.
	saved, err := client.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.PackChoice) != 2 || saved.PackChoice[1] != c3 {
		t.Errorf("saved %v", saved.PackChoice)
	}

	// Enter keeps the selection instead of resetting it.
	ui, _ = newTestUI("\n")
	next, err = choosePack(ui, cfgPath, saved, lib)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.PackChoice) != 2 {
		t.Errorf("a bare Enter changed the choice: %v", next.PackChoice)
	}

	// An unknown name is reported and leaves the domains alone.
	ui, out = newTestUI("no-such-category\n")
	if _, err := choosePack(ui, cfgPath, saved, lib); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "无法识别") {
		t.Errorf("unknown category not reported:\n%s", out.String())
	}
}

func TestDescribeChoiceReadsAsChinese(t *testing.T) {
	lib, err := pack.EmbeddedLibrary()
	if err != nil {
		t.Fatal(err)
	}
	got := describeChoice(lib, []string{"quick", "search"})
	if !strings.Contains(got, "快速清单") || !strings.Contains(got, "搜索引擎") {
		t.Errorf("describeChoice = %q", got)
	}
	if describeChoice(lib, nil) != "未选择" {
		t.Errorf("empty = %q", describeChoice(lib, nil))
	}
}

// A library on disk must win over the built-in copy, since that is how the
// lists are meant to be edited.
func TestClientLibraryPrefersDisk(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "categories"), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "quick-test.txt"), []byte("x.example.com\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "full-test.txt"), []byte("x.example.com\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "categories", "01-mine.txt"), []byte("y.example.com\tMine\t\n"), 0o600)

	ui, _ := newTestUI("")
	lib, origin, err := loadLibrary(ui, client.Config{PackDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if origin != dir || len(lib.Full) != 1 {
		t.Errorf("origin=%q full=%v", origin, lib.Full)
	}

	// A bad path must not stop the tool from working.
	lib, origin, err = loadLibrary(ui, client.Config{PackDir: filepath.Join(dir, "missing")})
	if err != nil || !strings.Contains(origin, "built in") || len(lib.Full) < 500 {
		t.Errorf("fallback: origin=%q err=%v", origin, err)
	}
}

// The table offers "q" and "f" as the shortcuts, so typing them must work and
// must be remembered as quick/full rather than as an unknown category.
func TestChoosePackAcceptsTheShownShortcuts(t *testing.T) {
	lib, err := pack.EmbeddedLibrary()
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "client.yaml")
	cfg := client.Config{}.WithDefaults(cfgPath)
	for _, tc := range []struct{ in, want string }{{"q\n", "quick"}, {"f\n", "full"}, {"Q\n", "quick"}} {
		ui, out := newTestUI(tc.in)
		next, err := choosePack(ui, cfgPath, cfg, lib)
		if err != nil {
			t.Fatal(err)
		}
		if len(next.PackChoice) != 1 || next.PackChoice[0] != tc.want {
			t.Errorf("%q selected %v (want %s)\n%s", tc.in, next.PackChoice, tc.want, out.String())
		}
		domains, _, err := lib.Select(next.PackChoice)
		if err != nil || len(domains) == 0 {
			t.Errorf("%q produced no domains: %v", tc.in, err)
		}
	}
}

func TestAskIPDisplayDefaultsToMasked(t *testing.T) {
	for _, tt := range []struct {
		input string
		full  bool
	}{{"\n", false}, {"n\n", false}, {"y\n", true}} {
		var b bytes.Buffer
		full, err := askIPDisplay(tui.New(strings.NewReader(tt.input), &b))
		if err != nil || full != tt.full {
			t.Fatalf("%q: %v %v", tt.input, full, err)
		}
		if !strings.Contains(b.String(), "完整出口 IP") {
			t.Fatal(b.String())
		}
	}
}

func TestChooseDefaultPlusExternalJSONAndReuse(t *testing.T) {
	lib, err := pack.EmbeddedLibrary()
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "client.yaml")
	cfg := client.Config{}.WithDefaults(cfgPath)
	ui, out := newTestUI("1 4\nhttps://lists.example/domains.json\n")
	calls := 0
	fetch := func(ctx context.Context, raw string) (pack.ExternalImport, error) {
		calls++
		if raw != "https://lists.example/domains.json" {
			t.Fatal(raw)
		}
		return pack.ParseExternal([]byte(`{"version":"v1","domains":[{"domain":"mine.example","category":"我的分类"},{"domain":"other.example"},{"domain":"1,2.3.4"}]}`))
	}
	next, err := choosePackWithFetcher(ui, cfgPath, cfg, lib, fetch)
	if err != nil || len(next.PackChoice) != 2 || next.PackChoice[0] != "quick" || next.PackChoice[1] != "external" || len(next.ExternalDomains) != 2 {
		t.Fatalf("selection: %+v %v", next, err)
	}
	if !strings.Contains(out.String(), "跳过无效条目 1") || !strings.Contains(out.String(), "自定义外置清单") {
		t.Fatal(out.String())
	}
	saved, err := client.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	merged, _, err := loadLibrary(ui, saved)
	if err != nil {
		t.Fatal(err)
	}
	domains, _, err := merged.Select(saved.PackChoice)
	if err != nil || len(domains) != len(lib.Quick)+2 {
		t.Fatalf("selected %d domains: %v", len(domains), err)
	}
	categories := merged.ReportCategories(domains)
	names := map[string]bool{}
	for _, c := range categories {
		names[c.Name] = true
	}
	if !names["我的分类"] || !names["其他"] {
		t.Fatalf("classifications lost: %+v", categories)
	}
	ui, _ = newTestUI("\n")
	again, err := choosePackWithFetcher(ui, cfgPath, saved, merged, fetch)
	if err != nil || calls != 1 || len(again.ExternalDomains) != 2 {
		t.Fatalf("cached choice re-downloaded: calls=%d %v", calls, err)
	}
	// Explicitly choosing 4 refreshes the URL, including when accepting its default.
	ui, _ = newTestUI("4\n\n")
	onlyExternal, err := choosePackWithFetcher(ui, cfgPath, saved, merged, fetch)
	if err != nil || calls != 2 || len(onlyExternal.PackChoice) != 1 || onlyExternal.PackChoice[0] != "external" {
		t.Fatalf("refresh: %+v calls=%d %v", onlyExternal, calls, err)
	}
}

func TestFailedExternalImportKeepsPriorConfiguration(t *testing.T) {
	lib, _ := pack.EmbeddedLibrary()
	path := filepath.Join(t.TempDir(), "client.yaml")
	cfg := client.Config{PackChoice: []string{"quick"}, ExternalURL: "https://old.example/list.json", ExternalDomains: []pack.ExternalDomain{{Domain: "old.example", Category: "旧分类"}}}.WithDefaults(path)
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	ui, out := newTestUI("1 4\nhttps://new.example/list.json\n")
	next, err := choosePackWithFetcher(ui, path, cfg, lib, func(context.Context, string) (pack.ExternalImport, error) {
		return pack.ExternalImport{}, errors.New("模拟下载失败")
	})
	after, _ := os.ReadFile(path)
	if err != nil || next.ExternalURL != cfg.ExternalURL || !bytes.Equal(before, after) || !strings.Contains(out.String(), "原有配置未更改") {
		t.Fatalf("failed import changed configuration: %+v %v\n%s", next, err, out)
	}
}
