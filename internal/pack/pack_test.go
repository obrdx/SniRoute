package pack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The built-in library must be usable: the menu offers whatever it finds, so
// an empty or broken embed would only show up on a user's first run.
func TestEmbeddedLibraryLoads(t *testing.T) {
	lib, err := EmbeddedLibrary()
	if err != nil {
		t.Fatal(err)
	}
	if len(lib.Quick) < 50 || len(lib.Full) < 500 {
		t.Fatalf("quick=%d full=%d: embedded library looks truncated", len(lib.Quick), len(lib.Full))
	}
	if len(lib.Categories) < 10 {
		t.Fatalf("categories = %d", len(lib.Categories))
	}
	for _, c := range lib.Categories {
		if c.Count() == 0 {
			t.Errorf("category %s is empty", c.ID)
		}
		if c.Name == "baseline" {
			t.Error("the library's connectivity-check hosts must not be offered as a test category")
		}
		for _, h := range c.Domains {
			if strings.ContainsAny(h, " \t") {
				t.Errorf("category %s kept a raw line as a hostname: %q", c.ID, h)
				break
			}
		}
	}
	if len(lib.Baseline) == 0 {
		t.Error("baseline hosts were not read")
	}
	// Hostnames are lower-cased and de-duplicated.
	seen := map[string]bool{}
	for _, h := range lib.Full {
		if h != strings.ToLower(h) {
			t.Errorf("not lower-cased: %q", h)
		}
		if seen[h] {
			t.Errorf("duplicate %q", h)
		}
		seen[h] = true
	}
}

func TestSelectCombinesAndRejects(t *testing.T) {
	lib, err := EmbeddedLibrary()
	if err != nil {
		t.Fatal(err)
	}
	search, ok := lib.Find("search")
	if !ok {
		t.Fatal("no search category")
	}
	got, unknown, err := lib.Select([]string{"quick", search.Name, "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if len(unknown) != 1 || unknown[0] != "nope" {
		t.Errorf("unknown = %v", unknown)
	}
	// A domain in both the quick list and the category appears once.
	want := len(lib.Quick) + search.Count() - search.Quick
	if len(got) != want {
		t.Errorf("selected %d, want %d (quick %d + %s %d - overlap %d)", len(got), want, len(lib.Quick), search.Name, search.Count(), search.Quick)
	}
	// The numeric id works as well as the name.
	if c, ok := lib.Find("01-search"); !ok || c.Name != "search" {
		t.Errorf("lookup by id: %+v %v", c, ok)
	}
	if got, _, _ := lib.Select([]string{"full"}); len(got) != len(lib.Full) {
		t.Errorf("full = %d, want %d", len(got), len(lib.Full))
	}
}

// A directory on disk wins over the embedded copy so lists can be edited
// without a rebuild, and the origin is reported for the menu.
func TestDiskLibraryTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "categories"), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("quick-test.txt", "a.example.com\nB.example.com\n")
	write("full-test.txt", "a.example.com\nb.example.com\nc.example.com\n")
	write(filepath.Join("categories", "01-mine.txt"), "d.example.com\tMine\ttag1,tag2\n")
	write(filepath.Join("categories", "00-baseline.txt"), "base.example.com\tBaseline\t\n")

	lib, origin, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if origin != dir || lib.Origin() != dir {
		t.Errorf("origin = %q / %q", origin, lib.Origin())
	}
	if len(lib.Quick) != 2 || lib.Full[1] != "b.example.com" {
		t.Errorf("quick=%v full=%v", lib.Quick, lib.Full)
	}
	if len(lib.Categories) != 1 || lib.Categories[0].Count() != 1 || lib.Categories[0].Tags[0] != "tag1" {
		t.Errorf("categories: %+v", lib.Categories)
	}
	if len(lib.Baseline) != 1 {
		t.Errorf("baseline = %v", lib.Baseline)
	}
	// A missing directory falls back to the built-in copy rather than failing.
	if lib, origin, err := Load(filepath.Join(dir, "missing")); err != nil || origin != "(built in)" || len(lib.Full) < 500 {
		t.Errorf("fallback: %q %v", origin, err)
	}
}
