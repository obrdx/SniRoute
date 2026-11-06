// Package pack loads the domain library that ships with the tool and the
// user's own lists. A pack is a named group of concrete hostnames that a run
// can be started from, so the client menu can offer "which sites do you want
// to test" instead of asking for a file path.
//
// Names and groups come from the library's own files; nothing here invents a
// service category, and the library's tags are unverified labels (see
// domains/README.md).
package pack

import (
	"bufio"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed domains/categories/*.txt domains/quick-test.txt domains/full-test.txt domains/README.md
var embedded embed.FS

// Embedded lists the bundled files; used by tests to keep the embed pattern
// honest.
func Embedded() embed.FS { return embedded }

// Category is one group of domains from the library.
type Category struct {
	External bool
	ID       string   // "01-search"
	Name     string   // "search"
	Title    string   // human label, from the file's first comment when available
	Domains  []string // de-duplicated, lower-cased
	Tags     []string // union of the per-line tags, sorted
	Quick    int      // how many of them are in the recommended quick list
}

// Count returns the number of domains in the category.
func (c Category) Count() int { return len(c.Domains) }

// Library is everything the tool can offer to test.
type Library struct {
	External   []string
	OriginPath string     // where it was loaded from, for display
	Quick      []string   // recommended short list (library order)
	Full       []string   // complete list (library order)
	Baseline   []string   // the library's connectivity-check hosts (not used as SNI baseline automatically)
	Categories []Category // sorted by id
	Notes      string     // the library's README, shown in the menu
}

// QuickCount reports how many quick domains are in cat.
func (l Library) QuickCount(cat Category) int { return cat.Quick }

// Origin names where the library came from.
func (l Library) Origin() string {
	if l.OriginPath == "" {
		return "(built in)"
	}
	return l.OriginPath
}

// GroupNames are the library's category names in Chinese, so the menu reads
// like a list of things to test rather than a list of file names. An unknown
// category keeps its own name: the library is data, not a fixed enumeration.
var GroupNames = map[string]string{
	"search":            "搜索引擎",
	"ai":                "AI 服务",
	"social":            "社交",
	"messaging":         "即时通讯",
	"video-streaming":   "视频 / 流媒体",
	"music-audio":       "音乐 / 音频",
	"gaming":            "游戏",
	"developer":         "开发者平台",
	"cloud-cdn":         "云与 CDN",
	"software-download": "软件下载",
	"dns-security":      "DNS 与安全",
	"payment-finance":   "支付与金融",
	"news-media":        "新闻媒体",
	"wiki-academic":     "百科与学术",
	"shopping":          "购物",
	"mail-office":       "邮箱与办公",
	"privacy-proxy":     "隐私与代理",
	"restricted":        "受限站点",
	"custom":            "自定义",
}

// Short is just the human name, for use inside a sentence where the raw id
// would read as noise.
func (c Category) Short() string {
	if c.External {
		return c.Name
	}
	if zh, ok := GroupNames[c.Name]; ok {
		return zh
	}
	return c.Name
}

// Display is the menu label of a category.
func (c Category) Display() string {
	if c.External {
		return c.Name
	}
	if zh, ok := GroupNames[c.Name]; ok {
		return zh + "（" + c.Name + "）"
	}
	return c.Name
}

// Find returns the category with the given id or name.
func (l Library) Find(name string) (Category, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, c := range l.Categories {
		if strings.ToLower(c.ID) == name || strings.ToLower(c.Name) == name {
			return c, true
		}
	}
	return Category{}, false
}

// EmbeddedLibrary loads the copy compiled into the binary.
func EmbeddedLibrary() (Library, error) { return load(embedded, "", "domains") }

// DiskLibrary loads a library directory on disk (the repository's domains/
// folder), which lets the lists be edited without rebuilding.
func DiskLibrary(dir string) (Library, error) {
	return load(os.DirFS(dir), dir, ".")
}

// Load prefers a directory on disk and falls back to the compiled-in copy, so
// a binary run outside the repository still has the lists.
func Load(dir string) (Library, string, error) {
	if dir != "" {
		l, err := DiskLibrary(dir)
		if err == nil {
			return l, dir, nil
		}
		if !os.IsNotExist(err) && !isMissing(err) {
			return Library{}, "", err
		}
	}
	l, err := EmbeddedLibrary()
	return l, "(built in)", err
}

func isMissing(err error) bool {
	return strings.Contains(err.Error(), "file does not exist") || strings.Contains(err.Error(), "no such file")
}

func readLines(fsys fs.FS, name string) ([]string, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}

// hostnames extracts the first TAB/space separated field of every non-comment
// line. The library stores "hostname<TAB>service<TAB>tags" and plain lists
// store one hostname per line, so both work.
func hostnames(lines []string) (hosts, tags []string) {
	seen := map[string]bool{}
	seenTag := map[string]bool{}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		h := strings.ToLower(strings.TrimSuffix(fields[0], "."))
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
		if len(fields) > 2 {
			for _, t := range strings.Split(fields[2], ",") {
				if t = strings.ToLower(strings.TrimSpace(t)); t != "" && !seenTag[t] {
					seenTag[t] = true
					tags = append(tags, t)
				}
			}
		}
	}
	sort.Strings(tags)
	return hosts, tags
}

func title(lines []string) string {
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "#") {
			t := strings.TrimSpace(strings.TrimPrefix(l, "#"))
			if t != "" && !strings.Contains(t, "hostname<TAB>") {
				return t
			}
		}
	}
	return ""
}

func load(fsys fs.FS, origin, root string) (Library, error) {
	lib := Library{OriginPath: origin}

	quick, err := readLines(fsys, filepath.Join(root, "quick-test.txt"))
	if err != nil {
		return Library{}, err
	}
	full, err := readLines(fsys, filepath.Join(root, "full-test.txt"))
	if err != nil {
		return Library{}, err
	}
	lib.Quick, _ = hostnames(quick)
	lib.Full, _ = hostnames(full)
	if len(lib.Full) == 0 {
		return Library{}, fmt.Errorf("domain library has no hostnames")
	}
	quickSet := map[string]bool{}
	for _, h := range lib.Quick {
		quickSet[h] = true
	}

	entries, err := fs.ReadDir(fsys, filepath.Join(root, "categories"))
	if err != nil {
		return Library{}, err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".txt") {
			continue
		}
		lines, err := readLines(fsys, filepath.Join(root, "categories", name))
		if err != nil {
			return Library{}, err
		}
		hosts, tags := hostnames(lines)
		id := strings.TrimSuffix(name, ".txt")
		short := id
		if i := strings.IndexByte(id, '-'); i >= 0 {
			short = id[i+1:]
		}
		c := Category{ID: id, Name: short, Domains: hosts, Tags: tags}
		if t := title(lines); !strings.Contains(t, ".txt") && !strings.Contains(t, "<TAB>") {
			c.Title = t
		}
		for _, h := range hosts {
			if quickSet[h] {
				c.Quick++
			}
		}
		if len(hosts) == 0 {
			// An empty template (20-custom.txt ships that way) would only add a
			// row that selects nothing.
			continue
		}
		if id == "00-baseline" || short == "baseline" {
			lib.Baseline = append([]string(nil), hosts...)
			// The library's baseline entries are ordinary public hosts used for
			// connectivity checks. They are not used as the neutral SNI
			// baseline, which must be a name no per-site rule matches.
			continue
		}
		lib.Categories = append(lib.Categories, c)
	}
	sort.Slice(lib.Categories, func(i, j int) bool { return lib.Categories[i].ID < lib.Categories[j].ID })
	if readme, err := readLines(fsys, filepath.Join(root, "README.md")); err == nil {
		lib.Notes = strings.Join(readme, "\n")
	}
	return lib, nil
}

// Select builds a domain list from named categories plus the special names
// "quick" and "full". Order follows the categories given, duplicates are
// removed (case-insensitively), and the baseline category is never included
// implicitly.
func (l Library) Select(names []string) ([]string, []string, error) {
	var out, unknown []string
	seen := map[string]bool{}
	addAll := func(list []string) {
		for _, h := range list {
			if k := strings.ToLower(h); !seen[k] {
				seen[k] = true
				out = append(out, h)
			}
		}
	}
	for _, raw := range names {
		n := strings.ToLower(strings.TrimSpace(raw))
		switch n {
		case "":
			continue
		case "quick", "q", "快速":
			addAll(l.Quick)
			continue
		case "external", "自定义":
			addAll(l.External)
			continue
		case "full", "f", "全部", "all":
			addAll(l.Full)
			continue
		}
		if c, ok := l.Find(n); ok {
			addAll(c.Domains)
			continue
		}
		unknown = append(unknown, raw)
	}
	return out, unknown, nil
}

// ReportCategory freezes a category as indices into sorted, unique task domains.
// Indices keep full-library snapshots within the control API's size limit.
type ReportCategory struct {
	Name    string `json:"name"`
	Domains []int  `json:"domains"`
}

// SortedDomains defines the stable index order used in category snapshots.
func SortedDomains(domains []string) []string {
	seen := map[string]bool{}
	for _, d := range domains {
		seen[strings.ToLower(d)] = true
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// ReportCategories assigns each host once, using exact library membership.
func (l Library) ReportCategories(domains []string) []ReportCategory {
	byHost := map[string]string{}
	for _, c := range l.Categories {
		for _, h := range c.Domains {
			if _, ok := byHost[h]; !ok || c.External {
				byHost[h] = c.Short()
			}
		}
	}
	for _, h := range l.Baseline {
		byHost[h] = "连通性检查站点"
	}
	groups := map[string][]int{}
	for i, h := range SortedDomains(domains) {
		name := byHost[h]
		if name == "" {
			name = "自定义 / 未分类"
		}
		groups[name] = append(groups[name], i)
	}
	var out []ReportCategory
	add := func(name string) {
		if ids := groups[name]; len(ids) > 0 {
			out = append(out, ReportCategory{Name: name, Domains: ids})
			delete(groups, name)
		}
	}
	add("连通性检查站点")
	for _, c := range l.Categories {
		add(c.Short())
	}
	add("自定义 / 未分类")
	return out
}
