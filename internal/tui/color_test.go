package tui

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

func TestColorsPreserveMenuAndTableLayout(t *testing.T) {
	render := func(color bool) string {
		u, out := newUI("1\n")
		u.color = color
		u.Menu("服务端管理", []string{"https://github.com/obrdx/SniRoute", "运行中"}, []Item{Opt("1", "实时连接"), Opt("0", "返回")})
		u.Table([][]string{{"客户端", "进度"}, {"示例节点", "3/9"}})
		u.Println("已保存。")
		u.Println("提醒：测试环境异常")
		u.Println("错误：认证失败")
		return out.String()
	}
	plain, colored := render(false), render(true)
	strip := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	if strip.ReplaceAllString(colored, "") != plain {
		t.Fatal("colors changed menu text or table layout")
	}
	for _, code := range []string{"1;36", "36", "32", "33", "31"} {
		if !strings.Contains(colored, "\x1b["+code+"m") {
			t.Fatalf("missing color %s", code)
		}
	}
	if strings.Contains(plain, "\x1b") {
		t.Fatal("ANSI in plain output")
	}
}

func TestRedirectedOutputHasNoColors(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	var out bytes.Buffer
	u := New(strings.NewReader("0\n"), &out)
	u.Menu("客户端", nil, []Item{Opt("0", "退出")})
	u.Styled("danger", "错误：测试")
	if strings.Contains(out.String(), "\x1b") {
		t.Fatal("redirected output colored")
	}
	t.Setenv("NO_COLOR", "")
	if ColorEnabled(&out) {
		t.Fatal("NO_COLOR ignored")
	}
}
