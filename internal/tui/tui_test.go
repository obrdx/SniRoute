package tui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func newUI(in string) (*UI, *bytes.Buffer) {
	var out bytes.Buffer
	return New(strings.NewReader(in), &out), &out
}

func TestPromptDefaultsAndTrim(t *testing.T) {
	u, _ := newUI("\n  hello  \n")
	if s, _ := u.Prompt("a", "dflt"); s != "dflt" {
		t.Errorf("default: %q", s)
	}
	if s, _ := u.Prompt("b", ""); s != "hello" {
		t.Errorf("trim: %q", s)
	}
	if _, err := u.Prompt("c", ""); !errors.Is(err, ErrCancel) {
		t.Errorf("eof: %v", err)
	}
}

func TestMenuRepromptsOnInvalid(t *testing.T) {
	u, out := newUI("9\nabc\n2\n")
	key, err := u.Menu("T", []string{"hdr"}, []Item{{"1", "one"}, {"2", "two"}, {"0", "quit"}})
	if err != nil || key != "2" {
		t.Fatalf("key=%q err=%v", key, err)
	}
	if strings.Count(out.String(), "无效选择") != 2 || !strings.Contains(out.String(), "hdr") {
		t.Errorf("output: %s", out)
	}
	u, _ = newUI("")
	if _, err := u.Menu("T", nil, []Item{{"0", "q"}}); !errors.Is(err, ErrCancel) {
		t.Errorf("eof: %v", err)
	}
}

func TestConfirmAndLines(t *testing.T) {
	u, _ := newUI("maybe\ny\n\nn\n")
	if ok, _ := u.Confirm("q", false); !ok {
		t.Error("y")
	}
	if ok, _ := u.Confirm("q", true); !ok {
		t.Error("default yes")
	}
	if ok, _ := u.Confirm("q", true); ok {
		t.Error("n")
	}
	u, _ = newUI("a.com\nb.com\n\nignored\n")
	lines, _ := u.ReadLines("enter")
	if len(lines) != 2 {
		t.Errorf("lines: %v", lines)
	}
}

func TestSecretFromPipe(t *testing.T) {
	u, _ := newUI("s3cret \n")
	if s, _ := u.PromptSecret("k"); s != "s3cret" {
		t.Errorf("secret: %q", s)
	}
}
