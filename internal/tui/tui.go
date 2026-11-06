// Package tui is a tiny numbered-menu toolkit for SSH terminals: line input,
// hidden input, confirmations and tables. No cursor control, no mouse.
package tui

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"
)

// ErrCancel is returned when input ends (EOF / Ctrl+D); menus treat it as "back".
var ErrCancel = errors.New("tui: input closed")

// UI reads from In and writes to Out.
type UI struct {
	in    *bufio.Reader
	out   io.Writer
	color bool
	stdin *os.File // set when In is a real terminal, for hidden input
}

// New creates a UI. If in is a terminal, secrets are read without echo.
func New(in io.Reader, out io.Writer) *UI {
	u := &UI{in: bufio.NewReader(in), out: out, color: ColorEnabled(out)}
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		u.stdin = f
	}
	return u
}

// Printf writes formatted output.
func (u *UI) Printf(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	u.writeRole(s, messageRole(s))
}

// Println writes a line.
func (u *UI) Println(a ...any) { s := fmt.Sprintln(a...); u.writeRole(s, messageRole(s)) }

// Rule prints a separator line.
func (u *UI) Rule() { u.Styled("muted", strings.Repeat("─", 46)) }

func (u *UI) readLine() (string, error) {
	line, err := u.in.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return "", ErrCancel
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// WaitLine waits for one line without writing, for a live view's return key.
// Only one reader may consume UI input at a time.
func (u *UI) WaitLine() { _, _ = u.readLine() }

// Prompt asks for a value; an empty answer returns def.
func (u *UI) Prompt(label, def string) (string, error) {
	if def != "" {
		u.writeRole(fmt.Sprintf("%s [%s]: ", label, def), "accent")
	} else {
		u.writeRole(label+": ", "accent")
	}
	s, err := u.readLine()
	if err != nil {
		return "", err
	}
	if s = strings.TrimSpace(s); s == "" {
		return def, nil
	}
	return s, nil
}

// PromptSecret reads a value without echo when attached to a terminal.
func (u *UI) PromptSecret(label string) (string, error) {
	u.writeRole(label+": ", "accent")
	if u.stdin != nil {
		b, err := term.ReadPassword(int(u.stdin.Fd()))
		u.Println()
		if err != nil {
			return "", ErrCancel
		}
		return strings.TrimSpace(string(b)), nil
	}
	s, err := u.readLine()
	return strings.TrimSpace(s), err
}

// Confirm asks a yes/no question.
func (u *UI) Confirm(label string, def bool) (bool, error) {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	for {
		u.writeRole(fmt.Sprintf("%s [%s]: ", label, hint), "warning")
		s, err := u.readLine()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "":
			return def, nil
		case "y", "yes", "是":
			return true, nil
		case "n", "no", "否":
			return false, nil
		}
	}
}

// ReadLines reads lines until a blank line or EOF.
func (u *UI) ReadLines(hint string) ([]string, error) {
	u.Println(hint)
	var out []string
	for {
		s, err := u.readLine()
		if err != nil {
			return out, nil // EOF ends the list
		}
		if strings.TrimSpace(s) == "" {
			return out, nil
		}
		out = append(out, s)
	}
}

// Item is one menu entry. Key is what the user types.
type Item struct {
	Key   string
	Label string
}

// Menu prints a titled numbered menu and returns the chosen key. Invalid
// input re-prompts; end of input returns ErrCancel.
func (u *UI) Menu(title string, header []string, items []Item) (string, error) {
	for {
		u.Println()
		u.Styled("title", title)
		u.Rule()
		for _, h := range header {
			u.Println(h)
		}
		if len(header) > 0 {
			u.Println()
		}
		for _, it := range items {
			fmt.Fprintf(u.out, "  %s %s\n", u.paint(it.Key+".", "accent"), it.Label)
		}
		u.Rule()
		u.writeRole("请选择：", "accent")
		s, err := u.readLine()
		if err != nil {
			return "", err
		}
		s = strings.TrimSpace(s)
		for _, it := range items {
			if it.Key == s {
				return s, nil
			}
		}
		u.Styled("warning", "无效选择，请重新输入。")
	}
}

// Table prints rows with aligned columns; the first row is the header.
func (u *UI) Table(rows [][]string) {
	var rendered bytes.Buffer
	tw := tabwriter.NewWriter(&rendered, 0, 4, 2, ' ', 0)
	for _, r := range rows {
		fmt.Fprintln(tw, strings.Join(r, "\t"))
	}
	tw.Flush()
	for i, line := range strings.SplitAfter(rendered.String(), "\n") {
		role := messageRole(line)
		if i == 0 {
			role = "title"
		}
		u.writeRole(line, role)
	}
}

// Opt builds a menu item.
func Opt(key, label string) Item { return Item{Key: key, Label: label} }

// Writer returns the output stream, for code that renders reports directly.
func (u *UI) Writer() io.Writer { return u.out }
