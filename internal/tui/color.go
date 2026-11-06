package tui

import (
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// ColorEnabled keeps files, logs and dumb terminals free of ANSI sequences.
func ColorEnabled(w io.Writer) bool {
	_, disabled := os.LookupEnv("NO_COLOR")
	f, ok := w.(*os.File)
	return !disabled && ok && term.IsTerminal(int(f.Fd())) && os.Getenv("TERM") != "" && os.Getenv("TERM") != "dumb"
}

func (u *UI) paint(s, role string) string {
	if !u.color || s == "" {
		return s
	}
	code := map[string]string{"title": "1;36", "accent": "36", "muted": "90", "success": "32", "warning": "33", "danger": "31"}[role]
	if code == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// Styled prints a status with an explicit semantic role, without changing
// the original text or adding color to data returned by Writer.
func (u *UI) Styled(role, text string) {
	u.writeRole(text+"\n", role)
}

func (u *UI) writeRole(text, role string) {
	// Reset before the newline so the next prompt starts with normal colors.
	body := strings.TrimRight(text, "\r\n")
	io.WriteString(u.out, u.paint(body, role)+text[len(body):])
}

func messageRole(text string) string {
	text = strings.TrimSpace(text)
	for _, prefix := range []string{"错误：", "出错：", "无法", "读取报告失败", "启动失败", "注册失败", "测试未能完成"} {
		if strings.HasPrefix(text, prefix) {
			return "danger"
		}
	}
	for _, prefix := range []string{"提示：", "提醒：", "已中断", "未观测", "当前没有", "没有", "尚未", "服务没有"} {
		if strings.HasPrefix(text, prefix) {
			return "warning"
		}
	}
	if strings.HasPrefix(text, "已停止") {
		return "muted"
	}
	for _, prefix := range []string{"已", "运行中", "服务已"} {
		if strings.HasPrefix(text, prefix) {
			return "success"
		}
	}
	if strings.HasPrefix(text, "https://") || strings.HasPrefix(text, "开始测试") {
		return "accent"
	}
	return ""
}
