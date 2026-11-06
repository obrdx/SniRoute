package main

import (
	"time"

	"github.com/nyktios/sniroute/internal/report"
	"github.com/nyktios/sniroute/internal/server"
	"github.com/nyktios/sniroute/internal/tui"
)

func shorten(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// renderResults prints the full report for a task view.
func renderResults(ui *tui.UI, v server.TaskView) {
	report.WriteText(ui.Writer(), report.Build(v, time.Now()))
}

// renderDomain prints every recorded fact about one domain.
func renderDomain(ui *tui.UI, v server.TaskView, sni string) bool {
	ok, _ := report.WriteDomain(ui.Writer(), report.Build(v, time.Now()), sni)
	return ok
}
