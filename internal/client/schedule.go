package client

import (
	"context"
	"strings"
	"time"

	"github.com/nyktios/sniroute/internal/server"
)

const DefaultConcurrency = 6
const SNIProbeInterval = 2 * time.Second

// attemptPhases keeps baseline slots and domain rounds separate. A phase must
// finish before the next begins, so a slow baseline cannot overlap later rounds.
func attemptPhases(attempts []server.IssuedAttempt) [][]server.IssuedAttempt {
	var phases [][]server.IssuedAttempt
	for _, a := range attempts {
		if len(phases) == 0 || phases[len(phases)-1][0].Kind != a.Kind || phases[len(phases)-1][0].Round != a.Round {
			phases = append(phases, nil)
		}
		phases[len(phases)-1] = append(phases[len(phases)-1], a)
	}
	return phases
}

// scheduleProbes spaces repeated SNIs after completion, across targets as well
// as rounds. Cooling SNIs do not occupy workers or block other ready SNIs.
func scheduleProbes(ctx context.Context, attempts []server.IssuedAttempt, concurrency int, interval time.Duration, run func(server.IssuedAttempt)) {
	concurrency = max(1, concurrency)
	completed := make(chan string, concurrency)
	last := make(map[string]time.Time)
	active := make(map[string]bool)
	running := 0
	finish := func(key string) {
		running--
		delete(active, key)
		last[key] = time.Now()
	}
	defer func() {
		for running > 0 {
			finish(<-completed)
		}
	}()
	for _, phase := range attemptPhases(attempts) {
		pending := append([]server.IssuedAttempt(nil), phase...)
		for len(pending) > 0 || running > 0 {
			if ctx.Err() != nil {
				return
			}
			var next time.Time
			chosen := -1
			if running < concurrency {
				now := time.Now()
				for i, a := range pending {
					key := strings.ToLower(a.SNI)
					if active[key] {
						continue
					}
					ready := last[key].Add(interval)
					if !now.Before(ready) {
						chosen = i
						break
					}
					if next.IsZero() || ready.Before(next) {
						next = ready
					}
				}
			}
			if chosen >= 0 {
				a := pending[chosen]
				pending = append(pending[:chosen], pending[chosen+1:]...)
				key := strings.ToLower(a.SNI)
				active[key] = true
				running++
				go func() { run(a); completed <- key }()
				continue
			}
			if len(pending) == 0 && running == 0 {
				break
			}
			var tick <-chan time.Time
			var timer *time.Timer
			if !next.IsZero() {
				timer = time.NewTimer(time.Until(next))
				tick = timer.C
			}
			select {
			case key := <-completed:
				finish(key)
			case <-tick:
			case <-ctx.Done():
				if timer != nil {
					timer.Stop()
				}
				return
			}
			if timer != nil {
				timer.Stop()
			}
		}
	}
}
