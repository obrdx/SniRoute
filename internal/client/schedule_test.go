package client

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nyktios/sniroute/internal/server"
)

func TestScheduleSpacingConcurrencyAndPhases(t *testing.T) {
	attempts := []server.IssuedAttempt{
		{ID: "0", SNI: "baseline.example", Kind: "baseline", Round: 0},
		{ID: "1", SNI: "a.example", Target: "v4", Kind: "domain", Round: 1},
		{ID: "2", SNI: "A.example", Target: "v6", Kind: "domain", Round: 1},
		{ID: "3", SNI: "b.example", Kind: "domain", Round: 1},
		{ID: "4", SNI: "a.example", Kind: "domain", Round: 2},
		{ID: "5", SNI: "baseline.example", Kind: "baseline", Round: 2},
	}
	const gap = 30 * time.Millisecond
	type record struct {
		a          server.IssuedAttempt
		start, end time.Time
	}
	var mu sync.Mutex
	var records []record
	active, peak := 0, 0
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	scheduleProbes(ctx, attempts, 2, gap, func(a server.IssuedAttempt) {
		start := time.Now()
		mu.Lock()
		active++
		peak = max(peak, active)
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		active--
		records = append(records, record{a, start, time.Now()})
		mu.Unlock()
	})
	if len(records) != len(attempts) || peak != 2 {
		t.Fatalf("completed=%d, peak=%d", len(records), peak)
	}
	last := map[string]time.Time{}
	byID := map[string]record{}
	for _, r := range records {
		key := strings.ToLower(r.a.SNI)
		if prev, ok := last[key]; ok && r.start.Sub(prev) < gap {
			t.Fatalf("SNI %s repeated after %s", key, r.start.Sub(prev))
		}
		last[key] = r.end
		byID[r.a.ID] = r
	}
	for _, id := range []string{"1", "2", "3"} {
		if byID[id].start.Before(byID["0"].end) || byID["4"].start.Before(byID[id].end) {
			t.Fatal("phases overlapped")
		}
	}
	if byID["5"].start.Before(byID["4"].end) {
		t.Fatal("final baseline started early")
	}
	if !byID["3"].start.Before(byID["2"].start) {
		t.Fatal("cooling SNI blocked a ready domain")
	}
}

func TestScheduleCancellationDuringCooldown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := []server.IssuedAttempt{{SNI: "a.example", Kind: "domain", Round: 1}, {SNI: "a.example", Kind: "domain", Round: 2}}
	count := 0
	done := make(chan struct{})
	go func() {
		scheduleProbes(ctx, attempts, 2, time.Hour, func(server.IssuedAttempt) { count++; time.AfterFunc(10*time.Millisecond, cancel) })
		close(done)
	}()
	select {
	case <-done:
		if count != 1 {
			t.Fatalf("started %d attempts", count)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation waited for cooldown")
	}
}
