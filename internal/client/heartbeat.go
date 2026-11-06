package client

import (
	"context"
	"time"
)

// KeepAlive keeps the client online while its process (including menus) runs.
// The returned stop function cancels in-flight requests and waits for exit.
func (r *Runner) KeepAlive(parent context.Context) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				hctx, stop := context.WithTimeout(ctx, 5*time.Second)
				r.CC.Heartbeat(hctx, r.State.Path, r.State.NodeKey)
				stop()
			}
		}
	}()
	return func() { cancel(); <-done }
}
