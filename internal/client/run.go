package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nyktios/sniroute/internal/auth"
	"github.com/nyktios/sniroute/internal/server"
)

// RunOptions configures one task run.
type RunOptions struct {
	Plan        PlanSpec
	Concurrency int // default 6
	Timeout     time.Duration
	// OnASN reports the outcome of the egress-network lookup the observer runs
	// at the end of a task. Failure here never fails the run.
	// OnProbePinRefresh explains when the authenticated task pin replaces the cached enrolment pin.
	OnProbePinRefresh func()
	OnASN             func(enabled bool, v *server.ASNView, err error)
	ProviderLabel     string // recorded in the task snapshot
	EnvNote           string // free-text note about VPN/TUN/proxy environment, recorded in the snapshot
	Version           string
}

// AttemptReport is the client's result for one attempt, delivered as it completes.
type AttemptReport struct {
	Attempt  server.IssuedAttempt
	Result   ProbeResult
	EventErr error // non-nil if the client event could not be delivered
	Done     int   // attempts finished so far, including this one
	Total    int   // attempts planned
}

// Runner executes tasks for an enrolled node.
type Runner struct {
	CC    *ControlClient
	State Enrollment
	// Outbox, when set, makes delivery of client events and the
	// cancel notice survive a dropped control connection: they are saved
	// locally first and re-sent later. Nil sends directly and drops failures.
	Outbox *Outbox
	now    func() time.Time
}

func (r *Runner) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// send performs the control call for one queued item.
func (r *Runner) send(ctx context.Context, it Item) error {
	switch it.Kind {
	case KindEvent:
		var ev server.ClientEventIn
		if err := json.Unmarshal(it.Payload, &ev); err != nil {
			return &APIError{Status: 400, Message: "corrupt queued event"}
		}
		return r.CC.PostEvent(ctx, r.State.Path, r.State.NodeKey, it.TaskID, ev)
	case KindCancel:
		return r.CC.Cancel(ctx, r.State.Path, r.State.NodeKey, it.TaskID)
	case "webcheck":
		// Old queues may still contain website results. Retire them locally,
		// retaining their payload and reason without contacting a removed API.
		return &APIError{Status: 410, Message: "真实网站访问测试已移除，旧结果保留在本地，不再补交"}
	}
	return &APIError{Status: 400, Message: "unknown queued kind"}
}

// deliver saves an item to the outbox (if any) and tries to send it once. A
// failed send leaves it queued for Flush; the returned error then only says
// "not delivered yet".
func (r *Runner) deliver(ctx context.Context, taskID, kind, eventID string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if r.Outbox == nil {
		return r.send(rctx, Item{TaskID: taskID, Kind: kind, EventID: eventID, Payload: b})
	}
	it, err := r.Outbox.Enqueue(taskID, kind, eventID, b, r.clock())
	if err != nil {
		return err
	}
	if serr := r.send(rctx, it); serr != nil {
		var api *APIError
		if errors.As(serr, &api) && api.Status >= 400 && api.Status < 500 && api.Status != 429 && api.Status != 401 {
			r.Outbox.markRejected(it.ID, serr, r.clock())
		} else {
			r.Outbox.MarkFailed(it.ID, serr)
		}
		return serr
	}
	return r.Outbox.MarkDelivered(it.ID, r.clock())
}

// Flush re-sends everything still queued (for one task, or all with "").
// Safe to call repeatedly: the server stores events idempotently.
func (r *Runner) Flush(ctx context.Context, taskID string) (delivered, remaining int, err error) {
	if r.Outbox == nil {
		return 0, 0, nil
	}
	return r.Outbox.Deliver(ctx, taskID, r.send, r.clock)
}

// RecoverInterrupted marks runs left 'running' by a dead process as
// interrupted and returns their task ids, so they can be reported on.
func (r *Runner) RecoverInterrupted() ([]string, error) {
	if r.Outbox == nil {
		return nil, nil
	}
	ids, err := r.Outbox.Interrupted()
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		r.Outbox.MarkInterrupted(id, r.clock())
	}
	return ids, nil
}

// Watch polls a task's merged view until it is no longer pending or running,
// the context ends, or the task expires. progress is called after each poll.
func (r *Runner) Watch(ctx context.Context, taskID string, every time.Duration, progress func(server.TaskView)) (server.TaskView, error) {
	if every <= 0 {
		every = 2 * time.Second
	}
	for {
		v, err := r.CC.GetTask(ctx, r.State.Path, r.State.NodeKey, taskID)
		if err != nil {
			return v, err
		}
		if progress != nil {
			progress(v)
		}
		if v.Status != server.TaskPending && v.Status != server.TaskRunning || !time.Now().Before(v.ExpiresAt) {
			return v, nil
		}
		select {
		case <-ctx.Done():
			return v, ctx.Err()
		case <-time.After(every):
		}
	}
}

// Run creates a task, probes every attempt (bounded concurrency), reports
// each outcome to the observer, and returns the merged final view. If ctx is
// cancelled, no new attempts start; attempts never started are left without
// client events, so they are not counted as network failures.
func (r *Runner) Run(ctx context.Context, opt RunOptions, progress func(AttemptReport)) (server.TaskView, error) {
	if opt.Concurrency <= 0 {
		opt.Concurrency = DefaultConcurrency
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 5 * time.Second
	}
	stopHeartbeat := r.KeepAlive(ctx)
	defer stopHeartbeat()
	opt.Plan.Rounds = max(opt.Plan.Rounds, 0)
	if opt.Plan.Rounds == 0 {
		opt.Plan.Rounds = 3
	}
	plan, seed, err := BuildPlan(opt.Plan)
	if err != nil {
		return server.TaskView{}, err
	}
	opt.Plan.Seed = seed
	// Include phase barriers and repeated-SNI cooldowns in credential lifetime.
	issued := make([]server.IssuedAttempt, len(plan))
	for i, a := range plan {
		issued[i] = server.IssuedAttempt{Kind: a.Kind, Round: a.Round, SNI: a.SNI}
	}
	budget := time.Minute
	for _, phase := range attemptPhases(issued) {
		counts := map[string]int{}
		repeats := 0
		for _, a := range phase {
			key := strings.ToLower(a.SNI)
			counts[key]++
			repeats = max(repeats, counts[key])
		}
		batches := (len(phase) + opt.Concurrency - 1) / opt.Concurrency
		budget += time.Duration(batches+repeats-1)*opt.Timeout + time.Duration(repeats)*SNIProbeInterval
	}
	ttl := int(budget.Seconds())
	created, err := r.CC.CreateTask(ctx, r.State.Path, r.State.NodeKey, server.CreateRequest{
		Attempts: plan, Params: ParamsJSON(opt.Plan, seed, opt), TTLSeconds: ttl,
	})
	if err != nil {
		return server.TaskView{}, err
	}
	// The authenticated control channel is authoritative, allowing observer key
	// rotation. Enrollment.ProbePin is only a cached copy from registration.
	if r.State.ProbePin != "" && !strings.EqualFold(r.State.ProbePin, created.ProbePin) && opt.OnProbePinRefresh != nil {
		opt.OnProbePinRefresh()
	}
	taskID := created.Task.ID
	localView := created.Task
	if r.Outbox != nil {
		if err := r.Outbox.SaveTask(localView); err != nil {
			return server.TaskView{}, fmt.Errorf("保存本地任务失败：%w", err)
		}
	}

	if r.Outbox != nil {
		r.Outbox.StartRun(taskID, r.clock())
	}
	// On interruption, tell the server at once (independent of the run's
	// cancelled context) so it stops accepting new probes for this task.
	finished := make(chan struct{})
	var cancelWG sync.WaitGroup
	cancelWG.Add(1)
	go func() {
		defer cancelWG.Done()
		select {
		case <-ctx.Done():
			r.deliver(ctx, taskID, KindCancel, "cancel", struct{}{})
		case <-finished:
		}
	}()

	var pmu sync.Mutex
	done := 0
	scheduleProbes(ctx, created.Attempts, opt.Concurrency, SNIProbeInterval, func(a server.IssuedAttempt) {
		res := Probe(ctx, ProbeSpec{
			Target: a.Target, SNI: a.SNI, Pin: created.ProbePin, Path: r.State.Path,
			AttemptID: a.ID, Credential: a.Credential, Timeout: opt.Timeout,
		})
		// Reporting must survive cancellation of the run itself, and
		// survive a dropped connection (outbox).
		evID := "ev_" + auth.RandomString(9)
		evErr := r.deliver(ctx, taskID, KindEvent, evID, server.ClientEventIn{
			AttemptID: a.ID, EventID: evID, Stage: res.Stage, Outcome: res.Outcome,
			Error: res.Error, StartedAt: res.StartedAt, DurationMS: res.Duration.Milliseconds(), HelloSHA256: res.HelloSHA256,
		})
		pmu.Lock()
		for i := range localView.Attempts {
			av := &localView.Attempts[i]
			if av.ID != a.ID {
				continue
			}
			av.Client = append(av.Client, server.ClientEventView{EventID: evID, Stage: res.Stage, Outcome: res.Outcome, Error: res.Error, StartedAt: res.StartedAt, DurationMS: res.Duration.Milliseconds(), HelloSent: res.HelloSHA256 != ""})
			av.State = server.StateUnobserved
			if res.Outcome == OutcomeCancelled {
				av.State = server.StateCancelled
			}
			if rc := res.Receipt; rc != nil {
				av.State = server.StateAuthenticated
				if !rc.SNIMatch {
					av.State = server.StateSNIMismatch
				}
				av.Observation = &server.Observation{SourceIP: rc.SourceIP, ObservedSNI: rc.ObservedSNI, SNIMatch: rc.SNIMatch, ObservedAt: rc.ObservedAt, Evidence: "authenticated"}
			}
		}
		localView.Status = server.TaskRunning
		if r.Outbox != nil {
			r.Outbox.SaveTask(localView)
		}
		done++
		if progress != nil {
			progress(AttemptReport{Attempt: a, Result: res, EventErr: evErr, Done: done, Total: len(plan)})
		}
		pmu.Unlock()
	})

	close(finished)
	cancelWG.Wait()
	interrupted := ctx.Err() != nil
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	// One more try for anything that could not be delivered while the link was down.
	r.Flush(fctx, taskID)
	// Ask the observer which networks the egress IPs belong to. Best effort:
	// if the link is down or the source is unavailable, the report is still
	// complete without it and a later refresh adds a new snapshot.
	actx, acancel := context.WithTimeout(context.WithoutCancel(ctx), 40*time.Second)
	v, enabled, aerr := r.CC.ASN(actx, r.State.Path, r.State.NodeKey, taskID, false)
	acancel()
	if opt.OnASN != nil {
		opt.OnASN(enabled, v, aerr)
	}
	if r.Outbox != nil {
		status := "finished"
		if interrupted {
			status = "cancelled"
		}
		r.Outbox.FinishRun(taskID, status, r.clock())
	}
	readCtx, readCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer readCancel()
	final, err := r.CC.GetTask(readCtx, r.State.Path, r.State.NodeKey, taskID)
	if err != nil {
		if interrupted {
			localView.Status = server.TaskAborted
			now := r.clock()
			localView.CancelledAt = &now
		}
		if r.Outbox != nil {
			r.Outbox.SaveTask(localView)
		}
		return localView, err
	}
	if r.Outbox != nil {
		if err := r.Outbox.SaveTask(final); err != nil {
			return final, fmt.Errorf("保存本地报告失败：%w", err)
		}
	}
	return final, nil
}
