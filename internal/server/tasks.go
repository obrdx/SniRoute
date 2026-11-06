package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/nyktios/sniroute/internal/asn"
	"github.com/nyktios/sniroute/internal/auth"
	"github.com/nyktios/sniroute/internal/probe"
	"github.com/nyktios/sniroute/internal/store"
	"github.com/nyktios/sniroute/internal/version"
)

// TaskStatus is derived from attempts and the clock; nothing is stored.
type TaskStatus string

const (
	TaskPending   TaskStatus = "pending"   // nothing resolved yet
	TaskRunning   TaskStatus = "running"   // some attempts resolved, others open
	TaskCompleted TaskStatus = "completed" // every attempt resolved or expired
	// TaskAborted / TaskFailed are reserved for the cancellation work (P4).
	TaskAborted TaskStatus = "aborted"
	TaskFailed  TaskStatus = "failed"
)

// AttemptState is the combined, derived view of one attempt.
type AttemptState string

const (
	StatePending       AttemptState = "pending"         // waiting for the probe / client report
	StateAuthenticated AttemptState = "authenticated"   // observer issued a receipt, SNI as planned
	StateSNIMismatch   AttemptState = "sni_mismatch"    // receipt issued, but a different SNI was observed
	StateHelloMatched  AttemptState = "hello_matched"   // observer saw the ClientHello the client reported; nothing authenticated
	StateHelloAmbig    AttemptState = "hello_ambiguous" // several connections carried that ClientHello; not attributed
	StateUnobserved    AttemptState = "unobserved"      // client reported an outcome; observer saw nothing
	StateTimeout       AttemptState = "timeout"         // nothing arrived before the task expired
	StateCancelled     AttemptState = "cancelled"       // the task was cancelled before this attempt produced anything
)

var ErrTooMany = errors.New("server: too many active tasks")

// cancelGrace is how long after a cancel a probe that was already on the wire
// may still be recorded.
const cancelGrace = 3 * time.Second

// BadRequestError is returned for invalid input; its text is safe to show.
type BadRequestError string

func (e BadRequestError) Error() string { return string(e) }

// Observation is the observer-side fact for an attempt.
type Observation struct {
	SourceIP    string    `json:"source_ip"`
	SourcePort  int       `json:"source_port"`
	ObservedSNI string    `json:"observed_sni"`
	ObservedAt  time.Time `json:"observed_at"`
	Evidence    string    `json:"evidence"`
	SNIMatch    bool      `json:"sni_match"`
}

// ClientEventView is a client-reported fact for an attempt.
type ClientEventView struct {
	EventID    string    `json:"event_id"`
	Stage      string    `json:"stage"`
	Outcome    string    `json:"outcome"`
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	HelloSent  bool      `json:"hello_sent"` // client reported the digest of the ClientHello it sent
}

// AttemptView is a snapshot of one attempt.
type AttemptView struct {
	ID          string            `json:"id"`
	Index       int               `json:"index"`
	SNI         string            `json:"sni"`
	Target      string            `json:"target"`
	Kind        string            `json:"kind"`
	Round       int               `json:"round"`
	State       AttemptState      `json:"state"`
	Observation *Observation      `json:"observation,omitempty"`
	Client      []ClientEventView `json:"client_events,omitempty"`
}

// ASNView is one frozen snapshot of egress-network lookups for a task. Newer
// snapshots never alter older ones.
type ASNView struct {
	Snapshot  int        `json:"snapshot"`  // number of this snapshot (1, 2, ...)
	Snapshots int        `json:"snapshots"` // how many exist
	Source    string     `json:"source"`
	QueriedAt time.Time  `json:"queried_at"`
	Items     []asn.Info `json:"items"`
}

// NodeSummary identifies the node a task belongs to.
type NodeSummary struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ProviderLabel string `json:"provider_label"`
}

// TaskView is a snapshot of a task.
type TaskView struct {
	ID          string          `json:"id"`
	Target      string          `json:"target"`
	CollectorID string          `json:"collector_id"`
	Params      json.RawMessage `json:"params,omitempty"` // client-supplied test conditions, as frozen at creation
	Status      TaskStatus      `json:"status"`
	CreatedAt   time.Time       `json:"created_at"`
	ExpiresAt   time.Time       `json:"expires_at"`
	Attempts    []AttemptView   `json:"attempts"`
	ASN         *ASNView        `json:"asn,omitempty"` // egress-network lookups (one frozen snapshot)
	Node        NodeSummary     `json:"node"`
	CancelledAt *time.Time      `json:"cancelled_at,omitempty"`
}

// IssuedAttempt carries the one-time credential the client must present on
// the probe connection. It is returned only when the task is created.
type IssuedAttempt struct {
	ID         string `json:"id"`
	Index      int    `json:"index"`
	SNI        string `json:"sni"`
	Target     string `json:"target"`
	Kind       string `json:"kind"`
	Round      int    `json:"round"`
	Credential string `json:"credential"`
}

// TasksConfig bounds task creation. Zero values select defaults.
type TasksConfig struct {
	TaskTTL          time.Duration // default credential lifetime, default 5m
	MaxTaskTTL       time.Duration // longest lifetime a client may request, default 1h
	MaxAttempts      int           // attempts per task, default 4000 (the whole library at 3 rounds)
	MaxActivePerNode int           // unfinished tasks per node, default 4
	MaxActive        int           // unfinished tasks overall, default 64
}

func (c *TasksConfig) setDefaults() {
	if c.TaskTTL <= 0 {
		c.TaskTTL = 5 * time.Minute
	}
	if c.MaxTaskTTL <= 0 {
		c.MaxTaskTTL = time.Hour
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 4000
	}
	if c.MaxActivePerNode <= 0 {
		c.MaxActivePerNode = 4
	}
	if c.MaxActive <= 0 {
		c.MaxActive = 64
	}

}

// Tasks creates tasks, issues attempt credentials, and merges observer and
// client evidence. It is safe for concurrent use.
type Tasks struct {
	cfg         TasksConfig
	reg         *auth.Registry
	st          *store.Store
	collectorID string
	now         func() time.Time
	hellos      helloRing
	// ASN performs egress-network lookups; nil disables them.
	ASN *asn.Service
}

// NewTasks creates a task manager.
func NewTasks(cfg TasksConfig, reg *auth.Registry, st *store.Store, collectorID string) *Tasks {
	cfg.setDefaults()
	return &Tasks{cfg: cfg, reg: reg, st: st, collectorID: collectorID, now: time.Now, hellos: newHelloRing(4096)}
}

// PlannedAttempt is one probe the client intends to make.
type PlannedAttempt struct {
	Target string `json:"target"` // observer ip:port; one comparison group per target
	SNI    string `json:"sni"`
	Kind   string `json:"kind"` // "baseline" or "domain"
	Round  int    `json:"round"`
}

// CreateRequest plans a task. Params is an opaque JSON object holding the
// client's test conditions (domains, baseline names, rounds, seed, timeouts,
// environment note...); it is frozen into the task snapshot.
type CreateRequest struct {
	Attempts   []PlannedAttempt `json:"attempts"`
	Params     json.RawMessage  `json:"params,omitempty"`
	TTLSeconds int              `json:"ttl_seconds"`
}

const maxParamsBytes = 16 << 10

// Create validates the plan and creates a task with one attempt (and one
// one-time credential) per planned probe.
func (s *Tasks) Create(nodeID string, req CreateRequest) (TaskView, []IssuedAttempt, error) {
	if n := len(req.Attempts); n == 0 || n > s.cfg.MaxAttempts {
		return TaskView{}, nil, BadRequestError("attempts: need between 1 and " + strconv.Itoa(s.cfg.MaxAttempts) + " entries")
	}
	for _, a := range req.Attempts {
		ap, err := netip.ParseAddrPort(a.Target)
		if err != nil || ap.Port() == 0 || ap.Addr().IsUnspecified() {
			return TaskView{}, nil, BadRequestError("attempts: target must be ip:port")
		}
		if probe.ValidateSNI(a.SNI) != nil {
			return TaskView{}, nil, BadRequestError("attempts: invalid SNI (printable ASCII, 1-255 bytes)")
		}
		if _, err := netip.ParseAddr(a.SNI); err == nil {
			// Go (and most stacks) omit SNI for IP literals, so it could not be tested.
			return TaskView{}, nil, BadRequestError("attempts: IP literals are not sent as SNI")
		}
		if a.Kind != "baseline" && a.Kind != "domain" {
			return TaskView{}, nil, BadRequestError(`attempts: kind must be "baseline" or "domain"`)
		}
		if a.Round < 0 || a.Round > 1000 {
			return TaskView{}, nil, BadRequestError("attempts: round out of range")
		}
	}
	params := json.RawMessage("{}")
	if len(req.Params) > 0 {
		var probeObj map[string]json.RawMessage
		if len(req.Params) > maxParamsBytes || json.Unmarshal(req.Params, &probeObj) != nil || probeObj == nil {
			return TaskView{}, nil, BadRequestError("params must be a JSON object of at most 16 KiB")
		}
		params = req.Params
	}
	ttl := s.cfg.TaskTTL
	if req.TTLSeconds > 0 {
		ttl = min(max(time.Duration(req.TTLSeconds)*time.Second, 30*time.Second), s.cfg.MaxTaskTTL)
	}

	now := s.now()
	all, node, err := s.st.CountActive(now, nodeID)
	if err != nil {
		return TaskView{}, nil, err
	}
	if all >= s.cfg.MaxActive || node >= s.cfg.MaxActivePerNode {
		return TaskView{}, nil, ErrTooMany
	}

	snapshot, _ := json.Marshal(map[string]any{
		"version": version.Protocol, "protocol_version": version.Protocol, "collector_id": s.collectorID, "alpn": "http/1.1",
		"task_ttl_seconds": int(ttl.Seconds()), "attempt_count": len(req.Attempts), "params": params,
	})
	t := &store.Task{
		ID: "task_" + auth.RandomString(9), NodeID: nodeID, CollectorID: s.collectorID, Target: req.Attempts[0].Target,
		CreatedAt: now, ExpiresAt: now.Add(ttl), Snapshot: string(snapshot),
	}
	atts := make([]store.Attempt, len(req.Attempts))
	issued := make([]IssuedAttempt, len(req.Attempts))
	for i, a := range req.Attempts {
		cred := auth.NewAttemptCredential()
		id := auth.NewAttemptID()
		atts[i] = store.Attempt{ID: id, Index: i, SNI: a.SNI, Target: a.Target, Kind: a.Kind, Round: a.Round, CredHash: auth.HashCredential(cred)}
		issued[i] = IssuedAttempt{ID: id, Index: i, SNI: a.SNI, Target: a.Target, Kind: a.Kind, Round: a.Round, Credential: cred}
	}
	if err := s.st.InsertTask(t, atts); err != nil {
		return TaskView{}, nil, err
	}
	view, _, err := s.Get(nodeID, t.ID)
	return view, issued, err
}

// Get returns a snapshot of a task owned by nodeID.
func (s *Tasks) Get(nodeID, id string) (TaskView, bool, error) { return s.GetAt(nodeID, id, 0) }

// GetAt is Get with a chosen ASN snapshot (0 = the latest).
func (s *Tasks) GetAt(nodeID, id string, asnSnapshot int) (TaskView, bool, error) {
	t, err := s.st.GetTask(id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && t.NodeID != nodeID) {
		return TaskView{}, false, nil
	}
	if err != nil {
		return TaskView{}, false, err
	}
	return s.build(t, asnSnapshot)
}

// GetAny returns a task regardless of owner. For operator tools that read the
// database directly (the server menu); never exposed through the node API.
func (s *Tasks) GetAny(id string) (TaskView, bool, error) {
	t, err := s.st.GetTask(id)
	if errors.Is(err, store.ErrNotFound) {
		return TaskView{}, false, nil
	}
	if err != nil {
		return TaskView{}, false, err
	}
	return s.build(t, 0)
}

func (s *Tasks) build(t *store.Task, asnSnapshot int) (TaskView, bool, error) {
	id := t.ID
	atts, err := s.st.TaskAttempts(id)
	if err != nil {
		return TaskView{}, false, err
	}
	obs, err := s.st.TaskObservations(id)
	if err != nil {
		return TaskView{}, false, err
	}
	evs, err := s.st.TaskClientEvents(id)
	if err != nil {
		return TaskView{}, false, err
	}
	asnView, err := s.asnView(id, asnSnapshot)
	if err != nil {
		return TaskView{}, false, err
	}
	byAttempt := make(map[string][]ClientEventView)
	for _, e := range evs {
		byAttempt[e.AttemptID] = append(byAttempt[e.AttemptID], ClientEventView{
			EventID: e.EventID, Stage: e.Stage, Outcome: e.Outcome, Error: e.Error,
			StartedAt: e.StartedAt, DurationMS: e.DurationMS, HelloSent: e.HelloSHA256 != "",
		})
	}

	now := s.now()
	expired := !now.Before(t.ExpiresAt)
	view := TaskView{
		ID: t.ID, Target: t.Target, CollectorID: t.CollectorID,
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, CancelledAt: t.CancelledAt, Attempts: make([]AttemptView, len(atts)),
	}
	view.ASN = asnView
	if n, err := s.st.NodeByID(t.NodeID); err == nil {
		view.Node = NodeSummary{ID: n.ID, Name: n.Name, ProviderLabel: n.ProviderLabel}
	}
	var snap struct {
		Params json.RawMessage `json:"params"`
	}
	if json.Unmarshal([]byte(t.Snapshot), &snap) == nil {
		view.Params = snap.Params
	}
	open, resolved := 0, 0
	for i, a := range atts {
		av := AttemptView{ID: a.ID, Index: a.Index, SNI: a.SNI, Target: a.Target, Kind: a.Kind, Round: a.Round, Client: byAttempt[a.ID]}
		if o, ok := obs[a.ID]; ok {
			av.Observation = &Observation{
				SourceIP: o.RemoteIP, SourcePort: o.RemotePort, ObservedSNI: o.ObservedSNI,
				ObservedAt: o.ObservedAt, Evidence: o.Evidence, SNIMatch: o.SNIMatch,
			}
		}
		switch {
		case a.State == store.AttemptAuthenticated:
			av.State = StateAuthenticated
		case a.State == store.AttemptSNIMismatch:
			av.State = StateSNIMismatch
		case a.State == store.AttemptHelloMatched:
			av.State = StateHelloMatched
		case a.State == store.AttemptHelloAmbig:
			av.State = StateHelloAmbig
		case len(av.Client) > 0 && av.Client[len(av.Client)-1].Outcome == "cancelled":
			// Interrupted by the user before it produced anything: not a failure.
			av.State = StateCancelled
		case len(av.Client) > 0:
			av.State = StateUnobserved
		case t.CancelledAt != nil:
			av.State = StateCancelled
		case expired:
			av.State = StateTimeout
		default:
			av.State = StatePending
		}
		if av.State == StatePending {
			open++
		} else {
			resolved++
		}
		view.Attempts[i] = av
	}
	switch {
	case t.CancelledAt != nil:
		view.Status = TaskAborted
	case open == 0:
		view.Status = TaskCompleted
	case resolved > 0:
		view.Status = TaskRunning
	default:
		view.Status = TaskPending
	}
	return view, true, nil
}

// Outcome describes how a probe receipt request was handled, for logging.
type Outcome string

const (
	OutcomeAccepted          Outcome = "accepted"           // credential valid, SNI as planned
	OutcomeMismatch          Outcome = "sni_mismatch"       // credential valid, different SNI observed
	OutcomeUnknownCredential Outcome = "unknown_credential" // never issued, wrong path/attempt, or swept
	OutcomeReused            Outcome = "reused"
	OutcomeExpired           Outcome = "expired"
	OutcomeRevoked           Outcome = "node_revoked"
	OutcomeCancelled         Outcome = "task_cancelled"
)

// ReceiptRequest is the body the client sends over the established TLS
// connection to the probe endpoint.
type ReceiptRequest struct {
	Path       string `json:"path"`
	AttemptID  string `json:"attempt_id"`
	Credential string `json:"credential"`
}

// Observed is what the observer saw on the connection that carried the request.
type Observed struct {
	Remote netip.AddrPort
	SNI    string // from the ClientHello
	At     time.Time
}

// Receipt is the observer's answer: the source address it saw.
type Receipt struct {
	AttemptID   string    `json:"attempt_id"`
	SourceIP    string    `json:"source_ip"`
	ObservedSNI string    `json:"observed_sni"`
	SNIMatch    bool      `json:"sni_match"`
	ObservedAt  time.Time `json:"observed_at"`
}

// HandleReceipt authenticates the request and records the observation. The
// credential is consumed by its first valid use.
func (s *Tasks) HandleReceipt(req ReceiptRequest, obs Observed) (*Receipt, Outcome, error) {
	ref, err := s.st.AttemptByCred(auth.HashCredential(req.Credential))
	if errors.Is(err, store.ErrNotFound) {
		return nil, OutcomeUnknownCredential, nil
	}
	if err != nil {
		return nil, "", err
	}
	// The credential is bound to one attempt of one node; a mismatch is a
	// forged or confused request and burns nothing.
	if ref.ID != req.AttemptID || ref.NodePath != req.Path {
		return nil, OutcomeUnknownCredential, nil
	}
	if ref.NodeRevoked || !s.reg.Active(ref.NodeID) {
		return nil, OutcomeRevoked, nil
	}
	if !obs.At.Before(ref.TaskExpires) {
		return nil, OutcomeExpired, nil
	}
	// After a cancel, only connections that were already in flight (within a
	// short grace) are still recorded; later probes are refused.
	if ref.TaskCancel != nil && obs.At.After(ref.TaskCancel.Add(cancelGrace)) {
		return nil, OutcomeCancelled, nil
	}

	match := ref.SNI == obs.SNI
	state, out := store.AttemptAuthenticated, OutcomeAccepted
	if !match {
		state, out = store.AttemptSNIMismatch, OutcomeMismatch
	}
	ok, err := s.st.RecordObservation(store.Observation{
		AttemptID: ref.ID, ObservedAt: obs.At, RemoteIP: obs.Remote.Addr().String(), RemotePort: int(obs.Remote.Port()),
		ObservedSNI: obs.SNI, Evidence: store.EvidenceAuthenticated, SNIMatch: match,
	}, state)
	if err != nil {
		return nil, "", err
	}
	if !ok {
		return nil, OutcomeReused, nil
	}
	return &Receipt{
		AttemptID: ref.ID, SourceIP: obs.Remote.Addr().String(), ObservedSNI: obs.SNI,
		SNIMatch: match, ObservedAt: obs.At,
	}, out, nil
}

// ClientEventIn is a client's report about one attempt.
type ClientEventIn struct {
	AttemptID  string    `json:"attempt_id"`
	EventID    string    `json:"event_id"`
	Stage      string    `json:"stage"`
	Outcome    string    `json:"outcome"`
	Error      string    `json:"error"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	// HelloSHA256 is the hex SHA-256 of the complete ClientHello message the
	// client sent for this attempt (empty if none was sent, e.g. dial failure).
	HelloSHA256 string `json:"hello_sha256"`
}

var (
	validStages   = map[string]bool{"tcp": true, "tls": true, "http": true, "control": true}
	validOutcomes = map[string]bool{
		"receipt": true, "dial_failed": true, "timeout": true, "tls_failed": true,
		"identity_mismatch": true, "http_failed": true, "cancelled": true,
	}
)

// RecordClientEvent stores a client report idempotently. The attempt must
// belong to taskID and to nodeID.
func (s *Tasks) RecordClientEvent(nodeID, taskID string, e ClientEventIn) error {
	if e.EventID == "" || len(e.EventID) > 64 || !validStages[e.Stage] || !validOutcomes[e.Outcome] ||
		e.DurationMS < 0 || e.DurationMS > int64(time.Hour/time.Millisecond) || e.StartedAt.IsZero() {
		return BadRequestError("invalid event")
	}
	var digest [sha256.Size]byte
	if e.HelloSHA256 != "" {
		b, err := hex.DecodeString(e.HelloSHA256)
		if err != nil || len(b) != sha256.Size {
			return BadRequestError("invalid hello_sha256")
		}
		copy(digest[:], b)
	}
	if len(e.Error) > 512 {
		e.Error = e.Error[:512]
	}
	ref, err := s.st.AttemptByID(e.AttemptID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (ref.TaskID != taskID || ref.NodeID != nodeID)) {
		return BadRequestError("unknown attempt")
	}
	if err != nil {
		return err
	}
	fresh, err := s.st.InsertClientEvent(store.ClientEvent{
		AttemptID: e.AttemptID, EventID: e.EventID, ReceivedAt: s.now(), Stage: e.Stage, Outcome: e.Outcome,
		Error: e.Error, StartedAt: e.StartedAt, DurationMS: e.DurationMS, HelloSHA256: e.HelloSHA256,
	})
	if err != nil || !fresh || e.HelloSHA256 == "" {
		return err
	}
	return s.matchHello(ref, digest)
}

// matchHello binds an attempt to the ClientHello the observer saw, if any.
// This is weaker evidence than a receipt (nothing was authenticated) and is
// only recorded when the attempt has no observation yet. Several connections
// with the same digest (a replay, say) are marked ambiguous, never attributed.
func (s *Tasks) matchHello(ref *store.AttemptRef, digest [sha256.Size]byte) error {
	if ref.State != store.AttemptPending {
		return nil
	}
	seen := s.hellos.find(digest, ref.TaskCreated)
	o := store.Observation{AttemptID: ref.ID, ObservedAt: s.now()}
	switch len(seen) {
	case 0:
		return nil // the observer never saw this ClientHello: no evidence either way
	case 1:
		h := seen[0]
		o.ObservedAt, o.RemoteIP, o.RemotePort, o.ObservedSNI = h.at, h.remote.Addr().String(), int(h.remote.Port()), h.sni
		o.Evidence, o.SNIMatch = store.EvidenceHelloMatch, h.sni == ref.SNI
		_, err := s.st.RecordObservation(o, store.AttemptHelloMatched)
		return err
	default:
		o.Evidence = store.EvidenceAmbiguous
		_, err := s.st.RecordObservation(o, store.AttemptHelloAmbig)
		return err
	}
}

// NoteHello remembers an unauthenticated ClientHello seen by the probe
// listener, in a bounded in-memory ring, so a later client report can be
// matched against it. Entries are never attributed on their own.
func (s *Tasks) NoteHello(ev Event) {
	if ev.Status == StatusReceived {
		s.hellos.add(helloEntry{at: ev.Time, remote: ev.Remote, sni: ev.SNI, digest: ev.Digest})
	}
}

type helloEntry struct {
	at     time.Time
	remote netip.AddrPort
	sni    string
	digest [sha256.Size]byte
}

// helloRing is a fixed-size ring: the oldest entries are overwritten, so
// memory use is bounded no matter how many scanners connect.
type helloRing struct {
	mu   sync.Mutex
	buf  []helloEntry
	next int
	n    int
}

func newHelloRing(size int) helloRing { return helloRing{buf: make([]helloEntry, size)} }

// Cleanup also expires unassigned handshake evidence, which has no node owner.
func (s *Tasks) Cleanup(now time.Time) (int64, error) {
	s.hellos.mu.Lock()
	for i, e := range s.hellos.buf {
		if !e.at.After(now.Add(-store.NodeOfflineTTL)) {
			s.hellos.buf[i] = helloEntry{}
		}
	}
	s.hellos.mu.Unlock()
	return s.st.PruneOfflineNodes(now)
}

func (r *helloRing) add(e helloEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = e
	r.next = (r.next + 1) % len(r.buf)
	if r.n < len(r.buf) {
		r.n++
	}
}

func (r *helloRing) find(d [sha256.Size]byte, since time.Time) []helloEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []helloEntry
	for i := 0; i < r.n; i++ {
		if e := r.buf[i]; e.digest == d && !e.at.Before(since) {
			out = append(out, e)
		}
	}
	return out
}

// Cancel marks a task cancelled: no new probes are accepted (beyond the grace
// for those in flight) and its unfinished attempts read as "cancelled", not as
// failures. Facts already recorded stay. Idempotent.
func (s *Tasks) Cancel(nodeID, taskID string) error {
	t, err := s.st.GetTask(taskID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && t.NodeID != nodeID) {
		return BadRequestError("unknown task")
	}
	if err != nil {
		return err
	}
	_, err = s.st.CancelTask(taskID, s.now())
	return err
}

// TaskListItem is one row of a node's task history.
type TaskListItem struct {
	ID        string     `json:"id"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	Status    TaskStatus `json:"status"`
	Target    string     `json:"target"`
	Planned   int        `json:"planned"`
	Recorded  int        `json:"recorded"` // attempts with any observer or client fact
	Cancelled bool       `json:"cancelled"`
}

// List returns the node's newest tasks, newest first.
func (s *Tasks) List(nodeID string, limit int) ([]TaskListItem, error) {
	if limit <= 0 || limit > 100 {
		limit = 30
	}
	rows, err := s.st.RecentTasks(nodeID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]TaskListItem, 0, len(rows))
	for _, r := range rows {
		v, ok, err := s.Get(nodeID, r.ID)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		rec := 0
		for _, a := range v.Attempts {
			if a.Observation != nil || len(a.Client) > 0 {
				rec++
			}
		}
		out = append(out, TaskListItem{ID: v.ID, CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt, Status: v.Status,
			Target: v.Target, Planned: len(v.Attempts), Recorded: rec, Cancelled: v.CancelledAt != nil})
	}
	return out, nil
}

// asnView loads a stored ASN snapshot (0 = latest); nil when there is none.
func (s *Tasks) asnView(taskID string, snapshot int) (*ASNView, error) {
	rows, n, err := s.st.TaskASN(taskID, snapshot)
	if err != nil || n == 0 {
		return nil, err
	}
	all, err := s.st.ASNSnapshots(taskID)
	if err != nil {
		return nil, err
	}
	v := &ASNView{Snapshot: n, Snapshots: len(all), Items: []asn.Info{}}
	for _, r := range rows {
		var i asn.Info
		if json.Unmarshal([]byte(r.Result), &i) != nil {
			continue
		}
		i.QueriedAt = r.QueriedAt
		v.Source = r.Source
		if r.QueriedAt.After(v.QueriedAt) {
			v.QueriedAt = r.QueriedAt
		}
		v.Items = append(v.Items, i)
	}
	return v, nil
}

// ErrASNDisabled is returned when egress-network lookups are switched off.
var ErrASNDisabled = errors.New("server: egress-network lookups are disabled")

// minASNRefresh stops a task's snapshots being created in a tight loop.
const minASNRefresh = 30 * time.Second

const maxASNIPs = 200

// EnsureASN makes sure the task has an ASN snapshot. Without refresh, an
// existing latest snapshot is returned untouched. With refresh a NEW snapshot
// is created; older ones are never modified. Lookups run here, on the
// observer, and a failed lookup is recorded per IP: the observed IPs stay
// valid and the run is never failed by this step.
func (s *Tasks) EnsureASN(ctx context.Context, nodeID, taskID string, refresh bool) (*ASNView, error) {
	t, err := s.st.GetTask(taskID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && t.NodeID != nodeID) {
		return nil, BadRequestError("unknown task")
	}
	if err != nil {
		return nil, err
	}
	return s.ensureASN(ctx, t, refresh)
}

// EnsureASNAny is EnsureASN without the ownership check, for operator tools.
func (s *Tasks) EnsureASNAny(ctx context.Context, taskID string, refresh bool) (*ASNView, error) {
	t, err := s.st.GetTask(taskID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, BadRequestError("unknown task")
	}
	if err != nil {
		return nil, err
	}
	return s.ensureASN(ctx, t, refresh)
}

func (s *Tasks) ensureASN(ctx context.Context, t *store.Task, refresh bool) (*ASNView, error) {
	if s.ASN == nil {
		return nil, ErrASNDisabled
	}
	existing, err := s.asnView(t.ID, 0)
	if err != nil {
		return nil, err
	}
	if existing != nil && !refresh {
		return existing, nil
	}
	if existing != nil && s.now().Sub(existing.QueriedAt) < minASNRefresh {
		return nil, ErrTooMany
	}

	obs, err := s.st.TaskObservations(t.ID)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, o := range obs {
		ip, err := netip.ParseAddr(o.RemoteIP)
		if err != nil || seen[ip.Unmap()] || len(ips) >= maxASNIPs {
			continue
		}
		seen[ip.Unmap()] = true
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return existing, nil // nothing observed, nothing to look up
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Compare(ips[j]) < 0 })

	infos := s.ASN.LookupMany(ctx, ips)
	rows := make([]store.ASNRow, 0, len(infos))
	for _, i := range infos {
		b, err := json.Marshal(i)
		if err != nil {
			return nil, err
		}
		rows = append(rows, store.ASNRow{IP: i.IP, Source: i.Source, QueriedAt: i.QueriedAt, Status: string(i.Status), Result: string(b)})
	}
	n, err := s.st.InsertASNSnapshot(t.ID, rows)
	if err != nil {
		return nil, err
	}
	return s.asnView(t.ID, n)
}
