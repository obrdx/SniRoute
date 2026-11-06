package server

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/nyktios/sniroute/internal/auth"
	"github.com/nyktios/sniroute/internal/version"
)

// maxBodyBytes bounds a control request. Creating a task is the largest one:
// every attempt carries a credential, and the attempt count is capped by
// TasksConfig.MaxAttempts (4000 by default, about 900 KiB of JSON). The old
// 64 KiB cap rejected a full-library run before it could be validated, so the
// client saw only "413 body too large".
const maxBodyBytes = 4 << 20

// Control is the HTTP API of the central server.
//
//	GET  /api/health                        anonymous: service identity + probe pin
//	POST /api/register                     {reg_token|reg_key, name, provider_label} -> credentials
//	POST /api/admin/reg-tokens             {ttl_seconds?}        (admin)
//	GET  /api/admin/reg-tokens                                  (admin) outstanding tokens
//	DELETE /api/admin/reg-tokens/{id}                            (admin) revoke one token
//	GET /api/admin/connections                                (admin) testing clients
//	POST /n/{path}/heartbeat                                  (node key) keep alive
//	POST /n/{path}/tasks                   {attempts, params, ttl_seconds} (node key)
//	GET  /n/{path}/tasks/{id}                                   (node key)
//	POST /n/{path}/tasks/{id}/events       {attempt_id, event_id, ...} (node key)
//	GET  /n/{path}/tasks?limit=N                                (node key) task history
//	POST /n/{path}/tasks/{id}/cancel                            (node key)
//	POST /n/{path}/tasks/{id}/asn          {refresh}            (node key) egress-network lookup
//
// Admin and node routes take "Authorization: Bearer <key>". Node routes
// answer every authentication failure with the same 401.
type Control struct {
	reg      *auth.Registry
	tasks    *Tasks
	log      *slog.Logger
	probePin string // SPKI pin of the probe endpoint, delivered over this authenticated channel
	// ProbeAddr is the address the probe listener was configured with. Only its
	// port is published: clients need it to build a default probe target, and a
	// port is not a secret.
	ProbeAddr string
}

// probePort reports the port of the probe listener, or "" when it is unknown.
func (c *Control) probePort() string {
	if c.ProbeAddr == "" {
		return ""
	}
	if _, port, err := net.SplitHostPort(c.ProbeAddr); err == nil {
		return port
	}
	return ""
}

// NewControl builds the API around a registry and task manager. probePin is
// the hex SHA-256 of the probe certificate's public key; clients learn it
// here and use it to verify the probe endpoint.
func NewControl(reg *auth.Registry, tasks *Tasks, probePin string, log *slog.Logger) *Control {
	if log == nil {
		log = slog.Default()
	}
	return &Control{reg: reg, tasks: tasks, probePin: probePin, log: log}
}

// WithProbeAddr records where the probe listener actually ended up, so the
// published port is the real one even when the config used port 0.
func (c *Control) WithProbeAddr(addr string) *Control {
	c.ProbeAddr = addr
	return c
}

// Handler returns the HTTP handler for the control service.
func (c *Control) Handler() http.Handler {
	mux := http.NewServeMux()
	// A link pasted into a browser lands here. It explains what to do and never
	// echoes the fragment: the browser does not send it, and a token in a URL
	// is exactly what this design keeps out of logs.
	mux.HandleFunc("GET /join", c.joinPage)
	mux.HandleFunc("GET /api/health", c.health)
	mux.HandleFunc("POST /api/register", c.register)
	mux.HandleFunc("POST /api/admin/reg-tokens", c.admin(c.newRegToken))
	mux.HandleFunc("GET /api/admin/reg-tokens", c.admin(c.listRegTokens))
	mux.HandleFunc("DELETE /api/admin/reg-tokens/{id}", c.admin(c.deleteRegToken))
	mux.HandleFunc("GET /api/admin/connections", c.admin(c.liveConnections))
	mux.HandleFunc("POST /n/{path}/heartbeat", c.node(func(w http.ResponseWriter, r *http.Request, n auth.NodeInfo) { w.WriteHeader(http.StatusNoContent) }))
	mux.HandleFunc("POST /n/{path}/tasks", c.node(c.createTask))
	mux.HandleFunc("GET /n/{path}/tasks/{id}", c.node(c.getTask))
	mux.HandleFunc("POST /n/{path}/tasks/{id}/events", c.node(c.postEvent))
	mux.HandleFunc("GET /n/{path}/tasks", c.node(c.listTasks))
	mux.HandleFunc("POST /n/{path}/tasks/{id}/cancel", c.node(c.cancelTask))
	mux.HandleFunc("POST /n/{path}/tasks/{id}/asn", c.node(c.postASN))
	return mux
}

func (c *Control) liveConnections(w http.ResponseWriter, r *http.Request) {
	rows, err := c.tasks.st.LiveClients(time.Now())
	if err != nil {
		c.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// health is the one anonymous endpoint. It tells a client that this really is
// a SniRoute control service and hands over the probe pin, which is public by
// design (anyone who connects to the probe endpoint sees that certificate).
// Nothing secret is exposed, so a client that only has an address can enrol.
// joinPage is the plain page someone sees if they open the registration link
// on the wrong machine.
func (c *Control) joinPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	io.WriteString(w, joinHTML)
}

func (c *Control) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service":          "sniroute-control",
		"api":              1,
		"protocol_version": version.Protocol,
		"probe_pin":        c.probePin,
		"probe_port":       c.probePort(),
		"collector_id":     c.tasks.collectorID,
	})
}

func (c *Control) register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RegToken      string `json:"reg_token"`
		RegKey        string `json:"reg_key"` // accepted under its old name too
		Name          string `json:"name"`
		ProviderLabel string `json:"provider_label"`
	}
	if !decode(w, r, &req) {
		return
	}
	token := req.RegToken
	if token == "" {
		token = req.RegKey
	}
	creds, err := c.reg.Register(token, req.Name, req.ProviderLabel)
	switch {
	case errors.Is(err, auth.ErrUnauthorized):
		writeErr(w, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, auth.ErrInvalidName):
		writeErr(w, http.StatusBadRequest, "invalid name")
	case errors.Is(err, auth.ErrLimit):
		writeErr(w, http.StatusTooManyRequests, "node limit reached")
	case err != nil:
		c.internal(w, err)
	default:
		c.log.Debug("node registered", "node", creds.NodeID, "from", remoteIP(r).String())
		writeJSON(w, http.StatusCreated, map[string]any{
			"node_id": creds.NodeID, "path": creds.Path, "node_key": creds.NodeKey,
			"collector_id": c.tasks.collectorID, "probe_pin": c.probePin, "probe_port": c.probePort(),
		})
	}
}

func (c *Control) newRegToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TTLSeconds int `json:"ttl_seconds"`
	}
	if r.ContentLength != 0 && !decode(w, r, &req) {
		return
	}
	t, token, err := c.reg.NewRegToken(time.Duration(req.TTLSeconds) * time.Second)
	switch {
	case errors.Is(err, auth.ErrLimit):
		writeErr(w, http.StatusTooManyRequests, "too many outstanding registration tokens")
		return
	case err != nil:
		c.internal(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": t.ID, "token": token, "created_at": t.CreatedAt, "expires_at": t.ExpiresAt,
	})
}

func (c *Control) listRegTokens(w http.ResponseWriter, r *http.Request) {
	ts, err := c.reg.RegTokens()
	if err != nil {
		c.internal(w, err)
		return
	}
	out := make([]map[string]any, 0, len(ts))
	for _, t := range ts {
		out = append(out, map[string]any{
			"id": t.ID, "token": c.reg.RegTokenFor(t), "created_at": t.CreatedAt, "expires_at": t.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

func (c *Control) deleteRegToken(w http.ResponseWriter, r *http.Request) {
	if err := c.reg.DeleteRegToken(r.PathValue("id")); err != nil {
		c.internal(w, err)
		return
	}
	c.log.Info("registration token revoked", "id", r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

func (c *Control) createTask(w http.ResponseWriter, r *http.Request, n auth.NodeInfo) {
	var req CreateRequest
	if !decode(w, r, &req) {
		return
	}
	view, issued, err := c.tasks.Create(n.ID, req)
	var bre BadRequestError
	switch {
	case errors.As(err, &bre):
		writeErr(w, http.StatusBadRequest, bre.Error())
	case errors.Is(err, ErrTooMany):
		writeErr(w, http.StatusTooManyRequests, "too many active tasks")
	case err != nil:
		c.internal(w, err)
	default:
		writeJSON(w, http.StatusCreated, map[string]any{"task": view, "attempts": issued, "probe_pin": c.probePin})
	}
}

func (c *Control) getTask(w http.ResponseWriter, r *http.Request, n auth.NodeInfo) {
	snap, _ := strconv.Atoi(r.URL.Query().Get("asn"))
	view, ok, err := c.tasks.GetAt(n.ID, r.PathValue("id"), snap)
	if err != nil {
		c.internal(w, err)
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (c *Control) postEvent(w http.ResponseWriter, r *http.Request, n auth.NodeInfo) {
	var ev ClientEventIn
	if !decode(w, r, &ev) {
		return
	}
	err := c.tasks.RecordClientEvent(n.ID, r.PathValue("id"), ev)
	var bre BadRequestError
	switch {
	case errors.As(err, &bre):
		writeErr(w, http.StatusBadRequest, bre.Error())
	case err != nil:
		c.internal(w, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (c *Control) listTasks(w http.ResponseWriter, r *http.Request, n auth.NodeInfo) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := c.tasks.List(n.ID, limit)
	if err != nil {
		c.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tasks": items})
}

func (c *Control) cancelTask(w http.ResponseWriter, r *http.Request, n auth.NodeInfo) {
	err := c.tasks.Cancel(n.ID, r.PathValue("id"))
	var bre BadRequestError
	switch {
	case errors.As(err, &bre):
		writeErr(w, http.StatusBadRequest, bre.Error())
	case err != nil:
		c.internal(w, err)
	default:
		c.log.Debug("task cancelled", "task", r.PathValue("id"), "node", n.ID)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (c *Control) postASN(w http.ResponseWriter, r *http.Request, n auth.NodeInfo) {
	var in struct {
		Refresh bool `json:"refresh"`
	}
	if r.ContentLength != 0 && !decode(w, r, &in) {
		return
	}
	v, err := c.tasks.EnsureASN(r.Context(), n.ID, r.PathValue("id"), in.Refresh)
	var bre BadRequestError
	switch {
	case errors.As(err, &bre):
		writeErr(w, http.StatusBadRequest, bre.Error())
	case errors.Is(err, ErrASNDisabled):
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
	case errors.Is(err, ErrTooMany):
		writeErr(w, http.StatusTooManyRequests, "snapshots can be refreshed at most every 30 seconds")
	case err != nil:
		c.internal(w, err)
	default:
		writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "asn": v})
	}
}

// internal logs an unexpected error and answers with a generic 500.
func (c *Control) internal(w http.ResponseWriter, err error) {
	c.log.Error("internal error", "err", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

// admin wraps a handler with admin-key authentication.
func (c *Control) admin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !c.reg.CheckAdmin(bearer(r)) {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		h(w, r)
	}
}

// node wraps a handler with node-key authentication for the {path} segment.
func (c *Control) node(h func(http.ResponseWriter, *http.Request, auth.NodeInfo)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n, err := c.reg.Authenticate(r.PathValue("path"), bearer(r), remoteIP(r))
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		h(w, r, n)
	}
}

func bearer(r *http.Request) string {
	const p = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return h[len(p):]
	}
	return ""
}

func remoteIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
		} else {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
		}
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
