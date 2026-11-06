package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nyktios/sniroute/internal/server"
	"github.com/nyktios/sniroute/internal/version"
)

// APIError is a non-2xx answer from the control service.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("control API: %d %s", e.Status, e.Message) }

// ControlClient talks to the control service over HTTPS. With a pin, the
// server certificate must match it exactly (no CA needed); without one the
// system roots are used.
type ControlClient struct {
	base string
	hc   *http.Client
}

// NewControlClient creates a client for baseURL (https://host:port).
func NewControlClient(baseURL, certPin string) (*ControlClient, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(baseURL, "https://") {
		return nil, errors.New("control URL must start with https://")
	}
	cc, err := newControlClient(baseURL, certPin)
	if err != nil {
		return nil, err
	}
	return cc, nil
}

func (c *ControlClient) health(ctx context.Context) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/health", nil)
	if err != nil {
		return nil, err
	}
	return c.hc.Do(req)
}

// Probe reports whether the control service answers and whether its
// certificate matches the pin. It is what the client runs before enrolling so
// a wrong address or a stale pin fails with a readable message instead of a
// confusing registration error.
func (c *ControlClient) Probe(ctx context.Context) error {
	resp, err := c.health(ctx)
	if err != nil {
		return transportError(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("控制接口返回 %d（地址对，但不是 SniRoute 控制服务？）", resp.StatusCode)
	}
	return nil
}

// Discover fetches the observer's public facts so a link that carries only an
// address is enough to enrol: the probe pin comes over the (verified) control
// channel, and "check before trust" still holds because the control
// certificate was already validated (by pin or by the system roots).
func (c *ControlClient) Discover(ctx context.Context) (Health, error) {
	resp, err := c.health(ctx)
	if err != nil {
		return Health{}, transportError(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil {
		return Health{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Health{}, fmt.Errorf("控制接口返回 %d（地址对，但不是 SniRoute 控制服务？）", resp.StatusCode)
	}
	var out Health
	if err := json.Unmarshal(data, &out); err != nil {
		return Health{}, errors.New("控制接口的响应不是有效 JSON（不是 SniRoute 控制服务？）")
	}
	if out.Service != "sniroute-control" {
		return Health{}, fmt.Errorf("这不是 SniRoute 控制服务（service=%q）", out.Service)
	}
	if out.ProtocolVersion != "" && out.ProtocolVersion != version.Protocol {
		return Health{}, errors.New("客户端与观测端通信协议不兼容，请同步更新两端程序")
	}
	return out, nil
}

// Health is the anonymous advertisement of a control service. It carries the
// probe pin, which is public information (the probe endpoint presents that key
// to anyone who connects).
type Health struct {
	Service         string `json:"service"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
	API             int    `json:"api"`
	ProbePin        string `json:"probe_pin"`
	ProbePort       string `json:"probe_port"` // observer's probe listener port, when it is not 443
	Collector       string `json:"collector_id"`
}

// transportError turns certificate failures into the advice the user needs:
// either the address is wrong or the pin is stale.
func transportError(err error) error {
	var uae x509.UnknownAuthorityError
	var hve x509.HostnameError
	var cie x509.CertificateInvalidError
	msg := err.Error()
	switch {
	case strings.Contains(msg, "does not match the pinned fingerprint"):
		return errors.New("控制证书与控制端记录不一致：观测端可能换了证书（重新生成过 control.pem），请向服务端要一个新的注册链接")
	case errors.As(err, &uae), errors.As(err, &hve), errors.As(err, &cie), strings.Contains(msg, "certificate"):
		return fmt.Errorf("控制证书验证失败（%v）。自签名证书需要链接里携带指纹；若观测端换过证书，请重新生成注册链接", err)
	}
	return fmt.Errorf("控制接口连接失败，请检查观测端地址、控制端口、服务状态和网络连通性（此错误不表示域名被阻断）：%w", err)
}

func newControlClient(baseURL, certPin string) (*ControlClient, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if certPin != "" {
		want, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(certPin)))
		if err != nil || len(want) != sha256.Size {
			return nil, errors.New("control pin must be 64 hex characters (SHA-256 of the certificate)")
		}
		cfg.InsecureSkipVerify = true // replaced by the pin check below
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return errors.New("control certificate does not match the pinned fingerprint")
			}
			return nil
		}
	}
	return &ControlClient{base: baseURL, hc: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       cfg,
			Proxy:                 nil, // never use environment proxies
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
		},
	}}, nil
}

func (c *ControlClient) do(ctx context.Context, method, path, bearer string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return transportError(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(data, &e)
		if resp.StatusCode == http.StatusUnauthorized {
			e.Error = "节点密钥已失效或认证失败；离线满 15 分钟后需从观测端获取新的注册链接"
		}
		return &APIError{Status: resp.StatusCode, Message: e.Error}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// RegisterResponse is what registration returns; NodeKey is shown only once.
type RegisterResponse struct {
	NodeID      string `json:"node_id"`
	Path        string `json:"path"`
	NodeKey     string `json:"node_key"`
	CollectorID string `json:"collector_id"`
	ProbePin    string `json:"probe_pin"`
	ProbePort   string `json:"probe_port"` // observer's probe listener port ("" = 443)
}

// Register exchanges a one-time registration token for a node identity.
// token may be the full derived token or the short id the server menu shows.
func (c *ControlClient) Register(ctx context.Context, token, name, label string) (RegisterResponse, error) {
	var out RegisterResponse
	err := c.do(ctx, "POST", "/api/register", "", map[string]string{"reg_token": token, "name": name, "provider_label": label}, &out)
	return out, err
}

// CreateTaskResponse carries the planned attempts and their one-time credentials.
type CreateTaskResponse struct {
	Task     server.TaskView        `json:"task"`
	Attempts []server.IssuedAttempt `json:"attempts"`
	ProbePin string                 `json:"probe_pin"`
}

// CreateTask submits a plan; the answer carries one credential per attempt.
func (c *ControlClient) CreateTask(ctx context.Context, path, key string, req server.CreateRequest) (CreateTaskResponse, error) {
	var out CreateTaskResponse
	err := c.do(ctx, "POST", "/n/"+path+"/tasks", key, req, &out)
	return out, err
}

// GetTask fetches the merged observer + client view of a task.
func (c *ControlClient) GetTask(ctx context.Context, path, key, id string) (server.TaskView, error) {
	var out server.TaskView
	err := c.do(ctx, "GET", "/n/"+path+"/tasks/"+id, key, nil, &out)
	return out, err
}

// PostEvent reports the client's own view of an attempt (idempotent).
func (c *ControlClient) PostEvent(ctx context.Context, path, key, taskID string, ev server.ClientEventIn) error {
	return c.do(ctx, "POST", "/n/"+path+"/tasks/"+taskID+"/events", key, ev, nil)
}

// Cancel tells the server the task was interrupted: it stops accepting new
// probes for it and reads its unrun attempts as cancelled, not failed.
func (c *ControlClient) Cancel(ctx context.Context, path, key, taskID string) error {
	return c.do(ctx, "POST", "/n/"+path+"/tasks/"+taskID+"/cancel", key, nil, nil)
}

// ListTasks returns this node's task history, newest first.
func (c *ControlClient) ListTasks(ctx context.Context, path, key string, limit int) ([]server.TaskListItem, error) {
	var out struct {
		Tasks []server.TaskListItem `json:"tasks"`
	}
	err := c.do(ctx, "GET", "/n/"+path+"/tasks?limit="+strconv.Itoa(limit), key, nil, &out)
	return out.Tasks, err
}

// ASN asks the observer to look up the egress networks of a task's observed
// IPs (the lookup runs there, so this machine's network is irrelevant). With
// refresh a NEW snapshot is created; older ones are never altered. enabled is
// false when the observer has lookups switched off; the view is nil when
// there was nothing to look up.
func (c *ControlClient) ASN(ctx context.Context, path, key, taskID string, refresh bool) (view *server.ASNView, enabled bool, err error) {
	var out struct {
		Enabled bool            `json:"enabled"`
		ASN     *server.ASNView `json:"asn"`
	}
	err = c.do(ctx, "POST", "/n/"+path+"/tasks/"+taskID+"/asn", key, map[string]bool{"refresh": refresh}, &out)
	return out.ASN, out.Enabled, err
}

// Heartbeat keeps an active client identity alive without extending a task.
func (c *ControlClient) Heartbeat(ctx context.Context, path, key string) error {
	return c.do(ctx, "POST", "/n/"+path+"/heartbeat", key, nil, nil)
}
