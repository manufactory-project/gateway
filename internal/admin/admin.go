// Package admin implements gatewayd's minimal Unix-domain-socket (0660) JSON Admin API
// and its typed client for gwctl (NOW.md:67).
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/metrics"
	"github.com/manufactory-project/gateway/internal/proxy"
)

// StatusResponse is returned by GET /v1/status.
type StatusResponse struct {
	ConfigHash       string    `json:"config_hash"`
	LoadedAt         time.Time `json:"loaded_at"`
	ActiveFlows      int       `json:"active_flows"`
	ActiveGrants     int       `json:"active_grants"`
	AuditHealthy     bool      `json:"audit_healthy"`
	AuditWriteErrors uint64    `json:"audit_write_errors"`
}

// ReloadResponse is returned by POST /v1/reload.
type ReloadResponse struct {
	ConfigHash  string   `json:"config_hash"`
	WipedGrants []string `json:"wiped_grants"`
}

// RevokeRequest is accepted by POST /v1/revoke.
type RevokeRequest struct {
	FlowID    string `json:"flow_id,omitempty"`
	GrantID   string `json:"grant_id,omitempty"`
	Principal string `json:"principal,omitempty"`
	Host      string `json:"host,omitempty"`
}

// RevokeResponse is returned by POST /v1/revoke.
type RevokeResponse struct {
	RevokedFlows int  `json:"revoked_flows"`
	RevokedGrant bool `json:"revoked_grant,omitempty"`
}

// GrantRequest is accepted by POST /v1/grants.
type GrantRequest struct {
	Principal string   `json:"principal"`
	Host      string   `json:"host"`
	Port      uint16   `json:"port,omitempty"`
	Methods   []string `json:"methods,omitempty"`
	Paths     []string `json:"paths,omitempty"`
	TTL       string   `json:"ttl"`
}

// Options configures the Unix-socket Admin Server.
type Options struct {
	SocketPath  string
	SocketGroup string
	Store       *config.Store
	Flows       *proxy.FlowRegistry
	Audit       *audit.Writer
	Metrics     *metrics.Collector
}

// Server serves the Admin API strictly over a local Unix domain socket (mode 0660).
type Server struct {
	socketPath  string
	socketGroup string
	store       *config.Store
	flows       *proxy.FlowRegistry
	audit       *audit.Writer
	metrics     *metrics.Collector

	ln  net.Listener
	srv *http.Server
	wg  sync.WaitGroup
}

// NewServer constructs an Admin API Server.
func NewServer(opts Options) (*Server, error) {
	if opts.SocketPath == "" {
		return nil, errors.New("admin: socket path is required")
	}
	if opts.Store == nil || opts.Flows == nil || opts.Audit == nil {
		return nil, errors.New("admin: store, flows, and audit are required")
	}
	return &Server{
		socketPath:  opts.SocketPath,
		socketGroup: opts.SocketGroup,
		store:       opts.Store,
		flows:       opts.Flows,
		audit:       opts.Audit,
		metrics:     opts.Metrics,
	}, nil
}

// Start binds the Unix domain socket with permissions 0660 and serves requests.
func (s *Server) Start() error {
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0o750); err != nil {
		return fmt.Errorf("admin: mkdir socket dir: %w", err)
	}
	if err := os.Remove(s.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("admin: remove stale socket %s: %w", s.socketPath, err)
	}

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("admin: listen unix %s: %w", s.socketPath, err)
	}
	if err := os.Chmod(s.socketPath, 0o660); err != nil {
		closeErr := ln.Close()
		return errors.Join(fmt.Errorf("admin: chmod 0660 %s: %w", s.socketPath, err), closeErr)
	}
	if s.socketGroup != "" {
		grp, err := user.LookupGroup(s.socketGroup)
		if err != nil {
			closeErr := ln.Close()
			return errors.Join(fmt.Errorf("admin: lookup group %q: %w", s.socketGroup, err), closeErr)
		}
		gid, err := strconv.Atoi(grp.Gid)
		if err != nil {
			closeErr := ln.Close()
			return errors.Join(fmt.Errorf("admin: parse gid %q: %w", grp.Gid, err), closeErr)
		}
		if err := os.Chown(s.socketPath, -1, gid); err != nil {
			closeErr := ln.Close()
			return errors.Join(fmt.Errorf("admin: chown socket group %q: %w", s.socketGroup, err), closeErr)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	mux.HandleFunc("POST /v1/reload", s.handleReload)
	mux.HandleFunc("GET /v1/flows", s.handleFlows)
	mux.HandleFunc("POST /v1/revoke", s.handleRevoke)
	mux.HandleFunc("GET /v1/grants", s.handleListGrants)
	mux.HandleFunc("POST /v1/grants", s.handleCreateGrant)
	mux.HandleFunc("DELETE /v1/grants/{id}", s.handleDeleteGrant)
	mux.HandleFunc("GET /v1/audit", s.handleAudit)

	s.ln = ln
	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return
		}
	}()
	return nil
}

// Shutdown gracefully stops the Unix socket server, waits for goroutines, and removes the socket file.
func (s *Server) Shutdown(ctx context.Context) error {
	var errs error
	if s.srv != nil {
		if err := s.srv.Shutdown(ctx); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	s.wg.Wait()
	if err := os.Remove(s.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = errors.Join(errs, err)
	}
	return errs
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	snap := s.store.Current()
	writeJSON(w, http.StatusOK, StatusResponse{
		ConfigHash:       snap.Hash,
		LoadedAt:         snap.LoadedAt,
		ActiveFlows:      s.flows.Count(),
		ActiveGrants:     len(s.store.ActiveGrants()),
		AuditHealthy:     s.audit.Healthy(),
		AuditWriteErrors: s.audit.WriteErrors(),
	})
}

func (s *Server) handleReload(w http.ResponseWriter, _ *http.Request) {
	snap, wiped, err := s.store.Reload()
	if err != nil {
		if s.metrics != nil {
			s.metrics.ObserveReload(false)
		}
		if aErr := s.audit.WriteSync(audit.Event{
			Kind:   audit.KindLifecycle,
			Reason: "reload-failed",
			Error:  err.Error(),
		}); aErr != nil {
			writeError(w, http.StatusServiceUnavailable, "audit sink unavailable")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.metrics != nil {
		s.metrics.ObserveReload(true)
	}
	if aErr := s.audit.WriteSync(audit.Event{
		Kind:       audit.KindLifecycle,
		Reason:     "reload",
		ConfigHash: snap.Hash,
	}); aErr != nil {
		writeError(w, http.StatusServiceUnavailable, "audit sink unavailable")
		return
	}
	writeJSON(w, http.StatusOK, ReloadResponse{
		ConfigHash:  snap.Hash,
		WipedGrants: wiped,
	})
}

func (s *Server) handleFlows(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.flows.List())
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req RevokeRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var (
		revokedFlows int
		revokedGrant bool
		reason       string
	)
	switch {
	case req.FlowID != "":
		revokedFlows = s.flows.RevokeByID(req.FlowID)
		reason = "revoke-flow"
	case req.GrantID != "":
		revokedGrant = s.store.RevokeGrant(req.GrantID)
		revokedFlows = s.flows.RevokeByGrant(req.GrantID)
		reason = "revoke-grant"
	case req.Principal != "":
		revokedFlows = s.flows.RevokeByPrincipal(req.Principal, req.Host)
		reason = "revoke-principal"
	default:
		writeError(w, http.StatusBadRequest, "must specify flow_id, grant_id, or principal")
		return
	}

	if err := s.audit.WriteSync(audit.Event{
		Kind:      audit.KindRevoke,
		Principal: req.Principal,
		Host:      req.Host,
		FlowID:    req.FlowID,
		GrantID:   req.GrantID,
		Reason:    reason,
	}); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit sink unavailable")
		return
	}

	writeJSON(w, http.StatusOK, RevokeResponse{
		RevokedFlows: revokedFlows,
		RevokedGrant: revokedGrant,
	})
}

func (s *Server) handleListGrants(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.store.ActiveGrants())
}

func (s *Server) handleCreateGrant(w http.ResponseWriter, r *http.Request) {
	var req GrantRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ttl, err := time.ParseDuration(req.TTL)
	if err != nil || ttl <= 0 {
		writeError(w, http.StatusBadRequest, "invalid ttl duration")
		return
	}
	g, err := s.store.AddGrant(req.Principal, req.Host, req.Port, req.Methods, req.Paths, ttl)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.audit.WriteSync(audit.Event{
		Kind:      audit.KindGrant,
		Principal: g.Principal,
		Host:      g.Host,
		Port:      int(g.Port),
		GrantID:   g.ID,
		Effect:    audit.EffectAllow,
		Reason:    "grant-created",
	}); err != nil {
		s.store.RevokeGrant(g.ID)
		writeError(w, http.StatusServiceUnavailable, "audit sink unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, g)
}

func (s *Server) handleDeleteGrant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing grant id")
		return
	}
	existed := s.store.RevokeGrant(id)
	revokedFlows := s.flows.RevokeByGrant(id)
	if err := s.audit.WriteSync(audit.Event{
		Kind:    audit.KindRevoke,
		GrantID: id,
		Reason:  "grant-deleted",
	}); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit sink unavailable")
		return
	}
	writeJSON(w, http.StatusOK, RevokeResponse{
		RevokedFlows: revokedFlows,
		RevokedGrant: existed,
	})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	opts := audit.QueryOptions{
		Principal: q.Get("principal"),
		Host:      q.Get("host"),
		Effect:    audit.Effect(q.Get("effect")),
	}
	if tailStr := q.Get("tail"); tailStr != "" {
		n, err := strconv.Atoi(tailStr)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "invalid tail parameter")
			return
		}
		opts.Tail = n
	}
	if sinceStr := q.Get("since"); sinceStr != "" {
		if dur, err := time.ParseDuration(sinceStr); err == nil {
			opts.Since = time.Now().UTC().Add(-dur)
		} else if ts, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			opts.Since = ts.UTC()
		} else {
			writeError(w, http.StatusBadRequest, "invalid since parameter")
			return
		}
	}
	follow := q.Get("follow") == "1" || strings.EqualFold(q.Get("follow"), "true")

	events, err := audit.Query(s.audit.Dir(), opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	enc := json.NewEncoder(w)

	var lastTime time.Time
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return
		}
		if ev.Time.After(lastTime) {
			lastTime = ev.Time
		}
	}
	if err := rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return
	}
	if !follow {
		return
	}

	seenCount := len(events)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			allOpts := opts
			allOpts.Tail = 0
			all, err := audit.Query(s.audit.Dir(), allOpts)
			if err != nil {
				return
			}
			if len(all) > seenCount {
				for _, ev := range all[seenCount:] {
					if err := enc.Encode(ev); err != nil {
						return
					}
				}
				seenCount = len(all)
				if err := rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
					return
				}
			}
		}
	}
}

func decodeStrictJSON(body io.Reader, dst any) error {
	dec := json.NewDecoder(io.LimitReader(body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// Client talks to gatewayd's Admin API over its local Unix domain socket.
type Client struct {
	httpClient *http.Client
	transport  *http.Transport
}

// NewClient creates a Unix-socket Admin API Client.
func NewClient(socketPath string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{
		httpClient: &http.Client{Transport: tr},
		transport:  tr,
	}
}

// Close closes idle Unix socket connections held by Client.
func (c *Client) Close() {
	c.transport.CloseIdleConnections()
}

// Status calls GET /v1/status.
func (c *Client) Status(ctx context.Context) (StatusResponse, error) {
	var out StatusResponse
	err := c.doJSON(ctx, http.MethodGet, "/v1/status", nil, &out)
	return out, err
}

// Reload calls POST /v1/reload.
func (c *Client) Reload(ctx context.Context) (ReloadResponse, error) {
	var out ReloadResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/reload", nil, &out)
	return out, err
}

// Flows calls GET /v1/flows.
func (c *Client) Flows(ctx context.Context) ([]proxy.FlowInfo, error) {
	var out []proxy.FlowInfo
	err := c.doJSON(ctx, http.MethodGet, "/v1/flows", nil, &out)
	return out, err
}

// Revoke calls POST /v1/revoke.
func (c *Client) Revoke(ctx context.Context, req RevokeRequest) (RevokeResponse, error) {
	var out RevokeResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/revoke", req, &out)
	return out, err
}

// Grants calls GET /v1/grants.
func (c *Client) Grants(ctx context.Context) ([]config.Grant, error) {
	var out []config.Grant
	err := c.doJSON(ctx, http.MethodGet, "/v1/grants", nil, &out)
	return out, err
}

// CreateGrant calls POST /v1/grants.
func (c *Client) CreateGrant(ctx context.Context, req GrantRequest) (config.Grant, error) {
	var out config.Grant
	err := c.doJSON(ctx, http.MethodPost, "/v1/grants", req, &out)
	return out, err
}

// DeleteGrant calls DELETE /v1/grants/{id}.
func (c *Client) DeleteGrant(ctx context.Context, id string) (RevokeResponse, error) {
	var out RevokeResponse
	err := c.doJSON(ctx, http.MethodDelete, "/v1/grants/"+url.PathEscape(id), nil, &out)
	return out, err
}

// AuditParams selects audit records from GET /v1/audit.
type AuditParams struct {
	Tail      int
	Follow    bool
	Principal string
	Host      string
	Effect    string
	Since     string
}

// StreamAudit calls GET /v1/audit and invokes fn for each received audit.Event.
func (c *Client) StreamAudit(ctx context.Context, params AuditParams, fn func(audit.Event) error) error {
	q := url.Values{}
	if params.Tail > 0 {
		q.Set("tail", strconv.Itoa(params.Tail))
	}
	if params.Follow {
		q.Set("follow", "1")
	}
	if params.Principal != "" {
		q.Set("principal", params.Principal)
	}
	if params.Host != "" {
		q.Set("host", params.Host)
	}
	if params.Effect != "" {
		q.Set("effect", params.Effect)
	}
	if params.Since != "" {
		q.Set("since", params.Since)
	}

	u := "http://unix/v1/audit"
	if enc := q.Encode(); enc != "" {
		u += "?" + enc
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			return
		}
	}()
	if resp.StatusCode >= 400 {
		msg, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("admin: GET /v1/audit status %d (read err: %w)", resp.StatusCode, readErr)
		}
		return fmt.Errorf("admin: GET /v1/audit status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var ev audit.Event
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		if err := fn(ev); err != nil {
			return err
		}
	}
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var bodyReader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = strings.NewReader(string(raw))
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, bodyReader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			return
		}
	}()
	if resp.StatusCode >= 400 {
		rawErr, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("admin: %s %s status %d (read err: %w)", method, path, resp.StatusCode, readErr)
		}
		return fmt.Errorf("admin: %s %s status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(rawErr)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
