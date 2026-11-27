// Package admin implements gateway's minimal Unix-domain-socket (0660) JSON Admin API
// and its typed client for gateway.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/metrics"
)

// FlowInfo describes one active in-flight HTTP request, H2 stream, SSE stream, or WebSocket flow.
type FlowInfo struct {
	ID        string    `json:"id"`
	Principal string    `json:"principal"`
	Link      string    `json:"link"`
	Host      string    `json:"host"`
	Port      uint16    `json:"port"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	RuleID    string    `json:"rule_id,omitempty"`
	GrantID   string    `json:"grant_id,omitempty"`
	Protocol  string    `json:"protocol"`
	StartedAt time.Time `json:"started_at"`
}

// FlowManager exposes the minimal active-flow query and revocation operations needed by Admin.
type FlowManager interface {
	ListFlows() []FlowInfo
	CountFlows() int
	RevokeByID(flowID string) int
	RevokeByGrant(grantID string) int
	RevokeByPrincipal(principal, host string) int
}

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
	Principal      string   `json:"principal"`
	Host           string   `json:"host"`
	Port           uint16   `json:"port,omitempty"`
	Methods        []string `json:"methods,omitempty"`
	Paths          []string `json:"paths,omitempty"`
	TTL            string   `json:"ttl"`
	AllowWebSocket bool     `json:"allow_websocket,omitempty"`
}

// Options configures the Unix-socket Admin Server.
type Options struct {
	SocketPath  string
	SocketGroup string
	Store       *config.Store
	Flows       FlowManager
	Audit       *audit.Writer
	Metrics     *metrics.Collector
}

// Server serves the Admin API strictly over a local Unix domain socket (mode 0660).
type Server struct {
	socketPath  string
	socketGroup string
	store       *config.Store
	flows       FlowManager
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
		ActiveFlows:      s.flows.CountFlows(),
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
	writeJSON(w, http.StatusOK, s.flows.ListFlows())
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req RevokeRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	selectors := 0
	if req.FlowID != "" {
		selectors++
	}
	if req.GrantID != "" {
		selectors++
	}
	if req.Principal != "" {
		selectors++
	}
	if selectors == 0 {
		writeError(w, http.StatusBadRequest, "must specify flow_id, grant_id, or principal")
		return
	}
	if selectors > 1 {
		writeError(w, http.StatusBadRequest, "must specify only one of flow_id, grant_id, or principal")
		return
	}
	if req.Host != "" && req.Principal == "" {
		writeError(w, http.StatusBadRequest, "host filter requires principal")
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
	g, err := s.store.AddGrant(req.Principal, req.Host, req.Port, req.Methods, req.Paths, ttl, req.AllowWebSocket)
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
		TTL:       ttl.String(),
		ExpiresAt: g.ExpiresAt.UTC().Format(time.RFC3339),
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
