// SPDX-License-Identifier: AGPL-3.0-only

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
	SocketPath   string
	SocketGroup  string
	Store        *config.Store
	Flows        FlowManager
	Audit        *audit.Writer
	Metrics      *metrics.Collector
	OnServeError func(error)
	// MaxGrantTTL caps a grant's lifetime and MaxGrants the number of live grants;
	// zero selects DefaultMaxGrantTTL and DefaultMaxGrants.
	MaxGrantTTL time.Duration
	MaxGrants   int
}

// Defaults for Options.MaxGrantTTL and Options.MaxGrants.
const (
	DefaultMaxGrantTTL = time.Hour
	DefaultMaxGrants   = 32
)

var errAuditUnavailable = errors.New("audit sink unavailable")

// Server serves the Admin API strictly over a local Unix domain socket (mode 0660).
type Server struct {
	socketPath   string
	socketGroup  string
	store        *config.Store
	flows        FlowManager
	audit        *audit.Writer
	metrics      *metrics.Collector
	onServeError func(error)
	maxGrantTTL  time.Duration
	maxGrants    int

	grantMu sync.Mutex // serializes grant creation so the live-grant cap holds

	ln  net.Listener
	srv *http.Server
	wg  sync.WaitGroup
}

// NewServer constructs an Admin API Server.
func NewServer(opts Options) (*Server, error) {
	if opts.SocketPath == "" {
		return nil, errors.New("admin: socket path is required")
	}
	if opts.Store == nil || opts.Flows == nil || opts.Audit == nil || opts.OnServeError == nil {
		return nil, errors.New("admin: store, flows, audit, and onServeError are required")
	}
	if opts.MaxGrantTTL <= 0 {
		opts.MaxGrantTTL = DefaultMaxGrantTTL
	}
	if opts.MaxGrants <= 0 {
		opts.MaxGrants = DefaultMaxGrants
	}
	return &Server{
		maxGrantTTL:  opts.MaxGrantTTL,
		maxGrants:    opts.MaxGrants,
		socketPath:   opts.SocketPath,
		socketGroup:  opts.SocketGroup,
		store:        opts.Store,
		flows:        opts.Flows,
		audit:        opts.Audit,
		metrics:      opts.Metrics,
		onServeError: opts.OnServeError,
	}, nil
}

// Start binds the Unix domain socket with permissions 0660 and serves requests.
func (s *Server) Start() error {
	ln, err := s.listen()
	if err != nil {
		return err
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
		Handler:           s.requirePeer(mux),
		ConnContext:       peerConnContext,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		serveUntilClosed(s.srv, ln, func(err error) {
			if s.onServeError != nil {
				s.onServeError(fmt.Errorf("admin: %w", err))
			}
		})
	}()
	return nil
}

// listen binds the socket inside a private (0700) directory, sets its final mode
// and group there, and only then renames it into place, so the socket is never
// reachable with a mode wider than 0660 or the wrong group.
func (s *Server) listen() (net.Listener, error) {
	dir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("admin: mkdir socket dir: %w", err)
	}
	staging, err := os.MkdirTemp(dir, ".admin-")
	if err != nil {
		return nil, fmt.Errorf("admin: staging dir: %w", err)
	}
	ln, err := s.listenIn(staging)
	rmErr := os.RemoveAll(staging)
	if err != nil {
		return nil, errors.Join(err, rmErr)
	}
	if rmErr != nil {
		return nil, errors.Join(fmt.Errorf("admin: remove staging dir: %w", rmErr), ln.Close())
	}
	return ln, nil
}

func (s *Server) listenIn(staging string) (net.Listener, error) {
	staged := filepath.Join(staging, "sock")
	ln, err := net.Listen("unix", staged)
	if err != nil {
		return nil, fmt.Errorf("admin: listen unix %s: %w", s.socketPath, err)
	}
	fail := func(err error) (net.Listener, error) { return nil, errors.Join(err, ln.Close()) }
	if err := os.Chmod(staged, 0o660); err != nil {
		return fail(fmt.Errorf("admin: chmod 0660 %s: %w", s.socketPath, err))
	}
	if s.socketGroup != "" {
		grp, err := user.LookupGroup(s.socketGroup)
		if err != nil {
			return fail(fmt.Errorf("admin: lookup group %q: %w", s.socketGroup, err))
		}
		gid, err := strconv.Atoi(grp.Gid)
		if err != nil {
			return fail(fmt.Errorf("admin: parse gid %q: %w", grp.Gid, err))
		}
		if err := os.Chown(staged, -1, gid); err != nil {
			return fail(fmt.Errorf("admin: chown socket group %q: %w", s.socketGroup, err))
		}
	}
	if err := os.Rename(staged, s.socketPath); err != nil {
		return fail(fmt.Errorf("admin: install socket %s: %w", s.socketPath, err))
	}
	return ln, nil
}

// requirePeer refuses any request whose peer credentials could not be read, so
// every served request can be attributed.
func (s *Server) requirePeer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := r.Context().Value(peerKey{}).(peer); !ok || p.err != nil {
			writeError(w, http.StatusForbidden, "peer credentials unavailable")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// record writes ev to the audit log stamped with the caller's uid and pid.
func (s *Server) record(r *http.Request, ev audit.Event) error {
	p, ok := r.Context().Value(peerKey{}).(peer)
	if !ok {
		return errors.New("admin: request has no peer credentials")
	}
	ev.PeerUID, ev.PeerPID = &p.uid, &p.pid
	return s.audit.WriteSync(ev)
}

// revokeGrant is the only way a grant is revoked: the grant and every flow
// running under it go together.
func (s *Server) revokeGrant(id string) (g config.Grant, existed bool, revokedFlows int) {
	g, existed = s.store.RevokeGrant(id)
	return g, existed, s.flows.RevokeByGrant(id)
}

func serveUntilClosed(srv *http.Server, ln net.Listener, onErr func(error)) {
	// Shutdown closes the listener and causes Serve to return http.ErrServerClosed.
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		if onErr != nil {
			onErr(err)
		}
	}
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

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	snap, wiped, revokedFlows, err := s.store.Reload()
	if err != nil {
		if s.metrics != nil {
			s.metrics.ObserveReload(false)
		}
		if aErr := s.record(r, audit.Event{
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
	if aErr := s.record(r, audit.Event{
		Kind:         audit.KindLifecycle,
		Reason:       "reload",
		ConfigHash:   snap.Hash,
		RevokedFlows: &revokedFlows,
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
		principal    = req.Principal
		host         = req.Host
		port         int
	)
	switch {
	case req.FlowID != "":
		revokedFlows = s.flows.RevokeByID(req.FlowID)
		reason = "revoke-flow"
	case req.GrantID != "":
		var deletedGrant config.Grant
		deletedGrant, revokedGrant, revokedFlows = s.revokeGrant(req.GrantID)
		principal = deletedGrant.Principal
		host = deletedGrant.Host
		port = int(deletedGrant.Port)
		reason = "revoke-grant"
	case req.Principal != "":
		revokedFlows = s.flows.RevokeByPrincipal(req.Principal, req.Host)
		reason = "revoke-principal"
	}

	if err := s.record(r, audit.Event{
		Kind:         audit.KindRevoke,
		Principal:    principal,
		Host:         host,
		Port:         port,
		FlowID:       req.FlowID,
		GrantID:      req.GrantID,
		RevokedFlows: &revokedFlows,
		Reason:       reason,
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
	refuse := func(status int, reason string) {
		if aErr := s.record(r, audit.Event{
			Kind: audit.KindGrant, Principal: req.Principal, Host: req.Host, Port: int(req.Port),
			TTL: req.TTL, Effect: audit.EffectDeny, Reason: reason,
		}); aErr != nil {
			status, reason = http.StatusServiceUnavailable, errAuditUnavailable.Error()
		}
		writeError(w, status, reason)
	}
	if ttl > s.maxGrantTTL {
		refuse(http.StatusBadRequest, "grant-ttl-exceeds-max")
		return
	}
	s.grantMu.Lock()
	defer s.grantMu.Unlock()
	if len(s.store.ActiveGrants()) >= s.maxGrants {
		refuse(http.StatusTooManyRequests, "grant-limit-reached")
		return
	}
	// The grant-created record is written before the grant exists, so a grant is
	// never live without being audited and there is nothing to roll back.
	g, err := s.store.AddGrant(req.Principal, req.Host, req.Port, req.Methods, req.Paths, ttl, req.AllowWebSocket, func(g config.Grant) error {
		allowWS := g.AllowWebSocket
		if err := s.record(r, audit.Event{
			Kind:           audit.KindGrant,
			Principal:      g.Principal,
			Host:           g.Host,
			Port:           int(g.Port),
			Methods:        g.Methods,
			Paths:          g.Paths,
			AllowWebSocket: &allowWS,
			GrantID:        g.ID,
			TTL:            ttl.String(),
			ExpiresAt:      g.ExpiresAt.UTC().Format(time.RFC3339),
			Effect:         audit.EffectAllow,
			Reason:         "grant-created",
		}); err != nil {
			return errors.Join(errAuditUnavailable, err)
		}
		return nil
	})
	switch {
	case errors.Is(err, errAuditUnavailable):
		writeError(w, http.StatusServiceUnavailable, errAuditUnavailable.Error())
	case err != nil:
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeJSON(w, http.StatusCreated, g)
	}
}

func (s *Server) handleDeleteGrant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing grant id")
		return
	}
	deletedGrant, existed, revokedFlows := s.revokeGrant(id)
	if err := s.record(r, audit.Event{
		Kind:         audit.KindRevoke,
		Principal:    deletedGrant.Principal,
		Host:         deletedGrant.Host,
		Port:         int(deletedGrant.Port),
		GrantID:      id,
		RevokedFlows: &revokedFlows,
		Reason:       "grant-deleted",
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
