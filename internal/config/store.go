package config

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Snapshot is an immutable loaded configuration with its hash and load time.
type Snapshot struct {
	Config   *Config
	Hash     string
	LoadedAt time.Time
}

// Grant is an ephemeral in-memory allow rule with a TTL.
// Grants are never persisted to disk and are wiped on every SIGHUP/reload.
type Grant struct {
	ID             string    `json:"id"`
	Principal      string    `json:"principal"`
	Host           string    `json:"host"`
	Port           uint16    `json:"port"`
	Methods        []string  `json:"methods,omitempty"`
	Paths          []string  `json:"paths,omitempty"`
	AllowWebSocket bool      `json:"allow_websocket,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// Store holds the active configuration Snapshot and ephemeral in-memory TTL grants.
// Reload swaps the snapshot atomically, wipes all TTL grants, and invokes reload callbacks.
type Store struct {
	path string
	now  func() time.Time

	snap atomic.Pointer[Snapshot]

	reloadMu  sync.Mutex
	mu        sync.RWMutex
	gen       uint64
	grantGen  uint64
	grants    map[string]Grant
	onReload  []func(prev, next *Snapshot, wipedGrantIDs []string) int
	onExpired []func(grant Grant)
}

// NewStore loads path once and returns a Store holding the initial snapshot.
func NewStore(path string) (*Store, error) {
	return NewStoreWithClock(path, time.Now)
}

// NewStoreWithClock is like NewStore with an injectable clock.
func NewStoreWithClock(path string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	cfg, hash, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	s := &Store{
		path:   path,
		now:    now,
		grants: make(map[string]Grant),
	}
	s.snap.Store(&Snapshot{
		Config:   cfg,
		Hash:     hash,
		LoadedAt: now().UTC(),
	})
	return s, nil
}

// Current returns the currently active configuration Snapshot.
func (s *Store) Current() *Snapshot {
	return s.snap.Load()
}

// StateToken returns the current config snapshot pointer and grant-set generation
// so callers can detect any config reload or grant mutation since an earlier check.
func (s *Store) StateToken() (*Snapshot, uint64) {
	s.mu.RLock()
	snap := s.snap.Load()
	gg := s.grantGen
	s.mu.RUnlock()
	return snap, gg
}

// OnReload registers a callback invoked after every successful reload,
// returning the number of active flows torn down by that callback.
func (s *Store) OnReload(fn func(prev, next *Snapshot, wipedGrantIDs []string) int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onReload = append(s.onReload, fn)
}

// OnGrantExpired registers a callback invoked when a grant is pruned on TTL expiry.
// Multiple callbacks may be registered (e.g. teardown and audit wiring).
func (s *Store) OnGrantExpired(fn func(grant Grant)) {
	if fn == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onExpired = append(s.onExpired, fn)
}

// Reload re-reads and validates the YAML file from disk. If validation fails or
// any restart-only section changed (links, principals, fake_cidr, ca, audit,
// admin, metrics, dataplane, http.max_header_bytes), the previous snapshot and
// grants remain intact and an error is returned. On success, the snapshot is
// atomically replaced and all in-memory TTL grants are wiped before reload
// callbacks run.
func (s *Store) Reload() (*Snapshot, []string, int, error) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	cfg, hash, err := LoadFile(s.path)
	if err != nil {
		return nil, nil, 0, err
	}
	next := &Snapshot{
		Config:   cfg,
		Hash:     hash,
		LoadedAt: s.now().UTC(),
	}

	s.mu.Lock()
	cur := s.snap.Load()
	if cur != nil && cur.Config != nil {
		if diffErr := checkReloadImmutable(cur.Config, cfg); diffErr != nil {
			s.mu.Unlock()
			return nil, nil, 0, diffErr
		}
	}
	prev := s.snap.Swap(next)
	s.gen++
	s.grantGen++
	wiped := make([]string, 0, len(s.grants))
	for id := range s.grants {
		wiped = append(wiped, id)
	}
	s.grants = make(map[string]Grant)
	callbacks := slices.Clone(s.onReload)
	s.mu.Unlock()

	revokedFlows := 0
	for _, fn := range callbacks {
		revokedFlows += fn(prev, next, wiped)
	}
	return next, wiped, revokedFlows, nil
}

func checkReloadImmutable(prev, next *Config) error {
	if prev.CA != next.CA {
		return errors.New("reload refused: ca configuration changed (restart required)")
	}
	if prev.Audit != next.Audit {
		return errors.New("reload refused: audit configuration changed (restart required)")
	}
	if prev.Admin != next.Admin {
		return errors.New("reload refused: admin configuration changed (restart required)")
	}
	if prev.Metrics != next.Metrics {
		return errors.New("reload refused: metrics configuration changed (restart required)")
	}
	if prev.FakePrefix != next.FakePrefix {
		return errors.New("reload refused: dns.fake_cidr changed (restart required)")
	}
	if prev.Dataplane.ReadyFile != next.Dataplane.ReadyFile ||
		prev.Dataplane.StateFile != next.Dataplane.StateFile ||
		prev.Dataplane.DHCP != next.Dataplane.DHCP {
		return errors.New("reload refused: dataplane configuration changed (restart required)")
	}
	if prev.HTTP.MaxHeaderBytes != next.HTTP.MaxHeaderBytes {
		return errors.New("reload refused: http.max_header_bytes changed (restart required)")
	}
	if prev.HTTP.MaxConnsPerLink != next.HTTP.MaxConnsPerLink {
		return errors.New("reload refused: http.max_conns_per_link changed (restart required)")
	}
	if prev.HTTP.ParsedUpstreamResponseHeaderTimeout != next.HTTP.ParsedUpstreamResponseHeaderTimeout {
		return errors.New("reload refused: http.upstream_response_header_timeout changed (restart required)")
	}
	if !slices.Equal(prev.Links, next.Links) {
		return errors.New("reload refused: links or principals changed (restart required)")
	}
	return nil
}

// WatchSIGHUP listens for syscall.SIGHUP until ctx is cancelled, calling Reload
// on each signal and invoking onResult (if non-nil) with the outcome.
// It returns only after unregistering its signal channel so callers can join cleanly.
func (s *Store) WatchSIGHUP(ctx context.Context, onResult func(*Snapshot, []string, int, error)) {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			snap, wiped, revokedFlows, err := s.Reload()
			if onResult != nil {
				onResult(snap, wiped, revokedFlows, err)
			}
		}
	}
}

// AddGrant validates and inserts an ephemeral in-memory TTL grant.
// Grants accept exact hostnames only (no wildcards), ports 80 or 443, and positive TTLs.
func (s *Store) AddGrant(principal, rawHost string, port uint16, methods, paths []string, ttl time.Duration, allowWebSocket bool) (Grant, error) {
	if ttl <= 0 {
		return Grant{}, errors.New("grant: ttl must be > 0")
	}
	if port == 0 {
		port = 443
	}
	if port != 80 && port != 443 {
		return Grant{}, fmt.Errorf("grant: port %d is forbidden (only 80 and 443 are permitted)", port)
	}
	host, err := NormalizeExactHost(rawHost)
	if err != nil {
		return Grant{}, fmt.Errorf("grant: host: %w", err)
	}

	normMethods := make([]string, len(methods))
	for i, m := range methods {
		if !isValidHTTPMethod(m) {
			return Grant{}, fmt.Errorf("grant: invalid method %q", m)
		}
		normMethods[i] = strings.ToUpper(m)
	}
	normPaths := make([]string, len(paths))
	for i, p := range paths {
		if err := ValidatePathPattern(p); err != nil {
			return Grant{}, fmt.Errorf("grant: path %q: %w", p, err)
		}
		normPaths[i] = p
	}

	s.mu.RLock()
	startGen := s.gen
	s.mu.RUnlock()

	id, err := randomGrantID()
	if err != nil {
		return Grant{}, fmt.Errorf("grant: generate id: %w", err)
	}

	s.mu.Lock()
	if s.gen != startGen {
		s.mu.Unlock()
		return Grant{}, errors.New("grant: concurrent reload wiped grants; retry")
	}
	snap := s.snap.Load()
	principalKnown := false
	for _, l := range snap.Config.Links {
		if l.Principal == principal {
			principalKnown = true
			break
		}
	}
	if !principalKnown {
		s.mu.Unlock()
		return Grant{}, fmt.Errorf("grant: principal %q does not match any declared link", principal)
	}
	if allowWebSocket {
		for _, r := range snap.Config.Rules {
			if r.Principal != principal {
				continue
			}
			for _, b := range r.Bindings {
				if b.Host == host {
					s.mu.Unlock()
					return Grant{}, fmt.Errorf("grant: allow_websocket is forbidden on host %q with a secret binding", host)
				}
			}
		}
	}
	now := s.now().UTC()
	g := Grant{
		ID:             id,
		Principal:      principal,
		Host:           host,
		Port:           port,
		Methods:        normMethods,
		Paths:          normPaths,
		AllowWebSocket: allowWebSocket,
		CreatedAt:      now,
		ExpiresAt:      now.Add(ttl),
	}
	s.grants[g.ID] = g
	s.grantGen++
	s.mu.Unlock()
	return g, nil
}

// RevokeGrant removes a grant by ID and returns the removed grant and whether it existed.
func (s *Store) RevokeGrant(id string) (Grant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return Grant{}, false
	}
	delete(s.grants, id)
	s.grantGen++
	return g, true
}

// ActiveGrants returns all non-expired grants without mutating state or firing callbacks.
// Expired grants are removed and their callbacks invoked only by PruneExpiredGrants.
func (s *Store) ActiveGrants() []Grant {
	now := s.now().UTC()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Grant, 0, len(s.grants))
	for _, g := range s.grants {
		if g.ExpiresAt.After(now) {
			out = append(out, g)
		}
	}
	return out
}

// PruneExpiredGrants removes expired grants and returns their IDs.
func (s *Store) PruneExpiredGrants() []string {
	now := s.now().UTC()
	s.mu.Lock()
	var expired []Grant
	for id, g := range s.grants {
		if !g.ExpiresAt.After(now) {
			delete(s.grants, id)
			expired = append(expired, g)
		}
	}
	if len(expired) > 0 {
		s.grantGen++
	}
	cbs := slices.Clone(s.onExpired)
	s.mu.Unlock()

	ids := make([]string, 0, len(expired))
	for _, g := range expired {
		ids = append(ids, g.ID)
		for _, cb := range cbs {
			cb(g)
		}
	}
	return ids
}

// RunGrantPruner periodically prunes expired grants until ctx is cancelled.
func (s *Store) RunGrantPruner(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 50 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.PruneExpiredGrants()
		}
	}
}

func randomGrantID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "gr_" + hex.EncodeToString(b[:]), nil
}
