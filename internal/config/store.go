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
	ID        string    `json:"id"`
	Principal string    `json:"principal"`
	Host      string    `json:"host"`
	Port      uint16    `json:"port"`
	Methods   []string  `json:"methods,omitempty"`
	Paths     []string  `json:"paths,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Store holds the active configuration Snapshot and ephemeral in-memory TTL grants.
// Reload swaps the snapshot atomically, wipes all TTL grants, and invokes reload callbacks.
type Store struct {
	path string
	now  func() time.Time

	snap atomic.Pointer[Snapshot]

	mu        sync.RWMutex
	grants    map[string]Grant
	onReload  []func(prev, next *Snapshot, wipedGrantIDs []string)
	onExpired func(grantID string)
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

// OnReload registers a callback invoked after every successful reload.
func (s *Store) OnReload(fn func(prev, next *Snapshot, wipedGrantIDs []string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onReload = append(s.onReload, fn)
}

// SetOnGrantExpired sets a callback invoked when a grant is pruned on TTL expiry.
func (s *Store) SetOnGrantExpired(fn func(grantID string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onExpired = fn
}

// Reload re-reads and validates the YAML file from disk. If validation fails,
// the previous snapshot and grants remain intact and an error is returned.
// On success, the snapshot is atomically replaced and all in-memory TTL grants
// are wiped before reload callbacks run.
func (s *Store) Reload() (*Snapshot, []string, error) {
	cfg, hash, err := LoadFile(s.path)
	if err != nil {
		return nil, nil, err
	}
	next := &Snapshot{
		Config:   cfg,
		Hash:     hash,
		LoadedAt: s.now().UTC(),
	}

	s.mu.Lock()
	prev := s.snap.Swap(next)
	wiped := make([]string, 0, len(s.grants))
	for id := range s.grants {
		wiped = append(wiped, id)
	}
	s.grants = make(map[string]Grant)
	callbacks := slices.Clone(s.onReload)
	s.mu.Unlock()

	for _, fn := range callbacks {
		fn(prev, next, wiped)
	}
	return next, wiped, nil
}

// WatchSIGHUP listens for syscall.SIGHUP until ctx is cancelled, calling Reload
// on each signal and invoking onResult (if non-nil) with the outcome.
// It returns only after unregistering its signal channel so callers can join cleanly.
func (s *Store) WatchSIGHUP(ctx context.Context, onResult func(*Snapshot, []string, error)) {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			snap, wiped, err := s.Reload()
			if onResult != nil {
				onResult(snap, wiped, err)
			}
		}
	}
}

// AddGrant validates and inserts an ephemeral in-memory TTL grant.
// Grants accept exact hostnames only (no wildcards), ports 80 or 443, and positive TTLs.
func (s *Store) AddGrant(principal, rawHost string, port uint16, methods, paths []string, ttl time.Duration) (Grant, error) {
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

	snap := s.Current()
	principalKnown := false
	for _, l := range snap.Config.Links {
		if l.Principal == principal {
			principalKnown = true
			break
		}
	}
	if !principalKnown {
		return Grant{}, fmt.Errorf("grant: principal %q does not match any declared link", principal)
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
		if !strings.HasPrefix(p, "/") {
			return Grant{}, fmt.Errorf("grant: path %q must start with '/'", p)
		}
		normPaths[i] = p
	}

	id, err := randomGrantID()
	if err != nil {
		return Grant{}, fmt.Errorf("grant: generate id: %w", err)
	}
	now := s.now().UTC()
	g := Grant{
		ID:        id,
		Principal: principal,
		Host:      host,
		Port:      port,
		Methods:   normMethods,
		Paths:     normPaths,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}

	s.mu.Lock()
	s.grants[g.ID] = g
	s.mu.Unlock()
	return g, nil
}

// RevokeGrant removes a grant by ID and reports whether it existed.
func (s *Store) RevokeGrant(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.grants[id]; !ok {
		return false
	}
	delete(s.grants, id)
	return true
}

// ActiveGrants returns all non-expired grants (pruning expired ones and firing onExpired).
func (s *Store) ActiveGrants() []Grant {
	now := s.now().UTC()
	s.mu.Lock()
	var expired []string
	out := make([]Grant, 0, len(s.grants))
	for id, g := range s.grants {
		if !g.ExpiresAt.After(now) {
			delete(s.grants, id)
			expired = append(expired, id)
			continue
		}
		out = append(out, g)
	}
	cb := s.onExpired
	s.mu.Unlock()

	if cb != nil {
		for _, id := range expired {
			cb(id)
		}
	}
	return out
}

// PruneExpiredGrants removes expired grants and returns their IDs.
func (s *Store) PruneExpiredGrants() []string {
	now := s.now().UTC()
	s.mu.Lock()
	var expired []string
	for id, g := range s.grants {
		if !g.ExpiresAt.After(now) {
			delete(s.grants, id)
			expired = append(expired, id)
		}
	}
	cb := s.onExpired
	s.mu.Unlock()

	if cb != nil {
		for _, id := range expired {
			cb(id)
		}
	}
	return expired
}

func randomGrantID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "gr_" + hex.EncodeToString(b[:]), nil
}
