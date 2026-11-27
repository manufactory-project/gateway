package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"time"
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

type activeFlow struct {
	info      FlowInfo
	cancel    context.CancelFunc
	guestConn net.Conn

	mu       sync.Mutex
	upConn   net.Conn
	tornDown bool
}

// setUpstreamConn attaches c to the flow, or closes c immediately if teardown already ran.
func (f *activeFlow) setUpstreamConn(c net.Conn) {
	if c == nil {
		return
	}
	f.mu.Lock()
	if f.tornDown {
		f.mu.Unlock()
		closeQuietly(c)
		return
	}
	f.upConn = c
	f.mu.Unlock()
}

// teardown immediately invokes BOTH reqCancel() and conn.Close() on guest and upstream sockets (NOW.md:64).
func (f *activeFlow) teardown() {
	f.mu.Lock()
	if f.tornDown {
		f.mu.Unlock()
		return
	}
	f.tornDown = true
	up := f.upConn
	f.mu.Unlock()

	if f.cancel != nil {
		f.cancel()
	}
	if f.guestConn != nil {
		closeQuietly(f.guestConn)
	}
	if up != nil {
		closeQuietly(up)
	}
}

// FlowRegistry tracks every active per-request/per-stream flow independently so
// HTTP/1.1 keep-alive and HTTP/2 multiplexing never overwrite grantID/ruleID per conn.
type FlowRegistry struct {
	mu       sync.RWMutex
	flows    map[string]*activeFlow
	onRevoke func(int)
}

// NewFlowRegistry constructs an empty FlowRegistry.
func NewFlowRegistry() *FlowRegistry {
	return &FlowRegistry{
		flows: make(map[string]*activeFlow),
	}
}

// SetOnRevoke registers an observer called with the number of flows torn down
// by any revocation, grant expiry, or config reload.
func (r *FlowRegistry) SetOnRevoke(fn func(int)) {
	r.mu.Lock()
	r.onRevoke = fn
	r.mu.Unlock()
}

func (r *FlowRegistry) register(info FlowInfo, cancel context.CancelFunc, guestConn net.Conn) *activeFlow {
	if info.ID == "" {
		info.ID = newFlowID()
	}
	if info.StartedAt.IsZero() {
		info.StartedAt = time.Now().UTC()
	}
	af := &activeFlow{
		info:      info,
		cancel:    cancel,
		guestConn: guestConn,
	}
	r.mu.Lock()
	r.flows[info.ID] = af
	r.mu.Unlock()
	return af
}

func (r *FlowRegistry) unregister(id string) {
	r.mu.Lock()
	delete(r.flows, id)
	r.mu.Unlock()
}

// List returns a snapshot of all currently active flows.
func (r *FlowRegistry) List() []FlowInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]FlowInfo, 0, len(r.flows))
	for _, af := range r.flows {
		out = append(out, af.info)
	}
	return out
}

// Count returns the number of active flows.
func (r *FlowRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.flows)
}

// RevokeByID tears down the single flow with flowID and reports how many flows were terminated.
func (r *FlowRegistry) RevokeByID(flowID string) int {
	return r.revokeMatching(func(info FlowInfo) bool {
		return info.ID == flowID
	})
}

// RevokeByGrant tears down every active flow running under grantID.
func (r *FlowRegistry) RevokeByGrant(grantID string) int {
	if grantID == "" {
		return 0
	}
	return r.revokeMatching(func(info FlowInfo) bool {
		return info.GrantID == grantID
	})
}

// RevokeByPrincipal tears down every active flow for principal (optionally filtered to exact host).
func (r *FlowRegistry) RevokeByPrincipal(principal, host string) int {
	normHost := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	return r.revokeMatching(func(info FlowInfo) bool {
		if info.Principal != principal {
			return false
		}
		if normHost != "" && info.Host != normHost {
			return false
		}
		return true
	})
}

// RevokeWhere tears down every active flow matching pred, fires onRevoke, and returns the terminated FlowInfos.
func (r *FlowRegistry) RevokeWhere(pred func(FlowInfo) bool) []FlowInfo {
	revoked := r.teardownWhere(pred)
	if len(revoked) > 0 {
		r.mu.RLock()
		cb := r.onRevoke
		r.mu.RUnlock()
		if cb != nil {
			cb(len(revoked))
		}
	}
	return revoked
}

// drainLink tears down remaining flows on shutdown without incrementing revocation metrics.
func (r *FlowRegistry) drainLink(linkName string) {
	r.teardownWhere(func(info FlowInfo) bool {
		return info.Link == linkName
	})
}

func (r *FlowRegistry) teardownWhere(pred func(FlowInfo) bool) []FlowInfo {
	r.mu.Lock()
	var targets []*activeFlow
	for id, af := range r.flows {
		if pred(af.info) {
			targets = append(targets, af)
			delete(r.flows, id)
		}
	}
	r.mu.Unlock()

	revoked := make([]FlowInfo, 0, len(targets))
	for _, af := range targets {
		af.teardown()
		revoked = append(revoked, af.info)
	}
	return revoked
}

func (r *FlowRegistry) revokeMatching(pred func(FlowInfo) bool) int {
	return len(r.RevokeWhere(pred))
}

func newFlowID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "fl_fallback"
	}
	return "fl_" + hex.EncodeToString(b[:])
}

type guestConnCtxKey struct{}

func guestConnFromContext(ctx context.Context) net.Conn {
	c, ok := ctx.Value(guestConnCtxKey{}).(net.Conn)
	if !ok {
		return nil
	}
	return c
}

type activeFlowCtxKey struct{}

func withActiveFlow(ctx context.Context, af *activeFlow) context.Context {
	return context.WithValue(ctx, activeFlowCtxKey{}, af)
}

func activeFlowFromContext(ctx context.Context) *activeFlow {
	af, ok := ctx.Value(activeFlowCtxKey{}).(*activeFlow)
	if !ok {
		return nil
	}
	return af
}
