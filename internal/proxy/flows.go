package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/policy"
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

// Teardown reason tokens recorded in completion audit events.
const (
	TeardownRevoked        = "revoked"
	TeardownGrantExpired   = "grant-expired"
	TeardownReload         = "reload"
	TeardownClientCanceled = "client-canceled"
)

type activeFlow struct {
	info      FlowInfo
	cancel    context.CancelFunc
	guestConn net.Conn

	mu             sync.Mutex
	upConn         net.Conn
	tornDown       bool
	teardownReason string
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

func (f *activeFlow) reason() string {
	f.mu.Lock()
	r := f.teardownReason
	f.mu.Unlock()
	return r
}

// teardown immediately cancels the request context, closes the guest connection,
// and closes any gateway-owned WebSocket upstream socket.
func (f *activeFlow) teardown(reason string) {
	f.mu.Lock()
	if f.tornDown {
		f.mu.Unlock()
		return
	}
	f.tornDown = true
	f.teardownReason = reason
	up := f.upConn
	f.mu.Unlock()

	// Close the guest connection before canceling reqCtx so net/http cannot
	// observe cancellation and flush a synthetic 200 OK on an open socket.
	if f.guestConn != nil {
		closeQuietly(f.guestConn)
	}
	if f.cancel != nil {
		f.cancel()
	}
	// Direct upstream close applies only to WebSockets, where gateway owns the raw socket.
	// Transport-managed HTTP/H2/SSE flows rely on reqCancel() + guestConn.Close().
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
	}, TeardownRevoked)
}

// RevokeByGrant tears down every active flow running under grantID.
func (r *FlowRegistry) RevokeByGrant(grantID string) int {
	return r.RevokeByGrantWithReason(grantID, TeardownRevoked)
}

// RevokeByGrantWithReason tears down every active flow running under grantID with a specific teardown reason.
func (r *FlowRegistry) RevokeByGrantWithReason(grantID, reason string) int {
	if grantID == "" {
		return 0
	}
	return r.revokeMatching(func(info FlowInfo) bool {
		return info.GrantID == grantID
	}, reason)
}

// RevokeByPrincipal tears down every active flow for principal (optionally filtered to exact host).
func (r *FlowRegistry) RevokeByPrincipal(principal, host string) int {
	normHost := config.NormalizeHost(host)
	return r.revokeMatching(func(info FlowInfo) bool {
		if info.Principal != principal {
			return false
		}
		if normHost != "" && info.Host != normHost {
			return false
		}
		return true
	}, TeardownRevoked)
}

// RevokeWhere tears down every active flow matching pred, fires onRevoke, and returns the terminated FlowInfos.
func (r *FlowRegistry) RevokeWhere(pred func(FlowInfo) bool) []FlowInfo {
	return r.RevokeWhereWithReason(pred, TeardownRevoked)
}

// RevokeWhereWithReason tears down every active flow matching pred with reason, fires onRevoke, and returns the terminated FlowInfos.
func (r *FlowRegistry) RevokeWhereWithReason(pred func(FlowInfo) bool, reason string) []FlowInfo {
	revoked := r.teardownWhere(pred, reason)
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
	}, TeardownRevoked)
}

func (r *FlowRegistry) teardownWhere(pred func(FlowInfo) bool, reason string) []FlowInfo {
	r.mu.RLock()
	snapshot := make([]*activeFlow, 0, len(r.flows))
	for _, af := range r.flows {
		snapshot = append(snapshot, af)
	}
	r.mu.RUnlock()

	var matched []*activeFlow
	for _, af := range snapshot {
		if pred(af.info) {
			matched = append(matched, af)
		}
	}
	if len(matched) == 0 {
		return nil
	}

	r.mu.Lock()
	targets := make([]*activeFlow, 0, len(matched))
	for _, af := range matched {
		if cur, ok := r.flows[af.info.ID]; ok && cur == af {
			delete(r.flows, af.info.ID)
			targets = append(targets, af)
		}
	}
	r.mu.Unlock()

	revoked := make([]FlowInfo, 0, len(targets))
	for _, af := range targets {
		af.teardown(reason)
		revoked = append(revoked, af.info)
	}
	return revoked
}

func (r *FlowRegistry) revokeMatching(pred func(FlowInfo) bool, reason string) int {
	return len(r.RevokeWhereWithReason(pred, reason))
}

// RevokeReloadedFlows tears down every active flow across all links that was admitted
// by a wiped grant or is no longer permitted by the reloaded policy.
func RevokeReloadedFlows(flows *FlowRegistry, eval *policy.Evaluator, wipedGrantIDs []string) int {
	revoked := flows.RevokeWhereWithReason(func(info FlowInfo) bool {
		if info.GrantID != "" && slices.Contains(wipedGrantIDs, info.GrantID) {
			return true
		}
		dec := eval.DecideRequest(info.Principal, info.Host, info.Port, info.Method, info.Path)
		if !dec.Allow {
			return true
		}
		if info.Protocol == "websocket" && !dec.AllowWebSocket {
			return true
		}
		return false
	}, TeardownReload)
	return len(revoked)
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
