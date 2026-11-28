// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"reflect"
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

	// admitted is the whole policy decision the flow runs under: its rule and
	// grant, WebSocket permission, and the host's bindings, which fix whether its
	// response is scrubbed and of what.
	admitted policy.Decision
}

// Teardown reason tokens recorded in completion audit events.
const (
	TeardownRevoked        = "revoked"
	TeardownGrantExpired   = "grant-expired"
	TeardownReload         = "reload"
	TeardownClientCanceled = "client-canceled"
)

type activeFlow struct {
	info   FlowInfo
	cancel context.CancelFunc
	// abort ends the guest side of this flow alone (see guestAbort).
	abort func()

	mu             sync.Mutex
	upConn         net.Conn
	tornDown       bool
	done           bool
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

// finish marks the handler as returning. A ResponseWriter must not be used after
// that, so teardown never calls abort on a finished flow.
func (f *activeFlow) finish() {
	f.mu.Lock()
	f.done = true
	f.mu.Unlock()
}

// teardown ends the guest side, cancels the request context, and closes any
// gateway-owned WebSocket upstream socket.
func (f *activeFlow) teardown(reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tornDown || f.done {
		return
	}
	f.tornDown = true
	f.teardownReason = reason

	// End the guest side before canceling reqCtx so net/http cannot observe the
	// cancellation and flush a synthetic 200 OK on an open socket.
	if f.abort != nil {
		f.abort()
	}
	if f.cancel != nil {
		f.cancel()
	}
	// Direct upstream close applies only to WebSockets, where gateway owns the raw socket.
	// Transport-managed HTTP/H2/SSE flows rely on cancel() ending the upstream exchange.
	if f.upConn != nil {
		closeQuietly(f.upConn)
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

func (r *FlowRegistry) register(info FlowInfo, cancel context.CancelFunc, abort func()) *activeFlow {
	if info.ID == "" {
		info.ID = newFlowID()
	}
	if info.StartedAt.IsZero() {
		info.StartedAt = time.Now().UTC()
	}
	af := &activeFlow{info: info, cancel: cancel, abort: abort}
	r.mu.Lock()
	r.flows[info.ID] = af
	r.mu.Unlock()
	return af
}

func (r *FlowRegistry) unregister(af *activeFlow) {
	r.mu.Lock()
	delete(r.flows, af.info.ID)
	r.mu.Unlock()
	af.finish()
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
	return len(r.RevokeWhere(func(info FlowInfo) bool {
		return info.ID == flowID
	}, TeardownRevoked))
}

// RevokeByGrant tears down every active flow running under grantID with reason.
func (r *FlowRegistry) RevokeByGrant(grantID, reason string) int {
	if grantID == "" {
		return 0
	}
	return len(r.RevokeWhere(func(info FlowInfo) bool {
		return info.GrantID == grantID
	}, reason))
}

// RevokeByPrincipal tears down every active flow for principal (optionally filtered to exact host).
func (r *FlowRegistry) RevokeByPrincipal(principal, host string) int {
	normHost := config.NormalizeHost(host)
	return len(r.RevokeWhere(func(info FlowInfo) bool {
		return info.Principal == principal && (normHost == "" || info.Host == normHost)
	}, TeardownRevoked))
}

// RevokeWhere tears down every active flow matching pred with reason, fires onRevoke, and returns the terminated FlowInfos.
func (r *FlowRegistry) RevokeWhere(pred func(FlowInfo) bool, reason string) []FlowInfo {
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

// teardownWhere unregisters and tears down every flow matching pred. pred runs
// outside the registry lock so it may call back into the registry.
func (r *FlowRegistry) teardownWhere(pred func(FlowInfo) bool, reason string) []FlowInfo {
	r.mu.RLock()
	snapshot := make([]*activeFlow, 0, len(r.flows))
	for _, af := range r.flows {
		snapshot = append(snapshot, af)
	}
	r.mu.RUnlock()

	var revoked []FlowInfo
	for _, af := range snapshot {
		if !pred(af.info) {
			continue
		}
		r.mu.Lock()
		cur, ok := r.flows[af.info.ID]
		if ok && cur == af {
			delete(r.flows, af.info.ID)
		}
		r.mu.Unlock()
		if ok && cur == af {
			af.teardown(reason)
			revoked = append(revoked, af.info)
		}
	}
	return revoked
}

// RevokeReloadedFlows tears down every active flow, across all links, whose
// admission no longer holds. A flow is admitted by one policy decision (its rule,
// grant, and the host's bindings, which fix whether its response is scrubbed and
// of what). The same request decided under the reloaded state must come out
// identical or the flow ends. That covers a wiped grant, a removed or changed
// rule, and a binding added to the host.
func RevokeReloadedFlows(flows *FlowRegistry, eval *policy.Evaluator) int {
	return len(flows.RevokeWhere(func(info FlowInfo) bool {
		now := eval.DecideRequest(info.Principal, info.Host, info.Port, info.Method, info.Path)
		return !reflect.DeepEqual(admissionFacts(info.admitted, info.Protocol), admissionFacts(now, info.Protocol))
	}, TeardownReload))
}

// admissionFacts is the part of dec that a flow of this protocol depends on:
// WebSocket terms matter to WebSockets only.
func admissionFacts(dec policy.Decision, protocol string) policy.Decision {
	if protocol != "websocket" {
		dec.AllowWebSocket = false
		dec.WSMaxEgressBytes = 0
	}
	return dec
}

func newFlowID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "fl_fallback"
	}
	return "fl_" + hex.EncodeToString(b[:])
}

type guestConnCtxKey struct{}

// guestAbort returns how to end r's guest side alone. HTTP/1 and WebSocket own
// their connection, so it is closed. An HTTP/2 connection carries sibling
// streams, so only this stream is reset: a write deadline already past resets it
// at once, even while the handler is blocked in a write. Where that is
// unsupported the connection is closed rather than left open.
func guestAbort(w http.ResponseWriter, r *http.Request) func() {
	conn, ok := r.Context().Value(guestConnCtxKey{}).(net.Conn)
	if !ok {
		return nil
	}
	if r.ProtoMajor != 2 {
		return func() { closeQuietly(conn) }
	}
	rc := http.NewResponseController(w)
	return func() {
		if err := rc.SetWriteDeadline(time.Now()); err != nil {
			closeQuietly(conn)
		}
	}
}
