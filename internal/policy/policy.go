// SPDX-License-Identifier: AGPL-3.0-only

// Package policy implements pure, I/O-free default-deny egress policy evaluation
// per link principal: any matching deny wins, otherwise the most specific allow
// rule or live in-memory ephemeral TTL grant decides.
package policy

import (
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/manufactory-project/gateway/internal/config"
)

// Decision is the result of evaluating policy for a DNS query, TLS SNI, or HTTP request.
type Decision struct {
	Allow            bool
	RuleID           string
	GrantID          string
	Reason           string
	AllowWebSocket   bool
	WSMaxEgressBytes int64
	HasBindings      bool
	MatchedBindings  []config.BindingConfig
	HostBindings     []config.BindingConfig
	// PinnedIP is the address the deciding rule pins for the host, or the zero
	// Addr. Only a request decided by that rule may dial it.
	PinnedIP netip.Addr
}

type compiledRule struct {
	id               string
	principal        string
	allow            bool
	hosts            []hostPattern
	ports            []uint16
	methods          []string
	paths            []string
	allowWebSocket   bool
	wsMaxEgressBytes int64
	bindings         []config.BindingConfig
	pins             map[string]netip.Addr
}

type hostPattern struct {
	raw      string
	wildcard bool
	suffix   string // ".example.com" for "*.example.com"
}

type compiledSet struct {
	byPrincipal map[string][]compiledRule
	boundHosts  map[string][]config.BindingConfig // exact host -> every principal's bindings
	wsDefault   int64
}

// Evaluator evaluates egress policy against the active config.Store snapshot
// and live ephemeral TTL grants.
type Evaluator struct {
	store *config.Store

	mu       sync.RWMutex
	lastCfg  *config.Config
	compiled *compiledSet
}

// NewEvaluator constructs an Evaluator backed by store.
func NewEvaluator(store *config.Store) *Evaluator {
	return &Evaluator{store: store}
}

func (e *Evaluator) currentCompiled() *compiledSet {
	cfg := e.store.Current().Config
	e.mu.RLock()
	if e.lastCfg == cfg && e.compiled != nil {
		cs := e.compiled
		e.mu.RUnlock()
		return cs
	}
	e.mu.RUnlock()

	cs := compileConfig(cfg)
	e.mu.Lock()
	e.lastCfg = cfg
	e.compiled = cs
	e.mu.Unlock()
	return cs
}

func compileConfig(cfg *config.Config) *compiledSet {
	cs := &compiledSet{
		byPrincipal: make(map[string][]compiledRule),
		boundHosts:  make(map[string][]config.BindingConfig),
		wsDefault:   cfg.HTTP.WSMaxEgressBytes,
	}
	for _, r := range cfg.Rules {
		cr := compiledRule{
			id:               r.ID,
			principal:        r.Principal,
			allow:            r.Effect == "allow",
			ports:            slices.Clone(r.Ports),
			methods:          slices.Clone(r.Methods),
			paths:            slices.Clone(r.Paths),
			allowWebSocket:   r.AllowWebSocket,
			wsMaxEgressBytes: r.WSMaxEgressBytes,
			bindings:         slices.Clone(r.Bindings),
			pins:             r.ParsedPins,
		}
		for _, h := range r.Hosts {
			hp := hostPattern{raw: h}
			if strings.HasPrefix(h, "*.") {
				hp.wildcard = true
				hp.suffix = h[1:] // ".zone"
			}
			cr.hosts = append(cr.hosts, hp)
		}
		cs.byPrincipal[r.Principal] = append(cs.byPrincipal[r.Principal], cr)

		for _, b := range r.Bindings {
			cs.boundHosts[b.Host] = append(cs.boundHosts[b.Host], b)
		}
	}
	return cs
}

// DecideDNS reports whether principal is permitted to resolve rawHost on either
// port 443 or port 80 (default-deny), preserving explicit rule-deny decisions.
func (e *Evaluator) DecideDNS(principal, rawHost string) Decision {
	host, ok := normalizeLookupHost(rawHost)
	if !ok {
		return Decision{Allow: false, Reason: "invalid-host"}
	}
	d443 := e.DecideHost(principal, host, 443)
	if d443.Allow {
		return d443
	}
	d80 := e.DecideHost(principal, host, 80)
	if d80.Allow {
		return d80
	}
	if d443.Reason == "rule-deny" {
		return d443
	}
	if d80.Reason == "rule-deny" {
		return d80
	}
	return Decision{Allow: false, Reason: "default-deny"}
}

// DecideHost evaluates connection/SNI admission for (principal, rawHost, port).
// Only port 80 and 443 are permitted; method/path-scoped allow rules still admit
// the TLS handshake so request-level evaluation can run inside MITM.
func (e *Evaluator) DecideHost(principal, rawHost string, port uint16) Decision {
	return e.decide(principal, rawHost, port, true, "", "")
}

// DecideRequest evaluates an HTTP request for (principal, rawHost, port, method, path).
func (e *Evaluator) DecideRequest(principal, rawHost string, port uint16, method, reqPath string) Decision {
	return e.decide(principal, rawHost, port, false, method, reqPath)
}

func (e *Evaluator) decide(principal, rawHost string, port uint16, hostScope bool, method, reqPath string) Decision {
	if port != 80 && port != 443 {
		return Decision{Allow: false, Reason: "port-denied"}
	}
	host, ok := normalizeLookupHost(rawHost)
	if !ok {
		return Decision{Allow: false, Reason: "invalid-host"}
	}
	q := query{host: host, port: port, hostScope: hostScope}
	if !hostScope {
		if !strings.HasPrefix(reqPath, "/") {
			return Decision{Allow: false, Reason: "invalid-path"}
		}
		q.method = strings.ToUpper(method)
		q.path = reqPath
	}

	cs := e.currentCompiled()
	hostBindings := slices.Clone(cs.boundHosts[host])
	hasBindings := len(hostBindings) > 0
	rules := cs.byPrincipal[principal]

	// A matching deny is absolute: no allow rule or grant, however specific, overrides it.
	for _, r := range rules {
		if !r.allow {
			if _, ok := r.match(q); ok {
				return Decision{Allow: false, RuleID: r.id, Reason: "rule-deny", HasBindings: hasBindings, HostBindings: hostBindings}
			}
		}
	}

	best, hasBest := bestAllow(rules, e.store.ActiveGrants(), cs.wsDefault, principal, q)
	if !hasBest {
		return Decision{Allow: false, Reason: "default-deny", HasBindings: hasBindings, HostBindings: hostBindings}
	}
	reason := "rule-allow"
	if best.grantID != "" {
		reason = "grant-allow"
	}
	var matchedBindings []config.BindingConfig
	if !hostScope && best.ruleID != "" {
		matchedBindings = matchRuleBindings(best.bindings, host, port, q.method, reqPath)
	}
	return Decision{
		Allow:            true,
		RuleID:           best.ruleID,
		GrantID:          best.grantID,
		Reason:           reason,
		AllowWebSocket:   best.allowWebSocket && !hasBindings,
		WSMaxEgressBytes: best.wsMaxEgressBytes,
		PinnedIP:         best.pin,
		HasBindings:      hasBindings,
		MatchedBindings:  matchedBindings,
		HostBindings:     hostBindings,
	}
}

// query is one normalized policy question. hostScope asks only whether the host
// may be reached at all (DNS, TLS handshake); otherwise method and path apply.
type query struct {
	host      string
	port      uint16
	hostScope bool
	method    string
	path      string
}

// bestAllow picks the most specific matching allow rule or grant. Among equally
// specific matches the first rule in config order wins, and rules win over grants.
func bestAllow(rules []compiledRule, grants []config.Grant, wsDefault int64, principal string, q query) (candidate, bool) {
	var best candidate
	found := false
	consider := func(c candidate, ok bool) {
		if ok && (!found || c.rank.compare(best.rank) > 0) {
			best, found = c, true
		}
	}
	for _, r := range rules {
		if !r.allow {
			continue
		}
		rank, ok := r.match(q)
		wsCap := r.wsMaxEgressBytes
		if wsCap == 0 {
			wsCap = wsDefault
		}
		consider(candidate{
			rank:             rank,
			ruleID:           r.id,
			allowWebSocket:   r.allowWebSocket,
			wsMaxEgressBytes: wsCap,
			bindings:         r.bindings,
			pin:              r.pins[q.host],
		}, ok)
	}
	for _, g := range grants {
		if g.Principal != principal || g.Port != q.port || g.Host != q.host {
			continue
		}
		rank, ok := matchScope(g.Methods, g.Paths, exactHostRank, q)
		consider(candidate{rank: rank, grantID: g.ID, allowWebSocket: g.AllowWebSocket, wsMaxEgressBytes: wsDefault}, ok)
	}
	return best, found
}

// match reports whether the rule applies to q and how specifically. A deny that
// narrows by method or path applies to HTTP requests only, never to the host as a whole.
func (r compiledRule) match(q query) (rankKey, bool) {
	if !slices.Contains(r.ports, q.port) {
		return rankKey{}, false
	}
	if q.hostScope && !r.allow && (len(r.methods) > 0 || len(r.paths) > 0) {
		return rankKey{}, false
	}
	hr, ok := matchHosts(r.hosts, q.host)
	if !ok {
		return rankKey{}, false
	}
	return matchScope(r.methods, r.paths, hr, q)
}

func matchScope(methods, paths []string, hostRank int, q query) (rankKey, bool) {
	rank := rankKey{hostRank: hostRank, methodSpecified: len(methods) > 0, pathSpecified: len(paths) > 0}
	if q.hostScope {
		return rank, true
	}
	if len(methods) > 0 && !slices.Contains(methods, q.method) {
		return rankKey{}, false
	}
	spec, ok := matchPaths(paths, q.path)
	rank.pathSpecificity = spec
	return rank, ok
}

func matchRuleBindings(bindings []config.BindingConfig, host string, port uint16, methodUpper, reqPath string) []config.BindingConfig {
	if port != 443 || len(bindings) == 0 {
		return nil
	}
	var matched []config.BindingConfig
	for _, b := range bindings {
		if b.Host != host {
			continue
		}
		if len(b.Methods) > 0 && !slices.Contains(b.Methods, methodUpper) {
			continue
		}
		if _, ok := matchPaths(b.Paths, reqPath); !ok {
			continue
		}
		matched = append(matched, b)
	}
	return matched
}

// exactHostRank outranks every wildcard suffix length (max DNS name is 253 bytes).
const exactHostRank = 1000

type rankKey struct {
	hostRank        int
	methodSpecified bool
	pathSpecified   bool
	pathSpecificity int
}

func (a rankKey) compare(b rankKey) int {
	if a.hostRank != b.hostRank {
		if a.hostRank > b.hostRank {
			return 1
		}
		return -1
	}
	if a.pathSpecified != b.pathSpecified {
		if a.pathSpecified {
			return 1
		}
		return -1
	}
	if a.pathSpecificity != b.pathSpecificity {
		if a.pathSpecificity > b.pathSpecificity {
			return 1
		}
		return -1
	}
	if a.methodSpecified != b.methodSpecified {
		if a.methodSpecified {
			return 1
		}
		return -1
	}
	return 0
}

type candidate struct {
	rank             rankKey
	ruleID           string
	grantID          string
	allowWebSocket   bool
	wsMaxEgressBytes int64
	bindings         []config.BindingConfig
	pin              netip.Addr
}

func matchHosts(patterns []hostPattern, host string) (int, bool) {
	bestRank := 0
	matched := false
	for _, hp := range patterns {
		if !hp.wildcard {
			if hp.raw == host {
				return exactHostRank, true
			}
			continue
		}
		if strings.HasSuffix(host, hp.suffix) && len(host) > len(hp.suffix) {
			r := len(hp.suffix)
			if !matched || r > bestRank {
				bestRank = r
				matched = true
			}
		}
	}
	return bestRank, matched
}

func matchPaths(patterns []string, reqPath string) (int, bool) {
	if len(patterns) == 0 {
		return 0, true
	}
	bestSpec := -1
	matched := false
	for _, pat := range patterns {
		if globPathMatch(pat, reqPath) {
			spec := pathPatternSpecificity(pat)
			if !matched || spec > bestSpec {
				bestSpec = spec
				matched = true
			}
		}
	}
	return bestSpec, matched
}

func pathPatternSpecificity(pat string) int {
	if !strings.Contains(pat, "*") {
		return 10000 + len(pat)
	}
	// Count non-wildcard characters so "/v1/messages/**" outranks "/**".
	n := 0
	for i := 0; i < len(pat); i++ {
		if pat[i] != '*' {
			n++
		}
	}
	return n
}

// globPathMatch supports exact paths, single-segment '*', and multi-segment '**'.
func globPathMatch(pattern, value string) bool {
	if pattern == "/**" {
		return strings.HasPrefix(value, "/")
	}
	// "/x/**" covers "/x" itself, so a deny on "/v1/admin/**" cannot be sidestepped
	// by asking for "/v1/admin".
	if base, ok := strings.CutSuffix(pattern, "/**"); ok && value == base {
		return true
	}
	return matchGlob(pattern, value)
}

type globTokenKind uint8

const (
	globLit globTokenKind = iota
	globStar
	globDoubleStar
)

type globToken struct {
	kind globTokenKind
	ch   byte
}

func tokenizeGlob(pat string) []globToken {
	toks := make([]globToken, 0, len(pat))
	for i := 0; i < len(pat); {
		if pat[i] == '*' {
			if i+1 < len(pat) && pat[i+1] == '*' {
				toks = append(toks, globToken{kind: globDoubleStar})
				i += 2
				continue
			}
			toks = append(toks, globToken{kind: globStar})
			i++
			continue
		}
		toks = append(toks, globToken{kind: globLit, ch: pat[i]})
		i++
	}
	return toks
}

// matchGlob evaluates pat against val using a linear-time NFA simulation so
// worst-case non-matching paths never backtrack exponentially.
func matchGlob(pat, val string) bool {
	toks := tokenizeGlob(pat)
	if len(toks) < 64 {
		return matchGlobBitmask(toks, val)
	}
	return matchGlobSlice(toks, val)
}

func matchGlobBitmask(toks []globToken, val string) bool {
	n := len(toks)
	var (
		wildMask uint64
		starMask uint64
		dblMask  uint64
		charMask [256]uint64
	)
	for j, tk := range toks {
		bit := uint64(1) << j
		switch tk.kind {
		case globDoubleStar:
			dblMask |= bit
			wildMask |= bit
		case globStar:
			starMask |= bit
			wildMask |= bit
		case globLit:
			charMask[tk.ch] |= bit
		}
	}

	cur := uint64(1)
	for add := (cur & wildMask) << 1; add & ^cur != 0; add = (cur & wildMask) << 1 {
		cur |= add
	}
	for i := 0; i < len(val); i++ {
		ch := val[i]
		next := ((cur & charMask[ch]) << 1) | (cur & dblMask)
		if ch != '/' {
			next |= cur & starMask
		}
		if next == 0 {
			return false
		}
		for add := (next & wildMask) << 1; add & ^next != 0; add = (next & wildMask) << 1 {
			next |= add
		}
		cur = next
	}
	return cur&(uint64(1)<<n) != 0
}

func matchGlobSlice(toks []globToken, val string) bool {
	n := len(toks)
	cur := make([]bool, n+1)
	next := make([]bool, n+1)

	closeEps := func(states []bool) {
		for j := 0; j < n; j++ {
			if states[j] && (toks[j].kind == globStar || toks[j].kind == globDoubleStar) {
				states[j+1] = true
			}
		}
	}

	cur[0] = true
	closeEps(cur)

	for i := 0; i < len(val); i++ {
		ch := val[i]
		clear(next)
		any := false
		for j := 0; j < n; j++ {
			if !cur[j] {
				continue
			}
			switch toks[j].kind {
			case globDoubleStar:
				next[j] = true
				any = true
			case globStar:
				if ch != '/' {
					next[j] = true
					any = true
				}
			case globLit:
				if toks[j].ch == ch {
					next[j+1] = true
					any = true
				}
			}
		}
		if !any {
			return false
		}
		closeEps(next)
		cur, next = next, cur
	}
	return cur[n]
}

func normalizeLookupHost(raw string) (string, bool) {
	h := config.NormalizeHost(raw)
	if h == "" || len(h) > 253 || strings.Contains(h, "*") {
		return "", false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "", false
	}
	return h, true
}
