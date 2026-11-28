// SPDX-License-Identifier: AGPL-3.0-only

// Package policy implements pure, I/O-free default-deny egress policy evaluation
// per link principal, including specificity ranking (exact > wildcard; deny beats allow
// on ties) and live in-memory ephemeral TTL grants.
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
	methodUpper := ""
	if !hostScope {
		if !strings.HasPrefix(reqPath, "/") {
			return Decision{Allow: false, Reason: "invalid-path"}
		}
		methodUpper = strings.ToUpper(method)
	}

	cs := e.currentCompiled()
	grants := e.store.ActiveGrants()
	hostBindings := slices.Clone(cs.boundHosts[host])
	hasBindings := len(hostBindings) > 0

	best, hasBest := matchBestCandidate(cs, grants, principal, host, port, hostScope, methodUpper, reqPath)
	if !hasBest {
		return Decision{Allow: false, Reason: "default-deny", HasBindings: hasBindings, HostBindings: hostBindings}
	}
	if !best.allow {
		return Decision{Allow: false, RuleID: best.ruleID, Reason: "rule-deny", HasBindings: hasBindings, HostBindings: hostBindings}
	}
	reason := "rule-allow"
	if best.grantID != "" {
		reason = "grant-allow"
	}
	var matchedBindings []config.BindingConfig
	if !hostScope && best.ruleID != "" {
		matchedBindings = matchRuleBindings(best.bindings, host, port, methodUpper, reqPath)
	}
	return Decision{
		Allow:            true,
		RuleID:           best.ruleID,
		GrantID:          best.grantID,
		Reason:           reason,
		AllowWebSocket:   best.allowWebSocket && !hasBindings,
		WSMaxEgressBytes: best.wsMaxEgressBytes,
		HasBindings:      hasBindings,
		MatchedBindings:  matchedBindings,
		HostBindings:     hostBindings,
	}
}

func matchBestCandidate(
	cs *compiledSet,
	grants []config.Grant,
	principal, host string,
	port uint16,
	hostScope bool,
	methodUpper, reqPath string,
) (candidate, bool) {
	var best candidate
	hasBest := false

	for _, r := range cs.byPrincipal[principal] {
		c, ok := evalRuleCandidate(r, cs.wsDefault, host, port, hostScope, methodUpper, reqPath)
		if ok && (!hasBest || c.beats(best)) {
			best = c
			hasBest = true
		}
	}
	for _, g := range grants {
		c, ok := evalGrantCandidate(g, cs.wsDefault, principal, host, port, hostScope, methodUpper, reqPath)
		if ok && (!hasBest || c.beats(best)) {
			best = c
			hasBest = true
		}
	}
	return best, hasBest
}

func evalRuleCandidate(r compiledRule, wsDefault int64, host string, port uint16, hostScope bool, methodUpper, reqPath string) (candidate, bool) {
	if !slices.Contains(r.ports, port) {
		return candidate{}, false
	}
	if hostScope && !r.allow && (len(r.methods) > 0 || len(r.paths) > 0) {
		return candidate{}, false
	}
	hr, matched := matchHosts(r.hosts, host)
	if !matched {
		return candidate{}, false
	}
	pathSpec := 0
	if !hostScope {
		if len(r.methods) > 0 && !slices.Contains(r.methods, methodUpper) {
			return candidate{}, false
		}
		var pathMatched bool
		pathSpec, pathMatched = matchPaths(r.paths, reqPath)
		if !pathMatched {
			return candidate{}, false
		}
	}
	wsCap := r.wsMaxEgressBytes
	if wsCap == 0 {
		wsCap = wsDefault
	}
	return candidate{
		rank: rankKey{
			hostRank:        hr,
			methodSpecified: len(r.methods) > 0,
			pathSpecified:   len(r.paths) > 0,
			pathSpecificity: pathSpec,
		},
		allow:            r.allow,
		ruleID:           r.id,
		allowWebSocket:   r.allowWebSocket,
		wsMaxEgressBytes: wsCap,
		bindings:         r.bindings,
	}, true
}

func evalGrantCandidate(g config.Grant, wsDefault int64, principal, host string, port uint16, hostScope bool, methodUpper, reqPath string) (candidate, bool) {
	if g.Principal != principal || g.Port != port || g.Host != host {
		return candidate{}, false
	}
	pathSpec := 0
	if !hostScope {
		if len(g.Methods) > 0 && !slices.Contains(g.Methods, methodUpper) {
			return candidate{}, false
		}
		var pathMatched bool
		pathSpec, pathMatched = matchPaths(g.Paths, reqPath)
		if !pathMatched {
			return candidate{}, false
		}
	}
	return candidate{
		rank: rankKey{
			hostRank:        exactHostRank,
			methodSpecified: len(g.Methods) > 0,
			pathSpecified:   len(g.Paths) > 0,
			pathSpecificity: pathSpec,
		},
		allow:            true,
		grantID:          g.ID,
		allowWebSocket:   g.AllowWebSocket,
		wsMaxEgressBytes: wsDefault,
	}, true
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
	allow            bool
	ruleID           string
	grantID          string
	allowWebSocket   bool
	wsMaxEgressBytes int64
	bindings         []config.BindingConfig
}

func (c candidate) beats(other candidate) bool {
	cmp := c.rank.compare(other.rank)
	if cmp != 0 {
		return cmp > 0
	}
	// On exact tie, deny always beats allow.
	if !c.allow && other.allow {
		return true
	}
	return false
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
