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
	boundHosts  map[string]map[string][]config.BindingConfig // principal -> exact host -> bindings
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
		boundHosts:  make(map[string]map[string][]config.BindingConfig),
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

		if len(r.Bindings) > 0 {
			m := cs.boundHosts[r.Principal]
			if m == nil {
				m = make(map[string][]config.BindingConfig)
				cs.boundHosts[r.Principal] = m
			}
			for _, b := range r.Bindings {
				m[b.Host] = append(m[b.Host], b)
			}
		}
	}
	return cs
}

// DecideDNS reports whether principal is permitted to resolve rawHost on either
// port 443 or port 80 (default-deny).
func (e *Evaluator) DecideDNS(principal, rawHost string) Decision {
	host, ok := normalizeLookupHost(rawHost)
	if !ok {
		return Decision{Allow: false, Reason: "invalid-host"}
	}
	if d := e.DecideHost(principal, host, 443); d.Allow {
		return d
	}
	if d := e.DecideHost(principal, host, 80); d.Allow {
		return d
	}
	return Decision{Allow: false, Reason: "default-deny"}
}

// DecideHost evaluates connection/SNI admission for (principal, rawHost, port).
// Only port 80 and 443 are permitted; method/path-scoped allow rules still admit
// the TLS handshake so request-level evaluation can run inside MITM.
func (e *Evaluator) DecideHost(principal, rawHost string, port uint16) Decision {
	if port != 80 && port != 443 {
		return Decision{Allow: false, Reason: "port-denied"}
	}
	host, ok := normalizeLookupHost(rawHost)
	if !ok {
		return Decision{Allow: false, Reason: "invalid-host"}
	}

	cs := e.currentCompiled()
	grants := e.store.ActiveGrants()
	hasBindings := len(cs.boundHosts[principal][host]) > 0

	var best candidate
	hasBest := false

	for _, r := range cs.byPrincipal[principal] {
		if !slices.Contains(r.ports, port) {
			continue
		}
		// At connection/SNI scope, a deny rule scoped to specific methods/paths
		// must NOT block unrelated requests on the same host; it is evaluated at request scope.
		if !r.allow && (len(r.methods) > 0 || len(r.paths) > 0) {
			continue
		}
		hr, matched := matchHosts(r.hosts, host)
		if !matched {
			continue
		}
		wsCap := r.wsMaxEgressBytes
		if wsCap == 0 {
			wsCap = cs.wsDefault
		}
		c := candidate{
			rank:             rankKey{hostRank: hr},
			allow:            r.allow,
			ruleID:           r.id,
			allowWebSocket:   r.allowWebSocket,
			wsMaxEgressBytes: wsCap,
		}
		if !hasBest || c.beats(best) {
			best = c
			hasBest = true
		}
	}

	for _, g := range grants {
		if g.Principal != principal || g.Port != port || g.Host != host {
			continue
		}
		c := candidate{
			rank:             rankKey{hostRank: exactHostRank},
			allow:            true,
			grantID:          g.ID,
			allowWebSocket:   g.AllowWebSocket,
			wsMaxEgressBytes: cs.wsDefault,
		}
		if !hasBest || c.beats(best) {
			best = c
			hasBest = true
		}
	}

	if !hasBest {
		return Decision{Allow: false, Reason: "default-deny", HasBindings: hasBindings}
	}
	if !best.allow {
		return Decision{Allow: false, RuleID: best.ruleID, Reason: "rule-deny", HasBindings: hasBindings}
	}
	reason := "rule-allow"
	if best.grantID != "" {
		reason = "grant-allow"
	}
	return Decision{
		Allow:            true,
		RuleID:           best.ruleID,
		GrantID:          best.grantID,
		Reason:           reason,
		AllowWebSocket:   best.allowWebSocket && !hasBindings,
		WSMaxEgressBytes: best.wsMaxEgressBytes,
		HasBindings:      hasBindings,
	}
}

// DecideRequest evaluates an HTTP request for (principal, rawHost, port, method, path).
func (e *Evaluator) DecideRequest(principal, rawHost string, port uint16, method, reqPath string) Decision {
	if port != 80 && port != 443 {
		return Decision{Allow: false, Reason: "port-denied"}
	}
	host, ok := normalizeLookupHost(rawHost)
	if !ok {
		return Decision{Allow: false, Reason: "invalid-host"}
	}
	if !strings.HasPrefix(reqPath, "/") {
		return Decision{Allow: false, Reason: "invalid-path"}
	}
	methodUpper := strings.ToUpper(method)

	cs := e.currentCompiled()
	grants := e.store.ActiveGrants()
	hostBindings := slices.Clone(cs.boundHosts[principal][host])
	hasBindings := len(hostBindings) > 0

	var best candidate
	hasBest := false

	for _, r := range cs.byPrincipal[principal] {
		if !slices.Contains(r.ports, port) {
			continue
		}
		hr, matched := matchHosts(r.hosts, host)
		if !matched {
			continue
		}
		if len(r.methods) > 0 && !slices.Contains(r.methods, methodUpper) {
			continue
		}
		pathSpec, pathMatched := matchPaths(r.paths, reqPath)
		if !pathMatched {
			continue
		}
		wsCap := r.wsMaxEgressBytes
		if wsCap == 0 {
			wsCap = cs.wsDefault
		}
		rk := rankKey{
			hostRank:        hr,
			methodSpecified: len(r.methods) > 0,
			pathSpecified:   len(r.paths) > 0,
			pathSpecificity: pathSpec,
		}
		c := candidate{
			rank:             rk,
			allow:            r.allow,
			ruleID:           r.id,
			allowWebSocket:   r.allowWebSocket,
			wsMaxEgressBytes: wsCap,
			bindings:         r.bindings,
		}
		if !hasBest || c.beats(best) {
			best = c
			hasBest = true
		}
	}

	for _, g := range grants {
		if g.Principal != principal || g.Port != port || g.Host != host {
			continue
		}
		if len(g.Methods) > 0 && !slices.Contains(g.Methods, methodUpper) {
			continue
		}
		pathSpec, pathMatched := matchPaths(g.Paths, reqPath)
		if !pathMatched {
			continue
		}
		rk := rankKey{
			hostRank:        exactHostRank,
			methodSpecified: len(g.Methods) > 0,
			pathSpecified:   len(g.Paths) > 0,
			pathSpecificity: pathSpec,
		}
		c := candidate{
			rank:             rk,
			allow:            true,
			grantID:          g.ID,
			allowWebSocket:   g.AllowWebSocket,
			wsMaxEgressBytes: cs.wsDefault,
		}
		if !hasBest || c.beats(best) {
			best = c
			hasBest = true
		}
	}

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
	if best.ruleID != "" {
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

func matchGlob(pat, val string) bool {
	for len(pat) > 0 {
		if strings.HasPrefix(pat, "**") {
			rest := pat[2:]
			if rest == "" {
				return true
			}
			for i := 0; i <= len(val); i++ {
				if matchGlob(rest, val[i:]) {
					return true
				}
			}
			return false
		}
		if pat[0] == '*' {
			rest := pat[1:]
			for i := 0; i <= len(val); i++ {
				if i > 0 && val[i-1] == '/' {
					break
				}
				if matchGlob(rest, val[i:]) {
					return true
				}
			}
			return false
		}
		if len(val) == 0 || pat[0] != val[0] {
			return false
		}
		pat = pat[1:]
		val = val[1:]
	}
	return len(val) == 0
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
