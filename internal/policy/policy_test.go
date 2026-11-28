// SPDX-License-Identifier: AGPL-3.0-only

package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/policy"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func makeStore(t *testing.T, yamlBody string, nowFn func() time.Time) *config.Store {
	t.Helper()
	p := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.WriteFile(p, []byte(yamlBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	st, err := config.NewStoreWithClock(p, nowFn)
	if err != nil {
		t.Fatalf("NewStoreWithClock: %v", err)
	}
	return st
}

const policyYAML = `
ca:
  cert_path: /tmp/ca.crt
  key_path: /tmp/ca.key
audit:
  dir: /tmp/audit
dataplane:
  ready_file: /run/gateway-dataplane/dataplane.ready
  dhcp: {user: dnsmasq, lease_file: /var/lib/gateway/dnsmasq.leases}
links:
  - name: sbx0
    interface: t216
    ct_zone: 216
    route_table: 216
    principal: worker-a
    subnet: 127.0.10.0/28
    gateway_ip: 127.0.10.1
  - name: sbx1
    interface: t217
    ct_zone: 217
    route_table: 217
    principal: worker-b
    subnet: 127.0.20.0/28
    gateway_ip: 127.0.20.1
rules:
  - id: allow-wildcard
    principal: worker-a
    effect: allow
    hosts: ["*.example.com"]
    ports: [443]
    methods: [GET, POST]
    paths: ["/v1/**"]
  - id: deny-sub
    principal: worker-a
    effect: deny
    hosts: ["secret.example.com"]
    ports: [443]
  - id: allow-tie
    principal: worker-a
    effect: allow
    hosts: ["tie.example.com"]
    ports: [443]
  - id: deny-tie
    principal: worker-a
    effect: deny
    hosts: ["tie.example.com"]
    ports: [443]
  - id: allow-cleartext
    principal: worker-a
    effect: allow
    hosts: ["deb.debian.org"]
    ports: [80]
  - id: allow-bound
    principal: worker-a
    effect: allow
    hosts: ["code.lan.example"]
    ports: [443, 80]
    methods: [GET, POST]
    paths: ["/**"]
    bindings:
      - name: forge-tok
        host: code.lan.example
        methods: [POST]
        paths: ["/api/**"]
        header: Authorization
        scheme: bearer
        placeholder: mf_ph_forge
        secret_file: /tmp/secret
  - id: allow-ws
    principal: worker-b
    effect: allow
    hosts: ["chatgpt.com"]
    ports: [443]
    allow_websocket: true
    ws_max_egress_bytes: 1048576
`

func TestPolicySpecificityDenyTiesAndIsolation(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	st := makeStore(t, policyYAML, func() time.Time { return now })
	ev := policy.NewEvaluator(st)

	// Positive control: wildcard allows matching host/method/path on 443.
	if d := ev.DecideRequest("worker-a", "api.example.com", 443, "POST", "/v1/messages"); !d.Allow || d.RuleID != "allow-wildcard" {
		t.Fatalf("expected allow-wildcard, got %+v", d)
	}

	// Containment: exact deny beats wildcard allow.
	if d := ev.DecideRequest("worker-a", "secret.example.com", 443, "GET", "/v1/messages"); d.Allow || d.RuleID != "deny-sub" {
		t.Fatalf("expected deny-sub to beat wildcard allow, got %+v", d)
	}
	if d := ev.DecideDNS("worker-a", "secret.example.com"); d.Allow {
		t.Fatalf("expected DNS deny for secret.example.com, got %+v", d)
	}

	// Containment: on exact rank tie, deny beats allow.
	if d := ev.DecideRequest("worker-a", "tie.example.com", 443, "GET", "/"); d.Allow || d.RuleID != "deny-tie" {
		t.Fatalf("expected deny-tie to beat allow-tie, got %+v", d)
	}

	// Containment: method and path enforcement.
	if d := ev.DecideRequest("worker-a", "api.example.com", 443, "DELETE", "/v1/messages"); d.Allow {
		t.Fatalf("expected DELETE denied, got %+v", d)
	}
	if d := ev.DecideRequest("worker-a", "api.example.com", 443, "GET", "/v2/other"); d.Allow {
		t.Fatalf("expected /v2/other denied, got %+v", d)
	}

	// Containment: port 80 denied unless explicitly opted in; positive control on deb.debian.org:80.
	if d := ev.DecideRequest("worker-a", "api.example.com", 80, "GET", "/v1/messages"); d.Allow {
		t.Fatalf("expected port 80 denied on 443-only rule, got %+v", d)
	}
	if d := ev.DecideRequest("worker-a", "deb.debian.org", 80, "GET", "/debian"); !d.Allow {
		t.Fatalf("expected deb.debian.org:80 allowed, got %+v", d)
	}
	if d := ev.DecideRequest("worker-a", "deb.debian.org", 443, "GET", "/debian"); d.Allow {
		t.Fatalf("expected deb.debian.org:443 denied on 80-only rule, got %+v", d)
	}

	// Containment: principal isolation.
	if d := ev.DecideRequest("worker-b", "api.example.com", 443, "GET", "/v1/messages"); d.Allow {
		t.Fatalf("worker-b must not inherit worker-a rules: %+v", d)
	}
	if d := ev.DecideRequest("worker-b", "chatgpt.com", 443, "GET", "/backend-api/codex/responses"); !d.Allow || !d.AllowWebSocket || d.WSMaxEgressBytes != 1048576 {
		t.Fatalf("expected worker-b ws allow, got %+v", d)
	}

	// Containment: bindings match ONLY on port 443 and ONLY under their owning rule; HasBindings true for host.
	if d := ev.DecideRequest("worker-a", "code.lan.example", 80, "POST", "/api/v1"); !d.Allow || len(d.MatchedBindings) != 0 {
		t.Fatalf("bindings must never match port 80, got %+v", d)
	}
	if d := ev.DecideRequest("worker-a", "code.lan.example", 443, "POST", "/api/v1"); !d.Allow || len(d.MatchedBindings) != 1 || len(d.HostBindings) != 1 {
		t.Fatalf("expected 1 matched and host binding on 443 POST /api/v1, got %+v", d)
	}
	if d := ev.DecideRequest("worker-a", "code.lan.example", 443, "GET", "/other"); !d.Allow || !d.HasBindings || len(d.MatchedBindings) != 0 || len(d.HostBindings) != 1 {
		t.Fatalf("expected HasBindings=true and 0 matched bindings on GET /other, got %+v", d)
	}

	// Ephemeral TTL grant lifecycle: allow while active, deny beats grant on tie, deny after expiry.
	g, err := st.AddGrant("worker-b", "login.openai.com", 443, []string{"GET"}, []string{"/oauth/**"}, 2*time.Minute, false)
	if err != nil {
		t.Fatalf("AddGrant: %v", err)
	}
	if d := ev.DecideRequest("worker-b", "login.openai.com", 443, "GET", "/oauth/callback"); !d.Allow || d.GrantID != g.ID {
		t.Fatalf("expected grant allow, got %+v", d)
	}
	if d := ev.DecideRequest("worker-b", "login.openai.com", 443, "POST", "/oauth/callback"); d.Allow {
		t.Fatalf("expected POST denied outside grant methods, got %+v", d)
	}
	now = now.Add(3 * time.Minute)
	if d := ev.DecideRequest("worker-b", "login.openai.com", 443, "GET", "/oauth/callback"); d.Allow {
		t.Fatalf("expected expired grant denied, got %+v", d)
	}

	// Explicit YAML deny still beats an ephemeral grant on the exact same host.
	if _, err := st.AddGrant("worker-a", "secret.example.com", 443, nil, nil, 5*time.Minute, false); err != nil {
		t.Fatalf("AddGrant on denied host: %v", err)
	}
	if d := ev.DecideRequest("worker-a", "secret.example.com", 443, "GET", "/"); d.Allow {
		t.Fatalf("explicit YAML deny must beat ephemeral grant, got %+v", d)
	}
}

func TestGlobPatternWorstCaseUnder10ms(t *testing.T) {
	yamlCfg := `
ca:
  cert_path: /tmp/ca.crt
  key_path: /tmp/ca.key
audit:
  dir: /tmp/audit
dataplane:
  ready_file: /run/gateway-dataplane/dataplane.ready
  dhcp: {user: dnsmasq, lease_file: /var/lib/gateway/dnsmasq.leases}
links:
  - name: sbx0
    interface: t218
    ct_zone: 218
    route_table: 218
    principal: worker-a
    subnet: 127.0.10.0/28
    gateway_ip: 127.0.10.1
rules:
  - id: worst-glob
    principal: worker-a
    effect: allow
    hosts: ["glob.example.com"]
    ports: [443]
    paths: ["/**a*a*a*a*Z", "/*a*a*a*Z"]
`
	st := makeStore(t, yamlCfg, time.Now)
	ev := policy.NewEvaluator(st)

	path32K := "/" + strings.Repeat("a", 32<<10)
	start := time.Now()
	d := ev.DecideRequest("worker-a", "glob.example.com", 443, "GET", path32K)
	elapsed := time.Since(start)
	if d.Allow {
		t.Fatal("expected non-matching 32 KiB path to be denied")
	}
	if elapsed >= 10*time.Millisecond {
		t.Fatalf("worst allowed glob on 32 KiB non-matching path took %v, want < 10ms", elapsed)
	}
}

func TestGrantIsolationBetweenPrincipals(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	st := makeStore(t, policyYAML, func() time.Time { return now })
	ev := policy.NewEvaluator(st)

	g, err := st.AddGrant("worker-a", "iso-grant.example.com", 443, []string{"GET"}, []string{"/only-a"}, 5*time.Minute, false)
	if err != nil {
		t.Fatalf("AddGrant: %v", err)
	}

	if d := ev.DecideHost("worker-a", "iso-grant.example.com", 443); !d.Allow || d.GrantID != g.ID {
		t.Fatalf("worker-a host-scope grant allow failed: %+v", d)
	}
	if d := ev.DecideRequest("worker-a", "iso-grant.example.com", 443, "GET", "/only-a"); !d.Allow || d.GrantID != g.ID {
		t.Fatalf("worker-a request-scope grant allow failed: %+v", d)
	}

	if d := ev.DecideHost("worker-b", "iso-grant.example.com", 443); d.Allow {
		t.Fatalf("worker-b must not be admitted at host scope by worker-a grant: %+v", d)
	}
	if d := ev.DecideRequest("worker-b", "iso-grant.example.com", 443, "GET", "/only-a"); d.Allow {
		t.Fatalf("worker-b must not be admitted at request scope by worker-a grant: %+v", d)
	}
}

func TestWebSocketDeniedOnBoundHostPolicyDefenseInDepth(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	st := makeStore(t, policyYAML, func() time.Time { return now })
	// Mutate loaded config in-memory to exercise policy.Evaluator's !hasBindings defense-in-depth.
	for i := range st.Current().Config.Rules {
		if st.Current().Config.Rules[i].ID == "allow-bound" {
			st.Current().Config.Rules[i].AllowWebSocket = true
		}
	}
	ev := policy.NewEvaluator(st)

	if d := ev.DecideHost("worker-a", "code.lan.example", 443); !d.Allow || !d.HasBindings || d.AllowWebSocket {
		t.Fatalf("DecideHost must set AllowWebSocket=false when HasBindings=true, got %+v", d)
	}
	if d := ev.DecideRequest("worker-a", "code.lan.example", 443, "GET", "/ws"); !d.Allow || !d.HasBindings || d.AllowWebSocket {
		t.Fatalf("DecideRequest must set AllowWebSocket=false when HasBindings=true, got %+v", d)
	}
}

func TestHostDenyBeatsPathScopedAllowAndDecideDNSPreservesRuleDeny(t *testing.T) {
	yamlCfg := `
ca:
  cert_path: /tmp/ca.crt
  key_path: /tmp/ca.key
audit:
  dir: /tmp/audit
dataplane:
  ready_file: /run/gateway-dataplane/dataplane.ready
  dhcp: {user: dnsmasq, lease_file: /var/lib/gateway/dnsmasq.leases}
links:
  - name: sbx0
    interface: t219
    ct_zone: 219
    route_table: 219
    principal: worker-a
    subnet: 127.0.10.0/28
    gateway_ip: 127.0.10.1
rules:
  - id: deny-example
    principal: worker-a
    effect: deny
    hosts: ["example.com"]
    ports: [443]
  - id: allow-example-ok
    principal: worker-a
    effect: allow
    hosts: ["example.com"]
    ports: [443]
    paths: ["/ok"]
  - id: allow-free-ok
    principal: worker-a
    effect: allow
    hosts: ["free.example.org"]
    ports: [443]
    paths: ["/ok"]
  - id: deny-blocked
    principal: worker-a
    effect: deny
    hosts: ["blocked.example.com"]
    ports: [443]
`
	st := makeStore(t, yamlCfg, time.Now)
	ev := policy.NewEvaluator(st)

	// A host-wide deny is absolute: the narrower path-scoped allow on the same
	// host changes nothing at DNS, SNI or request scope.
	if d := ev.DecideDNS("worker-a", "example.com"); d.Allow || d.Reason != "rule-deny" || d.RuleID != "deny-example" {
		t.Fatalf("DecideDNS(example.com) = %+v, want rule-deny by deny-example", d)
	}
	if d := ev.DecideHost("worker-a", "example.com", 443); d.Allow || d.RuleID != "deny-example" {
		t.Fatalf("DecideHost(example.com, 443) = %+v, want rule-deny by deny-example", d)
	}
	for _, reqPath := range []string{"/ok", "/other"} {
		if d := ev.DecideRequest("worker-a", "example.com", 443, "GET", reqPath); d.Allow || d.Reason != "rule-deny" || d.RuleID != "deny-example" {
			t.Fatalf("DecideRequest(%s) = %+v, want rule-deny by deny-example", reqPath, d)
		}
	}
	// Positive control: the same allow, on a host with no deny, admits /ok and only /ok.
	if d := ev.DecideRequest("worker-a", "free.example.org", 443, "GET", "/ok"); !d.Allow || d.RuleID != "allow-free-ok" {
		t.Fatalf("DecideRequest(free.example.org /ok) = %+v, want allow by allow-free-ok", d)
	}
	if d := ev.DecideRequest("worker-a", "free.example.org", 443, "GET", "/other"); d.Allow {
		t.Fatalf("DecideRequest(free.example.org /other) = %+v, want denied", d)
	}

	// Explicit rule-deny is preserved by DecideDNS instead of collapsing to default-deny.
	if d := ev.DecideDNS("worker-a", "blocked.example.com"); d.Allow || d.Reason != "rule-deny" || d.RuleID != "deny-blocked" {
		t.Fatalf("DecideDNS(blocked.example.com) = %+v, want reason=rule-deny rule_id=deny-blocked", d)
	}
	if d := ev.DecideDNS("worker-a", "unknown.example.com"); d.Allow || d.Reason != "default-deny" || d.RuleID != "" {
		t.Fatalf("DecideDNS(unknown.example.com) = %+v, want reason=default-deny", d)
	}
}

func twoPrincipalEvaluator(t *testing.T) *policy.Evaluator {
	t.Helper()
	long := "/" + strings.Repeat("a", 80)
	cfg := `
ca: {cert_path: /tmp/ca.crt, key_path: /tmp/ca.key}
audit: {dir: /tmp/audit}
dataplane:
  ready_file: /run/gateway-dataplane/dataplane.ready
  dhcp: {user: dnsmasq, lease_file: /var/lib/gateway/dnsmasq.leases}
links:
  - {name: a, principal: alice, subnet: 127.9.1.0/28, gateway_ip: 127.9.1.1, interface: t220, ct_zone: 220, route_table: 220}
  - {name: b, principal: bob, subnet: 127.9.2.0/28, gateway_ip: 127.9.2.1, interface: t221, ct_zone: 221, route_table: 221}
rules:
  - id: alice-bound
    principal: alice
    effect: allow
    hosts: [api.example.com]
    bindings:
      - {name: k, host: api.example.com, header: Authorization, scheme: bearer, placeholder: mf_ph_k, secret_file: /tmp/k}
  - id: bob-open
    principal: bob
    effect: allow
    hosts: [api.example.com]
  - id: bob-long
    principal: bob
    effect: allow
    hosts: [long.example.com]
    paths: ["` + long + `/*"]
`
	path := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	store, err := config.NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	for i := range store.Current().Config.Rules {
		if store.Current().Config.Rules[i].ID == "bob-open" {
			store.Current().Config.Rules[i].AllowWebSocket = true
		}
	}
	return policy.NewEvaluator(store)
}

func TestLongPathGlobStillRejects(t *testing.T) {
	eval := twoPrincipalEvaluator(t)
	long := "/" + strings.Repeat("a", 80)
	if d := eval.DecideRequest("bob", "long.example.com", 443, "GET", long+"/x"); !d.Allow {
		t.Fatalf("long pattern should match: %+v", d)
	}
	for _, reqPath := range []string{long, long + "/x/y", "/other"} {
		if d := eval.DecideRequest("bob", "long.example.com", 443, "GET", reqPath); d.Allow {
			t.Fatalf("long pattern admitted %q", reqPath)
		}
	}
}

func TestHostBindingsCoverEveryPrincipal(t *testing.T) {
	eval := twoPrincipalEvaluator(t)
	d := eval.DecideRequest("bob", "api.example.com", 443, "GET", "/")
	if !d.Allow || !d.HasBindings || len(d.HostBindings) != 1 || len(d.MatchedBindings) != 0 || d.AllowWebSocket {
		t.Fatalf("bob on alice's bound host = %+v; want redaction bindings, no substitution, no websocket", d)
	}
}
