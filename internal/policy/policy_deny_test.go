// SPDX-License-Identifier: AGPL-3.0-only

package policy_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/policy"
)

const denyHeader = `
ca: {cert_path: /tmp/ca.crt, key_path: /tmp/ca.key}
audit: {dir: /tmp/audit}
dataplane:
  ready_file: /run/gateway-dataplane/dataplane.ready
  dhcp: {user: dnsmasq, lease_file: /var/lib/gateway/dnsmasq.leases}
links:
  - {name: a, principal: alice, subnet: 127.9.1.0/28, gateway_ip: 127.9.1.1, interface: t230, ct_zone: 230, route_table: 230}
  - {name: b, principal: bob, subnet: 127.9.2.0/28, gateway_ip: 127.9.2.1, interface: t231, ct_zone: 231, route_table: 231}
rules:
`

func denyEvaluator(t *testing.T, rules string) (*policy.Evaluator, func(principal, host string, ports []uint16, methods, paths []string) (string, error)) {
	t.Helper()
	st := makeStore(t, denyHeader+rules, time.Now)
	grant := func(principal, host string, ports []uint16, methods, paths []string) (string, error) {
		g, err := st.AddGrant(principal, host, ports[0], methods, paths, time.Minute, false)
		return g.ID, err
	}
	return policy.NewEvaluator(st), grant
}

// A deny rule without ports covers every port the gateway serves, even though
// the allow beside it lists both.
func TestDenyWithoutPortsCoversPort80AndDNS(t *testing.T) {
	ev, _ := denyEvaluator(t, `
  - {id: allow-zone, principal: alice, effect: allow, hosts: ["*.example.com"], ports: [80, 443]}
  - {id: deny-evil, principal: alice, effect: deny, hosts: [evil.example.com]}
`)
	for _, port := range []uint16{80, 443} {
		if d := ev.DecideRequest("alice", "evil.example.com", port, "GET", "/"); d.Allow || d.RuleID != "deny-evil" {
			t.Errorf("evil.example.com:%d = %+v, want rule-deny by deny-evil", port, d)
		}
		if d := ev.DecideHost("alice", "evil.example.com", port); d.Allow || d.RuleID != "deny-evil" {
			t.Errorf("DecideHost evil.example.com:%d = %+v, want rule-deny by deny-evil", port, d)
		}
	}
	if d := ev.DecideDNS("alice", "evil.example.com"); d.Allow || d.Reason != "rule-deny" || d.RuleID != "deny-evil" {
		t.Errorf("DecideDNS(evil.example.com) = %+v, want rule-deny by deny-evil", d)
	}

	// Positive control: the rest of the zone resolves and is reachable on both ports.
	for _, port := range []uint16{80, 443} {
		if d := ev.DecideRequest("alice", "good.example.com", port, "GET", "/"); !d.Allow || d.RuleID != "allow-zone" {
			t.Errorf("good.example.com:%d = %+v, want allow by allow-zone", port, d)
		}
	}
	if d := ev.DecideDNS("alice", "good.example.com"); !d.Allow {
		t.Errorf("DecideDNS(good.example.com) = %+v, want allow", d)
	}
	// A deny does not leak to another principal.
	if d := ev.DecideDNS("bob", "evil.example.com"); d.Reason != "default-deny" {
		t.Errorf("bob DecideDNS(evil.example.com) = %+v, want default-deny (bob has no rules)", d)
	}
}

// Any matching deny wins, however specific the allow or grant it meets.
func TestDenyBeatsEveryMoreSpecificAllowAndGrant(t *testing.T) {
	ev, grant := denyEvaluator(t, `
  - {id: deny-host, principal: alice, effect: deny, hosts: [api.example.com]}
  - {id: allow-exact-path, principal: alice, effect: allow, hosts: [api.example.com], methods: [GET], paths: ["/v1/exact"]}
  - {id: allow-all-paths, principal: alice, effect: allow, hosts: [api.example.com], paths: ["/**"]}
  - id: deny-delete
    principal: alice
    effect: deny
    hosts: [files.example.com]
    methods: [DELETE]
  - {id: allow-files, principal: alice, effect: allow, hosts: [files.example.com], paths: ["/**"]}
  - {id: allow-ok, principal: alice, effect: allow, hosts: [ok.example.com]}
`)
	gid, err := grant("alice", "api.example.com", []uint16{443}, nil, []string{"/**"})
	if err != nil {
		t.Fatalf("AddGrant: %v", err)
	}
	for _, path := range []string{"/", "/v1/exact", "/anything/at/all"} {
		d := ev.DecideRequest("alice", "api.example.com", 443, "GET", path)
		if d.Allow || d.RuleID != "deny-host" || d.GrantID != "" {
			t.Errorf("GET %s with allow rules and grant %s = %+v, want rule-deny by deny-host", path, gid, d)
		}
	}

	// A deny on one method does not touch the others: DELETE denied, GET allowed.
	if d := ev.DecideRequest("alice", "files.example.com", 443, "DELETE", "/x"); d.Allow || d.RuleID != "deny-delete" {
		t.Errorf("DELETE = %+v, want rule-deny by deny-delete", d)
	}
	if d := ev.DecideRequest("alice", "files.example.com", 443, "GET", "/x"); !d.Allow || d.RuleID != "allow-files" {
		t.Errorf("GET = %+v, want allow by allow-files", d)
	}
	// A method-scoped deny never blocks the host itself (DNS, SNI).
	if d := ev.DecideDNS("alice", "files.example.com"); !d.Allow {
		t.Errorf("DecideDNS(files.example.com) = %+v, want allow", d)
	}

	// Positive control: with no deny, the same shape of allow admits the request.
	if d := ev.DecideRequest("alice", "ok.example.com", 443, "GET", "/"); !d.Allow || d.RuleID != "allow-ok" {
		t.Errorf("ok.example.com = %+v, want allow by allow-ok", d)
	}
}

// A pin travels on the Decision of the rule that owns it, and only that one.
func TestPinOnlyReachesRequestsDecidedByItsRule(t *testing.T) {
	ev, grant := denyEvaluator(t, `
  - id: pinned
    principal: alice
    effect: allow
    hosts: [forge.lan.example]
    paths: ["/pinned/**"]
    pins: {forge.lan.example: 10.10.20.5}
  - {id: plain, principal: alice, effect: allow, hosts: [forge.lan.example], paths: ["/plain/**"]}
  - {id: bob-plain, principal: bob, effect: allow, hosts: [forge.lan.example]}
  - id: pinned-other-host
    principal: alice
    effect: allow
    hosts: ["*.lan.example"]
    pins: {git.lan.example: 10.10.20.6}
`)
	want := netip.MustParseAddr("10.10.20.5")

	if d := ev.DecideRequest("alice", "forge.lan.example", 443, "GET", "/pinned/x"); !d.Allow || d.RuleID != "pinned" || d.PinnedIP != want {
		t.Errorf("pinned rule decision = %+v, want rule pinned with pin %s", d, want)
	}
	// Same principal and host, decided by another rule: no pin.
	if d := ev.DecideRequest("alice", "forge.lan.example", 443, "GET", "/plain/x"); !d.Allow || d.RuleID != "plain" || d.PinnedIP.IsValid() {
		t.Errorf("sibling rule decision = %+v, want rule plain without a pin", d)
	}
	// Another principal on the same host: no pin.
	if d := ev.DecideRequest("bob", "forge.lan.example", 443, "GET", "/pinned/x"); !d.Allow || d.PinnedIP.IsValid() {
		t.Errorf("bob decision = %+v, want allow without a pin", d)
	}
	// A pin is for its exact host: a sibling host under the rule's wildcard is not pinned.
	if d := ev.DecideRequest("alice", "git.lan.example", 443, "GET", "/"); !d.Allow || d.PinnedIP != netip.MustParseAddr("10.10.20.6") {
		t.Errorf("git.lan.example decision = %+v, want pin 10.10.20.6", d)
	}
	if d := ev.DecideRequest("alice", "wiki.lan.example", 443, "GET", "/"); !d.Allow || d.PinnedIP.IsValid() {
		t.Errorf("wiki.lan.example decision = %+v, want allow without a pin", d)
	}
	// A grant never carries a pin, even on a pinned host.
	if _, err := grant("alice", "forge.lan.example", []uint16{443}, nil, []string{"/granted/**"}); err != nil {
		t.Fatalf("AddGrant: %v", err)
	}
	if d := ev.DecideRequest("alice", "forge.lan.example", 443, "GET", "/granted/x"); !d.Allow || d.GrantID == "" || d.PinnedIP.IsValid() {
		t.Errorf("grant decision = %+v, want a grant allow without a pin", d)
	}
}

// "/x/**" covers "/x" itself, so a deny on a subtree cannot be sidestepped by
// naming its root, and an allow on a subtree admits its root.
func TestDoubleStarCoversItsOwnRoot(t *testing.T) {
	ev, _ := denyEvaluator(t, `
  - {id: allow-all, principal: alice, effect: allow, hosts: [api.example.com], paths: ["/**"]}
  - {id: deny-admin, principal: alice, effect: deny, hosts: [api.example.com], paths: ["/v1/admin/**"]}
  - {id: allow-docs, principal: bob, effect: allow, hosts: [api.example.com], paths: ["/docs/**"]}
`)
	for _, p := range []string{"/v1/admin", "/v1/admin/", "/v1/admin/x/y"} {
		if d := ev.DecideRequest("alice", "api.example.com", 443, "GET", p); d.Allow || d.RuleID != "deny-admin" {
			t.Errorf("GET %s = %+v, want rule-deny by deny-admin", p, d)
		}
	}
	// Positive controls: siblings and look-alikes stay open, and paths are case-sensitive.
	for _, p := range []string{"/v1/administrator", "/v1/other", "/v1/Admin", "/v1"} {
		if d := ev.DecideRequest("alice", "api.example.com", 443, "GET", p); !d.Allow || d.RuleID != "allow-all" {
			t.Errorf("GET %s = %+v, want allow by allow-all", p, d)
		}
	}
	for _, p := range []string{"/docs", "/docs/", "/docs/a"} {
		if d := ev.DecideRequest("bob", "api.example.com", 443, "GET", p); !d.Allow || d.RuleID != "allow-docs" {
			t.Errorf("bob GET %s = %+v, want allow by allow-docs", p, d)
		}
	}
	for _, p := range []string{"/docsx", "/doc", "/Docs"} {
		if d := ev.DecideRequest("bob", "api.example.com", 443, "GET", p); d.Allow {
			t.Errorf("bob GET %s = %+v, want denied", p, d)
		}
	}
}
