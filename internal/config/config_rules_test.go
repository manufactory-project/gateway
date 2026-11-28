// SPDX-License-Identifier: AGPL-3.0-only

package config_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/manufactory-project/gateway/internal/config"
)

// rulesYAML swaps the rules of validYAML for the given block.
func rulesYAML(t *testing.T, rules string) string {
	t.Helper()
	i := strings.Index(validYAML, "rules:\n")
	if i < 0 {
		t.Fatal("validYAML has no rules block")
	}
	return validYAML[:i] + "rules:\n" + rules
}

func parseRules(t *testing.T, rules string) (*config.Config, error) {
	t.Helper()
	return config.Parse([]byte(rulesYAML(t, rules)))
}

func TestRulePortDefaultsDependOnEffect(t *testing.T) {
	cfg, err := parseRules(t, `
  - {id: allow-default, principal: worker-claude, effect: allow, hosts: [a.example.com]}
  - {id: deny-default, principal: worker-claude, effect: deny, hosts: [b.example.com]}
  - {id: deny-443, principal: worker-claude, effect: deny, hosts: [c.example.com], ports: [443]}
  - {id: allow-both, principal: worker-claude, effect: allow, hosts: [d.example.com], ports: [80, 443]}
`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := map[string][]uint16{
		"allow-default": {443},
		"deny-default":  {80, 443}, // a deny must cover every port the gateway serves
		"deny-443":      {443},
		"allow-both":    {80, 443},
	}
	for _, r := range cfg.Rules {
		if !slices.Equal(r.Ports, want[r.ID]) {
			t.Errorf("rule %s ports = %v, want %v", r.ID, r.Ports, want[r.ID])
		}
	}
}

func TestExplicitEmptyListsAreErrors(t *testing.T) {
	for _, tc := range []struct{ name, rule, want string }{
		{"hosts", `{id: r, principal: worker-claude, effect: deny, hosts: []}`, "hosts must not be empty"},
		{"ports", `{id: r, principal: worker-claude, effect: deny, hosts: [a.example.com], ports: []}`, "ports must not be an empty list"},
		{"methods", `{id: r, principal: worker-claude, effect: deny, hosts: [a.example.com], methods: []}`, "methods must not be an empty list"},
		{"paths", `{id: r, principal: worker-claude, effect: deny, hosts: [a.example.com], paths: []}`, "paths must not be an empty list"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRules(t, "  - "+tc.rule+"\n")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse err = %v, want %q", err, tc.want)
			}
		})
	}
	for _, field := range []string{"methods", "paths"} {
		t.Run("binding "+field, func(t *testing.T) {
			rule := `
  - id: r
    principal: worker-claude
    effect: allow
    hosts: [a.example.com]
    bindings:
      - {name: b, host: a.example.com, header: Authorization, scheme: bearer, placeholder: mf_ph_x, secret_file: /run/s, ` + field + `: []}
`
			_, err := parseRules(t, rule)
			if err == nil || !strings.Contains(err.Error(), field+" must not be an empty list") {
				t.Fatalf("Parse err = %v, want an empty-%s error", err, field)
			}
		})
	}
	// Positive control: omitting the keys is fine and means "any".
	if _, err := parseRules(t, "  - {id: r, principal: worker-claude, effect: deny, hosts: [a.example.com]}\n"); err != nil {
		t.Fatalf("omitted lists rejected: %v", err)
	}
}

func TestAuditFileSizeMustNotExceedTotal(t *testing.T) {
	bad := strings.Replace(validYAML, "audit:\n", "audit:\n  max_file_bytes: 2000\n  max_total_bytes: 1000\n", 1)
	if _, err := config.Parse([]byte(bad)); err == nil || !strings.Contains(err.Error(), "max_file_bytes") {
		t.Fatalf("Parse err = %v, want a max_file_bytes error", err)
	}
	good := strings.Replace(validYAML, "audit:\n", "audit:\n  max_file_bytes: 1000\n  max_total_bytes: 1000\n", 1)
	if _, err := config.Parse([]byte(good)); err != nil {
		t.Fatalf("equal limits rejected: %v", err)
	}
}

func TestFakeCIDRMustNotOverlapLinks(t *testing.T) {
	for _, cidr := range []string{"10.200.0.0/24", "10.200.0.16/28", "10.0.0.0/8"} {
		yaml := strings.Replace(validYAML, "links:\n", "dns:\n  fake_cidr: "+cidr+"\nlinks:\n", 1)
		if _, err := config.Parse([]byte(yaml)); err == nil || !strings.Contains(err.Error(), "overlaps link") {
			t.Errorf("fake_cidr %s: err = %v, want an overlap error", cidr, err)
		}
	}
	for _, cidr := range []string{"198.18.0.0/15", "100.64.0.0/10", "10.201.0.0/24"} {
		yaml := strings.Replace(validYAML, "links:\n", "dns:\n  fake_cidr: "+cidr+"\nlinks:\n", 1)
		if _, err := config.Parse([]byte(yaml)); err != nil {
			t.Errorf("fake_cidr %s rejected: %v", cidr, err)
		}
	}
}

const pinRule = `
  - id: forge
    principal: worker-claude
    effect: allow
    hosts: [forge.internal.example, "*.lan.example"]
    pins:
      %s
`

func TestPinValidation(t *testing.T) {
	accepted := []string{
		"10.10.20.5", "172.16.0.9", "192.168.1.20", // RFC 1918
		"100.64.0.7",           // CGNAT (Tailscale)
		"fd00::20",             // ULA
		"2606:4700:4700::1111", // global unicast
		"::ffff:10.10.20.5",    // v4-mapped, unmapped before the checks
	}
	for _, ip := range accepted {
		cfg, err := parseRules(t, strings.Replace(pinRule, "%s", "forge.internal.example: \""+ip+"\"", 1))
		if err != nil {
			t.Errorf("pin %s rejected: %v", ip, err)
			continue
		}
		if cfg.Rules[0].ParsedPins["forge.internal.example"].Is4In6() {
			t.Errorf("pin %s was not unmapped", ip)
		}
	}

	rejected := map[string]string{
		"127.0.0.1":        "global unicast",
		"127.8.9.10":       "global unicast",
		"0.0.0.0":          "global unicast",
		"0.1.2.3":          "global unicast",
		"169.254.169.254":  "global unicast",
		"224.0.0.1":        "global unicast",
		"255.255.255.255":  "global unicast",
		"::1":              "global unicast",
		"::":               "global unicast",
		"fe80::1":          "global unicast",
		"ff02::1":          "global unicast",
		"::ffff:127.0.0.1": "global unicast",
		"64:ff9b::a00:1":   "IPv6 must be",
		"198.18.5.5":       "dns.fake_cidr", // inside the default fake range
		"10.200.0.1":       "link",          // a link gateway_ip
		"10.200.0.20":      "link",          // inside a link subnet
		"not-an-ip":        "invalid IP",
	}
	for ip, want := range rejected {
		_, err := parseRules(t, strings.Replace(pinRule, "%s", "forge.internal.example: \""+ip+"\"", 1))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("pin %s: err = %v, want %q", ip, err, want)
		}
	}
}

func TestPinHostMustBeCoveredByRule(t *testing.T) {
	// Covered by a wildcard host of the rule: fine.
	if _, err := parseRules(t, strings.Replace(pinRule, "%s", "git.lan.example: 10.10.20.5", 1)); err != nil {
		t.Fatalf("pin under the rule's wildcard rejected: %v", err)
	}
	for _, host := range []string{"other.example.com", "*.lan.example", "lan.example"} {
		_, err := parseRules(t, strings.Replace(pinRule, "%s", host+": 10.10.20.5", 1))
		if err == nil {
			t.Errorf("pin for %q not covered by the rule was accepted", host)
		}
	}
}

func wildcardRule(host string) string {
	return fmt.Sprintf("  - {id: r, principal: worker-claude, effect: allow, hosts: [%q]}\n", host)
}

func TestWildcardOverPublicSuffixRefused(t *testing.T) {
	for _, host := range []string{"*.co.uk", "*.github.io", "*.com", "*.s3.amazonaws.com"} {
		if _, err := parseRules(t, wildcardRule(host)); err == nil {
			t.Errorf("wildcard %s was accepted", host)
		}
	}
	// A wildcard over a registrable domain, public or internal, is fine.
	for _, host := range []string{"*.example.com", "*.example.co.uk", "*.lan.example", "*.corp.internal"} {
		if _, err := parseRules(t, wildcardRule(host)); err != nil {
			t.Errorf("wildcard %s rejected: %v", host, err)
		}
	}
	// Exact hosts are never affected.
	if _, err := parseRules(t, wildcardRule("example.co.uk")); err != nil {
		t.Errorf("exact host rejected: %v", err)
	}
}
