// SPDX-License-Identifier: AGPL-3.0-only

package proxy_test

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/manufactory-project/gateway/internal/audit"
)

// Tomcat, Spring and Jetty drop ";params" from path segments and some decode a
// second time, so "/v1/public/..;/admin" or "/v1/%252e%252e/admin" can reach
// "/admin" upstream after the gateway matched it against "/v1/**". Both
// ambiguities are refused outright.
func TestAmbiguousPathsRefusedBeforeUpstream(t *testing.T) {
	var upHits atomic.Int32
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"path.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			upHits.Add(1)
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: `
  - id: allow-v1
    principal: worker-test
    effect: allow
    hosts: [path.example.com]
    paths: ["/v1/**"]
`,
	})
	send := func(target string) (int, string) {
		return rawRequest(t, gw, "path.example.com", http.MethodGet, target)
	}

	// Positive control first: ordinary paths, including a single-encoded space and
	// a query string that holds ';' and an encoded escape, pass.
	// A "%25" not followed by two hex digits is a literal percent sign.
	for _, target := range []string{"/v1/public/ok", "/v1/a%20b", "/v1/ok?x=a;b%252e", "/v1/files/100%25", "/v1/files/a%25zz", "/v1/files/%25g1"} {
		if code, body := send(target); code != http.StatusOK {
			t.Fatalf("%s = %d %q, want 200", target, code, body)
		}
	}
	before := upHits.Load()

	refused := []struct{ target, reason string }{
		{"/v1/public/..;/admin", "semicolon-in-path"},
		{"/v1/public;jsessionid=1/x", "semicolon-in-path"},
		{"/v1/x;/y", "semicolon-in-path"},
		{"/v1/public/%3b/admin", "semicolon-in-path"},
		{"/v1/public/%3B/admin", "semicolon-in-path"},
		{"/v1/public/.%2e;/admin", "semicolon-in-path"},
		{"/v1/public/%2e%2e;/admin", "semicolon-in-path"},
		{"/v1/public/..;foo/admin", "semicolon-in-path"},
		{"/v1/public/last;", "semicolon-in-path"},
		{"/v1/public/last;x=1", "semicolon-in-path"},
		{"/v1/%252e%252e/admin", "double-encoded-path"},
		{"/v1/%252E%252E/admin", "double-encoded-path"},
		{"/v1/a%252fb", "double-encoded-path"},
		{"/v1/100%2541", "double-encoded-path"},
	}
	for _, tc := range refused {
		if code, body := send(tc.target); code != http.StatusForbidden || !strings.Contains(body, tc.reason) {
			t.Errorf("%s = %d %q, want 403 %s", tc.target, code, body, tc.reason)
		}
	}
	if got := upHits.Load(); got != before {
		t.Fatalf("refused requests reached upstream: %d hits, want %d", got, before)
	}

	// Every refusal is audited with its reason.
	seen := map[string]bool{}
	for _, ev := range gw.AuditEvents(t) {
		if ev.Kind == audit.KindRequest && ev.Effect == audit.EffectDeny {
			seen[ev.Reason] = true
		}
	}
	for _, reason := range []string{"semicolon-in-path", "double-encoded-path"} {
		if !seen[reason] {
			t.Errorf("no audited deny with reason %s", reason)
		}
	}
}
