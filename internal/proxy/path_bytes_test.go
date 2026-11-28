// SPDX-License-Identifier: AGPL-3.0-only

package proxy_test

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// rawRequest sends one request line as written, with no client normalisation,
// and returns the status and body.
func rawRequest(t *testing.T, gw *testGateway, sni, method, target string) (int, string) {
	t.Helper()
	conn := gw.DialTLS(t, sni)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close conn: %v", err)
		}
	}()
	if _, err := io.WriteString(conn, method+" "+target+" HTTP/1.1\r\nHost: "+sni+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write %s: %v", target, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ReadResponse %s: %v", target, err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body %s: %v", target, err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close body %s: %v", target, err)
	}
	return resp.StatusCode, string(body)
}

// Bytes a rule cannot see through, and a method spelled differently from the one
// the rule matched, are refused; the same rules still admit ordinary requests.
func TestPathBytesCaseAndMethodGuards(t *testing.T) {
	var upHits atomic.Int32
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"bytes.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			upHits.Add(1)
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: `
  - id: allow-all
    principal: worker-test
    effect: allow
    hosts: [bytes.example.com]
    paths: ["/**"]
  - id: deny-admin
    principal: worker-test
    effect: deny
    hosts: [bytes.example.com]
    paths: ["/admin/**"]
`,
	})
	send := func(method, target string) (int, string) {
		return rawRequest(t, gw, "bytes.example.com", method, target)
	}

	// Positive controls: ordinary paths, a valid multi-byte character, an inner
	// space, and a different case (paths are case-sensitive and exact) all pass.
	for _, target := range []string{"/ok", "/%C3%A9", "/a%20b", "/Admin", "/administrator"} {
		if code, body := send(http.MethodGet, target); code != http.StatusOK {
			t.Fatalf("GET %s = %d %q, want 200", target, code, body)
		}
	}
	before := upHits.Load()

	for _, tc := range []struct{ method, target, reason string }{
		// The deny covers the subtree and its root.
		{http.MethodGet, "/admin", "rule-deny"},
		{http.MethodGet, "/admin/", "rule-deny"},
		{http.MethodGet, "/admin/x", "rule-deny"},
		// Bytes a server may strip or re-read.
		{http.MethodGet, "/admin%00", "control-byte-in-path"},
		{http.MethodGet, "/admin%09/x", "control-byte-in-path"},
		{http.MethodGet, "/admin%0d%0a", "control-byte-in-path"},
		{http.MethodGet, "/admin%7f", "control-byte-in-path"},
		{http.MethodGet, "/admin%20", "padded-path-segment"},
		{http.MethodGet, "/%20admin", "padded-path-segment"},
		{http.MethodGet, "/%ff", "invalid-utf8-path"},
		{http.MethodGet, "/%c0%af", "invalid-utf8-path"},
		// A method is forwarded as sent, so only the canonical spelling is accepted.
		{"get", "/ok", "non-canonical-method"},
		{"Get", "/ok", "non-canonical-method"},
		{"gEt", "/admin", "non-canonical-method"},
	} {
		code, body := send(tc.method, tc.target)
		if code != http.StatusForbidden || !strings.Contains(body, tc.reason) {
			t.Errorf("%s %s = %d %q, want 403 %s", tc.method, tc.target, code, body, tc.reason)
		}
	}
	if got := upHits.Load(); got != before {
		t.Fatalf("refused requests reached upstream: %d hits, want %d", got, before)
	}
}
