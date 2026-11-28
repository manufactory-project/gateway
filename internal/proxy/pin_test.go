// SPDX-License-Identifier: AGPL-3.0-only

package proxy_test

import (
	"io"
	"net/http"
	"net/netip"
	"testing"
)

// A rule's pin is dialed only for requests that rule decides, and a pinned
// connection is never pooled for, or borrowed from, any other request.
func TestPinnedDialIsolatedFromOtherRulesAndPooling(t *testing.T) {
	gw := newTestGateway(t, testGatewaySpec{
		Hosts:   []string{"forge.lan.example"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
		RulesYAML: `
  - id: pinned
    principal: worker-test
    effect: allow
    hosts: [forge.lan.example]
    paths: ["/pinned/**"]
    pins: {forge.lan.example: 10.10.20.5}
  - id: plain
    principal: worker-test
    effect: allow
    hosts: [forge.lan.example]
    paths: ["/plain/**"]
`,
	})
	client := gw.H1Client(t, "forge.lan.example")
	get := func(path string) {
		t.Helper()
		resp, err := client.Get("https://forge.lan.example" + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close %s: %v", path, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, resp.StatusCode)
		}
	}

	pin := netip.MustParseAddr("10.10.20.5")
	// plain (unpinned dial, pooled), pinned (must not borrow it), pinned again
	// (must not be pooled), plain again (reuses the first connection: positive control).
	for _, path := range []string{"/plain/a", "/pinned/a", "/pinned/b", "/plain/b"} {
		get(path)
	}
	got := gw.Dials.all()
	want := []netip.Addr{{}, pin, pin}
	if len(got) != len(want) {
		t.Fatalf("dials = %+v, want %d (plain, pinned, pinned; the last plain request reuses the pool)", got, len(want))
	}
	for i, d := range got {
		if d.pin != want[i] {
			t.Errorf("dial %d to %s carried pin %v, want %v", i, d.addr, d.pin, want[i])
		}
	}
}
