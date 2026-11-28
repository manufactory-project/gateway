// SPDX-License-Identifier: AGPL-3.0-only

package proxy_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func sseHold(open chan<- string, release <-chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		if _, err := io.WriteString(w, "data: open "+r.URL.Path+"\n\n"); err != nil {
			return
		}
		if err := rc.Flush(); err != nil {
			return
		}
		open <- r.URL.Path
		select {
		case <-release:
			if _, err := io.WriteString(w, "data: done "+r.URL.Path+"\n\n"); err != nil {
				return
			}
		case <-r.Context().Done():
		}
	})
}

const apiRule = `
  - id: allow-api
    principal: worker-test
    effect: allow
    hosts: [api.example.com]
    ports: [443]
`

// TestReloadThatBindsAnOpenFlowsHostTearsItDown pins that a flow admitted while its
// host had no bindings (so nothing scrubs its response) ends when a reload makes
// the host bound, even though the rule that admitted it is unchanged.
func TestReloadThatBindsAnOpenFlowsHostTearsItDown(t *testing.T) {
	open := make(chan string, 1)
	release := make(chan struct{})
	var once sync.Once
	gw := newTestGateway(t, testGatewaySpec{
		OnCleanupFirst: func() { once.Do(func() { close(release) }) },
		Hosts:          []string{"api.example.com"},
		Handler:        sseHold(open, release),
		RulesYAML:      apiRule,
	})

	resp, err := gw.H1Client(t, "api.example.com").Get("https://api.example.com/stream")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /stream: resp=%+v err=%v", resp, err)
	}
	<-open

	reload := func(yaml string) int {
		t.Helper()
		if err := os.WriteFile(gw.CfgPath, []byte(yaml), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		_, _, revoked, err := gw.Store.Reload()
		if err != nil {
			t.Fatalf("Reload: %v", err)
		}
		return revoked
	}

	// Positive control: a reload that changes nothing this flow depends on leaves it open.
	unrelated := gw.BaseYAML + "  - id: allow-other\n    principal: worker-test\n    effect: allow\n    hosts: [other.example.com]\n    ports: [443]\n"
	if n := reload(unrelated); n != 0 {
		t.Fatalf("unrelated reload revoked %d flow(s), want 0", n)
	}
	if got := gw.Flows.Count(); got != 1 {
		t.Fatalf("active flows after unrelated reload = %d, want 1", got)
	}

	secFile := writeSecretFile(t, t.TempDir(), "api.secret", "sec-"+randHex(t)+"\n")
	bound := strings.Replace(gw.BaseYAML, "    ports: [443]\n", fmt.Sprintf(`    ports: [443]
    bindings:
      - name: api-key
        host: api.example.com
        header: Authorization
        scheme: bearer
        placeholder: mf_ph_api
        secret_file: %s
`, secFile), 1)
	if n := reload(bound); n != 1 {
		t.Fatalf("reload binding the host revoked %d flow(s), want 1", n)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Logf("stream closed on reload: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Logf("close resp: %v", err)
	}
	waitAuditCompletedError(t, gw, "/stream", "reload")
}

// TestRevokedHTTP2StreamLeavesSiblingStreamsRunning pins that revoking one HTTP/2
// stream resets that stream only: a sibling stream on the same connection keeps
// receiving and is audited as an ordinary completion.
func TestRevokedHTTP2StreamLeavesSiblingStreamsRunning(t *testing.T) {
	open := make(chan string, 2)
	release := make(chan struct{})
	var once sync.Once
	gw := newTestGateway(t, testGatewaySpec{
		OnCleanupFirst: func() { once.Do(func() { close(release) }) },
		Hosts:          []string{"api.example.com"},
		Handler:        sseHold(open, release),
		RulesYAML:      apiRule,
	})
	client := gw.H2Client(t, "api.example.com")

	get := func(path string) (*http.Response, net.Conn) {
		t.Helper()
		connCh := make(chan net.Conn, 1)
		ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
			GotConn: func(ci httptrace.GotConnInfo) { connCh <- ci.Conn },
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com"+path, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
			t.Fatalf("GET %s: resp=%+v err=%v", path, resp, err)
		}
		<-open
		return resp, <-connCh
	}
	respA, connA := get("/a")
	respB, connB := get("/b")
	if connA != connB {
		t.Fatal("test setup: streams did not share one connection")
	}
	brA, brB := bufio.NewReader(respA.Body), bufio.NewReader(respB.Body)
	for _, br := range []*bufio.Reader{brA, brB} {
		if line, err := br.ReadString('\n'); err != nil || !strings.HasPrefix(line, "data: open") {
			t.Fatalf("first event = %q, err %v", line, err)
		}
	}

	var flowA string
	for _, f := range gw.Flows.List() {
		if f.Path == "/a" {
			flowA = f.ID
		}
	}
	if flowA == "" || gw.Flows.RevokeByID(flowA) != 1 {
		t.Fatalf("could not revoke the /a flow (id %q)", flowA)
	}
	if _, err := io.ReadAll(brA); err == nil {
		t.Fatal("revoked stream /a ended cleanly, want a stream reset")
	}

	once.Do(func() { close(release) })
	rest, err := io.ReadAll(brB)
	if err != nil || !strings.Contains(string(rest), "data: done /b") {
		t.Fatalf("sibling stream /b after revoking /a: body=%q err=%v", rest, err)
	}
	waitAuditCompletedError(t, gw, "/a", "revoked")
	waitAuditCompletedError(t, gw, "/b", "")
}

// TestShutdownStopsAcceptingAndWaitsForHijackedFlows pins that Shutdown closes the
// listeners, tears down every flow (a hijacked WebSocket included), and returns
// only once their completion audit is written, so the audit writer can close next.
func TestShutdownStopsAcceptingAndWaitsForHijackedFlows(t *testing.T) {
	open := make(chan string, 1)
	release := make(chan struct{})
	var once sync.Once
	gw := newTestGateway(t, testGatewaySpec{
		OnCleanupFirst: func() { once.Do(func() { close(release) }) },
		Hosts:          []string{"api.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				wsEchoHandler(w, r)
				return
			}
			sseHold(open, release).ServeHTTP(w, r)
		}),
		RulesYAML: apiRule + "    allow_websocket: true\n",
	})
	resp, err := gw.H1Client(t, "api.example.com").Get("https://api.example.com/stream")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /stream: resp=%+v err=%v", resp, err)
	}
	<-open
	wsConn, wsBR := openTestWSUpgrade(t, gw, "api.example.com", "/ws")
	if got := gw.Flows.Count(); got != 2 {
		t.Fatalf("active flows before shutdown = %d, want 2", got)
	}
	// Positive control: the listener accepts before shutdown.
	if c, err := net.DialTimeout("tcp", gw.HTTPSAddr, time.Second); err != nil {
		t.Fatalf("dial before shutdown: %v", err)
	} else if err := c.Close(); err != nil {
		t.Fatalf("close control conn: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := gw.Server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	if c, err := net.DialTimeout("tcp", gw.HTTPSAddr, time.Second); err == nil {
		if cErr := c.Close(); cErr != nil {
			t.Logf("close: %v", cErr)
		}
		t.Fatal("listener still accepting after Shutdown")
	}
	if got := gw.Flows.Count(); got != 0 {
		t.Fatalf("active flows after shutdown = %d, want 0", got)
	}
	// Both completions must already be in the audit log: no handler outlives Shutdown.
	done := map[string]string{}
	for _, ev := range gw.AuditEvents(t) {
		if ev.Kind == "request" || ev.Kind == "websocket" {
			done[ev.Path] = ev.Error
		}
	}
	for _, p := range []string{"/stream", "/ws"} {
		if e, ok := done[p]; !ok || e != "revoked" {
			t.Fatalf("completion audit for %s = (%q, present %v) right after Shutdown, want revoked", p, e, ok)
		}
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Logf("stream closed on shutdown: %v", err)
	}
	if _, err := io.ReadAll(wsBR); err != nil {
		t.Logf("ws closed on shutdown: %v", err)
	}
	if err := wsConn.Close(); err != nil {
		t.Logf("close ws: %v", err)
	}
}

// TestShutdownWaitsForInFlightHandlers pins that Shutdown does not return while a
// handler is still completing, even after its flow was torn down, so the audit
// writer is never closed under a handler that has yet to write.
func TestShutdownWaitsForInFlightHandlers(t *testing.T) {
	open := make(chan string, 1)
	release := make(chan struct{})
	reached := make(chan struct{})
	gate := make(chan struct{})
	var once, gateOnce sync.Once
	gw := newTestGateway(t, testGatewaySpec{
		OnCleanupFirst: func() {
			once.Do(func() { close(release) })
			gateOnce.Do(func() { close(gate) })
		},
		Hosts:   []string{"api.example.com"},
		Handler: sseHold(open, release),
		OnRequest: func(_, effect string, status int, reason string) {
			if effect == "allow" && reason == "revoked" {
				close(reached)
				<-gate
			}
		},
		RulesYAML: apiRule,
	})
	resp, err := gw.H1Client(t, "api.example.com").Get("https://api.example.com/stream")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /stream: resp=%+v err=%v", resp, err)
	}
	<-open

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- gw.Server.Shutdown(ctx) }()
	<-reached // the flow is torn down and its handler is mid-completion
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Shutdown returned %v while a handler was still completing, want context.Canceled", err)
	}
	gateOnce.Do(func() { close(gate) })
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Logf("stream closed on shutdown: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Logf("close resp: %v", err)
	}
}

func holdOrQuick(open chan<- string, release <-chan struct{}) http.Handler {
	hold := sseHold(open, release)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/quick":
			w.WriteHeader(http.StatusOK)
		case strings.EqualFold(r.Header.Get("Upgrade"), "websocket"):
			wsEchoHandler(w, r)
		default:
			hold.ServeHTTP(w, r)
		}
	})
}

func tracedGet(t *testing.T, c *http.Client, path string) (*http.Response, bool) {
	t.Helper()
	reused := make(chan bool, 1)
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GotConn: func(ci httptrace.GotConnInfo) { reused <- ci.Reused },
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com"+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: resp=%+v err=%v", path, resp, err)
	}
	return resp, <-reused
}

// TestRevokeOnKeptAliveHTTP1ConnDoesNotMisattributeNeighbours pins that on one
// kept-alive HTTP/1.1 connection each request is its own flow: a finished request
// cannot be revoked later, and revoking the live one is audited against it alone.
func TestRevokeOnKeptAliveHTTP1ConnDoesNotMisattributeNeighbours(t *testing.T) {
	open := make(chan string, 1)
	release := make(chan struct{})
	var once sync.Once
	gw := newTestGateway(t, testGatewaySpec{
		OnCleanupFirst: func() { once.Do(func() { close(release) }) },
		Hosts:          []string{"api.example.com"},
		Handler:        holdOrQuick(open, release),
		RulesYAML:      apiRule,
	})
	client := gw.H1Client(t, "api.example.com")

	first, _ := tracedGet(t, client, "/quick")
	if _, err := io.Copy(io.Discard, first.Body); err != nil {
		t.Fatalf("drain /quick: %v", err)
	}
	if err := first.Body.Close(); err != nil {
		t.Fatalf("close /quick: %v", err)
	}
	second, reused := tracedGet(t, client, "/stream")
	if !reused {
		t.Fatal("test setup: /stream did not reuse the kept-alive connection")
	}
	<-open
	flows := gw.Flows.List()
	if len(flows) != 1 || flows[0].Path != "/stream" {
		t.Fatalf("active flows = %+v, want only /stream", flows)
	}
	if n := gw.Flows.RevokeByID(flows[0].ID); n != 1 {
		t.Fatalf("RevokeByID = %d, want 1", n)
	}
	if _, err := io.Copy(io.Discard, second.Body); err == nil {
		t.Fatal("revoked /stream ended cleanly, want a closed connection")
	}
	waitAuditCompletedError(t, gw, "/stream", "revoked")
	waitAuditCompletedError(t, gw, "/quick", "")
}

// TestRevokingWebSocketAndHTTP2StreamsAreIndependent pins that on one link a
// revoked WebSocket leaves an HTTP/2 stream running, and a revoked HTTP/2
// stream leaves the WebSocket running.
func TestRevokingWebSocketAndHTTP2StreamsAreIndependent(t *testing.T) {
	open := make(chan string, 2)
	release := make(chan struct{})
	var once sync.Once
	gw := newTestGateway(t, testGatewaySpec{
		OnCleanupFirst: func() { once.Do(func() { close(release) }) },
		Hosts:          []string{"api.example.com"},
		Handler:        holdOrQuick(open, release),
		RulesYAML:      apiRule + "    allow_websocket: true\n",
	})
	flowID := func(path string) string {
		for _, f := range gw.Flows.List() {
			if f.Path == path {
				return f.ID
			}
		}
		t.Fatalf("no active flow for %s", path)
		return ""
	}
	h2 := gw.H2Client(t, "api.example.com")

	// WebSocket revoked, H2 stream survives.
	resp, _ := tracedGet(t, h2, "/s1")
	<-open
	wsConn, wsBR := openTestWSUpgrade(t, gw, "api.example.com", "/ws1")
	if n := gw.Flows.RevokeByID(flowID("/ws1")); n != 1 {
		t.Fatalf("revoke /ws1 = %d", n)
	}
	if _, err := io.ReadAll(wsBR); err != nil {
		t.Logf("ws closed: %v", err)
	}
	if err := wsConn.Close(); err != nil {
		t.Logf("close ws: %v", err)
	}
	waitAuditCompletedError(t, gw, "/ws1", "revoked")
	if gw.Flows.Count() != 1 {
		t.Fatalf("H2 stream /s1 must still be registered, flows=%+v", gw.Flows.List())
	}

	// H2 stream revoked, a second WebSocket survives.
	wsConn2, wsBR2 := openTestWSUpgrade(t, gw, "api.example.com", "/ws2")
	if n := gw.Flows.RevokeByID(flowID("/s1")); n != 1 {
		t.Fatalf("revoke /s1 = %d", n)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err == nil {
		t.Fatal("revoked H2 stream ended cleanly")
	}
	if _, err := io.WriteString(wsConn2, "x"); err != nil {
		t.Fatalf("write on surviving websocket: %v", err)
	}
	if gw.Flows.Count() != 1 {
		t.Fatalf("websocket /ws2 must still be registered, flows=%+v", gw.Flows.List())
	}
	if n := gw.Flows.RevokeByID(flowID("/ws2")); n != 1 {
		t.Fatalf("revoke /ws2 = %d", n)
	}
	if _, err := io.ReadAll(wsBR2); err != nil {
		t.Logf("ws2 closed: %v", err)
	}
	if err := wsConn2.Close(); err != nil {
		t.Logf("close ws2: %v", err)
	}
	waitAuditCompletedError(t, gw, "/s1", "revoked")
	waitAuditCompletedError(t, gw, "/ws2", "revoked")
}

// TestReloadRevokingOneHTTP2StreamLeavesSiblingRunning combines reload revocation
// with stream-only teardown: a reload that removes the rule of one stream resets
// that stream while its sibling, under another rule, keeps running and completes
// with a clean audit record.
func TestReloadRevokingOneHTTP2StreamLeavesSiblingRunning(t *testing.T) {
	open := make(chan string, 2)
	release := make(chan struct{})
	var once sync.Once
	const ruleA = "  - id: allow-a\n    principal: worker-test\n    effect: allow\n    hosts: [api.example.com]\n    ports: [443]\n    paths: [\"/a\"]\n"
	const ruleB = "  - id: allow-b\n    principal: worker-test\n    effect: allow\n    hosts: [api.example.com]\n    ports: [443]\n    paths: [\"/b\"]\n"
	gw := newTestGateway(t, testGatewaySpec{
		OnCleanupFirst: func() { once.Do(func() { close(release) }) },
		Hosts:          []string{"api.example.com"},
		Handler:        sseHold(open, release),
		RulesYAML:      ruleA + ruleB,
	})
	client := gw.H2Client(t, "api.example.com")
	respA, _ := tracedGet(t, client, "/a")
	<-open
	respB, _ := tracedGet(t, client, "/b")
	<-open

	if err := os.WriteFile(gw.CfgPath, []byte(strings.Replace(gw.BaseYAML, ruleA, "", 1)), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, _, n, err := gw.Store.Reload(); err != nil || n != 1 {
		t.Fatalf("Reload = (%d revoked, %v), want 1", n, err)
	}
	if _, err := io.Copy(io.Discard, respA.Body); err == nil {
		t.Fatal("stream /a ended cleanly after its rule was removed")
	}
	once.Do(func() { close(release) })
	rest, err := io.ReadAll(respB.Body)
	if err != nil || !strings.Contains(string(rest), "data: done /b") {
		t.Fatalf("sibling /b after reload: body=%q err=%v", rest, err)
	}
	waitAuditCompletedError(t, gw, "/a", "reload")
	waitAuditCompletedError(t, gw, "/b", "")
}
