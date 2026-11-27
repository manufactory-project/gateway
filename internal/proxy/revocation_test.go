package proxy_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/netguard"
)

func TestLiveTeardownOnGrantExpiryRevokeAndReload(t *testing.T) {
	streamStarted := make(chan struct{}, 16)
	wsStarted := make(chan struct{}, 4)
	holdRelease := make(chan struct{})

	gw := newTestGateway(t, testGatewaySpec{
		StartGrantPruner: true,
		OnCleanupFirst:   func() { close(holdRelease) },
		Hosts:            []string{"grant.example.com", "ws.example.com", "unbound.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/hold":
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				rc := http.NewResponseController(w)
				if _, err := io.WriteString(w, "data: open\n\n"); err != nil {
					return
				}
				if err := rc.Flush(); err != nil {
					return
				}
				streamStarted <- struct{}{}
				<-holdRelease
			case "/ws-hold":
				conn, rw, err := http.NewResponseController(w).Hijack()
				if err != nil {
					return
				}
				defer func() {
					if cErr := conn.Close(); cErr != nil {
						return
					}
				}()
				if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
					return
				}
				wsStarted <- struct{}{}
				if _, err := io.Copy(conn, rw); err != nil {
					return
				}
			default:
				w.WriteHeader(http.StatusOK)
			}
		}),
		RulesYAML: `
  - id: allow-unbound
    principal: worker-test
    effect: allow
    hosts: [unbound.example.com]
    ports: [443]
  - id: allow-ws
    principal: worker-test
    effect: allow
    hosts: [ws.example.com]
    ports: [443]
    allow_websocket: true
`,
	})

	// 1. Ephemeral TTL grant tears down an open H2 SSE stream when TTL expires.
	gTTL, err := gw.Store.AddGrant("worker-test", "grant.example.com", 443, []string{"GET"}, []string{"/hold"}, 120*time.Millisecond)
	if err != nil {
		t.Fatalf("AddGrant TTL: %v", err)
	}
	rTTL, err := gw.H2Client(t, "grant.example.com").Get("https://grant.example.com/hold")
	if err != nil {
		t.Fatalf("GET /hold under TTL grant: %v", err)
	}
	<-streamStarted
	if active := gw.Flows.List(); len(active) == 0 || active[0].GrantID != gTTL.ID {
		t.Fatalf("expected active flow with grant_id %s, got %+v", gTTL.ID, active)
	}
	ttlDone := make(chan error, 1)
	go func() {
		_, rErr := io.ReadAll(rTTL.Body)
		ttlDone <- rErr
	}()
	select {
	case <-ttlDone:
	case <-time.After(2 * time.Second):
		t.Fatal("open H2 stream was not torn down on grant TTL expiry")
	}
	if err := rTTL.Body.Close(); err != nil {
		t.Logf("close rTTL body after teardown: %v", err)
	}

	// 2. Live revoke tears down an open WebSocket flow immediately.
	wsConn := gw.DialTLS(t, "ws.example.com")
	if _, err := io.WriteString(wsConn, "GET /ws-hold HTTP/1.1\r\nHost: ws.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"); err != nil {
		t.Fatalf("write WS: %v", err)
	}
	wsBR := bufio.NewReader(wsConn)
	wsResp, err := http.ReadResponse(wsBR, nil)
	if err != nil || wsResp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("WS upgrade failed: resp=%+v err=%v", wsResp, err)
	}
	<-wsStarted
	if n := gw.Flows.RevokeByPrincipal("worker-test", "ws.example.com"); n != 1 {
		t.Fatalf("RevokeByPrincipal ws count = %d, want 1", n)
	}
	wsReadDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, rErr := wsBR.Read(buf)
		wsReadDone <- rErr
	}()
	select {
	case <-wsReadDone:
	case <-time.After(2 * time.Second):
		t.Fatal("open WebSocket was not torn down by live revoke")
	}
	if err := wsConn.Close(); err != nil {
		t.Logf("close wsConn after teardown: %v", err)
	}

	// 3. Reload removing a rule tears down an active H1 keep-alive SSE stream AND closes the guest TCP socket.
	rawKeepAlive := gw.DialTLS(t, "unbound.example.com")
	if _, err := io.WriteString(rawKeepAlive, "GET /hold HTTP/1.1\r\nHost: unbound.example.com\r\nConnection: keep-alive\r\n\r\n"); err != nil {
		t.Fatalf("write H1 keep-alive GET /hold: %v", err)
	}
	kaBR := bufio.NewReader(rawKeepAlive)
	rHold, err := http.ReadResponse(kaBR, nil)
	if err != nil || rHold.StatusCode != http.StatusOK {
		t.Fatalf("H1 keep-alive /hold failed: resp=%+v err=%v", rHold, err)
	}
	<-streamStarted
	updatedYAML := strings.Replace(gw.BaseYAML, "  - id: allow-unbound\n    principal: worker-test\n    effect: allow\n    hosts: [unbound.example.com]\n    ports: [443]\n", "", 1)
	if err := os.WriteFile(gw.CfgPath, []byte(updatedYAML), 0o600); err != nil {
		t.Fatalf("write updated config: %v", err)
	}
	if _, _, err := gw.Store.Reload(); err != nil {
		t.Fatalf("store.Reload: %v", err)
	}
	reloadDone := make(chan error, 1)
	go func() {
		_, rErr := io.ReadAll(rHold.Body)
		reloadDone <- rErr
	}()
	select {
	case <-reloadDone:
	case <-time.After(2 * time.Second):
		t.Fatal("active H1 stream was not torn down when reload removed its rule")
	}
	if err := rHold.Body.Close(); err != nil {
		t.Logf("close rHold after teardown: %v", err)
	}
	if err := rawKeepAlive.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("set keep-alive deadline: %v", err)
	}
	var one [1]byte
	if _, rErr := kaBR.Read(one[:]); rErr == nil {
		t.Fatal("expected guest keep-alive socket to be closed after teardown, read succeeded")
	} else if ne, ok := rErr.(net.Error); ok && ne.Timeout() {
		t.Fatal("guest keep-alive socket remained open (timed out instead of closed on teardown)")
	}
	if err := rawKeepAlive.Close(); err != nil {
		t.Logf("close rawKeepAlive: %v", err)
	}
}

func TestRevocationMetricsOnTTLExpiryAndReload(t *testing.T) {
	holdRelease := make(chan struct{})
	streamStarted := make(chan struct{}, 8)

	gw := newTestGateway(t, testGatewaySpec{
		StartGrantPruner: true,
		OnCleanupFirst:   func() { close(holdRelease) },
		Hosts:            []string{"reload.example.com", "ttl.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/hold" {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				rc := http.NewResponseController(w)
				if _, err := io.WriteString(w, "data: open\n\n"); err != nil {
					return
				}
				if err := rc.Flush(); err != nil {
					return
				}
				streamStarted <- struct{}{}
				<-holdRelease
				return
			}
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: `
  - id: allow-reload
    principal: worker-test
    effect: allow
    hosts: [reload.example.com]
    ports: [443]
`,
	})

	scrapeRevocations := func() string {
		rec := httptest.NewRecorder()
		gw.Metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rec.Body.String()
	}

	// 1. TTL expiry teardown increments gatewayd_revocations_total.
	if _, err := gw.Store.AddGrant("worker-test", "ttl.example.com", 443, []string{"GET"}, []string{"/hold"}, 100*time.Millisecond); err != nil {
		t.Fatalf("AddGrant TTL: %v", err)
	}
	rTTL, err := gw.H1Client(t, "ttl.example.com").Get("https://ttl.example.com/hold")
	if err != nil {
		t.Fatalf("GET ttl /hold: %v", err)
	}
	<-streamStarted
	if _, err := io.Copy(io.Discard, rTTL.Body); err != nil {
		t.Logf("rTTL stream ended on TTL teardown: %v", err)
	}
	if err := rTTL.Body.Close(); err != nil {
		t.Logf("close rTTL: %v", err)
	}
	if m := scrapeRevocations(); !strings.Contains(m, "gatewayd_revocations_total 1\n") {
		t.Fatalf("expected gatewayd_revocations_total 1 after TTL expiry, got:\n%s", m)
	}

	// 2. Reload teardown increments gatewayd_revocations_total.
	rRel, err := gw.H1Client(t, "reload.example.com").Get("https://reload.example.com/hold")
	if err != nil {
		t.Fatalf("GET reload /hold: %v", err)
	}
	<-streamStarted
	updated := strings.Replace(gw.BaseYAML, "  - id: allow-reload\n    principal: worker-test\n    effect: allow\n    hosts: [reload.example.com]\n    ports: [443]\n", "", 1)
	if err := os.WriteFile(gw.CfgPath, []byte(updated), 0o600); err != nil {
		t.Fatalf("write updated config: %v", err)
	}
	if _, _, err := gw.Store.Reload(); err != nil {
		t.Fatalf("store.Reload: %v", err)
	}
	if _, err := io.Copy(io.Discard, rRel.Body); err != nil {
		t.Logf("rRel stream ended on reload teardown: %v", err)
	}
	if err := rRel.Body.Close(); err != nil {
		t.Logf("close rRel: %v", err)
	}
	if m := scrapeRevocations(); !strings.Contains(m, "gatewayd_revocations_total 2\n") {
		t.Fatalf("expected gatewayd_revocations_total 2 after reload teardown, got:\n%s", m)
	}
}

func TestTeardownDuringDialRaceHTTPAndWebSocket(t *testing.T) {
	var (
		wsUpWrites   atomic.Int32
		httpRaceHits atomic.Int32
		raceWSConn   atomic.Pointer[closeTrackingConn]
		gw           *testGateway
	)

	gw = newTestGateway(t, testGatewaySpec{
		Hosts: []string{"race-http.example.com", "race-ws.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/ws-race":
				wsUpWrites.Add(1)
			case "/ok":
				httpRaceHits.Add(1)
			}
			w.WriteHeader(http.StatusOK)
		}),
		DialOverride: func(guard *netguard.Dialer, upTLSPort, _ uint16) func(ctx context.Context, network, addr string) (net.Conn, error) {
			return func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				conn, err := guard.DialHost(ctx, network, host, upTLSPort)
				if err != nil {
					return nil, err
				}
				switch host {
				case "race-http.example.com":
					gw.Flows.RevokeByPrincipal("worker-test", "race-http.example.com")
					return conn, nil
				case "race-ws.example.com":
					tc := &closeTrackingConn{Conn: conn}
					raceWSConn.Store(tc)
					gw.Flows.RevokeByPrincipal("worker-test", "race-ws.example.com")
					return tc, nil
				}
				return conn, nil
			}
		},
		RulesYAML: `
  - id: allow-race-http
    principal: worker-test
    effect: allow
    hosts: [race-http.example.com]
    ports: [443]
  - id: allow-race-ws
    principal: worker-test
    effect: allow
    hosts: [race-ws.example.com]
    ports: [443]
    allow_websocket: true
`,
	})

	// 1. HTTP teardown during dial cancels RoundTrip so upstream never receives request.
	if r, err := gw.H1Client(t, "race-http.example.com").Get("https://race-http.example.com/ok"); err == nil {
		if cErr := r.Body.Close(); cErr != nil {
			t.Logf("close race-http body: %v", cErr)
		}
		if r.StatusCode == http.StatusOK {
			t.Fatal("revoked HTTP request succeeded despite teardown during dial")
		}
	}
	if httpRaceHits.Load() != 0 {
		t.Fatalf("revoked HTTP request reached upstream /ok: hits=%d", httpRaceHits.Load())
	}

	// 2. WebSocket teardown racing before setUpstreamConn closes upstream socket & never writes.
	wsConn := gw.DialTLS(t, "race-ws.example.com")
	if _, err := io.WriteString(wsConn, "GET /ws-race HTTP/1.1\r\nHost: race-ws.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"); err != nil {
		t.Fatalf("race-ws write: %v", err)
	}
	if resp, rErr := http.ReadResponse(bufio.NewReader(wsConn), nil); rErr == nil {
		if cErr := resp.Body.Close(); cErr != nil {
			t.Logf("close race-ws resp: %v", cErr)
		}
	}
	if cErr := wsConn.Close(); cErr != nil {
		t.Logf("close race-ws conn: %v", cErr)
	}
	tcWS := raceWSConn.Load()
	if tcWS == nil {
		t.Fatal("race-ws dial never ran")
	}
	deadline := time.Now().Add(time.Second)
	for !tcWS.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !tcWS.closed.Load() {
		t.Fatal("WebSocket upstream socket leaked open when teardown raced before setUpstreamConn")
	}
	if wsUpWrites.Load() != 0 {
		t.Fatalf("WebSocket wrote upgrade to upstream despite prior teardown: writes=%d", wsUpWrites.Load())
	}
}

func TestSIGHUPWipesGrantsAndTearsDownStream(t *testing.T) {
	streamOpenCh := make(chan string, 4)
	releaseHold := make(chan struct{})

	gw := newTestGateway(t, testGatewaySpec{
		OnCleanupFirst: func() { close(releaseHold) },
		Hosts:          []string{"h2grant.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			rc := http.NewResponseController(w)
			if _, err := io.WriteString(w, "data: "+r.URL.Path+"\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			streamOpenCh <- r.URL.Path
			<-releaseHold
		}),
	})

	sigCtx, sigCancel := context.WithCancel(context.Background())
	sigDone := make(chan struct{})
	go func() {
		defer close(sigDone)
		gw.Store.WatchSIGHUP(sigCtx, nil)
	}()
	t.Cleanup(func() {
		sigCancel()
		<-sigDone
	})
	time.Sleep(25 * time.Millisecond)

	gHUP, err := gw.Store.AddGrant("worker-test", "h2grant.example.com", 443, []string{"GET"}, []string{"/stream-hup"}, 5*time.Minute)
	if err != nil {
		t.Fatalf("AddGrant gHUP: %v", err)
	}
	rHUP, err := gw.H2Client(t, "h2grant.example.com").Get("https://h2grant.example.com/stream-hup")
	if err != nil {
		t.Fatalf("GET /stream-hup: %v", err)
	}
	<-streamOpenCh

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}
	hupDone := make(chan error, 1)
	go func() {
		_, rErr := io.ReadAll(rHUP.Body)
		hupDone <- rErr
	}()
	select {
	case <-hupDone:
	case <-time.After(2 * time.Second):
		t.Fatalf("stream under grant %s was not torn down on SIGHUP", gHUP.ID)
	}
	if err := rHUP.Body.Close(); err != nil {
		t.Logf("close rHUP: %v", err)
	}
	if active := gw.Store.ActiveGrants(); len(active) != 0 {
		t.Fatalf("SIGHUP did not wipe grants, still active: %+v", active)
	}
}
