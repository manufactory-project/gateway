package proxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/netguard"
	"github.com/manufactory-project/gateway/internal/proxy"
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
	gTTL, err := gw.Store.AddGrant("worker-test", "grant.example.com", 443, []string{"GET"}, []string{"/hold"}, 120*time.Millisecond, false)
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

	// 1. TTL expiry teardown increments gateway_revocations_total.
	if _, err := gw.Store.AddGrant("worker-test", "ttl.example.com", 443, []string{"GET"}, []string{"/hold"}, 100*time.Millisecond, false); err != nil {
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
	if m := scrapeRevocations(); !strings.Contains(m, "gateway_revocations_total 1\n") {
		t.Fatalf("expected gateway_revocations_total 1 after TTL expiry, got:\n%s", m)
	}

	// 2. Reload teardown increments gateway_revocations_total.
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
	if m := scrapeRevocations(); !strings.Contains(m, "gateway_revocations_total 2\n") {
		t.Fatalf("expected gateway_revocations_total 2 after reload teardown, got:\n%s", m)
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

	gHUP, err := gw.Store.AddGrant("worker-test", "h2grant.example.com", 443, []string{"GET"}, []string{"/stream-hup"}, 5*time.Minute, false)
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

func TestWebSocketRevokedDuringHandshake(t *testing.T) {
	runCase := func(t *testing.T, byGrantExpiry bool) {
		t.Helper()

		reqReceived := make(chan struct{}, 2)
		upClosed := make(chan struct{}, 2)

		rawLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen silent ws upstream: %v", err)
		}
		silentPort := tcpPort(t, rawLn.Addr())

		host := "ws-hs.example.com"
		rulesYAML := `
  - id: allow-ws-hs
    principal: worker-test
    effect: allow
    hosts: [ws-hs.example.com]
    ports: [443]
    allow_websocket: true
`
		if byGrantExpiry {
			host = "ws-grant.example.com"
			rulesYAML = ""
		}

		var (
			upMu    sync.Mutex
			upConns []net.Conn
			upWG    sync.WaitGroup
			tlsLn   net.Listener
		)

		gw := newTestGateway(t, testGatewaySpec{
			StartGrantPruner: byGrantExpiry,
			Hosts:            []string{host},
			RulesYAML:        rulesYAML,
			DialOverride: func(guard *netguard.Dialer, _, _ uint16) func(ctx context.Context, network, addr string) (net.Conn, error) {
				return func(ctx context.Context, network, addr string) (net.Conn, error) {
					h, _, err := net.SplitHostPort(addr)
					if err != nil {
						return nil, err
					}
					return guard.DialHost(ctx, network, h, silentPort)
				}
			},
		})

		tlsLn = tls.NewListener(rawLn, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{makeSignedServerCert(t, testUpstreamCA, []string{host})},
		})
		upWG.Add(1)
		go func() {
			defer upWG.Done()
			for {
				c, err := tlsLn.Accept()
				if err != nil {
					return
				}
				upMu.Lock()
				upConns = append(upConns, c)
				upMu.Unlock()
				upWG.Add(1)
				go func(conn net.Conn) {
					defer upWG.Done()
					defer func() {
						if cErr := conn.Close(); cErr != nil {
							return
						}
					}()
					br := bufio.NewReader(conn)
					if _, err := http.ReadRequest(br); err != nil {
						return
					}
					// Upgrade request received; intentionally never send any response.
					reqReceived <- struct{}{}
					if _, err := io.Copy(io.Discard, br); err != nil {
						upClosed <- struct{}{}
						return
					}
					upClosed <- struct{}{}
				}(c)
			}
		}()
		// Registered AFTER newTestGateway so LIFO closes silent upstream first on exit/failure.
		t.Cleanup(func() {
			if err := tlsLn.Close(); err != nil {
				t.Errorf("close silent tlsLn: %v", err)
			}
			upMu.Lock()
			for _, c := range upConns {
				if cErr := c.Close(); cErr != nil {
					continue
				}
			}
			upMu.Unlock()
			upWG.Wait()
		})

		var grantID string
		if byGrantExpiry {
			g, err := gw.Store.AddGrant("worker-test", host, 443, []string{"GET"}, []string{"/ws-hs"}, 120*time.Millisecond, true)
			if err != nil {
				t.Fatalf("AddGrant ws: %v", err)
			}
			grantID = g.ID
		}

		guestConn := gw.DialTLS(t, host)
		t.Cleanup(func() {
			if cErr := guestConn.Close(); cErr != nil {
				return
			}
		})
		if _, err := io.WriteString(guestConn, "GET /ws-hs HTTP/1.1\r\nHost: "+host+"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"); err != nil {
			t.Fatalf("write WS upgrade: %v", err)
		}

		select {
		case <-reqReceived:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for upstream to receive WS upgrade request")
		}

		active := gw.Flows.List()
		if len(active) != 1 || active[0].Protocol != "websocket" {
			t.Fatalf("expected 1 active websocket flow, got %+v", active)
		}
		if byGrantExpiry {
			if active[0].GrantID != grantID {
				t.Fatalf("active flow grant_id = %q, want %q", active[0].GrantID, grantID)
			}
		} else {
			if n := gw.Flows.RevokeByID(active[0].ID); n != 1 {
				t.Fatalf("RevokeByID(%s) = %d, want 1", active[0].ID, n)
			}
		}

		bound := 600 * time.Millisecond
		if byGrantExpiry {
			bound = time.Second
		}

		// 1. Upstream connection must be closed by gateway within bound.
		select {
		case <-upClosed:
		case <-time.After(bound):
			t.Fatal("upstream connection remained open after WS handshake revocation")
		}

		// 2. Guest connection must close within bound.
		if err := guestConn.SetReadDeadline(time.Now().Add(bound)); err != nil {
			t.Fatalf("set guest deadline: %v", err)
		}
		var one [1]byte
		if _, rErr := guestConn.Read(one[:]); rErr == nil {
			t.Fatal("expected guest connection to close, read succeeded")
		} else if ne, ok := rErr.(net.Error); ok && ne.Timeout() {
			t.Fatal("guest connection remained open (timed out instead of closing)")
		}

		// 3. Flow must leave the registry within bound.
		deadline := time.Now().Add(bound)
		for gw.Flows.Count() != 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if cnt := gw.Flows.Count(); cnt != 0 {
			t.Fatalf("flow remained in registry after revocation: count=%d", cnt)
		}
	}

	t.Run("by_flow_id", func(t *testing.T) { runCase(t, false) })
	t.Run("by_grant_expiry", func(t *testing.T) { runCase(t, true) })
}

func TestReloadWithUnprunedExpiredGrantDoesNotDeadlock(t *testing.T) {
	streamOpenCh := make(chan struct{}, 2)
	releaseHold := make(chan struct{})

	gw := newTestGateway(t, testGatewaySpec{
		OnCleanupFirst:   func() { close(releaseHold) },
		StartGrantPruner: false,
		Hosts:            []string{"reload-exp.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			rc := http.NewResponseController(w)
			if _, err := io.WriteString(w, "data: open\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			streamOpenCh <- struct{}{}
			<-releaseHold
		}),
	})

	g, err := gw.Store.AddGrant("worker-test", "reload-exp.example.com", 443, []string{"GET"}, []string{"/stream"}, 40*time.Millisecond, false)
	if err != nil {
		t.Fatalf("AddGrant: %v", err)
	}

	resp, err := gw.H1Client(t, "reload-exp.example.com").Get("https://reload-exp.example.com/stream")
	if err != nil {
		t.Fatalf("GET /stream: %v", err)
	}
	t.Cleanup(func() {
		if cErr := resp.Body.Close(); cErr != nil {
			t.Logf("close resp: %v", cErr)
		}
	})
	select {
	case <-streamOpenCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SSE stream to open")
	}

	// Wait past grant expiry without running the pruner.
	time.Sleep(70 * time.Millisecond)

	// ActiveGrants must be a pure read: filters out expired grant without firing expiry callbacks.
	if active := gw.Store.ActiveGrants(); len(active) != 0 {
		t.Fatalf("expected 0 active grants after expiry, got %+v", active)
	}
	if cnt := gw.Flows.Count(); cnt != 1 {
		t.Fatalf("ActiveGrants must not fire expiry teardown; expected 1 active flow, got %d", cnt)
	}

	// teardownWhere must not hold r.mu while invoking pred (re-entering RevokeByGrant must not deadlock).
	reenterDone := make(chan struct{})
	go func() {
		defer close(reenterDone)
		gw.Flows.RevokeWhere(func(_ proxy.FlowInfo) bool {
			_ = gw.Store.ActiveGrants()
			_ = gw.Flows.RevokeByGrant("nonexistent")
			return false
		})
	}()
	select {
	case <-reenterDone:
	case <-time.After(2 * time.Second):
		t.Fatal("RevokeWhere deadlocked on re-entrant predicate")
	}

	// Reload while flow is open and grant is expired-but-unpruned must complete within 2s and tear down the flow.
	type reloadRes struct {
		wiped []string
		err   error
	}
	reloadDone := make(chan reloadRes, 1)
	go func() {
		_, wiped, rErr := gw.Store.Reload()
		reloadDone <- reloadRes{wiped: wiped, err: rErr}
	}()
	select {
	case res := <-reloadDone:
		if res.err != nil {
			t.Fatalf("Reload failed: %v", res.err)
		}
		if !slices.Contains(res.wiped, g.ID) {
			t.Fatalf("expected Reload to wipe unpruned expired grant %s, got wiped=%v", g.ID, res.wiped)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Reload deadlocked or timed out with unpruned expired grant")
	}

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		if _, rErr := io.Copy(io.Discard, resp.Body); rErr != nil {
			return
		}
	}()
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("open flow was not torn down after Reload")
	}
	deadline := time.Now().Add(2 * time.Second)
	for gw.Flows.Count() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if cnt := gw.Flows.Count(); cnt != 0 {
		t.Fatalf("flow remained in registry after reload teardown: count=%d", cnt)
	}
}

func TestAdmissionRecheckAfterFlowRegistrationBlocksRevokedRule(t *testing.T) {
	fifoPath := filepath.Join(t.TempDir(), "secret.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	var upHits atomic.Int32
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"recheck.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			upHits.Add(1)
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: fmt.Sprintf(`
  - id: allow-recheck
    principal: worker-test
    effect: allow
    hosts: [recheck.example.com]
    ports: [443]
    bindings:
      - name: fifo-sec
        host: recheck.example.com
        header: X-Tok
        scheme: raw
        placeholder: mf_ph_fifo
        secret_file: %s
`, fifoPath),
	})

	req, err := http.NewRequest(http.MethodGet, "https://recheck.example.com/race", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Tok", "mf_ph_fifo")

	type reqRes struct {
		status int
		err    error
	}
	resCh := make(chan reqRes, 1)
	client := gw.H1Client(t, "recheck.example.com")
	go func() {
		resp, rErr := client.Do(req)
		if rErr != nil {
			resCh <- reqRes{err: rErr}
			return
		}
		st := resp.StatusCode
		if cErr := resp.Body.Close(); cErr != nil {
			resCh <- reqRes{status: st, err: cErr}
			return
		}
		resCh <- reqRes{status: st}
	}()

	// Opening the FIFO for write rendezvous blocks until prepare() opens it for read,
	// guaranteeing the request is paused strictly between admit() and flows.register().
	wf, err := os.OpenFile(fifoPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open FIFO writer: %v", err)
	}

	// Remove the allow rule and reload while the request is between admit() and register().
	idx := strings.Index(gw.BaseYAML, "rules:\n")
	if idx < 0 {
		t.Fatal("missing rules block in BaseYAML")
	}
	if err := os.WriteFile(gw.CfgPath, []byte(gw.BaseYAML[:idx]), 0o600); err != nil {
		t.Fatalf("write empty-rules config: %v", err)
	}
	if _, _, err := gw.Store.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// Unblock prepare() so the request proceeds to flows.register() and post-registration recheck.
	if _, err := wf.WriteString("fifo_secret_value\n"); err != nil {
		t.Fatalf("write FIFO: %v", err)
	}
	if err := wf.Close(); err != nil {
		t.Fatalf("close FIFO: %v", err)
	}

	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("client Do error: %v", res.err)
		}
		if res.status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 after rule revoked between admit and register", res.status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for request response")
	}

	if upHits.Load() != 0 {
		t.Fatalf("revoked request reached upstream: hits=%d, want 0", upHits.Load())
	}
	var sawDeny bool
	for _, ev := range gw.AuditEvents(t) {
		if ev.Kind == "request" && ev.Path == "/race" && ev.Effect == "deny" && ev.Status == http.StatusForbidden {
			sawDeny = true
		}
	}
	if !sawDeny {
		t.Fatal("missing audited 403 deny for post-registration recheck")
	}
}
