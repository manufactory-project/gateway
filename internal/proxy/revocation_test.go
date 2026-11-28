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

	"github.com/manufactory-project/gateway/internal/ca"
	"github.com/manufactory-project/gateway/internal/netguard"
	"github.com/manufactory-project/gateway/internal/policy"
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
	if _, _, _, err := gw.Store.Reload(); err != nil {
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
	if _, _, _, err := gw.Store.Reload(); err != nil {
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

	gHUP, err := gw.Store.AddGrant("worker-test", "h2grant.example.com", 443, []string{"GET"}, []string{"/stream-hup"}, 5*time.Minute, false)
	if err != nil {
		t.Fatalf("AddGrant gHUP: %v", err)
	}
	rHUP, err := gw.H2Client(t, "h2grant.example.com").Get("https://h2grant.example.com/stream-hup")
	if err != nil {
		t.Fatalf("GET /stream-hup: %v", err)
	}
	<-streamOpenCh

	hupDone := make(chan error, 1)
	go func() {
		_, rErr := io.ReadAll(rHUP.Body)
		hupDone <- rErr
	}()
	sigTicker := time.NewTicker(15 * time.Millisecond)
	defer sigTicker.Stop()
	deadline := time.After(2 * time.Second)
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}
	for tornDown := false; !tornDown; {
		select {
		case <-hupDone:
			tornDown = true
		case <-sigTicker.C:
			if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
				t.Fatalf("send SIGHUP retry: %v", err)
			}
		case <-deadline:
			t.Fatalf("stream under grant %s was not torn down on SIGHUP", gHUP.ID)
		}
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
		_, wiped, _, rErr := gw.Store.Reload()
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
	if _, _, _, err := gw.Store.Reload(); err != nil {
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
		if ev.Kind == "request" && ev.Path == "/race" && ev.Effect == "deny" && ev.Status == http.StatusForbidden && ev.Reason == "admission-changed" {
			sawDeny = true
		}
	}
	if !sawDeny {
		t.Fatal("missing audited 403 admission-changed deny for post-registration recheck")
	}
}

func runFIFORecheckCase(t *testing.T, mutateWhilePaused func(t *testing.T, gw *testGateway, altSecretFile string)) {
	t.Helper()
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "secret.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	altSecretFile := filepath.Join(dir, "alt.sec")
	if err := os.WriteFile(altSecretFile, []byte("alt_secret_val\n"), 0o600); err != nil {
		t.Fatalf("write alt.sec: %v", err)
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
    paths: ["/**"]
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
		body   string
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
		raw, readErr := io.ReadAll(resp.Body)
		st := resp.StatusCode
		if cErr := resp.Body.Close(); cErr != nil {
			resCh <- reqRes{status: st, body: string(raw), err: cErr}
			return
		}
		if readErr != nil {
			resCh <- reqRes{status: st, body: string(raw), err: readErr}
			return
		}
		resCh <- reqRes{status: st, body: string(raw)}
	}()

	wf, err := os.OpenFile(fifoPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open FIFO writer: %v", err)
	}

	mutateWhilePaused(t, gw, altSecretFile)

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
		if res.status != http.StatusForbidden || !strings.Contains(res.body, "admission-changed") {
			t.Fatalf("got status=%d body=%q, want 403 admission-changed", res.status, res.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for request response")
	}
	if upHits.Load() != 0 {
		t.Fatalf("mutated admission request reached upstream: hits=%d, want 0", upHits.Load())
	}
}

func TestAdmissionRecheckRuleToGrantAndInPlaceBindingEdit(t *testing.T) {
	t.Run("rule_to_grant_transition", func(t *testing.T) {
		runFIFORecheckCase(t, func(t *testing.T, gw *testGateway, _ string) {
			// Add a narrower path-scoped grant on /race so DecideRequest transitions from rule -> grant.
			if _, err := gw.Store.AddGrant("worker-test", "recheck.example.com", 443, []string{"GET"}, []string{"/race"}, 5*time.Minute, false); err != nil {
				t.Fatalf("AddGrant: %v", err)
			}
		})
	})
	t.Run("in_place_binding_edit_same_rule_id", func(t *testing.T) {
		runFIFORecheckCase(t, func(t *testing.T, gw *testGateway, altSecretFile string) {
			// Reload keeping the exact same RuleID (allow-recheck) while editing the binding's secret_file.
			idx := strings.Index(gw.BaseYAML, "        secret_file: ")
			if idx < 0 {
				t.Fatal("missing secret_file in BaseYAML")
			}
			updated := gw.BaseYAML[:idx] + "        secret_file: " + altSecretFile + "\n"
			if err := os.WriteFile(gw.CfgPath, []byte(updated), 0o600); err != nil {
				t.Fatalf("write edited binding config: %v", err)
			}
			if _, _, _, err := gw.Store.Reload(); err != nil {
				t.Fatalf("Reload edited binding: %v", err)
			}
		})
	})
}

func waitAuditCompletedError(t *testing.T, gw *testGateway, path, wantErr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range gw.AuditEvents(t) {
			if (ev.Kind == "request" || ev.Kind == "websocket") && ev.Path == path {
				if ev.Error != wantErr {
					t.Fatalf("path %s completion audit error = %q, want %q", path, ev.Error, wantErr)
				}
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for completion audit on %s with error=%q", path, wantErr)
}

func openTestWSUpgrade(t *testing.T, gw *testGateway, host, path string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c := gw.DialTLS(t, host)
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", path, host)
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatalf("write WS upgrade %s: %v", path, err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("WS %s upgrade resp=%+v err=%v", path, resp, err)
	}
	return c, br
}

func drainHTTPAndWS(t *testing.T, resp *http.Response, wsConn net.Conn, wsBR *bufio.Reader) {
	t.Helper()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Logf("http stream ended: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Logf("close http resp: %v", err)
	}
	if _, err := io.ReadAll(wsBR); err != nil {
		t.Logf("ws stream ended: %v", err)
	}
	if err := wsConn.Close(); err != nil {
		t.Logf("close ws conn: %v", err)
	}
}

func TestFlowTeardownReasonsHTTPAndWebSocket(t *testing.T) {
	holdRelease := make(chan struct{})
	streamReady := make(chan struct{}, 16)
	hangEntered := make(chan struct{}, 4)
	gw := newTestGateway(t, testGatewaySpec{
		StartGrantPruner: true,
		OnCleanupFirst:   func() { close(holdRelease) },
		Hosts:            []string{"reason.example.com", "ttl-reason.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/hang") {
				hangEntered <- struct{}{}
				select {
				case <-r.Context().Done():
				case <-holdRelease:
				}
				return
			}
			if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				wsEchoHandler(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "data: hold\n\n"); err != nil {
				return
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
			streamReady <- struct{}{}
			select {
			case <-r.Context().Done():
			case <-holdRelease:
			}
		}),
		RulesYAML: `
  - id: allow-reason
    principal: worker-test
    effect: allow
    hosts: [reason.example.com]
    ports: [443]
    allow_websocket: true
`,
	})

	// 1. revoked (HTTP + WebSocket)
	rRev, err := gw.H1Client(t, "reason.example.com").Get("https://reason.example.com/http-revoked")
	if err != nil {
		t.Fatalf("GET /http-revoked: %v", err)
	}
	<-streamReady
	wsRev, wsRevBR := openTestWSUpgrade(t, gw, "reason.example.com", "/ws-revoked")
	if n := gw.Flows.RevokeByPrincipal("worker-test", "reason.example.com"); n != 2 {
		t.Fatalf("RevokeByPrincipal = %d, want 2", n)
	}
	drainHTTPAndWS(t, rRev, wsRev, wsRevBR)
	waitAuditCompletedError(t, gw, "/http-revoked", "revoked")
	waitAuditCompletedError(t, gw, "/ws-revoked", "revoked")

	// 2. grant-expired (HTTP + WebSocket)
	if _, err := gw.Store.AddGrant("worker-test", "ttl-reason.example.com", 443, []string{"GET"}, []string{"/**"}, 120*time.Millisecond, true); err != nil {
		t.Fatalf("AddGrant ttl: %v", err)
	}
	rExp, err := gw.H1Client(t, "ttl-reason.example.com").Get("https://ttl-reason.example.com/http-expired")
	if err != nil {
		t.Fatalf("GET /http-expired: %v", err)
	}
	<-streamReady
	wsExp, wsExpBR := openTestWSUpgrade(t, gw, "ttl-reason.example.com", "/ws-expired")
	drainHTTPAndWS(t, rExp, wsExp, wsExpBR)
	waitAuditCompletedError(t, gw, "/http-expired", "grant-expired")
	waitAuditCompletedError(t, gw, "/ws-expired", "grant-expired")

	// 3. client-canceled (HTTP + WebSocket handshake)
	cCtx, cCancel := context.WithCancel(context.Background())
	reqCancel, err := http.NewRequestWithContext(cCtx, http.MethodGet, "https://reason.example.com/hang-http", nil)
	if err != nil {
		t.Fatalf("NewRequest /hang-http: %v", err)
	}
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		if resp, dErr := gw.H1Client(t, "reason.example.com").Do(reqCancel); dErr == nil {
			if cErr := resp.Body.Close(); cErr != nil {
				t.Errorf("close canceled resp: %v", cErr)
			}
		}
	}()
	<-hangEntered
	cCancel()
	<-clientDone
	waitAuditCompletedError(t, gw, "/hang-http", "client-canceled")

	wsHang := gw.DialTLS(t, "reason.example.com")
	if _, err := io.WriteString(wsHang, "GET /hang-ws HTTP/1.1\r\nHost: reason.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"); err != nil {
		t.Fatalf("write /hang-ws: %v", err)
	}
	<-hangEntered
	if err := wsHang.Close(); err != nil {
		t.Fatalf("close wsHang: %v", err)
	}
	waitAuditCompletedError(t, gw, "/hang-ws", "client-canceled")

	// 4. reload (HTTP + WebSocket)
	rRel, err := gw.H1Client(t, "reason.example.com").Get("https://reason.example.com/http-reload")
	if err != nil {
		t.Fatalf("GET /http-reload: %v", err)
	}
	<-streamReady
	wsRel, wsRelBR := openTestWSUpgrade(t, gw, "reason.example.com", "/ws-reload")
	idx := strings.Index(gw.BaseYAML, "rules:\n")
	if err := os.WriteFile(gw.CfgPath, []byte(gw.BaseYAML[:idx]), 0o600); err != nil {
		t.Fatalf("write no-rules config: %v", err)
	}
	if _, _, _, err := gw.Store.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	drainHTTPAndWS(t, rRel, wsRel, wsRelBR)
	waitAuditCompletedError(t, gw, "/http-reload", "reload")
	waitAuditCompletedError(t, gw, "/ws-reload", "reload")
}

func TestNewServerRequiresFlows(t *testing.T) {
	gw := newTestGateway(t, testGatewaySpec{Hosts: []string{"reqflows.example.com"}})
	_, err := proxy.NewServer(proxy.Options{
		Link:      gw.Store.Current().Config.Links[0],
		Store:     gw.Store,
		Evaluator: policy.NewEvaluator(gw.Store),
		Audit:     gw.Audit,
		Leaves:    ca.NewLeafCache(testUpstreamCA),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		Flows: nil,
	})
	if err == nil {
		t.Fatal("expected proxy.NewServer with Flows=nil to return an error")
	}
}

func TestReloadFlowPathDecodingInvariants(t *testing.T) {
	t.Run("utf8_path_survives_unchanged_reload", func(t *testing.T) {
		streamOpen := make(chan struct{}, 2)
		sendSecond := make(chan struct{})
		release := make(chan struct{})
		gw := newTestGateway(t, testGatewaySpec{
			OnCleanupFirst: func() { close(release) },
			Hosts:          []string{"utf8.example.com"},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				rc := http.NewResponseController(w)
				if _, err := io.WriteString(w, "data: one\n\n"); err != nil {
					return
				}
				if err := rc.Flush(); err != nil {
					return
				}
				streamOpen <- struct{}{}
				select {
				case <-sendSecond:
					if _, err := io.WriteString(w, "data: two\n\n"); err != nil {
						return
					}
					if err := rc.Flush(); err != nil {
						return
					}
				case <-r.Context().Done():
				case <-release:
				}
			}),
			RulesYAML: `
  - id: allow-cafe
    principal: worker-test
    effect: allow
    hosts: [utf8.example.com]
    ports: [443]
    paths: ["/files/café"]
`,
		})

		resp, err := gw.H1Client(t, "utf8.example.com").Get("https://utf8.example.com/files/caf%C3%A9")
		if err != nil {
			t.Fatalf("GET /files/caf%%C3%%A9: %v", err)
		}
		defer func() {
			if cErr := resp.Body.Close(); cErr != nil {
				t.Logf("close resp: %v", cErr)
			}
		}()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		<-streamOpen

		_, _, revoked, err := gw.Store.Reload()
		if err != nil {
			t.Fatalf("unchanged Reload: %v", err)
		}
		if revoked != 0 {
			t.Fatalf("unchanged reload revoked %d flow(s) on /files/café, want 0", revoked)
		}
		close(sendSecond)
		body, rErr := io.ReadAll(resp.Body)
		if rErr != nil {
			t.Fatalf("read surviving stream: %v", rErr)
		}
		if !strings.Contains(string(body), "data: two") {
			t.Fatalf("stream did not receive post-reload data: %q", string(body))
		}
	})

	t.Run("percent_encoded_ascii_revoked_when_reload_adds_deny", func(t *testing.T) {
		streamOpen := make(chan struct{}, 2)
		release := make(chan struct{})
		gw := newTestGateway(t, testGatewaySpec{
			OnCleanupFirst: func() { close(release) },
			Hosts:          []string{"enc.example.com"},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				if _, err := io.WriteString(w, "data: open\n\n"); err != nil {
					return
				}
				if err := http.NewResponseController(w).Flush(); err != nil {
					return
				}
				streamOpen <- struct{}{}
				select {
				case <-r.Context().Done():
				case <-release:
				}
			}),
			RulesYAML: `
  - id: allow-all
    principal: worker-test
    effect: allow
    hosts: [enc.example.com]
    ports: [443]
    paths: ["/**"]
`,
		})

		conn := gw.DialTLS(t, "enc.example.com")
		defer func() {
			if cErr := conn.Close(); cErr != nil {
				t.Logf("close conn: %v", cErr)
			}
		}()
		if _, err := io.WriteString(conn, "GET /v1/%61dmin HTTP/1.1\r\nHost: enc.example.com\r\n\r\n"); err != nil {
			t.Fatalf("write raw request: %v", err)
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /v1/%%61dmin resp=%+v err=%v", resp, err)
		}
		<-streamOpen

		denyRule := `  - id: deny-admin
    principal: worker-test
    effect: deny
    hosts: [enc.example.com]
    ports: [443]
    paths: ["/v1/admin"]
`
		if err := os.WriteFile(gw.CfgPath, []byte(gw.BaseYAML+denyRule), 0o600); err != nil {
			t.Fatalf("write updated config: %v", err)
		}
		_, _, revoked, err := gw.Store.Reload()
		if err != nil {
			t.Fatalf("Reload with deny rule: %v", err)
		}
		if revoked != 1 {
			t.Fatalf("reload adding deny /v1/admin revoked %d flow(s) for /v1/%%61dmin, want 1", revoked)
		}
		if _, rErr := io.Copy(io.Discard, resp.Body); rErr != nil {
			t.Logf("revoked stream ended: %v", rErr)
		}
		if cErr := resp.Body.Close(); cErr != nil {
			t.Logf("close resp: %v", cErr)
		}
		waitAuditCompletedError(t, gw, "/v1/%61dmin", "reload")
	})
}

func TestRevokeReloadedFlowsWipedGrantAndWebSocketFlagRemoved(t *testing.T) {
	t.Run("wiped_grant_torn_down_even_when_reloaded_rule_allows", func(t *testing.T) {
		streamOpen := make(chan struct{}, 2)
		release := make(chan struct{})
		gw := newTestGateway(t, testGatewaySpec{
			OnCleanupFirst: func() { close(release) },
			Hosts:          []string{"wiped.example.com"},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				if _, err := io.WriteString(w, "data: open\n\n"); err != nil {
					return
				}
				if err := http.NewResponseController(w).Flush(); err != nil {
					return
				}
				streamOpen <- struct{}{}
				select {
				case <-r.Context().Done():
				case <-release:
				}
			}),
		})

		if _, err := gw.Store.AddGrant("worker-test", "wiped.example.com", 443, []string{"GET"}, []string{"/stream"}, 5*time.Minute, false); err != nil {
			t.Fatalf("AddGrant: %v", err)
		}
		resp, err := gw.H1Client(t, "wiped.example.com").Get("https://wiped.example.com/stream")
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /stream: resp=%+v err=%v", resp, err)
		}
		<-streamOpen

		// Reload adds an explicit allow rule for wiped.example.com so DecideRequest allows it,
		// yet the grant-admitted flow MUST still be torn down because its grant was wiped.
		addedRule := `rules:
  - id: allow-wiped-now
    principal: worker-test
    effect: allow
    hosts: [wiped.example.com]
    ports: [443]
`
		if err := os.WriteFile(gw.CfgPath, []byte(gw.BaseYAML+addedRule), 0o600); err != nil {
			t.Fatalf("write reloaded config: %v", err)
		}
		_, _, revoked, err := gw.Store.Reload()
		if err != nil {
			t.Fatalf("Reload: %v", err)
		}
		if revoked != 1 {
			t.Fatalf("Reload revoked %d flow(s), want 1 (grant was wiped even though new rule allows host)", revoked)
		}
		if _, rErr := io.Copy(io.Discard, resp.Body); rErr != nil {
			t.Logf("stream closed on reload: %v", rErr)
		}
		if cErr := resp.Body.Close(); cErr != nil {
			t.Logf("close resp: %v", cErr)
		}
		waitAuditCompletedError(t, gw, "/stream", "reload")
	})

	t.Run("websocket_torn_down_when_allow_websocket_removed_while_http_stays_allowed", func(t *testing.T) {
		streamOpen := make(chan struct{}, 2)
		sendSecond := make(chan struct{})
		release := make(chan struct{})
		gw := newTestGateway(t, testGatewaySpec{
			OnCleanupFirst: func() { close(release) },
			Hosts:          []string{"wsdrop.example.com"},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
					wsEchoHandler(w, r)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				rc := http.NewResponseController(w)
				if _, err := io.WriteString(w, "data: one\n\n"); err != nil {
					return
				}
				if err := rc.Flush(); err != nil {
					return
				}
				streamOpen <- struct{}{}
				select {
				case <-sendSecond:
					if _, err := io.WriteString(w, "data: two\n\n"); err != nil {
						return
					}
					if err := rc.Flush(); err != nil {
						return
					}
				case <-r.Context().Done():
				case <-release:
				}
			}),
			RulesYAML: `
  - id: allow-wsdrop
    principal: worker-test
    effect: allow
    hosts: [wsdrop.example.com]
    ports: [443]
    allow_websocket: true
`,
		})

		httpResp, err := gw.H1Client(t, "wsdrop.example.com").Get("https://wsdrop.example.com/keep-http")
		if err != nil || httpResp.StatusCode != http.StatusOK {
			t.Fatalf("GET /keep-http: resp=%+v err=%v", httpResp, err)
		}
		defer func() {
			if cErr := httpResp.Body.Close(); cErr != nil {
				t.Logf("close httpResp: %v", cErr)
			}
		}()
		<-streamOpen

		wsConn, wsBR := openTestWSUpgrade(t, gw, "wsdrop.example.com", "/drop-ws")
		updated := strings.Replace(gw.BaseYAML, "    allow_websocket: true\n", "", 1)
		if err := os.WriteFile(gw.CfgPath, []byte(updated), 0o600); err != nil {
			t.Fatalf("write config without allow_websocket: %v", err)
		}
		_, _, revoked, err := gw.Store.Reload()
		if err != nil {
			t.Fatalf("Reload removing allow_websocket: %v", err)
		}
		if revoked != 1 {
			t.Fatalf("Reload revoked %d flow(s), want 1 (only WebSocket, not HTTP)", revoked)
		}
		if _, rErr := io.ReadAll(wsBR); rErr != nil {
			t.Logf("ws closed on reload: %v", rErr)
		}
		if cErr := wsConn.Close(); cErr != nil {
			t.Logf("close wsConn: %v", cErr)
		}
		waitAuditCompletedError(t, gw, "/drop-ws", "reload")

		close(sendSecond)
		body, rErr := io.ReadAll(httpResp.Body)
		if rErr != nil || !strings.Contains(string(body), "data: two") {
			t.Fatalf("HTTP stream should survive allow_websocket removal: body=%q err=%v", string(body), rErr)
		}
	})
}
