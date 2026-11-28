// SPDX-License-Identifier: AGPL-3.0-only

package proxy_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
)

func wsEchoHandler(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "need ws", http.StatusBadRequest)
		return
	}
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
	if _, err := io.Copy(conn, rw); err != nil {
		return
	}
}

func TestWebSocketEchoAndEgressCap(t *testing.T) {
	gw := newTestGateway(t, testGatewaySpec{
		HTTPBlockYAML: "http:\n  ws_max_egress_bytes: 64\n",
		Hosts:         []string{"ws.example.com"},
		Handler:       http.HandlerFunc(wsEchoHandler),
		RulesYAML: `
  - id: allow-ws
    principal: worker-test
    effect: allow
    hosts: [ws.example.com]
    ports: [443]
    methods: [GET]
    paths: ["/ws"]
    allow_websocket: true
    ws_max_egress_bytes: 64
`,
	})

	wsConn := gw.DialTLS(t, "ws.example.com")
	if _, err := io.WriteString(wsConn, "GET /ws HTTP/1.1\r\nHost: ws.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"); err != nil {
		t.Fatalf("write WS upgrade: %v", err)
	}
	wsBR := bufio.NewReader(wsConn)
	wsResp, err := http.ReadResponse(wsBR, nil)
	if err != nil {
		t.Fatalf("read WS 101: %v", err)
	}
	if wsResp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("WS status = %d, want 101", wsResp.StatusCode)
	}

	// Small payload (10B <= 64B cap) echoed cleanly.
	if _, err := io.WriteString(wsConn, "hello-ws!!"); err != nil {
		t.Fatalf("write small ws payload: %v", err)
	}
	echoBuf := make([]byte, 10)
	if _, err := io.ReadFull(wsBR, echoBuf); err != nil {
		t.Fatalf("read ws echo: %v", err)
	}
	if string(echoBuf) != "hello-ws!!" {
		t.Fatalf("ws echo = %q", echoBuf)
	}

	// Exceeding 64B egress cap tears down the connection immediately.
	if _, writeErr := wsConn.Write(bytes.Repeat([]byte("X"), 128)); writeErr != nil {
		t.Logf("wsConn write stopped during teardown: %v", writeErr)
	}
	if err := wsConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set WS read deadline: %v", err)
	}
	drained, drainErr := io.ReadAll(wsBR)
	if drainErr != nil {
		t.Logf("wsConn read ended with expected close error: %v", drainErr)
	}
	if len(drained) > 64 {
		t.Fatalf("WS proxy forwarded %d bytes past 64B cap", len(drained))
	}
	if err := wsConn.Close(); err != nil {
		t.Fatalf("close wsConn: %v", err)
	}
}

func TestWebSocketUpgradeWithBodyRejected(t *testing.T) {
	var upReceived atomic.Int32
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"ws.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upReceived.Add(1)
			wsEchoHandler(w, r)
		}),
		RulesYAML: `
  - id: allow-ws
    principal: worker-test
    effect: allow
    hosts: [ws.example.com]
    ports: [443]
    allow_websocket: true
`,
	})

	for _, tc := range []struct {
		name string
		raw  string
	}{
		{
			name: "ws-with-content-length",
			raw:  "GET /ws HTTP/1.1\r\nHost: ws.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nContent-Length: 5\r\n\r\nhello",
		},
		{
			name: "ws-with-chunked-te",
			raw:  "GET /ws HTTP/1.1\r\nHost: ws.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
		},
	} {
		conn := gw.DialTLS(t, "ws.example.com")
		if _, err := io.WriteString(conn, tc.raw); err != nil {
			t.Fatalf("%s write: %v", tc.name, err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("%s ReadResponse: %v", tc.name, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("%s close body: %v", tc.name, err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("%s close conn: %v", tc.name, err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: status=%d, want 400", tc.name, resp.StatusCode)
		}
	}
	if upReceived.Load() != 0 {
		t.Fatalf("WS upgrade with body hit upstream: %d != 0", upReceived.Load())
	}

	// Positive control: bodyless WS upgrade succeeds (101).
	wsConn := gw.DialTLS(t, "ws.example.com")
	if _, err := io.WriteString(wsConn, "GET /ws HTTP/1.1\r\nHost: ws.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"); err != nil {
		t.Fatalf("ws positive write: %v", err)
	}
	wsResp, err := http.ReadResponse(bufio.NewReader(wsConn), nil)
	if err != nil || wsResp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("ws positive status = %v err = %v, want 101", wsResp, err)
	}
	if err := wsConn.Close(); err != nil {
		t.Fatalf("close wsConn: %v", err)
	}
}

func TestWebSocketUpstreamNonWS101Returns502(t *testing.T) {
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"ws101.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			conn, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer func() {
				if cErr := conn.Close(); cErr != nil {
					return
				}
			}()
			if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"); err != nil {
				return
			}
		}),
		RulesYAML: `
  - id: allow-ws101
    principal: worker-test
    effect: allow
    hosts: [ws101.example.com]
    ports: [443]
    allow_websocket: true
`,
	})

	conn := gw.DialTLS(t, "ws101.example.com")
	if _, err := io.WriteString(conn, "GET /ws-fake-101 HTTP/1.1\r\nHost: ws101.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"); err != nil {
		t.Fatalf("ws101 write: %v", err)
	}
	resp101, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ws101 ReadResponse: %v", err)
	}
	if err := resp101.Body.Close(); err != nil {
		t.Fatalf("close resp101: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close ws101 conn: %v", err)
	}
	if resp101.StatusCode != http.StatusBadGateway {
		t.Fatalf("upstream non-WS 101 returned status=%d, want 502", resp101.StatusCode)
	}

	var sawNonWS101 bool
	for _, ev := range gw.AuditEvents(t) {
		if ev.Error == "unexpected-101-non-websocket" && ev.Status == http.StatusBadGateway {
			sawNonWS101 = true
		}
	}
	if !sawNonWS101 {
		t.Fatal("missing audit record for unexpected-101-non-websocket")
	}
}

func TestWebSocketGuestDisconnectDuringHandshakeClosesUpstreamAndUnregistersFlow(t *testing.T) {
	reqReceived := make(chan struct{}, 2)
	upClosed := make(chan struct{}, 2)

	rawLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen silent ws upstream: %v", err)
	}
	silentPort := tcpPort(t, rawLn.Addr())

	const host = "ws-silent.example.com"
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{host},
		RulesYAML: `
  - id: allow-ws-silent
    principal: worker-test
    effect: allow
    hosts: [ws-silent.example.com]
    ports: [443]
    allow_websocket: true
`,
		DialOverride: func(guard guardDial, _, _ uint16) func(ctx context.Context, network, addr string) (net.Conn, error) {
			return func(ctx context.Context, network, addr string) (net.Conn, error) {
				h, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				return guard(ctx, network, h, silentPort)
			}
		},
	})

	tlsLn := tls.NewListener(rawLn, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{makeSignedServerCert(t, testUpstreamCA, []string{host})},
	})
	var (
		upMu    sync.Mutex
		upConns []net.Conn
		upWG    sync.WaitGroup
	)
	upWG.Add(1)
	go func() {
		defer upWG.Done()
		for {
			c, aErr := tlsLn.Accept()
			if aErr != nil {
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
				req, rErr := http.ReadRequest(br)
				if rErr != nil {
					return
				}
				if cErr := req.Body.Close(); cErr != nil {
					return
				}
				reqReceived <- struct{}{}
				var buf [1]byte
				if _, rErr := br.Read(buf[:]); rErr != nil {
					upClosed <- struct{}{}
				}
			}(c)
		}
	}()
	t.Cleanup(func() {
		if cErr := tlsLn.Close(); cErr != nil {
			t.Logf("close silent tlsLn: %v", cErr)
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

	guestConn := gw.DialTLS(t, host)
	if _, err := io.WriteString(guestConn, "GET /ws-hang HTTP/1.1\r\nHost: "+host+"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"); err != nil {
		t.Fatalf("write WS upgrade: %v", err)
	}
	select {
	case <-reqReceived:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for silent upstream to receive WS upgrade")
	}

	// Guest disconnects while upstream never answers.
	if err := guestConn.Close(); err != nil {
		t.Fatalf("close guestConn: %v", err)
	}

	select {
	case <-upClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream connection remained open after guest disconnected during WS handshake")
	}

	deadline := time.Now().Add(2 * time.Second)
	for gw.Flows.Count() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if cnt := gw.Flows.Count(); cnt != 0 {
		t.Fatalf("flow remained in registry after guest disconnect during WS handshake: count=%d", cnt)
	}
}

func TestWebSocketUpgradeRefusedOnBoundHostAndSweepsHeaders(t *testing.T) {
	secFile := writeSecretFile(t, t.TempDir(), "ws.sec", "ws_secret_val\n")
	var (
		boundHits atomic.Int32
		hdrMu     sync.Mutex
		seenHdr   http.Header
	)

	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"bound-ws.example.com", "ws-sweep.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host == "bound-ws.example.com" {
				boundHits.Add(1)
			}
			hdrMu.Lock()
			seenHdr = r.Header.Clone()
			hdrMu.Unlock()
			wsEchoHandler(w, r)
		}),
		RulesYAML: fmt.Sprintf(`
  - id: allow-bound-host
    principal: worker-test
    effect: allow
    hosts: [bound-ws.example.com]
    ports: [443]
    bindings:
      - name: bound-tok
        host: bound-ws.example.com
        header: Authorization
        scheme: bearer
        placeholder: mf_ph_bound_ws
        secret_file: %s
  - id: allow-ws-sweep
    principal: worker-test
    effect: allow
    hosts: [ws-sweep.example.com]
    ports: [443]
    allow_websocket: true
`, secFile),
	})

	// 1. WebSocket upgrade on a bound host must be refused with 403 and never reach upstream.
	connBound := gw.DialTLS(t, "bound-ws.example.com")
	if _, err := io.WriteString(connBound, "GET /ws HTTP/1.1\r\nHost: bound-ws.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"); err != nil {
		t.Fatalf("write bound WS upgrade: %v", err)
	}
	respBound, err := http.ReadResponse(bufio.NewReader(connBound), nil)
	if err != nil {
		t.Fatalf("read bound WS resp: %v", err)
	}
	if err := respBound.Body.Close(); err != nil {
		t.Fatalf("close bound WS resp: %v", err)
	}
	if err := connBound.Close(); err != nil {
		t.Fatalf("close connBound: %v", err)
	}
	if respBound.StatusCode != http.StatusForbidden {
		t.Fatalf("bound host WS upgrade status = %d, want 403", respBound.StatusCode)
	}
	if boundHits.Load() != 0 {
		t.Fatalf("bound host WS upgrade reached upstream: hits=%d", boundHits.Load())
	}

	// 2. Allowed WebSocket upgrade must strip Proxy-Authorization and all mf_ph_* placeholders.
	connWS := gw.DialTLS(t, "ws-sweep.example.com")
	basicPh := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:mf_ph_wsbasic"))
	upgradeReq := "GET /ws HTTP/1.1\r\n" +
		"Host: ws-sweep.example.com\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Proxy-Authorization: Bearer proxy_secret\r\n" +
		"X-Leak: mf_ph_wsleak\r\n" +
		"Authorization: " + basicPh + "\r\n\r\n"
	if _, err := io.WriteString(connWS, upgradeReq); err != nil {
		t.Fatalf("write sweep WS upgrade: %v", err)
	}
	respWS, err := http.ReadResponse(bufio.NewReader(connWS), nil)
	if err != nil {
		t.Fatalf("read sweep WS resp: %v", err)
	}
	if err := connWS.Close(); err != nil {
		t.Fatalf("close connWS: %v", err)
	}
	if respWS.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("ws-sweep status = %d, want 101", respWS.StatusCode)
	}
	hdrMu.Lock()
	h := seenHdr.Clone()
	hdrMu.Unlock()
	if h.Get("Proxy-Authorization") != "" {
		t.Fatalf("Proxy-Authorization leaked on WebSocket upgrade: %q", h.Get("Proxy-Authorization"))
	}
	if h.Get("X-Leak") != "" {
		t.Fatalf("mf_ph_* header leaked on WebSocket upgrade: %q", h.Get("X-Leak"))
	}
	if h.Get("Authorization") != "" {
		t.Fatalf("Basic mf_ph_* Authorization leaked on WebSocket upgrade: %q", h.Get("Authorization"))
	}
}

func TestTruncatedNonUpgradeResponseIsAuditedByClass(t *testing.T) {
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"ws.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeRawHTTP1(w, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
		}),
		RulesYAML: `
  - id: allow-ws
    principal: worker-test
    effect: allow
    hosts: [ws.example.com]
    ports: [443]
    allow_websocket: true
`,
	})
	resp := do(t, gw.H1Client(t, "ws.example.com"), http.MethodGet, "https://ws.example.com/ws",
		map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"})
	// The abort follows the completion audit, so the failed read orders the check.
	if body, err := io.ReadAll(resp.Body); err == nil {
		t.Fatalf("truncated response read cleanly: %q", body)
	}
	var got []string
	for _, ev := range gw.AuditEvents(t) {
		if ev.Kind == audit.KindWebSocket {
			got = append(got, ev.Error)
		}
	}
	if len(got) != 1 || got[0] != "upstream-error: connection-closed" {
		t.Fatalf("websocket completion errors = %q, want [upstream-error: connection-closed]", got)
	}
}
