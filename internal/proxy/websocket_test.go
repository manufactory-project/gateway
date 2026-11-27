package proxy_test

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
