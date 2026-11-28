// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy_test

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
)

func sendRawTLSClientHello(t *testing.T, addr, sni string) {
	t.Helper()
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03}) // TLS 1.2
	body.Write(make([]byte, 32))   // Random
	body.WriteByte(0x00)           // SessionID length = 0
	body.Write([]byte{0x00, 0x02, 0xc0, 0x2f})
	body.Write([]byte{0x01, 0x00}) // Compression methods: null
	if sni != "" {
		var ext bytes.Buffer
		var sniList bytes.Buffer
		sniList.WriteByte(0x00) // host_name
		if err := binary.Write(&sniList, binary.BigEndian, uint16(len(sni))); err != nil {
			t.Fatalf("encode sni len: %v", err)
		}
		sniList.WriteString(sni)

		ext.Write([]byte{0x00, 0x00}) // extension_type: server_name
		if err := binary.Write(&ext, binary.BigEndian, uint16(2+sniList.Len())); err != nil {
			t.Fatalf("encode ext len: %v", err)
		}
		if err := binary.Write(&ext, binary.BigEndian, uint16(sniList.Len())); err != nil {
			t.Fatalf("encode sniList len: %v", err)
		}
		ext.Write(sniList.Bytes())

		if err := binary.Write(&body, binary.BigEndian, uint16(ext.Len())); err != nil {
			t.Fatalf("encode exts len: %v", err)
		}
		body.Write(ext.Bytes())
	} else {
		body.Write([]byte{0x00, 0x00}) // no extensions
	}

	bLen := body.Len()
	hs := make([]byte, 4+bLen)
	hs[0] = 0x01 // ClientHello
	hs[1] = byte(bLen >> 16)
	hs[2] = byte(bLen >> 8)
	hs[3] = byte(bLen)
	copy(hs[4:], body.Bytes())

	rec := make([]byte, 5+len(hs))
	rec[0] = 0x16 // Handshake record
	rec[1] = 0x03
	rec[2] = 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial %s for raw ClientHello (sni=%q): %v", addr, sni, err)
	}
	if _, err := conn.Write(rec); err != nil {
		if cErr := conn.Close(); cErr != nil {
			t.Errorf("close raw conn: %v", cErr)
		}
		t.Fatalf("write ClientHello (sni=%q): %v", sni, err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		if cErr := conn.Close(); cErr != nil {
			t.Errorf("close raw conn: %v", cErr)
		}
		t.Fatalf("set deadline: %v", err)
	}
	// Wait for TLS alert / close so synchronous audit write completes before returning.
	var reply [64]byte
	if _, err := conn.Read(reply[:]); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			if cErr := conn.Close(); cErr != nil {
				t.Errorf("close raw conn: %v", cErr)
			}
			t.Fatalf("timed out waiting for TLS rejection (sni=%q)", sni)
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close raw conn: %v", err)
	}
}

func TestDeniedSNINoLeafMintAndSSHRejected(t *testing.T) {
	gw := newTestGateway(t, testGatewaySpec{
		CountCASigns: true,
		Hosts:        []string{"api.example.com"},
		RulesYAML: `
  - id: allow-api
    principal: worker-test
    effect: allow
    hosts: [api.example.com]
    ports: [443]
`,
	})

	// 1. Denied SNI fails TLS handshake, never mints/caches a leaf, and writes one audit record.
	if _, err := gw.H1Client(t, "blocked.example.com").Get("https://blocked.example.com/"); err == nil {
		t.Fatal("expected TLS handshake failure for denied SNI")
	}

	// 2. Missing SNI and IP-literal SNI fail TLS handshake without minting leaves and are audited.
	sendRawTLSClientHello(t, gw.HTTPSAddr, "")
	sendRawTLSClientHello(t, gw.HTTPSAddr, "1.2.3.4")

	if gw.CASigns.signs.Load() != 0 {
		t.Fatalf("denied/missing/IP SNIs must never mint or cache a leaf, got %d CA signs", gw.CASigns.signs.Load())
	}

	events := gw.AuditEvents(t)
	assertOneTLSDeny := func(wantHost, wantReason string) {
		t.Helper()
		count := 0
		for _, ev := range events {
			if ev.Protocol == "tls" && ev.Effect == audit.EffectDeny && ev.Host == wantHost && ev.Reason == wantReason {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("expected exactly 1 tls deny audit event for host=%q reason=%q, got %d (events=%+v)", wantHost, wantReason, count, events)
		}
	}
	assertOneTLSDeny("blocked.example.com", "default-deny")
	assertOneTLSDeny("", "missing-sni")
	assertOneTLSDeny("1.2.3.4", "ip-literal-sni")

	// Non-TLS SSH traffic over port 443 fails TLS handshake (no raw-TCP fallback).
	sshConn, err := net.DialTimeout("tcp", gw.HTTPSAddr, time.Second)
	if err != nil {
		t.Fatalf("dial https for SSH test: %v", err)
	}
	if _, err := io.WriteString(sshConn, "SSH-2.0-OpenSSH_9.6\r\n"); err != nil {
		t.Fatalf("write SSH banner: %v", err)
	}
	buf := make([]byte, 64)
	if err := sshConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	n, readErr := sshConn.Read(buf)
	if readErr == nil && strings.HasPrefix(string(buf[:n]), "SSH-") {
		t.Fatalf("SSH banner echoed on port 443: %q", string(buf[:n]))
	}
	if err := sshConn.Close(); err != nil {
		t.Fatalf("close sshConn: %v", err)
	}
}

func TestHTTP1RequestGuardsAndMethodPathDeny(t *testing.T) {
	var httpsReceived atomic.Int32
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"api.example.com", "ws.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			httpsReceived.Add(1)
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: `
  - id: allow-api
    principal: worker-test
    effect: allow
    hosts: [api.example.com]
    ports: [443]
    methods: [GET, POST]
    paths: ["/v1/**"]
  - id: allow-ws
    principal: worker-test
    effect: allow
    hosts: [ws.example.com]
    ports: [443]
    methods: [GET]
    paths: ["/ws"]
    allow_websocket: true
`,
	})

	cAPI := gw.H1Client(t, "api.example.com")
	for _, tc := range []struct {
		method string
		url    string
		host   string
		hdrs   map[string]string
	}{
		{http.MethodDelete, "https://api.example.com/v1/ok", "", nil},
		{http.MethodGet, "https://api.example.com/v2/forbidden", "", nil},
		{http.MethodGet, "https://api.example.com/ws", "ws.example.com", nil},
		{http.MethodGet, "https://api.example.com/v1/ok", "api.example.com:8443", nil},
		{http.MethodGet, "https://api.example.com/v1/ok", "", map[string]string{"Connection": "Upgrade", "Upgrade": "h2c"}},
		{http.MethodGet, "https://api.example.com/v1/ok", "", map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"}},
	} {
		req, err := http.NewRequest(tc.method, tc.url, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		if tc.host != "" {
			req.Host = tc.host
		}
		for k, v := range tc.hdrs {
			req.Header.Set(k, v)
		}
		r, err := cAPI.Do(req)
		if err != nil {
			t.Fatalf("Do %s %s (host=%q): %v", tc.method, tc.url, tc.host, err)
		}
		if err := r.Body.Close(); err != nil {
			t.Fatalf("close body: %v", err)
		}
		if r.StatusCode != http.StatusForbidden {
			t.Fatalf("%s %s (host=%q hdrs=%v): status=%d, want 403", tc.method, tc.url, tc.host, tc.hdrs, r.StatusCode)
		}
	}

	// Raw HTTP/1.1 wire tests for CONNECT, asterisk '*', absolute-URI, and path traversal '..'.
	for _, tc := range []struct {
		rawReq     string
		wantReason string
	}{
		{"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "connect-forbidden"},
		{"OPTIONS * HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "asterisk-target-forbidden"},
		{"GET https://api.example.com/v1/ok HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "absolute-uri-forbidden"},
		{"GET /v1/../secret HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "path-traversal"},
	} {
		tcConn := gw.DialTLS(t, "api.example.com")
		if _, err := io.WriteString(tcConn, tc.rawReq); err != nil {
			t.Fatalf("write raw req: %v", err)
		}
		r, err := http.ReadResponse(bufio.NewReader(tcConn), nil)
		if err != nil {
			t.Fatalf("ReadResponse for %q: %v", tc.rawReq, err)
		}
		rawBody, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read raw resp: %v", err)
		}
		if err := r.Body.Close(); err != nil {
			t.Fatalf("close raw resp: %v", err)
		}
		if err := tcConn.Close(); err != nil {
			t.Fatalf("close raw tls conn: %v", err)
		}
		if r.StatusCode != http.StatusForbidden || !strings.Contains(string(rawBody), tc.wantReason) {
			t.Fatalf("raw req %q: status=%d body=%q, want 403 containing %q", tc.rawReq, r.StatusCode, rawBody, tc.wantReason)
		}
	}

	if httpsReceived.Load() != 0 {
		t.Fatalf("blocked requests reached upstream: received=%d, want 0", httpsReceived.Load())
	}
}

func TestNonCanonicalPathsRejectedH1AndH2(t *testing.T) {
	var upReceived atomic.Int32
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"canon.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upReceived.Add(1)
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "ok:"+r.URL.Path); err != nil {
				return
			}
		}),
		RulesYAML: `
  - id: allow-canon
    principal: worker-test
    effect: allow
    hosts: [canon.example.com]
    ports: [443]
    paths: ["/**"]
  - id: deny-admin
    principal: worker-test
    effect: deny
    hosts: [canon.example.com]
    ports: [443]
    paths: ["/v1/admin"]
`,
	})

	badPaths := []string{"/./", "//", "/a/.", "/v1/./admin", "/v1//admin", "/a//"}
	for _, h2 := range []bool{false, true} {
		protoLabel := "H1"
		c := gw.H1Client(t, "canon.example.com")
		if h2 {
			protoLabel = "H2"
			c = gw.H2Client(t, "canon.example.com")
		}

		before := upReceived.Load()
		for _, p := range badPaths {
			req, err := http.NewRequest(http.MethodGet, "https://canon.example.com"+p, nil)
			if err != nil {
				t.Fatalf("%s NewRequest %q: %v", protoLabel, p, err)
			}
			resp, err := c.Do(req)
			if err != nil {
				t.Fatalf("%s Do %q: %v", protoLabel, p, err)
			}
			if err := resp.Body.Close(); err != nil {
				t.Fatalf("close body: %v", err)
			}
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("%s path %q: status=%d, want 403", protoLabel, p, resp.StatusCode)
			}
		}
		if upReceived.Load() != before {
			t.Fatalf("%s non-canonical path reached upstream: %d != %d", protoLabel, upReceived.Load(), before)
		}

		// Positive control: single trailing slash "/a/" is allowed on both H1 and H2.
		respOK, err := c.Get("https://canon.example.com/a/")
		if err != nil {
			t.Fatalf("%s GET /a/: %v", protoLabel, err)
		}
		b, err := io.ReadAll(respOK.Body)
		if err != nil {
			t.Fatalf("read /a/: %v", err)
		}
		if err := respOK.Body.Close(); err != nil {
			t.Fatalf("close /a/: %v", err)
		}
		if respOK.StatusCode != http.StatusOK || string(b) != "ok:/a/" {
			t.Fatalf("%s GET /a/ got status=%d body=%q", protoLabel, respOK.StatusCode, b)
		}
		if h2 && respOK.ProtoMajor != 2 {
			t.Fatalf("expected H2 response, got %s", respOK.Proto)
		}
	}
}

func TestRedirectsNotFollowed(t *testing.T) {
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"api.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "https://evil.example/steal")
			w.WriteHeader(http.StatusFound)
		}),
		RulesYAML: `
  - id: allow-api
    principal: worker-test
    effect: allow
    hosts: [api.example.com]
    ports: [443]
`,
	})

	r302, err := gw.H1Client(t, "api.example.com").Get("https://api.example.com/v1/redirect")
	if err != nil {
		t.Fatalf("GET redirect: %v", err)
	}
	if err := r302.Body.Close(); err != nil {
		t.Fatalf("close r302: %v", err)
	}
	if r302.StatusCode != http.StatusFound || r302.Header.Get("Location") != "https://evil.example/steal" {
		t.Fatalf("expected raw 302 passthrough, got status=%d loc=%q", r302.StatusCode, r302.Header.Get("Location"))
	}
}

func TestStreamingRequestBodyCap(t *testing.T) {
	subToken := "sub_oauth_" + randHex(t)
	var seenSubAuth atomic.Value

	gw := newTestGateway(t, testGatewaySpec{
		HTTPBlockYAML: "http:\n  max_request_body_bytes: 128\n  max_header_bytes: 32768\n",
		Hosts:         []string{"api.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if auth := r.Header.Get("Authorization"); auth != "" {
				seenSubAuth.Store(auth)
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("ok:" + strconv.Itoa(len(body)))); err != nil {
				return
			}
		}),
		RulesYAML: `
  - id: allow-api
    principal: worker-test
    effect: allow
    hosts: [api.example.com]
    ports: [443]
    methods: [GET, POST]
    paths: ["/v1/**"]
`,
	})

	cAPI := gw.H1Client(t, "api.example.com")

	// Streaming chunked body over 128B cap -> 413.
	pr, pw := io.Pipe()
	go func() {
		if _, err := pw.Write(bytes.Repeat([]byte("A"), 200)); err != nil {
			return
		}
		if err := pw.Close(); err != nil {
			return
		}
	}()
	reqOver, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/ok", pr)
	if err != nil {
		t.Fatalf("NewRequest chunked over: %v", err)
	}
	reqOver.ContentLength = -1
	rOver, err := cAPI.Do(reqOver)
	if err != nil {
		t.Fatalf("chunked over cap request: %v", err)
	}
	if err := rOver.Body.Close(); err != nil {
		t.Fatalf("close rOver: %v", err)
	}
	if rOver.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked over cap status = %d, want 413", rOver.StatusCode)
	}

	// Positive control: chunked POST under cap (64B <= 128B) succeeds 200 with subscription auth intact.
	pr2, pw2 := io.Pipe()
	go func() {
		if _, err := pw2.Write(bytes.Repeat([]byte("B"), 64)); err != nil {
			return
		}
		if err := pw2.Close(); err != nil {
			return
		}
	}()
	reqUnder, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/ok", pr2)
	if err != nil {
		t.Fatalf("NewRequest chunked under: %v", err)
	}
	reqUnder.ContentLength = -1
	reqUnder.Header.Set("Authorization", "Bearer "+subToken)
	rUnder, err := cAPI.Do(reqUnder)
	if err != nil {
		t.Fatalf("chunked under cap: %v", err)
	}
	bodyUnder, err := io.ReadAll(rUnder.Body)
	if err != nil {
		t.Fatalf("read under body: %v", err)
	}
	if err := rUnder.Body.Close(); err != nil {
		t.Fatalf("close rUnder: %v", err)
	}
	if rUnder.StatusCode != http.StatusOK || string(bodyUnder) != "ok:64" {
		t.Fatalf("chunked under cap got status=%d body=%q", rUnder.StatusCode, bodyUnder)
	}
	gotAuth, ok := seenSubAuth.Load().(string)
	if !ok || gotAuth != "Bearer "+subToken {
		t.Fatalf("subscription Authorization not passed untouched: got %q", gotAuth)
	}
	gw.AssertAuditNotContains(t, subToken)
}

func TestCleartextPort80OptInAndDeny(t *testing.T) {
	var httpReceived atomic.Int32
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"api.example.com", "plain.example.com"},
		PlainHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			httpReceived.Add(1)
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "plain-ok"); err != nil {
				return
			}
		}),
		RulesYAML: `
  - id: allow-api
    principal: worker-test
    effect: allow
    hosts: [api.example.com]
    ports: [443]
  - id: allow-plain
    principal: worker-test
    effect: allow
    hosts: [plain.example.com]
    ports: [80]
`,
	})

	plainClient := gw.PlainClient(t)

	rPlainDeny, err := plainClient.Get("http://api.example.com/v1/ok")
	if err != nil {
		t.Fatalf("http deny check: %v", err)
	}
	if err := rPlainDeny.Body.Close(); err != nil {
		t.Fatalf("close rPlainDeny: %v", err)
	}
	if rPlainDeny.StatusCode != http.StatusForbidden {
		t.Fatalf("port 80 on 443-only host status = %d, want 403", rPlainDeny.StatusCode)
	}
	if httpReceived.Load() != 0 {
		t.Fatalf("denied port 80 hit upstream: %d", httpReceived.Load())
	}

	rPlainOK, err := plainClient.Get("http://plain.example.com/")
	if err != nil {
		t.Fatalf("http opt-in check: %v", err)
	}
	plainBody, err := io.ReadAll(rPlainOK.Body)
	if err != nil {
		t.Fatalf("read plain body: %v", err)
	}
	if err := rPlainOK.Body.Close(); err != nil {
		t.Fatalf("close rPlainOK: %v", err)
	}
	if rPlainOK.StatusCode != http.StatusOK || string(plainBody) != "plain-ok" {
		t.Fatalf("plain opt-in got status=%d body=%q", rPlainOK.StatusCode, plainBody)
	}
}

func TestAuditPreservesEscapedHashAndQuestionMark(t *testing.T) {
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"esc.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: `
  - id: allow-esc
    principal: worker-test
    effect: allow
    hosts: [esc.example.com]
    ports: [443]
    paths: ["/**"]
`,
	})

	client := gw.H1Client(t, "esc.example.com")
	for _, rawTarget := range []string{
		"https://esc.example.com/v1/ok%23tail",
		"https://esc.example.com/v1/ok%3Ftail",
		"https://esc.example.com/v1/ok?x=1",
	} {
		resp, err := client.Get(rawTarget)
		if err != nil {
			t.Fatalf("GET %s: %v", rawTarget, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close %s: %v", rawTarget, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", rawTarget, resp.StatusCode)
		}
	}

	type wantRec struct {
		path     string
		hasQuery bool
	}
	wants := []wantRec{
		{path: "/v1/ok%23tail", hasQuery: false},
		{path: "/v1/ok%3Ftail", hasQuery: false},
		{path: "/v1/ok", hasQuery: true},
	}

	var got []wantRec
	for _, ev := range gw.AuditEvents(t) {
		if ev.Kind == "request" && ev.Host == "esc.example.com" {
			got = append(got, wantRec{path: ev.Path, hasQuery: ev.HasQuery})
		}
	}
	if len(got) != len(wants) {
		t.Fatalf("got %d request audit events (%+v), want %d", len(got), got, len(wants))
	}
	for i, w := range wants {
		if got[i] != w {
			t.Fatalf("event[%d] = %+v, want %+v", i, got[i], w)
		}
	}
}
