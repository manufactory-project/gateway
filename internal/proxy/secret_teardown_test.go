package proxy_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/ca"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/netguard"
	"github.com/manufactory-project/gateway/internal/policy"
	"github.com/manufactory-project/gateway/internal/proxy"
)

func TestProxySecretsIdentityRedactionAndLiveTeardown(t *testing.T) {
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")

	mitmCert := filepath.Join(dir, "mitm-ca.crt")
	mitmKey := filepath.Join(dir, "mitm-ca.key")
	mitmCA, err := ca.Init(mitmCert, mitmKey)
	if err != nil {
		t.Fatalf("ca.Init MITM: %v", err)
	}
	upCA, err := ca.Init(filepath.Join(dir, "up-ca.crt"), filepath.Join(dir, "up-ca.key"))
	if err != nil {
		t.Fatalf("ca.Init upstream: %v", err)
	}
	upstreamRoots := x509.NewCertPool()
	if !upstreamRoots.AppendCertsFromPEM(upCA.CertPEM) {
		t.Fatal("append upstream CA")
	}
	mitmRoots := x509.NewCertPool()
	if !mitmRoots.AppendCertsFromPEM(mitmCA.CertPEM) {
		t.Fatal("append MITM CA")
	}

	secForge := "s3cr3t_" + randHex(t) + "/&\"<>"
	secFile := filepath.Join(dir, "forge.secret")
	if err := os.WriteFile(secFile, []byte(secForge+"\n"), 0o600); err != nil {
		t.Fatalf("write forge secret: %v", err)
	}
	badSecFile := filepath.Join(dir, "bad.secret")
	if err := os.WriteFile(badSecFile, []byte("bad\nline2"), 0o600); err != nil {
		t.Fatalf("write bad secret: %v", err)
	}

	var (
		upReceived      atomic.Int32
		streamStarted   = make(chan struct{}, 16)
		wsStarted       = make(chan struct{}, 4)
		holdRelease     = make(chan struct{})
		seenHeadersMu   sync.Mutex
		lastSeenHeaders http.Header
	)

	upSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upReceived.Add(1)
		seenHeadersMu.Lock()
		lastSeenHeaders = r.Header.Clone()
		seenHeadersMu.Unlock()

		switch r.URL.Path {
		case "/echo":
			// Echo secret in response header, streaming chunked body (literal, URL-encoded, JSON-escaped), and trailer!
			jsonBytes, err := json.Marshal(secForge)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			jsonInner := strings.Trim(string(jsonBytes), `"`)
			w.Header().Set("X-Echo", "hdr="+secForge)
			w.Header().Set("Trailer", "X-Trailer-Secret")
			w.WriteHeader(http.StatusOK)
			rc := http.NewResponseController(w)
			body := "lit=" + secForge + "|url=" + url.QueryEscape(secForge) + "|json=" + jsonInner
			// Write split chunks to test sliding-window boundary scrubbing.
			for i := 0; i < len(body); i += 5 {
				end := i + 5
				if end > len(body) {
					end = len(body)
				}
				if _, err := io.WriteString(w, body[i:end]); err != nil {
					return
				}
				if err := rc.Flush(); err != nil {
					return
				}
			}
			w.Header().Set("X-Trailer-Secret", "tr="+secForge)

		case "/echo-cl":
			// Upstream sends explicit Content-Length for unredacted secret (longer than placeholder);
			// proxy MUST strip Content-Length before WriteHeader so rewritten shorter body succeeds.
			body := "secret=" + secForge
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, body); err != nil {
				return
			}

		case "/gzip-bound":
			// Upstream ignores Accept-Encoding: identity and returns gzip -> proxy MUST fail closed 502!
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			if _, err := io.WriteString(gz, "leaked:"+secForge); err != nil {
				return
			}
			if err := gz.Close(); err != nil {
				return
			}
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(buf.Bytes()); err != nil {
				return
			}

		case "/hold":
			// Long-lived streaming SSE/H2 response that stays open until test cleanup
			// (does NOT rely on polite upstream cooperation, proving proxy's conn.Close() tears it down!).
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
			rc := http.NewResponseController(w)
			conn, rw, err := rc.Hijack()
			if err != nil {
				return
			}
			defer func() {
				if err := conn.Close(); err != nil {
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
	}))
	upSrv.EnableHTTP2 = true
	upSrv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{makeSignedServerCert(t, upCA, []string{"code.lan.example", "badsec.lan.example", "unbound.example.com", "grant.example.com", "ws.example.com"})},
	}
	upSrv.StartTLS()
	t.Cleanup(upSrv.Close)
	t.Cleanup(func() { close(holdRelease) })

	ports := freePorts(t, "127.0.13.1", 3)
	httpsPort, httpPort, dnsPort := ports[0], ports[1], ports[2]

	baseYAML := fmt.Sprintf(`
ca:
  cert_path: %s
  key_path: %s
audit:
  dir: %s
records:
  code.lan.example: 127.0.0.1
  badsec.lan.example: 127.0.0.1
  unbound.example.com: 127.0.0.1
  grant.example.com: 127.0.0.1
  ws.example.com: 127.0.0.1
links:
  - name: sbx0
    principal: worker-claude
    subnet: 127.0.13.0/28
    gateway_ip: 127.0.13.1
    https_port: %d
    http_port: %d
    dns_port: %d
rules:
  - id: allow-forge
    principal: worker-claude
    effect: allow
    hosts: [code.lan.example]
    ports: [443, 80]
    bindings:
      - name: forge-basic
        host: code.lan.example
        header: Authorization
        scheme: basic
        placeholder: mf_ph_forge
        secret_file: %s
  - id: allow-badsec
    principal: worker-claude
    effect: allow
    hosts: [badsec.lan.example]
    ports: [443]
    bindings:
      - name: forge-bad
        host: badsec.lan.example
        header: X-Bad-Token
        scheme: raw
        placeholder: mf_ph_bad
        secret_file: %s
  - id: allow-unbound
    principal: worker-claude
    effect: allow
    hosts: [unbound.example.com]
    ports: [443]
  - id: allow-ws
    principal: worker-claude
    effect: allow
    hosts: [ws.example.com]
    ports: [443]
    allow_websocket: true
`, mitmCert, mitmKey, auditDir, httpsPort, httpPort, dnsPort, secFile, badSecFile)

	cfgPath := filepath.Join(dir, "gatewayd.yaml")
	if err := os.WriteFile(cfgPath, []byte(baseYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	store, err := config.NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	aw, err := audit.NewWriter(audit.Options{Dir: auditDir})
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}
	t.Cleanup(func() {
		if err := aw.Close(); err != nil {
			t.Errorf("audit close: %v", err)
		}
	})

	guardDialer := netguard.NewDialer(netguard.Options{Store: store})
	upPort := tcpPort(t, upSrv.Listener.Addr())
	dialUpstream := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		return guardDialer.DialHost(ctx, network, host, upPort)
	}

	flows := proxy.NewFlowRegistry()
	httpsAddr := fmt.Sprintf("127.0.13.1:%d", httpsPort)
	srv, err := proxy.NewServer(proxy.Options{
		Link:          store.Current().Config.Links[0],
		Store:         store,
		Evaluator:     policy.NewEvaluator(store),
		Audit:         aw,
		Leaves:        ca.NewLeafCache(mitmCA),
		DialContext:   dialUpstream,
		UpstreamRoots: upstreamRoots,
		Flows:         flows,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	pruneCtx, pruneCancel := context.WithCancel(context.Background())
	pruneDone := make(chan struct{})
	go func() {
		defer close(pruneDone)
		store.RunGrantPruner(pruneCtx, 20*time.Millisecond)
	}()
	t.Cleanup(func() {
		pruneCancel()
		<-pruneDone
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})

	makeClient := func(sni string, h2 bool) *http.Client {
		protos := new(http.Protocols)
		protos.SetHTTP1(true)
		protos.SetHTTP2(h2)
		tr := &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, httpsAddr)
			},
			TLSClientConfig: &tls.Config{
				ServerName: sni,
				RootCAs:    mitmRoots,
				MinVersion: tls.VersionTLS12,
			},
			ForceAttemptHTTP2:  h2,
			DisableCompression: true,
			Protocols:          protos,
		}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr}
	}

	// --- 1. Bound host substitution + post-sub stripping + identity response redaction ---
	cForge := makeClient("code.lan.example", false)
	req, err := http.NewRequest(http.MethodGet, "https://code.lan.example/echo", nil)
	if err != nil {
		t.Fatalf("NewRequest echo: %v", err)
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("git:mf_ph_forge")))
	req.Header.Set("X-Unbound-Ph", "mf_ph_other")
	req.Header.Set("Proxy-Authorization", "Bearer leak")
	req.Header.Set("Accept-Encoding", "gzip, br")

	resp, err := cForge.Do(req)
	if err != nil {
		t.Fatalf("Do /echo: %v", err)
	}
	echoBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /echo body: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close /echo body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/echo status = %d, want 200", resp.StatusCode)
	}
	// Verify upstream received substituted Basic Auth, Accept-Encoding: identity, and NO leaked placeholders.
	seenHeadersMu.Lock()
	hdrCopy := lastSeenHeaders.Clone()
	seenHeadersMu.Unlock()
	wantBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("git:"+secForge))
	if hdrCopy.Get("Authorization") != wantBasic {
		t.Fatalf("upstream Authorization = %q, want %q", hdrCopy.Get("Authorization"), wantBasic)
	}
	if hdrCopy.Get("Accept-Encoding") != "identity" {
		t.Fatalf("upstream Accept-Encoding = %q, want identity", hdrCopy.Get("Accept-Encoding"))
	}
	if hdrCopy.Get("X-Unbound-Ph") != "" || hdrCopy.Get("Proxy-Authorization") != "" {
		t.Fatalf("unbound placeholder / Proxy-Authorization leaked to bound host: %+v", hdrCopy)
	}
	// Verify response header, body (literal/URL/JSON), and trailer were scrubbed & Content-Length stripped.
	if resp.Header.Get("Content-Length") != "" {
		t.Fatalf("Content-Length must be stripped on bound host, got %q", resp.Header.Get("Content-Length"))
	}
	if resp.Header.Get("X-Echo") != "hdr=mf_ph_forge" {
		t.Fatalf("response header not scrubbed: %q", resp.Header.Get("X-Echo"))
	}
	if strings.Contains(string(echoBody), secForge) || string(echoBody) != "lit=mf_ph_forge|url=mf_ph_forge|json=mf_ph_forge" {
		t.Fatalf("response body not scrubbed cleanly: %q", echoBody)
	}
	if resp.Trailer.Get("X-Trailer-Secret") != "tr=mf_ph_forge" {
		t.Fatalf("response trailer not scrubbed: %q", resp.Trailer.Get("X-Trailer-Secret"))
	}

	// Verify Content-Length is stripped when upstream sends explicit Content-Length on a bound host.
	rCL, err := cForge.Get("https://code.lan.example/echo-cl")
	if err != nil {
		t.Fatalf("GET /echo-cl: %v", err)
	}
	clBody, err := io.ReadAll(rCL.Body)
	if err != nil {
		t.Fatalf("read /echo-cl: %v", err)
	}
	if err := rCL.Body.Close(); err != nil {
		t.Fatalf("close /echo-cl: %v", err)
	}
	if rCL.Header.Get("Content-Length") != "" {
		t.Fatalf("Content-Length not stripped on /echo-cl: %q", rCL.Header.Get("Content-Length"))
	}
	if string(clBody) != "secret=mf_ph_forge" {
		t.Fatalf("/echo-cl body = %q, want secret=mf_ph_forge", clBody)
	}

	// --- 2. Bound host returning compressed Content-Encoding -> fail closed 502 ---
	rGzipBound, err := cForge.Get("https://code.lan.example/gzip-bound")
	if err != nil {
		t.Fatalf("GET /gzip-bound: %v", err)
	}
	gzBoundBody, err := io.ReadAll(rGzipBound.Body)
	if err != nil {
		t.Fatalf("read /gzip-bound: %v", err)
	}
	if err := rGzipBound.Body.Close(); err != nil {
		t.Fatalf("close /gzip-bound: %v", err)
	}
	if rGzipBound.StatusCode != http.StatusBadGateway {
		t.Fatalf("/gzip-bound status = %d, want 502", rGzipBound.StatusCode)
	}
	if strings.Contains(string(gzBoundBody), secForge) {
		t.Fatal("secret leaked in 502 error body")
	}

	// --- 3. Corrupt/interior-newline secret fails closed 403 WITHOUT dialing upstream ---
	beforeBad := upReceived.Load()
	cBad := makeClient("badsec.lan.example", false)
	reqBad, err := http.NewRequest(http.MethodGet, "https://badsec.lan.example/echo", nil)
	if err != nil {
		t.Fatalf("NewRequest bad secret: %v", err)
	}
	reqBad.Header.Set("X-Bad-Token", "mf_ph_bad")
	rBad, err := cBad.Do(reqBad)
	if err != nil {
		t.Fatalf("Do bad secret: %v", err)
	}
	if err := rBad.Body.Close(); err != nil {
		t.Fatalf("close rBad: %v", err)
	}
	if rBad.StatusCode != http.StatusForbidden {
		t.Fatalf("bad secret status = %d, want 403", rBad.StatusCode)
	}
	if upReceived.Load() != beforeBad {
		t.Fatalf("unresolved secret request hit upstream: %d != %d", upReceived.Load(), beforeBad)
	}

	// --- 4. Unbound host strips mf_ph_* unconditionally ---
	cUnbound := makeClient("unbound.example.com", false)
	reqUnb, err := http.NewRequest(http.MethodGet, "https://unbound.example.com/ok", nil)
	if err != nil {
		t.Fatalf("NewRequest unbound: %v", err)
	}
	reqUnb.Header.Set("Authorization", "Bearer mf_ph_forge")
	rUnb, err := cUnbound.Do(reqUnb)
	if err != nil {
		t.Fatalf("Do unbound: %v", err)
	}
	if err := rUnb.Body.Close(); err != nil {
		t.Fatalf("close rUnb: %v", err)
	}
	seenHeadersMu.Lock()
	unbAuth := lastSeenHeaders.Get("Authorization")
	seenHeadersMu.Unlock()
	if unbAuth != "" {
		t.Fatalf("placeholder leaked to unbound host: %q", unbAuth)
	}

	// --- 5. Live open-flow teardown: H2 multiplexed grant TTL expiry + revoke + SIGHUP reload + WS ---
	// 5a. Ephemeral TTL grant tears down an open H2 SSE stream automatically when TTL expires!
	gTTL, err := store.AddGrant("worker-claude", "grant.example.com", 443, []string{"GET"}, []string{"/hold"}, 120*time.Millisecond)
	if err != nil {
		t.Fatalf("AddGrant TTL: %v", err)
	}
	cGrantH2 := makeClient("grant.example.com", true)
	rTTL, err := cGrantH2.Get("https://grant.example.com/hold")
	if err != nil {
		t.Fatalf("GET /hold under TTL grant: %v", err)
	}
	<-streamStarted
	if active := flows.List(); len(active) == 0 || active[0].GrantID != gTTL.ID {
		t.Fatalf("expected active flow with grant_id %s, got %+v", gTTL.ID, active)
	}
	// Read until EOF/error: must terminate promptly once the 120ms TTL expires!
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

	// 5b. Live revoke tears down an open WebSocket flow immediately.
	wsConn, err := tls.Dial("tcp", httpsAddr, &tls.Config{
		ServerName: "ws.example.com",
		RootCAs:    mitmRoots,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("WS tls.Dial: %v", err)
	}
	if _, err := io.WriteString(wsConn, "GET /ws-hold HTTP/1.1\r\nHost: ws.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"); err != nil {
		t.Fatalf("write WS: %v", err)
	}
	wsBR := bufio.NewReader(wsConn)
	wsResp, err := http.ReadResponse(wsBR, nil)
	if err != nil || wsResp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("WS upgrade failed: resp=%+v err=%v", wsResp, err)
	}
	<-wsStarted
	if n := flows.RevokeByPrincipal("worker-claude", "ws.example.com"); n != 1 {
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

	// 5c. Reload removing a rule tears down an active H1 keep-alive SSE stream AND closes the guest TCP socket.
	rawKeepAlive, err := tls.Dial("tcp", httpsAddr, &tls.Config{
		ServerName: "unbound.example.com",
		RootCAs:    mitmRoots,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("H1 keep-alive tls.Dial: %v", err)
	}
	if _, err := io.WriteString(rawKeepAlive, "GET /hold HTTP/1.1\r\nHost: unbound.example.com\r\nConnection: keep-alive\r\n\r\n"); err != nil {
		t.Fatalf("write H1 keep-alive GET /hold: %v", err)
	}
	kaBR := bufio.NewReader(rawKeepAlive)
	rHold, err := http.ReadResponse(kaBR, nil)
	if err != nil || rHold.StatusCode != http.StatusOK {
		t.Fatalf("H1 keep-alive /hold failed: resp=%+v err=%v", rHold, err)
	}
	<-streamStarted
	// Remove allow-unbound from YAML and call Reload().
	updatedYAML := strings.Replace(baseYAML, "  - id: allow-unbound\n    principal: worker-claude\n    effect: allow\n    hosts: [unbound.example.com]\n    ports: [443]\n", "", 1)
	if err := os.WriteFile(cfgPath, []byte(updatedYAML), 0o600); err != nil {
		t.Fatalf("write updated config: %v", err)
	}
	if _, _, err := store.Reload(); err != nil {
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
	// Verify the underlying guest TCP connection itself was closed (not merely cleanly EOF'd for keep-alive reuse).
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

	// Verify raw secret NEVER appeared in any audit log file.
	entries, err := os.ReadDir(auditDir)
	if err != nil {
		t.Fatalf("readdir auditDir: %v", err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(auditDir, e.Name()))
		if err != nil {
			t.Fatalf("read audit file: %v", err)
		}
		if strings.Contains(string(data), secForge) {
			t.Fatalf("raw secret leaked into audit log %s", e.Name())
		}
	}
}
