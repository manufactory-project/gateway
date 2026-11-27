package proxy_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/ca"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/netguard"
	"github.com/manufactory-project/gateway/internal/policy"
	"github.com/manufactory-project/gateway/internal/proxy"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func tcpPort(t *testing.T, addr net.Addr) uint16 {
	t.Helper()
	ta, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected addr type %T", addr)
	}
	return uint16(ta.Port)
}

func freePort(t *testing.T, ip string) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp4", ip+":0")
	if err != nil {
		t.Fatalf("freePort %s: %v", ip, err)
	}
	port := tcpPort(t, ln.Addr())
	if err := ln.Close(); err != nil {
		t.Fatalf("close freePort: %v", err)
	}
	return port
}

func randHex(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return hex.EncodeToString(b[:])
}

func makeSignedServerCert(t *testing.T, root ca.CA, dnsNames []string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate upstream leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.Certificate, &key.PublicKey, root.Key)
	if err != nil {
		t.Fatalf("sign upstream leaf: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestProxyMITMHardeningH2SSEWSAndFalsePositives(t *testing.T) {
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")

	// 1. Initialize MITM CA and a separate Upstream CA (trusted by proxy) + Untrusted CA.
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
	badCA, err := ca.Init(filepath.Join(dir, "bad-ca.crt"), filepath.Join(dir, "bad-ca.key"))
	if err != nil {
		t.Fatalf("ca.Init bad: %v", err)
	}

	upstreamRoots := x509.NewCertPool()
	if !upstreamRoots.AppendCertsFromPEM(upCA.CertPEM) {
		t.Fatal("append upstream CA")
	}
	mitmRoots := x509.NewCertPool()
	if !mitmRoots.AppendCertsFromPEM(mitmCA.CertPEM) {
		t.Fatal("append MITM CA")
	}

	// 2. Start real local upstream servers with atomic request counters.
	var (
		httpsReceived     atomic.Int32
		httpReceived      atomic.Int32
		untrustedReceived atomic.Int32
		sseGate           = make(chan struct{})
		subToken          = "sub_oauth_" + randHex(t)
		seenSubAuth       atomic.Value
		seenUpH2          atomic.Bool
	)

	trustedSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpsReceived.Add(1)
		if r.ProtoMajor == 2 {
			seenUpH2.Store(true)
		}
		if auth := r.Header.Get("Authorization"); auth != "" {
			seenSubAuth.Store(auth)
		}
		switch r.URL.Path {
		case "/v1/ok":
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
		case "/v1/redirect":
			w.Header().Set("Location", "https://evil.example/steal")
			w.WriteHeader(http.StatusFound)
		case "/v1/grpc":
			w.Header().Set("Trailer", "Grpc-Status")
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "grpc-payload"); err != nil {
				return
			}
			w.Header().Set("Grpc-Status", "0")
		case "/v1/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			rc := http.NewResponseController(w)
			if _, err := io.WriteString(w, "data: chunk1\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			<-sseGate
			if _, err := io.WriteString(w, "data: chunk2\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
		case "/v1/gzip":
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			if _, err := io.WriteString(gz, "compressed-hello"); err != nil {
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
		case "/ws":
			if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				http.Error(w, "need ws", http.StatusBadRequest)
				return
			}
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
			// Echo raw bytes back until EOF.
			if _, err := io.Copy(conn, rw); err != nil {
				return
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	trustedSrv.EnableHTTP2 = true
	trustedSrv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{makeSignedServerCert(t, upCA, []string{"api.example.com", "ws.example.com"})},
	}
	trustedSrv.StartTLS()
	t.Cleanup(trustedSrv.Close)

	untrustedSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		untrustedReceived.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	untrustedSrv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{makeSignedServerCert(t, badCA, []string{"untrusted.example.com"})},
	}
	untrustedSrv.StartTLS()
	t.Cleanup(untrustedSrv.Close)

	plainSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpReceived.Add(1)
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, "plain-ok"); err != nil {
			return
		}
	}))
	t.Cleanup(plainSrv.Close)

	// 3. Configure and start proxy.Server on explicit 127.0.12.1 ports.
	httpsPort := freePort(t, "127.0.12.1")
	httpPort := freePort(t, "127.0.12.1")
	dnsPort := freePort(t, "127.0.12.1")

	cfgYAML := fmt.Sprintf(`
ca:
  cert_path: %s
  key_path: %s
audit:
  dir: %s
http:
  max_request_body_bytes: 128
  ws_max_egress_bytes: 64
  max_header_bytes: 32768
  denied_sni_rate_per_sec: 100
  denied_sni_burst: 100
records:
  api.example.com: 127.0.0.1
  ws.example.com: 127.0.0.1
  untrusted.example.com: 127.0.0.1
  plain.example.com: 127.0.0.1
links:
  - name: sbx0
    principal: worker-claude
    subnet: 127.0.12.0/28
    gateway_ip: 127.0.12.1
    https_port: %d
    http_port: %d
    dns_port: %d
rules:
  - id: allow-api
    principal: worker-claude
    effect: allow
    hosts: [api.example.com]
    ports: [443]
    methods: [GET, POST]
    paths: ["/v1/**"]
  - id: allow-ws
    principal: worker-claude
    effect: allow
    hosts: [ws.example.com]
    ports: [443]
    methods: [GET]
    paths: ["/ws"]
    allow_websocket: true
    ws_max_egress_bytes: 64
  - id: allow-untrusted
    principal: worker-claude
    effect: allow
    hosts: [untrusted.example.com]
    ports: [443]
  - id: allow-plain
    principal: worker-claude
    effect: allow
    hosts: [plain.example.com]
    ports: [80]
`, mitmCert, mitmKey, auditDir, httpsPort, httpPort, dnsPort)

	cfgPath := filepath.Join(dir, "gatewayd.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
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

	leaves := ca.NewLeafCache(mitmCA)
	guardDialer := netguard.NewDialer(netguard.Options{Store: store})

	trustedPort := tcpPort(t, trustedSrv.Listener.Addr())
	untrustedPort := tcpPort(t, untrustedSrv.Listener.Addr())
	plainPort := tcpPort(t, plainSrv.Listener.Addr())

	dialUpstream := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		switch {
		case host == "untrusted.example.com":
			return guardDialer.DialHost(ctx, network, host, untrustedPort)
		case portStr == "80":
			return guardDialer.DialHost(ctx, network, host, plainPort)
		default:
			return guardDialer.DialHost(ctx, network, host, trustedPort)
		}
	}

	srv, err := proxy.NewServer(proxy.Options{
		Link:          store.Current().Config.Links[0],
		Store:         store,
		Evaluator:     policy.NewEvaluator(store),
		Audit:         aw,
		Leaves:        leaves,
		DialContext:   dialUpstream,
		UpstreamRoots: upstreamRoots,
	})
	if err != nil {
		t.Fatalf("proxy.NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("proxy.Shutdown: %v", err)
		}
	})

	makeClient := func(sni string, h2 bool) *http.Client {
		protos := new(http.Protocols)
		protos.SetHTTP1(true)
		protos.SetHTTP2(h2)
		tr := &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, srv.HTTPSAddr())
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
		return &http.Client{
			Transport: tr,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	// --- Containment 1: Denied SNI fails TLS handshake and is NEVER cached in LeafCache ---
	if _, err := makeClient("blocked.example.com", false).Get("https://blocked.example.com/"); err == nil {
		t.Fatal("expected TLS handshake failure for denied SNI")
	}
	if leaves.Cached("blocked.example.com") {
		t.Fatal("denied SNI must never be cached in LeafCache")
	}

	// --- Containment 2: SSH over port 443 fails TLS handshake (zero raw-TCP fallback) ---
	sshConn, err := net.DialTimeout("tcp", srv.HTTPSAddr(), time.Second)
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

	// --- Containment 3: Untrusted upstream TLS cert refused (502, never InsecureSkipVerify) ---
	respUntrusted, err := makeClient("untrusted.example.com", false).Get("https://untrusted.example.com/")
	if err != nil {
		t.Fatalf("request to untrusted.example.com: %v", err)
	}
	if err := respUntrusted.Body.Close(); err != nil {
		t.Fatalf("close untrusted body: %v", err)
	}
	if respUntrusted.StatusCode != http.StatusBadGateway {
		t.Fatalf("untrusted upstream status = %d, want 502", respUntrusted.StatusCode)
	}
	if untrustedReceived.Load() != 0 {
		t.Fatalf("untrusted upstream received %d requests, want 0", untrustedReceived.Load())
	}

	// --- Containment 4: Method/path 403, SNI!=Host, Host port mismatch, CONNECT, Upgrade: h2c, non-origin targets ---
	beforeBlocked := httpsReceived.Load()

	// 4a. Disallowed method, disallowed path, SNI!=Host (against a path ws.example.com allows!), host port mismatch, upgrades
	cAPI := makeClient("api.example.com", false)
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

	// 4b. Raw HTTP/1.1 wire tests for CONNECT, asterisk '*', absolute-URI, and path traversal '..'
	for _, tc := range []struct {
		rawReq     string
		wantReason string
	}{
		{"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "connect-forbidden"},
		{"OPTIONS * HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "asterisk-target-forbidden"},
		{"GET https://api.example.com/v1/ok HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "absolute-uri-forbidden"},
		{"GET /v1/../secret HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "path-traversal"},
	} {
		tcConn, err := tls.Dial("tcp", srv.HTTPSAddr(), &tls.Config{
			ServerName: "api.example.com",
			RootCAs:    mitmRoots,
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			t.Fatalf("raw tls.Dial: %v", err)
		}
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

	if httpsReceived.Load() != beforeBlocked {
		t.Fatalf("blocked requests reached upstream: received=%d, want %d", httpsReceived.Load(), beforeBlocked)
	}

	// --- Containment 5: 3xx redirect is NOT followed ---
	r302, err := cAPI.Get("https://api.example.com/v1/redirect")
	if err != nil {
		t.Fatalf("GET redirect: %v", err)
	}
	if err := r302.Body.Close(); err != nil {
		t.Fatalf("close r302: %v", err)
	}
	if r302.StatusCode != http.StatusFound || r302.Header.Get("Location") != "https://evil.example/steal" {
		t.Fatalf("expected raw 302 passthrough, got status=%d loc=%q", r302.StatusCode, r302.Header.Get("Location"))
	}

	// --- Containment 6: Streaming chunked max_request_body_bytes -> 413; under-cap chunked POST -> 200 ---
	pr, pw := io.Pipe()
	go func() {
		if _, err := pw.Write(bytes.Repeat([]byte("A"), 200)); err != nil {
			// Expected when server stops reading at 128 bytes.
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

	// Positive control: chunked POST under cap (64 bytes <= 128) succeeds with 200.
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

	// --- Positive control 7: HTTP/2 + gRPC trailer forwarding ---
	cH2 := makeClient("api.example.com", true)
	rH2, err := cH2.Get("https://api.example.com/v1/grpc")
	if err != nil {
		t.Fatalf("H2 gRPC request: %v", err)
	}
	h2Body, err := io.ReadAll(rH2.Body)
	if err != nil {
		t.Fatalf("read H2 body: %v", err)
	}
	if err := rH2.Body.Close(); err != nil {
		t.Fatalf("close H2 body: %v", err)
	}
	if rH2.ProtoMajor != 2 || !seenUpH2.Load() {
		t.Fatalf("expected HTTP/2 end-to-end (client=%s upstreamH2=%v)", rH2.Proto, seenUpH2.Load())
	}
	if string(h2Body) != "grpc-payload" || rH2.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("H2 trailer mismatch: body=%q trailer=%v", h2Body, rH2.Trailer)
	}

	// --- Positive control 8: SSE per-chunk flushing before upstream EOF ---
	rSSE, err := cAPI.Get("https://api.example.com/v1/sse")
	if err != nil {
		t.Fatalf("GET SSE: %v", err)
	}
	sseReader := bufio.NewReader(rSSE.Body)
	line1, err := sseReader.ReadString('\n')
	if err != nil {
		t.Fatalf("read SSE chunk1 before EOF: %v", err)
	}
	if line1 != "data: chunk1\n" {
		t.Fatalf("SSE chunk1 = %q", line1)
	}
	close(sseGate)
	restSSE, err := io.ReadAll(sseReader)
	if err != nil {
		t.Fatalf("read rest SSE: %v", err)
	}
	if err := rSSE.Body.Close(); err != nil {
		t.Fatalf("close SSE: %v", err)
	}
	if !strings.Contains(string(restSSE), "data: chunk2") {
		t.Fatalf("SSE missing chunk2: %q", restSSE)
	}

	// --- Positive control 9: Gzip response on unbound host passed through untouched ---
	rGz, err := cAPI.Get("https://api.example.com/v1/gzip")
	if err != nil {
		t.Fatalf("GET gzip: %v", err)
	}
	gzBytes, err := io.ReadAll(rGz.Body)
	if err != nil {
		t.Fatalf("read gzip: %v", err)
	}
	if err := rGz.Body.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	if rGz.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected Content-Encoding: gzip preserved on unbound host, got %q", rGz.Header.Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(bytes.NewReader(gzBytes))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	plainGz, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read ungzipped: %v", err)
	}
	if err := zr.Close(); err != nil {
		t.Fatalf("close gzip reader: %v", err)
	}
	if string(plainGz) != "compressed-hello" {
		t.Fatalf("ungzipped body = %q", plainGz)
	}

	// --- Positive control & containment 10: Opted-in WebSocket + 64B egress byte cap ---
	wsConn, err := tls.Dial("tcp", srv.HTTPSAddr(), &tls.Config{
		ServerName: "ws.example.com",
		RootCAs:    mitmRoots,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("WS tls.Dial: %v", err)
	}
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
	// Small payload (10 bytes <= 64B cap) echoed cleanly.
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
	// Exceed 64B egress cap -> proxy tears down connection immediately.
	if _, writeErr := wsConn.Write(bytes.Repeat([]byte("X"), 128)); writeErr != nil {
		t.Logf("wsConn write stopped as expected during teardown: %v", writeErr)
	}
	if err := wsConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set WS read deadline: %v", err)
	}
	// Drain remaining echoed bytes up to cap, then must hit EOF/closed.
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

	// --- Positive control & containment 11: Cleartext port 80 opt-in vs denied ---
	plainClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, srv.HTTPAddr())
			},
		},
	}
	t.Cleanup(plainClient.CloseIdleConnections)

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

	// --- Audit check: zero subscription auth token leakage in JSONL audit files ---
	entries, err := os.ReadDir(auditDir)
	if err != nil {
		t.Fatalf("readdir auditDir: %v", err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(auditDir, e.Name()))
		if err != nil {
			t.Fatalf("read audit file: %v", err)
		}
		if strings.Contains(string(data), subToken) {
			t.Fatalf("subscription auth token leaked into audit log %s", e.Name())
		}
	}
}
