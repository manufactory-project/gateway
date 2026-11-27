package proxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/ca"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/metrics"
	"github.com/manufactory-project/gateway/internal/netguard"
	"github.com/manufactory-project/gateway/internal/policy"
	"github.com/manufactory-project/gateway/internal/proxy"
)

type closeTrackingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTrackingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// TestSlice6CRevocationMetricsAndTeardownRace covers:
// 12. gatewayd_revocations_total counts teardowns from reload AND grant TTL expiry.
// 13. teardown() racing before setUpstreamConn(c) closes c immediately on BOTH HTTP and WebSocket paths.
func TestSlice6CRevocationMetricsAndTeardownRace(t *testing.T) {
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")

	mitmCert := filepath.Join(dir, "mitm.crt")
	mitmKey := filepath.Join(dir, "mitm.key")
	mitmCA, err := ca.Init(mitmCert, mitmKey)
	if err != nil {
		t.Fatalf("ca.Init MITM: %v", err)
	}
	upCA, err := ca.Init(filepath.Join(dir, "up.crt"), filepath.Join(dir, "up.key"))
	if err != nil {
		t.Fatalf("ca.Init upstream: %v", err)
	}
	upRoots := x509.NewCertPool()
	if !upRoots.AppendCertsFromPEM(upCA.CertPEM) {
		t.Fatal("append upstream CA")
	}
	mitmRoots := x509.NewCertPool()
	if !mitmRoots.AppendCertsFromPEM(mitmCA.CertPEM) {
		t.Fatal("append MITM CA")
	}

	holdRelease := make(chan struct{})
	streamStarted := make(chan struct{}, 8)
	var wsUpWrites atomic.Int32

	upSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		case "/ws-race":
			wsUpWrites.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	upSrv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{makeSignedServerCert(t, upCA, []string{"reload.example.com", "ttl.example.com", "race-http.example.com", "race-ws.example.com"})},
	}
	upSrv.StartTLS()
	// Register upSrv.Close BEFORE close(holdRelease) so LIFO cleanup releases /hold first!
	t.Cleanup(upSrv.Close)
	t.Cleanup(func() { close(holdRelease) })

	ports := freePorts(t, "127.0.33.1", 3)
	httpsPort, httpPort, dnsPort := ports[0], ports[1], ports[2]
	httpsAddr := fmt.Sprintf("127.0.33.1:%d", httpsPort)

	baseYAML := fmt.Sprintf(`
ca:
  cert_path: %s
  key_path: %s
audit:
  dir: %s
records:
  reload.example.com: 127.0.0.1
  ttl.example.com: 127.0.0.1
  race-http.example.com: 127.0.0.1
  race-ws.example.com: 127.0.0.1
links:
  - name: sbx0
    principal: worker-c
    subnet: 127.0.33.0/28
    gateway_ip: 127.0.33.1
    https_port: %d
    http_port: %d
    dns_port: %d
rules:
  - id: allow-reload
    principal: worker-c
    effect: allow
    hosts: [reload.example.com]
    ports: [443]
  - id: allow-race-http
    principal: worker-c
    effect: allow
    hosts: [race-http.example.com]
    ports: [443]
  - id: allow-race-ws
    principal: worker-c
    effect: allow
    hosts: [race-ws.example.com]
    ports: [443]
    allow_websocket: true
`, mitmCert, mitmKey, auditDir, httpsPort, httpPort, dnsPort)

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

	flows := proxy.NewFlowRegistry()
	col := metrics.NewCollector(metrics.Options{ActiveFlows: flows.Count})
	flows.SetOnRevoke(col.AddRevocations)

	guardDialer := netguard.NewDialer(netguard.Options{Store: store})
	upPort := tcpPort(t, upSrv.Listener.Addr())

	var (
		raceHTTPConn atomic.Pointer[closeTrackingConn]
		raceWSConn   atomic.Pointer[closeTrackingConn]
	)

	srv, err := proxy.NewServer(proxy.Options{
		Link:               store.Current().Config.Links[0],
		Store:              store,
		Evaluator:          policy.NewEvaluator(store),
		Audit:              aw,
		Leaves:             ca.NewLeafCache(mitmCA),
		Flows:              flows,
		UpstreamRoots:      upRoots,
		GrantPruneInterval: 20 * time.Millisecond,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			conn, err := guardDialer.DialHost(ctx, network, host, upPort)
			if err != nil {
				return nil, err
			}
			switch host {
			case "race-http.example.com":
				// Trigger teardown BEFORE DialContext returns (so BEFORE GotConn -> setUpstreamConn!).
				tc := &closeTrackingConn{Conn: conn}
				raceHTTPConn.Store(tc)
				flows.RevokeByPrincipal("worker-c", "race-http.example.com")
				return tc, nil
			case "race-ws.example.com":
				// Trigger teardown BEFORE DialContext returns (so BEFORE serveWebSocket -> setUpstreamConn!).
				tc := &closeTrackingConn{Conn: conn}
				raceWSConn.Store(tc)
				flows.RevokeByPrincipal("worker-c", "race-ws.example.com")
				return tc, nil
			}
			return conn, nil
		},
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

	makeClient := func(sni string) *http.Client {
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
			DisableCompression: true,
		}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr}
	}

	scrapeRevocations := func() string {
		rec := httptest.NewRecorder()
		col.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rec.Body.String()
	}

	// --- Item 12a: TTL expiry teardown increments gatewayd_revocations_total ---
	if _, err := store.AddGrant("worker-c", "ttl.example.com", 443, []string{"GET"}, []string{"/hold"}, 100*time.Millisecond); err != nil {
		t.Fatalf("AddGrant TTL: %v", err)
	}
	rTTL, err := makeClient("ttl.example.com").Get("https://ttl.example.com/hold")
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

	// --- Item 12b: Reload teardown increments gatewayd_revocations_total ---
	rRel, err := makeClient("reload.example.com").Get("https://reload.example.com/hold")
	if err != nil {
		t.Fatalf("GET reload /hold: %v", err)
	}
	<-streamStarted
	updated := strings.Replace(baseYAML, "  - id: allow-reload\n    principal: worker-c\n    effect: allow\n    hosts: [reload.example.com]\n    ports: [443]\n", "", 1)
	if err := os.WriteFile(cfgPath, []byte(updated), 0o600); err != nil {
		t.Fatalf("write updated config: %v", err)
	}
	if _, _, err := store.Reload(); err != nil {
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

	// --- Item 13a: HTTP path teardown racing before setUpstreamConn closes upstream socket immediately ---
	if r, err := makeClient("race-http.example.com").Get("https://race-http.example.com/ok"); err == nil {
		if cErr := r.Body.Close(); cErr != nil {
			t.Logf("close race-http body: %v", cErr)
		}
	}
	tcHTTP := raceHTTPConn.Load()
	if tcHTTP == nil {
		t.Fatal("race-http dial never ran")
	}
	deadline := time.Now().Add(time.Second)
	for !tcHTTP.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !tcHTTP.closed.Load() {
		t.Fatal("HTTP upstream socket leaked open when teardown raced before setUpstreamConn")
	}

	// --- Item 13b: WebSocket path teardown racing before setUpstreamConn closes upstream socket & never writes ---
	wsConn, err := tls.Dial("tcp", httpsAddr, &tls.Config{
		ServerName: "race-ws.example.com",
		RootCAs:    mitmRoots,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("race-ws tls.Dial: %v", err)
	}
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
	deadline = time.Now().Add(time.Second)
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
