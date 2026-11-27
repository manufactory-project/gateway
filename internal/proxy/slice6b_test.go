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
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/ca"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/netguard"
	"github.com/manufactory-project/gateway/internal/policy"
	"github.com/manufactory-project/gateway/internal/proxy"
)

// TestSlice6BFailClosedPromises covers:
// 5. Redaction must fail closed 502 (audited) if any bound host's secret file cannot be resolved.
// 6. Content-Encoding on bound hosts checks every header value split on ',' and returns 502 unless all tokens are "identity".
// 8. Upstream 101 that is not Upgrade: websocket returns 502 instead of forwarding 101.
func TestSlice6BFailClosedPromises(t *testing.T) {
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

	goodSec := "good_" + randHex(t)
	goodSecFile := filepath.Join(dir, "good.sec")
	if err := os.WriteFile(goodSecFile, []byte(goodSec+"\n"), 0o600); err != nil {
		t.Fatalf("write good.sec: %v", err)
	}
	missingSecFile := filepath.Join(dir, "missing.sec") // intentionally absent

	upSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/unscrubbed":
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "would-leak-if-fail-open"); err != nil {
				return
			}
		case "/ce-comma-gzip":
			w.Header().Set("Content-Encoding", "identity, gzip")
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "compressed-body"); err != nil {
				return
			}
		case "/ce-multi-header":
			w.Header().Add("Content-Encoding", "identity")
			w.Header().Add("Content-Encoding", "br")
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "compressed-body"); err != nil {
				return
			}
		case "/ce-identity-ok":
			w.Header().Set("Content-Encoding", "identity, identity")
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "val="+goodSec); err != nil {
				return
			}
		case "/ws-fake-101":
			rc := http.NewResponseController(w)
			conn, _, err := rc.Hijack()
			if err != nil {
				return
			}
			defer func() {
				if cErr := conn.Close(); cErr != nil {
					return
				}
			}()
			// Upstream replies 101 Switching Protocols with Upgrade: h2c (NOT websocket).
			if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"); err != nil {
				return
			}
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	upSrv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{makeSignedServerCert(t, upCA, []string{"good.example.com", "broken.example.com", "ws101.example.com"})},
	}
	upSrv.StartTLS()
	t.Cleanup(upSrv.Close)

	ports := freePorts(t, "127.0.32.1", 3)
	httpsPort, httpPort, dnsPort := ports[0], ports[1], ports[2]
	httpsAddr := fmt.Sprintf("127.0.32.1:%d", httpsPort)

	cfgYAML := fmt.Sprintf(`
ca:
  cert_path: %s
  key_path: %s
audit:
  dir: %s
records:
  good.example.com: 127.0.0.1
  broken.example.com: 127.0.0.1
  ws101.example.com: 127.0.0.1
links:
  - name: sbx0
    principal: worker-b
    subnet: 127.0.32.0/28
    gateway_ip: 127.0.32.1
    https_port: %d
    http_port: %d
    dns_port: %d
rules:
  - id: allow-good
    principal: worker-b
    effect: allow
    hosts: [good.example.com]
    ports: [443]
    bindings:
      - name: good-b
        host: good.example.com
        header: Authorization
        scheme: bearer
        placeholder: mf_ph_good_b
        secret_file: %s
  - id: allow-broken
    principal: worker-b
    effect: allow
    hosts: [broken.example.com]
    ports: [443]
    bindings:
      - name: broken-b
        host: broken.example.com
        header: Authorization
        scheme: bearer
        placeholder: mf_ph_broken_b
        secret_file: %s
  - id: allow-ws101
    principal: worker-b
    effect: allow
    hosts: [ws101.example.com]
    ports: [443]
    allow_websocket: true
`, mitmCert, mitmKey, auditDir, httpsPort, httpPort, dnsPort, goodSecFile, missingSecFile)

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

	guardDialer := netguard.NewDialer(netguard.Options{Store: store})
	upPort := tcpPort(t, upSrv.Listener.Addr())
	srv, err := proxy.NewServer(proxy.Options{
		Link:      store.Current().Config.Links[0],
		Store:     store,
		Evaluator: policy.NewEvaluator(store),
		Audit:     aw,
		Leaves:    ca.NewLeafCache(mitmCA),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return guardDialer.DialHost(ctx, network, host, upPort)
		},
		UpstreamRoots: upRoots,
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

	// --- Item 5: Broken binding secret file on bound host fails closed 502 (even on GET with no auth header) ---
	rBroken, err := makeClient("broken.example.com").Get("https://broken.example.com/unscrubbed")
	if err != nil {
		t.Fatalf("GET broken host: %v", err)
	}
	brokenBody, err := io.ReadAll(rBroken.Body)
	if err != nil {
		t.Fatalf("read broken body: %v", err)
	}
	if err := rBroken.Body.Close(); err != nil {
		t.Fatalf("close broken body: %v", err)
	}
	if rBroken.StatusCode != http.StatusBadGateway {
		t.Fatalf("broken redaction secret status=%d, want 502", rBroken.StatusCode)
	}
	if strings.Contains(string(brokenBody), "would-leak-if-fail-open") {
		t.Fatalf("unscrubbed body leaked on redaction error: %q", brokenBody)
	}

	// --- Item 6: Multi-token and multi-header Content-Encoding checks on bound host ---
	cGood := makeClient("good.example.com")
	for _, p := range []string{"/ce-comma-gzip", "/ce-multi-header"} {
		r, err := cGood.Get("https://good.example.com" + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		if err := r.Body.Close(); err != nil {
			t.Fatalf("close %s: %v", p, err)
		}
		if r.StatusCode != http.StatusBadGateway {
			t.Fatalf("%s status=%d, want 502", p, r.StatusCode)
		}
	}
	// Positive control: identity, identity is allowed and scrubbed.
	rIdent, err := cGood.Get("https://good.example.com/ce-identity-ok")
	if err != nil {
		t.Fatalf("GET /ce-identity-ok: %v", err)
	}
	identBody, err := io.ReadAll(rIdent.Body)
	if err != nil {
		t.Fatalf("read /ce-identity-ok: %v", err)
	}
	if err := rIdent.Body.Close(); err != nil {
		t.Fatalf("close /ce-identity-ok: %v", err)
	}
	if rIdent.StatusCode != http.StatusOK || string(identBody) != "val=mf_ph_good_b" {
		t.Fatalf("/ce-identity-ok got status=%d body=%q", rIdent.StatusCode, identBody)
	}

	// --- Item 8: Upstream 101 that is NOT Upgrade: websocket returns 502 (never forwards 101) ---
	conn, err := tls.Dial("tcp", httpsAddr, &tls.Config{
		ServerName: "ws101.example.com",
		RootCAs:    mitmRoots,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("ws101 dial: %v", err)
	}
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

	// Confirm redaction error and non-WS 101 were both audited.
	events, _, err := audit.QueryWithCursor(auditDir, audit.QueryOptions{})
	if err != nil {
		t.Fatalf("audit.QueryWithCursor: %v", err)
	}
	var sawRedactErr, sawNonWS101 bool
	for _, ev := range events {
		if ev.Error == "redaction-secret-unresolved" && ev.Status == 502 {
			sawRedactErr = true
		}
		if ev.Error == "unexpected-101-non-websocket" && ev.Status == 502 {
			sawNonWS101 = true
		}
	}
	if !sawRedactErr || !sawNonWS101 {
		t.Fatalf("missing expected audit records: sawRedactErr=%v sawNonWS101=%v", sawRedactErr, sawNonWS101)
	}
}
