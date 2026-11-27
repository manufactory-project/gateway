package proxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// TestSlice6ARequestGuards covers:
// 1. Non-canonical paths (/./, //, /a/., /v1/./admin, /v1//admin) rejected 403 and /a/ allowed on H1 and H2.
// 2. WebSocket upgrade carrying a body (Content-Length or chunked) rejected 400 without dialing upstream.
// 3. HTTP/2 auth headers with leading OWS ("  Basic <b64>") properly substituted and swept.
func TestSlice6ARequestGuards(t *testing.T) {
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

	secVal := "h2ows_" + randHex(t)
	secFile := filepath.Join(dir, "sec.txt")
	if err := os.WriteFile(secFile, []byte(secVal+"\n"), 0o600); err != nil {
		t.Fatalf("write secFile: %v", err)
	}

	var (
		upReceived atomic.Int32
		hdrMu      sync.Mutex
		lastHdr    http.Header
	)
	upSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upReceived.Add(1)
		hdrMu.Lock()
		lastHdr = r.Header.Clone()
		hdrMu.Unlock()
		if r.URL.Path == "/ws" {
			rc := http.NewResponseController(w)
			conn, rw, err := rc.Hijack()
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
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, "ok:"+r.URL.Path); err != nil {
			return
		}
	}))
	upSrv.EnableHTTP2 = true
	upSrv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{makeSignedServerCert(t, upCA, []string{"canon.example.com", "ws.example.com", "bound.example.com"})},
	}
	upSrv.StartTLS()
	t.Cleanup(upSrv.Close)

	ports := freePorts(t, "127.0.31.1", 3)
	httpsPort, httpPort, dnsPort := ports[0], ports[1], ports[2]

	cfgYAML := fmt.Sprintf(`
ca:
  cert_path: %s
  key_path: %s
audit:
  dir: %s
records:
  canon.example.com: 127.0.0.1
  ws.example.com: 127.0.0.1
  bound.example.com: 127.0.0.1
links:
  - name: sbx0
    principal: worker-a
    subnet: 127.0.31.0/28
    gateway_ip: 127.0.31.1
    https_port: %d
    http_port: %d
    dns_port: %d
rules:
  - id: allow-canon
    principal: worker-a
    effect: allow
    hosts: [canon.example.com]
    ports: [443]
    paths: ["/**"]
  - id: deny-admin
    principal: worker-a
    effect: deny
    hosts: [canon.example.com]
    ports: [443]
    paths: ["/v1/admin"]
  - id: allow-ws
    principal: worker-a
    effect: allow
    hosts: [ws.example.com]
    ports: [443]
    allow_websocket: true
  - id: allow-bound
    principal: worker-a
    effect: allow
    hosts: [bound.example.com]
    ports: [443]
    bindings:
      - name: b-basic
        host: bound.example.com
        header: Authorization
        scheme: basic
        placeholder: mf_ph_ows
        secret_file: %s
`, mitmCert, mitmKey, auditDir, httpsPort, httpPort, dnsPort, secFile)

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

	makeClient := func(sni string, h2 bool) *http.Client {
		protos := new(http.Protocols)
		protos.SetHTTP1(!h2)
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
		return &http.Client{Transport: tr}
	}

	// --- Item 1: Non-canonical paths on BOTH H1 and H2 ---
	badPaths := []string{"/./", "//", "/a/.", "/v1/./admin", "/v1//admin", "/a//"}
	for _, h2 := range []bool{false, true} {
		protoLabel := "H1"
		if h2 {
			protoLabel = "H2"
		}
		c := makeClient("canon.example.com", h2)

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

		// Positive control: single trailing slash "/a/" MUST be allowed on both H1 and H2.
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

	// --- Item 2: WebSocket upgrade with body (Content-Length and chunked) rejected 400 ---
	beforeWS := upReceived.Load()
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
		conn, err := tls.Dial("tcp", srv.HTTPSAddr(), &tls.Config{
			ServerName: "ws.example.com",
			RootCAs:    mitmRoots,
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			t.Fatalf("%s tls.Dial: %v", tc.name, err)
		}
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
	if upReceived.Load() != beforeWS {
		t.Fatalf("WS upgrade with body hit upstream: %d != %d", upReceived.Load(), beforeWS)
	}

	// Positive control: bodyless WS upgrade succeeds (101).
	wsConn, err := tls.Dial("tcp", srv.HTTPSAddr(), &tls.Config{
		ServerName: "ws.example.com",
		RootCAs:    mitmRoots,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("ws positive dial: %v", err)
	}
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

	// --- Item 3: HTTP/2 auth headers with leading OWS ("  Basic <b64>") substituted AND swept ---
	cBoundH2 := makeClient("bound.example.com", true)
	reqH2, err := http.NewRequest(http.MethodGet, "https://bound.example.com/ok", nil)
	if err != nil {
		t.Fatalf("NewRequest H2 OWS: %v", err)
	}
	reqH2.Header.Set("Authorization", "  Basic "+base64.StdEncoding.EncodeToString([]byte("git:mf_ph_ows"))+" ")
	reqH2.Header.Set("X-Leak-Basic", "\tBasic "+base64.StdEncoding.EncodeToString([]byte("u:mf_ph_other")))

	respH2, err := cBoundH2.Do(reqH2)
	if err != nil {
		t.Fatalf("Do H2 OWS: %v", err)
	}
	if err := respH2.Body.Close(); err != nil {
		t.Fatalf("close H2 OWS body: %v", err)
	}
	if respH2.ProtoMajor != 2 || respH2.StatusCode != http.StatusOK {
		t.Fatalf("H2 OWS resp: proto=%s status=%d", respH2.Proto, respH2.StatusCode)
	}
	hdrMu.Lock()
	gotAuth := lastHdr.Get("Authorization")
	gotLeak := lastHdr.Get("X-Leak-Basic")
	hdrMu.Unlock()
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("git:"+secVal))
	if gotAuth != wantAuth {
		t.Fatalf("H2 leading-OWS Basic auth not substituted: got %q, want %q", gotAuth, wantAuth)
	}
	if gotLeak != "" {
		t.Fatalf("H2 leading-OWS Basic placeholder not swept: got %q", gotLeak)
	}
}
