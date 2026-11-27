package admin_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/manufactory-project/gateway/internal/admin"
	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/ca"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/metrics"
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

func freePorts(t *testing.T, ip string, n int) []uint16 {
	t.Helper()
	lns := make([]net.Listener, 0, n)
	ports := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp4", ip+":0")
		if err != nil {
			for _, prev := range lns {
				if cErr := prev.Close(); cErr != nil {
					t.Errorf("close prev listener: %v", cErr)
				}
			}
			t.Fatalf("freePorts %s[%d]: %v", ip, i, err)
		}
		lns = append(lns, ln)
		ports = append(ports, tcpPort(t, ln.Addr()))
	}
	for _, ln := range lns {
		if err := ln.Close(); err != nil {
			t.Fatalf("close freePorts: %v", err)
		}
	}
	return ports
}

func signLeaf(t *testing.T, root ca.CA, names []string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.Certificate, &key.PublicKey, root.Key)
	if err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestAdminSocketPermissionsAndRoutes(t *testing.T) {
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	sockPath := filepath.Join(dir, "admin.sock")
	cfgPath := filepath.Join(dir, "gatewayd.yaml")

	cfgYAML := fmt.Sprintf(`
ca:
  cert_path: /tmp/ca.crt
  key_path: /tmp/ca.key
audit:
  dir: %s
links:
  - name: sbx0
    principal: worker-claude
    subnet: 127.0.21.0/28
    gateway_ip: 127.0.21.1
rules:
  - id: r1
    principal: worker-claude
    effect: allow
    hosts: [api.anthropic.com]
    ports: [443]
`, auditDir)
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

	flows := proxy.NewFlowRegistry()
	col := metrics.NewCollector(metrics.Options{
		ActiveFlows:  flows.Count,
		ActiveGrants: func() int { return len(store.ActiveGrants()) },
	})
	flows.SetOnRevoke(col.AddRevocations)
	srv, err := admin.NewServer(admin.Options{
		SocketPath: sockPath,
		Store:      store,
		Flows:      flows,
		Audit:      aw,
		Metrics:    col,
	})
	if err != nil {
		t.Fatalf("admin.NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("admin.Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("admin.Shutdown: %v", err)
		}
	})

	// Verify Unix socket file mode is 0660.
	fi, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %o, want 0660", fi.Mode().Perm())
	}

	client := admin.NewClient(sockPath)
	t.Cleanup(client.Close)
	ctx := context.Background()

	// Status
	st, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.AuditHealthy || st.ConfigHash == "" || st.ActiveGrants != 0 {
		t.Fatalf("unexpected status: %+v", st)
	}

	// Create grant -> list -> delete
	g, err := client.CreateGrant(ctx, admin.GrantRequest{
		Principal: "worker-claude",
		Host:      "login.anthropic.com",
		Port:      443,
		TTL:       "5m",
	})
	if err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	grants, err := client.Grants(ctx)
	if err != nil || len(grants) != 1 || grants[0].ID != g.ID {
		t.Fatalf("Grants = (%+v, %v)", grants, err)
	}
	delRes, err := client.DeleteGrant(ctx, g.ID)
	if err != nil || !delRes.RevokedGrant {
		t.Fatalf("DeleteGrant = (%+v, %v)", delRes, err)
	}

	// Create second grant, then Reload must wipe it.
	g2, err := client.CreateGrant(ctx, admin.GrantRequest{
		Principal: "worker-claude",
		Host:      "auth.anthropic.com",
		Port:      443,
		TTL:       "5m",
	})
	if err != nil {
		t.Fatalf("CreateGrant g2: %v", err)
	}
	relRes, err := client.Reload(ctx)
	if err != nil || len(relRes.WipedGrants) != 1 || relRes.WipedGrants[0] != g2.ID {
		t.Fatalf("Reload = (%+v, %v)", relRes, err)
	}
}

// TestStressReloadRevokeH1H2SSEAndSlowlorisBounds is the NOW.md:105 concurrency & leak gate:
// hammers SIGHUP + Admin Reload + Admin Revoke + Grant Delete while H1 keep-alive,
// H2 multiplexed, and SSE streams are mid-flight, plus header-flood/slowloris bounds.
func TestStressReloadRevokeH1H2SSEAndSlowlorisBounds(t *testing.T) {
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	sockPath := filepath.Join(dir, "admin.sock")

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

	stopUpstream := make(chan struct{})
	t.Cleanup(func() { close(stopUpstream) })

	upSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fast":
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "ok"); err != nil {
				return
			}
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			rc := http.NewResponseController(w)
			for i := 0; i < 4; i++ {
				if _, err := io.WriteString(w, "data: tick\n\n"); err != nil {
					return
				}
				if err := rc.Flush(); err != nil {
					return
				}
				select {
				case <-r.Context().Done():
					return
				case <-stopUpstream:
					return
				case <-time.After(15 * time.Millisecond):
				}
			}
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	upSrv.EnableHTTP2 = true
	upSrv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{signLeaf(t, upCA, []string{"stress.example.com", "ephemeral.example.com"})},
	}
	upSrv.StartTLS()
	t.Cleanup(upSrv.Close)

	linkPorts := freePorts(t, "127.0.22.1", 3)
	httpsPort, httpPort, dnsPort := linkPorts[0], linkPorts[1], linkPorts[2]
	metricsPort := freePorts(t, "127.0.0.1", 1)[0]
	httpsAddr := fmt.Sprintf("127.0.22.1:%d", httpsPort)
	metricsAddr := fmt.Sprintf("127.0.0.1:%d", metricsPort)

	cfgYAML := fmt.Sprintf(`
ca:
  cert_path: %s
  key_path: %s
audit:
  dir: %s
admin:
  socket: %s
metrics:
  listen: 127.0.0.1:%d
http:
  max_header_bytes: 2048
records:
  stress.example.com: 127.0.0.1
  ephemeral.example.com: 127.0.0.1
links:
  - name: sbx0
    principal: worker-stress
    subnet: 127.0.22.0/28
    gateway_ip: 127.0.22.1
    https_port: %d
    http_port: %d
    dns_port: %d
rules:
  - id: stress-allow
    principal: worker-stress
    effect: allow
    hosts: [stress.example.com]
    ports: [443]
`, mitmCert, mitmKey, auditDir, sockPath, metricsPort, httpsPort, httpPort, dnsPort)

	cfgPath := filepath.Join(dir, "gatewayd.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	store, err := config.NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	flows := proxy.NewFlowRegistry()
	col := metrics.NewCollector(metrics.Options{
		ActiveFlows:  flows.Count,
		ActiveGrants: func() int { return len(store.ActiveGrants()) },
	})
	flows.SetOnRevoke(col.AddRevocations)
	aw, err := audit.NewWriter(audit.Options{
		Dir:          auditDir,
		OnWriteError: col.IncAuditWriteError,
	})
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
	dialUp := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		return guardDialer.DialHost(ctx, network, host, upPort)
	}

	pSrv, err := proxy.NewServer(proxy.Options{
		Link:          store.Current().Config.Links[0],
		Store:         store,
		Evaluator:     policy.NewEvaluator(store),
		Audit:         aw,
		Leaves:        ca.NewLeafCache(mitmCA),
		DialContext:   dialUp,
		UpstreamRoots: upRoots,
		Flows:         flows,
		OnRequest:     col.ObserveRequest,
	})
	if err != nil {
		t.Fatalf("proxy.NewServer: %v", err)
	}
	if err := pSrv.Start(); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pSrv.Shutdown(ctx); err != nil {
			t.Errorf("proxy.Shutdown: %v", err)
		}
	})

	aSrv, err := admin.NewServer(admin.Options{
		SocketPath: sockPath,
		Store:      store,
		Flows:      flows,
		Audit:      aw,
		Metrics:    col,
	})
	if err != nil {
		t.Fatalf("admin.NewServer: %v", err)
	}
	if err := aSrv.Start(); err != nil {
		t.Fatalf("admin.Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := aSrv.Shutdown(ctx); err != nil {
			t.Errorf("admin.Shutdown: %v", err)
		}
	})

	mSrv, err := metrics.NewServer(store.Current().Config.Metrics.Listen, col)
	if err != nil {
		t.Fatalf("metrics.NewServer: %v", err)
	}
	if err := mSrv.Start(); err != nil {
		t.Fatalf("metrics.Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := mSrv.Shutdown(ctx); err != nil {
			t.Errorf("metrics.Shutdown: %v", err)
		}
	})

	// Start real SIGHUP watcher.
	sigCtx, sigCancel := context.WithCancel(context.Background())
	sigDone := make(chan struct{})
	go func() {
		defer close(sigDone)
		store.WatchSIGHUP(sigCtx, func(_ *config.Snapshot, _ []string, reloadErr error) {
			col.ObserveReload(reloadErr == nil)
		})
	}()
	t.Cleanup(func() {
		sigCancel()
		<-sigDone
	})
	time.Sleep(20 * time.Millisecond)

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
		return &http.Client{Transport: tr, Timeout: 2 * time.Second}
	}

	cH1 := makeClient("stress.example.com", false)
	cH2 := makeClient("stress.example.com", true)
	cAdmin := admin.NewClient(sockPath)
	t.Cleanup(cAdmin.Close)

	// Concurrently hammer H1 keep-alive, H2 multiplexed, SSE, SIGHUP reloads, Admin reloads, and Admin revokes!
	var (
		wg          sync.WaitGroup
		completedOK atomic.Int32
		revokedHits atomic.Int32
	)
	stressCtx, stressCancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer stressCancel()

	// 4 H1 keep-alive workers
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for stressCtx.Err() == nil {
				r, err := cH1.Get("https://stress.example.com/fast")
				if err != nil {
					continue
				}
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					// Torn down mid-flight by revoke.
					if cErr := r.Body.Close(); cErr != nil {
						continue
					}
					continue
				}
				if cErr := r.Body.Close(); cErr != nil {
					continue
				}
				if r.StatusCode == http.StatusOK {
					completedOK.Add(1)
				}
			}
		}()
	}

	// 4 H2 multiplexed SSE/fast workers
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			target := "https://stress.example.com/sse"
			if idx%2 == 0 {
				target = "https://stress.example.com/fast"
			}
			for stressCtx.Err() == nil {
				r, err := cH2.Get(target)
				if err != nil {
					continue
				}
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					if cErr := r.Body.Close(); cErr != nil {
						continue
					}
					continue
				}
				if cErr := r.Body.Close(); cErr != nil {
					continue
				}
				if r.StatusCode == http.StatusOK {
					completedOK.Add(1)
				}
			}
		}(i)
	}

	// Control-plane hammer: SIGHUP + rule edits + Admin Reload + Add/Delete/Expire grants + Admin Revoke
	wg.Add(1)
	go func() {
		defer wg.Done()
		altYAML := strings.Replace(cfgYAML, "hosts: [stress.example.com]", "hosts: [stress.example.com, ephemeral.example.com]", 1)
		for i := 0; i < 6 && stressCtx.Err() == nil; i++ {
			// Flip YAML rule set back and forth while requests are in flight.
			nextCfg := altYAML
			if i%2 == 1 {
				nextCfg = cfgYAML
			}
			if err := os.WriteFile(cfgPath, []byte(nextCfg), 0o600); err != nil {
				t.Errorf("write toggled config: %v", err)
			}
			// Add a grant, delete it, and add a short-TTL grant that expires mid-flight.
			if gDel, err := cAdmin.CreateGrant(context.Background(), admin.GrantRequest{
				Principal: "worker-stress",
				Host:      "ephemeral.example.com",
				Port:      443,
				TTL:       "5m",
			}); err == nil {
				if _, dErr := cAdmin.DeleteGrant(context.Background(), gDel.ID); dErr != nil {
					t.Errorf("DeleteGrant: %v", dErr)
				}
			}
			if _, err := cAdmin.CreateGrant(context.Background(), admin.GrantRequest{
				Principal: "worker-stress",
				Host:      "ephemeral.example.com",
				Port:      443,
				TTL:       "30ms",
			}); err != nil {
				t.Logf("CreateGrant short TTL raced with reload: %v", err)
			}
			time.Sleep(20 * time.Millisecond)
			if res, err := cAdmin.Revoke(context.Background(), admin.RevokeRequest{Principal: "worker-stress"}); err != nil {
				t.Errorf("Admin Revoke: %v", err)
			} else {
				revokedHits.Add(int32(res.RevokedFlows))
			}
			if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
				t.Errorf("kill SIGHUP: %v", err)
			}
			if _, err := cAdmin.Reload(context.Background()); err != nil {
				t.Errorf("Admin Reload: %v", err)
			}
			time.Sleep(25 * time.Millisecond)
		}
		// Restore base config cleanly for subsequent header-flood check.
		if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
			t.Errorf("restore base config: %v", err)
		}
		if _, err := cAdmin.Reload(context.Background()); err != nil {
			t.Errorf("final restore Reload: %v", err)
		}
	}()

	wg.Wait()

	if completedOK.Load() == 0 {
		t.Fatal("stress test completed 0 successful requests")
	}
	if revokedHits.Load() == 0 {
		t.Fatal("stress test revoked 0 in-flight flows (expected revokedHits > 0)")
	}

	// Resource-bound check: header flood (> MaxHeaderBytes + Go 4 KiB read slop) is rejected cleanly with 431.
	reqBig, err := http.NewRequest(http.MethodGet, "https://stress.example.com/fast", nil)
	if err != nil {
		t.Fatalf("NewRequest header flood: %v", err)
	}
	reqBig.Header.Set("X-Pad", strings.Repeat("Z", 8192))
	rBig, err := makeClient("stress.example.com", false).Do(reqBig)
	if err != nil {
		t.Fatalf("header flood request: %v", err)
	}
	if err := rBig.Body.Close(); err != nil {
		t.Fatalf("close rBig: %v", err)
	}
	if rBig.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("header flood status = %d, want 431", rBig.StatusCode)
	}

	// Verify /metrics reports live counters cleanly.
	mTr := &http.Transport{}
	t.Cleanup(mTr.CloseIdleConnections)
	mResp, err := (&http.Client{Transport: mTr}).Get("http://" + metricsAddr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	mBody, err := io.ReadAll(mResp.Body)
	if err != nil {
		t.Fatalf("read /metrics: %v", err)
	}
	if err := mResp.Body.Close(); err != nil {
		t.Fatalf("close /metrics: %v", err)
	}
	mText := string(mBody)
	for _, want := range []string{
		"gatewayd_requests_total",
		`gatewayd_reloads_total{result="ok"}`,
		"gatewayd_active_flows",
	} {
		if !strings.Contains(mText, want) {
			t.Errorf("/metrics missing %q\n%s", want, mText)
		}
	}
}
