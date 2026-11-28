package admin_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
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

var testUpstreamCA ca.CA

type cleanupTestingM struct {
	*testing.M
	cleanup func()
}

func (c cleanupTestingM) Run() int {
	defer c.cleanup()
	return c.M.Run()
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gateway-admin-upca-*")
	if err != nil {
		panic(fmt.Sprintf("admin TestMain mkdir: %v", err))
	}
	certPath := filepath.Join(dir, "up-ca.crt")
	keyPath := filepath.Join(dir, "up-ca.key")
	testUpstreamCA, err = ca.Init(certPath, keyPath)
	if err != nil {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			panic(fmt.Sprintf("admin TestMain ca.Init: %v (cleanup: %v)", err, rmErr))
		}
		panic(fmt.Sprintf("admin TestMain ca.Init: %v", err))
	}
	if err := os.Setenv("SSL_CERT_FILE", certPath); err != nil {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			panic(fmt.Sprintf("admin TestMain setenv: %v (cleanup: %v)", err, rmErr))
		}
		panic(fmt.Sprintf("admin TestMain setenv: %v", err))
	}
	sighupSink := make(chan os.Signal, 1)
	signal.Notify(sighupSink, syscall.SIGHUP)
	goleak.VerifyTestMain(cleanupTestingM{
		M: m,
		cleanup: func() {
			signal.Stop(sighupSink)
			if rmErr := os.RemoveAll(dir); rmErr != nil {
				panic(fmt.Sprintf("admin TestMain cleanup: %v", rmErr))
			}
		},
	})
}

type testFlowAdapter struct {
	flows *proxy.FlowRegistry
}

func (a testFlowAdapter) ListFlows() []admin.FlowInfo {
	src := a.flows.List()
	out := make([]admin.FlowInfo, len(src))
	for i, f := range src {
		out[i] = admin.FlowInfo{
			ID:        f.ID,
			Principal: f.Principal,
			Link:      f.Link,
			Host:      f.Host,
			Port:      f.Port,
			Method:    f.Method,
			Path:      f.Path,
			RuleID:    f.RuleID,
			GrantID:   f.GrantID,
			Protocol:  f.Protocol,
			StartedAt: f.StartedAt,
		}
	}
	return out
}

func (a testFlowAdapter) CountFlows() int                   { return a.flows.Count() }
func (a testFlowAdapter) RevokeByID(id string) int          { return a.flows.RevokeByID(id) }
func (a testFlowAdapter) RevokeByGrant(id string) int       { return a.flows.RevokeByGrant(id, proxy.TeardownRevoked) }
func (a testFlowAdapter) RevokeByPrincipal(p, h string) int { return a.flows.RevokeByPrincipal(p, h) }

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
	cfgPath := filepath.Join(dir, "gateway.yaml")

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
		Flows:      testFlowAdapter{flows: flows},
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

// TestStressReloadRevokeH1H2SSEAndSlowlorisBounds hammers SIGHUP + Admin Reload +
// Admin Revoke + Grant Delete while H1 keep-alive, H2 multiplexed, and SSE streams
// are mid-flight, plus header-flood/slowloris bounds.
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
		Certificates: []tls.Certificate{signLeaf(t, testUpstreamCA, []string{"stress.example.com", "ephemeral.example.com"})},
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

	cfgPath := filepath.Join(dir, "gateway.yaml")
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

	eval := policy.NewEvaluator(store)
	pSrv, err := proxy.NewServer(proxy.Options{
		Link:        store.Current().Config.Links[0],
		Store:       store,
		Evaluator:   eval,
		Audit:       aw,
		Leaves:      ca.NewLeafCache(mitmCA),
		DialContext: dialUp,
		Flows:       flows,
		OnRequest:   col.ObserveRequest,
	})
	if err != nil {
		t.Fatalf("proxy.NewServer: %v", err)
	}
	store.OnReload(func(_, _ *config.Snapshot, wipedGrantIDs []string) int {
		n := proxy.RevokeReloadedFlows(flows, eval, wipedGrantIDs)
		pSrv.CloseIdleConnections()
		return n
	})
	store.OnGrantExpired(func(g config.Grant) {
		flows.RevokeByGrant(g.ID, proxy.TeardownGrantExpired)
	})
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
		Flows:      testFlowAdapter{flows: flows},
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

	// Start real SIGHUP watcher and grant pruner so short-TTL grants expire mid-flight.
	bgCtx, bgCancel := context.WithCancel(context.Background())
	var bgWG sync.WaitGroup
	bgWG.Add(2)
	go func() {
		defer bgWG.Done()
		store.WatchSIGHUP(bgCtx, func(_ *config.Snapshot, _ []string, _ int, reloadErr error) {
			col.ObserveReload(reloadErr == nil)
		})
	}()
	go func() {
		defer bgWG.Done()
		store.RunGrantPruner(bgCtx, 20*time.Millisecond)
	}()
	t.Cleanup(func() {
		bgCancel()
		bgWG.Wait()
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
	stressCtx, stressCancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer stressCancel()

	// 4 H1 keep-alive workers
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for stressCtx.Err() == nil {
				req, err := http.NewRequestWithContext(stressCtx, http.MethodGet, "https://stress.example.com/fast", nil)
				if err != nil {
					continue
				}
				r, err := cH1.Do(req)
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
				req, err := http.NewRequestWithContext(stressCtx, http.MethodGet, target, nil)
				if err != nil {
					continue
				}
				r, err := cH2.Do(req)
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

	writeCfgAtomic := func(content string) error {
		tmp, err := os.CreateTemp(dir, "stress-cfg-*")
		if err != nil {
			return err
		}
		tmpName := tmp.Name()
		if _, err := tmp.WriteString(content); err != nil {
			if cErr := tmp.Close(); cErr != nil {
				return cErr
			}
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		return os.Rename(tmpName, cfgPath)
	}

	// Control-plane hammer: run until workload conditions (completedOK, revokedHits, and >=3 rounds) are met or deadline passes.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stressCancel()
		altYAML := strings.Replace(cfgYAML, "hosts: [stress.example.com]", "hosts: [stress.example.com, ephemeral.example.com]", 1)
		for round := 0; stressCtx.Err() == nil; round++ {
			nextCfg := altYAML
			if round%2 == 1 {
				nextCfg = cfgYAML
			}
			if err := writeCfgAtomic(nextCfg); err != nil {
				t.Errorf("write toggled config: %v", err)
			}
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

			// Wait until at least one flow is active (or short poll timeout) before revoking.
			waitFlow := time.Now().Add(200 * time.Millisecond)
			for flows.Count() == 0 && time.Now().Before(waitFlow) && stressCtx.Err() == nil {
				time.Sleep(5 * time.Millisecond)
			}
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
			if round >= 2 && completedOK.Load() >= 5 && revokedHits.Load() > 0 {
				break
			}
		}
		// Restore base config cleanly for subsequent header-flood check.
		if err := writeCfgAtomic(cfgYAML); err != nil {
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
		"gateway_requests_total",
		`gateway_reloads_total{result="ok"}`,
		"gateway_active_flows",
	} {
		if !strings.Contains(mText, want) {
			t.Errorf("/metrics missing %q\n%s", want, mText)
		}
	}
}

func TestAdminRevokeRejectsMultipleSelectors(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if _, err := ca.Init(certPath, keyPath); err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	cfgYAML := fmt.Sprintf(`
ca:
  cert_path: %s
  key_path: %s
audit:
  dir: %s
links:
  - name: sbx0
    principal: worker-a
    subnet: 127.0.23.0/28
    gateway_ip: 127.0.23.1
`, certPath, keyPath, filepath.Join(dir, "audit"))
	cfgPath := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	store, err := config.NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	aw, err := audit.NewWriter(audit.Options{Dir: filepath.Join(dir, "audit")})
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}
	t.Cleanup(func() {
		if err := aw.Close(); err != nil {
			t.Errorf("audit close: %v", err)
		}
	})
	sockPath := filepath.Join(dir, "admin.sock")
	srv, err := admin.NewServer(admin.Options{
		SocketPath: sockPath,
		Store:      store,
		Flows:      testFlowAdapter{flows: proxy.NewFlowRegistry()},
		Audit:      aw,
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

	unixClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		},
	}
	t.Cleanup(unixClient.CloseIdleConnections)

	for _, body := range []string{
		`{"flow_id":"f1","grant_id":"g1"}`,
		`{"flow_id":"f1","principal":"worker-a"}`,
		`{"grant_id":"g1","principal":"worker-a"}`,
		`{"host":"example.com"}`,
	} {
		resp, err := unixClient.Post("http://unix/v1/revoke", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST /v1/revoke %s: %v", body, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close body: %v", err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("POST /v1/revoke %s status = %d, want 400", body, resp.StatusCode)
		}
	}
}

func readAuditEvents(t *testing.T, dir string) []audit.Event {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir audit: %v", err)
	}
	var events []audit.Event
	for _, ent := range entries {
		if !strings.HasSuffix(ent.Name(), ".jsonl") {
			continue
		}
		raw, rErr := os.ReadFile(filepath.Join(dir, ent.Name()))
		if rErr != nil {
			t.Fatalf("read audit %s: %v", ent.Name(), rErr)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if line == "" {
				continue
			}
			var ev audit.Event
			if uErr := json.Unmarshal([]byte(line), &ev); uErr != nil {
				t.Fatalf("unmarshal audit line %q: %v", line, uErr)
			}
			events = append(events, ev)
		}
	}
	return events
}

func startAdminAuditHarness(t *testing.T, baseYAML, auditDir string, rootCA ca.CA, httpsAddr, upAddr string) (cfgPath string, admClient *admin.Client, openStream func(host, path string) *http.Response) {
	t.Helper()
	dir := filepath.Dir(auditDir)
	cfgPath = filepath.Join(dir, "gateway.yaml")
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
			t.Errorf("audit.Close: %v", err)
		}
	})
	flows := proxy.NewFlowRegistry()
	eval := policy.NewEvaluator(store)
	pSrv, err := proxy.NewServer(proxy.Options{
		Link: store.Current().Config.Links[0], Store: store, Evaluator: eval,
		Leaves: ca.NewLeafCache(rootCA), Audit: aw, Flows: flows,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upAddr)
		},
	})
	if err != nil {
		t.Fatalf("proxy.NewServer: %v", err)
	}
	store.OnReload(func(_, _ *config.Snapshot, wipedGrantIDs []string) int {
		n := proxy.RevokeReloadedFlows(flows, eval, wipedGrantIDs)
		pSrv.CloseIdleConnections()
		return n
	})
	store.OnGrantExpired(func(g config.Grant) {
		flows.RevokeByGrant(g.ID, proxy.TeardownGrantExpired)
	})
	if err := pSrv.Start(); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := pSrv.Shutdown(ctx); err != nil {
			t.Errorf("proxy.Shutdown: %v", err)
		}
	})
	sockPath := filepath.Join(dir, "admin.sock")
	aSrv, err := admin.NewServer(admin.Options{
		SocketPath: sockPath, Store: store, Flows: testFlowAdapter{flows: flows}, Audit: aw,
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
	mitmRoots := x509.NewCertPool()
	if !mitmRoots.AppendCertsFromPEM(rootCA.CertPEM) {
		t.Fatal("append MITM CA")
	}
	openStream = func(host, path string) *http.Response {
		tr := &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, httpsAddr)
			},
			TLSClientConfig: &tls.Config{ServerName: host, RootCAs: mitmRoots, MinVersion: tls.VersionTLS12},
		}
		t.Cleanup(tr.CloseIdleConnections)
		resp, gErr := (&http.Client{Transport: tr}).Get("https://" + host + path)
		if gErr != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("openStream %s%s: resp=%+v err=%v", host, path, resp, gErr)
		}
		return resp
	}
	return cfgPath, admin.NewClient(sockPath), openStream
}

func drainStreamResp(t *testing.T, resp *http.Response) {
	t.Helper()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Logf("stream ended on teardown: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Logf("close stream body: %v", err)
	}
}

func TestGrantRevokeAndReloadAuditCompleteness(t *testing.T) {
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	rootCA, err := ca.Init(certPath, keyPath)
	if err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	holdRelease := make(chan struct{})
	streamOpen := make(chan struct{}, 8)
	upSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, "data: hold\n\n"); err != nil {
			return
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}
		streamOpen <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-holdRelease:
		}
	}))
	upSrv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{signLeaf(t, testUpstreamCA, []string{"grant.example.com", "rule.example.com"})},
	}
	upSrv.StartTLS()
	t.Cleanup(upSrv.Close)
	t.Cleanup(func() { close(holdRelease) })

	ports := freePorts(t, "127.0.24.1", 3)
	httpsAddr := fmt.Sprintf("127.0.24.1:%d", ports[0])
	baseYAML := fmt.Sprintf(`ca:
  cert_path: %s
  key_path: %s
audit:
  dir: %s
links:
  - name: sbx0
    principal: worker-a
    subnet: 127.0.24.0/28
    gateway_ip: 127.0.24.1
    https_port: %d
    http_port: %d
    dns_port: %d
rules:
  - id: allow-rule
    principal: worker-a
    effect: allow
    hosts: [rule.example.com]
    ports: [443]
`, certPath, keyPath, auditDir, ports[0], ports[1], ports[2])

	cfgPath, admClient, openStream := startAdminAuditHarness(t, baseYAML, auditDir, rootCA, httpsAddr, upSrv.Listener.Addr().String())

	// 1. Create grant with methods, paths, and allow_websocket; open stream; delete grant.
	g, err := admClient.CreateGrant(context.Background(), admin.GrantRequest{
		Principal: "worker-a", Host: "grant.example.com", Port: 443,
		Methods: []string{"GET", "POST"}, Paths: []string{"/api/**"},
		TTL: "5m", AllowWebSocket: true,
	})
	if err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	r1 := openStream("grant.example.com", "/api/stream")
	<-streamOpen
	if _, err := admClient.DeleteGrant(context.Background(), g.ID); err != nil {
		t.Fatalf("DeleteGrant: %v", err)
	}
	drainStreamResp(t, r1)

	// 1b. Create a second grant and revoke it via POST /v1/revoke {grant_id}; verify audit records Principal/Host/Port.
	gRevoke, err := admClient.CreateGrant(context.Background(), admin.GrantRequest{
		Principal: "worker-a", Host: "revoke.example.com", Port: 443,
		TTL: "5m",
	})
	if err != nil {
		t.Fatalf("CreateGrant for revoke-grant: %v", err)
	}
	if _, err := admClient.Revoke(context.Background(), admin.RevokeRequest{GrantID: gRevoke.ID}); err != nil {
		t.Fatalf("Revoke grant_id: %v", err)
	}

	// 2. Open stream on allow-rule, then revoke principal.
	r2 := openStream("rule.example.com", "/hold")
	<-streamOpen
	if _, err := admClient.Revoke(context.Background(), admin.RevokeRequest{Principal: "worker-a"}); err != nil {
		t.Fatalf("Revoke principal: %v", err)
	}
	drainStreamResp(t, r2)

	// 3. Open stream on allow-rule, then reload removing allow-rule.
	r3 := openStream("rule.example.com", "/hold")
	<-streamOpen
	noRulesYAML := baseYAML[:strings.Index(baseYAML, "rules:\n")]
	if err := os.WriteFile(cfgPath, []byte(noRulesYAML), 0o600); err != nil {
		t.Fatalf("write no-rules config: %v", err)
	}
	if _, err := admClient.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	drainStreamResp(t, r3)

	var sawCreated, sawDeleted, sawRevokeGrant, sawRevoke, sawReload bool
	for _, ev := range readAuditEvents(t, auditDir) {
		switch ev.Reason {
		case "grant-created":
			if ev.GrantID == g.ID {
				sawCreated = true
				if !slices.Equal(ev.Methods, []string{"GET", "POST"}) || !slices.Equal(ev.Paths, []string{"/api/**"}) || ev.AllowWebSocket == nil || !*ev.AllowWebSocket {
					t.Fatalf("grant-created audit missing scope: methods=%v paths=%v allow_ws=%v", ev.Methods, ev.Paths, ev.AllowWebSocket)
				}
			}
		case "grant-deleted":
			if ev.GrantID == g.ID {
				sawDeleted = true
				if ev.Principal != "worker-a" || ev.Host != "grant.example.com" || ev.Port != 443 || ev.RevokedFlows == nil || *ev.RevokedFlows != 1 {
					t.Fatalf("grant-deleted audit incomplete: %+v", ev)
				}
			}
		case "revoke-grant":
			if ev.GrantID == gRevoke.ID {
				sawRevokeGrant = true
				if ev.Principal != "worker-a" || ev.Host != "revoke.example.com" || ev.Port != 443 {
					t.Fatalf("revoke-grant audit missing grant identity: principal=%q host=%q port=%d", ev.Principal, ev.Host, ev.Port)
				}
			}
		case "revoke-principal":
			sawRevoke = true
			if ev.RevokedFlows == nil || *ev.RevokedFlows != 1 {
				t.Fatalf("revoke-principal audit revoked_flows = %v, want 1", ev.RevokedFlows)
			}
		case "reload":
			sawReload = true
			if ev.RevokedFlows == nil || *ev.RevokedFlows != 1 {
				t.Fatalf("reload audit revoked_flows = %v, want 1", ev.RevokedFlows)
			}
		}
	}
	if !sawCreated || !sawDeleted || !sawRevokeGrant || !sawRevoke || !sawReload {
		t.Fatalf("missing audit events: created=%v deleted=%v revokeGrant=%v revoke=%v reload=%v", sawCreated, sawDeleted, sawRevokeGrant, sawRevoke, sawReload)
	}
}
