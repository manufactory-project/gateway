package proxy_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/ca"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/netguard"
	"github.com/manufactory-project/gateway/internal/policy"
	"github.com/manufactory-project/gateway/internal/proxy"
)

type stepResolver struct {
	mu      sync.Mutex
	answers map[string][][]netip.Addr
	calls   map[string]int
}

func (r *stepResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.calls[host]
	r.calls[host] = i + 1
	seq := r.answers[host]
	if len(seq) == 0 {
		return nil, errors.New("nxdomain")
	}
	if i >= len(seq) {
		i = len(seq) - 1
	}
	return seq[i], nil
}

// TestSectionEWireInvariants covers every remaining NOW.md:104 wire test from Slice 6 Section E:
// - H2 :authority and port mismatch (separate from H1 Host/SNI)
// - Port 80 to a bound host: no substitution, placeholder stripped
// - H2 grant isolation: (a) two multiplexed H2 streams under distinct grants on one conn;
//   (b) separate conn under another grant untouched when first grant is revoked
// - SIGHUP while a stream is open under a grant: grant wiped + stream torn down (cancel + conn.Close)
// - Proxy 503 when audit sink cannot be written (upstream received == 0)
// - No substitution of placeholder in body or query string
// - git smart HTTP (GET /repo.git/info/refs + POST /repo.git/git-upload-pack) false-positive control
// - Two-step DNS rebinding through the proxy (real netguard.Dialer)
// - Subscription MITM auth + cookie passthrough with zero audit leakage
func TestSectionEWireInvariants(t *testing.T) {
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

	forgeSec := "gitsec_" + randHex(t)
	forgeSecFile := filepath.Join(dir, "forge.sec")
	if err := os.WriteFile(forgeSecFile, []byte(forgeSec+"\n"), 0o600); err != nil {
		t.Fatalf("write forge.sec: %v", err)
	}

	var (
		httpsHits    atomic.Int32
		plainHits    atomic.Int32
		rebindHits   atomic.Int32
		streamOpenCh = make(chan string, 16)
		releaseHold  = make(chan struct{})
		releaseC     = make(chan struct{})
		mu           sync.Mutex
		lastAuth     string
		lastProxyAut string
		lastCookie   string
		lastBody     string
		lastRawQuery string
	)

	// Rebind canary listener on 127.0.0.1 (must NEVER be reached by unpinned rebind.example.com).
	rebindLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen rebind canary: %v", err)
	}
	rebindDone := make(chan struct{})
	go func() {
		defer close(rebindDone)
		for {
			c, err := rebindLn.Accept()
			if err != nil {
				return
			}
			rebindHits.Add(1)
			if cErr := c.Close(); cErr != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		if err := rebindLn.Close(); err != nil {
			t.Errorf("close rebindLn: %v", err)
		}
		<-rebindDone
	})
	rebindPort := tcpPort(t, rebindLn.Addr())

	upTLS := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpsHits.Add(1)
		bodyBytes, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		lastAuth = r.Header.Get("Authorization")
		lastProxyAut = r.Header.Get("Proxy-Authorization")
		lastCookie = r.Header.Get("Cookie")
		lastBody = string(bodyBytes)
		lastRawQuery = r.URL.RawQuery
		mu.Unlock()

		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "ok"); err != nil {
				return
			}
		case "/repo.git/info/refs":
			w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "001e# service=git-upload-pack\n0000"); err != nil {
				return
			}
		case "/repo.git/git-upload-pack":
			w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
			w.WriteHeader(http.StatusOK)
			// Echo exact packfile request bytes back to verify binary fidelity.
			if _, err := w.Write(append([]byte("PACK"), bodyBytes...)); err != nil {
				return
			}
		case "/stream-a", "/stream-b", "/stream-hup":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			rc := http.NewResponseController(w)
			if _, err := io.WriteString(w, "data: "+r.URL.Path+"\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			streamOpenCh <- r.URL.Path
			<-releaseHold
		case "/stream-c":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			rc := http.NewResponseController(w)
			if _, err := io.WriteString(w, "data: c-start\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			streamOpenCh <- r.URL.Path
			<-releaseC
			if _, err := io.WriteString(w, "data: c-done\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	upTLS.EnableHTTP2 = true
	upTLS.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{makeSignedServerCert(t, upCA, []string{
			"h2a.example.com", "h2b.example.com", "code.lan.example",
			"h2grant.example.com", "sub.vendor.example",
		})},
	}
	upTLS.StartTLS()
	t.Cleanup(upTLS.Close)
	t.Cleanup(func() {
		close(releaseHold)
	})

	upPlain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHits.Add(1)
		mu.Lock()
		lastAuth = r.Header.Get("Authorization")
		lastProxyAut = r.Header.Get("Proxy-Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, "plain"); err != nil {
			return
		}
	}))
	t.Cleanup(upPlain.Close)

	ports := freePorts(t, "127.0.35.1", 3)
	httpsPort, httpPort, dnsPort := ports[0], ports[1], ports[2]
	httpsAddr := fmt.Sprintf("127.0.35.1:%d", httpsPort)
	httpAddr := fmt.Sprintf("127.0.35.1:%d", httpPort)

	cfgYAML := fmt.Sprintf(`
ca:
  cert_path: %s
  key_path: %s
audit:
  dir: %s
  max_file_bytes: 512
records:
  h2a.example.com: 127.0.0.1
  h2b.example.com: 127.0.0.1
  code.lan.example: 127.0.0.1
  h2grant.example.com: 127.0.0.1
  sub.vendor.example: 127.0.0.1
links:
  - name: sbx0
    principal: worker-e
    subnet: 127.0.35.0/28
    gateway_ip: 127.0.35.1
    https_port: %d
    http_port: %d
    dns_port: %d
rules:
  - id: allow-h2
    principal: worker-e
    effect: allow
    hosts: [h2a.example.com, h2b.example.com]
    ports: [443]
  - id: allow-forge
    principal: worker-e
    effect: allow
    hosts: [code.lan.example]
    ports: [443, 80]
    bindings:
      - name: forge-git
        host: code.lan.example
        header: Authorization
        scheme: basic
        placeholder: mf_ph_git
        secret_file: %s
  - id: allow-rebind
    principal: worker-e
    effect: allow
    hosts: [rebind.example.com]
    ports: [443]
  - id: allow-sub
    principal: worker-e
    effect: allow
    hosts: [sub.vendor.example]
    ports: [443]
`, mitmCert, mitmKey, auditDir, httpsPort, httpPort, dnsPort, forgeSecFile)

	cfgPath := filepath.Join(dir, "gatewayd.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	store, err := config.NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	aw, err := audit.NewWriter(audit.Options{Dir: auditDir, MaxFileBytes: 512})
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}
	t.Cleanup(func() {
		if err := aw.Close(); err != nil {
			t.Errorf("audit close: %v", err)
		}
	})

	// Two-step DNS rebinding resolver: step 1 returns 127.0.0.1; step 2 returns ::ffff:127.0.0.1.
	rebindRes := &stepResolver{
		answers: map[string][][]netip.Addr{
			"rebind.example.com": {
				{netip.MustParseAddr("127.0.0.1")},
				{netip.MustParseAddr("::ffff:127.0.0.1")},
			},
		},
		calls: make(map[string]int),
	}
	guardDialer := netguard.NewDialer(netguard.Options{
		Store:    store,
		Resolver: rebindRes,
		Timeout:  time.Second,
	})
	upTLSPort := tcpPort(t, upTLS.Listener.Addr())
	upPlainPort := tcpPort(t, upPlain.Listener.Addr())

	flows := proxy.NewFlowRegistry()
	srv, err := proxy.NewServer(proxy.Options{
		Link:      store.Current().Config.Links[0],
		Store:     store,
		Evaluator: policy.NewEvaluator(store),
		Audit:     aw,
		Leaves:    ca.NewLeafCache(mitmCA),
		Flows:     flows,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			switch {
			case host == "rebind.example.com":
				return guardDialer.DialHost(ctx, network, host, rebindPort)
			case portStr == "80":
				return guardDialer.DialHost(ctx, network, host, upPlainPort)
			default:
				return guardDialer.DialHost(ctx, network, host, upTLSPort)
			}
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

	makeH2Client := func(sni string) *http.Client {
		protos := new(http.Protocols)
		protos.SetHTTP1(false)
		protos.SetHTTP2(true)
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
			ForceAttemptHTTP2:  true,
			DisableCompression: true,
			MaxConnsPerHost:    1,
			Protocols:          protos,
		}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr}
	}

	// --- E1: H2 :authority and port mismatch (separate from H1 Host/SNI) ---
	cH2A := makeH2Client("h2a.example.com")
	beforeE1 := httpsHits.Load()
	for _, badAuth := range []string{"h2b.example.com", "h2a.example.com:8443"} {
		req, err := http.NewRequest(http.MethodGet, "https://h2a.example.com/ok", nil)
		if err != nil {
			t.Fatalf("NewRequest H2 %s: %v", badAuth, err)
		}
		req.Host = badAuth
		r, err := cH2A.Do(req)
		if err != nil {
			t.Fatalf("Do H2 %s: %v", badAuth, err)
		}
		if err := r.Body.Close(); err != nil {
			t.Fatalf("close H2 %s: %v", badAuth, err)
		}
		if r.ProtoMajor != 2 || r.StatusCode != http.StatusForbidden {
			t.Fatalf("H2 :authority=%q got proto=%s status=%d, want HTTP/2 403", badAuth, r.Proto, r.StatusCode)
		}
	}
	if httpsHits.Load() != beforeE1 {
		t.Fatalf("H2 :authority/port mismatch hit upstream: %d != %d", httpsHits.Load(), beforeE1)
	}
	// Positive control over H2 with matching :authority and explicit :443.
	reqOKH2, err := http.NewRequest(http.MethodGet, "https://h2a.example.com/ok", nil)
	if err != nil {
		t.Fatalf("NewRequest H2 ok: %v", err)
	}
	reqOKH2.Host = "h2a.example.com:443"
	rOKH2, err := cH2A.Do(reqOKH2)
	if err != nil {
		t.Fatalf("Do H2 ok: %v", err)
	}
	if err := rOKH2.Body.Close(); err != nil {
		t.Fatalf("close H2 ok: %v", err)
	}
	if rOKH2.ProtoMajor != 2 || rOKH2.StatusCode != http.StatusOK {
		t.Fatalf("H2 matching :authority:443 got proto=%s status=%d", rOKH2.Proto, rOKH2.StatusCode)
	}

	// --- E2: Port 80 to a bound host -> NO substitution, placeholder stripped ---
	plainTr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, httpAddr)
		},
	}
	t.Cleanup(plainTr.CloseIdleConnections)
	cPlain := &http.Client{Transport: plainTr}
	reqP80, err := http.NewRequest(http.MethodGet, "http://code.lan.example/ok", nil)
	if err != nil {
		t.Fatalf("NewRequest port 80 bound: %v", err)
	}
	reqP80.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("git:mf_ph_git")))
	reqP80.Header.Set("Proxy-Authorization", "Bearer nope")
	rP80, err := cPlain.Do(reqP80)
	if err != nil {
		t.Fatalf("Do port 80 bound: %v", err)
	}
	if err := rP80.Body.Close(); err != nil {
		t.Fatalf("close port 80 bound: %v", err)
	}
	if rP80.StatusCode != http.StatusOK || plainHits.Load() != 1 {
		t.Fatalf("port 80 bound status=%d plainHits=%d", rP80.StatusCode, plainHits.Load())
	}
	mu.Lock()
	p80Auth, p80Proxy := lastAuth, lastProxyAut
	mu.Unlock()
	if p80Auth != "" || p80Proxy != "" {
		t.Fatalf("port 80 bound leaked or substituted auth: auth=%q proxy=%q", p80Auth, p80Proxy)
	}

	// --- E6 & E7: No substitution in body or query string + git smart HTTP false-positive control ---
	cForge := makeH2Client("code.lan.example")
	reqNoBodySub, err := http.NewRequest(http.MethodPost, "https://code.lan.example/ok?token=mf_ph_git", strings.NewReader("body=mf_ph_git"))
	if err != nil {
		t.Fatalf("NewRequest body/query: %v", err)
	}
	reqNoBodySub.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("git:mf_ph_git")))
	rNBS, err := cForge.Do(reqNoBodySub)
	if err != nil {
		t.Fatalf("Do body/query: %v", err)
	}
	if err := rNBS.Body.Close(); err != nil {
		t.Fatalf("close body/query: %v", err)
	}
	mu.Lock()
	gotAuth, gotBody, gotQuery := lastAuth, lastBody, lastRawQuery
	mu.Unlock()
	wantBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("git:"+forgeSec))
	if gotAuth != wantBasic {
		t.Fatalf("expected Basic auth substituted on :443, got %q", gotAuth)
	}
	if gotBody != "body=mf_ph_git" || strings.Contains(gotBody, forgeSec) {
		t.Fatalf("placeholder was substituted in body! got %q", gotBody)
	}
	if gotQuery != "token=mf_ph_git" || strings.Contains(gotQuery, forgeSec) {
		t.Fatalf("placeholder was substituted in query! got %q", gotQuery)
	}

	// Git smart HTTP: GET /repo.git/info/refs?service=git-upload-pack + POST /repo.git/git-upload-pack.
	rRefs, err := cForge.Get("https://code.lan.example/repo.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("git info/refs: %v", err)
	}
	refsBody, err := io.ReadAll(rRefs.Body)
	if err != nil {
		t.Fatalf("read info/refs: %v", err)
	}
	if err := rRefs.Body.Close(); err != nil {
		t.Fatalf("close info/refs: %v", err)
	}
	if rRefs.StatusCode != http.StatusOK || string(refsBody) != "001e# service=git-upload-pack\n0000" {
		t.Fatalf("git info/refs failed: status=%d body=%q", rRefs.StatusCode, refsBody)
	}
	packReq := []byte("0032want 0123456789abcdef0123456789abcdef01234567\n00000009done\n")
	reqPack, err := http.NewRequest(http.MethodPost, "https://code.lan.example/repo.git/git-upload-pack", bytes.NewReader(packReq))
	if err != nil {
		t.Fatalf("NewRequest git-upload-pack: %v", err)
	}
	reqPack.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	reqPack.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("git:mf_ph_git")))
	rPack, err := cForge.Do(reqPack)
	if err != nil {
		t.Fatalf("POST git-upload-pack: %v", err)
	}
	packResp, err := io.ReadAll(rPack.Body)
	if err != nil {
		t.Fatalf("read git-upload-pack: %v", err)
	}
	if err := rPack.Body.Close(); err != nil {
		t.Fatalf("close git-upload-pack: %v", err)
	}
	if rPack.StatusCode != http.StatusOK || !bytes.Equal(packResp, append([]byte("PACK"), packReq...)) {
		t.Fatalf("git-upload-pack mismatch: status=%d len=%d", rPack.StatusCode, len(packResp))
	}

	// --- E8: Two-step DNS rebinding through the proxy ---
	cRebind := makeH2Client("rebind.example.com")
	for step := 1; step <= 2; step++ {
		rReb, err := cRebind.Get("https://rebind.example.com/ok")
		if err != nil {
			t.Fatalf("rebind step %d request: %v", step, err)
		}
		if err := rReb.Body.Close(); err != nil {
			t.Fatalf("close rebind step %d: %v", step, err)
		}
		if rReb.StatusCode != http.StatusBadGateway {
			t.Fatalf("rebind step %d status=%d, want 502", step, rReb.StatusCode)
		}
	}
	if rebindHits.Load() != 0 {
		t.Fatalf("DNS rebinding reached canary listener: hits=%d", rebindHits.Load())
	}

	// --- E9: Subscription MITM auth + cookie passthrough with zero audit logging ---
	subBearer := "oauth_live_" + randHex(t)
	subCookie := "session_live_" + randHex(t)
	cSub := makeH2Client("sub.vendor.example")
	reqSub, err := http.NewRequest(http.MethodGet, "https://sub.vendor.example/ok", nil)
	if err != nil {
		t.Fatalf("NewRequest sub: %v", err)
	}
	reqSub.Header.Set("Authorization", "Bearer "+subBearer)
	reqSub.Header.Set("Cookie", subCookie)
	rSub, err := cSub.Do(reqSub)
	if err != nil {
		t.Fatalf("Do sub: %v", err)
	}
	if err := rSub.Body.Close(); err != nil {
		t.Fatalf("close sub: %v", err)
	}
	mu.Lock()
	gotSubAuth, gotSubCookie := lastAuth, lastCookie
	mu.Unlock()
	if gotSubAuth != "Bearer "+subBearer || gotSubCookie != subCookie {
		t.Fatalf("subscription MITM modified auth/cookie: auth=%q cookie=%q", gotSubAuth, gotSubCookie)
	}

	// --- E3: H2 grant isolation (a) multiplexed streams on one conn, (b) separate conn untouched ---
	gA, err := store.AddGrant("worker-e", "h2grant.example.com", 443, []string{"GET"}, []string{"/stream-a"}, 5*time.Minute)
	if err != nil {
		t.Fatalf("AddGrant gA: %v", err)
	}
	gB, err := store.AddGrant("worker-e", "h2grant.example.com", 443, []string{"GET"}, []string{"/stream-b"}, 5*time.Minute)
	if err != nil {
		t.Fatalf("AddGrant gB: %v", err)
	}
	gC, err := store.AddGrant("worker-e", "h2grant.example.com", 443, []string{"GET"}, []string{"/stream-c"}, 5*time.Minute)
	if err != nil {
		t.Fatalf("AddGrant gC: %v", err)
	}

	cMux := makeH2Client("h2grant.example.com")  // ONE shared H2 conn (MaxConnsPerHost: 1)
	cSep := makeH2Client("h2grant.example.com")  // SEPARATE H2 conn

	rA, err := cMux.Get("https://h2grant.example.com/stream-a")
	if err != nil {
		t.Fatalf("GET /stream-a: %v", err)
	}
	<-streamOpenCh
	rB, err := cMux.Get("https://h2grant.example.com/stream-b")
	if err != nil {
		t.Fatalf("GET /stream-b: %v", err)
	}
	<-streamOpenCh
	rC, err := cSep.Get("https://h2grant.example.com/stream-c")
	if err != nil {
		t.Fatalf("GET /stream-c: %v", err)
	}
	<-streamOpenCh

	// Verify flows registry records ALL THREE distinct grant IDs without overwriting per conn!
	seenGrants := make(map[string]bool)
	for _, f := range flows.List() {
		seenGrants[f.GrantID] = true
	}
	if !seenGrants[gA.ID] || !seenGrants[gB.ID] || !seenGrants[gC.ID] {
		t.Fatalf("missing distinct grantIDs in active flows: got %v, want %s/%s/%s", seenGrants, gA.ID, gB.ID, gC.ID)
	}

	// Revoke gA: tears down stream A (and shared conn of mux) while leaving separate conn stream C alive!
	store.RevokeGrant(gA.ID)
	if n := flows.RevokeByGrant(gA.ID); n != 1 {
		t.Fatalf("RevokeByGrant(gA) = %d, want 1", n)
	}
	doneA := make(chan error, 1)
	go func() {
		_, rErr := io.ReadAll(rA.Body)
		doneA <- rErr
	}()
	select {
	case <-doneA:
	case <-time.After(2 * time.Second):
		t.Fatal("stream A was not torn down on gA revoke")
	}
	if err := rA.Body.Close(); err != nil {
		t.Logf("close rA: %v", err)
	}
	if err := rB.Body.Close(); err != nil {
		t.Logf("close rB: %v", err)
	}

	// Separate connection stream C MUST survive and finish cleanly once releaseC closes!
	close(releaseC)
	bodyC, err := io.ReadAll(rC.Body)
	if err != nil {
		t.Fatalf("separate conn stream C broke when gA was revoked: %v", err)
	}
	if err := rC.Body.Close(); err != nil {
		t.Fatalf("close rC: %v", err)
	}
	if !strings.Contains(string(bodyC), "c-done") {
		t.Fatalf("stream C did not complete cleanly: %q", bodyC)
	}

	// --- E4: SIGHUP while a stream is open under a grant wipes grant + tears down stream ---
	sigCtx, sigCancel := context.WithCancel(context.Background())
	sigDone := make(chan struct{})
	go func() {
		defer close(sigDone)
		store.WatchSIGHUP(sigCtx, nil)
	}()
	t.Cleanup(func() {
		sigCancel()
		<-sigDone
	})
	time.Sleep(25 * time.Millisecond)

	gHUP, err := store.AddGrant("worker-e", "h2grant.example.com", 443, []string{"GET"}, []string{"/stream-hup"}, 5*time.Minute)
	if err != nil {
		t.Fatalf("AddGrant gHUP: %v", err)
	}
	cHUP := makeH2Client("h2grant.example.com")
	rHUP, err := cHUP.Get("https://h2grant.example.com/stream-hup")
	if err != nil {
		t.Fatalf("GET /stream-hup: %v", err)
	}
	<-streamOpenCh

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}
	hupDone := make(chan error, 1)
	go func() {
		_, rErr := io.ReadAll(rHUP.Body)
		hupDone <- rErr
	}()
	select {
	case <-hupDone:
	case <-time.After(2 * time.Second):
		t.Fatalf("stream under grant %s was not torn down on SIGHUP", gHUP.ID)
	}
	if err := rHUP.Body.Close(); err != nil {
		t.Logf("close rHUP: %v", err)
	}
	if active := store.ActiveGrants(); len(active) != 0 {
		t.Fatalf("SIGHUP did not wipe grants, still active: %+v", active)
	}

	// Verify audit logs contain ZERO subscription credentials or forge secret.
	entries, err := os.ReadDir(auditDir)
	if err != nil {
		t.Fatalf("readdir auditDir: %v", err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(auditDir, e.Name()))
		if err != nil {
			t.Fatalf("read audit %s: %v", e.Name(), err)
		}
		for _, secretTok := range []string{forgeSec, subBearer, subCookie} {
			if strings.Contains(string(data), secretTok) {
				t.Fatalf("audit %s leaked credential %q", e.Name(), secretTok)
			}
		}
	}

	// --- E5: Proxy returns 503 when audit sink is unwritable (upstream received == 0) ---
	if err := os.RemoveAll(auditDir); err != nil {
		t.Fatalf("remove auditDir: %v", err)
	}
	if err := os.WriteFile(auditDir, []byte("blocked"), 0o600); err != nil {
		t.Fatalf("replace auditDir with file: %v", err)
	}
	var got503 bool
	// Write requests until the 512-byte segment attempts rotation on the broken dir and fails closed 503.
	for i := 0; i < 6; i++ {
		r, err := cH2A.Get("https://h2a.example.com/ok")
		if err != nil {
			t.Fatalf("audit-fail request %d: %v", i, err)
		}
		if cErr := r.Body.Close(); cErr != nil {
			t.Fatalf("close r: %v", cErr)
		}
		if r.StatusCode == http.StatusServiceUnavailable {
			got503 = true
			// Verify one more request while broken ALSO returns 503 with ZERO upstream hits!
			hitsBefore := httpsHits.Load()
			r2, err := cH2A.Get("https://h2a.example.com/ok")
			if err != nil {
				t.Fatalf("second 503 check: %v", err)
			}
			if cErr := r2.Body.Close(); cErr != nil {
				t.Fatalf("close r2: %v", cErr)
			}
			if r2.StatusCode != http.StatusServiceUnavailable || httpsHits.Load() != hitsBefore {
				t.Fatalf("fail-closed 503 check failed: status=%d hitsBefore=%d hitsAfter=%d", r2.StatusCode, hitsBefore, httpsHits.Load())
			}
			break
		}
	}
	if !got503 {
		t.Fatal("proxy did not return 503 when audit sink became unwritable")
	}
}
