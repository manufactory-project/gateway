package proxy_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

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

var nextTestLinkOctet atomic.Int32

type countingSigner struct {
	crypto.Signer
	signs atomic.Int32
}

func (c *countingSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	c.signs.Add(1)
	return c.Signer.Sign(r, digest, opts)
}

type closeTrackingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTrackingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

type testGatewaySpec struct {
	Principal         string
	AuditMaxFileBytes int64
	HTTPBlockYAML     string
	Hosts             []string
	RulesYAML         string
	Handler           http.Handler
	PlainHandler      http.Handler
	Resolver          netguard.Resolver
	DialOverride      func(guard *netguard.Dialer, upTLSPort, upPlainPort uint16) func(ctx context.Context, network, addr string) (net.Conn, error)
	CountCASigns      bool
	StartGrantPruner  bool
	OnCleanupFirst    func()
}

type testGateway struct {
	Dir       string
	AuditDir  string
	CfgPath   string
	BaseYAML  string
	Store     *config.Store
	Audit     *audit.Writer
	Flows     *proxy.FlowRegistry
	Metrics   *metrics.Collector
	Server    *proxy.Server
	HTTPSAddr string
	HTTPAddr  string
	MITMRoots *x509.CertPool
	UpCA      ca.CA
	UpTLS     *httptest.Server
	UpPlain   *httptest.Server
	CASigns   *countingSigner
}

func newTestGateway(t *testing.T, spec testGatewaySpec) *testGateway {
	t.Helper()

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
	upRoots := x509.NewCertPool()
	if !upRoots.AppendCertsFromPEM(upCA.CertPEM) {
		t.Fatal("append upstream CA")
	}
	mitmRoots := x509.NewCertPool()
	if !mitmRoots.AppendCertsFromPEM(mitmCA.CertPEM) {
		t.Fatal("append MITM CA")
	}

	handler := spec.Handler
	if handler == nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}
	certHosts := spec.Hosts
	if len(certHosts) == 0 {
		certHosts = []string{"example.com"}
	}
	upTLS := httptest.NewUnstartedServer(handler)
	upTLS.EnableHTTP2 = true
	upTLS.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{makeSignedServerCert(t, upCA, certHosts)},
	}
	upTLS.StartTLS()
	upTLSPort := tcpPort(t, upTLS.Listener.Addr())

	var upPlain *httptest.Server
	var upPlainPort uint16
	if spec.PlainHandler != nil {
		upPlain = httptest.NewServer(spec.PlainHandler)
		upPlainPort = tcpPort(t, upPlain.Listener.Addr())
	}

	octet := 40 + nextTestLinkOctet.Add(1)
	linkIP := fmt.Sprintf("127.0.%d.1", octet)
	linkSubnet := fmt.Sprintf("127.0.%d.0/28", octet)
	ports := freePorts(t, linkIP, 3)
	httpsPort, httpPort, dnsPort := ports[0], ports[1], ports[2]
	httpsAddr := net.JoinHostPort(linkIP, strconv.Itoa(int(httpsPort)))
	httpAddr := net.JoinHostPort(linkIP, strconv.Itoa(int(httpPort)))

	principal := spec.Principal
	if principal == "" {
		principal = "worker-test"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "ca:\n  cert_path: %s\n  key_path: %s\n", mitmCert, mitmKey)
	fmt.Fprintf(&sb, "audit:\n  dir: %s\n", auditDir)
	if spec.AuditMaxFileBytes > 0 {
		fmt.Fprintf(&sb, "  max_file_bytes: %d\n", spec.AuditMaxFileBytes)
	}
	if spec.HTTPBlockYAML != "" {
		sb.WriteString(spec.HTTPBlockYAML)
		if !strings.HasSuffix(spec.HTTPBlockYAML, "\n") {
			sb.WriteByte('\n')
		}
	}
	if len(spec.Hosts) > 0 {
		sb.WriteString("records:\n")
		for _, h := range spec.Hosts {
			fmt.Fprintf(&sb, "  %s: 127.0.0.1\n", h)
		}
	}
	fmt.Fprintf(&sb, "links:\n  - name: sbx0\n    principal: %s\n    subnet: %s\n    gateway_ip: %s\n    https_port: %d\n    http_port: %d\n    dns_port: %d\n",
		principal, linkSubnet, linkIP, httpsPort, httpPort, dnsPort)
	if spec.RulesYAML != "" {
		sb.WriteString("rules:\n")
		sb.WriteString(spec.RulesYAML)
		if !strings.HasSuffix(spec.RulesYAML, "\n") {
			sb.WriteByte('\n')
		}
	}
	baseYAML := sb.String()
	cfgPath := filepath.Join(dir, "gatewayd.yaml")
	if err := os.WriteFile(cfgPath, []byte(baseYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	store, err := config.NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	aw, err := audit.NewWriter(audit.Options{
		Dir:          auditDir,
		MaxFileBytes: spec.AuditMaxFileBytes,
	})
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}

	flows := proxy.NewFlowRegistry()
	col := metrics.NewCollector(metrics.Options{
		ActiveFlows:  flows.Count,
		ActiveGrants: func() int { return len(store.ActiveGrants()) },
	})
	flows.SetOnRevoke(col.AddRevocations)

	var cs *countingSigner
	leafCA := mitmCA
	if spec.CountCASigns {
		cs = &countingSigner{Signer: mitmCA.Key}
		leafCA.Key = cs
	}

	guardDialer := netguard.NewDialer(netguard.Options{
		Store:    store,
		Resolver: spec.Resolver,
		Timeout:  time.Second,
	})
	var dialFn func(ctx context.Context, network, addr string) (net.Conn, error)
	if spec.DialOverride != nil {
		dialFn = spec.DialOverride(guardDialer, upTLSPort, upPlainPort)
	} else {
		dialFn = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if portStr == "80" && upPlain != nil {
				return guardDialer.DialHost(ctx, network, host, upPlainPort)
			}
			return guardDialer.DialHost(ctx, network, host, upTLSPort)
		}
	}

	srv, err := proxy.NewServer(proxy.Options{
		Link:          store.Current().Config.Links[0],
		Store:         store,
		Evaluator:     policy.NewEvaluator(store),
		Audit:         aw,
		Leaves:        ca.NewLeafCache(leafCA),
		DialContext:   dialFn,
		UpstreamRoots: upRoots,
		Flows:         flows,
		OnRequest:     col.ObserveRequest,
	})
	if err != nil {
		t.Fatalf("proxy.NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	// Register cleanups in LIFO order so blocked upstream handlers release first,
	// then grant pruner stops, then proxy shuts down, then upstream closes, then audit closes.
	t.Cleanup(func() {
		if err := aw.Close(); err != nil {
			t.Errorf("audit close: %v", err)
		}
	})
	if upPlain != nil {
		t.Cleanup(upPlain.Close)
	}
	t.Cleanup(upTLS.Close)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("proxy.Shutdown: %v", err)
		}
	})
	if spec.StartGrantPruner {
		pruneCtx, pruneCancel := context.WithCancel(context.Background())
		pruneDone := make(chan struct{})
		go func() {
			defer close(pruneDone)
			store.RunGrantPruner(pruneCtx, 20*time.Millisecond)
		}()
		t.Cleanup(func() {
			pruneCancel()
			<-pruneDone
		})
	}
	if spec.OnCleanupFirst != nil {
		t.Cleanup(spec.OnCleanupFirst)
	}

	return &testGateway{
		Dir:       dir,
		AuditDir:  auditDir,
		CfgPath:   cfgPath,
		BaseYAML:  baseYAML,
		Store:     store,
		Audit:     aw,
		Flows:     flows,
		Metrics:   col,
		Server:    srv,
		HTTPSAddr: httpsAddr,
		HTTPAddr:  httpAddr,
		MITMRoots: mitmRoots,
		UpCA:      upCA,
		UpTLS:     upTLS,
		UpPlain:   upPlain,
		CASigns:   cs,
	}
}

func (g *testGateway) H1Client(t *testing.T, sni string) *http.Client {
	t.Helper()
	return g.makeClient(t, sni, false, 0)
}

func (g *testGateway) H2Client(t *testing.T, sni string) *http.Client {
	t.Helper()
	return g.makeClient(t, sni, true, 1)
}

func (g *testGateway) makeClient(t *testing.T, sni string, h2 bool, maxConns int) *http.Client {
	t.Helper()
	protos := new(http.Protocols)
	protos.SetHTTP1(!h2)
	protos.SetHTTP2(h2)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, g.HTTPSAddr)
		},
		TLSClientConfig: &tls.Config{
			ServerName: sni,
			RootCAs:    g.MITMRoots,
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2:  h2,
		DisableCompression: true,
		MaxConnsPerHost:    maxConns,
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

func (g *testGateway) PlainClient(t *testing.T) *http.Client {
	t.Helper()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, g.HTTPAddr)
		},
		DisableCompression: true,
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

func (g *testGateway) DialTLS(t *testing.T, sni string) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", g.HTTPSAddr, &tls.Config{
		ServerName: sni,
		RootCAs:    g.MITMRoots,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Dial %s: %v", sni, err)
	}
	return conn
}

func (g *testGateway) AuditEvents(t *testing.T) []audit.Event {
	t.Helper()
	entries, err := os.ReadDir(g.AuditDir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", g.AuditDir, err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
			names = append(names, e.Name())
		}
	}
	sort.Slice(names, func(i, j int) bool {
		return strings.TrimSuffix(names[i], ".jsonl") < strings.TrimSuffix(names[j], ".jsonl")
	})
	var out []audit.Event
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(g.AuditDir, name))
		if err != nil {
			t.Fatalf("ReadFile %s: %v", name, err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var ev audit.Event
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				t.Fatalf("unmarshal %s: %v", name, err)
			}
			out = append(out, ev)
		}
	}
	return out
}

func (g *testGateway) AssertAuditNotContains(t *testing.T, tokens ...string) {
	t.Helper()
	entries, err := os.ReadDir(g.AuditDir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", g.AuditDir, err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(g.AuditDir, e.Name()))
		if err != nil {
			t.Fatalf("read audit file %s: %v", e.Name(), err)
		}
		for _, tok := range tokens {
			if strings.Contains(string(data), tok) {
				t.Fatalf("audit log %s leaked sensitive token %q", e.Name(), tok)
			}
		}
	}
}

func writeSecretFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write secret %s: %v", name, err)
	}
	return p
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
			t.Fatalf("close freePorts listener: %v", err)
		}
	}
	return ports
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
