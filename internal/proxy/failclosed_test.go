package proxy_test

import (
	"context"
	"crypto/tls"
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
	"testing"

	"github.com/manufactory-project/gateway/internal/ca"
	"github.com/manufactory-project/gateway/internal/netguard"
)

func TestUntrustedUpstreamCertRefused(t *testing.T) {
	badDir := t.TempDir()
	badCA, err := ca.Init(filepath.Join(badDir, "bad-ca.crt"), filepath.Join(badDir, "bad-ca.key"))
	if err != nil {
		t.Fatalf("ca.Init bad: %v", err)
	}
	var untrustedReceived atomic.Int32
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
	untrustedPort := tcpPort(t, untrustedSrv.Listener.Addr())

	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"untrusted.example.com"},
		DialOverride: func(guard *netguard.Dialer, _, _ uint16) func(ctx context.Context, network, addr string) (net.Conn, error) {
			return func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				return guard.DialHost(ctx, network, host, untrustedPort)
			}
		},
		RulesYAML: `
  - id: allow-untrusted
    principal: worker-test
    effect: allow
    hosts: [untrusted.example.com]
    ports: [443]
`,
	})

	resp, err := gw.H1Client(t, "untrusted.example.com").Get("https://untrusted.example.com/")
	if err != nil {
		t.Fatalf("request to untrusted.example.com: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close untrusted body: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("untrusted upstream status = %d, want 502", resp.StatusCode)
	}
	if untrustedReceived.Load() != 0 {
		t.Fatalf("untrusted upstream received %d requests, want 0", untrustedReceived.Load())
	}
}

func TestBoundHostMissingSecretFailsClosedRedaction(t *testing.T) {
	missingSecFile := filepath.Join(t.TempDir(), "missing.sec")
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"broken.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "would-leak-if-fail-open"); err != nil {
				return
			}
		}),
		RulesYAML: fmt.Sprintf(`
  - id: allow-broken
    principal: worker-test
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
`, missingSecFile),
	})

	rBroken, err := gw.H1Client(t, "broken.example.com").Get("https://broken.example.com/unscrubbed")
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

	var sawRedactErr bool
	for _, ev := range gw.AuditEvents(t) {
		if ev.Error == "redaction-secret-unresolved" && ev.Status == http.StatusBadGateway {
			sawRedactErr = true
		}
	}
	if !sawRedactErr {
		t.Fatal("missing audit record for redaction-secret-unresolved")
	}
}

func TestBoundHostContentEncodingMultiTokenAndMultiHeader(t *testing.T) {
	goodSec := "good_" + randHex(t)
	goodSecFile := writeSecretFile(t, t.TempDir(), "good.sec", goodSec+"\n")

	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"good.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
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
			default:
				w.WriteHeader(http.StatusOK)
			}
		}),
		RulesYAML: fmt.Sprintf(`
  - id: allow-good
    principal: worker-test
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
`, goodSecFile),
	})

	cGood := gw.H1Client(t, "good.example.com")
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
}

func TestAuditSinkFailureReturns503NoUpstreamDial(t *testing.T) {
	var httpsHits atomic.Int32
	gw := newTestGateway(t, testGatewaySpec{
		AuditMaxFileBytes: 512,
		Hosts:             []string{"auditfail.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			httpsHits.Add(1)
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: `
  - id: allow-auditfail
    principal: worker-test
    effect: allow
    hosts: [auditfail.example.com]
    ports: [443]
`,
	})

	c := gw.H2Client(t, "auditfail.example.com")
	if err := os.RemoveAll(gw.AuditDir); err != nil {
		t.Fatalf("remove auditDir: %v", err)
	}
	if err := os.WriteFile(gw.AuditDir, []byte("blocked"), 0o600); err != nil {
		t.Fatalf("replace auditDir with file: %v", err)
	}

	var got503 bool
	for i := 0; i < 6; i++ {
		r, err := c.Get("https://auditfail.example.com/ok")
		if err != nil {
			t.Fatalf("audit-fail request %d: %v", i, err)
		}
		if cErr := r.Body.Close(); cErr != nil {
			t.Fatalf("close r: %v", cErr)
		}
		if r.StatusCode == http.StatusServiceUnavailable {
			got503 = true
			hitsBefore := httpsHits.Load()
			r2, err := c.Get("https://auditfail.example.com/ok")
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

func TestDNSRebindingBlockedThroughProxy(t *testing.T) {
	var rebindHits atomic.Int32
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

	rebindRes := &stepResolver{
		answers: map[string][][]netip.Addr{
			"rebind.example.com": {
				{netip.MustParseAddr("127.0.0.1")},
				{netip.MustParseAddr("::ffff:127.0.0.1")},
			},
		},
		calls: make(map[string]int),
	}

	gw := newTestGateway(t, testGatewaySpec{
		Resolver: rebindRes,
		DialOverride: func(guard *netguard.Dialer, _, _ uint16) func(ctx context.Context, network, addr string) (net.Conn, error) {
			return func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				return guard.DialHost(ctx, network, host, rebindPort)
			}
		},
		RulesYAML: `
  - id: allow-rebind
    principal: worker-test
    effect: allow
    hosts: [rebind.example.com]
    ports: [443]
`,
	})

	cRebind := gw.H2Client(t, "rebind.example.com")
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
}
