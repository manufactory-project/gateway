package proxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/ca"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/netguard"
	"github.com/manufactory-project/gateway/internal/policy"
	"github.com/manufactory-project/gateway/internal/proxy"
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

func TestClientCanceled499AndUpstreamFailure502(t *testing.T) {
	t.Run("client_canceled_records_499_not_5xx", func(t *testing.T) {
		upStarted := make(chan struct{})
		releaseUp := make(chan struct{})
		t.Cleanup(func() { close(releaseUp) })

		gw := newTestGateway(t, testGatewaySpec{
			Hosts: []string{"cancel.example.com"},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/slow-cancel" {
					close(upStarted)
					select {
					case <-r.Context().Done():
					case <-releaseUp:
					}
					return
				}
				w.WriteHeader(http.StatusOK)
			}),
			RulesYAML: `
  - id: allow-cancel
    principal: worker-test
    effect: allow
    hosts: [cancel.example.com]
    ports: [443]
`,
		})

		reqCtx, reqCancel := context.WithCancel(context.Background())
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://cancel.example.com/slow-cancel", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		client := gw.H1Client(t, "cancel.example.com")
		reqDone := make(chan error, 1)
		go func() {
			resp, rErr := client.Do(req)
			if resp != nil {
				if cErr := resp.Body.Close(); cErr != nil {
					t.Errorf("close resp: %v", cErr)
				}
			}
			reqDone <- rErr
		}()

		<-upStarted
		reqCancel()
		if rErr := <-reqDone; rErr == nil {
			t.Fatal("expected canceled client request to return error")
		}

		var gotEvent *audit.Event
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			for _, ev := range gw.AuditEvents(t) {
				if ev.Kind == audit.KindRequest && ev.Path == "/slow-cancel" {
					e := ev
					gotEvent = &e
					break
				}
			}
			if gotEvent != nil {
				break
			}
			time.Sleep(15 * time.Millisecond)
		}
		if gotEvent == nil {
			t.Fatal("missing completed audit event for /slow-cancel")
		}
		if gotEvent.Status != 499 || gotEvent.Error != "client-canceled" {
			t.Fatalf("audit event status=%d error=%q, want status=499 error=%q", gotEvent.Status, gotEvent.Error, "client-canceled")
		}

		rec := httptest.NewRecorder()
		gw.Metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		mText := rec.Body.String()
		if !strings.Contains(mText, `gateway_requests_total{effect="allow",principal="worker-test",status="499"} 1`) {
			t.Fatalf("metrics missing status=499 counter:\n%s", mText)
		}
		if strings.Contains(mText, `status="502"`) {
			t.Fatalf("metrics unexpectedly counted client-canceled request as 502:\n%s", mText)
		}
	})

	t.Run("upstream_failure_stays_502_and_revoke_is_not_499", func(t *testing.T) {
		revokeStarted := make(chan struct{})
		releaseRevoke := make(chan struct{})
		t.Cleanup(func() { close(releaseRevoke) })

		gw := newTestGateway(t, testGatewaySpec{
			Hosts: []string{"fail.example.com"},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/drop-upstream":
					panic(http.ErrAbortHandler)
				case "/slow-revoke":
					close(revokeStarted)
					select {
					case <-r.Context().Done():
					case <-releaseRevoke:
					}
				default:
					w.WriteHeader(http.StatusOK)
				}
			}),
			RulesYAML: `
  - id: allow-fail
    principal: worker-test
    effect: allow
    hosts: [fail.example.com]
    ports: [443]
`,
		})

		client := gw.H1Client(t, "fail.example.com")
		resp, err := client.Get("https://fail.example.com/drop-upstream")
		if err != nil {
			t.Fatalf("GET /drop-upstream: %v", err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close resp: %v", err)
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("upstream failure status = %d, want 502", resp.StatusCode)
		}

		// Also verify gateway-initiated revoke teardown does NOT record 499.
		revDone := make(chan error, 1)
		go func() {
			r2, rErr := gw.H1Client(t, "fail.example.com").Get("https://fail.example.com/slow-revoke")
			if r2 != nil {
				if cErr := r2.Body.Close(); cErr != nil {
					t.Errorf("close r2: %v", cErr)
				}
			}
			revDone <- rErr
		}()
		<-revokeStarted
		if n := gw.Flows.RevokeByPrincipal("worker-test", ""); n == 0 {
			t.Fatal("expected RevokeByPrincipal to tear down /slow-revoke flow")
		}
		<-revDone

		var dropEv, revEv *audit.Event
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			for _, ev := range gw.AuditEvents(t) {
				if ev.Kind == audit.KindRequest && ev.Path == "/drop-upstream" {
					e := ev
					dropEv = &e
				}
				if ev.Kind == audit.KindRequest && ev.Path == "/slow-revoke" {
					e := ev
					revEv = &e
				}
			}
			if dropEv != nil && revEv != nil {
				break
			}
			time.Sleep(15 * time.Millisecond)
		}
		if dropEv == nil || dropEv.Status != http.StatusBadGateway || dropEv.Error == "client-canceled" {
			t.Fatalf("unexpected /drop-upstream audit event: %+v", dropEv)
		}
		if revEv == nil || revEv.Status != http.StatusBadGateway || revEv.Error == "client-canceled" {
			t.Fatalf("revoked flow must not be logged as 499/client-canceled, got: %+v", revEv)
		}

		rec := httptest.NewRecorder()
		gw.Metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		mText := rec.Body.String()
		if !strings.Contains(mText, `gateway_requests_total{effect="allow",principal="worker-test",status="502"} 2`) {
			t.Fatalf("metrics missing status=502 count 2:\n%s", mText)
		}
		if strings.Contains(mText, `status="499"`) {
			t.Fatalf("metrics unexpectedly recorded status=499:\n%s", mText)
		}
	})
}

func TestTruncatedUpstreamResponseAbortsGuestH1AndH2(t *testing.T) {
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"trunc.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			rc := http.NewResponseController(w)
			if _, err := io.WriteString(w, "partial-chunk-before-abort"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			panic(http.ErrAbortHandler)
		}),
		RulesYAML: `
  - id: allow-trunc
    principal: worker-test
    effect: allow
    hosts: [trunc.example.com]
    ports: [443]
`,
	})

	for _, tc := range []struct {
		name   string
		path   string
		client *http.Client
	}{
		{name: "H1", path: "/trunc-h1", client: gw.H1Client(t, "trunc.example.com")},
		{name: "H2", path: "/trunc-h2", client: gw.H2Client(t, "trunc.example.com")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tc.client.Get("https://trunc.example.com" + tc.path)
			if err != nil {
				t.Fatalf("%s GET failed before headers: %v", tc.name, err)
			}
			body, readErr := io.ReadAll(resp.Body)
			if cErr := resp.Body.Close(); cErr != nil {
				t.Logf("%s close body: %v", tc.name, cErr)
			}
			if readErr == nil {
				t.Fatalf("%s guest read succeeded cleanly (%q) despite truncated upstream response", tc.name, string(body))
			}

			var found *audit.Event
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				for _, ev := range gw.AuditEvents(t) {
					if ev.Kind == audit.KindRequest && ev.Path == tc.path {
						e := ev
						found = &e
					}
				}
				if found != nil {
					break
				}
				time.Sleep(15 * time.Millisecond)
			}
			if found == nil || found.Error == "" {
				t.Fatalf("%s missing completion audit with error: %+v", tc.name, found)
			}
		})
	}
}

func TestMaxConnsPerLinkCapAndMetric(t *testing.T) {
	gw := newTestGateway(t, testGatewaySpec{
		Hosts:         []string{"cap.example.com"},
		HTTPBlockYAML: "http:\n  max_conns_per_link: 2\n",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: `
  - id: allow-cap
    principal: worker-test
    effect: allow
    hosts: [cap.example.com]
    ports: [443]
`,
	})

	// Hold 2 raw TCP connections (1 HTTPS + 1 HTTP) to saturate the shared per-link cap=2.
	c1, err := net.DialTimeout("tcp4", gw.HTTPSAddr, time.Second)
	if err != nil {
		t.Fatalf("dial c1: %v", err)
	}
	c2, err := net.DialTimeout("tcp4", gw.HTTPAddr, time.Second)
	if err != nil {
		if cErr := c1.Close(); cErr != nil {
			t.Logf("close c1: %v", cErr)
		}
		t.Fatalf("dial c2: %v", err)
	}
	// Give listener goroutines a moment to accept both slots.
	time.Sleep(40 * time.Millisecond)

	// Connection N+1 (3rd) must be closed immediately and counted in gateway_conns_rejected_total.
	c3, err := net.DialTimeout("tcp4", gw.HTTPSAddr, time.Second)
	if err == nil {
		if dErr := c3.SetReadDeadline(time.Now().Add(time.Second)); dErr != nil {
			t.Fatalf("set c3 deadline: %v", dErr)
		}
		var one [1]byte
		if _, rErr := c3.Read(one[:]); rErr == nil {
			t.Fatal("expected 3rd connection beyond cap to be closed, read succeeded")
		} else if ne, ok := rErr.(net.Error); ok && ne.Timeout() {
			t.Fatal("3rd connection beyond cap stayed open instead of closing immediately")
		}
		if cErr := c3.Close(); cErr != nil {
			t.Logf("close c3: %v", cErr)
		}
	}

	// Verify metric incremented for link sbx0.
	deadline := time.Now().Add(time.Second)
	sawMetric := false
	for time.Now().Before(deadline) {
		rec := httptest.NewRecorder()
		gw.Metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if strings.Contains(rec.Body.String(), `gateway_conns_rejected_total{link="sbx0"} 1`) {
			sawMetric = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !sawMetric {
		rec := httptest.NewRecorder()
		gw.Metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		t.Fatalf("missing gateway_conns_rejected_total{link=\"sbx0\"} 1 in metrics:\n%s", rec.Body.String())
	}

	// Release held connections and confirm requests under the cap succeed.
	if err := c1.Close(); err != nil {
		t.Fatalf("close c1: %v", err)
	}
	if err := c2.Close(); err != nil {
		t.Fatalf("close c2: %v", err)
	}
	time.Sleep(40 * time.Millisecond)
	resp, err := gw.H1Client(t, "cap.example.com").Get("https://cap.example.com/ok")
	if err != nil {
		t.Fatalf("GET under cap failed: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close resp: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET under cap status = %d, want 200", resp.StatusCode)
	}
}

func TestUpstreamResponseHeaderTimeoutAudits502(t *testing.T) {
	release := make(chan struct{})
	gw := newTestGateway(t, testGatewaySpec{
		OnCleanupFirst: func() { close(release) },
		Hosts:          []string{"slowhdr.example.com"},
		HTTPBlockYAML:  "http:\n  upstream_response_header_timeout: 80ms\n",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-release:
			}
		}),
		RulesYAML: `
  - id: allow-slowhdr
    principal: worker-test
    effect: allow
    hosts: [slowhdr.example.com]
    ports: [443]
`,
	})

	resp, err := gw.H1Client(t, "slowhdr.example.com").Get("https://slowhdr.example.com/stall")
	if err != nil {
		t.Fatalf("GET /stall: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close resp: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}

	var saw502 bool
	for _, ev := range gw.AuditEvents(t) {
		if ev.Kind == audit.KindRequest && ev.Path == "/stall" && ev.Status == http.StatusBadGateway && ev.Error != "" {
			saw502 = true
		}
	}
	if !saw502 {
		t.Fatal("missing audited 502 for upstream_response_header_timeout")
	}
}

type countingStaticResolver struct {
	hosts map[string][]netip.Addr
	hits  atomic.Int32
}

func (r *countingStaticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.hits.Add(1)
	return r.hosts[host], nil
}

func TestProductionDialPathBlocksDeniedAddresses(t *testing.T) {
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	mitmCert := filepath.Join(dir, "ca.crt")
	mitmKey := filepath.Join(dir, "ca.key")
	mitmCA, err := ca.Init(mitmCert, mitmKey)
	if err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	mitmRoots := x509.NewCertPool()
	if !mitmRoots.AppendCertsFromPEM(mitmCA.CertPEM) {
		t.Fatal("append MITM CA")
	}

	idx := nextTestLinkIndex.Add(1) - 1
	b2 := 1 + (idx/254)%254
	b3 := 1 + (idx % 254)
	linkIP := fmt.Sprintf("127.%d.%d.1", b2, b3)
	linkSubnet := fmt.Sprintf("127.%d.%d.0/28", b2, b3)
	ports := freePorts(t, linkIP, 3)
	httpsAddr := fmt.Sprintf("%s:%d", linkIP, ports[0])

	cfgYAML := fmt.Sprintf(`
ca:
  cert_path: %s
  key_path: %s
audit:
  dir: %s
links:
  - name: sbx0
    principal: worker-test
    subnet: %s
    gateway_ip: %s
    https_port: %d
    http_port: %d
    dns_port: %d
rules:
  - id: allow-ssrf-targets
    principal: worker-test
    effect: allow
    hosts: [loop.ssrf.test, meta.ssrf.test, rfc1918.ssrf.test]
    ports: [443]
`, mitmCert, mitmKey, auditDir, linkSubnet, linkIP, ports[0], ports[1], ports[2])
	cfgPath := filepath.Join(dir, "gateway.yaml")
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

	resolver := &countingStaticResolver{
		hosts: map[string][]netip.Addr{
			"loop.ssrf.test":    {netip.MustParseAddr("127.0.0.1")},
			"meta.ssrf.test":    {netip.MustParseAddr("169.254.169.254")},
			"rfc1918.ssrf.test": {netip.MustParseAddr("10.0.0.1")},
		},
	}
	// Production wiring: Dialer set, DialContext unset (nil).
	srv, err := proxy.NewServer(proxy.Options{
		Link:      store.Current().Config.Links[0],
		Store:     store,
		Evaluator: policy.NewEvaluator(store),
		Audit:     aw,
		Leaves:    ca.NewLeafCache(mitmCA),
		Dialer: netguard.NewDialer(netguard.Options{
			Store:    store,
			Resolver: resolver,
			Timeout:  time.Second,
		}),
		Flows: proxy.NewFlowRegistry(),
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

	for _, host := range []string{"loop.ssrf.test", "meta.ssrf.test", "rfc1918.ssrf.test"} {
		tr := &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, httpsAddr)
			},
			TLSClientConfig: &tls.Config{
				ServerName: host,
				RootCAs:    mitmRoots,
				MinVersion: tls.VersionTLS12,
			},
		}
		t.Cleanup(tr.CloseIdleConnections)
		resp, err := (&http.Client{Transport: tr}).Get("https://" + host + "/probe")
		if err != nil {
			t.Fatalf("GET %s: %v", host, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close %s: %v", host, err)
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("GET %s status = %d, want 502", host, resp.StatusCode)
		}
	}

	if resolver.hits.Load() != 3 {
		t.Fatalf("netguard resolver hits = %d, want 3 (production Dialer was bypassed)", resolver.hits.Load())
	}

	// Confirm every denied dial was audited as 502 with netguard.ErrBlockedAddress.
	gwTmp := &testGateway{AuditDir: auditDir}
	var blockedAudits int
	for _, ev := range gwTmp.AuditEvents(t) {
		if ev.Kind == audit.KindRequest && ev.Status == http.StatusBadGateway && strings.Contains(ev.Error, netguard.ErrBlockedAddress.Error()) {
			blockedAudits++
		}
	}
	if blockedAudits != 3 {
		t.Fatalf("audited SSRF-blocked 502 events = %d, want 3", blockedAudits)
	}
}
