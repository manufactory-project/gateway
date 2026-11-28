// SPDX-License-Identifier: AGPL-3.0-only

package proxy_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/manufactory-project/gateway/internal/audit"
	gwdns "github.com/manufactory-project/gateway/internal/dns"
	"github.com/manufactory-project/gateway/internal/policy"
)

func TestDeclaredContentLengthOverCap413BeforeDial(t *testing.T) {
	var upHits atomic.Int32
	gw := newTestGateway(t, testGatewaySpec{
		Hosts:         []string{"clcap.example.com"},
		HTTPBlockYAML: "http:\n  max_request_body_bytes: 64\n",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			upHits.Add(1)
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: `
  - id: allow-clcap
    principal: worker-test
    effect: allow
    hosts: [clcap.example.com]
    ports: [443]
`,
	})

	req, err := http.NewRequest(http.MethodPost, "https://clcap.example.com/upload", strings.NewReader(strings.Repeat("x", 512)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := gw.H1Client(t, "clcap.example.com").Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	if upHits.Load() != 0 {
		t.Fatalf("oversized Content-Length reached upstream: hits=%d, want 0", upHits.Load())
	}
}

func TestAuditFailClosedOnDenyPath(t *testing.T) {
	gw := newTestGateway(t, testGatewaySpec{
		Hosts:             []string{"denyfail.example.com"},
		AuditMaxFileBytes: 120,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: `
  - id: allow-ok-only
    principal: worker-test
    effect: allow
    hosts: [denyfail.example.com]
    ports: [443]
    paths: ["/ok"]
`,
	})

	// Fill first audit segment so next write must rotate.
	respOK, err := gw.H1Client(t, "denyfail.example.com").Get("https://denyfail.example.com/ok")
	if err != nil {
		t.Fatalf("GET /ok: %v", err)
	}
	if err := respOK.Body.Close(); err != nil {
		t.Fatalf("close /ok: %v", err)
	}

	// Break the audit directory so the deny audit write fails closed.
	if err := os.RemoveAll(gw.AuditDir); err != nil {
		t.Fatalf("remove audit dir: %v", err)
	}
	if err := os.WriteFile(gw.AuditDir, []byte("blocked"), 0o600); err != nil {
		t.Fatalf("replace audit dir with file: %v", err)
	}

	respDeny, err := gw.H1Client(t, "denyfail.example.com").Get("https://denyfail.example.com/blocked")
	if err != nil {
		t.Fatalf("GET /blocked: %v", err)
	}
	if err := respDeny.Body.Close(); err != nil {
		t.Fatalf("close /blocked: %v", err)
	}
	if respDeny.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("deny path with broken audit status = %d, want 503", respDeny.StatusCode)
	}
	if gw.Audit.WriteErrors() == 0 {
		t.Fatal("expected Audit.WriteErrors() > 0 on broken audit deny path")
	}
}

func TestRevokeByPrincipalWithHostScoping(t *testing.T) {
	opened := make(chan string, 4)
	release := make(chan struct{})

	gw := newTestGateway(t, testGatewaySpec{
		OnCleanupFirst: func() { close(release) },
		Hosts:          []string{"keep.example.com", "drop.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			rc := http.NewResponseController(w)
			if _, err := io.WriteString(w, "data: open\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			opened <- r.Host
			<-release
		}),
		RulesYAML: `
  - id: allow-both
    principal: worker-test
    effect: allow
    hosts: [keep.example.com, drop.example.com]
    ports: [443]
`,
	})

	respKeep, err := gw.H1Client(t, "keep.example.com").Get("https://keep.example.com/sse")
	if err != nil {
		t.Fatalf("GET keep: %v", err)
	}
	t.Cleanup(func() {
		if cErr := respKeep.Body.Close(); cErr != nil {
			t.Logf("close keep: %v", cErr)
		}
	})
	respDrop, err := gw.H1Client(t, "drop.example.com").Get("https://drop.example.com/sse")
	if err != nil {
		t.Fatalf("GET drop: %v", err)
	}
	t.Cleanup(func() {
		if cErr := respDrop.Body.Close(); cErr != nil {
			t.Logf("close drop: %v", cErr)
		}
	})

	for i := 0; i < 2; i++ {
		select {
		case <-opened:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for SSE streams to open")
		}
	}

	if n := gw.Flows.RevokeByPrincipal("worker-test", "drop.example.com"); n != 1 {
		t.Fatalf("RevokeByPrincipal(drop) = %d, want 1", n)
	}

	dropDone := make(chan struct{})
	go func() {
		defer close(dropDone)
		if _, err := io.Copy(io.Discard, respDrop.Body); err != nil {
			return
		}
	}()
	select {
	case <-dropDone:
	case <-time.After(2 * time.Second):
		t.Fatal("drop.example.com stream was not torn down")
	}

	rem := gw.Flows.List()
	if len(rem) != 1 || rem[0].Host != "keep.example.com" {
		t.Fatalf("expected only keep.example.com to remain active, got %+v", rem)
	}
}

func TestIPLiteralHostOnPort80Refused(t *testing.T) {
	var plainHits atomic.Int32
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"plain80.example.com"},
		PlainHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			plainHits.Add(1)
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: `
  - id: allow-plain80
    principal: worker-test
    effect: allow
    hosts: [plain80.example.com]
    ports: [80]
`,
	})

	conn, err := net.DialTimeout("tcp4", gw.HTTPAddr, time.Second)
	if err != nil {
		t.Fatalf("dial HTTPAddr: %v", err)
	}
	defer func() {
		if cErr := conn.Close(); cErr != nil {
			t.Logf("close conn: %v", cErr)
		}
	}()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write raw port-80 IP-literal request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "ip-literal-host") {
		t.Fatalf("port 80 IP-literal Host got status=%d body=%q, want 403 ip-literal-host", resp.StatusCode, string(body))
	}
	if plainHits.Load() != 0 {
		t.Fatalf("IP-literal port 80 request reached upstream: hits=%d", plainHits.Load())
	}
}

func TestBearerBindingSubstitutesOnlyBearerScheme(t *testing.T) {
	secVal := "bearer_sec_" + randHex(t)
	secFile := writeSecretFile(t, t.TempDir(), "bearer.sec", secVal+"\n")

	var (
		mu       sync.Mutex
		lastAuth string
	)
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"bearer.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			lastAuth = r.Header.Get("Authorization")
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: fmt.Sprintf(`
  - id: allow-bearer
    principal: worker-test
    effect: allow
    hosts: [bearer.example.com]
    ports: [443]
    bindings:
      - name: api-bearer
        host: bearer.example.com
        header: Authorization
        scheme: bearer
        placeholder: mf_ph_bearer_tok
        secret_file: %s
`, secFile),
	})

	send := func(authHeader string) (string, int) {
		t.Helper()
		mu.Lock()
		lastAuth = ""
		mu.Unlock()
		req, err := http.NewRequest(http.MethodGet, "https://bearer.example.com/check", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Authorization", authHeader)
		resp, err := gw.H1Client(t, "bearer.example.com").Do(req)
		if err != nil {
			t.Fatalf("Do(%q): %v", authHeader, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close body: %v", err)
		}
		mu.Lock()
		got := lastAuth
		mu.Unlock()
		return got, resp.StatusCode
	}

	if got, status := send("Bearer mf_ph_bearer_tok"); status != http.StatusOK || got != "Bearer "+secVal {
		t.Fatalf("Bearer scheme got %q (status %d), want %q (200)", got, status, "Bearer "+secVal)
	}
	// The placeholder anywhere but exactly "Bearer <placeholder>" is refused, never forwarded.
	for _, bad := range []string{"Token mf_ph_bearer_tok", "mf_ph_bearer_tok", "Bearer x mf_ph_bearer_tok"} {
		if got, status := send(bad); status != http.StatusForbidden || got != "" {
			t.Fatalf("%q: status %d upstream saw %q, want 403 and nothing forwarded", bad, status, got)
		}
	}
	var refused int
	for _, ev := range gw.AuditEvents(t) {
		if ev.Reason == "placeholder-misplaced" && ev.Status == http.StatusForbidden && len(ev.Secrets) == 1 && ev.Secrets[0] == "api-bearer" {
			refused++
		}
	}
	if refused != 3 {
		t.Fatalf("audited %d placeholder-misplaced refusals, want 3", refused)
	}
}

func appendHPACKLiteralNewName(buf *bytes.Buffer, name, val string) {
	buf.WriteByte(0x00)
	buf.WriteByte(byte(len(name)))
	buf.WriteString(name)
	buf.WriteByte(byte(len(val)))
	buf.WriteString(val)
}

func writeH2Frame(w io.Writer, frameType, flags byte, streamID uint32, payload []byte) error {
	var hdr [9]byte
	n := len(payload)
	hdr[0] = byte(n >> 16)
	hdr[1] = byte(n >> 8)
	hdr[2] = byte(n)
	hdr[3] = frameType
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:9], streamID&0x7fffffff)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func TestHTTP2ExplicitHostHeaderRejected(t *testing.T) {
	var upHits atomic.Int32
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"h2host.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			upHits.Add(1)
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: `
  - id: allow-h2host
    principal: worker-test
    effect: allow
    hosts: [h2host.example.com]
    ports: [443]
`,
	})

	conn, err := tls.Dial("tcp4", gw.HTTPSAddr, &tls.Config{
		ServerName: "h2host.example.com",
		RootCAs:    gw.MITMRoots,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
	})
	if err != nil {
		t.Fatalf("tls.Dial h2: %v", err)
	}
	defer func() {
		if cErr := conn.Close(); cErr != nil {
			t.Logf("close h2 conn: %v", cErr)
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	// Send HTTP/2 client preface + empty SETTINGS frame.
	if _, err := io.WriteString(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"); err != nil {
		t.Fatalf("write h2 preface: %v", err)
	}
	if err := writeH2Frame(conn, 0x4, 0x0, 0, nil); err != nil {
		t.Fatalf("write client SETTINGS: %v", err)
	}

	// Build HPACK block with :method=GET, :scheme=https, :path=/, :authority=h2host.example.com, AND explicit host header.
	var hpack bytes.Buffer
	hpack.WriteByte(0x82) // :method GET
	hpack.WriteByte(0x87) // :scheme https
	hpack.WriteByte(0x84) // :path /
	appendHPACKLiteralNewName(&hpack, ":authority", "h2host.example.com")
	appendHPACKLiteralNewName(&hpack, "host", "h2host.example.com")

	// Send HEADERS frame (type 0x1, flags END_STREAM|END_HEADERS = 0x5, stream 1).
	if err := writeH2Frame(conn, 0x1, 0x5, 1, hpack.Bytes()); err != nil {
		t.Fatalf("write HEADERS: %v", err)
	}

	// Wait for gateway to write the audited 403 h2-host-header event.
	var sawH2HostDeny bool
	gw.Records.until(2*time.Second, func() bool {
		for _, ev := range gw.AuditEvents(t) {
			if ev.Kind == audit.KindRequest && ev.Host == "h2host.example.com" && ev.Status == http.StatusForbidden && ev.Reason == "h2-host-header" {
				sawH2HostDeny = true
				break
			}
		}
		return sawH2HostDeny
	})
	if !sawH2HostDeny {
		t.Fatal("missing audited 403 h2-host-header for HTTP/2 request with explicit Host header")
	}
	if upHits.Load() != 0 {
		t.Fatalf("HTTP/2 explicit Host header request reached upstream: hits=%d", upHits.Load())
	}
}

func TestEscapedPathSeparatorsCannotEvadeDenyPolicy(t *testing.T) {
	var upHits atomic.Int32
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"sep.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			upHits.Add(1)
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: `
  - id: allow-all
    principal: worker-test
    effect: allow
    hosts: [sep.example.com]
    ports: [443]
    paths: ["/**"]
  - id: deny-admin
    principal: worker-test
    effect: deny
    hosts: [sep.example.com]
    ports: [443]
    paths: ["/admin/**"]
`,
	})

	for _, rawPath := range []string{"/admin%2fsecret", "/admin%5csecret", "/public%2f..%2fadmin"} {
		conn := gw.DialTLS(t, "sep.example.com")
		if _, err := io.WriteString(conn, "GET "+rawPath+" HTTP/1.1\r\nHost: sep.example.com\r\nConnection: close\r\n\r\n"); err != nil {
			t.Fatalf("write %s: %v", rawPath, err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("ReadResponse %s: %v", rawPath, err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body %s: %v", rawPath, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close body %s: %v", rawPath, err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("close conn %s: %v", rawPath, err)
		}
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "escaped-path-separator") {
			t.Fatalf("path %s got status=%d body=%q, want 403 escaped-path-separator", rawPath, resp.StatusCode, string(body))
		}
	}
	if upHits.Load() != 0 {
		t.Fatalf("escaped-path-separator requests reached upstream: hits=%d", upHits.Load())
	}
}

func TestWebSocketDefaultEgressCapAppliesWhenRuleOmitsCap(t *testing.T) {
	gw := newTestGateway(t, testGatewaySpec{
		Hosts:         []string{"wsdefcap.example.com"},
		HTTPBlockYAML: "http:\n  ws_max_egress_bytes: 512\n",
		Handler:       http.HandlerFunc(wsEchoHandler),
		RulesYAML: `
  - id: allow-ws-default-cap
    principal: worker-test
    effect: allow
    hosts: [wsdefcap.example.com]
    ports: [443]
    allow_websocket: true
`,
	})

	conn := gw.DialTLS(t, "wsdefcap.example.com")
	defer func() {
		if cErr := conn.Close(); cErr != nil {
			t.Logf("close ws conn: %v", cErr)
		}
	}()
	if _, err := io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: wsdefcap.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"); err != nil {
		t.Fatalf("write WS upgrade: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse 101: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	// Send more than the 512-byte default cap; connection must close (EOF/err, NOT timeout).
	payload := bytes.Repeat([]byte("A"), 4096)
	if _, wErr := conn.Write(payload); wErr != nil {
		// Write itself may fail once gateway closes the socket mid-write.
		t.Logf("write hit expected close: %v", wErr)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 4096)
	for {
		_, rErr := br.Read(buf)
		if rErr != nil {
			if ne, ok := rErr.(net.Error); ok && ne.Timeout() {
				t.Fatal("WebSocket stayed open (timed out) instead of closing on default egress cap")
			}
			break
		}
	}

	var sawCapAudit bool
	gw.Records.until(2*time.Second, func() bool {
		for _, ev := range gw.AuditEvents(t) {
			if ev.Kind == audit.KindWebSocket && ev.Host == "wsdefcap.example.com" && strings.Contains(ev.Error, "ws-egress-cap-exceeded") {
				sawCapAudit = true
				break
			}
		}
		return sawCapAudit
	})
	if !sawCapAudit {
		rec := httptest.NewRecorder()
		gw.Metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		t.Fatalf("missing ws-egress-cap-exceeded audit record for default WS egress cap (metrics:\n%s)", rec.Body.String())
	}
}

// A deny with no ports covers port 80 as well as 443: the zone is allowed on both,
// one name in it is denied, and neither DNS nor either port reaches it.
func TestDenyWithoutPortsRefusesDNSAndBothPortsEndToEnd(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, "allowed-ok"); err != nil {
			return
		}
	})
	gw := newTestGateway(t, testGatewaySpec{
		Hosts:        []string{"good.example.com", "evil.example.com"},
		Handler:      handler,
		PlainHandler: handler,
		RulesYAML: `
  - id: allow-zone
    principal: worker-test
    effect: allow
    hosts: ["*.example.com"]
    ports: [80, 443]
  - id: deny-evil
    principal: worker-test
    effect: deny
    hosts: [evil.example.com]
`,
	})

	link := gw.Store.Current().Config.Links[0]
	alloc, err := gwdns.NewAllocator(netip.MustParsePrefix("198.18.0.0/15"))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	dnsSrv, err := gwdns.NewServer(gwdns.ServerOptions{
		Link:         link,
		Store:        gw.Store,
		Evaluator:    policy.NewEvaluator(gw.Store),
		Audit:        gw.Audit,
		Allocator:    alloc,
		OnServeError: func(error) {},
	})
	if err != nil {
		t.Fatalf("dns.NewServer: %v", err)
	}
	if err := dnsSrv.Start(); err != nil {
		t.Fatalf("dns.Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := dnsSrv.Shutdown(ctx); err != nil {
			t.Errorf("dns.Shutdown: %v", err)
		}
	})
	dnsAddr := net.JoinHostPort(link.ParsedGatewayIP.String(), strconv.Itoa(int(link.DNSPort)))
	query := func(name string) *mdns.Msg {
		q := new(mdns.Msg)
		q.SetQuestion(name+".", mdns.TypeA)
		ans, _, qErr := (&mdns.Client{Net: "udp", Timeout: 2 * time.Second}).Exchange(q, dnsAddr)
		if qErr != nil {
			t.Fatalf("DNS %s: %v", name, qErr)
		}
		return ans
	}
	get := func(client *http.Client, url string) (int, string) {
		resp, gErr := client.Get(url)
		if gErr != nil {
			return 0, gErr.Error()
		}
		body, rErr := io.ReadAll(resp.Body)
		if cErr := resp.Body.Close(); cErr != nil || rErr != nil {
			t.Fatalf("read %s: %v %v", url, rErr, cErr)
		}
		return resp.StatusCode, string(body)
	}

	// Positive control: the rest of the zone resolves and is served on both ports.
	if ans := query("good.example.com"); ans.Rcode != mdns.RcodeSuccess || len(ans.Answer) != 1 {
		t.Fatalf("DNS good.example.com = %+v, want NOERROR with 1 A record", ans)
	}
	if code, body := get(gw.H1Client(t, "good.example.com"), "https://good.example.com/"); code != http.StatusOK || body != "allowed-ok" {
		t.Fatalf("https good.example.com = %d %q, want 200 allowed-ok", code, body)
	}
	if code, body := get(gw.PlainClient(t), "http://good.example.com/"); code != http.StatusOK || body != "allowed-ok" {
		t.Fatalf("http good.example.com = %d %q, want 200 allowed-ok", code, body)
	}

	// Containment: the denied name is refused at DNS and on port 80 and 443.
	if ans := query("evil.example.com"); ans.Rcode != mdns.RcodeRefused {
		t.Fatalf("DNS evil.example.com = %+v, want REFUSED", ans)
	}
	if code, body := get(gw.PlainClient(t), "http://evil.example.com/"); code != http.StatusForbidden || !strings.Contains(body, "rule-deny") {
		t.Fatalf("http evil.example.com = %d %q, want 403 rule-deny", code, body)
	}
	if code, body := get(gw.H1Client(t, "evil.example.com"), "https://evil.example.com/"); code != 0 {
		t.Fatalf("https evil.example.com = %d %q, want a failed TLS handshake", code, body)
	}
	denied := map[int]bool{}
	for _, ev := range gw.AuditEvents(t) {
		if ev.Host == "evil.example.com" && ev.Effect == audit.EffectDeny && ev.RuleID == "deny-evil" {
			denied[ev.Port] = true
		}
	}
	if !denied[80] || !denied[443] {
		t.Fatalf("audit lacks deny-evil refusals on both ports: %v", denied)
	}
}

func TestSharedFakeIPDoesNotBreakProxying(t *testing.T) {
	// /30 has only 2 usable host IPs (.1 and .2); among 3 names, at least 2 deterministically collide.
	prefix := netip.MustParsePrefix("198.18.0.0/30")
	alloc, err := gwdns.NewAllocator(prefix)
	if err != nil {
		t.Fatalf("NewAllocator(/30): %v", err)
	}
	candidates := []string{"a.collide.example", "b.collide.example", "c.collide.example"}
	byIP := make(map[netip.Addr]string)
	var hostA, hostB string
	var sharedIP netip.Addr
	for _, h := range candidates {
		ip := alloc.Allocate(h)
		if ip == netip.MustParseAddr("198.18.0.0") || ip == netip.MustParseAddr("198.18.0.3") || !prefix.Contains(ip) {
			t.Fatalf("Allocate(%s) = %s, outside usable /30 range", h, ip)
		}
		if again := alloc.Allocate(strings.ToUpper(h) + "."); again != ip {
			t.Fatalf("Allocate not stable for %s: %s != %s", h, again, ip)
		}
		if prev, ok := byIP[ip]; ok {
			hostA, hostB, sharedIP = prev, h, ip
			break
		}
		byIP[ip] = h
	}
	if hostA == "" || hostB == "" {
		t.Fatal("pigeonhole invariant violated: 3 names in /30 produced no shared IP")
	}

	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{hostA, hostB},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "host="+r.Host); err != nil {
				return
			}
		}),
		RulesYAML: fmt.Sprintf(`
  - id: allow-colliding
    principal: worker-test
    effect: allow
    hosts: [%s, %s]
    ports: [443]
`, hostA, hostB),
	})

	link := gw.Store.Current().Config.Links[0]
	dnsSrv, err := gwdns.NewServer(gwdns.ServerOptions{
		Link:         link,
		Store:        gw.Store,
		Evaluator:    policy.NewEvaluator(gw.Store),
		Audit:        gw.Audit,
		Allocator:    alloc,
		OnServeError: func(error) {},
	})
	if err != nil {
		t.Fatalf("dns.NewServer: %v", err)
	}
	if err := dnsSrv.Start(); err != nil {
		t.Fatalf("dns.Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := dnsSrv.Shutdown(ctx); err != nil {
			t.Errorf("dns.Shutdown: %v", err)
		}
	})
	dnsAddr := net.JoinHostPort(link.ParsedGatewayIP.String(), strconv.Itoa(int(link.DNSPort)))
	for _, h := range []string{hostA, hostB} {
		q := new(mdns.Msg)
		q.SetQuestion(mdns.Fqdn(h), mdns.TypeA)
		ans, _, qErr := (&mdns.Client{Net: "udp", Timeout: 2 * time.Second}).Exchange(q, dnsAddr)
		if qErr != nil || ans.Rcode != mdns.RcodeSuccess || len(ans.Answer) != 1 {
			t.Fatalf("DNS %s failed: ans=%+v err=%v", h, ans, qErr)
		}
		aRec, ok := ans.Answer[0].(*mdns.A)
		if !ok || aRec.A.String() != sharedIP.String() {
			t.Fatalf("DNS %s returned %v, want shared IP %s", h, ans.Answer[0], sharedIP)
		}

		resp, rErr := gw.H1Client(t, h).Get("https://" + h + "/check")
		if rErr != nil {
			t.Fatalf("GET %s: %v", h, rErr)
		}
		body, bErr := io.ReadAll(resp.Body)
		if cErr := resp.Body.Close(); cErr != nil {
			t.Fatalf("close %s: %v", h, cErr)
		}
		if bErr != nil || resp.StatusCode != http.StatusOK || string(body) != "host="+h {
			t.Fatalf("GET %s got status=%d body=%q err=%v, want 200 host=%s", h, resp.StatusCode, string(body), bErr, h)
		}
	}
}
