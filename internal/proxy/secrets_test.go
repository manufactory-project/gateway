package proxy_test

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestBoundSecretSubstitutionUnboundSweepAndCorruptSecretFailClosed(t *testing.T) {
	secDir := t.TempDir()
	secForge := "s3cr3t_" + randHex(t) + "/&\"<>"
	secFile := writeSecretFile(t, secDir, "forge.secret", secForge+"\n")
	badSecFile := writeSecretFile(t, secDir, "bad.secret", "bad\nline2")

	var (
		upReceived      atomic.Int32
		seenHeadersMu   sync.Mutex
		lastSeenHeaders http.Header
	)

	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"code.lan.example", "badsec.lan.example", "unbound.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upReceived.Add(1)
			seenHeadersMu.Lock()
			lastSeenHeaders = r.Header.Clone()
			seenHeadersMu.Unlock()
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: fmt.Sprintf(`
  - id: allow-forge
    principal: worker-test
    effect: allow
    hosts: [code.lan.example]
    ports: [443]
    bindings:
      - name: forge-basic
        host: code.lan.example
        header: Authorization
        scheme: basic
        placeholder: mf_ph_forge
        secret_file: %s
  - id: allow-badsec
    principal: worker-test
    effect: allow
    hosts: [badsec.lan.example]
    ports: [443]
    bindings:
      - name: forge-bad
        host: badsec.lan.example
        header: X-Bad-Token
        scheme: raw
        placeholder: mf_ph_bad
        secret_file: %s
  - id: allow-unbound
    principal: worker-test
    effect: allow
    hosts: [unbound.example.com]
    ports: [443]
`, secFile, badSecFile),
	})

	// 1. Bound host substitutes Basic Auth, forces Accept-Encoding: identity, and strips unbound placeholders + Proxy-Authorization.
	req, err := http.NewRequest(http.MethodGet, "https://code.lan.example/ok", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("git:mf_ph_forge")))
	req.Header.Set("X-Unbound-Ph", "mf_ph_other")
	req.Header.Set("Proxy-Authorization", "Bearer leak")
	req.Header.Set("Accept-Encoding", "gzip, br")

	resp, err := gw.H1Client(t, "code.lan.example").Do(req)
	if err != nil {
		t.Fatalf("Do bound: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close bound body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bound status = %d, want 200", resp.StatusCode)
	}
	seenHeadersMu.Lock()
	hdrCopy := lastSeenHeaders.Clone()
	seenHeadersMu.Unlock()
	wantBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("git:"+secForge))
	if hdrCopy.Get("Authorization") != wantBasic {
		t.Fatalf("upstream Authorization = %q, want %q", hdrCopy.Get("Authorization"), wantBasic)
	}
	if hdrCopy.Get("Accept-Encoding") != "identity" {
		t.Fatalf("upstream Accept-Encoding = %q, want identity", hdrCopy.Get("Accept-Encoding"))
	}
	if hdrCopy.Get("X-Unbound-Ph") != "" || hdrCopy.Get("Proxy-Authorization") != "" {
		t.Fatalf("unbound placeholder / Proxy-Authorization leaked to bound host: %+v", hdrCopy)
	}

	// 2. Corrupt/interior-newline secret fails closed 403 without dialing upstream.
	beforeBad := upReceived.Load()
	reqBad, err := http.NewRequest(http.MethodGet, "https://badsec.lan.example/ok", nil)
	if err != nil {
		t.Fatalf("NewRequest bad secret: %v", err)
	}
	reqBad.Header.Set("X-Bad-Token", "mf_ph_bad")
	rBad, err := gw.H1Client(t, "badsec.lan.example").Do(reqBad)
	if err != nil {
		t.Fatalf("Do bad secret: %v", err)
	}
	if err := rBad.Body.Close(); err != nil {
		t.Fatalf("close rBad: %v", err)
	}
	if rBad.StatusCode != http.StatusForbidden {
		t.Fatalf("bad secret status = %d, want 403", rBad.StatusCode)
	}
	if upReceived.Load() != beforeBad {
		t.Fatalf("unresolved secret request hit upstream: %d != %d", upReceived.Load(), beforeBad)
	}

	// 3. Unbound host strips mf_ph_* unconditionally.
	reqUnb, err := http.NewRequest(http.MethodGet, "https://unbound.example.com/ok", nil)
	if err != nil {
		t.Fatalf("NewRequest unbound: %v", err)
	}
	reqUnb.Header.Set("Authorization", "Bearer mf_ph_forge")
	rUnb, err := gw.H1Client(t, "unbound.example.com").Do(reqUnb)
	if err != nil {
		t.Fatalf("Do unbound: %v", err)
	}
	if err := rUnb.Body.Close(); err != nil {
		t.Fatalf("close rUnb: %v", err)
	}
	seenHeadersMu.Lock()
	unbAuth := lastSeenHeaders.Get("Authorization")
	seenHeadersMu.Unlock()
	if unbAuth != "" {
		t.Fatalf("placeholder leaked to unbound host: %q", unbAuth)
	}

	gw.AssertAuditNotContains(t, secForge)
}

func TestHTTP2LeadingOWSBasicAuthSubstitutedAndSwept(t *testing.T) {
	secVal := "h2ows_" + randHex(t)
	secFile := writeSecretFile(t, t.TempDir(), "sec.txt", secVal+"\n")

	var (
		hdrMu   sync.Mutex
		lastHdr http.Header
	)
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"bound.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hdrMu.Lock()
			lastHdr = r.Header.Clone()
			hdrMu.Unlock()
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: fmt.Sprintf(`
  - id: allow-bound
    principal: worker-test
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
`, secFile),
	})

	reqH2, err := http.NewRequest(http.MethodGet, "https://bound.example.com/ok", nil)
	if err != nil {
		t.Fatalf("NewRequest H2 OWS: %v", err)
	}
	reqH2.Header.Set("Authorization", "  Basic "+base64.StdEncoding.EncodeToString([]byte("git:mf_ph_ows"))+" ")
	reqH2.Header.Set("X-Leak-Basic", "\tBasic "+base64.StdEncoding.EncodeToString([]byte("u:mf_ph_other")))

	respH2, err := gw.H2Client(t, "bound.example.com").Do(reqH2)
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

func TestPort80BoundHostNoSubstitutionPlaceholderStripped(t *testing.T) {
	forgeSec := "gitsec_" + randHex(t)
	forgeSecFile := writeSecretFile(t, t.TempDir(), "forge.sec", forgeSec+"\n")

	var (
		plainHits    atomic.Int32
		mu           sync.Mutex
		lastAuth     string
		lastProxyAut string
	)
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"code.lan.example"},
		PlainHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			plainHits.Add(1)
			mu.Lock()
			lastAuth = r.Header.Get("Authorization")
			lastProxyAut = r.Header.Get("Proxy-Authorization")
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "plain"); err != nil {
				return
			}
		}),
		RulesYAML: fmt.Sprintf(`
  - id: allow-forge
    principal: worker-test
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
`, forgeSecFile),
	})

	reqP80, err := http.NewRequest(http.MethodGet, "http://code.lan.example/ok", nil)
	if err != nil {
		t.Fatalf("NewRequest port 80 bound: %v", err)
	}
	reqP80.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("git:mf_ph_git")))
	reqP80.Header.Set("Proxy-Authorization", "Bearer nope")
	rP80, err := gw.PlainClient(t).Do(reqP80)
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
}

func TestNoSecretSubstitutionInBodyOrQuery(t *testing.T) {
	forgeSec := "gitsec_" + randHex(t)
	forgeSecFile := writeSecretFile(t, t.TempDir(), "forge.sec", forgeSec+"\n")

	var (
		mu           sync.Mutex
		lastAuth     string
		lastBody     string
		lastRawQuery string
	)
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"code.lan.example"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			mu.Lock()
			lastAuth = r.Header.Get("Authorization")
			lastBody = string(b)
			lastRawQuery = r.URL.RawQuery
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: fmt.Sprintf(`
  - id: allow-forge
    principal: worker-test
    effect: allow
    hosts: [code.lan.example]
    ports: [443]
    bindings:
      - name: forge-git
        host: code.lan.example
        header: Authorization
        scheme: basic
        placeholder: mf_ph_git
        secret_file: %s
`, forgeSecFile),
	})

	req, err := http.NewRequest(http.MethodPost, "https://code.lan.example/ok?token=mf_ph_git", strings.NewReader("body=mf_ph_git"))
	if err != nil {
		t.Fatalf("NewRequest body/query: %v", err)
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("git:mf_ph_git")))
	resp, err := gw.H2Client(t, "code.lan.example").Do(req)
	if err != nil {
		t.Fatalf("Do body/query: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
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
		t.Fatalf("placeholder was substituted in body: got %q", gotBody)
	}
	if gotQuery != "token=mf_ph_git" || strings.Contains(gotQuery, forgeSec) {
		t.Fatalf("placeholder was substituted in query: got %q", gotQuery)
	}
	gw.AssertAuditNotContains(t, forgeSec)
}
