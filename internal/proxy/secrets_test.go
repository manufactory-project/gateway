// SPDX-License-Identifier: AGPL-3.0-only

package proxy_test

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func TestBindingScopedToOwningRuleAndSingleSnapshotRedaction(t *testing.T) {
	secDir := t.TempDir()
	secScoped := "scoped_secret_" + randHex(t)
	secFile := writeSecretFile(t, secDir, "scoped.secret", secScoped+"\n")

	var (
		mu            sync.Mutex
		lastKey       string
		lastAcceptEnc string
	)
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"scoped.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			lastKey = r.Header.Get("X-Api-Key")
			lastAcceptEnc = r.Header.Get("Accept-Encoding")
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "echo="+secScoped); err != nil {
				return
			}
		}),
		RulesYAML: fmt.Sprintf(`
  - id: rule-a-bound
    principal: worker-test
    effect: allow
    hosts: [scoped.example.com]
    ports: [443]
    methods: [POST]
    paths: ["/api/**"]
    bindings:
      - name: scoped-key
        host: scoped.example.com
        header: X-Api-Key
        scheme: raw
        placeholder: mf_ph_scoped
        secret_file: %s
  - id: rule-b-public
    principal: worker-test
    effect: allow
    hosts: [scoped.example.com]
    ports: [443]
    methods: [GET]
    paths: ["/public/**"]
`, secFile),
	})

	if _, err := gw.Store.AddGrant("worker-test", "scoped.example.com", 443, []string{"GET"}, []string{"/debug/**"}, 5*time.Minute, false); err != nil {
		t.Fatalf("AddGrant: %v", err)
	}

	doReq := func(method, path string) (body, gotKey, gotAE string) {
		t.Helper()
		req, err := http.NewRequest(method, "https://scoped.example.com"+path, nil)
		if err != nil {
			t.Fatalf("NewRequest %s %s: %v", method, path, err)
		}
		req.Header.Set("X-Api-Key", "mf_ph_scoped")
		req.Header.Set("Accept-Encoding", "gzip")
		resp, err := gw.H1Client(t, "scoped.example.com").Do(req)
		if err != nil {
			t.Fatalf("Do %s %s: %v", method, path, err)
		}
		raw, rErr := io.ReadAll(resp.Body)
		if cErr := resp.Body.Close(); cErr != nil {
			t.Fatalf("close body: %v", cErr)
		}
		if rErr != nil {
			t.Fatalf("read body: %v", rErr)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %s status = %d, want 200", method, path, resp.StatusCode)
		}
		mu.Lock()
		k, ae := lastKey, lastAcceptEnc
		mu.Unlock()
		return string(raw), k, ae
	}

	// 1. Owning rule A (POST /api/x): substituted + identity + redacted.
	bodyA, keyA, aeA := doReq(http.MethodPost, "/api/x")
	if keyA != secScoped {
		t.Fatalf("rule A upstream X-Api-Key = %q, want substituted secret", keyA)
	}
	if aeA != "identity" || bodyA != "echo=mf_ph_scoped" {
		t.Fatalf("rule A identity/redaction failed: ae=%q body=%q", aeA, bodyA)
	}

	// 2. Unrelated rule B (GET /public/x): NOT substituted (placeholder swept), still host-redacted + identity.
	bodyB, keyB, aeB := doReq(http.MethodGet, "/public/x")
	if keyB != "" {
		t.Fatalf("rule B escalated secret or leaked placeholder: X-Api-Key = %q", keyB)
	}
	if aeB != "identity" || bodyB != "echo=mf_ph_scoped" {
		t.Fatalf("rule B host-scoped identity/redaction failed: ae=%q body=%q", aeB, bodyB)
	}

	// 3. Ephemeral grant (GET /debug/x): NOT substituted (placeholder swept), still host-redacted + identity.
	bodyG, keyG, aeG := doReq(http.MethodGet, "/debug/x")
	if keyG != "" {
		t.Fatalf("ephemeral grant escalated secret or leaked placeholder: X-Api-Key = %q", keyG)
	}
	if aeG != "identity" || bodyG != "echo=mf_ph_scoped" {
		t.Fatalf("grant host-scoped identity/redaction failed: ae=%q body=%q", aeG, bodyG)
	}
	gw.AssertAuditNotContains(t, secScoped)
}

func TestSingleSnapshotRedactionOnReloadToggle(t *testing.T) {
	secDir := t.TempDir()
	secRace := "race_secret_" + randHex(t)
	raceSecFile := writeSecretFile(t, secDir, "race.secret", secRace+"\n")
	baseRules := `
  - id: allow-race
    principal: worker-test
    effect: allow
    hosts: [race-bind.example.com]
    ports: [443]
    methods: [GET]
    paths: ["/**"]
`
	boundRules := baseRules + fmt.Sprintf(`    bindings:
      - name: race-key
        host: race-bind.example.com
        header: X-Api-Key
        scheme: raw
        placeholder: mf_ph_race
        secret_file: %s
`, raceSecFile)

	gwRace := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"race-bind.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Seen-AE", r.Header.Get("Accept-Encoding"))
			w.Header().Set("X-Was-Sub", fmt.Sprintf("%v", r.Header.Get("X-Api-Key") == secRace))
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "val="+r.Header.Get("X-Api-Key")); err != nil {
				return
			}
		}),
		RulesYAML: baseRules,
	})
	idx := strings.Index(gwRace.BaseYAML, "rules:\n")
	if idx < 0 {
		t.Fatal("missing rules block in BaseYAML")
	}
	prefixYAML := gwRace.BaseYAML[:idx] + "rules:\n"

	stopReload := make(chan struct{})
	var reloadWG sync.WaitGroup
	reloadWG.Add(1)
	go func() {
		defer reloadWG.Done()
		toggle := false
		for {
			select {
			case <-stopReload:
				return
			default:
			}
			toggle = !toggle
			rules := baseRules
			if toggle {
				rules = boundRules
			}
			if err := os.WriteFile(gwRace.CfgPath, []byte(prefixYAML+rules), 0o600); err != nil {
				return
			}
			if _, _, _, err := gwRace.Store.Reload(); err != nil {
				return
			}
		}
	}()

	client := gwRace.H1Client(t, "race-bind.example.com")
	var subCount int
	for i := 0; i < 60; i++ {
		req, err := http.NewRequest(http.MethodGet, "https://race-bind.example.com/check", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("X-Api-Key", "mf_ph_race")
		req.Header.Set("Accept-Encoding", "gzip")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		raw, rErr := io.ReadAll(resp.Body)
		if cErr := resp.Body.Close(); cErr != nil {
			t.Fatalf("close race resp: %v", cErr)
		}
		if rErr != nil {
			continue
		}
		if resp.Header.Get("X-Was-Sub") == "true" {
			subCount++
			if resp.Header.Get("X-Seen-AE") != "identity" {
				t.Fatalf("TOCTOU: secret substituted without Accept-Encoding: identity (got %q)", resp.Header.Get("X-Seen-AE"))
			}
			if strings.Contains(string(raw), secRace) {
				t.Fatalf("TOCTOU: substituted secret leaked unredacted in response: %q", string(raw))
			}
		}
	}
	close(stopReload)
	reloadWG.Wait()
	if subCount == 0 {
		if err := os.WriteFile(gwRace.CfgPath, []byte(prefixYAML+boundRules), 0o600); err != nil {
			t.Fatalf("write bound config: %v", err)
		}
		if _, _, _, err := gwRace.Store.Reload(); err != nil {
			t.Fatalf("Reload bound config: %v", err)
		}
		req, err := http.NewRequest(http.MethodGet, "https://race-bind.example.com/check", nil)
		if err != nil {
			t.Fatalf("NewRequest final: %v", err)
		}
		req.Header.Set("X-Api-Key", "mf_ph_race")
		req.Header.Set("Accept-Encoding", "gzip")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do final: %v", err)
		}
		raw, rErr := io.ReadAll(resp.Body)
		if cErr := resp.Body.Close(); cErr != nil {
			t.Fatalf("close final resp: %v", cErr)
		}
		if rErr != nil {
			t.Fatalf("read final resp: %v", rErr)
		}
		if resp.Header.Get("X-Was-Sub") != "true" || resp.Header.Get("X-Seen-AE") != "identity" || strings.Contains(string(raw), secRace) {
			t.Fatalf("bound final check failed: sub=%q ae=%q body=%q", resp.Header.Get("X-Was-Sub"), resp.Header.Get("X-Seen-AE"), string(raw))
		}
	}
	gwRace.AssertAuditNotContains(t, secRace)
}
