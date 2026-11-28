// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
)

func TestUnboundGzipPassthrough(t *testing.T) {
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"api.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			if _, err := io.WriteString(gz, "compressed-hello"); err != nil {
				return
			}
			if err := gz.Close(); err != nil {
				return
			}
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(buf.Bytes()); err != nil {
				return
			}
		}),
		RulesYAML: `
  - id: allow-api
    principal: worker-test
    effect: allow
    hosts: [api.example.com]
    ports: [443]
`,
	})

	rGz, err := gw.H1Client(t, "api.example.com").Get("https://api.example.com/v1/gzip")
	if err != nil {
		t.Fatalf("GET gzip: %v", err)
	}
	gzBytes, err := io.ReadAll(rGz.Body)
	if err != nil {
		t.Fatalf("read gzip: %v", err)
	}
	if err := rGz.Body.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	if rGz.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected Content-Encoding: gzip preserved on unbound host, got %q", rGz.Header.Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(bytes.NewReader(gzBytes))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	plainGz, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read ungzipped: %v", err)
	}
	if err := zr.Close(); err != nil {
		t.Fatalf("close gzip reader: %v", err)
	}
	if string(plainGz) != "compressed-hello" {
		t.Fatalf("ungzipped body = %q", plainGz)
	}
}

func TestGitSmartHTTPAndSubscriptionAuthPassthrough(t *testing.T) {
	forgeSec := "gitsec_" + randHex(t)
	forgeSecFile := writeSecretFile(t, t.TempDir(), "forge.sec", forgeSec+"\n")

	var (
		mu         sync.Mutex
		lastAuth   string
		lastCookie string
	)
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"code.lan.example", "sub.vendor.example"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bodyBytes, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				http.Error(w, readErr.Error(), http.StatusBadRequest)
				return
			}
			mu.Lock()
			lastAuth = r.Header.Get("Authorization")
			lastCookie = r.Header.Get("Cookie")
			mu.Unlock()
			switch r.URL.Path {
			case "/repo.git/info/refs":
				w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
				w.WriteHeader(http.StatusOK)
				if _, err := io.WriteString(w, "001e# service=git-upload-pack\n0000"); err != nil {
					return
				}
			case "/repo.git/git-upload-pack":
				w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
				w.WriteHeader(http.StatusOK)
				if _, err := w.Write(append([]byte("PACK"), bodyBytes...)); err != nil {
					return
				}
			default:
				w.WriteHeader(http.StatusOK)
			}
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
  - id: allow-sub
    principal: worker-test
    effect: allow
    hosts: [sub.vendor.example]
    ports: [443]
`, forgeSecFile),
	})

	// 1. Git smart HTTP: GET /repo.git/info/refs + POST /repo.git/git-upload-pack binary fidelity.
	cForge := gw.H2Client(t, "code.lan.example")
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

	// 2. Subscription MITM auth + cookie passthrough with zero audit logging.
	subBearer := "oauth_live_" + randHex(t)
	subCookie := "session_live_" + randHex(t)
	reqSub, err := http.NewRequest(http.MethodGet, "https://sub.vendor.example/ok", nil)
	if err != nil {
		t.Fatalf("NewRequest sub: %v", err)
	}
	reqSub.Header.Set("Authorization", "Bearer "+subBearer)
	reqSub.Header.Set("Cookie", subCookie)
	rSub, err := gw.H2Client(t, "sub.vendor.example").Do(reqSub)
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

	gw.AssertAuditNotContains(t, forgeSec, subBearer, subCookie)
}
