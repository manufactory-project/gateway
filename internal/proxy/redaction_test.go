// SPDX-License-Identifier: AGPL-3.0-only

package proxy_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestBoundHostResponseRedactionHeadersBodyTrailersAndGzip502(t *testing.T) {
	secForge := "s3cr3t_" + randHex(t) + "/&\"<>"
	secFile := writeSecretFile(t, t.TempDir(), "forge.secret", secForge+"\n")

	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"code.lan.example"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/echo":
				jsonBytes, err := json.Marshal(secForge)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				jsonInner := strings.Trim(string(jsonBytes), `"`)
				w.Header().Set("X-Echo", "hdr="+secForge)
				w.Header().Set("Trailer", "X-Trailer-Secret")
				w.WriteHeader(http.StatusOK)
				rc := http.NewResponseController(w)
				body := "lit=" + secForge + "|url=" + url.QueryEscape(secForge) + "|json=" + jsonInner
				// Write split chunks to exercise sliding-window boundary scrubbing.
				for i := 0; i < len(body); i += 5 {
					end := i + 5
					if end > len(body) {
						end = len(body)
					}
					if _, err := io.WriteString(w, body[i:end]); err != nil {
						return
					}
					if err := rc.Flush(); err != nil {
						return
					}
				}
				w.Header().Set("X-Trailer-Secret", "tr="+secForge)

			case "/echo-cl":
				body := "secret=" + secForge
				w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
				w.WriteHeader(http.StatusOK)
				if _, err := io.WriteString(w, body); err != nil {
					return
				}

			case "/gzip-bound":
				var buf bytes.Buffer
				gz := gzip.NewWriter(&buf)
				if _, err := io.WriteString(gz, "leaked:"+secForge); err != nil {
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
      - name: forge-basic
        host: code.lan.example
        header: Authorization
        scheme: basic
        placeholder: mf_ph_forge
        secret_file: %s
`, secFile),
	})

	cForge := gw.H1Client(t, "code.lan.example")

	// 1. Response headers, split-chunk literal/URL/JSON body, and trailer are scrubbed; Content-Length stripped.
	req, err := http.NewRequest(http.MethodGet, "https://code.lan.example/echo", nil)
	if err != nil {
		t.Fatalf("NewRequest /echo: %v", err)
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("git:mf_ph_forge")))
	resp, err := cForge.Do(req)
	if err != nil {
		t.Fatalf("Do /echo: %v", err)
	}
	echoBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /echo body: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close /echo body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/echo status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("Content-Length") != "" {
		t.Fatalf("Content-Length must be stripped on bound host, got %q", resp.Header.Get("Content-Length"))
	}
	if resp.Header.Get("X-Echo") != "hdr=mf_ph_forge" {
		t.Fatalf("response header not scrubbed: %q", resp.Header.Get("X-Echo"))
	}
	if strings.Contains(string(echoBody), secForge) || string(echoBody) != "lit=mf_ph_forge|url=mf_ph_forge|json=mf_ph_forge" {
		t.Fatalf("response body not scrubbed cleanly: %q", echoBody)
	}
	if resp.Trailer.Get("X-Trailer-Secret") != "tr=mf_ph_forge" {
		t.Fatalf("response trailer not scrubbed: %q", resp.Trailer.Get("X-Trailer-Secret"))
	}

	// 2. Explicit Content-Length from upstream is stripped so shorter scrubbed body succeeds.
	rCL, err := cForge.Get("https://code.lan.example/echo-cl")
	if err != nil {
		t.Fatalf("GET /echo-cl: %v", err)
	}
	clBody, err := io.ReadAll(rCL.Body)
	if err != nil {
		t.Fatalf("read /echo-cl: %v", err)
	}
	if err := rCL.Body.Close(); err != nil {
		t.Fatalf("close /echo-cl: %v", err)
	}
	if rCL.Header.Get("Content-Length") != "" {
		t.Fatalf("Content-Length not stripped on /echo-cl: %q", rCL.Header.Get("Content-Length"))
	}
	if string(clBody) != "secret=mf_ph_forge" {
		t.Fatalf("/echo-cl body = %q, want secret=mf_ph_forge", clBody)
	}

	// 3. Compressed gzip response on bound host fails closed 502 without leaking secret.
	rGzipBound, err := cForge.Get("https://code.lan.example/gzip-bound")
	if err != nil {
		t.Fatalf("GET /gzip-bound: %v", err)
	}
	gzBoundBody, err := io.ReadAll(rGzipBound.Body)
	if err != nil {
		t.Fatalf("read /gzip-bound: %v", err)
	}
	if err := rGzipBound.Body.Close(); err != nil {
		t.Fatalf("close /gzip-bound: %v", err)
	}
	if rGzipBound.StatusCode != http.StatusBadGateway {
		t.Fatalf("/gzip-bound status = %d, want 502", rGzipBound.StatusCode)
	}
	if strings.Contains(string(gzBoundBody), secForge) {
		t.Fatal("secret leaked in 502 error body")
	}

	gw.AssertAuditNotContains(t, secForge)
}
