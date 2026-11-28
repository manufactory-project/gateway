package proxy_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func boundRule(id, host, secretFile string) string {
	return fmt.Sprintf(`
  - id: %s
    principal: worker-test
    effect: allow
    hosts: [%s]
    ports: [443]
    bindings:
      - name: api-key
        host: %s
        header: Authorization
        scheme: bearer
        placeholder: mf_ph_key
        secret_file: %s
`, id, host, host, secretFile)
}

// do sends req with a deadline so that a stalled response fails an assertion.
func do(t *testing.T, c *http.Client, method, url string, hdr map[string]string) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	t.Cleanup(func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("close body: %v", err)
		}
	})
	return resp
}

func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

func TestBoundHostNeverServesPartialResponses(t *testing.T) {
	secretValue := "sk-" + strings.Repeat("Z", 40)
	secretFile := writeSecretFile(t, t.TempDir(), "key", secretValue)
	var sawRange atomic.Bool
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"api.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Range") != "" || r.Header.Get("If-Range") != "" {
				sawRange.Store(true)
			}
			if r.URL.Path == "/always-partial" {
				w.Header().Set("Content-Range", "bytes 0-9/100")
				w.WriteHeader(http.StatusPartialContent)
				if _, err := io.WriteString(w, secretValue[:10]); err != nil {
					return
				}
				return
			}
			http.ServeContent(w, r, "f.txt", time.Time{}, strings.NewReader("prefix:"+secretValue+":suffix"))
		}),
		RulesYAML: boundRule("r", "api.example.com", secretFile),
	})
	c := gw.H1Client(t, "api.example.com")

	resp := do(t, c, http.MethodGet, "https://api.example.com/raw", map[string]string{"Range": "bytes=0-26", "If-Range": `"x"`})
	if body := readAll(t, resp.Body); resp.StatusCode != http.StatusOK || body != "prefix:mf_ph_key:suffix" {
		t.Fatalf("ranged request = %d %q, want the whole redacted body", resp.StatusCode, body)
	}
	if sawRange.Load() {
		t.Fatal("Range or If-Range reached a bound host")
	}

	partial := do(t, c, http.MethodGet, "https://api.example.com/always-partial", nil)
	if body := readAll(t, partial.Body); partial.StatusCode != http.StatusBadGateway || strings.Contains(body, secretValue[:10]) {
		t.Fatalf("unsolicited 206 = %d %q, want 502 without upstream bytes", partial.StatusCode, body)
	}
}

func TestUnreadableBoundSecretFailsBeforeDispatch(t *testing.T) {
	var hits atomic.Int32
	gw := newTestGateway(t, testGatewaySpec{
		Hosts:     []string{"api.example.com"},
		Handler:   http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }),
		RulesYAML: boundRule("r", "api.example.com", t.TempDir()+"/missing"),
	})

	// The request carries no placeholder; the host still needs the secret to redact.
	resp := do(t, gw.H1Client(t, "api.example.com"), http.MethodPost, "https://api.example.com/create", nil)
	if resp.StatusCode != http.StatusForbidden || hits.Load() != 0 {
		t.Fatalf("status = %d, upstream requests = %d; want 403 and 0", resp.StatusCode, hits.Load())
	}
}
