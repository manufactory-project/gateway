package proxy_test

import (
	"bufio"
	"context"
	"errors"
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

// writeRawHTTP1 answers an HTTP/1.1 upstream request with exactly raw. A failure
// aborts the handler, which the calling test sees as a missing audit token.
func writeRawHTTP1(w http.ResponseWriter, raw string) {
	conn, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		panic(http.ErrAbortHandler)
	}
	_, writeErr := buf.WriteString(raw)
	if err := errors.Join(writeErr, buf.Flush(), conn.Close()); err != nil {
		panic(http.ErrAbortHandler)
	}
}

func TestBoundHostStreamsHeadersAndEventsWhileUpstreamIsOpen(t *testing.T) {
	secretFile := writeSecretFile(t, t.TempDir(), "key", "sk-"+strings.Repeat("a", 100))
	sendEvent := make(chan struct{})
	release := make(chan struct{})
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"api.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rc := http.NewResponseController(w)
			w.Header().Set("Content-Type", "text/event-stream")
			if err := rc.Flush(); err != nil {
				return
			}
			select {
			case <-sendEvent:
			case <-r.Context().Done():
				return
			}
			if _, err := io.WriteString(w, "data: first\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}),
		RulesYAML:      boundRule("r", "api.example.com", secretFile),
		OnCleanupFirst: func() { close(release) },
	})

	// Headers arrive before the upstream has written any body.
	resp := do(t, gw.H1Client(t, "api.example.com"), http.MethodGet, "https://api.example.com/events", nil)
	close(sendEvent)

	// A complete event arrives while the upstream response is still open.
	br := bufio.NewReader(resp.Body)
	for _, want := range []string{"data: first\n", "\n"} {
		got, err := br.ReadString('\n')
		if err != nil || got != want {
			t.Fatalf("event line = %q, %v; want %q", got, err, want)
		}
	}
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

func TestUpstreamControlledErrorTextNeverReachesAudit(t *testing.T) {
	secretValue := "sk-" + strings.Repeat("Q", 30)
	secretFile := writeSecretFile(t, t.TempDir(), "key", secretValue)
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"api.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			writeRawHTTP1(w, "HTTP/1.1 "+token+" nope\r\n\r\n")
		}),
		RulesYAML:  boundRule("r", "api.example.com", secretFile),
		UpstreamH1: true,
	})

	resp := do(t, gw.H1Client(t, "api.example.com"), http.MethodGet, "https://api.example.com/x",
		map[string]string{"Authorization": "Bearer mf_ph_key"})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	gw.AssertAuditNotContains(t, secretValue)
	for _, ev := range gw.AuditEvents(t) {
		if ev.Error == "upstream-error" {
			return
		}
	}
	t.Fatalf("no completion event with error upstream-error: %+v", gw.AuditEvents(t))
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

func TestUpstreamHangingUpIsAuditedAsConnectionClosed(t *testing.T) {
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"api.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeRawHTTP1(w, "")
		}),
		RulesYAML:  boundRule("r", "api.example.com", writeSecretFile(t, t.TempDir(), "key", "sk-unused-value")),
		UpstreamH1: true,
	})
	resp := do(t, gw.H1Client(t, "api.example.com"), http.MethodGet, "https://api.example.com/x", nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	for _, ev := range gw.AuditEvents(t) {
		if ev.Error == "upstream-error: connection-closed" {
			return
		}
	}
	t.Fatalf("no completion event classed connection-closed: %+v", gw.AuditEvents(t))
}
