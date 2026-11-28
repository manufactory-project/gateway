package proxy_test

import (
	"context"
	"fmt"
	"net/http"
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
