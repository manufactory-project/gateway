// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy_test

import (
	"fmt"
	"io"
	"net/http"
	"testing"
)

func BenchmarkBoundHTTPSGetRedacted(b *testing.B) {
	secVal := "bench_secret_token_0123456789abcdef"
	secFile := writeSecretFile(b, b.TempDir(), "bench.sec", secVal+"\n")
	payload := []byte("response payload echoing secret=" + secVal + " end\n")

	gw := newTestGateway(b, testGatewaySpec{
		Hosts: []string{"bench.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(payload); err != nil {
				return
			}
		}),
		RulesYAML: fmt.Sprintf(`
  - id: allow-bench
    principal: worker-test
    effect: allow
    hosts: [bench.example.com]
    ports: [443]
    bindings:
      - name: bench-bearer
        host: bench.example.com
        header: Authorization
        scheme: bearer
        placeholder: mf_ph_bench
        secret_file: %s
`, secFile),
	})

	runBench := func(b *testing.B, client *http.Client) {
		b.Helper()
		// Warm up TLS session and leaf cache before timing steady-state requests.
		warmReq, err := http.NewRequest(http.MethodGet, "https://bench.example.com/v1/bench", nil)
		if err != nil {
			b.Fatalf("NewRequest warmup: %v", err)
		}
		warmReq.Header.Set("Authorization", "Bearer mf_ph_bench")
		warmResp, err := client.Do(warmReq)
		if err != nil {
			b.Fatalf("warmup Do: %v", err)
		}
		if _, err := io.Copy(io.Discard, warmResp.Body); err != nil {
			b.Fatalf("warmup read: %v", err)
		}
		if err := warmResp.Body.Close(); err != nil {
			b.Fatalf("warmup close: %v", err)
		}

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req, err := http.NewRequest(http.MethodGet, "https://bench.example.com/v1/bench", nil)
			if err != nil {
				b.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Authorization", "Bearer mf_ph_bench")
			resp, err := client.Do(req)
			if err != nil {
				b.Fatalf("Do: %v", err)
			}
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				b.Fatalf("read body: %v", err)
			}
			if err := resp.Body.Close(); err != nil {
				b.Fatalf("close body: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				b.Fatalf("status = %d, want 200", resp.StatusCode)
			}
		}
		b.StopTimer()
	}

	b.Run("H1", func(b *testing.B) {
		runBench(b, gw.H1Client(b, "bench.example.com"))
	})
	b.Run("H2", func(b *testing.B) {
		runBench(b, gw.H2Client(b, "bench.example.com"))
	})
}
