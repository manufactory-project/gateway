package metrics_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/manufactory-project/gateway/internal/metrics"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func freePort(t *testing.T, ip string) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp4", ip+":0")
	if err != nil {
		t.Fatalf("freePort %s: %v", ip, err)
	}
	ta, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected addr type %T", ln.Addr())
	}
	p := uint16(ta.Port)
	if err := ln.Close(); err != nil {
		t.Fatalf("close freePort: %v", err)
	}
	return p
}

func TestMetricsExplicitBindAndExposition(t *testing.T) {
	col := metrics.NewCollector(metrics.Options{
		ActiveFlows:  func() int { return 3 },
		ActiveGrants: func() int { return 1 },
	})

	// Containment: wildcard listen addresses (including v4-mapped ::ffff:0.0.0.0) are forbidden.
	for _, bad := range []string{"0.0.0.0:9102", ":9102", "[::]:9102", "[::ffff:0.0.0.0]:9102", "localhost:9102"} {
		if _, err := metrics.NewServer(bad, col, func(error) {}); err == nil {
			t.Fatalf("expected NewServer(%q) to fail", bad)
		}
	}

	// Positive control: explicit loopback IP binds and serves Prometheus metrics.
	listenAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(freePort(t, "127.0.0.1"))))
	if _, err := metrics.NewServer(listenAddr, col, nil); err == nil {
		t.Fatal("expected metrics.NewServer with nil onServeError to fail")
	}
	srv, err := metrics.NewServer(listenAddr, col, func(error) {})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})

	col.IncAuditWriteError()
	col.ObserveRequest("worker-claude", "allow", 200, "rule-allow")
	col.ObserveRequest("worker-claude", "allow", 502, "free-form error: dial tcp 1.2.3.4:443 i/o timeout")
	col.ObserveDNSQuery("worker-claude", "deny")
	col.ObserveReload(true)
	col.AddRevocations(2)

	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://" + listenAddr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close /metrics: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", resp.StatusCode)
	}

	text := string(body)
	for _, want := range []string{
		"gateway_audit_write_errors_total 1",
		`gateway_requests_total{effect="allow",principal="worker-claude",reason="rule-allow",status="200"} 1`,
		`gateway_requests_total{effect="allow",principal="worker-claude",reason="other",status="502"} 1`,
		`gateway_dns_queries_total{effect="deny",principal="worker-claude"} 1`,
		`gateway_reloads_total{result="ok"} 1`,
		"gateway_revocations_total 2",
		"gateway_active_flows 3",
		"gateway_active_grants 1",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("/metrics output missing %q\nfull:\n%s", want, text)
		}
	}
}
