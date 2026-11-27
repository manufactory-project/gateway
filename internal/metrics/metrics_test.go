package metrics_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/manufactory-project/gateway/internal/metrics"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestMetricsExplicitBindAndExposition(t *testing.T) {
	col := metrics.NewCollector(metrics.Options{
		ActiveFlows:  func() int { return 3 },
		ActiveGrants: func() int { return 1 },
	})

	// Containment: wildcard listen addresses are forbidden.
	for _, bad := range []string{"0.0.0.0:9102", ":9102", "[::]:9102", "localhost:9102"} {
		if _, err := metrics.NewServer(bad, col); err == nil {
			t.Fatalf("expected NewServer(%q) to fail", bad)
		}
	}

	// Positive control: explicit loopback IP binds and serves Prometheus metrics.
	srv, err := metrics.NewServer("127.0.0.1:0", col)
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
	col.ObserveRequest("worker-claude", "allow", 200)
	col.ObserveDNSQuery("worker-claude", "deny")
	col.ObserveReload(true)
	col.AddRevocations(2)

	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://" + srv.Addr() + "/metrics")
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
		"gatewayd_audit_write_errors_total 1",
		`gatewayd_requests_total{effect="allow",principal="worker-claude",status="200"} 1`,
		`gatewayd_dns_queries_total{effect="deny",principal="worker-claude"} 1`,
		`gatewayd_reloads_total{result="ok"} 1`,
		"gatewayd_revocations_total 2",
		"gatewayd_active_flows 3",
		"gatewayd_active_grants 1",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("/metrics output missing %q\nfull:\n%s", want, text)
		}
	}
}
