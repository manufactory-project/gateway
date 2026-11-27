package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/manufactory-project/gateway/internal/admin"
	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/metrics"
	"github.com/manufactory-project/gateway/internal/proxy"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestGwctlVerbsEndToEnd(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	auditDir := filepath.Join(dir, "audit")
	sockPath := filepath.Join(dir, "admin.sock")

	// 1. Offline `gwctl ca init` with --json AFTER the subcommand (Item 18).
	var out, errBuf bytes.Buffer
	if err := run(context.Background(), []string{"ca", "init", "--cert", certPath, "--key", keyPath, "--json"}, &out, &errBuf); err != nil {
		t.Fatalf("gwctl ca init: %v (stderr=%s)", err, errBuf.String())
	}
	if !strings.Contains(out.String(), certPath) {
		t.Fatalf("unexpected ca init output: %s", out.String())
	}

	// Start real Admin server to exercise all online gwctl verbs.
	cfgYAML := fmt.Sprintf(`
ca:
  cert_path: %s
  key_path: %s
audit:
  dir: %s
links:
  - name: sbx0
    principal: worker-claude
    subnet: 127.0.25.0/28
    gateway_ip: 127.0.25.1
rules:
  - id: r1
    principal: worker-claude
    effect: allow
    hosts: [api.anthropic.com]
    ports: [443]
`, certPath, keyPath, auditDir)
	cfgPath := filepath.Join(dir, "gatewayd.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	store, err := config.NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	aw, err := audit.NewWriter(audit.Options{Dir: auditDir})
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}
	t.Cleanup(func() {
		if err := aw.Close(); err != nil {
			t.Errorf("audit close: %v", err)
		}
	})
	flows := proxy.NewFlowRegistry()
	aSrv, err := admin.NewServer(admin.Options{
		SocketPath: sockPath,
		Store:      store,
		Flows:      flows,
		Audit:      aw,
		Metrics:    metrics.NewCollector(metrics.Options{}),
	})
	if err != nil {
		t.Fatalf("admin.NewServer: %v", err)
	}
	if err := aSrv.Start(); err != nil {
		t.Fatalf("admin.Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := aSrv.Shutdown(ctx); err != nil {
			t.Errorf("admin.Shutdown: %v", err)
		}
	})

	runCLI := func(args ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		// Pass --json AFTER the subcommand to verify Item 18 on every subcommand.
		full := append([]string{"--socket", sockPath}, args...)
		full = append(full, "--json")
		if err := run(context.Background(), full, &stdout, &stderr); err != nil {
			t.Fatalf("gwctl %v failed: %v (stderr=%s)", args, err, stderr.String())
		}
		return stdout.String()
	}

	// Item 18: --port 65979 (65536 + 443) would wrap to 443 as uint16 if unchecked; must fail.
	var badOut, badErr bytes.Buffer
	if err := run(context.Background(), []string{"--socket", sockPath, "grant", "--principal", "worker-claude", "--host", "x.example.com", "--port", "65979", "--ttl", "5m"}, &badOut, &badErr); err == nil {
		t.Fatal("expected gwctl grant --port 65979 (wraps to 443) to fail")
	}

	// status
	var st admin.StatusResponse
	if err := json.Unmarshal([]byte(runCLI("status")), &st); err != nil {
		t.Fatalf("parse status JSON: %v", err)
	}
	if !st.AuditHealthy {
		t.Fatalf("expected audit_healthy=true, got %+v", st)
	}

	// grant + grants + grant revoke
	var g config.Grant
	if err := json.Unmarshal([]byte(runCLI("grant", "--principal", "worker-claude", "--host", "login.anthropic.com", "--ttl", "5m")), &g); err != nil {
		t.Fatalf("parse grant JSON: %v", err)
	}
	if g.Host != "login.anthropic.com" {
		t.Fatalf("unexpected grant: %+v", g)
	}
	if !strings.Contains(runCLI("grants"), g.ID) {
		t.Fatalf("grants did not list %s", g.ID)
	}
	if !strings.Contains(runCLI("grant", "revoke", g.ID), `"revoked_grant":true`) {
		t.Fatal("grant revoke did not report revoked_grant=true")
	}

	// flows + revoke + reload
	_ = runCLI("flows")
	if !strings.Contains(runCLI("revoke", "--principal", "worker-claude"), `"revoked_flows":0`) {
		t.Fatal("revoke output mismatch")
	}
	if !strings.Contains(runCLI("reload"), `"config_hash"`) {
		t.Fatal("reload output mismatch")
	}
}
