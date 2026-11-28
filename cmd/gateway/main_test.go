package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/manufactory-project/gateway/internal/admin"
	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/ca"
	"github.com/manufactory-project/gateway/internal/config"
	gwdns "github.com/manufactory-project/gateway/internal/dns"
	"github.com/manufactory-project/gateway/internal/metrics"
	"github.com/manufactory-project/gateway/internal/netguard"
	"github.com/manufactory-project/gateway/internal/netsetup"
	"github.com/manufactory-project/gateway/internal/policy"
	"github.com/manufactory-project/gateway/internal/proxy"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func freePorts(t *testing.T, ip string, n int) []uint16 {
	t.Helper()
	lns := make([]net.Listener, 0, n)
	ports := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp4", ip+":0")
		if err != nil {
			for _, prev := range lns {
				if cErr := prev.Close(); cErr != nil {
					t.Errorf("close prev listener: %v", cErr)
				}
			}
			t.Fatalf("freePorts %s[%d]: %v", ip, i, err)
		}
		ta, ok := ln.Addr().(*net.TCPAddr)
		if !ok {
			t.Fatalf("unexpected addr type %T", ln.Addr())
		}
		lns = append(lns, ln)
		ports = append(ports, uint16(ta.Port))
	}
	for _, ln := range lns {
		if err := ln.Close(); err != nil {
			t.Fatalf("close freePorts: %v", err)
		}
	}
	return ports
}

func TestGatewayNetsetupDryRunAndStartupGuards(t *testing.T) {
	dir := t.TempDir()

	// 1. `gateway netsetup --dry-run` against example config (with sample IP).
	rawEx, err := os.ReadFile(filepath.Join("..", "..", "examples", "gateway.yaml"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	exPath := filepath.Join(dir, "example.yaml")
	if err := os.WriteFile(exPath, []byte(strings.ReplaceAll(string(rawEx), "<forge-ip>", "10.10.20.5")), 0o600); err != nil {
		t.Fatalf("write example copy: %v", err)
	}
	var dryOut, dryErr bytes.Buffer
	if err := run(context.Background(), []string{"netsetup", "--config", exPath, "--dry-run"}, &dryOut, &dryErr); err != nil {
		t.Fatalf("gateway netsetup --dry-run: %v (stderr=%s)", err, dryErr.String())
	}
	for _, want := range []string{
		"table inet gw {",
		"port=0",
		"dhcp-broadcast",
		"no-ping",
		"ip addr replace 10.200.0.1/28 dev sbx0",
	} {
		if !strings.Contains(dryOut.String(), want) {
			t.Errorf("netsetup --dry-run missing %q", want)
		}
	}

	// 2. `gateway run` requires --config.
	var noCfgOut, noCfgErr bytes.Buffer
	if err := run(context.Background(), []string{"run"}, &noCfgOut, &noCfgErr); err == nil {
		t.Fatal("expected `gateway run` without --config to fail")
	}

	// 3. Daemon refuses to start when ready_file is missing (dataplane not applied).
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if _, err := ca.Init(certPath, keyPath); err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	auditDir := filepath.Join(dir, "audit")
	sockPath := filepath.Join(dir, "admin", "admin.sock")
	readyFile := filepath.Join(dir, "dataplane", "dataplane.ready")

	linkPorts := freePorts(t, "127.0.26.1", 3)
	httpsPort, httpPort, dnsPort := linkPorts[0], linkPorts[1], linkPorts[2]
	metricsPort := freePorts(t, "127.0.0.1", 1)[0]

	daemonYAML := fmt.Sprintf(`
ca:
  cert_path: %s
  key_path: %s
audit:
  dir: %s
admin:
  socket: %s
metrics:
  listen: 127.0.0.1:%d
dataplane:
  ready_file: %s
links:
  - name: sbx0
    principal: worker-claude
    subnet: 127.0.26.0/28
    gateway_ip: 127.0.26.1
    https_port: %d
    http_port: %d
    dns_port: %d
rules:
  - id: r1
    principal: worker-claude
    effect: allow
    hosts: [api.anthropic.com]
    ports: [443]
`, certPath, keyPath, auditDir, sockPath, metricsPort, readyFile, httpsPort, httpPort, dnsPort)
	cfgPath := filepath.Join(dir, "daemon.yaml")
	if err := os.WriteFile(cfgPath, []byte(daemonYAML), 0o600); err != nil {
		t.Fatalf("write daemon yaml: %v", err)
	}

	if err := serveDaemon(context.Background(), cfgPath, "/proc/sys", &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected daemon to refuse startup when ready_file is missing")
	}

	// Positive control: once ready_file exists, daemon starts, answers /v1/status, and shuts down cleanly.
	if err := os.MkdirAll(filepath.Dir(readyFile), 0o755); err != nil {
		t.Fatalf("mkdir readyFile dir: %v", err)
	}
	if err := os.WriteFile(readyFile, []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("write readyFile: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveDaemon(ctx, cfgPath, "/proc/sys", &bytes.Buffer{}, &bytes.Buffer{})
	}()

	client := admin.NewClient(sockPath)
	t.Cleanup(client.Close)
	deadline := time.Now().Add(2 * time.Second)
	var statusOK bool
	for time.Now().Before(deadline) {
		if st, err := client.Status(context.Background()); err == nil && st.AuditHealthy {
			statusOK = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serveDaemon clean shutdown error: %v", err)
	}
	if !statusOK {
		t.Fatal("daemon did not become ready on admin socket")
	}
}

func TestGatewayCLIVerbsEndToEnd(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	auditDir := filepath.Join(dir, "audit")
	sockPath := filepath.Join(dir, "admin.sock")

	// 1. Offline `gateway ca init` with --json AFTER the subcommand.
	var out, errBuf bytes.Buffer
	if err := run(context.Background(), []string{"ca", "init", "--cert", certPath, "--key", keyPath, "--json"}, &out, &errBuf); err != nil {
		t.Fatalf("gateway ca init: %v (stderr=%s)", err, errBuf.String())
	}
	if !strings.Contains(out.String(), certPath) {
		t.Fatalf("unexpected ca init output: %s", out.String())
	}

	// Start real Admin server to exercise all online CLI verbs using the single adminFlowAdapter.
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
	cfgPath := filepath.Join(dir, "gateway.yaml")
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
		Flows:      adminFlowAdapter{flows: flows},
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
		// Pass --json AFTER the subcommand to verify trailing flag handling on every verb.
		full := append([]string{"--socket", sockPath}, args...)
		full = append(full, "--json")
		if err := run(context.Background(), full, &stdout, &stderr); err != nil {
			t.Fatalf("gateway %v failed: %v (stderr=%s)", args, err, stderr.String())
		}
		return stdout.String()
	}

	// --port 65979 (65536 + 443) would wrap to 443 as uint16 if unchecked; must fail.
	var badOut, badErr bytes.Buffer
	if err := run(context.Background(), []string{"--socket", sockPath, "grant", "--principal", "worker-claude", "--host", "x.example.com", "--port", "65979", "--ttl", "5m"}, &badOut, &badErr); err == nil {
		t.Fatal("expected gateway grant --port 65979 (wraps to 443) to fail")
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

func TestGrantLifecycleAudit(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if _, err := ca.Init(certPath, keyPath); err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	auditDir := filepath.Join(dir, "audit")
	sockPath := filepath.Join(dir, "admin", "admin.sock")
	readyFile := filepath.Join(dir, "dataplane", "dataplane.ready")
	if err := os.MkdirAll(filepath.Dir(readyFile), 0o755); err != nil {
		t.Fatalf("mkdir readyFile dir: %v", err)
	}
	if err := os.WriteFile(readyFile, []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("write readyFile: %v", err)
	}

	linkPorts := freePorts(t, "127.0.27.1", 3)
	daemonYAML := fmt.Sprintf(`
ca:
  cert_path: %s
  key_path: %s
audit:
  dir: %s
admin:
  socket: %s
dataplane:
  ready_file: %s
links:
  - name: sbx0
    principal: worker-claude
    subnet: 127.0.27.0/28
    gateway_ip: 127.0.27.1
    https_port: %d
    http_port: %d
    dns_port: %d
rules:
  - id: r1
    principal: worker-claude
    effect: allow
    hosts: [api.anthropic.com]
    ports: [443]
`, certPath, keyPath, auditDir, sockPath, readyFile, linkPorts[0], linkPorts[1], linkPorts[2])
	cfgPath := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(cfgPath, []byte(daemonYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveDaemon(ctx, cfgPath, "/proc/sys", &bytes.Buffer{}, &bytes.Buffer{})
	}()

	client := admin.NewClient(sockPath)
	t.Cleanup(client.Close)
	deadline := time.Now().Add(2 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		if st, err := client.Status(context.Background()); err == nil && st.AuditHealthy {
			ready = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !ready {
		cancel()
		<-done
		t.Fatal("daemon did not become ready")
	}

	g, err := client.CreateGrant(context.Background(), admin.GrantRequest{
		Principal: "worker-claude",
		Host:      "login.example.test",
		Port:      443,
		TTL:       "120ms",
	})
	if err != nil {
		cancel()
		<-done
		t.Fatalf("CreateGrant: %v", err)
	}

	// Wait past expiry and several pruner ticks (50ms) so any duplicate emission would be caught.
	time.Sleep(320 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serveDaemon shutdown: %v", err)
	}

	entries, err := filepath.Glob(filepath.Join(auditDir, "*.jsonl"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("glob audit jsonl: %v (entries=%v)", err, entries)
	}
	var createdEvents, expiredEvents []audit.Event
	for _, p := range entries {
		raw, rErr := os.ReadFile(p)
		if rErr != nil {
			t.Fatalf("read audit %s: %v", p, rErr)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if line == "" {
				continue
			}
			var ev audit.Event
			if uErr := json.Unmarshal([]byte(line), &ev); uErr != nil {
				t.Fatalf("unmarshal audit line %q: %v", line, uErr)
			}
			if ev.Kind == audit.KindGrant && ev.GrantID == g.ID {
				switch ev.Reason {
				case "grant-created":
					createdEvents = append(createdEvents, ev)
				case "grant-expired":
					expiredEvents = append(expiredEvents, ev)
				}
			}
		}
	}

	wantExpires := g.ExpiresAt.UTC().Format(time.RFC3339)
	if len(createdEvents) != 1 {
		t.Fatalf("want 1 grant-created event, got %d", len(createdEvents))
	}
	ce := createdEvents[0]
	if ce.TTL != "120ms" || ce.ExpiresAt != wantExpires {
		t.Fatalf("grant-created ttl=%q expires_at=%q, want ttl=%q expires_at=%q", ce.TTL, ce.ExpiresAt, "120ms", wantExpires)
	}
	if _, err := time.Parse(time.RFC3339, ce.ExpiresAt); err != nil {
		t.Fatalf("grant-created expires_at %q is not RFC3339: %v", ce.ExpiresAt, err)
	}

	if len(expiredEvents) != 1 {
		t.Fatalf("want exactly 1 grant-expired event, got %d", len(expiredEvents))
	}
	ee := expiredEvents[0]
	if ee.Principal != "worker-claude" || ee.Host != "login.example.test" || ee.Port != 443 || ee.ExpiresAt != wantExpires {
		t.Fatalf("unexpected grant-expired event: %+v", ee)
	}
}

func TestDataplaneCheckIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	readyFile := filepath.Join(dir, "dataplane.ready")
	cfgYAML := fmt.Sprintf(`
ca:
  cert_path: /etc/gateway/ca/ca.crt
  key_path: /etc/gateway/ca/ca.key
audit:
  dir: /var/log/gateway/audit
dataplane:
  ready_file: %s
  dhcp:
    user: dnsmasq
    lease_file: /var/lib/gateway/dnsmasq.leases
links:
  - name: sbx0
    interface: sbx0
    principal: worker-claude
    subnet: 10.200.0.0/28
    gateway_ip: 10.200.0.1
    ct_zone: 101
    route_table: 101
`, readyFile)
	cfgPath := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, _, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	nftOut, err := netsetup.RenderNftables(cfg)
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}
	procSysRoot := filepath.Join(dir, "proc-sys")
	for _, sc := range netsetup.DesiredSysctls(cfg) {
		p := filepath.Join(procSysRoot, strings.ReplaceAll(sc.Key, ".", string(os.PathSeparator)))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir sysctl %s: %v", p, err)
		}
		if err := os.WriteFile(p, []byte(sc.Value+"\n"), 0o644); err != nil {
			t.Fatalf("write sysctl %s: %v", p, err)
		}
	}

	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir binDir: %v", err)
	}
	nftOutPath := filepath.Join(dir, "nft.out")
	if err := os.WriteFile(nftOutPath, []byte(nftOut), 0o600); err != nil {
		t.Fatalf("write nft.out: %v", err)
	}
	fakeNFT := filepath.Join(binDir, "nft")
	script := fmt.Sprintf("#!/bin/sh\ncat %q\n", nftOutPath)
	if err := os.WriteFile(fakeNFT, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake nft: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	var out bytes.Buffer
	if err := runDataplaneCheck(context.Background(), cfgPath, procSysRoot, true, &out); err != nil {
		t.Fatalf("runDataplaneCheck failed: %v", err)
	}
	if !strings.Contains(out.String(), `"status":"ok"`) {
		t.Fatalf("unexpected dataplane check output: %s", out.String())
	}
	if _, err := os.Stat(readyFile); !os.IsNotExist(err) {
		t.Fatalf("gateway dataplane check must be read-only and not create ready_file %s (stat err=%v)", readyFile, err)
	}
	// --proc-sys-root CLI flag was removed; passing it must fail with a flag error.
	if err := run(context.Background(), []string{"dataplane", "check", "--config", cfgPath, "--proc-sys-root", procSysRoot}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected gateway dataplane check --proc-sys-root to be rejected")
	}
	if err := run(context.Background(), []string{"run", "--config", cfgPath, "--proc-sys-root", procSysRoot}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected gateway run --proc-sys-root to be rejected")
	}
}

func TestGatewayCLIArgumentHandling(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	auditDir := filepath.Join(dir, "audit")
	sockPath := filepath.Join(dir, "admin.sock")

	if _, err := ca.Init(certPath, keyPath); err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	cfgYAML := fmt.Sprintf(`
ca:
  cert_path: %s
  key_path: %s
audit:
  dir: %s
links:
  - name: sbx0
    principal: worker-claude
    subnet: 127.0.28.0/28
    gateway_ip: 127.0.28.1
rules:
  - id: r1
    principal: worker-claude
    effect: allow
    hosts: [api.anthropic.com]
    ports: [443]
`, certPath, keyPath, auditDir)
	cfgPath := filepath.Join(dir, "gateway.yaml")
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
	aSrv, err := admin.NewServer(admin.Options{
		SocketPath: sockPath,
		Store:      store,
		Flows:      adminFlowAdapter{flows: proxy.NewFlowRegistry()},
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

	// --socket before status and before revoke works.
	var statusOut, statusErr bytes.Buffer
	if err := run(context.Background(), []string{"--socket", sockPath, "status"}, &statusOut, &statusErr); err != nil {
		t.Fatalf("gateway --socket <sock> status failed: %v (stderr=%s)", err, statusErr.String())
	}
	if !strings.Contains(statusOut.String(), "audit_healthy=true") {
		t.Fatalf("unexpected status output: %s", statusOut.String())
	}

	var revokeOut, revokeErr bytes.Buffer
	if err := run(context.Background(), []string{"--socket", sockPath, "revoke", "--principal", "worker-claude"}, &revokeOut, &revokeErr); err != nil {
		t.Fatalf("gateway --socket <sock> revoke failed: %v (stderr=%s)", err, revokeErr.String())
	}
	if !strings.Contains(revokeOut.String(), "revoked_flows=0") {
		t.Fatalf("unexpected revoke output: %s", revokeOut.String())
	}

	// Unexpected positional arguments and unknown flags are rejected across all subcommands.
	invalidCases := [][]string{
		{"--socket", sockPath, "status", "extra"},
		{"--socket", sockPath, "status", "--bogus"},
		{"status", "--socket", sockPath},
		{"--socket", sockPath, "reload", "extra"},
		{"--socket", sockPath, "reload", "--bogus"},
		{"--socket", sockPath, "flows", "extra"},
		{"--socket", sockPath, "flows", "--bogus"},
		{"--socket", sockPath, "grants", "extra"},
		{"--socket", sockPath, "grants", "--bogus"},
		{"--socket", sockPath, "revoke", "--principal", "worker-claude", "extra"},
		{"--socket", sockPath, "revoke", "--bogus"},
		{"--socket", sockPath, "grant", "--principal", "worker-claude", "--host", "example.com", "extra"},
		{"--socket", sockPath, "grant", "--bogus"},
		{"--socket", sockPath, "grant", "revoke"},
		{"--socket", sockPath, "grant", "revoke", "id1", "extra"},
		{"--socket", sockPath, "grant", "revoke", "--bogus"},
		{"ca", "init", "--cert", filepath.Join(dir, "c2.crt"), "--key", filepath.Join(dir, "c2.key"), "extra"},
		{"ca", "init", "--bogus"},
		{"dataplane", "check", "--config", cfgPath, "extra"},
		{"dataplane", "check", "--bogus"},
		{"run", "--config", cfgPath, "extra"},
		{"netsetup", "--config", cfgPath, "extra"},
		{"netsetup", "--config", cfgPath, "extra", "--dry-run"},
	}
	for _, args := range invalidCases {
		var out, errBuf bytes.Buffer
		err := run(context.Background(), args, &out, &errBuf)
		if err == nil {
			t.Errorf("expected gateway %v to fail with usage/flag error, got nil (stdout=%q)", args, out.String())
			continue
		}
		if !strings.Contains(err.Error(), "usage:") && !strings.Contains(err.Error(), "flag provided but not defined") {
			t.Errorf("gateway %v returned unexpected error %q (want usage or flag error)", args, err.Error())
		}
	}
}

type failingTestListener struct {
	err error
}

func (f failingTestListener) Accept() (net.Conn, error) { return nil, f.err }
func (f failingTestListener) Close() error              { return nil }
func (f failingTestListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestDaemonExitsNonZeroOnUnexpectedListenerError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	mitmCA, err := ca.Init(certPath, keyPath)
	if err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	auditDir := filepath.Join(dir, "audit")
	sockPath := filepath.Join(dir, "admin", "admin.sock")
	linkPorts := freePorts(t, "127.0.29.1", 3)
	metricsPort := freePorts(t, "127.0.0.1", 1)[0]

	cfgYAML := fmt.Sprintf(`
ca:
  cert_path: %s
  key_path: %s
audit:
  dir: %s
admin:
  socket: %s
metrics:
  listen: 127.0.0.1:%d
links:
  - name: sbx0
    principal: worker-claude
    subnet: 127.0.29.0/28
    gateway_ip: 127.0.29.1
    https_port: %d
    http_port: %d
    dns_port: %d
rules:
  - id: r1
    principal: worker-claude
    effect: allow
    hosts: [api.anthropic.com]
    ports: [443]
`, certPath, keyPath, auditDir, sockPath, metricsPort, linkPorts[0], linkPorts[1], linkPorts[2])
	cfgPath := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	store, err := config.NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	cfg := store.Current().Config
	aw, err := audit.NewWriter(audit.Options{Dir: auditDir})
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}
	flows := proxy.NewFlowRegistry()
	collector := metrics.NewCollector(metrics.Options{})
	rt := &daemonRuntime{auditWriter: aw}
	serveErrCh := make(chan error, 1)
	reportServeErr := func(e error) {
		select {
		case serveErrCh <- e:
		default:
		}
	}
	alloc, err := gwdns.NewAllocator(cfg.FakePrefix)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	eval := policy.NewEvaluator(store)
	leaves := ca.NewLeafCache(mitmCA)
	dialer := netguard.NewDialer(netguard.Options{Store: store})
	if err := rt.startLinks(cfg, store, eval, alloc, leaves, dialer, flows, collector, reportServeErr); err != nil {
		t.Fatalf("startLinks: %v", err)
	}
	if err := rt.startControl(cfg, store, flows, collector, reportServeErr); err != nil {
		t.Fatalf("startControl: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runCtx, runCancel := context.WithCancel(ctx)
	var bgWG sync.WaitGroup
	bgWG.Add(1)
	go func() {
		defer bgWG.Done()
		store.RunGrantPruner(runCtx, 50*time.Millisecond)
	}()

	permErr := errors.New("accept EMFILE permanent failure")
	go func() {
		if sErr := (&http.Server{}).Serve(failingTestListener{err: permErr}); sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
			reportServeErr(fmt.Errorf("proxy(sbx0/https): %w", sErr))
		}
	}()

	var stderr bytes.Buffer
	gotErr := rt.waitAndShutdown(ctx, runCancel, &bgWG, serveErrCh, &stderr)
	if !errors.Is(gotErr, permErr) {
		t.Fatalf("waitAndShutdown err = %v, want wrapped %v (non-zero exit)", gotErr, permErr)
	}
	if !strings.Contains(stderr.String(), "fatal listener error") || !strings.Contains(stderr.String(), permErr.Error()) {
		t.Fatalf("stderr = %q, want fatal listener error message", stderr.String())
	}

	entries, err := filepath.Glob(filepath.Join(auditDir, "*.jsonl"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("glob audit jsonl: %v (entries=%v)", err, entries)
	}
	var sawListenerErr bool
	for _, p := range entries {
		raw, rErr := os.ReadFile(p)
		if rErr != nil {
			t.Fatalf("read audit %s: %v", p, rErr)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if line == "" {
				continue
			}
			var ev audit.Event
			if uErr := json.Unmarshal([]byte(line), &ev); uErr != nil {
				t.Fatalf("unmarshal audit line: %v", uErr)
			}
			if ev.Kind == audit.KindLifecycle && ev.Reason == "listener-error" && strings.Contains(ev.Error, permErr.Error()) {
				sawListenerErr = true
			}
		}
	}
	if !sawListenerErr {
		t.Fatalf("missing audit lifecycle event with reason=listener-error and error containing %q", permErr.Error())
	}
}

type grantExpiredOrderSpy struct {
	flows          *proxy.FlowRegistry
	seen           atomic.Bool
	flowsAtAudit   atomic.Int64
}

func (s *grantExpiredOrderSpy) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(`"reason":"grant-expired"`)) {
		s.flowsAtAudit.Store(int64(s.flows.Count()))
		s.seen.Store(true)
	}
	return len(p), nil
}

func TestGrantExpiryTearsDownFlowsBeforeAuditWrite(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	mitmCA, err := ca.Init(certPath, keyPath)
	if err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	auditDir := filepath.Join(dir, "audit")
	linkPorts := freePorts(t, "127.0.30.1", 3)

	streamOpen := make(chan struct{})
	releaseUp := make(chan struct{})
	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, wErr := io.WriteString(w, "open\n"); wErr != nil {
			return
		}
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		close(streamOpen)
		select {
		case <-r.Context().Done():
		case <-releaseUp:
		}
	}))
	t.Cleanup(func() {
		close(releaseUp)
		upSrv.Close()
	})

	cfgYAML := fmt.Sprintf(`
ca:
  cert_path: %s
  key_path: %s
audit:
  dir: %s
links:
  - name: sbx0
    principal: worker-claude
    subnet: 127.0.30.0/28
    gateway_ip: 127.0.30.1
    https_port: %d
    http_port: %d
    dns_port: %d
`, certPath, keyPath, auditDir, linkPorts[0], linkPorts[1], linkPorts[2])
	cfgPath := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	store, err := config.NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	flows := proxy.NewFlowRegistry()
	spy := &grantExpiredOrderSpy{flows: flows}
	spy.flowsAtAudit.Store(-1)
	aw, err := audit.NewWriter(audit.Options{Dir: auditDir, Stdout: spy})
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}
	t.Cleanup(func() {
		if cErr := aw.Close(); cErr != nil {
			t.Errorf("audit close: %v", cErr)
		}
	})

	eval := policy.NewEvaluator(store)
	pSrv, err := proxy.NewServer(proxy.Options{
		Link:      store.Current().Config.Links[0],
		Store:     store,
		Evaluator: eval,
		Audit:     aw,
		Leaves:    ca.NewLeafCache(mitmCA),
		Flows:     flows,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upSrv.Listener.Addr().String())
		},
	})
	if err != nil {
		t.Fatalf("proxy.NewServer: %v", err)
	}
	if err := pSrv.Start(); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	t.Cleanup(func() {
		sCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer sCancel()
		if sErr := pSrv.Shutdown(sCtx); sErr != nil {
			t.Errorf("proxy.Shutdown: %v", sErr)
		}
	})

	registerDaemonCallbacks(store, eval, flows, []*proxy.Server{pSrv}, aw, &bytes.Buffer{})

	if _, err := store.AddGrant("worker-claude", "order.example.com", 80, nil, nil, 80*time.Millisecond, false); err != nil {
		t.Fatalf("AddGrant: %v", err)
	}
	httpAddr := fmt.Sprintf("127.0.30.1:%d", linkPorts[1])
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, httpAddr)
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://order.example.com/hold", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatalf("Do /hold: %v", err)
	}
	<-streamOpen

	time.Sleep(110 * time.Millisecond)
	store.PruneExpiredGrants()
	if _, rErr := io.ReadAll(resp.Body); rErr == nil {
		t.Log("stream closed with EOF")
	}
	if cErr := resp.Body.Close(); cErr != nil {
		t.Logf("close resp body: %v", cErr)
	}

	if !spy.seen.Load() {
		t.Fatal("grant-expired audit line was not observed")
	}
	if got := spy.flowsAtAudit.Load(); got != 0 {
		t.Fatalf("flows.Count() during grant-expired audit write = %d, want 0 (teardown must run before audit write)", got)
	}
}
