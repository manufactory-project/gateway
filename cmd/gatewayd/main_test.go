package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/manufactory-project/gateway/internal/admin"
	"github.com/manufactory-project/gateway/internal/ca"
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

func TestGatewaydNetsetupDryRunAndStartupGuards(t *testing.T) {
	dir := t.TempDir()

	// 1. `gatewayd netsetup --dry-run` against example config (with sample IP).
	rawEx, err := os.ReadFile(filepath.Join("..", "..", "examples", "gatewayd.yaml"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	exPath := filepath.Join(dir, "example.yaml")
	if err := os.WriteFile(exPath, []byte(strings.ReplaceAll(string(rawEx), "<forge-ip>", "10.10.20.5")), 0o600); err != nil {
		t.Fatalf("write example copy: %v", err)
	}
	var dryOut, dryErr bytes.Buffer
	if err := run([]string{"netsetup", "--config", exPath, "--dry-run"}, &dryOut, &dryErr); err != nil {
		t.Fatalf("gatewayd netsetup --dry-run: %v (stderr=%s)", err, dryErr.String())
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

	// 2. Daemon refuses to start when ready_file is missing (dataplane not applied).
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if _, err := ca.Init(certPath, keyPath); err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	auditDir := filepath.Join(dir, "audit")
	sockPath := filepath.Join(dir, "admin.sock")
	readyFile := filepath.Join(dir, "dataplane.ready")

	httpsPort := freePort(t, "127.0.26.1")
	httpPort := freePort(t, "127.0.26.1")
	dnsPort := freePort(t, "127.0.26.1")
	metricsPort := freePort(t, "127.0.0.1")

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
  verify_sysctls: false
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
