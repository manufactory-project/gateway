// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/admin"
	"github.com/manufactory-project/gateway/internal/ca"
)

type daemonFixture struct {
	cfgPath, procSys, sock, auditDir string
}

func newDaemonFixture(t *testing.T) daemonFixture {
	t.Helper()
	dir := t.TempDir()
	if _, err := ca.Init(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	f := daemonFixture{
		sock:     filepath.Join(dir, "admin", "admin.sock"),
		auditDir: filepath.Join(dir, "audit"),
		cfgPath:  filepath.Join(dir, "gateway.yaml"),
	}
	ready := filepath.Join(dir, "dataplane", "dataplane.ready")
	if err := os.MkdirAll(filepath.Dir(ready), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(ready, []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("write ready: %v", err)
	}
	ports := freePorts(t, "127.0.33.1", 3)
	yaml := fmt.Sprintf(`
ca:
  cert_path: %s
  key_path: %s
audit:
  dir: %s
  stdout_json: true
admin:
  socket: %s
dataplane:
  ready_file: %s
  dhcp: {user: dnsmasq, lease_file: /var/lib/gateway/dnsmasq.leases}
links:
  - name: sbx0
    interface: t330
    ct_zone: 330
    route_table: 330
    principal: worker-claude
    subnet: 127.0.33.0/28
    gateway_ip: 127.0.33.1
    https_port: %d
    http_port: %d
    dns_port: %d
rules:
  - id: r1
    principal: worker-claude
    effect: allow
    hosts: [api.anthropic.com]
    ports: [443]
`, filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), f.auditDir, f.sock, ready, ports[0], ports[1], ports[2])
	if err := os.WriteFile(f.cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	f.procSys = fakeSysctls(t, f.cfgPath)
	return f
}

// TestDaemonSignalsReadyOnlyOnceAdminSocketServes pins that the systemd readiness
// notification arrives after the admin socket answers, so `systemctl start`
// followed by `gateway status` cannot race the socket's creation.
func TestDaemonSignalsReadyOnlyOnceAdminSocketServes(t *testing.T) {
	f := newDaemonFixture(t)
	notify := filepath.Join(t.TempDir(), "notify.sock")
	pc, err := net.ListenPacket("unixgram", notify)
	if err != nil {
		t.Fatalf("listen notify: %v", err)
	}
	defer func() {
		if err := pc.Close(); err != nil {
			t.Errorf("close notify: %v", err)
		}
	}()
	t.Setenv("NOTIFY_SOCKET", notify)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveDaemon(ctx, nil, f.cfgPath, f.procSys, &bytes.Buffer{}, &bytes.Buffer{}) }()

	if err := pc.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 64)
	n, _, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "READY=1" {
		cancel()
		<-done
		t.Fatalf("notification = %q, err %v, want READY=1", buf[:n], err)
	}
	client := admin.NewClient(f.sock)
	_, statusErr := client.Status(context.Background())
	client.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serveDaemon: %v", err)
	}
	if statusErr != nil {
		t.Fatalf("admin status at the moment of READY=1: %v", statusErr)
	}
}

// TestDaemonAppliesSIGHUPReceivedBeforeReady pins that a reload requested while the
// daemon is still starting is queued and applied once it is ready, not lost.
func TestDaemonAppliesSIGHUPReceivedBeforeReady(t *testing.T) {
	f := newDaemonFixture(t)
	hup := make(chan os.Signal, 1)
	hup <- syscall.SIGHUP // arrives before serveDaemon has begun

	records := newRecordSignal()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveDaemon(ctx, hup, f.cfgPath, f.procSys, records, &bytes.Buffer{}) }()

	applied := records.until(10*time.Second, func() bool {
		return auditContains(t, f.auditDir, `"reason":"sighup-reload"`)
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serveDaemon: %v", err)
	}
	if !applied {
		t.Fatal("the SIGHUP received before ready was never applied")
	}
}
