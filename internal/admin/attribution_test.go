// SPDX-License-Identifier: AGPL-3.0-only

package admin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/manufactory-project/gateway/internal/admin"
	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/config"
)

// recordingFlows is a FlowManager that records the grants whose flows were revoked.
type recordingFlows struct {
	mu      sync.Mutex
	granted []string
}

func (*recordingFlows) ListFlows() []admin.FlowInfo          { return nil }
func (*recordingFlows) CountFlows() int                      { return 0 }
func (*recordingFlows) RevokeByID(string) int                { return 0 }
func (*recordingFlows) RevokeByPrincipal(string, string) int { return 0 }
func (r *recordingFlows) RevokeByGrant(id string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.granted = append(r.granted, id)
	return 1
}

type adminEnv struct {
	store  *config.Store
	audit  *audit.Writer
	flows  *recordingFlows
	client *admin.Client
	dir    string
	sock   string
}

func newAdminEnv(t *testing.T, opts admin.Options) *adminEnv {
	t.Helper()
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	cfgPath := filepath.Join(dir, "gateway.yaml")
	yaml := fmt.Sprintf(`
ca:
  cert_path: /tmp/ca.crt
  key_path: /tmp/ca.key
audit:
  dir: %s
dataplane:
  ready_file: /run/gateway-dataplane/dataplane.ready
  dhcp: {user: dnsmasq, lease_file: /var/lib/gateway/dnsmasq.leases}
links:
  - name: sbx0
    interface: t301
    ct_zone: 301
    route_table: 301
    principal: worker-test
    subnet: 127.0.31.0/28
    gateway_ip: 127.0.31.1
`, auditDir)
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
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
	flows := &recordingFlows{}
	sock := filepath.Join(dir, "run", "admin.sock")
	opts.SocketPath, opts.Store, opts.Flows, opts.Audit = sock, store, flows, aw
	opts.OnServeError = func(err error) { t.Errorf("serve error: %v", err) }
	srv, err := admin.NewServer(opts)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	client := admin.NewClient(sock)
	t.Cleanup(func() {
		client.Close()
		if err := srv.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	return &adminEnv{store: store, audit: aw, flows: flows, client: client, dir: dir, sock: sock}
}

func (e *adminEnv) events(t *testing.T) []audit.Event {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(e.dir, "audit", "*.jsonl"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var out []audit.Event
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			var ev audit.Event
			if line != "" {
				if err := json.Unmarshal([]byte(line), &ev); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				out = append(out, ev)
			}
		}
	}
	return out
}

func grantReq(ttl string) admin.GrantRequest {
	return admin.GrantRequest{Principal: "worker-test", Host: "api.example.com", Port: 443, TTL: ttl}
}

// TestAdminAuditNamesTheCaller pins that every admin audit record carries the
// uid and pid the kernel reports for the connecting process.
func TestAdminAuditNamesTheCaller(t *testing.T) {
	e := newAdminEnv(t, admin.Options{})
	ctx := context.Background()
	if _, err := e.client.CreateGrant(ctx, grantReq("5m")); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	if _, err := e.client.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	g2, err := e.client.CreateGrant(ctx, grantReq("5m"))
	if err != nil {
		t.Fatalf("CreateGrant 2: %v", err)
	}
	if _, err := e.client.Revoke(ctx, admin.RevokeRequest{GrantID: g2.ID}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	g3, err := e.client.CreateGrant(ctx, grantReq("5m"))
	if err != nil {
		t.Fatalf("CreateGrant 3: %v", err)
	}
	if _, err := e.client.DeleteGrant(ctx, g3.ID); err != nil {
		t.Fatalf("DeleteGrant: %v", err)
	}

	var seen int
	for _, ev := range e.events(t) {
		if ev.Kind != audit.KindGrant && ev.Kind != audit.KindRevoke && ev.Reason != "reload" {
			continue
		}
		seen++
		if ev.PeerUID == nil || *ev.PeerUID != os.Getuid() || ev.PeerPID == nil || *ev.PeerPID != os.Getpid() {
			t.Errorf("event %s/%s: peer = (%v, %v), want (%d, %d)", ev.Kind, ev.Reason, ev.PeerUID, ev.PeerPID, os.Getuid(), os.Getpid())
		}
	}
	if seen < 6 {
		t.Fatalf("saw only %d admin events, want at least 6", seen)
	}
}

// TestAdminCapsGrantTTLAndCount pins the grant limits and that a refusal is audited.
func TestAdminCapsGrantTTLAndCount(t *testing.T) {
	e := newAdminEnv(t, admin.Options{MaxGrantTTL: 10 * 60 * 1e9, MaxGrants: 2})
	ctx := context.Background()
	if _, err := e.client.CreateGrant(ctx, grantReq("10m")); err != nil {
		t.Fatalf("control: grant at the TTL cap must work: %v", err)
	}
	if _, err := e.client.CreateGrant(ctx, grantReq("10m1s")); err == nil || !strings.Contains(err.Error(), "grant-ttl-exceeds-max") {
		t.Fatalf("over-cap TTL: err = %v, want grant-ttl-exceeds-max", err)
	}
	if _, err := e.client.CreateGrant(ctx, grantReq("1m")); err != nil {
		t.Fatalf("control: second grant within the count cap must work: %v", err)
	}
	if _, err := e.client.CreateGrant(ctx, grantReq("1m")); err == nil || !strings.Contains(err.Error(), "grant-limit-reached") {
		t.Fatalf("third grant: err = %v, want grant-limit-reached", err)
	}
	if got := len(e.store.ActiveGrants()); got != 2 {
		t.Fatalf("live grants = %d, want 2", got)
	}
	reasons := map[string]bool{}
	for _, ev := range e.events(t) {
		if ev.Kind == audit.KindGrant && ev.Effect == audit.EffectDeny {
			reasons[ev.Reason] = true
		}
	}
	if !reasons["grant-ttl-exceeds-max"] || !reasons["grant-limit-reached"] {
		t.Fatalf("refusals not audited: %v", reasons)
	}
}

// TestGrantIsNeverLiveWithoutItsAuditRecord pins that when the audit sink fails the
// grant is never created, so there is nothing to roll back and no flow to revoke.
func TestGrantIsNeverLiveWithoutItsAuditRecord(t *testing.T) {
	e := newAdminEnv(t, admin.Options{})
	ctx := context.Background()
	if _, err := e.client.CreateGrant(ctx, grantReq("5m")); err != nil {
		t.Fatalf("control: grant with a healthy sink: %v", err)
	}
	if err := e.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}
	if _, err := e.client.CreateGrant(ctx, grantReq("5m")); err == nil || !strings.Contains(err.Error(), "audit sink unavailable") {
		t.Fatalf("CreateGrant with a dead sink: err = %v, want audit sink unavailable", err)
	}
	if got := len(e.store.ActiveGrants()); got != 1 {
		t.Fatalf("live grants = %d, want only the control grant", got)
	}
}

// TestEveryGrantRevocationRevokesItsFlows pins that revoking a grant through either
// admin route also revokes the flows running under it.
func TestEveryGrantRevocationRevokesItsFlows(t *testing.T) {
	e := newAdminEnv(t, admin.Options{})
	ctx := context.Background()
	a, err := e.client.CreateGrant(ctx, grantReq("5m"))
	if err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	b, err := e.client.CreateGrant(ctx, grantReq("5m"))
	if err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	if _, err := e.client.Revoke(ctx, admin.RevokeRequest{GrantID: a.ID}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := e.client.DeleteGrant(ctx, b.ID); err != nil {
		t.Fatalf("DeleteGrant: %v", err)
	}
	e.flows.mu.Lock()
	defer e.flows.mu.Unlock()
	if len(e.flows.granted) != 2 || e.flows.granted[0] != a.ID || e.flows.granted[1] != b.ID {
		t.Fatalf("flows revoked for grants %v, want [%s %s]", e.flows.granted, a.ID, b.ID)
	}
	if got := len(e.store.ActiveGrants()); got != 0 {
		t.Fatalf("live grants = %d, want 0", got)
	}
}

// TestAdminSocketModeAndNoStagingLeftovers pins the socket's final mode under a
// permissive umask, and that the private staging directory is gone.
func TestAdminSocketModeAndNoStagingLeftovers(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	e := newAdminEnv(t, admin.Options{})
	fi, err := os.Stat(e.sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %v, want 0660", fi.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(e.sock))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("socket dir holds %d entries, want only the socket", len(entries))
	}
}
