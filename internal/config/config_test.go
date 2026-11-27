package config_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/manufactory-project/gateway/internal/config"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

const validYAML = `
ca:
  cert_path: /etc/gatewayd/ca/ca.crt
  key_path: /etc/gatewayd/ca/ca.key
audit:
  dir: /var/log/gatewayd/audit
metrics:
  listen: 127.0.0.1:9102
dataplane:
  ready_file: /run/gatewayd/dataplane.ready
  dhcp:
    user: dnsmasq
    lease_file: /var/lib/gatewayd/dnsmasq.leases
    config_path: /run/gatewayd/dnsmasq.conf
records:
  forge.internal.example: 10.10.20.5
links:
  - name: sbx0
    interface: sbx0
    principal: worker-claude
    subnet: 10.200.0.0/28
    gateway_ip: 10.200.0.1
    ct_zone: 101
    route_table: 101
  - name: sbx1
    interface: sbx1
    principal: worker-codex
    subnet: 10.200.0.16/28
    gateway_ip: 10.200.0.17
    ct_zone: 102
    route_table: 102
rules:
  - id: forgejo
    principal: worker-claude
    effect: allow
    hosts: [forge.internal.example]
    ports: [443]
    bindings:
      - name: forgejo-token
        host: forge.internal.example
        header: Authorization
        scheme: basic
        placeholder: mf_ph_forgejo
        secret_file: /run/credentials/gatewayd/forgejo
  - id: codex-ws
    principal: worker-codex
    effect: allow
    hosts: [chatgpt.com]
    ports: [443]
    allow_websocket: true
  - id: http-optin
    principal: worker-claude
    effect: allow
    hosts: [deb.debian.org]
    ports: [80]
`

func TestParseValidAndDefaults(t *testing.T) {
	cfg, err := config.Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse valid YAML: %v", err)
	}
	if cfg.DNS.FakeCIDR != config.DefaultFakeCIDR {
		t.Fatalf("default fake_cidr = %q, want %q", cfg.DNS.FakeCIDR, config.DefaultFakeCIDR)
	}
	if cfg.HTTP.MaxRequestBodyBytes != config.DefaultMaxRequestBodyBytes {
		t.Fatalf("default max_request_body_bytes = %d, want %d", cfg.HTTP.MaxRequestBodyBytes, config.DefaultMaxRequestBodyBytes)
	}
	if cfg.HTTP.WSMaxEgressBytes != config.DefaultWSMaxEgressBytes {
		t.Fatalf("default ws_max_egress_bytes = %d, want %d", cfg.HTTP.WSMaxEgressBytes, config.DefaultWSMaxEgressBytes)
	}
	if got := cfg.ParsedRecords["forge.internal.example"].String(); got != "10.10.20.5" {
		t.Fatalf("parsed record = %q, want 10.10.20.5", got)
	}
}

func TestConfigValidationInvariants(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantError string
	}{
		{
			name:      "reject removed private_ip_pin field",
			yaml:      strings.Replace(validYAML, "ports: [443]\n    bindings:", "ports: [443]\n    private_ip_pin: true\n    bindings:", 1),
			wantError: "private_ip_pin",
		},
		{
			name:      "reject removed cleartext field",
			yaml:      strings.Replace(validYAML, "ports: [80]", "ports: [80]\n    cleartext: true", 1),
			wantError: "cleartext",
		},
		{
			name:      "reject ports outside 80 and 443",
			yaml:      strings.Replace(validYAML, "ports: [80]", "ports: [8080]", 1),
			wantError: "only 80 and 443",
		},
		{
			name:      "reject allow_websocket on rule with binding",
			yaml:      strings.Replace(validYAML, "ports: [443]\n    bindings:", "ports: [443]\n    allow_websocket: true\n    bindings:", 1),
			wantError: "cannot set allow_websocket",
		},
		{
			name:      "reject binding host not in rule hosts",
			yaml:      strings.Replace(validYAML, "host: forge.internal.example", "host: other.example.com", 1),
			wantError: "must be one of the rule's hosts",
		},
		{
			name:      "reject rule principal with no declared link",
			yaml:      strings.Replace(validYAML, "principal: worker-codex\n    effect: allow", "principal: ghost-worker\n    effect: allow", 1),
			wantError: "does not match any declared link",
		},
		{
			name:      "reject overlapping link subnets",
			yaml:      strings.Replace(validYAML, "subnet: 10.200.0.16/28\n    gateway_ip: 10.200.0.17", "subnet: 10.200.0.0/24\n    gateway_ip: 10.200.0.20", 1),
			wantError: "overlaps subnet",
		},
		{
			name:      "reject wildcard metrics listener",
			yaml:      strings.Replace(validYAML, "listen: 127.0.0.1:9102", "listen: 0.0.0.0:9102", 1),
			wantError: "wildcard listen address",
		},
		{
			name:      "reject /32 link subnet",
			yaml:      strings.Replace(validYAML, "subnet: 10.200.0.0/28", "subnet: 10.200.0.1/32", 1),
			wantError: "/29 or larger",
		},
		{
			name:      "reject cross-rule websocket on bound host",
			yaml:      validYAML + "\n  - id: conflict-ws\n    principal: worker-claude\n    effect: allow\n    hosts: [forge.internal.example]\n    ports: [443]\n    allow_websocket: true\n",
			wantError: "conflicts with binding",
		},
		{
			name:      "reject duplicate placeholder across bindings",
			yaml:      validYAML + "\n  - id: dup-ph\n    principal: worker-codex\n    effect: allow\n    hosts: [api.example.com]\n    ports: [443]\n    bindings:\n      - name: b2\n        host: api.example.com\n        header: Authorization\n        scheme: bearer\n        placeholder: mf_ph_forgejo\n        secret_file: /run/credentials/gatewayd/other\n",
			wantError: "duplicate placeholder",
		},
		{
			name:      "reject missing ready_file when Linux link exists",
			yaml:      strings.Replace(validYAML, "  ready_file: /run/gatewayd/dataplane.ready\n", "", 1),
			wantError: "dataplane.ready_file",
		},
		{
			name:      "reject v4-mapped wildcard metrics listener",
			yaml:      strings.Replace(validYAML, "listen: 127.0.0.1:9102", "listen: \"[::ffff:0.0.0.0]:9102\"", 1),
			wantError: "wildcard listen address",
		},
		{
			name:      "reject dot in interface name",
			yaml:      strings.Replace(validYAML, "interface: sbx0", "interface: sbx0.1", 1),
			wantError: "interface",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := config.Parse([]byte(tc.yaml)); err == nil {
				t.Fatalf("expected Parse to fail with %q, got nil", tc.wantError)
			} else if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantError)
			}
		})
	}
}

func TestStoreSIGHUPReloadWipesGrantsAndKeepsOldOnInvalid(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gatewayd.yaml")
	if err := os.WriteFile(cfgPath, []byte(validYAML), 0o600); err != nil {
		t.Fatalf("write initial yaml: %v", err)
	}

	var nowNano atomic.Int64
	nowNano.Store(time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC).UnixNano())
	store, err := config.NewStoreWithClock(cfgPath, func() time.Time { return time.Unix(0, nowNano.Load()).UTC() })
	if err != nil {
		t.Fatalf("NewStoreWithClock: %v", err)
	}
	initialHash := store.Current().Hash

	// Positive control: ephemeral TTL grant is active before reload and expires when clock passes TTL.
	g1, err := store.AddGrant("worker-claude", "login.anthropic.com", 443, []string{"GET"}, []string{"/oauth/**"}, 5*time.Minute)
	if err != nil {
		t.Fatalf("AddGrant: %v", err)
	}
	if len(store.ActiveGrants()) != 1 {
		t.Fatalf("expected 1 active grant, got %d", len(store.ActiveGrants()))
	}

	// Containment: invalid reload leaves prior snapshot AND grant intact.
	if err := os.WriteFile(cfgPath, []byte("invalid: [yaml\n"), 0o600); err != nil {
		t.Fatalf("write broken yaml: %v", err)
	}
	if _, _, err := store.Reload(); err == nil {
		t.Fatal("expected Reload on broken YAML to fail")
	}
	if store.Current().Hash != initialHash {
		t.Fatal("failed Reload mutated active snapshot")
	}
	if len(store.ActiveGrants()) != 1 {
		t.Fatal("failed Reload wiped active grants")
	}

	// Wire WatchSIGHUP and trigger a real SIGHUP after updating config.
	updatedYAML := strings.Replace(validYAML, "deb.debian.org", "archive.ubuntu.com", 1)
	if err := os.WriteFile(cfgPath, []byte(updatedYAML), 0o600); err != nil {
		t.Fatalf("write updated yaml: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	reloaded := make(chan []string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		store.WatchSIGHUP(ctx, func(_ *config.Snapshot, wiped []string, err error) {
			if err != nil {
				t.Errorf("SIGHUP reload error: %v", err)
				return
			}
			reloaded <- wiped
		})
	}()
	// Brief yield so signal.Notify is registered before raising SIGHUP.
	time.Sleep(25 * time.Millisecond)

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		cancel()
		<-done
		t.Fatalf("send SIGHUP: %v", err)
	}

	select {
	case wiped := <-reloaded:
		if len(wiped) != 1 || wiped[0] != g1.ID {
			t.Fatalf("wiped grants = %v, want [%s]", wiped, g1.ID)
		}
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("timed out waiting for SIGHUP reload")
	}

	cancel()
	<-done

	if store.Current().Hash == initialHash {
		t.Fatal("SIGHUP did not swap config snapshot")
	}
	if len(store.ActiveGrants()) != 0 {
		t.Fatalf("SIGHUP did not wipe grants, still have %d", len(store.ActiveGrants()))
	}

	// Verify grant TTL expiry fires callback cleanly.
	var expiredID string
	store.SetOnGrantExpired(func(id string) { expiredID = id })
	g2, err := store.AddGrant("worker-codex", "auth.openai.com", 443, nil, nil, 1*time.Minute)
	if err != nil {
		t.Fatalf("AddGrant g2: %v", err)
	}
	nowNano.Add(int64(2 * time.Minute))
	if got := store.ActiveGrants(); len(got) != 0 {
		t.Fatalf("expected expired grant to be pruned, got %+v", got)
	}
	if expiredID != g2.ID {
		t.Fatalf("expired callback id = %q, want %q", expiredID, g2.ID)
	}
}

func TestReloadRefusesImmutableSectionsConcurrentGrantAndMultiCallbacks(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gatewayd.yaml")
	if err := os.WriteFile(cfgPath, []byte(validYAML), 0o600); err != nil {
		t.Fatalf("write validYAML: %v", err)
	}

	var nowNano atomic.Int64
	nowNano.Store(time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC).UnixNano())
	store, err := config.NewStoreWithClock(cfgPath, func() time.Time { return time.Unix(0, nowNano.Load()).UTC() })
	if err != nil {
		t.Fatalf("NewStoreWithClock: %v", err)
	}
	origHash := store.Current().Hash

	// Every restart-only section change must be refused and keep the old snapshot + grants.
	gKeep, err := store.AddGrant("worker-claude", "keep.example.com", 443, nil, nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("AddGrant: %v", err)
	}

	immutableChanges := []struct {
		name string
		yaml string
	}{
		{"ca", strings.Replace(validYAML, "/etc/gatewayd/ca/ca.crt", "/etc/gatewayd/ca/new.crt", 1)},
		{"audit", strings.Replace(validYAML, "/var/log/gatewayd/audit", "/var/log/gatewayd/audit2", 1)},
		{"admin", validYAML + "\nadmin:\n  socket: /run/gatewayd/other.sock\n"},
		{"metrics", strings.Replace(validYAML, "127.0.0.1:9102", "127.0.0.1:9103", 1)},
		{"fake_cidr", validYAML + "\ndns:\n  fake_cidr: 198.19.0.0/16\n"},
		{"links_gateway_ip", strings.Replace(validYAML, "gateway_ip: 10.200.0.1", "gateway_ip: 10.200.0.2", 1)},
		{"principals", strings.ReplaceAll(validYAML, "worker-codex", "worker-renamed")},
		{"dataplane_ready_file", strings.Replace(validYAML, "/run/gatewayd/dataplane.ready", "/run/gatewayd/other.ready", 1)},
		{"dataplane_dhcp", strings.Replace(validYAML, "user: dnsmasq", "user: nobody", 1)},
		{"dataplane_verify_sysctls", strings.Replace(validYAML, "dataplane:\n", "dataplane:\n  verify_sysctls: false\n", 1)},
		{"http_max_header_bytes", validYAML + "\nhttp:\n  max_header_bytes: 65536\n"},
	}
	for _, tc := range immutableChanges {
		t.Run("refuse_"+tc.name, func(t *testing.T) {
			if err := os.WriteFile(cfgPath, []byte(tc.yaml), 0o600); err != nil {
				t.Fatalf("write %s yaml: %v", tc.name, err)
			}
			if _, _, err := store.Reload(); err == nil {
				t.Fatalf("expected Reload to refuse %s change", tc.name)
			}
			if store.Current().Hash != origHash {
				t.Fatalf("refused %s reload mutated snapshot hash", tc.name)
			}
			grants := store.ActiveGrants()
			if len(grants) != 1 || grants[0].ID != gKeep.ID {
				t.Fatalf("refused %s reload altered grants: %+v", tc.name, grants)
			}
		})
	}

	// Positive control: hot-reloading rules/records and per-request HTTP limits succeeds and wipes grants.
	ruleUpdated := strings.Replace(validYAML, "deb.debian.org", "security.debian.org", 1) + "\nhttp:\n  max_request_body_bytes: 1048576\n  ws_max_egress_bytes: 2097152\n"
	if err := os.WriteFile(cfgPath, []byte(ruleUpdated), 0o600); err != nil {
		t.Fatalf("write ruleUpdated: %v", err)
	}
	if _, wiped, err := store.Reload(); err != nil || len(wiped) != 1 {
		t.Fatalf("rule reload = (wiped=%v, err=%v), want 1 wiped grant and nil err", wiped, err)
	}

	// Multiple SetOnGrantExpired callbacks (e.g. across links) must ALL fire on expiry via a single RunGrantPruner loop.
	cb1Ch := make(chan string, 2)
	cb2Ch := make(chan string, 2)
	store.SetOnGrantExpired(func(id string) { cb1Ch <- id })
	store.SetOnGrantExpired(func(id string) { cb2Ch <- id })
	gExp, err := store.AddGrant("worker-claude", "exp.example.com", 443, nil, nil, time.Minute)
	if err != nil {
		t.Fatalf("AddGrant exp: %v", err)
	}
	pruneCtx, pruneCancel := context.WithCancel(context.Background())
	pruneDone := make(chan struct{})
	go func() {
		defer close(pruneDone)
		store.RunGrantPruner(pruneCtx, 10*time.Millisecond)
	}()
	nowNano.Add(int64(2 * time.Minute))
	select {
	case got := <-cb1Ch:
		if got != gExp.ID {
			pruneCancel()
			<-pruneDone
			t.Fatalf("cb1 got %q, want %q", got, gExp.ID)
		}
	case <-time.After(2 * time.Second):
		pruneCancel()
		<-pruneDone
		t.Fatal("timed out waiting for cb1 from RunGrantPruner")
	}
	select {
	case got := <-cb2Ch:
		if got != gExp.ID {
			pruneCancel()
			<-pruneDone
			t.Fatalf("cb2 got %q, want %q", got, gExp.ID)
		}
	case <-time.After(2 * time.Second):
		pruneCancel()
		<-pruneDone
		t.Fatal("timed out waiting for cb2 from RunGrantPruner")
	}
	pruneCancel()
	<-pruneDone

	// Concurrent AddGrant vs Reload must be race-free and never leave stale grants after a final Reload.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 40; i++ {
			if _, gErr := store.AddGrant("worker-claude", "race.example.com", 443, nil, nil, time.Minute); gErr != nil {
				continue
			}
		}
	}()
	for i := 0; i < 15; i++ {
		if _, _, rErr := store.Reload(); rErr != nil {
			t.Fatalf("concurrent Reload %d: %v", i, rErr)
		}
	}
	<-done
	if _, _, err := store.Reload(); err != nil {
		t.Fatalf("final Reload: %v", err)
	}
	if rem := store.ActiveGrants(); len(rem) != 0 {
		t.Fatalf("grants survived final Reload: %+v", rem)
	}
}
