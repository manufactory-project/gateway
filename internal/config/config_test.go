package config_test

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/manufactory-project/gateway/internal/config"
)

func TestMain(m *testing.M) {
	sighupSink := make(chan os.Signal, 1)
	signal.Notify(sighupSink, syscall.SIGHUP)
	defer signal.Stop(sighupSink)
	goleak.VerifyTestMain(m)
}

const validYAML = `
ca:
  cert_path: /etc/gateway/ca/ca.crt
  key_path: /etc/gateway/ca/ca.key
audit:
  dir: /var/log/gateway/audit
metrics:
  listen: 127.0.0.1:9102
dataplane:
  ready_file: /run/gateway-dataplane/dataplane.ready
  dhcp:
    user: dnsmasq
    lease_file: /var/lib/gateway/dnsmasq.leases
    config_path: /run/gateway-dataplane/dnsmasq.conf
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
        secret_file: /run/credentials/gateway/forgejo
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
			name:      "reject another principal's websocket on bound host",
			yaml:      validYAML + "\n  - id: other-ws\n    principal: worker-codex\n    effect: allow\n    hosts: [forge.internal.example]\n    ports: [443]\n    allow_websocket: true\n",
			wantError: "conflicts with binding",
		},
		{
			name:      "reject another principal's wildcard websocket covering bound host",
			yaml:      validYAML + "\n  - id: other-ws-wild\n    principal: worker-codex\n    effect: allow\n    hosts: [\"*.internal.example\"]\n    ports: [443]\n    allow_websocket: true\n",
			wantError: "conflicts with binding",
		},
		{
			name:      "reject duplicate placeholder across bindings",
			yaml:      validYAML + "\n  - id: dup-ph\n    principal: worker-codex\n    effect: allow\n    hosts: [api.example.com]\n    ports: [443]\n    bindings:\n      - name: b2\n        host: api.example.com\n        header: Authorization\n        scheme: bearer\n        placeholder: mf_ph_forgejo\n        secret_file: /run/credentials/gateway/other\n",
			wantError: "duplicate placeholder",
		},
		{
			name:      "reject link without interface",
			yaml:      strings.Replace(validYAML, "    interface: sbx0\n", "", 1),
			wantError: "links[sbx0].interface",
		},
		{
			name:      "reject zero ct_zone",
			yaml:      strings.Replace(validYAML, "ct_zone: 101", "ct_zone: 0", 1),
			wantError: "links[sbx0].ct_zone must be > 0",
		},
		{
			name:      "reject 0 route_table",
			yaml:      strings.Replace(validYAML, "route_table: 101", "route_table: 0", 1),
			wantError: "links[sbx0].route_table 0 is invalid",
		},
		{
			name:      "reject negative route_table",
			yaml:      strings.Replace(validYAML, "route_table: 101", "route_table: -1", 1),
			wantError: "links[sbx0].route_table -1 is invalid",
		},
		{
			name:      "reject 253 route_table",
			yaml:      strings.Replace(validYAML, "route_table: 101", "route_table: 253", 1),
			wantError: "links[sbx0].route_table 253 is invalid",
		},
		{
			name:      "reject 254 route_table",
			yaml:      strings.Replace(validYAML, "route_table: 101", "route_table: 254", 1),
			wantError: "links[sbx0].route_table 254 is invalid",
		},
		{
			name:      "reject 255 route_table",
			yaml:      strings.Replace(validYAML, "route_table: 101", "route_table: 255", 1),
			wantError: "links[sbx0].route_table 255 is invalid",
		},
		{
			name:      "reject missing dhcp.user",
			yaml:      strings.Replace(validYAML, "    user: dnsmasq\n", "", 1),
			wantError: "dataplane.dhcp.user",
		},
		{
			name:      "reject missing dhcp.lease_file",
			yaml:      strings.Replace(validYAML, "    lease_file: /var/lib/gateway/dnsmasq.leases\n", "", 1),
			wantError: "dataplane.dhcp.lease_file",
		},
		{
			name:      "reject missing ready_file when Linux link exists",
			yaml:      strings.Replace(validYAML, "  ready_file: /run/gateway-dataplane/dataplane.ready\n", "", 1),
			wantError: "dataplane.ready_file",
		},
		{
			name:      "reject ready_file inside admin.socket directory",
			yaml:      strings.Replace(validYAML, "  ready_file: /run/gateway-dataplane/dataplane.ready", "  ready_file: /run/gateway/dataplane.ready", 1) + "\nadmin:\n  socket: /run/gateway/admin.sock\n",
			wantError: "must not be inside admin.socket directory",
		},
		{
			name:      "reject relative state_file",
			yaml:      strings.Replace(validYAML, "  ready_file:", "  state_file: links.json\n  ready_file:", 1),
			wantError: "dataplane.state_file",
		},
		{
			name:      "reject state_file inside admin.socket directory",
			yaml:      strings.Replace(validYAML, "  ready_file:", "  state_file: /run/gateway/links.json\n  ready_file:", 1) + "\nadmin:\n  socket: /run/gateway/admin.sock\n",
			wantError: "must not be inside admin.socket directory",
		},
		{
			name:      "reject dhcp.config_path inside admin.socket directory",
			yaml:      strings.Replace(validYAML, "    config_path: /run/gateway-dataplane/dnsmasq.conf", "    config_path: /run/gateway/dnsmasq.conf", 1) + "\nadmin:\n  socket: /run/gateway/admin.sock\n",
			wantError: "must not be inside admin.socket directory",
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
		{
			name:      "reject two double-stars in rule path",
			yaml:      strings.Replace(validYAML, "hosts: [deb.debian.org]", "hosts: [deb.debian.org]\n    paths: [\"/**/a/**\"]", 1),
			wantError: "at most one '**'",
		},
		{
			name:      "reject five single-stars in one segment",
			yaml:      strings.Replace(validYAML, "hosts: [deb.debian.org]", "hosts: [deb.debian.org]\n    paths: [\"/*a*b*c*d*e\"]", 1),
			wantError: "max 4",
		},
		{
			name:      "reject negative audit.max_total_bytes",
			yaml:      strings.Replace(validYAML, "  dir: /var/log/gateway/audit", "  dir: /var/log/gateway/audit\n  max_total_bytes: -1", 1),
			wantError: "max_total_bytes",
		},
		{
			name:      "reject negative http.max_conns_per_link",
			yaml:      validYAML + "\nhttp:\n  max_conns_per_link: -5\n",
			wantError: "max_conns_per_link",
		},
		{
			name:      "reject invalid http.upstream_response_header_timeout",
			yaml:      validYAML + "\nhttp:\n  upstream_response_header_timeout: notaduration\n",
			wantError: "upstream_response_header_timeout",
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

func TestReloadRefusesLinkWithoutInterface(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.WriteFile(cfgPath, []byte(validYAML), 0o600); err != nil {
		t.Fatalf("write initial yaml: %v", err)
	}
	store, err := config.NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	before := store.Current()

	unguarded := strings.Replace(validYAML, "    interface: sbx0\n", "", 1)
	if err := os.WriteFile(cfgPath, []byte(unguarded), 0o600); err != nil {
		t.Fatalf("write unguarded yaml: %v", err)
	}
	// The restart-only link check would also refuse this, so require the validation error.
	if _, _, _, err := store.Reload(); err == nil || !strings.Contains(err.Error(), "links[sbx0].interface") {
		t.Fatalf("Reload error = %v, want the missing interface refusal", err)
	}
	if store.Current() != before {
		t.Fatal("refused Reload replaced the active snapshot")
	}
}

func TestStoreSIGHUPReloadWipesGrantsAndKeepsOldOnInvalid(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway.yaml")
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
	g1, err := store.AddGrant("worker-claude", "login.anthropic.com", 443, []string{"GET"}, []string{"/oauth/**"}, 5*time.Minute, false)
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
	if _, _, _, err := store.Reload(); err == nil {
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
		store.WatchSIGHUP(ctx, func(_ *config.Snapshot, wiped []string, _ int, err error) {
			if err != nil {
				t.Errorf("SIGHUP reload error: %v", err)
				return
			}
			select {
			case reloaded <- wiped:
			default:
			}
		})
	}()

	sigTicker := time.NewTicker(15 * time.Millisecond)
	defer sigTicker.Stop()
	deadline := time.After(2 * time.Second)
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		cancel()
		<-done
		t.Fatalf("send SIGHUP: %v", err)
	}

	var wiped []string
	for got := false; !got; {
		select {
		case wiped = <-reloaded:
			got = true
		case <-sigTicker.C:
			if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
				cancel()
				<-done
				t.Fatalf("send SIGHUP retry: %v", err)
			}
		case <-deadline:
			cancel()
			<-done
			t.Fatal("timed out waiting for SIGHUP reload")
		}
	}
	if len(wiped) != 1 || wiped[0] != g1.ID {
		t.Fatalf("wiped grants = %v, want [%s]", wiped, g1.ID)
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
	store.OnGrantExpired(func(g config.Grant) { expiredID = g.ID })
	g2, err := store.AddGrant("worker-codex", "auth.openai.com", 443, nil, nil, 1*time.Minute, false)
	if err != nil {
		t.Fatalf("AddGrant g2: %v", err)
	}
	nowNano.Add(int64(2 * time.Minute))
	if got := store.ActiveGrants(); len(got) != 0 {
		t.Fatalf("expected expired grant to be filtered out, got %+v", got)
	}
	if expiredID != "" {
		t.Fatalf("ActiveGrants must not fire expiry callback, got %q", expiredID)
	}
	if pruned := store.PruneExpiredGrants(); len(pruned) != 1 || pruned[0] != g2.ID {
		t.Fatalf("PruneExpiredGrants() = %v, want [%s]", pruned, g2.ID)
	}
	if expiredID != g2.ID {
		t.Fatalf("expired callback id = %q, want %q", expiredID, g2.ID)
	}
}

func TestReloadRefusesImmutableSectionsConcurrentGrantAndMultiCallbacks(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway.yaml")
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
	gKeep, err := store.AddGrant("worker-claude", "keep.example.com", 443, nil, nil, 5*time.Minute, false)
	if err != nil {
		t.Fatalf("AddGrant: %v", err)
	}
	if _, err := store.AddGrant("worker-claude", "forge.internal.example", 443, nil, nil, time.Minute, true); err == nil {
		t.Fatal("expected AddGrant with allow_websocket on bound host to fail")
	}
	if _, err := store.AddGrant("worker-codex", "forge.internal.example", 443, nil, nil, time.Minute, true); err == nil {
		t.Fatal("expected AddGrant with allow_websocket on another principal's bound host to fail")
	}
	if _, err := store.AddGrant("worker-claude", "glob.example.com", 443, nil, []string{"/**/a/**"}, time.Minute, false); err == nil {
		t.Fatal("expected AddGrant with two '**' wildcards to fail")
	}
	if _, err := store.AddGrant("worker-claude", "glob.example.com", 443, nil, []string{"/*a*b*c*d*e"}, time.Minute, false); err == nil {
		t.Fatal("expected AddGrant with five '*' in one segment to fail")
	}

	immutableChanges := []struct {
		name string
		yaml string
	}{
		{"ca", strings.Replace(validYAML, "/etc/gateway/ca/ca.crt", "/etc/gateway/ca/new.crt", 1)},
		{"audit", strings.Replace(validYAML, "/var/log/gateway/audit", "/var/log/gateway/audit2", 1)},
		{"admin", validYAML + "\nadmin:\n  socket: /run/gateway/other.sock\n"},
		{"metrics", strings.Replace(validYAML, "127.0.0.1:9102", "127.0.0.1:9103", 1)},
		{"fake_cidr", validYAML + "\ndns:\n  fake_cidr: 198.19.0.0/16\n"},
		{"links_gateway_ip", strings.Replace(validYAML, "gateway_ip: 10.200.0.1", "gateway_ip: 10.200.0.2", 1)},
		{"principals", strings.ReplaceAll(validYAML, "worker-codex", "worker-renamed")},
		{"dataplane_ready_file", strings.Replace(validYAML, "/run/gateway-dataplane/dataplane.ready", "/run/gateway-dataplane/other.ready", 1)},
		{"dataplane_state_file", strings.Replace(validYAML, "  ready_file:", "  state_file: /var/lib/elsewhere/links.json\n  ready_file:", 1)},
		{"dataplane_dhcp", strings.Replace(validYAML, "user: dnsmasq", "user: nobody", 1)},
		{"dataplane_verify_sysctls", strings.Replace(validYAML, "dataplane:\n", "dataplane:\n  verify_sysctls: false\n", 1)},
		{"http_max_header_bytes", validYAML + "\nhttp:\n  max_header_bytes: 65536\n"},
		{"http_max_conns_per_link", validYAML + "\nhttp:\n  max_conns_per_link: 64\n"},
		{"http_upstream_response_header_timeout", validYAML + "\nhttp:\n  upstream_response_header_timeout: 30s\n"},
		{"audit_max_total_bytes", strings.Replace(validYAML, "  dir: /var/log/gateway/audit", "  dir: /var/log/gateway/audit\n  max_total_bytes: 1048576", 1)},
	}
	for _, tc := range immutableChanges {
		t.Run("refuse_"+tc.name, func(t *testing.T) {
			if err := os.WriteFile(cfgPath, []byte(tc.yaml), 0o600); err != nil {
				t.Fatalf("write %s yaml: %v", tc.name, err)
			}
			if _, _, _, err := store.Reload(); err == nil {
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
	if _, wiped, _, err := store.Reload(); err != nil || len(wiped) != 1 {
		t.Fatalf("rule reload = (wiped=%v, err=%v), want 1 wiped grant and nil err", wiped, err)
	}

	// Multiple OnGrantExpired callbacks must ALL fire on expiry via a single RunGrantPruner loop.
	cb1Ch := make(chan string, 2)
	cb2Ch := make(chan string, 2)
	store.OnGrantExpired(func(g config.Grant) { cb1Ch <- g.ID })
	store.OnGrantExpired(func(g config.Grant) { cb2Ch <- g.ID })
	gExp, err := store.AddGrant("worker-claude", "exp.example.com", 443, nil, nil, time.Minute, false)
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
			if _, gErr := store.AddGrant("worker-claude", "race.example.com", 443, nil, nil, time.Minute, false); gErr != nil {
				continue
			}
		}
	}()
	for i := 0; i < 15; i++ {
		if _, _, _, rErr := store.Reload(); rErr != nil {
			t.Fatalf("concurrent Reload %d: %v", i, rErr)
		}
	}
	<-done
	if _, _, _, err := store.Reload(); err != nil {
		t.Fatalf("final Reload: %v", err)
	}
	if rem := store.ActiveGrants(); len(rem) != 0 {
		t.Fatalf("grants survived final Reload: %+v", rem)
	}
}

func TestConcurrentReloadsAreSerialized(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway.yaml")
	cfgA := strings.Replace(validYAML, "deb.debian.org", "alpha.example.com", 1)
	cfgB := strings.Replace(validYAML, "deb.debian.org", "beta.example.com", 1)
	if err := os.WriteFile(cfgPath, []byte(cfgA), 0o600); err != nil {
		t.Fatalf("write initial config: %v", err)
	}
	store, err := config.NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	var (
		inFlight      atomic.Int32
		overlapped    atomic.Bool
		lastMu        sync.Mutex
		lastFinishedH string
	)
	store.OnReload(func(_, next *config.Snapshot, _ []string) int {
		if inFlight.Add(1) > 1 {
			overlapped.Store(true)
		}
		time.Sleep(15 * time.Millisecond)
		lastMu.Lock()
		lastFinishedH = next.Hash
		lastMu.Unlock()
		inFlight.Add(-1)
		return 0
	})

	atomicWrite := func(content string) error {
		tmp, err := os.CreateTemp(dir, "cfg-*")
		if err != nil {
			return err
		}
		name := tmp.Name()
		if _, err := tmp.WriteString(content); err != nil {
			if cErr := tmp.Close(); cErr != nil {
				return cErr
			}
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		return os.Rename(name, cfgPath)
	}

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		body := cfgA
		if i%2 == 1 {
			body = cfgB
		}
		wg.Add(1)
		go func(payload string) {
			defer wg.Done()
			if wErr := atomicWrite(payload); wErr != nil {
				t.Errorf("atomicWrite: %v", wErr)
				return
			}
			if _, _, _, rErr := store.Reload(); rErr != nil {
				t.Errorf("Reload: %v", rErr)
			}
		}(body)
	}
	wg.Wait()

	if overlapped.Load() {
		t.Fatal("concurrent Reload calls overlapped instead of serializing")
	}
	lastMu.Lock()
	wantHash := lastFinishedH
	lastMu.Unlock()
	if got := store.Current().Hash; got != wantHash {
		t.Fatalf("final Current().Hash = %s, want last finished reload hash %s", got, wantHash)
	}
}
