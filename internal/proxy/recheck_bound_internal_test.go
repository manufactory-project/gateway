// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/ca"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/policy"
)

// TestAdmissionRecheckOfBoundRuleChangedBetweenPrepareAndRegister pins the
// post-registration recheck for a rule with a binding: a revoked rule, a rule
// replaced by a grant, and an in-place binding edit under the same rule id, each
// landing strictly between prepare() and relay(), end in an audited 403
// admission-changed with no upstream dial. The state is changed between the two
// calls directly, so no real request has to be paused.
func TestAdmissionRecheckOfBoundRuleChangedBetweenPrepareAndRegister(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, store *config.Store, cfgPath, baseYAML, altSecret string)
	}{
		{"rule_revoked", func(t *testing.T, store *config.Store, cfgPath, baseYAML, _ string) {
			if err := os.WriteFile(cfgPath, []byte(baseYAML[:strings.Index(baseYAML, "rules:\n")]), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			if _, _, _, err := store.Reload(); err != nil {
				t.Fatalf("Reload: %v", err)
			}
		}},
		{"rule_to_grant", func(t *testing.T, store *config.Store, _, _, _ string) {
			if _, err := store.AddGrant("worker-test", "recheck.example.com", 443, []string{"GET"}, []string{"/race"}, 5*time.Minute, false); err != nil {
				t.Fatalf("AddGrant: %v", err)
			}
		}},
		{"binding_edited_same_rule_id", func(t *testing.T, store *config.Store, cfgPath, baseYAML, altSecret string) {
			idx := strings.Index(baseYAML, "        secret_file: ")
			if err := os.WriteFile(cfgPath, []byte(baseYAML[:idx]+"        secret_file: "+altSecret+"\n"), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			if _, _, _, err := store.Reload(); err != nil {
				t.Fatalf("Reload: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			auditDir := filepath.Join(dir, "audit")
			rootCA, err := ca.Init(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
			if err != nil {
				t.Fatalf("ca.Init: %v", err)
			}
			secFile := filepath.Join(dir, "sec")
			altSecret := filepath.Join(dir, "alt")
			for _, f := range []string{secFile, altSecret} {
				if err := os.WriteFile(f, []byte("secret-"+filepath.Base(f)+"\n"), 0o600); err != nil {
					t.Fatalf("write secret: %v", err)
				}
			}
			baseYAML := "ca:\n  cert_path: " + filepath.Join(dir, "ca.crt") + "\n  key_path: " + filepath.Join(dir, "ca.key") + "\naudit:\n  dir: " + auditDir +
				"\ndataplane:\n  ready_file: /run/gateway-dataplane/dataplane.ready\n  dhcp: {user: dnsmasq, lease_file: /var/lib/gateway/dnsmasq.leases}\nlinks:\n  - name: sbx0\n    interface: sbx0\n    ct_zone: 101\n    route_table: 101\n    principal: worker-test\n    subnet: 127.0.29.0/28\n    gateway_ip: 127.0.29.1\n" +
				"rules:\n  - id: allow-recheck\n    principal: worker-test\n    effect: allow\n    hosts: [recheck.example.com]\n    ports: [443]\n    paths: [\"/**\"]\n    bindings:\n      - name: sec\n        host: recheck.example.com\n        header: X-Tok\n        scheme: raw\n        placeholder: mf_ph_sec\n        secret_file: " + secFile + "\n"
			cfgPath := filepath.Join(dir, "gateway.yaml")
			if err := os.WriteFile(cfgPath, []byte(baseYAML), 0o600); err != nil {
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
				if cErr := aw.Close(); cErr != nil {
					t.Errorf("audit.Close: %v", cErr)
				}
			})
			var dialHits atomic.Int32
			srv, err := NewServer(Options{
				Link:         store.Current().Config.Links[0],
				Store:        store,
				Evaluator:    policy.NewEvaluator(store),
				Audit:        aw,
				Leaves:       ca.NewLeafCache(rootCA),
				Flows:        NewFlowRegistry(),
				OnServeError: func(error) {},
				DialContext: func(context.Context, string, string, netip.Addr) (net.Conn, error) {
					dialHits.Add(1)
					return nil, net.ErrClosed
				},
			})
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/race", nil)
			req.Host = "recheck.example.com"
			req.TLS = &tls.ConnectionState{ServerName: "recheck.example.com"}
			req.Header.Set("X-Tok", "mf_ph_sec")
			rec := httptest.NewRecorder()
			rc, ok := srv.admit(rec, req, 443)
			if !ok || !srv.prepare(rec, rc) {
				t.Fatalf("admit/prepare denied: code=%d body=%q", rec.Code, rec.Body.String())
			}

			tc.mutate(t, store, cfgPath, baseYAML, altSecret)

			srv.relay(rec, rc)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admission-changed") {
				t.Fatalf("status=%d body=%q, want 403 admission-changed", rec.Code, rec.Body.String())
			}
			if dialHits.Load() != 0 {
				t.Fatalf("changed admission dialed upstream %d time(s)", dialHits.Load())
			}
			entries, err := os.ReadDir(auditDir)
			if err != nil {
				t.Fatalf("ReadDir: %v", err)
			}
			var sawDeny bool
			for _, e := range entries {
				raw, err := os.ReadFile(filepath.Join(auditDir, e.Name()))
				if err != nil {
					t.Fatalf("read audit: %v", err)
				}
				sawDeny = sawDeny || strings.Contains(string(raw), `"reason":"admission-changed"`)
			}
			if !sawDeny {
				t.Fatal("missing audited admission-changed deny")
			}
		})
	}
}
