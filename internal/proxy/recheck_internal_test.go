package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestAdmissionRecheckBlocksRevokedGrantBetweenAdmitAndRegister(t *testing.T) {
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	rootCA, err := ca.Init(certPath, keyPath)
	if err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	cfgYAML := "ca:\n  cert_path: " + certPath + "\n  key_path: " + keyPath + "\naudit:\n  dir: " + auditDir + "\nlinks:\n  - name: sbx0\n    principal: worker-test\n    subnet: 127.0.29.0/28\n    gateway_ip: 127.0.29.1\n"
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
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			dialHits.Add(1)
			return nil, net.ErrClosed
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	g, err := store.AddGrant("worker-test", "grant-race.example.com", 443, []string{"GET"}, []string{"/only"}, 5*time.Minute, false)
	if err != nil {
		t.Fatalf("AddGrant: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/only", nil)
	req.Host = "grant-race.example.com"
	req.TLS = &tls.ConnectionState{ServerName: "grant-race.example.com"}

	rec := httptest.NewRecorder()
	rc, ok := srv.admit(rec, req, 443)
	if !ok {
		t.Fatalf("admit unexpectedly denied: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if !srv.prepare(rec, rc) {
		t.Fatalf("prepare unexpectedly failed: code=%d", rec.Code)
	}

	// Revoke the grant strictly between admit() and relay()/flows.register() (no config reload).
	if _, existed := store.RevokeGrant(g.ID); !existed {
		t.Fatalf("RevokeGrant(%s) returned existed=false", g.ID)
	}

	srv.relay(rec, rc)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 admission-changed after grant revoked between admit and register (body=%q)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "admission-changed") {
		t.Fatalf("body = %q, want admission-changed", rec.Body.String())
	}
	if dialHits.Load() != 0 {
		t.Fatalf("dialHits = %d, want 0 (revoked grant must not dial upstream)", dialHits.Load())
	}
}

func TestAdmissionRecheckBlocksWhenOnlyAllowWebSocketChanges(t *testing.T) {
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	rootCA, err := ca.Init(certPath, keyPath)
	if err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	baseYAML := "ca:\n  cert_path: " + certPath + "\n  key_path: " + keyPath + "\naudit:\n  dir: " + auditDir + "\nlinks:\n  - name: sbx0\n    principal: worker-test\n    subnet: 127.0.29.0/28\n    gateway_ip: 127.0.29.1\nrules:\n  - id: allow-ws-recheck\n    principal: worker-test\n    effect: allow\n    hosts: [ws-recheck.example.com]\n    ports: [443]\n    paths: [\"/**\"]\n"
	cfgPath := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(cfgPath, []byte(baseYAML+"    allow_websocket: false\n"), 0o600); err != nil {
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
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			dialHits.Add(1)
			return nil, net.ErrClosed
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/stream", nil)
	req.Host = "ws-recheck.example.com"
	req.TLS = &tls.ConnectionState{ServerName: "ws-recheck.example.com"}

	rec := httptest.NewRecorder()
	rc, ok := srv.admit(rec, req, 443)
	if !ok {
		t.Fatalf("admit unexpectedly denied: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if !srv.prepare(rec, rc) {
		t.Fatalf("prepare unexpectedly failed: code=%d", rec.Code)
	}

	// Reload changing ONLY allow_websocket on the same rule between admit() and relay().
	if err := os.WriteFile(cfgPath, []byte(baseYAML+"    allow_websocket: true\n"), 0o600); err != nil {
		t.Fatalf("write reloaded config: %v", err)
	}
	if _, _, _, err := store.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	srv.relay(rec, rc)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 admission-changed when only AllowWebSocket changed (body=%q)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "admission-changed") {
		t.Fatalf("body = %q, want admission-changed", rec.Body.String())
	}
	if dialHits.Load() != 0 {
		t.Fatalf("dialHits = %d, want 0", dialHits.Load())
	}
}
