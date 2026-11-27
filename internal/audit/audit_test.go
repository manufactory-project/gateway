package audit_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/manufactory-project/gateway/internal/audit"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func randomHex(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return hex.EncodeToString(b[:])
}

func TestAuditQueryRedactionAndPeerEscaping(t *testing.T) {
	dir := t.TempDir()
	var stdout bytes.Buffer
	secretToken := "tok_" + randomHex(t)

	w, err := audit.NewWriter(audit.Options{
		Dir:        dir,
		RetainDays: 7,
		Stdout:     &stdout,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	// Containment: query string carrying secret token must never appear in audit output,
	// and forged peer strings with newlines/quotes must be escaped.
	err = w.WriteSync(audit.Event{
		Kind:      audit.KindRequest,
		Principal: "worker-claude",
		Host:      "evil.example\n{\"effect\":\"allow\"}",
		Method:    "GET \"forged\"",
		Path:      "/v1/messages?api_key=" + secretToken + "&foo=bar#frag",
		Port:      443,
		Effect:    audit.EffectAllow,
		RuleID:    "r1",
	})
	if err != nil {
		t.Fatalf("WriteSync containment event: %v", err)
	}

	// Positive control: clean path without query is preserved accurately with HasQuery=false.
	err = w.WriteSync(audit.Event{
		Kind:      audit.KindRequest,
		Principal: "worker-claude",
		Host:      "api.anthropic.com",
		Method:    "POST",
		Path:      "/v1/messages",
		Port:      443,
		Effect:    audit.EffectAllow,
		RuleID:    "r1",
	})
	if err != nil {
		t.Fatalf("WriteSync positive control: %v", err)
	}

	raw := stdout.String()
	if strings.Contains(raw, secretToken) {
		t.Fatalf("audit output leaked query secret %q:\n%s", secretToken, raw)
	}
	if strings.Contains(raw, "api_key") {
		t.Fatalf("audit output leaked query key:\n%s", raw)
	}
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected exactly 2 JSONL lines (no forged newline break), got %d:\n%s", len(lines), raw)
	}

	events, err := audit.Query(dir, audit.QueryOptions{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Path != "/v1/messages" || !events[0].HasQuery {
		t.Fatalf("containment event path/has_query mismatch: got path=%q has_query=%v", events[0].Path, events[0].HasQuery)
	}
	if strings.Contains(events[0].Host, "\n") || strings.Contains(events[0].Host, `"`) {
		t.Fatalf("host was not escaped: %q", events[0].Host)
	}
	if strings.Contains(events[0].Method, " ") || strings.Contains(events[0].Method, `"`) {
		t.Fatalf("method was not escaped: %q", events[0].Method)
	}
	if events[1].Host != "api.anthropic.com" || events[1].Path != "/v1/messages" || events[1].HasQuery {
		t.Fatalf("positive control mutated unexpectedly: %+v", events[1])
	}
}

func TestAuditFailClosedOnUnwritableSink(t *testing.T) {
	// Containment: unwritable directory fails NewWriter immediately.
	blockerFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blockerFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("create blocker file: %v", err)
	}
	var errCount atomic.Int32
	if _, err := audit.NewWriter(audit.Options{
		Dir:          filepath.Join(blockerFile, "sub"),
		OnWriteError: func() { errCount.Add(1) },
	}); err == nil {
		t.Fatal("expected NewWriter to fail when audit dir is unwritable")
	}
	if errCount.Load() == 0 {
		t.Fatal("expected OnWriteError callback to fire on unwritable sink")
	}

	// Containment: healthy writer whose underlying directory is broken on rotation fails closed.
	dir := t.TempDir()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	var cbHits atomic.Int32
	w, err := audit.NewWriter(audit.Options{
		Dir:          dir,
		MaxFileBytes: 120,
		Now:          func() time.Time { return now },
		OnWriteError: func() { cbHits.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	// Positive control: first write succeeds and sink reports healthy.
	if err := w.WriteSync(audit.Event{
		Kind:      audit.KindDNS,
		Principal: "worker-claude",
		Host:      "api.anthropic.com",
		Effect:    audit.EffectAllow,
	}); err != nil {
		t.Fatalf("first WriteSync: %v", err)
	}
	if !w.Healthy() || w.WriteErrors() != 0 {
		t.Fatalf("expected healthy writer with 0 errors, got healthy=%v errors=%d", w.Healthy(), w.WriteErrors())
	}

	// Replace the audit directory with a file so the next rotation cannot open a segment.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove audit dir: %v", err)
	}
	if err := os.WriteFile(dir, []byte("blocked"), 0o600); err != nil {
		t.Fatalf("replace audit dir with file: %v", err)
	}
	if err := w.WriteSync(audit.Event{
		Kind:      audit.KindDNS,
		Principal: "worker-claude",
		Host:      "api.anthropic.com",
		Effect:    audit.EffectAllow,
	}); err == nil {
		t.Fatal("expected WriteSync to fail closed when rotation cannot open sink")
	}
	if w.Healthy() {
		t.Fatal("expected Healthy() == false after write failure")
	}
	if w.WriteErrors() != 1 || cbHits.Load() != 1 {
		t.Fatalf("expected WriteErrors=1 and cbHits=1, got %d / %d", w.WriteErrors(), cbHits.Load())
	}
}

func TestAuditRotationRetentionAndQueryFilters(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	w, err := audit.NewWriter(audit.Options{
		Dir:          dir,
		RetainDays:   3,
		MaxFileBytes: 180,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	// Write old day events (should be pruned once clock advances >3 days).
	for i := 0; i < 3; i++ {
		if err := w.WriteSync(audit.Event{
			Kind:      audit.KindDNS,
			Principal: "p1",
			Host:      "old.example.com",
			Effect:    audit.EffectDeny,
		}); err != nil {
			t.Fatalf("write old event %d: %v", i, err)
		}
	}

	// Advance 5 days: triggers new day segment + pruning of 2026-11-20 segments.
	now = time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	if err := w.WriteSync(audit.Event{
		Kind:      audit.KindRequest,
		Principal: "p1",
		Host:      "api.anthropic.com",
		Effect:    audit.EffectAllow,
	}); err != nil {
		t.Fatalf("write new allow event: %v", err)
	}
	if err := w.WriteSync(audit.Event{
		Kind:      audit.KindRequest,
		Principal: "p2",
		Host:      "blocked.example.com",
		Effect:    audit.EffectDeny,
	}); err != nil {
		t.Fatalf("write new deny event: %v", err)
	}

	all, err := audit.Query(dir, audit.QueryOptions{})
	if err != nil {
		t.Fatalf("Query all: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 retained events after pruning old day, got %d: %+v", len(all), all)
	}

	filtered, err := audit.Query(dir, audit.QueryOptions{
		Principal: "p2",
		Effect:    audit.EffectDeny,
		Tail:      1,
	})
	if err != nil {
		t.Fatalf("Query filtered: %v", err)
	}
	if len(filtered) != 1 || filtered[0].Host != "blocked.example.com" {
		t.Fatalf("unexpected filtered events: %+v", filtered)
	}

	// Overflow guard on RetainDays.
	if _, err := audit.NewWriter(audit.Options{
		Dir:        t.TempDir(),
		RetainDays: audit.MaxRetainDays + 1,
	}); err == nil {
		t.Fatal("expected RetainDays > MaxRetainDays to fail")
	}
}
