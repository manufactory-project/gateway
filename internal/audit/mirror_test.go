// SPDX-License-Identifier: AGPL-3.0-only

package audit_test

import (
	"bytes"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
)

// blockingMirror is a stdout mirror whose consumer has stalled: every Write
// blocks until release is closed.
type blockingMirror struct {
	release chan struct{}
	written atomic.Int64
}

func (m *blockingMirror) Write(p []byte) (int, error) {
	<-m.release
	m.written.Add(1)
	return len(p), nil
}

// The JSONL file is the authoritative sink and is written under the writer's
// lock; the stdout mirror must never be. If it were, one stalled consumer would
// stall the audit write of every link.
func TestStalledMirrorNeverBlocksTheFileSink(t *testing.T) {
	const records = 3000 // well past the mirror's queue
	dir := t.TempDir()
	mirror := &blockingMirror{release: make(chan struct{})}
	var dropped atomic.Int64
	w, err := audit.NewWriter(audit.Options{
		Dir:             dir,
		Stdout:          mirror,
		OnMirrorDropped: func() { dropped.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(mirror.release) }) }
	t.Cleanup(releaseAll)

	done := make(chan error, 1)
	go func() {
		for range records {
			if err := w.WriteSync(audit.Event{Kind: audit.KindRequestAdmitted, Link: "other", Host: "api.example.com"}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WriteSync: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("audit writes stalled behind a blocked stdout mirror")
	}

	// The file has every record; the mirror's overflow is dropped and counted.
	if got := len(readAuditEvents(t, dir)); got != records {
		t.Fatalf("records in the audit file = %d, want %d", got, records)
	}
	// One record is held by the stalled Write and mirrorQueue wait behind it; the
	// consumer may not yet have taken the first, so allow for either.
	if d := dropped.Load(); d < records-1025 || d > records-1024 {
		t.Fatalf("mirror drops = %d, want %d or %d", d, records-1025, records-1024)
	}

	// Close drains what the mirror still holds once its consumer recovers.
	releaseAll()
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := mirror.written.Load() + dropped.Load(); got != records {
		t.Fatalf("mirrored %d + dropped %d != %d records", mirror.written.Load(), dropped.Load(), records)
	}
}

func TestMirrorReceivesEveryRecordWhenNotStalled(t *testing.T) {
	const records = 500
	var out bytes.Buffer
	var dropped atomic.Int64
	w, err := audit.NewWriter(audit.Options{
		Dir:             t.TempDir(),
		Stdout:          &out,
		OnMirrorDropped: func() { dropped.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for range records {
		if err := w.WriteSync(audit.Event{Kind: audit.KindDNS, Host: "api.example.com"}); err != nil {
			t.Fatalf("WriteSync: %v", err)
		}
	}
	if err := w.Close(); err != nil { // drains the mirror
		t.Fatalf("Close: %v", err)
	}
	if got := strings.Count(out.String(), "\n"); got != records {
		t.Fatalf("mirrored records = %d, want %d", got, records)
	}
	if dropped.Load() != 0 {
		t.Fatalf("mirror drops = %d, want 0", dropped.Load())
	}
}
