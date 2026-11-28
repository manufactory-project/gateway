// SPDX-License-Identifier: AGPL-3.0-only

package audit_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
)

// A short write or a crash leaves half a record at the end of a segment. Reopening
// must cut it back to the last newline, or the next record is glued onto it and
// both are lost to the reader.
func TestReopenTruncatesTrailingPartialLine(t *testing.T) {
	const whole = `{"version":1,"time":"2026-06-01T00:00:00Z","kind":"dns","reason":"before"}` + "\n"
	now := func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) }

	for _, tc := range []struct {
		name       string
		existing   string
		wantBefore int
	}{
		{"clean file is untouched", whole, 1},
		{"partial line after a whole one", whole + `{"version":1,"time":"2026-06-01T00:0`, 1},
		{"partial line only", `{"version":1,"ti`, 0},
		{"partial line longer than a read chunk", whole + `{"reason":"` + string(make([]byte, 10000)), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "gateway-2026-06-01.jsonl")
			if err := os.WriteFile(path, []byte(tc.existing), 0o640); err != nil {
				t.Fatalf("seed segment: %v", err)
			}
			w, err := audit.NewWriter(audit.Options{Dir: dir, Now: now})
			if err != nil {
				t.Fatalf("NewWriter: %v", err)
			}
			if err := w.WriteSync(audit.Event{Kind: audit.KindDNS, Reason: "after"}); err != nil {
				t.Fatalf("WriteSync: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			// readAuditEvents fails the test on any line that is not one whole record.
			events := readAuditEvents(t, dir)
			if len(events) != tc.wantBefore+1 {
				t.Fatalf("records after reopen = %d, want %d", len(events), tc.wantBefore+1)
			}
			if last := events[len(events)-1]; last.Reason != "after" {
				t.Fatalf("last record reason = %q, want \"after\"", last.Reason)
			}
		})
	}
}

// BenchmarkWriteSyncUnderFlood measures what one link waits for the audit writer
// while others hammer it: every write takes the one writer mutex, so this is the
// worst a cross-link stall can cost one request's admission record.
func BenchmarkWriteSyncUnderFlood(b *testing.B) {
	w, err := audit.NewWriter(audit.Options{Dir: b.TempDir()})
	if err != nil {
		b.Fatalf("NewWriter: %v", err)
	}
	b.Cleanup(func() {
		if err := w.Close(); err != nil {
			b.Errorf("Close: %v", err)
		}
	})
	const flooders = 8
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range flooders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := w.WriteSync(audit.Event{Kind: audit.KindDNS, Link: "flood", Host: "flood.example.com", QType: "A", Effect: audit.EffectDeny}); err != nil {
					b.Errorf("flood write: %v", err)
					return
				}
			}
		}()
	}
	var worst time.Duration
	b.ResetTimer()
	for range b.N {
		start := time.Now()
		if err := w.WriteSync(audit.Event{Kind: audit.KindRequestAdmitted, Link: "victim", Host: "api.example.com"}); err != nil {
			b.Fatalf("victim write: %v", err)
		}
		worst = max(worst, time.Since(start))
	}
	b.StopTimer()
	close(stop)
	wg.Wait()
	b.ReportMetric(float64(worst.Microseconds()), "worst-µs")
}
