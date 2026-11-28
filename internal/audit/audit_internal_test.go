package audit

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestPruneSizeWriteErrorSurfacesUnderlyingCause(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Fatalf("/dev/full required on Linux: %v", err)
	}
	dir := t.TempDir()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	w, err := NewWriter(Options{
		Dir:           dir,
		MaxFileBytes:  150,
		MaxTotalBytes: 250,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	t.Cleanup(func() {
		if cErr := w.Close(); cErr != nil {
			t.Errorf("Close: %v", cErr)
		}
	})

	// Seed an older closed segment (> MaxTotalBytes) and point the next rotated segment
	// at /dev/full so writeLineLocked inside pruneSizeLocked fails with syscall.ENOSPC.
	oldSeg := filepath.Join(dir, "gateway-2026-11-25.jsonl")
	if err := os.WriteFile(oldSeg, make([]byte, 300), 0o640); err != nil {
		t.Fatalf("write old segment: %v", err)
	}
	nextSeg := filepath.Join(dir, segmentFileName("2026-11-26", 1))
	if err := os.Symlink("/dev/full", nextSeg); err != nil {
		t.Fatalf("symlink /dev/full: %v", err)
	}

	ev := Event{
		Kind:      KindRequest,
		Principal: "worker-test",
		Host:      "api.example.com",
		Path:      "/v1/messages",
		Method:    "POST",
		Status:    200,
		Effect:    EffectAllow,
	}
	if err := w.WriteSync(ev); err != nil {
		t.Fatalf("first WriteSync: %v", err)
	}

	// Second WriteSync triggers rotation into .001 (/dev/full) -> pruneSizeLocked removes oldSeg
	// and attempts to write audit-size-pruned, which fails with ENOSPC.
	writeErr := w.WriteSync(ev)
	if writeErr == nil {
		t.Fatal("expected WriteSync to fail when audit-size-pruned write hits ENOSPC")
	}
	if !errors.Is(writeErr, syscall.ENOSPC) {
		t.Fatalf("WriteSync error = %v, want wrapped syscall.ENOSPC (errors.Is)", writeErr)
	}
	if w.Healthy() {
		t.Fatal("expected Healthy() == false after pruneSizeLocked write error")
	}
}
