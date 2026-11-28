package audit

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
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

	// Second WriteSync triggers rotation into .1 (/dev/full) -> pruneSizeLocked attempts
	// to write audit-size-pruned BEFORE deleting, hits ENOSPC, deletes nothing, and returns ENOSPC.
	firstSeg := filepath.Join(dir, segmentFileName("2026-11-26", 0))
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
	for _, seg := range []string{oldSeg, firstSeg} {
		if _, statErr := os.Stat(seg); statErr != nil {
			t.Fatalf("segment %s was deleted despite failed audit-size-pruned write: %v", filepath.Base(seg), statErr)
		}
	}
}

func TestWriteFailingOnAlreadyOpenSegmentMarksUnhealthy(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Fatalf("/dev/full required on Linux: %v", err)
	}
	dir := t.TempDir()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	var onErrCalls atomic.Int32
	w, err := NewWriter(Options{
		Dir:          dir,
		MaxFileBytes: 1 << 20, // no rotation during this test
		Now:          func() time.Time { return now },
		OnWriteError: func() { onErrCalls.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	t.Cleanup(func() {
		if cErr := w.Close(); cErr != nil {
			t.Errorf("Close: %v", cErr)
		}
	})

	ev := Event{
		Kind:      KindRequest,
		Principal: "worker-test",
		Host:      "api.example.com",
		Path:      "/v1/ok",
		Method:    "GET",
		Status:    200,
		Effect:    EffectAllow,
	}
	if err := w.WriteSync(ev); err != nil {
		t.Fatalf("initial WriteSync: %v", err)
	}
	if !w.Healthy() || w.WriteErrors() != 0 || onErrCalls.Load() != 0 {
		t.Fatalf("unexpected pre-failure state: healthy=%v errs=%d cb=%d", w.Healthy(), w.WriteErrors(), onErrCalls.Load())
	}

	// Swap the already-open segment fd to /dev/full so the next WriteSync fails without rotating.
	fullFD, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open /dev/full: %v", err)
	}
	w.mu.Lock()
	prev := w.file
	w.file = fullFD
	w.mu.Unlock()
	if err := prev.Close(); err != nil {
		t.Fatalf("close prev segment: %v", err)
	}

	writeErr := w.WriteSync(ev)
	if !errors.Is(writeErr, syscall.ENOSPC) {
		t.Fatalf("WriteSync on already-open failing segment err = %v, want wrapped syscall.ENOSPC", writeErr)
	}
	if w.WriteErrors() != 1 {
		t.Fatalf("WriteErrors() = %d, want 1", w.WriteErrors())
	}
	if onErrCalls.Load() != 1 {
		t.Fatalf("OnWriteError calls = %d, want 1", onErrCalls.Load())
	}
	if w.Healthy() {
		t.Fatal("Healthy() = true after write error on already-open segment, want false")
	}
}
