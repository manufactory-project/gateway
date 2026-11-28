// SPDX-License-Identifier: AGPL-3.0-only

package connlimit_test

import (
	"testing"

	"go.uber.org/goleak"

	"github.com/manufactory-project/gateway/internal/connlimit"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestLimitRefusesPastCapacityAndReusesReleasedSlots(t *testing.T) {
	rejected := 0
	l := connlimit.New(2, func() { rejected++ })
	for i := range 2 {
		if !l.TryAcquire() {
			t.Fatalf("slot %d within the limit was refused", i+1)
		}
	}
	if l.TryAcquire() {
		t.Fatal("a third slot was granted with the limit at 2")
	}
	if rejected != 1 {
		t.Fatalf("refusals counted = %d, want 1", rejected)
	}
	l.Release()
	if !l.TryAcquire() {
		t.Fatal("a released slot was not reusable")
	}
}

func TestBudgetCountsEveryRefusalAndReportsThemOnceAsABatch(t *testing.T) {
	const rate, events = 2, 500
	dropped := 0
	var reports []uint64
	drops := connlimit.NewDrops(func() { dropped++ }, func(n uint64) { reports = append(reports, n) })
	b := connlimit.NewBudget(rate, drops)

	allowed := 0
	for range events {
		if b.Allow() {
			allowed++
		}
	}
	// A bucket of 2 per second refills well under a token during this loop.
	if allowed < rate || allowed > rate+1 {
		t.Fatalf("allowed %d of %d events, want about %d", allowed, events, rate)
	}
	if dropped != events-allowed {
		t.Fatalf("drops counted = %d, want %d", dropped, events-allowed)
	}
	if len(reports) != 0 {
		t.Fatalf("batch reported before its interval or a flush: %v", reports)
	}

	drops.Flush()
	if len(reports) != 1 || reports[0] != uint64(events-allowed) {
		t.Fatalf("reports after flush = %v, want one batch of %d", reports, events-allowed)
	}
	drops.Flush()
	if len(reports) != 1 {
		t.Fatalf("an empty flush reported again: %v", reports)
	}
}
