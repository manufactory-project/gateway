// SPDX-License-Identifier: AGPL-3.0-only

package ca_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/ca"
)

func TestLeafMintIsAdmittedOnlyOnACacheMiss(t *testing.T) {
	dir := t.TempDir()
	c, err := ca.Init(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	cache := ca.NewLeafCache(c)
	asked := 0
	admit := func(ok bool) func() bool {
		return func() bool { asked++; return ok }
	}

	if cert, err := cache.Leaf("refused.example.com", admit(false)); !errors.Is(err, ca.ErrMintLimited) || cert != nil {
		t.Fatalf("refused mint = %v, %v; want nil and ErrMintLimited", cert, err)
	}
	// A refusal caches nothing: the same name mints once admitted.
	if _, err := cache.Leaf("refused.example.com", admit(true)); err != nil {
		t.Fatalf("mint after admission: %v", err)
	}
	if asked != 2 {
		t.Fatalf("admit asked %d times for 2 misses, want 2", asked)
	}
	// A hit never asks, so a spent budget cannot refuse a cached name.
	if _, err := cache.Leaf("refused.example.com", admit(false)); err != nil {
		t.Fatalf("cache hit refused: %v", err)
	}
	if asked != 2 {
		t.Fatalf("admit asked on a cache hit: %d calls, want 2", asked)
	}
}

// Links share one cache but not budgets: a link over its budget must not make
// another link's mint of the same name fail by being the one that led the flight.
func TestRefusedCallerDoesNotFailAnotherLinksMint(t *testing.T) {
	dir := t.TempDir()
	c, err := ca.Init(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	cache := ca.NewLeafCache(c)

	inRefused := make(chan struct{})
	releaseRefused := make(chan struct{})
	refused := make(chan error, 1)
	go func() {
		_, err := cache.Leaf("shared.example.com", func() bool {
			close(inRefused)
			<-releaseRefused
			return false
		})
		refused <- err
	}()
	<-inRefused // link A is deciding, over budget

	admitted := make(chan struct{})
	granted := make(chan error, 1)
	go func() {
		_, err := cache.Leaf("shared.example.com", func() bool {
			close(admitted)
			return true
		})
		granted <- err
	}()
	// Link B's budget is its own: it is consulted while A is still undecided.
	select {
	case <-admitted:
	case <-time.After(5 * time.Second):
		t.Fatal("link B waited on link A's refusal instead of spending its own budget")
	}
	close(releaseRefused)

	if err := <-refused; !errors.Is(err, ca.ErrMintLimited) {
		t.Fatalf("over-budget link: %v, want ErrMintLimited", err)
	}
	if err := <-granted; err != nil {
		t.Fatalf("under-budget link was refused: %v", err)
	}
}
