// SPDX-License-Identifier: AGPL-3.0-only

package ca_test

import (
	"errors"
	"path/filepath"
	"testing"

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
