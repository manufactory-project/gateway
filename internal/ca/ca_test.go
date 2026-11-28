// SPDX-License-Identifier: AGPL-3.0-only

package ca_test

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/manufactory-project/gateway/internal/ca"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestCAInitLoadAndFailClosed(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Containment: Load fails closed when files do not exist.
	if _, err := ca.Load(certPath, keyPath); err == nil {
		t.Fatal("expected Load on missing files to fail closed")
	}

	// Positive control: Init creates keypair with 0644/0600 and Load succeeds.
	created, err := ca.Init(certPath, keyPath)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !created.Certificate.IsCA {
		t.Fatal("generated cert is not IsCA")
	}

	// Containment: Init refuses to overwrite existing CA.
	if _, err := ca.Init(certPath, keyPath); err == nil {
		t.Fatal("expected second Init to refuse overwrite")
	}

	// Load succeeds and matches.
	loaded, err := ca.Load(certPath, keyPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !loaded.Certificate.Equal(created.Certificate) {
		t.Fatal("loaded cert does not match created cert")
	}

	// Containment: mismatched cert/key pair fails closed.
	dir2 := t.TempDir()
	cert2 := filepath.Join(dir2, "ca2.crt")
	key2 := filepath.Join(dir2, "ca2.key")
	if _, err := ca.Init(cert2, key2); err != nil {
		t.Fatalf("Init second CA: %v", err)
	}
	if _, err := ca.Load(certPath, key2); err == nil {
		t.Fatal("expected Load with mismatched cert/key to fail closed")
	}
}

func TestLeafCacheSingleflightConcurrencyAndEviction(t *testing.T) {
	dir := t.TempDir()
	c, err := ca.Init(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	now := time.Now().UTC()
	cache := ca.NewLeafCacheWithOptions(c, 3, func() time.Time { return now })

	// Concurrent requests for the same SNI coalesce via singleflight into one leaf.
	const workers = 16
	certs := make([]*x509.Certificate, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			tlsCert, err := cache.Leaf("API.Anthropic.com.")
			if err != nil {
				t.Errorf("Leaf: %v", err)
				return
			}
			parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
			if err != nil {
				t.Errorf("ParseCertificate: %v", err)
				return
			}
			certs[idx] = parsed
		}(i)
	}
	wg.Wait()

	for i := 1; i < workers; i++ {
		if certs[i] == nil || certs[0] == nil || certs[i].SerialNumber.Cmp(certs[0].SerialNumber) != 0 {
			t.Fatalf("singleflight did not coalesce leaf minting: serial %v != %v", certs[i], certs[0])
		}
	}

	// Verify signed leaf validates cleanly against CA cert.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CertPEM) {
		t.Fatal("AppendCertsFromPEM failed")
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{DNSName: "api.anthropic.com", Roots: roots}); err != nil {
		t.Fatalf("leaf verify failed: %v", err)
	}

	// Capacity bound evicts oldest name cleanly: re-requesting api.anthropic.com
	// after 3 other names must mint a fresh leaf with a new serial number.
	for _, h := range []string{"h2.example.com", "h3.example.com", "h4.example.com"} {
		if _, err := cache.Leaf(h); err != nil {
			t.Fatalf("Leaf %s: %v", h, err)
		}
	}
	reminted, err := cache.Leaf("api.anthropic.com")
	if err != nil {
		t.Fatalf("remint evicted api.anthropic.com: %v", err)
	}
	remintedCert, err := x509.ParseCertificate(reminted.Certificate[0])
	if err != nil {
		t.Fatalf("parse reminted leaf: %v", err)
	}
	if remintedCert.SerialNumber.Cmp(certs[0].SerialNumber) == 0 {
		t.Fatal("expected oldest leaf api.anthropic.com to be evicted and reminted with a new serial")
	}

	// Keep os import cleanly used by verifying key file mode 0600 on Linux.
	fi, err := os.Stat(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("stat ca.key: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("ca.key perm = %o, want 0600", fi.Mode().Perm())
	}
}
