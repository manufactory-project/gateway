// SPDX-License-Identifier: AGPL-3.0-only

package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/ca"
)

// writeCA writes a self-signed cert built from tmpl and its key (mode 0600).
func writeCA(t *testing.T, dir string, tmpl *x509.Certificate) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl.SerialNumber = big.NewInt(1)
	tmpl.Subject = pkix.Name{CommonName: "test ca"}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	certPath, keyPath = filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func caTemplate() *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
}

// TestLoadRefusesUnsoundCA pins the hygiene checks on an operator-supplied CA and
// keeps a well-formed one loading as the positive control.
func TestLoadRefusesUnsoundCA(t *testing.T) {
	cert, key := writeCA(t, t.TempDir(), caTemplate())
	if _, err := ca.Load(cert, key); err != nil {
		t.Fatalf("control: sound CA must load: %v", err)
	}

	mutations := map[string]func(*x509.Certificate){
		"not a CA":     func(c *x509.Certificate) { c.IsCA = false },
		"no cert sign": func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature },
		"expired":      func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) },
		"not yet valid": func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(time.Hour)
			c.NotAfter = time.Now().Add(2 * time.Hour)
		},
	}
	for name, mutate := range mutations {
		tmpl := caTemplate()
		mutate(tmpl)
		c, k := writeCA(t, t.TempDir(), tmpl)
		if _, err := ca.Load(c, k); err == nil {
			t.Errorf("%s: Load succeeded, want it refused", name)
		}
	}

	for _, mode := range []os.FileMode{0o640, 0o604, 0o660, 0o644} {
		c, k := writeCA(t, t.TempDir(), caTemplate())
		if err := os.Chmod(k, mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		if _, err := ca.Load(c, k); err == nil {
			t.Errorf("key mode %o: Load succeeded, want it refused", mode)
		}
	}

	c, k := writeCA(t, t.TempDir(), caTemplate())
	link := filepath.Join(filepath.Dir(k), "link.key")
	if err := os.Symlink(k, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := ca.Load(c, link); err == nil {
		t.Error("symlinked key: Load succeeded, want it refused")
	}
}

// TestInitNeverFollowsOrReusesExistingFiles pins that Init writes fresh files with
// exactly the intended modes, and refuses a symlink (dangling included) or any
// existing file at either path, leaving the symlink's target untouched.
func TestInitNeverFollowsOrReusesExistingFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := ca.Init(filepath.Join(dir, "ok.crt"), filepath.Join(dir, "ok.key")); err != nil {
		t.Fatalf("control: Init: %v", err)
	}
	for path, want := range map[string]os.FileMode{"ok.crt": 0o644, "ok.key": 0o600} {
		fi, err := os.Stat(filepath.Join(dir, path))
		if err != nil || fi.Mode().Perm() != want {
			t.Fatalf("%s: mode = %v (err %v), want %o", path, fi.Mode(), err, want)
		}
	}
	if left, err := filepath.Glob(filepath.Join(dir, ".ca-*")); err != nil || len(left) != 0 {
		t.Fatalf("temp files left behind: %v (%v)", left, err)
	}

	victim := filepath.Join(dir, "victim")
	for name, target := range map[string]string{"dangling": filepath.Join(dir, "nowhere"), "existing": victim} {
		d := t.TempDir()
		if err := os.WriteFile(victim, []byte("keep"), 0o666); err != nil {
			t.Fatalf("write victim: %v", err)
		}
		keyPath := filepath.Join(d, "ca.key")
		if err := os.Symlink(target, keyPath); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if _, err := ca.Init(filepath.Join(d, "ca.crt"), keyPath); err == nil {
			t.Errorf("%s symlink: Init succeeded, want it refused", name)
		}
		if raw, err := os.ReadFile(victim); err != nil || string(raw) != "keep" {
			t.Errorf("%s symlink: target was written through: %q (%v)", name, raw, err)
		}
	}
}
