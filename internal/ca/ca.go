// SPDX-License-Identifier: AGPL-3.0-only

// Package ca loads operator-supplied MITM CA keypairs, initializes new CAs for
// `gateway ca init`, and mints/caches per-SNI ECDSA P-256 leaf certificates using
// RWMutex + singleflight so no lock is ever held during keygen or signing.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	caNotBeforeSkew = time.Hour
	caValidity      = 10 * 365 * 24 * time.Hour

	leafValidity    = 24 * time.Hour
	leafRenewWithin = time.Hour
	leafCacheCap    = 1024
)

// CA holds the loaded MITM root certificate and signing private key.
type CA struct {
	Certificate *x509.Certificate
	Key         crypto.Signer
	CertPEM     []byte
}

// Init generates a fresh ECDSA P-256 CA and writes certPath (0644) and keyPath (0600)
// atomically. It refuses to overwrite if either file already exists.
func Init(certPath, keyPath string) (CA, error) {
	if certPath == "" || keyPath == "" {
		return CA{}, errors.New("ca: cert_path and key_path are required")
	}
	for _, p := range []string{certPath, keyPath} {
		exists, err := fileExists(p)
		if err != nil {
			return CA{}, fmt.Errorf("ca: stat %s: %w", p, err)
		}
		if exists {
			return CA{}, fmt.Errorf("ca: %s already exists (refusing to overwrite)", p)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return CA{}, fmt.Errorf("ca: generate key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return CA{}, fmt.Errorf("ca: generate serial: %w", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "gateway MITM CA"},
		NotBefore:             now.Add(-caNotBeforeSkew),
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return CA{}, fmt.Errorf("ca: create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return CA{}, fmt.Errorf("ca: parse generated certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return CA{}, fmt.Errorf("ca: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	if err := writeAtomic(keyPath, keyPEM, 0o600); err != nil {
		return CA{}, fmt.Errorf("ca: write key %s: %w", keyPath, err)
	}
	if err := writeAtomic(certPath, certPEM, 0o644); err != nil {
		rmErr := os.Remove(keyPath)
		return CA{}, errors.Join(fmt.Errorf("ca: write cert %s: %w", certPath, err), rmErr)
	}
	return CA{Certificate: cert, Key: key, CertPEM: certPEM}, nil
}

// Load reads an operator-supplied CA certificate and private key from certPath and keyPath.
// It fails closed if either file is missing, invalid, not a CA cert, or mismatched.
func Load(certPath, keyPath string) (CA, error) {
	if certPath == "" || keyPath == "" {
		return CA{}, errors.New("ca: cert_path and key_path are required")
	}

	rawCert, err := os.ReadFile(certPath)
	if err != nil {
		return CA{}, fmt.Errorf("ca: read cert %s: %w", certPath, err)
	}
	certBlock, _ := pem.Decode(rawCert)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return CA{}, fmt.Errorf("ca: parse cert %s: no CERTIFICATE PEM block", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return CA{}, fmt.Errorf("ca: parse cert %s: %w", certPath, err)
	}
	if !cert.IsCA {
		return CA{}, fmt.Errorf("ca: cert %s is not a CA certificate", certPath)
	}
	// Re-encode strictly the first CERTIFICATE block so trailing blocks never leak.
	cleanCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBlock.Bytes})

	rawKey, err := os.ReadFile(keyPath)
	if err != nil {
		return CA{}, fmt.Errorf("ca: read key %s: %w", keyPath, err)
	}
	keyBlock, _ := pem.Decode(rawKey)
	if keyBlock == nil {
		return CA{}, fmt.Errorf("ca: parse key %s: no PEM block", keyPath)
	}
	signer, err := parseSigner(keyBlock)
	if err != nil {
		return CA{}, fmt.Errorf("ca: parse key %s: %w", keyPath, err)
	}

	pubEqual, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pubEqual.Equal(signer.Public()) {
		return CA{}, fmt.Errorf("ca: key %s does not match certificate %s", keyPath, certPath)
	}

	return CA{Certificate: cert, Key: signer, CertPEM: cleanCertPEM}, nil
}

func parseSigner(block *pem.Block) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("PKCS8 key does not implement crypto.Signer")
		}
		return s, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported private key format")
}

type leafEntry struct {
	cert     *tls.Certificate
	notAfter time.Time
}

// LeafCache mints and caches per-SNI ECDSA P-256 leaf certificates signed by CA.
// Lookups use RLock; minting runs in singleflight outside any cache lock.
type LeafCache struct {
	ca  CA
	now func() time.Time
	cap int

	sf singleflight.Group

	mu      sync.RWMutex
	entries map[string]*leafEntry
	order   []string
}

// NewLeafCache constructs a bounded LeafCache with capacity 1024.
func NewLeafCache(c CA) *LeafCache {
	return NewLeafCacheWithOptions(c, leafCacheCap, time.Now)
}

// NewLeafCacheWithOptions constructs a LeafCache with custom capacity and clock.
func NewLeafCacheWithOptions(c CA, capacity int, now func() time.Time) *LeafCache {
	if capacity <= 0 {
		capacity = leafCacheCap
	}
	if now == nil {
		now = time.Now
	}
	return &LeafCache{
		ca:      c,
		now:     now,
		cap:     capacity,
		entries: make(map[string]*leafEntry, capacity),
	}
}

// ErrMintLimited is returned by Leaf when the caller's admit function refuses a mint.
var ErrMintLimited = errors.New("ca: leaf mint rate limit exceeded")

// Leaf returns a valid cached leaf for name or mints one without holding c.mu.
// A cache hit never calls admit; a mint calls it once first, and Leaf returns
// ErrMintLimited when it refuses, so each caller can budget its own minting.
func (c *LeafCache) Leaf(name string, admit func() bool) (*tls.Certificate, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return nil, errors.New("ca: empty leaf name")
	}

	now := c.now().UTC()
	c.mu.RLock()
	if e, ok := c.entries[name]; ok && e.notAfter.After(now.Add(leafRenewWithin)) {
		cert := e.cert
		c.mu.RUnlock()
		return cert, nil
	}
	c.mu.RUnlock()

	v, err, _ := c.sf.Do(name, func() (any, error) {
		nowInner := c.now().UTC()
		c.mu.RLock()
		if e, ok := c.entries[name]; ok && e.notAfter.After(nowInner.Add(leafRenewWithin)) {
			cert := e.cert
			c.mu.RUnlock()
			return cert, nil
		}
		c.mu.RUnlock()

		if !admit() {
			return nil, ErrMintLimited
		}
		// Mint ECDSA key and X.509 certificate with NO cache lock held.
		cert, notAfter, err := c.mint(name, nowInner)
		if err != nil {
			return nil, err
		}

		c.mu.Lock()
		if _, existed := c.entries[name]; !existed {
			if len(c.order) >= c.cap {
				oldest := c.order[0]
				c.order = c.order[1:]
				delete(c.entries, oldest)
			}
			c.order = append(c.order, name)
		}
		c.entries[name] = &leafEntry{cert: cert, notAfter: notAfter}
		c.mu.Unlock()
		return cert, nil
	})
	if err != nil {
		return nil, err
	}
	cert, ok := v.(*tls.Certificate)
	if !ok {
		return nil, errors.New("ca: unexpected singleflight value type")
	}
	return cert, nil
}

func (c *LeafCache) mint(name string, now time.Time) (*tls.Certificate, time.Time, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("ca: generate leaf key for %s: %w", name, err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("ca: generate leaf serial for %s: %w", name, err)
	}

	notBefore := now.Add(-caNotBeforeSkew)
	notAfter := now.Add(leafValidity)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca.Certificate, &key.PublicKey, c.ca.Key)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("ca: sign leaf for %s: %w", name, err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, notAfter, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		closeErr := f.Close()
		rmErr := os.Remove(tmp)
		return errors.Join(err, closeErr, rmErr)
	}
	if err := f.Close(); err != nil {
		rmErr := os.Remove(tmp)
		return errors.Join(err, rmErr)
	}
	if err := os.Rename(tmp, path); err != nil {
		rmErr := os.Remove(tmp)
		return errors.Join(err, rmErr)
	}
	return nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}
