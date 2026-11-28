// SPDX-License-Identifier: AGPL-3.0-only

// Package secret implements gateway's file-only secret placeholder substitution,
// unconditional post-substitution placeholder stripping, and streaming
// sliding-window identity response redaction.
package secret

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"os"
	"slices"
	"strings"
	"syscall"

	"github.com/manufactory-project/gateway/internal/config"
)

// ResolveError indicates a bound secret could not be loaded or failed safety validation.
type ResolveError struct {
	Name  string
	Cause string
	Err   error
}

func (e *ResolveError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("secret %q: %s: %v", e.Name, e.Cause, e.Err)
	}
	return fmt.Sprintf("secret %q: %s", e.Name, e.Cause)
}

func (e *ResolveError) Unwrap() error { return e.Err }

// MisplacedError reports a guest request that carries a binding's placeholder in
// its bound header anywhere but the one exact form the binding allows.
type MisplacedError struct{ Name string }

func (e *MisplacedError) Error() string {
	return fmt.Sprintf("secret %q: placeholder is not exactly the bound header value", e.Name)
}

// FileResolver reads secret values from files on demand (tmpfs / systemd LoadCredential).
type FileResolver struct{}

// maxSecretBytes caps a secret file; a larger one is refused, never truncated.
const maxSecretBytes = 64 << 10

// Resolve reads path, strips at most one trailing \r?\n, and fails closed on
// read error, empty value, or any interior \r, \n, or \x00. The path must be a
// regular file, not a symlink (nor a FIFO or device, which could block or stream
// forever), not accessible to "other", and at most 64 KiB.
func (FileResolver) Resolve(path string) (string, error) {
	if path == "" {
		return "", errors.New("empty secret file path")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	raw, err := readSecret(f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	val := stripSingleTrailingNewline(string(raw))
	if val == "" {
		return "", errors.New("secret value is empty")
	}
	if strings.ContainsAny(val, "\r\n\x00") {
		return "", errors.New("secret value contains forbidden control character (CR/LF/NUL)")
	}
	return val, nil
}

func readSecret(f *os.File) ([]byte, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("secret file is not a regular file")
	}
	if fi.Mode().Perm()&0o007 != 0 {
		return nil, errors.New("secret file is accessible to other users")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxSecretBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSecretBytes {
		return nil, fmt.Errorf("secret file exceeds %d bytes", maxSecretBytes)
	}
	return raw, nil
}

func stripSingleTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\r\n") {
		return s[:len(s)-2]
	}
	if strings.HasSuffix(s, "\n") {
		return s[:len(s)-1]
	}
	return s
}

// Pair maps a resolved secret value back to its inert placeholder for response scrubbing.
type Pair struct {
	Name        string
	Placeholder string
	Value       string
}

// Applied is what ApplyRequest sent upstream.
type Applied struct {
	// Names lists the substituted bindings.
	Names []string
	// Echoes maps Basic credentials as sent upstream back to the ones the guest
	// sent, so a response that echoes them whole is scrubbed like the bare secret.
	Echoes []Pair
}

const basicPrefix = "Basic "

// ApplyRequest injects the resolved values of the matched bindings on HTTPS
// (:443) ONLY, into the one exact header value the binding allows, then
// unconditionally sweeps Proxy-Authorization and any remaining mf_ph_*
// placeholders (literal or inside decoded Basic Auth) from EVERY header on EVERY
// request, including bound hosts and cleartext port 80. A bound header that
// mentions its placeholder in any other form is refused with *MisplacedError.
// pairs must come from ResolveHostPairs for the same host.
func ApplyRequest(hdr http.Header, bindings []config.BindingConfig, pairs []Pair, dstPort uint16) (Applied, error) {
	var out Applied
	if dstPort == 443 {
		for _, b := range bindings {
			value, ok := valueFor(pairs, b.Placeholder)
			if !ok {
				continue
			}
			vals := hdr[textproto.CanonicalMIMEHeaderKey(b.Header)]
			for i, raw := range vals {
				v := trimOWS(raw) // optional whitespace is not part of the field value
				sent, exact := exactForm(v, b, value)
				switch {
				case exact:
					vals[i] = sent
					if !slices.Contains(out.Names, b.Name) {
						out.Names = append(out.Names, b.Name)
					}
					if b.Scheme == "basic" {
						out.Echoes = append(out.Echoes, Pair{Name: b.Name, Placeholder: v[len(basicPrefix):], Value: sent[len(basicPrefix):]})
					}
				case containsAnyPlaceholder(v, b.Placeholder):
					return Applied{}, &MisplacedError{Name: b.Name}
				}
			}
		}
	}
	SweepHeaders(hdr)
	return out, nil
}

func valueFor(pairs []Pair, placeholder string) (string, bool) {
	for _, p := range pairs {
		if p.Placeholder == placeholder {
			return p.Value, true
		}
	}
	return "", false
}

// exactForm reports whether v is exactly b's placeholder in b's scheme ("Bearer
// <placeholder>", "Token <placeholder>", a bare placeholder for raw, or Basic
// credentials "user:<placeholder>") and returns v with value in its place.
func exactForm(v string, b config.BindingConfig, value string) (string, bool) {
	switch b.Scheme {
	case "raw":
		return value, v == b.Placeholder
	case "bearer", "token":
		n := len(b.Scheme)
		if len(v) == n+1+len(b.Placeholder) && strings.EqualFold(v[:n], b.Scheme) && v[n] == ' ' && v[n+1:] == b.Placeholder {
			return v[:n+1] + value, true
		}
	case "basic":
		if len(v) <= len(basicPrefix) || !strings.EqualFold(v[:len(basicPrefix)], basicPrefix) {
			return "", false
		}
		dec, err := base64.StdEncoding.DecodeString(v[len(basicPrefix):])
		if err != nil {
			return "", false
		}
		user, pw, found := strings.Cut(string(dec), ":")
		if found && pw == b.Placeholder {
			return basicPrefix + base64.StdEncoding.EncodeToString([]byte(user+":"+value)), true
		}
	}
	return "", false
}

// SweepHeaders unconditionally removes Proxy-Authorization and any header whose
// value carries mf_ph_* (literally or inside a decoded Basic Auth payload).
func SweepHeaders(hdr http.Header) {
	hdr.Del("Proxy-Authorization")
	for k, vals := range hdr {
		for _, v := range vals {
			if containsAnyPlaceholder(v, config.PlaceholderPrefix) {
				delete(hdr, k)
				break
			}
		}
	}
}

// ResolveHostPairs resolves every binding declared for a host, before dispatch,
// so the same values drive substitution and response scrubbing. It fails closed
// (returning a *ResolveError) if any binding's secret cannot be resolved.
func ResolveHostPairs(bindings []config.BindingConfig) ([]Pair, error) {
	resolver := FileResolver{}
	out := make([]Pair, 0, len(bindings))
	for _, b := range bindings {
		val, err := resolver.Resolve(b.SecretFile)
		if err != nil {
			return nil, &ResolveError{Name: b.Name, Cause: "resolve failed", Err: err}
		}
		out = append(out, Pair{Name: b.Name, Placeholder: b.Placeholder, Value: val})
	}
	return out, nil
}

func trimOWS(v string) string {
	return strings.Trim(v, " \t")
}

// decodeBasicPayload leniently decodes a Basic credential for the sweep, which
// must see through any encoding the guest might use to smuggle a placeholder.
func decodeBasicPayload(v string) (decoded []byte, ok bool) {
	v = trimOWS(v)
	if len(v) < 6 || !strings.EqualFold(v[:5], "basic") || (v[5] != ' ' && v[5] != '\t') {
		return nil, false
	}
	payload := strings.TrimRight(strings.TrimLeft(v[5:], " \t"), " \t\r\n")
	if payload == "" {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(payload)
	}
	return decoded, err == nil
}

func containsAnyPlaceholder(v, prefix string) bool {
	v = trimOWS(v)
	if strings.Contains(v, prefix) {
		return true
	}
	decoded, ok := decodeBasicPayload(v)
	return ok && strings.Contains(string(decoded), prefix)
}
