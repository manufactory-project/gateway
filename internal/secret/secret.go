// SPDX-License-Identifier: AGPL-3.0-only

// Package secret implements gateway's file-only secret placeholder substitution,
// unconditional post-substitution placeholder stripping, and streaming
// sliding-window identity response redaction.
package secret

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
	"os"
	"slices"
	"strings"

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

// FileResolver reads secret values from files on demand (tmpfs / systemd LoadCredential).
type FileResolver struct{}

// Resolve reads path, strips at most one trailing \r?\n, and fails closed on
// read error, empty value, or any interior \r, \n, or \x00.
func (FileResolver) Resolve(path string) (string, error) {
	if path == "" {
		return "", errors.New("empty secret file path")
	}
	raw, err := os.ReadFile(path)
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

// ApplyRequest injects the resolved values of the matched bindings on HTTPS
// (:443) ONLY, then unconditionally sweeps Proxy-Authorization and any remaining
// mf_ph_* placeholders (literal or inside decoded Basic Auth) from EVERY header
// on EVERY request, including bound hosts and cleartext port 80. pairs must come
// from ResolveHostPairs for the same host. It returns the substituted names.
func ApplyRequest(hdr http.Header, bindings []config.BindingConfig, pairs []Pair, dstPort uint16) []string {
	var names []string
	// Substitution happens ONLY on HTTPS :443, and ONLY into the exact named header and scheme.
	if dstPort == 443 {
		for _, b := range bindings {
			if value, ok := valueFor(pairs, b.Placeholder); ok && substitute(hdr, b, value) && !slices.Contains(names, b.Name) {
				names = append(names, b.Name)
			}
		}
	}
	SweepHeaders(hdr)
	return names
}

func valueFor(pairs []Pair, placeholder string) (string, bool) {
	for _, p := range pairs {
		if p.Placeholder == placeholder {
			return p.Value, true
		}
	}
	return "", false
}

// substitute replaces b's placeholder in the values of b's header that use b's scheme.
func substitute(hdr http.Header, b config.BindingConfig, value string) bool {
	vals := hdr[textproto.CanonicalMIMEHeaderKey(b.Header)]
	changed := false
	for i, v := range vals {
		if matchesSchemeAndPlaceholder(v, b.Scheme, b.Placeholder) {
			vals[i] = substituteByScheme(v, b.Scheme, b.Placeholder, value)
			changed = true
		}
	}
	return changed
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

func matchesSchemeAndPlaceholder(val, scheme, placeholder string) bool {
	switch scheme {
	case "basic":
		_, decoded, ok := decodeBasicPayload(val)
		return ok && strings.Contains(string(decoded), placeholder)
	case "bearer":
		return hasAuthSchemePrefix(val, "bearer") && strings.Contains(val, placeholder)
	case "token":
		return hasAuthSchemePrefix(val, "token") && strings.Contains(val, placeholder)
	case "raw":
		return strings.Contains(val, placeholder)
	default:
		return false
	}
}

func substituteByScheme(val, scheme, placeholder, realVal string) string {
	if scheme == "basic" {
		if prefix, decoded, ok := decodeBasicPayload(val); ok && strings.Contains(string(decoded), placeholder) {
			replaced := strings.ReplaceAll(string(decoded), placeholder, realVal)
			return prefix + base64.StdEncoding.EncodeToString([]byte(replaced))
		}
		return val
	}
	return strings.ReplaceAll(val, placeholder, realVal)
}

func trimOWS(v string) string {
	return strings.Trim(v, " \t")
}

func hasAuthSchemePrefix(v, scheme string) bool {
	v = trimOWS(v)
	n := len(scheme)
	if len(v) <= n {
		return false
	}
	return strings.EqualFold(v[:n], scheme) && (v[n] == ' ' || v[n] == '\t')
}

func decodeBasicPayload(v string) (prefix string, decoded []byte, ok bool) {
	v = trimOWS(v)
	if len(v) < 6 || !strings.EqualFold(v[:5], "basic") || (v[5] != ' ' && v[5] != '\t') {
		return "", nil, false
	}
	trimmed := strings.TrimLeft(v[5:], " \t")
	if trimmed == "" {
		return "", nil, false
	}
	prefix = v[:len(v)-len(trimmed)]
	payload := strings.TrimRight(trimmed, " \t\r\n")
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(payload)
	}
	if err != nil {
		return "", nil, false
	}
	return prefix, decoded, true
}

func containsAnyPlaceholder(v, prefix string) bool {
	v = trimOWS(v)
	if strings.Contains(v, prefix) {
		return true
	}
	if _, decoded, ok := decodeBasicPayload(v); ok {
		return strings.Contains(string(decoded), prefix)
	}
	return false
}
