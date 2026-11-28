// SPDX-License-Identifier: AGPL-3.0-only

package secret_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/goleak"

	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/secret"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func randSecret(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return "sec+" + hex.EncodeToString(b[:]) + "/&\"<>"
}

func TestFileResolverValidation(t *testing.T) {
	dir := t.TempDir()
	res := secret.FileResolver{}

	// Positive control: single trailing LF and CRLF stripped cleanly.
	pLF := filepath.Join(dir, "lf")
	if err := os.WriteFile(pLF, []byte("my-secret\n"), 0o600); err != nil {
		t.Fatalf("write lf: %v", err)
	}
	if got, err := res.Resolve(pLF); err != nil || got != "my-secret" {
		t.Fatalf("Resolve LF = (%q, %v), want (my-secret, nil)", got, err)
	}

	pCRLF := filepath.Join(dir, "crlf")
	if err := os.WriteFile(pCRLF, []byte("my-secret\r\n"), 0o600); err != nil {
		t.Fatalf("write crlf: %v", err)
	}
	if got, err := res.Resolve(pCRLF); err != nil || got != "my-secret" {
		t.Fatalf("Resolve CRLF = (%q, %v), want (my-secret, nil)", got, err)
	}

	// Containment: missing, empty, whitespace-only newline, interior CR/LF/NUL all fail closed.
	for name, content := range map[string][]byte{
		"empty":         []byte(""),
		"only-nl":       []byte("\n"),
		"double-nl":     []byte("tok\n\n"),
		"interior-lf":   []byte("line1\nline2"),
		"interior-cr":   []byte("line1\rline2"),
		"interior-null": []byte("tok\x00evil"),
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if got, err := res.Resolve(p); err == nil {
			t.Fatalf("%s: expected error, got %q", name, got)
		}
	}
	if _, err := res.Resolve(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file must fail closed")
	}
}

func TestApplyRequestSubstitutionAndUnconditionalPostSubSweep(t *testing.T) {
	dir := t.TempDir()
	valA := "real_" + randSecret(t)
	fileA := filepath.Join(dir, "secA")
	if err := os.WriteFile(fileA, []byte(valA+"\n"), 0o600); err != nil {
		t.Fatalf("write secA: %v", err)
	}

	bindingBasic := config.BindingConfig{
		Name:        "forge-basic",
		Host:        "code.lan.example",
		Header:      "Authorization",
		Scheme:      "basic",
		Placeholder: "mf_ph_A",
		SecretFile:  fileA,
	}

	// Bound host on :443: substitutes Basic Auth for mf_ph_A AND still strips X-Leak (mf_ph_B),
	// X-Copy (mf_ph_A in wrong header), X-Basic-Leak (Basic base64(u:mf_ph_B)), and Proxy-Authorization!
	hdr := make(http.Header)
	hdr.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("git:mf_ph_A")))
	hdr.Set("X-Leak", "Bearer mf_ph_B")
	hdr.Set("X-Wrong-Header", "mf_ph_A")
	hdr.Set("X-Basic-Leak", "Basic "+base64.StdEncoding.EncodeToString([]byte("u:mf_ph_B")))
	hdr.Set("Proxy-Authorization", "Basic dXNlcjpwYXNz")
	hdr.Set("X-Normal", "keep-me")

	pairs, err := secret.ResolveHostPairs([]config.BindingConfig{bindingBasic})
	if err != nil {
		t.Fatalf("ResolveHostPairs: %v", err)
	}
	applied, err := secret.ApplyRequest(hdr, []config.BindingConfig{bindingBasic}, pairs, 443)
	if err != nil {
		t.Fatalf("ApplyRequest: %v", err)
	}
	names := applied.Names
	if len(names) != 1 || names[0] != "forge-basic" || len(pairs) != 1 {
		t.Fatalf("unexpected names=%v pairs=%+v", names, pairs)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("git:"+valA))
	if got := hdr.Get("Authorization"); got != wantAuth {
		t.Fatalf("Authorization = %q, want %q", got, wantAuth)
	}
	for _, stripped := range []string{"X-Leak", "X-Wrong-Header", "X-Basic-Leak", "Proxy-Authorization"} {
		if hdr.Get(stripped) != "" {
			t.Fatalf("header %s was not stripped on bound host: %q", stripped, hdr.Get(stripped))
		}
	}
	if hdr.Get("X-Normal") != "keep-me" {
		t.Fatalf("normal header lost: %q", hdr.Get("X-Normal"))
	}

	// Cleartext port 80: MUST NOT substitute AND MUST strip mf_ph_A even when binding exists.
	hdr80 := make(http.Header)
	hdr80.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("git:mf_ph_A")))
	hdr80.Set("Proxy-Authorization", "Bearer abc")
	applied80, err := secret.ApplyRequest(hdr80, []config.BindingConfig{bindingBasic}, pairs, 80)
	if err != nil {
		t.Fatalf("ApplyRequest :80: %v", err)
	}
	if names80 := applied80.Names; len(names80) != 0 {
		t.Fatalf("port 80 must never substitute secrets, got %v", names80)
	}
	if hdr80.Get("Authorization") != "" || hdr80.Get("Proxy-Authorization") != "" {
		t.Fatalf("port 80 did not strip placeholder / Proxy-Authorization: %+v", hdr80)
	}
}

func TestStreamingRedactorAcrossChunkBoundariesAndEncodings(t *testing.T) {
	secVal := randSecret(t)
	ph := "mf_ph_forge"
	red := secret.NewRedactor([]secret.Pair{{Name: "forge", Placeholder: ph, Value: secVal}})

	jsonBytes, err := json.Marshal(secVal)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	jsonInner := strings.Trim(string(jsonBytes), `"`)
	urlForm := url.QueryEscape(secVal)

	payload := "literal=" + secVal + "|url=" + urlForm + "|json=" + jsonInner + "|end"

	// Feed 3 bytes at a time to force every single secret form across multiple chunk boundaries.
	var out bytes.Buffer
	sw := red.StreamWriter(&out, nil)
	for i := 0; i < len(payload); i += 3 {
		end := i + 3
		if end > len(payload) {
			end = len(payload)
		}
		if _, err := sw.Write([]byte(payload[i:end])); err != nil {
			t.Fatalf("StreamWriter.Write: %v", err)
		}
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("StreamWriter.Close: %v", err)
	}

	got := out.String()
	for _, forbidden := range []string{secVal, urlForm, jsonInner} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("redacted output leaked %q:\n%s", forbidden, got)
		}
	}
	want := "literal=" + ph + "|url=" + ph + "|json=" + ph + "|end"
	if got != want {
		t.Fatalf("redacted output = %q, want %q", got, want)
	}
}

// TestStreamingRedactorPrefixSecretAcrossChunkBoundary verifies that a shorter secret
// that is a prefix of a longer secret on the same host does not match prematurely
// at a chunk boundary and leak the longer secret's suffix.
func TestStreamingRedactorPrefixSecretAcrossChunkBoundary(t *testing.T) {
	shortSec := "tok_prefix_1234"
	longSec := shortSec + "_SECRET_SUFFIX_9999"
	red := secret.NewRedactor([]secret.Pair{
		{Name: "short", Placeholder: "mf_ph_short", Value: shortSec},
		{Name: "long", Placeholder: "mf_ph_long", Value: longSec},
	})

	var out bytes.Buffer
	sw := red.StreamWriter(&out, nil)
	// Chunk 1 ends right at the end of shortSec; chunk 2 carries the suffix of longSec!
	if _, err := sw.Write([]byte("lead " + shortSec)); err != nil {
		t.Fatalf("Write chunk 1: %v", err)
	}
	if _, err := sw.Write([]byte("_SECRET_SUFFIX_9999 tail")); err != nil {
		t.Fatalf("Write chunk 2: %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got := out.String()
	if strings.Contains(got, "SECRET_SUFFIX") || strings.Contains(got, shortSec) {
		t.Fatalf("prefix secret leaked suffix across chunk boundary: %q", got)
	}
	if got != "lead mf_ph_long tail" {
		t.Fatalf("got %q, want %q", got, "lead mf_ph_long tail")
	}
}

func writeSecret(t *testing.T, val string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sec")
	if err := os.WriteFile(p, []byte(val+"\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	return p
}

// TestPlaceholderMustBeExactBoundHeaderValue pins that the guest cannot choose where
// the placeholder sits: only the exact scheme form is substituted, every other
// mention in the bound header is refused, and a header without the placeholder passes.
func TestPlaceholderMustBeExactBoundHeaderValue(t *testing.T) {
	const ph = "mf_ph_exact"
	real := "real-" + randSecret(t)
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	mk := func(scheme string) config.BindingConfig {
		return config.BindingConfig{Name: "n-" + scheme, Host: "h.example", Header: "Authorization", Scheme: scheme, Placeholder: ph, SecretFile: writeSecret(t, real)}
	}
	cases := []struct {
		scheme, in string
		want       string // "" means refused
	}{
		{"bearer", "Bearer " + ph, "Bearer " + real},
		{"bearer", "bearer " + ph, "bearer " + real},
		{"bearer", "Bearer x" + ph, ""},
		{"bearer", "Bearer " + ph + "x", ""},
		{"bearer", "Bearer  " + ph, ""},
		{"bearer", "Bearer " + ph + " " + ph, ""},
		{"bearer", "Token " + ph, ""},
		{"token", "Token " + ph, "Token " + real},
		{"token", "Bearer " + ph, ""},
		{"raw", ph, real},
		{"raw", "prefix-" + ph, ""},
		{"raw", ph + ",other", ""},
		{"basic", "Basic " + b64("git:"+ph), "Basic " + b64("git:"+real)},
		{"basic", "Basic " + b64(":"+ph), "Basic " + b64(":"+real)},
		{"basic", "Basic " + b64("git:x"+ph), ""},
		{"basic", "Basic " + b64(ph+":pw"), ""},
		{"basic", "Basic " + b64("git:"+ph+":more"), ""},
		{"basic", "Bearer " + ph, ""},
		// Positive control: a header with no placeholder at all is the guest's own credential.
		{"bearer", "Bearer guest-own-token", "Bearer guest-own-token"},
	}
	for _, tc := range cases {
		b := mk(tc.scheme)
		pairs, err := secret.ResolveHostPairs([]config.BindingConfig{b})
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		hdr := http.Header{"Authorization": {tc.in}}
		applied, err := secret.ApplyRequest(hdr, []config.BindingConfig{b}, pairs, 443)
		if tc.want == "" {
			var mis *secret.MisplacedError
			if !errors.As(err, &mis) || mis.Name != b.Name {
				t.Errorf("%s %q: err = %v, want *MisplacedError", tc.scheme, tc.in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s %q: unexpected error %v", tc.scheme, tc.in, err)
			continue
		}
		if got := hdr.Get("Authorization"); got != tc.want {
			t.Errorf("%s %q: Authorization = %q, want %q", tc.scheme, tc.in, got, tc.want)
		}
		if tc.want != tc.in && len(applied.Names) != 1 {
			t.Errorf("%s %q: names = %v", tc.scheme, tc.in, applied.Names)
		}
	}
}

// TestBasicAuthEchoIsScrubbed pins that a response echoing the whole Basic header
// the gateway sent (base64(user:secret)) comes back as the guest's own value.
func TestBasicAuthEchoIsScrubbed(t *testing.T) {
	const ph = "mf_ph_echo"
	real := "real-" + randSecret(t)
	b := config.BindingConfig{Name: "echo", Host: "h.example", Header: "Authorization", Scheme: "basic", Placeholder: ph, SecretFile: writeSecret(t, real)}
	pairs, err := secret.ResolveHostPairs([]config.BindingConfig{b})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	guest := "Basic " + base64.StdEncoding.EncodeToString([]byte("git:"+ph))
	hdr := http.Header{"Authorization": {guest}}
	applied, err := secret.ApplyRequest(hdr, []config.BindingConfig{b}, pairs, 443)
	if err != nil {
		t.Fatalf("ApplyRequest: %v", err)
	}
	sent := hdr.Get("Authorization")
	if sent == guest {
		t.Fatal("control: Authorization was not substituted")
	}
	red := secret.NewRedactor(append(pairs, applied.Echoes...))
	if got := red.ScrubString(`{"auth":"` + sent + `"}`); got != `{"auth":"`+guest+`"}` {
		t.Fatalf("echoed Basic header not scrubbed: %q", got)
	}
	// Control: a Redactor built without the echoes would have let it through.
	if got := secret.NewRedactor(pairs).ScrubString(sent); got != sent {
		t.Fatalf("control: bare-secret redactor unexpectedly scrubbed the encoded form: %q", got)
	}
}
