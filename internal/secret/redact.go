package secret

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type needle struct {
	pattern     []byte
	replacement []byte
}

// Redactor rewrites literal, URL-encoded, and JSON-escaped occurrences of bound
// secrets back to their inert placeholders across headers, streaming bodies,
// and trailers (NOW.md:61).
type Redactor struct {
	needles []needle
	maxLen  int
}

// NewRedactor builds a Redactor for pairs. Empty values are ignored.
func NewRedactor(pairs []Pair) *Redactor {
	seen := make(map[string]bool)
	var needles []needle
	add := func(pat, repl string) {
		if pat == "" || pat == repl || seen[pat] {
			return
		}
		seen[pat] = true
		needles = append(needles, needle{
			pattern:     []byte(pat),
			replacement: []byte(repl),
		})
	}

	for _, p := range pairs {
		if p.Value == "" || p.Placeholder == "" {
			continue
		}
		// 1. Literal form
		add(p.Value, p.Placeholder)

		// 2. URL-encoded forms (query + path escaping, plus lowercase hex variants)
		qe := url.QueryEscape(p.Value)
		add(qe, p.Placeholder)
		add(lowerPercentHex(qe), p.Placeholder)

		pe := url.PathEscape(p.Value)
		add(pe, p.Placeholder)
		add(lowerPercentHex(pe), p.Placeholder)

		// 3. JSON-escaped forms (both default HTML-escaped and standard non-HTML-escaped)
		if jHTML, ok := jsonStringInner(p.Value, true); ok {
			add(jHTML, p.Placeholder)
		}
		if jPlain, ok := jsonStringInner(p.Value, false); ok {
			add(jPlain, p.Placeholder)
		}
	}

	// Longest patterns first so encoded forms win over shorter prefixes.
	sort.Slice(needles, func(i, j int) bool {
		if len(needles[i].pattern) != len(needles[j].pattern) {
			return len(needles[i].pattern) > len(needles[j].pattern)
		}
		return bytes.Compare(needles[i].pattern, needles[j].pattern) < 0
	})

	maxLen := 0
	for _, n := range needles {
		if len(n.pattern) > maxLen {
			maxLen = len(n.pattern)
		}
	}
	return &Redactor{needles: needles, maxLen: maxLen}
}

// Active reports whether the redactor has any secret patterns to scrub.
func (r *Redactor) Active() bool {
	return r != nil && len(r.needles) > 0
}

// ScrubBytes replaces all matching secret forms in b with their placeholders
// in a single left-to-right longest-match-first pass.
func (r *Redactor) ScrubBytes(b []byte) []byte {
	if !r.Active() || len(b) == 0 {
		return b
	}
	emitted, _ := r.scan(b, true)
	return emitted
}

// scan processes buf left-to-right matching longest secrets first.
// When final is false, it stops before the last maxLen-1 raw bytes and returns
// them as unscrubbed remainder so a shorter secret that is a prefix of a longer
// secret cannot prematurely match and leak the longer secret's suffix across a
// chunk boundary.
func (r *Redactor) scan(buf []byte, final bool) (emitted []byte, remainder []byte) {
	safeLimit := len(buf)
	if !final {
		keep := r.maxLen - 1
		if keep < 0 {
			keep = 0
		}
		if len(buf) <= keep {
			return nil, append([]byte(nil), buf...)
		}
		safeLimit = len(buf) - keep
	}

	out := make([]byte, 0, safeLimit)
	i := 0
	for i < safeLimit {
		matched := false
		for _, n := range r.needles {
			if len(buf)-i >= len(n.pattern) && bytes.HasPrefix(buf[i:], n.pattern) {
				out = append(out, n.replacement...)
				i += len(n.pattern)
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, buf[i])
			i++
		}
	}
	if i < len(buf) {
		remainder = append([]byte(nil), buf[i:]...)
	}
	return out, remainder
}

// ScrubString replaces all matching secret forms in s with their placeholders.
func (r *Redactor) ScrubString(s string) string {
	if !r.Active() || s == "" {
		return s
	}
	return string(r.ScrubBytes([]byte(s)))
}

// ScrubHeader rewrites every value in h in place.
func (r *Redactor) ScrubHeader(h http.Header) {
	if !r.Active() {
		return
	}
	for k, vals := range h {
		for i, v := range vals {
			vals[i] = r.ScrubString(v)
		}
		h[k] = vals
	}
}

// StreamWriter returns a sliding-window streaming writer that carries raw
// unscrubbed tail bytes across chunk boundaries and matches longest secrets first.
func (r *Redactor) StreamWriter(dst io.Writer, flushFn func() error) *StreamWriter {
	return &StreamWriter{
		redactor: r,
		dst:      dst,
		flushFn:  flushFn,
	}
}

// StreamWriter scrubs streaming bytes in constant O(maxPatternLen) tail memory.
type StreamWriter struct {
	redactor *Redactor
	dst      io.Writer
	flushFn  func() error
	carry    []byte
	written  int64
}

// Write appends raw p to the unscrubbed sliding window, emits only safe prefix
// bytes where longest-match is unambiguous, and retains at most maxLen-1 raw
// trailing bytes for cross-boundary matches.
func (sw *StreamWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !sw.redactor.Active() {
		n, err := sw.dst.Write(p)
		sw.written += int64(n)
		if err != nil {
			return n, err
		}
		if sw.flushFn != nil {
			if fErr := sw.flushFn(); fErr != nil {
				return n, fErr
			}
		}
		return n, nil
	}

	buf := make([]byte, len(sw.carry)+len(p))
	copy(buf, sw.carry)
	copy(buf[len(sw.carry):], p)

	emit, rem := sw.redactor.scan(buf, false)
	sw.carry = rem
	if len(emit) == 0 {
		return len(p), nil
	}

	n, err := sw.dst.Write(emit)
	sw.written += int64(n)
	if err != nil {
		return 0, err
	}
	if sw.flushFn != nil {
		if fErr := sw.flushFn(); fErr != nil {
			return len(p), fErr
		}
	}
	return len(p), nil
}

// Close scrubs and emits any remaining raw carry bytes at EOF.
func (sw *StreamWriter) Close() error {
	if len(sw.carry) == 0 {
		return nil
	}
	final, _ := sw.redactor.scan(sw.carry, true)
	sw.carry = nil
	if len(final) == 0 {
		return nil
	}
	n, err := sw.dst.Write(final)
	sw.written += int64(n)
	if err != nil {
		return err
	}
	if sw.flushFn != nil {
		return sw.flushFn()
	}
	return nil
}

// Written returns total bytes emitted to dst.
func (sw *StreamWriter) Written() int64 {
	return sw.written
}

func jsonStringInner(s string, escapeHTML bool) (string, bool) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(escapeHTML)
	if err := enc.Encode(s); err != nil {
		return "", false
	}
	b := bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		return "", false
	}
	return string(b[1 : len(b)-1]), true
}

func lowerPercentHex(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			b.WriteByte('%')
			b.WriteByte(toLowerASCII(s[i+1]))
			b.WriteByte(toLowerASCII(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func toLowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
