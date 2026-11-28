// SPDX-License-Identifier: AGPL-3.0-only

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
// and trailers.
type Redactor struct {
	needles []needle // longest first
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

	return &Redactor{needles: needles}
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

// scan processes buf left-to-right matching longest secrets first. When final is
// false it stops at the first position whose tail could still grow into a secret
// and returns that tail as the unscrubbed remainder, so nothing else is delayed.
func (r *Redactor) scan(buf []byte, final bool) (emitted []byte, remainder []byte) {
	out := make([]byte, 0, len(buf))
	for i := 0; i < len(buf); {
		tail := buf[i:]
		if !final && r.mayExtend(tail) {
			return out, append([]byte(nil), tail...)
		}
		if n, ok := r.match(tail); ok {
			out = append(out, n.replacement...)
			i += len(n.pattern)
			continue
		}
		out = append(out, buf[i])
		i++
	}
	return out, nil
}

// mayExtend reports whether tail is a proper prefix of any secret pattern.
func (r *Redactor) mayExtend(tail []byte) bool {
	for _, n := range r.needles {
		if len(n.pattern) > len(tail) && bytes.HasPrefix(n.pattern, tail) {
			return true
		}
	}
	return false
}

// match returns the longest secret pattern that b starts with.
func (r *Redactor) match(b []byte) (needle, bool) {
	for _, n := range r.needles {
		if bytes.HasPrefix(b, n.pattern) {
			return n, true
		}
	}
	return needle{}, false
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

// StreamWriter scrubs streaming bytes, holding back at most one partial secret.
type StreamWriter struct {
	redactor *Redactor
	dst      io.Writer
	flushFn  func() error
	carry    []byte
	written  int64
}

// Write appends raw p to the carried tail, emits every byte that cannot be part
// of a still-incomplete secret, and carries the rest to the next call.
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
