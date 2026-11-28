// SPDX-License-Identifier: AGPL-3.0-only

package secret

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"
)

// alt is one way a single character of a secret may appear in a response.
// Hex digits in escapes match in either case, so fold is set for those.
type alt struct {
	s    string
	fold bool
}

func (a alt) matches(b []byte) bool {
	if a.fold {
		return strings.EqualFold(a.s, string(b))
	}
	return a.s == string(b)
}

// prefixOf reports whether b, shorter than a.s, is the start of a.
func (a alt) prefixOf(b []byte) bool {
	if a.fold {
		return strings.EqualFold(a.s[:len(b)], string(b))
	}
	return a.s[:len(b)] == string(b)
}

var jsonEscapes = map[rune]string{
	'"': `\"`, '\\': `\\`, '/': `\/`, '\b': `\b`, '\f': `\f`, '\n': `\n`, '\r': `\r`, '\t': `\t`,
}

// altsFor lists every encoding of the character c (one UTF-8 character, or one
// stray byte when valid is false): literal, percent-encoded byte-wise, \uXXXX
// (a surrogate pair above the BMP), a JSON one-character escape, and "+" for a
// space. Each character of a secret is matched independently, so partly
// escaped forms such as Python's quote ("ab/cd%2Bef%3D%3D") match too.
func altsFor(lit string, r rune, valid bool) []alt {
	alts := []alt{{s: lit}}
	var pct strings.Builder
	for i := 0; i < len(lit); i++ {
		fmt.Fprintf(&pct, "%%%02X", lit[i])
	}
	alts = append(alts, alt{s: pct.String(), fold: true})
	if !valid {
		return alts
	}
	if r > 0xFFFF {
		hi, lo := 0xD800+((r-0x10000)>>10), 0xDC00+((r-0x10000)&0x3FF)
		alts = append(alts, alt{s: fmt.Sprintf(`\u%04X\u%04X`, hi, lo), fold: true})
	} else {
		alts = append(alts, alt{s: fmt.Sprintf(`\u%04X`, r), fold: true})
	}
	if esc, ok := jsonEscapes[r]; ok {
		alts = append(alts, alt{s: esc})
	}
	if r == ' ' {
		alts = append(alts, alt{s: "+"})
	}
	return alts
}

// matcher recognises one secret in any mix of the encodings above.
type matcher struct {
	chars       [][]alt
	placeholder []byte
}

func newMatcher(value, placeholder string) matcher {
	m := matcher{placeholder: []byte(placeholder)}
	for i := 0; i < len(value); {
		r, size := utf8.DecodeRuneInString(value[i:])
		m.chars = append(m.chars, altsFor(value[i:i+size], r, r != utf8.RuneError || size > 1))
		i += size
	}
	return m
}

// match returns the length of the longest encoded secret at the start of b (-1 if
// none) and whether b ends while a longer one could still be completing.
func (m matcher) match(b []byte, k int) (end int, partial bool) {
	if k == len(m.chars) {
		return 0, false
	}
	end = -1
	for _, a := range m.chars[k] {
		switch {
		case len(b) < len(a.s):
			partial = partial || a.prefixOf(b)
		case a.matches(b[:len(a.s)]):
			e, p := m.match(b[len(a.s):], k+1)
			partial = partial || p
			if e >= 0 && len(a.s)+e > end {
				end = len(a.s) + e
			}
		}
	}
	return end, partial
}

// Redactor rewrites every occurrence of a bound secret, in any of the encodings
// above, back to its inert placeholder across headers, streaming bodies, and
// trailers. Covered: literal; percent-encoded in either hex case, in full or per
// character (RFC 3986 and form "+" for space); JSON \uXXXX in either hex case
// and JSON one-character escapes (including PHP's \/ and HTML-safe =). Not
// covered: base64/hex/UTF-16 re-encodings and other transforms of the secret.
type Redactor struct {
	matchers []matcher
}

// NewRedactor builds a Redactor for pairs. Empty values are ignored.
func NewRedactor(pairs []Pair) *Redactor {
	r := &Redactor{}
	for _, p := range pairs {
		if p.Value != "" && p.Placeholder != "" && p.Value != p.Placeholder {
			r.matchers = append(r.matchers, newMatcher(p.Value, p.Placeholder))
		}
	}
	return r
}

// Active reports whether the redactor has any secret patterns to scrub.
func (r *Redactor) Active() bool {
	return r != nil && len(r.matchers) > 0
}

// ScrubBytes replaces all encoded secrets in b with their placeholders.
func (r *Redactor) ScrubBytes(b []byte) []byte {
	if !r.Active() || len(b) == 0 {
		return b
	}
	emitted, _ := r.scan(b, true)
	return emitted
}

// scan processes buf left to right. When final is false it stops at the first
// position whose tail could still grow into a secret and returns that tail as the
// unscrubbed remainder, so nothing else is delayed.
func (r *Redactor) scan(buf []byte, final bool) (emitted []byte, remainder []byte) {
	out := make([]byte, 0, len(buf))
	for i := 0; i < len(buf); {
		tail := buf[i:]
		n, repl, partial := r.longest(tail)
		if !final && partial {
			return out, append([]byte(nil), tail...)
		}
		if n > 0 {
			out = append(out, repl...)
			i += n
			continue
		}
		out = append(out, buf[i])
		i++
	}
	return out, nil
}

// longest returns the longest secret matching at the start of tail, its
// placeholder, and whether any secret could still complete past the end of tail.
func (r *Redactor) longest(tail []byte) (n int, repl []byte, partial bool) {
	for _, m := range r.matchers {
		e, p := m.match(tail, 0)
		partial = partial || p
		if e > n {
			n, repl = e, m.placeholder
		}
	}
	return n, repl, partial
}

// ScrubString replaces all encoded secrets in s with their placeholders.
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
// unscrubbed tail bytes across chunk boundaries.
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

	buf := bytes.Join([][]byte{sw.carry, p}, nil)
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
