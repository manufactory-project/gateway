// Package audit provides a fail-closed, bounded, structured JSONL audit log
// for gatewayd. Header values are never part of the Event schema, query strings
// are stripped before recording, and peer-supplied strings are escaped.
package audit

import (
	"net/url"
	"strings"
	"unicode"
)

// EscapeHost renders a guest-supplied hostname so control characters, quotes,
// whitespace, and structural punctuation cannot forge log or terminal lines.
func EscapeHost(host string) string {
	return escapeField(host, isPlainHostRune)
}

// EscapeMethod renders an HTTP method restricted to RFC 9110 tchar tokens.
func EscapeMethod(method string) string {
	return escapeField(method, isPlainMethodRune)
}

// EscapePath renders a URL path restricted to safe printable path characters
// (no whitespace, quotes, or control characters).
func EscapePath(p string) string {
	return escapeField(p, isPlainPathRune)
}

// EscapeString renders an arbitrary string with every non-printable rune or
// newline escaped.
func EscapeString(s string) string {
	return escapeField(s, func(r rune) bool {
		return unicode.IsPrint(r) && r != '"' && r != '\\'
	})
}

// StripQuery extracts only the path component from rawTarget, discarding any
// query string or fragment so query values never reach the audit log.
// hasQuery reports whether a query separator ('?') was present.
func StripQuery(rawTarget string) (pathOnly string, hasQuery bool) {
	if rawTarget == "" {
		return "", false
	}
	if idx := strings.IndexByte(rawTarget, '#'); idx >= 0 {
		rawTarget = rawTarget[:idx]
	}
	if idx := strings.IndexByte(rawTarget, '?'); idx >= 0 {
		hasQuery = true
		rawTarget = rawTarget[:idx]
	}
	// If a full URL was passed, extract only its path.
	if strings.Contains(rawTarget, "://") {
		if u, err := url.Parse(rawTarget); err == nil {
			rawTarget = u.EscapedPath()
			if rawTarget == "" {
				rawTarget = "/"
			}
		}
	}
	return EscapePath(rawTarget), hasQuery
}

func escapeField(s string, isPlain func(rune) bool) string {
	allPlain := true
	for _, r := range s {
		if !isPlain(r) {
			allPlain = false
			break
		}
	}
	if allPlain {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		if isPlain(r) {
			b.WriteRune(r)
			continue
		}
		switch {
		case r <= 0xff:
			b.WriteString(`\x`)
			writeHex(&b, uint64(r), 2)
		case r <= 0xffff:
			b.WriteString(`\u`)
			writeHex(&b, uint64(r), 4)
		default:
			b.WriteString(`\U`)
			writeHex(&b, uint64(r), 8)
		}
	}
	return b.String()
}

func writeHex(b *strings.Builder, v uint64, width int) {
	const digits = "0123456789abcdef"
	var buf [8]byte
	for i := width - 1; i >= 0; i-- {
		buf[i] = digits[v&0xf]
		v >>= 4
	}
	b.Write(buf[:width])
}

func isPlainHostRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case r == '.' || r == '_' || r == '-' || r == ':':
		return true
	}
	return false
}

func isPlainMethodRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		return true
	}
	return false
}

func isPlainPathRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case strings.ContainsRune("-._~:/@!$&'()*+,;=%", r):
		return true
	}
	return false
}
