package api

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxDisplayText bounds server-supplied text shown on one TUI line.
const maxDisplayText = 200

// sanitizeText makes server-supplied text safe to print on one terminal
// line: ANSI/OSC escape sequences are removed (a hostile or MITM'd server
// could otherwise retitle the terminal, write the clipboard via OSC 52 or
// clear the screen), remaining control characters and newlines become
// spaces, runs of whitespace are collapsed and the result is truncated to
// maxDisplayText runes.
func sanitizeText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b { // ESC
			i = skipEscape(s, i)
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r == 0x9b || r == 0x9d { // 8-bit CSI / OSC
			i = skipEscapeBody(s, i, r == 0x9d)
			continue
		}
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.IsSpace(r) {
			space = b.Len() > 0
			continue
		}
		if n >= maxDisplayText {
			b.WriteString("…")
			return b.String()
		}
		if space {
			b.WriteByte(' ')
			n++
			space = false
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// skipEscape returns the index just past the escape sequence starting at
// s[i] == ESC.
func skipEscape(s string, i int) int {
	i++ // ESC
	if i >= len(s) {
		return i
	}
	switch s[i] {
	case '[': // CSI
		return skipEscapeBody(s, i+1, false)
	case ']', 'P', 'X', '^', '_': // OSC, DCS, SOS, PM, APC: string until BEL or ST
		return skipEscapeBody(s, i+1, true)
	default: // two-character sequence
		_, size := utf8.DecodeRuneInString(s[i:])
		return i + size
	}
}

// skipEscapeBody skips the body of a CSI (final byte 0x40-0x7e) or, when
// isString is set, of a string sequence terminated by BEL or ESC \.
func skipEscapeBody(s string, i int, isString bool) int {
	for i < len(s) {
		c := s[i]
		if isString {
			if c == 0x07 {
				return i + 1
			}
			if c == 0x1b {
				if i+1 < len(s) && s[i+1] == '\\' {
					return i + 2
				}
				return i
			}
		} else if c >= 0x40 && c <= 0x7e {
			return i + 1
		}
		i++
	}
	return i
}
