package api

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "invalid API key", "invalid API key"},
		{"newlines collapse", "line1\r\n\tline2\n", "line1 line2"},
		{"csi color", "\x1b[31mred\x1b[0m text", "red text"},
		{"osc title with bel", "a\x1b]0;pwned\x07b", "ab"},
		{"osc 52 with st", "a\x1b]52;c;cHduZWQ=\x1b\\b", "ab"},
		{"two char escape", "a\x1bcb", "ab"},
		{"dangling escape", "abc\x1b", "abc"},
		{"unterminated osc", "abc\x1b]0;title", "abc"},
		{"c1 csi", "a\u009b2Jb", "ab"},
		{"invalid utf8", "a\xffb", "a b"},
		{"leading control", "\x00\x01ok", "ok"},
		{"unicode kept", "zürich ✓", "zürich ✓"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeText(tt.in); got != tt.want {
				t.Errorf("sanitizeText(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSanitizeTextTruncates(t *testing.T) {
	got := sanitizeText(strings.Repeat("é", 3*maxDisplayText))
	if n := utf8.RuneCountInString(got); n != maxDisplayText+1 {
		t.Errorf("rune count = %d, want %d (text plus ellipsis)", n, maxDisplayText+1)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncated text should end with an ellipsis: %q", got)
	}
	if !utf8.ValidString(got) {
		t.Error("truncation produced invalid UTF-8")
	}
}
