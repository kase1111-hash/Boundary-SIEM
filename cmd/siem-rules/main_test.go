package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// capture runs fn with os.Stdout and os.Stderr redirected and returns the exit
// code together with everything written to either stream.
func capture(t *testing.T, fn func() int) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	code := fn()
	os.Stdout, os.Stderr = oldOut, oldErr
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return code, out
}

// Regression (R22): validate reported every one of these files as OK (except
// broken YAML), silently dropped the second rule of multi.yaml and printed an
// unmarshal error for an unknown rule type.
func TestValidateRejectsBadRules(t *testing.T) {
	tests := []struct {
		file    string
		wantOut string // substring expected in the output
	}{
		{"bad_operator.yaml", "equalz"},
		{"bad_severity.yaml", "severity"},
		{"bad_type.yaml", "unknown rule type"},
		{"broken.yaml", "FAIL"},
		{"dangling_dep.yaml", "does-not-exist"},
		{"multi.yaml", "multi-2"},
		{"no_window.yaml", "no-window"},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			path := filepath.Join("testdata", "badrules", tt.file)
			code, out := capture(t, func() int { return runValidate([]string{path}, true) })
			if code == 0 {
				t.Errorf("validate %s exit code = 0, want non-zero; output:\n%s", tt.file, out)
			}
			if !strings.Contains(out, tt.wantOut) {
				t.Errorf("validate %s output does not mention %q:\n%s", tt.file, tt.wantOut, out)
			}
		})
	}
}

func TestValidateAcceptsGoodRules(t *testing.T) {
	code, out := capture(t, func() int {
		return runValidate([]string{filepath.Join("testdata", "good"), filepath.Join("..", "..", "rules")}, true)
	})
	if code != 0 {
		t.Fatalf("validate exit code = %d, want 0; output:\n%s", code, out)
	}
	for _, id := range []string{"stream-recon", "stream-follow-up", "list-one", "community-recon-then-exploit"} {
		if !strings.Contains(out, id) {
			t.Errorf("verbose output does not list rule %s:\n%s", id, out)
		}
	}
}

// Regression (R22): list silently skipped files that failed to load and
// exited 0 even for a missing directory.
func TestListReportsLoadErrors(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		wantCode bool // true = expect non-zero exit
		wantOut  []string
	}{
		{
			name:     "missing directory",
			paths:    []string{filepath.Join(t.TempDir(), "nonexistent")},
			wantCode: true,
			wantOut:  []string{"nonexistent"},
		},
		{
			name:     "directory with broken rules",
			paths:    []string{filepath.Join("testdata", "badrules")},
			wantCode: true,
			wantOut:  []string{"broken.yaml", "bad_type.yaml"},
		},
		{
			name:    "good rules list every rule of every document",
			paths:   []string{filepath.Join("testdata", "good")},
			wantOut: []string{"stream-recon", "stream-follow-up", "list-one"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out := capture(t, func() int { return runList(tt.paths) })
			if (code != 0) != tt.wantCode {
				t.Errorf("list exit code = %d, want non-zero=%v; output:\n%s", code, tt.wantCode, out)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(out, want) {
					t.Errorf("list output does not mention %q:\n%s", want, out)
				}
			}
		})
	}
}
