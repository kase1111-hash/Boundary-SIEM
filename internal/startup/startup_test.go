package startup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"boundary-siem/internal/config"
)

// ---------- helpers ----------

// newTestLogger returns a slog.Logger that writes to a buffer so tests
// can inspect log output without polluting stdout.
func newTestLogger(buf *bytes.Buffer) *slog.Logger {
	handler := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(handler)
}

// newTestDiagnostics creates a Diagnostics with a default config and a
// buffer-backed logger. The caller can tweak cfg before running checks.
func newTestDiagnostics() (*Diagnostics, *config.Config, *bytes.Buffer) {
	cfg := config.DefaultConfig()
	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	d := NewDiagnostics(cfg, logger)
	return d, cfg, &buf
}

// chdirTemp changes the working directory to a new temp dir for the
// duration of the test, then restores the original directory on cleanup.
func chdirTemp(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("os.Chdir(%q): %v", tmpDir, err)
	}
	t.Cleanup(func() {
		os.Chdir(origDir)
	})
	return tmpDir
}

// findResult searches a slice of DiagnosticResults for one whose Name
// matches the given name. Returns nil if not found.
func findResult(results []DiagnosticResult, name string) *DiagnosticResult {
	for i := range results {
		if results[i].Name == name {
			return &results[i]
		}
	}
	return nil
}

// findResultsPrefix returns all results whose Name starts with prefix.
func findResultsPrefix(results []DiagnosticResult, prefix string) []DiagnosticResult {
	var out []DiagnosticResult
	for _, r := range results {
		if strings.HasPrefix(r.Name, prefix) {
			out = append(out, r)
		}
	}
	return out
}

// ---------- Status.String() ----------

func TestStatusString(t *testing.T) {
	tests := []struct {
		status   Status
		expected string
	}{
		{StatusOK, "OK"},
		{StatusWarning, "WARNING"},
		{StatusError, "ERROR"},
		{StatusSkipped, "SKIPPED"},
		{Status(99), "UNKNOWN"},
		{Status(-1), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.status.String()
			if got != tt.expected {
				t.Errorf("Status(%d).String() = %q, want %q", int(tt.status), got, tt.expected)
			}
		})
	}
}

// ---------- Status constant values ----------

func TestStatusConstants(t *testing.T) {
	// Verify iota ordering so callers can rely on numeric comparison.
	if StatusOK != 0 {
		t.Errorf("StatusOK = %d, want 0", StatusOK)
	}
	if StatusWarning != 1 {
		t.Errorf("StatusWarning = %d, want 1", StatusWarning)
	}
	if StatusError != 2 {
		t.Errorf("StatusError = %d, want 2", StatusError)
	}
	if StatusSkipped != 3 {
		t.Errorf("StatusSkipped = %d, want 3", StatusSkipped)
	}
}

// ---------- NewDiagnostics ----------

func TestNewDiagnostics(t *testing.T) {
	cfg := config.DefaultConfig()
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	d := NewDiagnostics(cfg, logger)

	if d == nil {
		t.Fatal("NewDiagnostics returned nil")
	}
	if d.cfg != cfg {
		t.Error("Diagnostics.cfg does not point to the supplied config")
	}
	if d.logger != logger {
		t.Error("Diagnostics.logger does not point to the supplied logger")
	}
	if len(d.results) != 0 {
		t.Errorf("expected empty results, got %d entries", len(d.results))
	}
}

func TestNewDiagnostics_NilLogger(t *testing.T) {
	// Even with a nil logger the constructor should not panic.
	cfg := config.DefaultConfig()
	d := NewDiagnostics(cfg, nil)
	if d == nil {
		t.Fatal("NewDiagnostics returned nil with nil logger")
	}
}

// ---------- DiagnosticResult ----------

func TestDiagnosticResultFields(t *testing.T) {
	dr := DiagnosticResult{
		Name:    "test_check",
		Status:  StatusWarning,
		Message: "something happened",
		Details: map[string]string{"key": "value"},
	}

	if dr.Name != "test_check" {
		t.Errorf("Name = %q, want %q", dr.Name, "test_check")
	}
	if dr.Status != StatusWarning {
		t.Errorf("Status = %v, want %v", dr.Status, StatusWarning)
	}
	if dr.Message != "something happened" {
		t.Errorf("Message = %q, want %q", dr.Message, "something happened")
	}
	if dr.Details["key"] != "value" {
		t.Errorf("Details[\"key\"] = %q, want %q", dr.Details["key"], "value")
	}
}

func TestDiagnosticResultNilDetails(t *testing.T) {
	dr := DiagnosticResult{
		Name:   "no_details",
		Status: StatusOK,
	}
	if dr.Details != nil {
		t.Error("expected nil Details map")
	}
}

// ---------- addResult ----------

func TestAddResult(t *testing.T) {
	tests := []struct {
		name           string
		status         Status
		expectLogLevel string // "INFO", "WARN", "ERROR", "DEBUG"
	}{
		{"ok result", StatusOK, "INFO"},
		{"warning result", StatusWarning, "WARN"},
		{"error result", StatusError, "ERROR"},
		{"skipped result", StatusSkipped, "DEBUG"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := newTestLogger(&buf)
			d := NewDiagnostics(config.DefaultConfig(), logger)

			result := DiagnosticResult{
				Name:    "test_" + tt.name,
				Status:  tt.status,
				Message: "msg",
				Details: map[string]string{"detail": "val"},
			}

			d.addResult(result)

			if len(d.results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(d.results))
			}
			if d.results[0].Name != result.Name {
				t.Errorf("stored result name = %q, want %q", d.results[0].Name, result.Name)
			}

			logOutput := buf.String()
			if !strings.Contains(logOutput, fmt.Sprintf("level=%s", tt.expectLogLevel)) {
				t.Errorf("expected log level %s in output:\n%s", tt.expectLogLevel, logOutput)
			}
		})
	}
}

func TestAddResultMultiple(t *testing.T) {
	d, _, _ := newTestDiagnostics()

	for i := 0; i < 5; i++ {
		d.addResult(DiagnosticResult{
			Name:   fmt.Sprintf("check_%d", i),
			Status: StatusOK,
		})
	}

	if len(d.results) != 5 {
		t.Errorf("expected 5 results, got %d", len(d.results))
	}
}

func TestAddResultWithEmptyMessage(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	d := NewDiagnostics(config.DefaultConfig(), logger)

	d.addResult(DiagnosticResult{
		Name:   "no_msg",
		Status: StatusOK,
	})

	// Should not contain "message" key (empty message is not appended).
	logOutput := buf.String()
	if strings.Contains(logOutput, "message=") {
		t.Errorf("expected no 'message=' in log when Message is empty, got:\n%s", logOutput)
	}
}

// ---------- HasErrors ----------

func TestHasErrors(t *testing.T) {
	tests := []struct {
		name     string
		statuses []Status
		want     bool
	}{
		{"no results", nil, false},
		{"all ok", []Status{StatusOK, StatusOK}, false},
		{"one warning", []Status{StatusOK, StatusWarning}, false},
		{"one error", []Status{StatusOK, StatusError}, true},
		{"all errors", []Status{StatusError, StatusError}, true},
		{"mixed with error", []Status{StatusOK, StatusWarning, StatusError, StatusSkipped}, true},
		{"only skipped", []Status{StatusSkipped, StatusSkipped}, false},
		{"warning and skipped", []Status{StatusWarning, StatusSkipped}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, _, _ := newTestDiagnostics()
			for i, s := range tt.statuses {
				d.results = append(d.results, DiagnosticResult{
					Name:   fmt.Sprintf("check_%d", i),
					Status: s,
				})
			}
			got := d.HasErrors()
			if got != tt.want {
				t.Errorf("HasErrors() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------- HasWarnings ----------

func TestHasWarnings(t *testing.T) {
	tests := []struct {
		name     string
		statuses []Status
		want     bool
	}{
		{"no results", nil, false},
		{"all ok", []Status{StatusOK, StatusOK}, false},
		{"one warning", []Status{StatusOK, StatusWarning}, true},
		{"one error only", []Status{StatusOK, StatusError}, false},
		{"warning and error", []Status{StatusWarning, StatusError}, true},
		{"all warnings", []Status{StatusWarning, StatusWarning}, true},
		{"only skipped", []Status{StatusSkipped, StatusSkipped}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, _, _ := newTestDiagnostics()
			for i, s := range tt.statuses {
				d.results = append(d.results, DiagnosticResult{
					Name:   fmt.Sprintf("check_%d", i),
					Status: s,
				})
			}
			got := d.HasWarnings()
			if got != tt.want {
				t.Errorf("HasWarnings() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------- fileExists ----------

func TestFileExists(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		if fileExists("") {
			t.Error("fileExists(\"\") = true, want false")
		}
	})

	t.Run("nonexistent path", func(t *testing.T) {
		if fileExists("/this/path/definitely/does/not/exist/file.txt") {
			t.Error("fileExists returned true for nonexistent path")
		}
	})

	t.Run("existing file", func(t *testing.T) {
		tmpDir := t.TempDir()
		f := filepath.Join(tmpDir, "exists.txt")
		if err := os.WriteFile(f, []byte("data"), 0644); err != nil {
			t.Fatalf("os.WriteFile: %v", err)
		}
		if !fileExists(f) {
			t.Errorf("fileExists(%q) = false, want true", f)
		}
	})

	t.Run("existing directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		// os.Stat succeeds on a directory too, so fileExists should return true.
		if !fileExists(tmpDir) {
			t.Errorf("fileExists(%q) = false for a directory, want true", tmpDir)
		}
	})
}

// ---------- EnsureDirectories ----------

func TestEnsureDirectories(t *testing.T) {
	tmpDir := chdirTemp(t)

	err := EnsureDirectories()
	if err != nil {
		t.Fatalf("EnsureDirectories() error: %v", err)
	}

	expectedDirs := []string{
		"data",
		"data/events",
		"logs",
		"certs",
		"configs",
	}
	for _, dir := range expectedDirs {
		fullPath := filepath.Join(tmpDir, dir)
		info, err := os.Stat(fullPath)
		if err != nil {
			t.Errorf("directory %q not created: %v", dir, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("path %q exists but is not a directory", dir)
		}
		perm := info.Mode().Perm()
		if perm != 0750 {
			t.Errorf("directory %q has permissions %o, want 0750", dir, perm)
		}
	}
}

func TestEnsureDirectories_Idempotent(t *testing.T) {
	chdirTemp(t)

	// Call twice; the second call should not fail even though dirs exist.
	if err := EnsureDirectories(); err != nil {
		t.Fatalf("first EnsureDirectories: %v", err)
	}
	if err := EnsureDirectories(); err != nil {
		t.Fatalf("second EnsureDirectories: %v", err)
	}
}

// ---------- PrintBanner ----------

func TestPrintBanner(t *testing.T) {
	// Capture stdout.
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	PrintBanner("1.2.3-test")

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Check that the version string appears.
	if !strings.Contains(output, "1.2.3-test") {
		t.Error("PrintBanner output does not contain the version string")
	}

	// Check for key banner elements.
	if !strings.Contains(output, "SIEM") {
		t.Error("PrintBanner output does not contain 'SIEM'")
	}
	if !strings.Contains(output, "Agent-Native Security Intelligence Platform") {
		t.Error("PrintBanner output does not contain the tagline")
	}
}

func TestPrintBanner_EmptyVersion(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	PrintBanner("")

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "Version:") {
		t.Error("PrintBanner output does not contain 'Version:' prefix")
	}
}

// ---------- checkSystem ----------

func TestCheckSystem(t *testing.T) {
	d, _, logBuf := newTestDiagnostics()

	d.checkSystem()

	// Should have exactly 2 results: "runtime" and "memory".
	if len(d.results) != 2 {
		t.Fatalf("checkSystem produced %d results, want 2", len(d.results))
	}

	// Runtime result.
	rt := findResult(d.results, "runtime")
	if rt == nil {
		t.Fatal("missing 'runtime' diagnostic result")
	}
	if rt.Status != StatusOK {
		t.Errorf("runtime status = %v, want StatusOK", rt.Status)
	}
	if rt.Details["go_version"] != runtime.Version() {
		t.Errorf("go_version = %q, want %q", rt.Details["go_version"], runtime.Version())
	}
	if rt.Details["os"] != runtime.GOOS {
		t.Errorf("os = %q, want %q", rt.Details["os"], runtime.GOOS)
	}
	if rt.Details["arch"] != runtime.GOARCH {
		t.Errorf("arch = %q, want %q", rt.Details["arch"], runtime.GOARCH)
	}
	if rt.Details["cpus"] != fmt.Sprintf("%d", runtime.NumCPU()) {
		t.Errorf("cpus = %q, want %q", rt.Details["cpus"], fmt.Sprintf("%d", runtime.NumCPU()))
	}

	// Memory result.
	mem := findResult(d.results, "memory")
	if mem == nil {
		t.Fatal("missing 'memory' diagnostic result")
	}
	if mem.Status != StatusOK {
		t.Errorf("memory status = %v, want StatusOK", mem.Status)
	}
	if mem.Details["alloc_mb"] == "" {
		t.Error("alloc_mb detail is empty")
	}
	if mem.Details["sys_mb"] == "" {
		t.Error("sys_mb detail is empty")
	}
	if mem.Details["num_goroutines"] == "" {
		t.Error("num_goroutines detail is empty")
	}

	// Logger should contain the system check message.
	if !strings.Contains(logBuf.String(), "checking system requirements") {
		t.Error("log output missing 'checking system requirements'")
	}
}

// ---------- checkDirectories ----------

func TestCheckDirectories_CreatesAutoCreateDirs(t *testing.T) {
	tmpDir := chdirTemp(t)

	// Pre-create the "configs" required directory so the check does not
	// report an error for it.
	os.MkdirAll(filepath.Join(tmpDir, "configs"), 0750)

	d, _, _ := newTestDiagnostics()
	d.checkDirectories()

	// Directories that have create=true: data, data/events, logs, certs
	autoCreateDirs := []string{"data", "data/events", "logs", "certs"}
	for _, dir := range autoCreateDirs {
		full := filepath.Join(tmpDir, dir)
		info, err := os.Stat(full)
		if err != nil {
			t.Errorf("expected directory %q to be created, but got error: %v", dir, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("path %q exists but is not a directory", dir)
		}
	}

	// All results should be OK.
	for _, r := range d.results {
		if r.Status != StatusOK {
			t.Errorf("result %q has status %v, want StatusOK", r.Name, r.Status)
		}
	}
}

func TestCheckDirectories_RequiredDirMissing(t *testing.T) {
	chdirTemp(t)
	// Do NOT create "configs" so the check reports an error.

	d, _, _ := newTestDiagnostics()
	d.checkDirectories()

	configResult := findResult(d.results, "directory_configs")
	if configResult == nil {
		t.Fatal("missing result for 'directory_configs'")
	}
	if configResult.Status != StatusError {
		t.Errorf("directory_configs status = %v, want StatusError", configResult.Status)
	}
	if !strings.Contains(configResult.Message, "Required directory missing") {
		t.Errorf("unexpected message: %q", configResult.Message)
	}
}

func TestCheckDirectories_ExistingDirIsFile(t *testing.T) {
	tmpDir := chdirTemp(t)

	// Create "data" as a regular file instead of a directory.
	os.WriteFile(filepath.Join(tmpDir, "data"), []byte("not a dir"), 0644)
	// Create configs so we don't get an unrelated error.
	os.MkdirAll(filepath.Join(tmpDir, "configs"), 0750)

	d, _, _ := newTestDiagnostics()
	d.checkDirectories()

	dataResult := findResult(d.results, "directory_data")
	if dataResult == nil {
		t.Fatal("missing result for 'directory_data'")
	}
	if dataResult.Status != StatusError {
		t.Errorf("directory_data status = %v, want StatusError", dataResult.Status)
	}
	if !strings.Contains(dataResult.Message, "not a directory") {
		t.Errorf("unexpected message: %q", dataResult.Message)
	}
}

func TestCheckDirectories_AllPreExisting(t *testing.T) {
	tmpDir := chdirTemp(t)

	// Pre-create every directory with correct permissions.
	for _, dir := range []string{"data", "data/events", "logs", "certs", "configs"} {
		os.MkdirAll(filepath.Join(tmpDir, dir), 0750)
	}

	d, _, _ := newTestDiagnostics()
	d.checkDirectories()

	for _, r := range d.results {
		if r.Status != StatusOK {
			t.Errorf("result %q status = %v, want StatusOK", r.Name, r.Status)
		}
		if r.Message != "Directory exists" {
			t.Errorf("result %q message = %q, want 'Directory exists'", r.Name, r.Message)
		}
	}
}

// ---------- checkConfiguration ----------

func TestCheckConfiguration_NoConfigFile(t *testing.T) {
	tmpDir := chdirTemp(t)
	_ = tmpDir

	// Unset any existing config path env to use the default "configs/config.yaml"
	// which won't exist in the temp dir.
	origEnv := os.Getenv("SIEM_CONFIG_PATH")
	os.Setenv("SIEM_CONFIG_PATH", "")
	defer os.Setenv("SIEM_CONFIG_PATH", origEnv)

	d, _, _ := newTestDiagnostics()
	d.checkConfiguration()

	cfgFileResult := findResult(d.results, "config_file")
	if cfgFileResult == nil {
		t.Fatal("missing result for 'config_file'")
	}
	if cfgFileResult.Status != StatusWarning {
		t.Errorf("config_file status = %v, want StatusWarning (file not found)", cfgFileResult.Status)
	}
}

func TestCheckConfiguration_ConfigFileExists(t *testing.T) {
	tmpDir := chdirTemp(t)

	// Create a config file.
	os.MkdirAll(filepath.Join(tmpDir, "configs"), 0750)
	os.WriteFile(filepath.Join(tmpDir, "configs", "config.yaml"), []byte("server:\n  http_port: 8080\n"), 0644)

	origEnv := os.Getenv("SIEM_CONFIG_PATH")
	os.Setenv("SIEM_CONFIG_PATH", "")
	defer os.Setenv("SIEM_CONFIG_PATH", origEnv)

	d, _, _ := newTestDiagnostics()
	d.checkConfiguration()

	cfgFileResult := findResult(d.results, "config_file")
	if cfgFileResult == nil {
		t.Fatal("missing result for 'config_file'")
	}
	if cfgFileResult.Status != StatusOK {
		t.Errorf("config_file status = %v, want StatusOK", cfgFileResult.Status)
	}
}

func TestCheckConfiguration_CustomEnvPath(t *testing.T) {
	tmpDir := chdirTemp(t)

	customPath := filepath.Join(tmpDir, "custom.yaml")
	os.WriteFile(customPath, []byte("server:\n  http_port: 9090\n"), 0644)

	origEnv := os.Getenv("SIEM_CONFIG_PATH")
	os.Setenv("SIEM_CONFIG_PATH", customPath)
	defer os.Setenv("SIEM_CONFIG_PATH", origEnv)

	d, _, _ := newTestDiagnostics()
	d.checkConfiguration()

	cfgFileResult := findResult(d.results, "config_file")
	if cfgFileResult == nil {
		t.Fatal("missing result for 'config_file'")
	}
	if cfgFileResult.Status != StatusOK {
		t.Errorf("config_file status = %v, want StatusOK", cfgFileResult.Status)
	}
	if cfgFileResult.Details["path"] != customPath {
		t.Errorf("config_file path = %q, want %q", cfgFileResult.Details["path"], customPath)
	}
}

func TestCheckConfiguration_ValidationPasses(t *testing.T) {
	chdirTemp(t)

	origEnv := os.Getenv("SIEM_CONFIG_PATH")
	os.Setenv("SIEM_CONFIG_PATH", "")
	defer os.Setenv("SIEM_CONFIG_PATH", origEnv)

	d, _, _ := newTestDiagnostics()
	d.checkConfiguration()

	valResult := findResult(d.results, "config_validation")
	if valResult == nil {
		t.Fatal("missing result for 'config_validation'")
	}
	if valResult.Status != StatusOK {
		t.Errorf("config_validation status = %v, want StatusOK", valResult.Status)
	}
}

func TestCheckConfiguration_ValidationFails(t *testing.T) {
	chdirTemp(t)

	origEnv := os.Getenv("SIEM_CONFIG_PATH")
	os.Setenv("SIEM_CONFIG_PATH", "")
	defer os.Setenv("SIEM_CONFIG_PATH", origEnv)

	d, cfg, _ := newTestDiagnostics()
	cfg.Server.HTTPPort = -1 // invalid port
	d.checkConfiguration()

	valResult := findResult(d.results, "config_validation")
	if valResult == nil {
		t.Fatal("missing result for 'config_validation'")
	}
	if valResult.Status != StatusError {
		t.Errorf("config_validation status = %v, want StatusError", valResult.Status)
	}
	if !strings.Contains(valResult.Message, "validation failed") {
		t.Errorf("unexpected message: %q", valResult.Message)
	}
}

// ---------- checkSecurityConfiguration ----------

func TestCheckSecurityConfiguration_AllDisabled(t *testing.T) {
	d, cfg, _ := newTestDiagnostics()
	cfg.Auth.Enabled = false
	cfg.Ingest.CEF.UDP.Enabled = false
	cfg.Ingest.CEF.TCP.Enabled = false
	cfg.RateLimit.Enabled = false
	cfg.SecurityHeaders.Enabled = false
	cfg.Encryption.Enabled = false

	d.checkSecurityConfiguration()

	// Auth disabled should produce a warning.
	auth := findResult(d.results, "auth")
	if auth == nil {
		t.Fatal("missing 'auth' result")
	}
	if auth.Status != StatusWarning {
		t.Errorf("auth status = %v, want StatusWarning", auth.Status)
	}

	// UDP disabled is OK (secure).
	udp := findResult(d.results, "cef_udp_security")
	if udp == nil {
		t.Fatal("missing 'cef_udp_security' result")
	}
	if udp.Status != StatusOK {
		t.Errorf("cef_udp_security status = %v, want StatusOK", udp.Status)
	}

	// TCP disabled: no TCP-related result should be emitted.
	tcp := findResult(d.results, "cef_tcp_security")
	if tcp != nil {
		t.Errorf("unexpected 'cef_tcp_security' result when TCP is disabled")
	}

	// Rate limiting disabled.
	rl := findResult(d.results, "rate_limiting")
	if rl == nil {
		t.Fatal("missing 'rate_limiting' result")
	}
	if rl.Status != StatusWarning {
		t.Errorf("rate_limiting status = %v, want StatusWarning", rl.Status)
	}

	// Security headers disabled.
	sh := findResult(d.results, "security_headers")
	if sh == nil {
		t.Fatal("missing 'security_headers' result")
	}
	if sh.Status != StatusWarning {
		t.Errorf("security_headers status = %v, want StatusWarning", sh.Status)
	}

	// Encryption disabled.
	enc := findResult(d.results, "encryption_at_rest")
	if enc == nil {
		t.Fatal("missing 'encryption_at_rest' result")
	}
	if enc.Status != StatusWarning {
		t.Errorf("encryption_at_rest status = %v, want StatusWarning", enc.Status)
	}
}

func TestCheckSecurityConfiguration_AllEnabled(t *testing.T) {
	d, cfg, _ := newTestDiagnostics()
	cfg.Auth.Enabled = true
	cfg.Ingest.CEF.UDP.Enabled = false
	cfg.Ingest.CEF.TCP.Enabled = false
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.RequestsPerIP = 500
	cfg.RateLimit.WindowSize = 2 * time.Minute
	cfg.SecurityHeaders.Enabled = true
	cfg.Encryption.Enabled = true

	d.checkSecurityConfiguration()

	auth := findResult(d.results, "auth")
	if auth == nil || auth.Status != StatusOK {
		t.Error("expected auth StatusOK")
	}

	rl := findResult(d.results, "rate_limiting")
	if rl == nil || rl.Status != StatusOK {
		t.Error("expected rate_limiting StatusOK")
	}
	if rl != nil && rl.Details["requests_per_ip"] != "500" {
		t.Errorf("requests_per_ip = %q, want %q", rl.Details["requests_per_ip"], "500")
	}

	sh := findResult(d.results, "security_headers")
	if sh == nil || sh.Status != StatusOK {
		t.Error("expected security_headers StatusOK")
	}

	enc := findResult(d.results, "encryption_at_rest")
	if enc == nil || enc.Status != StatusOK {
		t.Error("expected encryption_at_rest StatusOK")
	}
}

func TestCheckSecurityConfiguration_UDPEnabled(t *testing.T) {
	d, cfg, _ := newTestDiagnostics()
	cfg.Ingest.CEF.UDP.Enabled = true

	d.checkSecurityConfiguration()

	udp := findResult(d.results, "cef_udp_security")
	if udp == nil {
		t.Fatal("missing 'cef_udp_security' result")
	}
	if udp.Status != StatusWarning {
		t.Errorf("cef_udp_security status = %v, want StatusWarning (insecure UDP)", udp.Status)
	}
}

func TestCheckSecurityConfiguration_TCPEnabledNoTLS(t *testing.T) {
	d, cfg, _ := newTestDiagnostics()
	cfg.Ingest.CEF.TCP.Enabled = true
	cfg.Ingest.CEF.TCP.TLSEnabled = false

	d.checkSecurityConfiguration()

	tcp := findResult(d.results, "cef_tcp_security")
	if tcp == nil {
		t.Fatal("missing 'cef_tcp_security' result")
	}
	if tcp.Status != StatusWarning {
		t.Errorf("cef_tcp_security status = %v, want StatusWarning (no TLS)", tcp.Status)
	}
}

func TestCheckSecurityConfiguration_TCPEnabledTLSMissingCerts(t *testing.T) {
	d, cfg, _ := newTestDiagnostics()
	cfg.Ingest.CEF.TCP.Enabled = true
	cfg.Ingest.CEF.TCP.TLSEnabled = true
	cfg.Ingest.CEF.TCP.TLSCertFile = "/nonexistent/cert.pem"
	cfg.Ingest.CEF.TCP.TLSKeyFile = "/nonexistent/key.pem"

	d.checkSecurityConfiguration()

	tcp := findResult(d.results, "cef_tcp_security")
	if tcp == nil {
		t.Fatal("missing 'cef_tcp_security' result")
	}
	if tcp.Status != StatusError {
		t.Errorf("cef_tcp_security status = %v, want StatusError (missing certs)", tcp.Status)
	}
	if !strings.Contains(tcp.Message, "certificate files missing") {
		t.Errorf("unexpected message: %q", tcp.Message)
	}
}

func TestCheckSecurityConfiguration_TCPEnabledTLSValidCerts(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	os.WriteFile(certFile, []byte("dummy cert"), 0644)
	os.WriteFile(keyFile, []byte("dummy key"), 0644)

	d, cfg, _ := newTestDiagnostics()
	cfg.Ingest.CEF.TCP.Enabled = true
	cfg.Ingest.CEF.TCP.TLSEnabled = true
	cfg.Ingest.CEF.TCP.TLSCertFile = certFile
	cfg.Ingest.CEF.TCP.TLSKeyFile = keyFile

	d.checkSecurityConfiguration()

	tcp := findResult(d.results, "cef_tcp_security")
	if tcp == nil {
		t.Fatal("missing 'cef_tcp_security' result")
	}
	if tcp.Status != StatusOK {
		t.Errorf("cef_tcp_security status = %v, want StatusOK", tcp.Status)
	}
}

// ---------- checkModules ----------

func TestCheckModules_DefaultConfig(t *testing.T) {
	d, _, _ := newTestDiagnostics()
	d.checkModules()

	moduleResults := findResultsPrefix(d.results, "module_")
	if len(moduleResults) == 0 {
		t.Fatal("no module results produced")
	}

	// HTTP API is always enabled.
	httpAPI := findResult(d.results, "module_HTTP API")
	if httpAPI == nil {
		t.Fatal("missing module_HTTP API result")
	}
	if httpAPI.Status != StatusOK {
		t.Errorf("module_HTTP API status = %v, want StatusOK", httpAPI.Status)
	}
	if httpAPI.Message != "Enabled" {
		t.Errorf("module_HTTP API message = %q, want 'Enabled'", httpAPI.Message)
	}
}

func TestCheckModules_AllEnabled(t *testing.T) {
	d, cfg, _ := newTestDiagnostics()
	cfg.Ingest.CEF.UDP.Enabled = true
	cfg.Ingest.CEF.TCP.Enabled = true
	cfg.Ingest.CEF.DTLS.Enabled = true
	cfg.Storage.Enabled = true
	cfg.Auth.Enabled = true
	cfg.RateLimit.Enabled = true
	cfg.CORS.Enabled = true
	cfg.SecurityHeaders.Enabled = true

	d.checkModules()

	for _, r := range d.results {
		if r.Status != StatusOK {
			t.Errorf("result %q status = %v, want StatusOK", r.Name, r.Status)
		}
		if r.Message != "Enabled" {
			t.Errorf("result %q message = %q, want 'Enabled'", r.Name, r.Message)
		}
	}
}

func TestCheckModules_AllDisabled(t *testing.T) {
	d, cfg, _ := newTestDiagnostics()
	cfg.Ingest.CEF.UDP.Enabled = false
	cfg.Ingest.CEF.TCP.Enabled = false
	cfg.Ingest.CEF.DTLS.Enabled = false
	cfg.Storage.Enabled = false
	cfg.Auth.Enabled = false
	cfg.RateLimit.Enabled = false
	cfg.CORS.Enabled = false
	cfg.SecurityHeaders.Enabled = false

	d.checkModules()

	// HTTP API is always enabled, so at least 1 should be OK.
	enabledCount := 0
	disabledCount := 0
	for _, r := range d.results {
		switch r.Status {
		case StatusOK:
			enabledCount++
		case StatusSkipped:
			disabledCount++
		}
	}

	if enabledCount != 1 {
		t.Errorf("expected exactly 1 enabled module (HTTP API), got %d", enabledCount)
	}
	if disabledCount != 8 {
		t.Errorf("expected 8 disabled modules, got %d", disabledCount)
	}
}

func TestCheckModules_ModuleCount(t *testing.T) {
	d, _, logBuf := newTestDiagnostics()
	d.checkModules()

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "modules summary") {
		t.Error("log output missing 'modules summary'")
	}
}

// ---------- checkStorage ----------

func TestCheckStorage_Disabled(t *testing.T) {
	d, cfg, _ := newTestDiagnostics()
	cfg.Storage.Enabled = false

	ctx := context.Background()
	d.checkStorage(ctx)

	storageResult := findResult(d.results, "storage")
	if storageResult == nil {
		t.Fatal("missing 'storage' result")
	}
	if storageResult.Status != StatusWarning {
		t.Errorf("storage status = %v, want StatusWarning", storageResult.Status)
	}
	if !strings.Contains(storageResult.Message, "DISABLED") {
		t.Errorf("expected message to contain 'DISABLED', got: %q", storageResult.Message)
	}
	if storageResult.Details["mode"] != "placeholder" {
		t.Errorf("details mode = %q, want 'placeholder'", storageResult.Details["mode"])
	}

	// When disabled, no clickhouse_connectivity result should appear.
	chResult := findResult(d.results, "clickhouse_connectivity")
	if chResult != nil {
		t.Error("unexpected clickhouse_connectivity result when storage is disabled")
	}
}

func TestCheckStorage_EnabledNoClickHouse(t *testing.T) {
	d, cfg, _ := newTestDiagnostics()
	cfg.Storage.Enabled = true
	// Point to a host that definitely won't be listening.
	cfg.Storage.ClickHouse.Hosts = []string{"127.0.0.1:19999"}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	d.checkStorage(ctx)

	chResult := findResult(d.results, "clickhouse_connectivity")
	if chResult == nil {
		t.Fatal("missing 'clickhouse_connectivity' result")
	}
	if chResult.Status != StatusError {
		t.Errorf("clickhouse_connectivity status = %v, want StatusError", chResult.Status)
	}
	if !strings.Contains(chResult.Message, "Cannot connect") {
		t.Errorf("unexpected message: %q", chResult.Message)
	}
}

// ---------- printSummary ----------

func TestPrintSummary_AllOK(t *testing.T) {
	d, _, logBuf := newTestDiagnostics()
	d.results = []DiagnosticResult{
		{Name: "a", Status: StatusOK},
		{Name: "b", Status: StatusOK},
	}

	d.printSummary()

	output := logBuf.String()
	if !strings.Contains(output, "Diagnostics Summary") {
		t.Error("output missing 'Diagnostics Summary'")
	}
	if !strings.Contains(output, "all startup diagnostics passed") {
		t.Error("expected 'all startup diagnostics passed' message")
	}
}

func TestPrintSummary_WithWarnings(t *testing.T) {
	d, _, logBuf := newTestDiagnostics()
	d.results = []DiagnosticResult{
		{Name: "a", Status: StatusOK},
		{Name: "b", Status: StatusWarning},
	}

	d.printSummary()

	output := logBuf.String()
	if !strings.Contains(output, "review for production readiness") {
		t.Error("expected production readiness warning in log")
	}
}

func TestPrintSummary_WithErrors(t *testing.T) {
	d, _, logBuf := newTestDiagnostics()
	d.results = []DiagnosticResult{
		{Name: "a", Status: StatusOK},
		{Name: "b", Status: StatusWarning},
		{Name: "c", Status: StatusError},
	}

	d.printSummary()

	output := logBuf.String()
	if !strings.Contains(output, "critical errors") {
		t.Error("expected critical errors message in log")
	}
}

func TestPrintSummary_Counts(t *testing.T) {
	d, _, logBuf := newTestDiagnostics()
	d.results = []DiagnosticResult{
		{Name: "ok1", Status: StatusOK},
		{Name: "ok2", Status: StatusOK},
		{Name: "warn1", Status: StatusWarning},
		{Name: "err1", Status: StatusError},
		{Name: "skip1", Status: StatusSkipped},
		{Name: "skip2", Status: StatusSkipped},
	}

	d.printSummary()

	output := logBuf.String()
	if !strings.Contains(output, "passed=2") {
		t.Errorf("expected 'passed=2' in output:\n%s", output)
	}
	if !strings.Contains(output, "warnings=1") {
		t.Errorf("expected 'warnings=1' in output:\n%s", output)
	}
	if !strings.Contains(output, "errors=1") {
		t.Errorf("expected 'errors=1' in output:\n%s", output)
	}
	if !strings.Contains(output, "skipped=2") {
		t.Errorf("expected 'skipped=2' in output:\n%s", output)
	}
}

func TestPrintSummary_Empty(t *testing.T) {
	d, _, logBuf := newTestDiagnostics()
	// No results at all.
	d.printSummary()

	output := logBuf.String()
	if !strings.Contains(output, "all startup diagnostics passed") {
		t.Error("expected 'all startup diagnostics passed' for zero results (0 errors, 0 warnings)")
	}
}

// ---------- checkPorts ----------

func TestCheckPorts_DisabledServices(t *testing.T) {
	d, cfg, _ := newTestDiagnostics()
	cfg.Server.HTTPPort = 0 // will not actually matter, only non-enabled extras are skipped
	cfg.Ingest.CEF.UDP.Enabled = false
	cfg.Ingest.CEF.TCP.Enabled = false

	// The HTTP API port is always checked. We use a high ephemeral port to
	// avoid conflicts in CI.
	cfg.Server.HTTPPort = 49152

	d.checkPorts()

	// There should be a result for the HTTP API port.
	httpResult := findResult(d.results, "port_HTTP API")
	if httpResult == nil {
		t.Fatal("missing 'port_HTTP API' result")
	}
	// It should succeed on an available port.
	if httpResult.Status != StatusOK {
		t.Errorf("port_HTTP API status = %v, want StatusOK (port %d)", httpResult.Status, cfg.Server.HTTPPort)
	}

	// No CEF port results since they are disabled.
	cefUDP := findResult(d.results, "port_CEF UDP")
	if cefUDP != nil {
		t.Error("unexpected 'port_CEF UDP' result when UDP is disabled")
	}
	cefTCP := findResult(d.results, "port_CEF TCP")
	if cefTCP != nil {
		t.Error("unexpected 'port_CEF TCP' result when TCP is disabled")
	}
}

func TestCheckPorts_CEFPortsEnabled(t *testing.T) {
	d, cfg, _ := newTestDiagnostics()
	// Use high ephemeral ports to avoid conflicts.
	cfg.Server.HTTPPort = 49153
	cfg.Ingest.CEF.UDP.Enabled = true
	cfg.Ingest.CEF.UDP.Address = ":49154"
	cfg.Ingest.CEF.TCP.Enabled = true
	cfg.Ingest.CEF.TCP.Address = ":49155"

	d.checkPorts()

	httpResult := findResult(d.results, "port_HTTP API")
	if httpResult == nil || httpResult.Status != StatusOK {
		t.Errorf("expected port_HTTP API StatusOK, got %v", httpResult)
	}

	cefUDP := findResult(d.results, "port_CEF UDP")
	if cefUDP == nil {
		t.Fatal("missing 'port_CEF UDP' result")
	}
	if cefUDP.Status != StatusOK {
		t.Errorf("port_CEF UDP status = %v, want StatusOK", cefUDP.Status)
	}

	cefTCP := findResult(d.results, "port_CEF TCP")
	if cefTCP == nil {
		t.Fatal("missing 'port_CEF TCP' result")
	}
	if cefTCP.Status != StatusOK {
		t.Errorf("port_CEF TCP status = %v, want StatusOK", cefTCP.Status)
	}
}

// ---------- RunAll (integration) ----------

func TestRunAll_StorageDisabled(t *testing.T) {
	tmpDir := chdirTemp(t)

	// Pre-create the required "configs" directory.
	os.MkdirAll(filepath.Join(tmpDir, "configs"), 0750)

	origEnv := os.Getenv("SIEM_CONFIG_PATH")
	os.Setenv("SIEM_CONFIG_PATH", "")
	defer os.Setenv("SIEM_CONFIG_PATH", origEnv)

	cfg := config.DefaultConfig()
	cfg.Storage.Enabled = false
	// Use high ports to avoid conflicts in test environments.
	cfg.Server.HTTPPort = 49160
	cfg.Ingest.CEF.TCP.Enabled = false
	cfg.Ingest.CEF.UDP.Enabled = false

	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	d := NewDiagnostics(cfg, logger)

	ctx := context.Background()
	results := d.RunAll(ctx)

	if len(results) == 0 {
		t.Fatal("RunAll returned no results")
	}

	// Verify results are stored.
	if len(d.results) != len(results) {
		t.Errorf("d.results length (%d) != returned results length (%d)", len(d.results), len(results))
	}

	// The log should contain the diagnostics banner.
	logOutput := buf.String()
	if !strings.Contains(logOutput, "Boundary-SIEM Startup Diagnostics") {
		t.Error("log output missing diagnostics banner")
	}
}

func TestRunAll_ContextCancelled(t *testing.T) {
	tmpDir := chdirTemp(t)
	os.MkdirAll(filepath.Join(tmpDir, "configs"), 0750)

	origEnv := os.Getenv("SIEM_CONFIG_PATH")
	os.Setenv("SIEM_CONFIG_PATH", "")
	defer os.Setenv("SIEM_CONFIG_PATH", origEnv)

	cfg := config.DefaultConfig()
	cfg.Storage.Enabled = false
	cfg.Server.HTTPPort = 49161
	cfg.Ingest.CEF.TCP.Enabled = false
	cfg.Ingest.CEF.UDP.Enabled = false

	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	d := NewDiagnostics(cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Should not panic or hang.
	results := d.RunAll(ctx)
	if len(results) == 0 {
		t.Fatal("RunAll returned no results even with cancelled context")
	}
}

// ---------- Edge cases ----------

func TestDiagnosticsResultsAreIndependent(t *testing.T) {
	// Running diagnostics twice should not accumulate results.
	d, cfg, _ := newTestDiagnostics()
	cfg.Ingest.CEF.UDP.Enabled = false
	cfg.Ingest.CEF.TCP.Enabled = false

	d.checkModules()
	firstCount := len(d.results)

	d.checkModules()
	secondCount := len(d.results)

	if secondCount != firstCount*2 {
		t.Errorf("expected %d results after two calls, got %d", firstCount*2, secondCount)
	}
}

func TestStatusStringExhaustive(t *testing.T) {
	// Verify all defined statuses produce non-"UNKNOWN" strings.
	definedStatuses := []Status{StatusOK, StatusWarning, StatusError, StatusSkipped}
	for _, s := range definedStatuses {
		str := s.String()
		if str == "UNKNOWN" {
			t.Errorf("Status(%d).String() returned UNKNOWN, should be a known value", s)
		}
		if str == "" {
			t.Errorf("Status(%d).String() returned empty string", s)
		}
	}

	// Out-of-range values should return UNKNOWN.
	outOfRange := []Status{Status(100), Status(-5), Status(255)}
	for _, s := range outOfRange {
		if s.String() != "UNKNOWN" {
			t.Errorf("Status(%d).String() = %q, want 'UNKNOWN'", s, s.String())
		}
	}
}

func TestEnsureDirectories_ReadOnlyParent(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test skipped when running as root")
	}

	tmpDir := t.TempDir()
	readonlyDir := filepath.Join(tmpDir, "readonly")
	os.MkdirAll(readonlyDir, 0500)
	t.Cleanup(func() {
		os.Chmod(readonlyDir, 0750) // restore so cleanup works
	})

	origDir, _ := os.Getwd()
	os.Chdir(readonlyDir)
	t.Cleanup(func() { os.Chdir(origDir) })

	err := EnsureDirectories()
	if err == nil {
		t.Error("expected error when creating directories in read-only parent, got nil")
	}
}

func TestHasErrors_EmptyResults(t *testing.T) {
	d, _, _ := newTestDiagnostics()
	if d.HasErrors() {
		t.Error("HasErrors() should return false for empty results")
	}
}

func TestHasWarnings_EmptyResults(t *testing.T) {
	d, _, _ := newTestDiagnostics()
	if d.HasWarnings() {
		t.Error("HasWarnings() should return false for empty results")
	}
}
