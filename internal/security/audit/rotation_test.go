package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testHMACKey is a fixed signing key so tests can write signed entries
// directly to disk.
var testHMACKey = bytes.Repeat([]byte{0x42}, 32)

// chainFile describes one log file of a crafted chain: its base name and the
// number of consecutive entries it holds.
type chainFile struct {
	name    string
	entries int
	sealed  bool // write a checksum file, as rotate and Close do
}

// writeChain writes a valid, signed hash chain starting at sequence 1 across
// files (in chain order) into dir and returns the entries in order.
func writeChain(t *testing.T, dir string, files []chainFile) []*AuditEntry {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	base := time.Date(2020, 1, 15, 10, 0, 0, 0, time.UTC)
	prev := computeGenesisHash()
	var all []*AuditEntry
	var seq uint64
	for _, f := range files {
		var buf bytes.Buffer
		for i := 0; i < f.entries; i++ {
			seq++
			entry := &AuditEntry{
				ID:           fmt.Sprintf("entry-%d", seq),
				Sequence:     seq,
				Timestamp:    base.Add(time.Duration(seq) * time.Second),
				Type:         EventSystemStart,
				Severity:     SeverityInfo,
				Message:      "crafted",
				PreviousHash: prev,
				Hostname:     "test-host",
				Success:      true,
			}
			entry.Sign(testHMACKey)
			prev = entry.EntryHash
			data, err := json.Marshal(entry)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			buf.Write(append(data, '\n'))
			all = append(all, entry)
		}
		path := filepath.Join(dir, f.name)
		if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		if f.sealed {
			al := &AuditLogger{}
			if err := al.writeFileChecksum(path); err != nil {
				t.Fatalf("writeFileChecksum() error = %v", err)
			}
		}
	}
	return all
}

// querySequences returns the sequence numbers of all entries in query order.
func querySequences(t *testing.T, al *AuditLogger) []uint64 {
	t.Helper()
	results, err := al.Query(context.Background(), QueryOptions{})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	seqs := make([]uint64, len(results))
	for i, e := range results {
		seqs[i] = e.Sequence
	}
	return seqs
}

// wantSequences returns 1..n.
func wantSequences(n int) []uint64 {
	seqs := make([]uint64, n)
	for i := range seqs {
		seqs[i] = uint64(i + 1)
	}
	return seqs
}

// TestAuditLogger_RotationOrder checks that integrity verification, state
// recovery and queries follow the order in which log files were written, not
// the plain string order of their names: "audit-D-<unix>.log" sorts before
// "audit-D.log" as a string although it is rotated from it.
func TestAuditLogger_RotationOrder(t *testing.T) {
	today := time.Now().Format("2006-01-02")
	todayRotated := fmt.Sprintf("audit-%s-%d.log", today, time.Now().Add(-time.Hour).Unix())

	tests := []struct {
		name  string
		files []chainFile
	}{
		{
			name: "same-day rotation",
			files: []chainFile{
				{name: "audit-2020-01-15.log", entries: 3, sealed: true},
				{name: "audit-2020-01-15-1579082400.log", entries: 3},
			},
		},
		{
			name: "several same-day rotations and a day change",
			files: []chainFile{
				{name: "audit-2020-01-15.log", entries: 2, sealed: true},
				{name: "audit-2020-01-15-1579082400.log", entries: 2, sealed: true},
				{name: "audit-2020-01-15-1579082401.log", entries: 1, sealed: true},
				{name: "audit-2020-01-16.log", entries: 2, sealed: true},
				{name: "audit-2020-01-16-1579168800.log", entries: 1},
			},
		},
		{
			name: "rotation suffixes compare numerically",
			files: []chainFile{
				{name: "audit-2020-01-15.log", entries: 1, sealed: true},
				{name: "audit-2020-01-15-99.log", entries: 2, sealed: true},
				{name: "audit-2020-01-15-100.log", entries: 2},
			},
		},
		{
			// A restart after a same-day rotation must continue in the
			// newest file, not append to the first file of the day.
			name: "restart after same-day rotation today",
			files: []chainFile{
				{name: "audit-" + today + ".log", entries: 3, sealed: true},
				{name: todayRotated, entries: 2},
			},
		},
		{
			// A clean shutdown sealed the newest file; appending to it would
			// invalidate its checksum.
			name: "restart after clean shutdown today",
			files: []chainFile{
				{name: "audit-" + today + ".log", entries: 3, sealed: true},
				{name: todayRotated, entries: 2, sealed: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := testConfig(t)
			config.KeyProvider = func() ([]byte, error) { return testHMACKey, nil }
			entries := writeChain(t, config.LogPath, tt.files)
			last := entries[len(entries)-1]

			al := reopenLogger(t, config)
			ctx := context.Background()

			if got := al.Metrics().CurrentSequence; got != last.Sequence {
				t.Errorf("recovered sequence = %d, want %d", got, last.Sequence)
			}
			al.mu.RLock()
			prevHash := al.previousHash
			al.mu.RUnlock()
			if prevHash != last.EntryHash {
				t.Errorf("recovered previous hash = %q, want hash of entry %d", prevHash, last.Sequence)
			}

			if err := al.VerifyIntegrity(ctx); err != nil {
				t.Fatalf("VerifyIntegrity() on untouched chain error = %v", err)
			}

			mustLog(t, al, EventSystemStart, SeverityInfo, "after restart")
			if err := al.ForceFlush(ctx); err != nil {
				t.Fatalf("ForceFlush() error = %v", err)
			}
			if err := al.VerifyIntegrity(ctx); err != nil {
				t.Fatalf("VerifyIntegrity() after logging error = %v", err)
			}

			want := wantSequences(len(entries) + 1)
			if got := querySequences(t, al); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("Query() sequences = %v, want %v", got, want)
			}
		})
	}
}

// TestAuditLogger_SameDayRotationAndRestart rotates the log several times in
// one day and restarts the logger, checking that the chain stays verifiable
// and recovery continues from the last written entry.
func TestAuditLogger_SameDayRotationAndRestart(t *testing.T) {
	config := testConfig(t)
	config.MaxFileSize = 1500 // a few entries per file
	config.MaxFiles = 100     // no retention in this test
	ctx := context.Background()

	al, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}
	const first = 20
	for i := 0; i < first; i++ {
		mustLog(t, al, EventSystemStart, SeverityInfo, "Event")
	}

	// Rotation must move writing to the new file.
	files, err := al.listLogFiles()
	if err != nil {
		t.Fatalf("listLogFiles() error = %v", err)
	}
	nonEmpty := 0
	for _, f := range files {
		entries, err := al.readLogFile(f)
		if err != nil {
			t.Fatalf("readLogFile(%s) error = %v", f, err)
		}
		if len(entries) > 0 {
			nonEmpty++
		}
	}
	if nonEmpty < 2 {
		t.Errorf("entries were written to %d log files, want at least 2 after rotation", nonEmpty)
	}

	if err := al.VerifyIntegrity(ctx); err != nil {
		t.Fatalf("VerifyIntegrity() after rotation error = %v", err)
	}
	mustFlushAndClose(t, al)

	// Restart: the sequence continues and the chain stays intact.
	al2, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() reopen error = %v", err)
	}
	if got := al2.Metrics().CurrentSequence; got != first {
		t.Errorf("recovered sequence = %d, want %d", got, first)
	}
	mustLog(t, al2, EventSystemStart, SeverityInfo, "after restart")
	if err := al2.VerifyIntegrity(ctx); err != nil {
		t.Fatalf("VerifyIntegrity() after restart error = %v", err)
	}
	if got, want := querySequences(t, al2), wantSequences(first+1); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Query() sequences = %v, want %v", got, want)
	}
	mustFlushAndClose(t, al2)

	// A restart that writes nothing leaves an empty newest file; the next
	// restart must still recover the last written entry.
	al3, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() third open error = %v", err)
	}
	mustFlushAndClose(t, al3)

	al4 := reopenLogger(t, config)
	if got := al4.Metrics().CurrentSequence; got != first+1 {
		t.Errorf("recovered sequence after empty restart = %d, want %d", got, first+1)
	}
	mustLog(t, al4, EventSystemStart, SeverityInfo, "after empty restart")
	if err := al4.VerifyIntegrity(ctx); err != nil {
		t.Fatalf("VerifyIntegrity() after empty restart error = %v", err)
	}
}

// TestAuditLogger_CleanupOldFilesRetention checks that MaxFiles retention
// removes the oldest files in rotation order together with their checksums.
func TestAuditLogger_CleanupOldFilesRetention(t *testing.T) {
	tests := []struct {
		name     string
		maxFiles int
		files    []string
		active   string   // file being written, never removed
		want     []string // remaining log files
	}{
		{
			name:     "under limit",
			maxFiles: 3,
			files:    []string{"audit-2020-01-15.log", "audit-2020-01-16.log"},
			want:     []string{"audit-2020-01-15.log", "audit-2020-01-16.log"},
		},
		{
			name:     "removes oldest days",
			maxFiles: 2,
			files:    []string{"audit-2020-01-14.log", "audit-2020-01-15.log", "audit-2020-01-16.log"},
			want:     []string{"audit-2020-01-15.log", "audit-2020-01-16.log"},
		},
		{
			name:     "same-day rotated file is newer than the day's first file",
			maxFiles: 2,
			files:    []string{"audit-2020-01-15.log", "audit-2020-01-15-1579082400.log", "audit-2020-01-16.log"},
			want:     []string{"audit-2020-01-15-1579082400.log", "audit-2020-01-16.log"},
		},
		{
			name:     "never removes the active file",
			maxFiles: 1,
			files:    []string{"audit-2020-01-14.log", "audit-2020-01-15.log", "audit-2020-01-16.log"},
			active:   "audit-2020-01-14.log",
			want:     []string{"audit-2020-01-14.log", "audit-2020-01-16.log"},
		},
		{
			name:     "retention disabled",
			maxFiles: 0,
			files:    []string{"audit-2020-01-14.log", "audit-2020-01-15.log"},
			want:     []string{"audit-2020-01-14.log", "audit-2020-01-15.log"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range tt.files {
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}
				if err := os.WriteFile(path+".sha256", []byte("x"), 0600); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}
			}

			al := &AuditLogger{
				config: &AuditLoggerConfig{LogPath: dir, MaxFiles: tt.maxFiles},
				logger: slog.Default(),
			}
			active := ""
			if tt.active != "" {
				active = filepath.Join(dir, tt.active)
			}
			al.cleanupOldFiles(nil, active)

			got := remainingNames(t, dir, "audit-*.log")
			if fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Errorf("remaining log files = %v, want %v", got, tt.want)
			}
			for _, name := range tt.want {
				if _, err := os.Stat(filepath.Join(dir, name+".sha256")); err != nil {
					t.Errorf("checksum of retained file %s: %v", name, err)
				}
			}
			if got := remainingNames(t, dir, "audit-*.log.sha256"); len(got) != len(tt.want) {
				t.Errorf("remaining checksum files = %v, want one per retained log file", got)
			}
		})
	}
}

// remainingNames returns the sorted base names in dir matching pattern.
func remainingNames(t *testing.T, dir, pattern string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	names := make([]string, len(matches))
	for i, m := range matches {
		names[i] = filepath.Base(m)
	}
	sortLogFiles(names)
	return names
}

// writeFakeChattr writes a chattr stand-in that records each call as
// "<op> <path> present|missing" in the returned log file and fails for
// "-i" on failPath.
func writeFakeChattr(t *testing.T, failPath string) (script, callLog string) {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	dir := t.TempDir()
	script = filepath.Join(dir, "chattr")
	callLog = filepath.Join(dir, "calls.log")
	body := fmt.Sprintf(`#!/bin/sh
if [ -e "$3" ]; then state=present; else state=missing; fi
echo "$1 $3 $state" >> %q
if [ "$1" = "-i" ] && [ "$3" = %q ]; then
	echo "chattr: simulated failure" >&2
	exit 1
fi
exit 0
`, callLog, failPath)
	if err := os.WriteFile(script, []byte(body), 0700); err != nil { // the script must be executable
		t.Fatalf("WriteFile() error = %v", err)
	}
	return script, callLog
}

// TestAuditLogger_CleanupOldFilesClearsImmutable uses a chattr stand-in to
// check that retention asks the immutable manager to clear the immutable
// attribute of each expired file before removing it, and logs failures.
func TestAuditLogger_CleanupOldFilesClearsImmutable(t *testing.T) {
	dir := t.TempDir()
	expired := []string{
		filepath.Join(dir, "audit-2020-01-14.log"),
		filepath.Join(dir, "audit-2020-01-15.log"),
	}
	kept := filepath.Join(dir, "audit-2020-01-16.log")
	for _, path := range append(append([]string{}, expired...), kept) {
		if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		if err := os.WriteFile(path+".sha256", []byte("x"), 0600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
	}
	// Make removal of one expired checksum fail: a non-empty directory
	// cannot be removed with os.Remove, even by root.
	blocked := expired[1] + ".sha256"
	if err := os.Remove(blocked); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(blocked, "child"), 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	script, callLog := writeFakeChattr(t, expired[0])
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	im := &ImmutableManager{
		config:            &ImmutableConfig{Enabled: true, ChattrPath: script, LsattrPath: script, ImmutableRotated: true},
		logger:            logger,
		hasCapability:     true,
		capabilityChecked: true,
		activeFiles:       make(map[string]bool),
	}
	al := &AuditLogger{
		config:       &AuditLoggerConfig{LogPath: dir, MaxFiles: 1},
		logger:       logger,
		immutableMgr: im,
	}
	al.cleanupOldFiles(al.immutableMgr, kept)

	callData, err := os.ReadFile(callLog)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("ReadFile() error = %v", err)
	}
	calls := string(callData)
	for _, path := range []string{expired[0], expired[0] + ".sha256", expired[1]} {
		if !strings.Contains(calls, "-i "+path+" present") {
			t.Errorf("chattr -i not run on %s before removal; calls:\n%s", path, calls)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("expired file %s still exists (stat error = %v)", path, err)
		}
	}
	if strings.Contains(calls, kept) {
		t.Errorf("chattr run on retained file %s; calls:\n%s", kept, calls)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Errorf("retained file %s: %v", kept, err)
	}

	logs := logBuf.String()
	for _, path := range []string{expired[0], blocked} {
		found := false
		for _, line := range strings.Split(logs, "\n") {
			if strings.Contains(line, "level=WARN") && strings.Contains(line, path) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no warning logged for failure on %s; logs:\n%s", path, logs)
		}
	}
}

// TestAuditLogger_CleanupOldFilesImmutableReal enforces retention on files
// that really carry the immutable attribute. It needs chattr and
// CAP_LINUX_IMMUTABLE on a filesystem that supports the attribute.
func TestAuditLogger_CleanupOldFilesImmutableReal(t *testing.T) {
	if !hasChattrCapability(t) {
		t.Skip("no chattr capability")
	}
	im, err := NewImmutableManager(DefaultImmutableConfig())
	if err != nil {
		t.Skipf("NewImmutableManager() error = %v", err)
	}

	dir := t.TempDir()
	names := []string{"audit-2020-01-14.log", "audit-2020-01-15.log", "audit-2020-01-16.log"}
	ctx := context.Background()
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		if err := im.SetImmutable(ctx, path); err != nil {
			t.Skipf("SetImmutable() error = %v", err)
		}
	}
	t.Cleanup(func() {
		for _, name := range names {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err == nil {
				clearAttrs(t, im, path)
			}
		}
	})

	al := &AuditLogger{
		config:       &AuditLoggerConfig{LogPath: dir, MaxFiles: 1},
		logger:       slog.Default(),
		immutableMgr: im,
	}
	al.cleanupOldFiles(al.immutableMgr, filepath.Join(dir, names[2]))

	if got := remainingNames(t, dir, "audit-*.log"); fmt.Sprint(got) != fmt.Sprint(names[2:]) {
		t.Errorf("remaining log files = %v, want %v", got, names[2:])
	}
}

// TestAuditLogger_MalformedLogLine checks that a malformed line (such as a
// line torn by a crash mid-write) makes verification fail instead of hanging.
func TestAuditLogger_MalformedLogLine(t *testing.T) {
	tests := []struct {
		name string
		tail string // appended after a valid chain
	}{
		{name: "torn final line", tail: `{"id":"torn","sequence":4,"mess`},
		{name: "garbage line", tail: "not json\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := testConfig(t)
			config.KeyProvider = func() ([]byte, error) { return testHMACKey, nil }
			writeChain(t, config.LogPath, []chainFile{{name: "audit-2020-01-15.log", entries: 3}})
			path := filepath.Join(config.LogPath, "audit-2020-01-15.log")
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatalf("OpenFile() error = %v", err)
			}
			if _, err := f.WriteString(tt.tail); err != nil {
				t.Fatalf("WriteString() error = %v", err)
			}
			if err := f.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}

			al := &AuditLogger{config: config, hmacKey: testHMACKey, logger: slog.Default()}
			done := make(chan error, 1)
			go func() { done <- al.VerifyIntegrity(context.Background()) }()
			select {
			case err := <-done:
				if err == nil {
					t.Error("VerifyIntegrity() = nil, want an error for the malformed line")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("VerifyIntegrity() did not return: reading the malformed line never ends")
			}

			// Queries still return the entries before the malformed line.
			if got, want := querySequences(t, al), wantSequences(3); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("Query() sequences = %v, want %v", got, want)
			}
		})
	}
}

// TestAuditLogger_RotationWithImmutableLogs rotates with real immutable
// attributes: logging must keep working after a rotation seals the previous
// file, and MaxFiles retention must remove the immutable rotated files.
func TestAuditLogger_RotationWithImmutableLogs(t *testing.T) {
	if !hasChattrCapability(t) {
		t.Skip("no chattr capability")
	}

	config := testConfig(t)
	config.MaxFileSize = 1500 // a few entries per file
	config.MaxFiles = 2
	cleanupIM, err := NewImmutableManager(DefaultImmutableConfig())
	if err != nil {
		t.Skipf("NewImmutableManager() error = %v", err)
	}
	t.Cleanup(func() {
		files, _ := filepath.Glob(filepath.Join(config.LogPath, "audit-*"))
		for _, f := range files {
			clearAttrs(t, cleanupIM, f)
		}
	})

	al, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}
	imConfig := DefaultImmutableConfig()
	imConfig.VerifyOnStartup = false
	if err := WithImmutableLogs(al, imConfig); err != nil {
		t.Fatalf("WithImmutableLogs() error = %v", err)
	}
	if status := al.GetImmutableStatus(); status == nil || !status.HasCapability {
		al.Close()
		t.Skip("immutable attributes not available")
	}

	const n = 30
	for i := 0; i < n; i++ {
		mustLog(t, al, EventSystemStart, SeverityInfo, "Event")
	}
	mustFlushAndClose(t, al)

	files, err := al.listLogFiles()
	if err != nil {
		t.Fatalf("listLogFiles() error = %v", err)
	}
	if len(files) != config.MaxFiles {
		t.Errorf("%d log files after retention, want %d: %v", len(files), config.MaxFiles, files)
	}

	al2 := reopenLogger(t, config)
	if got := al2.Metrics().CurrentSequence; got != n {
		t.Errorf("recovered sequence = %d, want %d", got, n)
	}
	if err := al2.VerifyIntegrity(context.Background()); err != nil {
		t.Errorf("VerifyIntegrity() after retention error = %v", err)
	}
}
