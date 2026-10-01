// Package audit provides tamper-evident audit logging for security events.
// It creates a hash chain of audit entries with HMAC signatures to detect
// any modification, deletion, or insertion of log entries.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Common errors.
var (
	ErrLoggerClosed     = errors.New("audit logger is closed")
	ErrTamperDetected   = errors.New("audit log tampering detected")
	ErrChainBroken      = errors.New("audit chain integrity broken")
	ErrSequenceGap      = errors.New("sequence gap detected in audit log")
	ErrInvalidSignature = errors.New("invalid audit entry signature")
	ErrTimestampAnomaly = errors.New("timestamp anomaly detected")
	ErrChecksumMismatch = errors.New("file checksum mismatch")
)

// EventType represents the type of audit event.
type EventType string

const (
	// Security mode events
	EventModeTransitionStart    EventType = "mode.transition.start"
	EventModeTransitionComplete EventType = "mode.transition.complete"
	EventModeTransitionFailed   EventType = "mode.transition.failed"
	EventModeConfirmation       EventType = "mode.confirmation"

	// Authentication events
	EventAuthSuccess EventType = "auth.success"
	EventAuthFailure EventType = "auth.failure"
	EventAuthLogout  EventType = "auth.logout"

	// Access control events
	EventAccessGranted EventType = "access.granted"
	EventAccessDenied  EventType = "access.denied"
	EventPrivilegeEsc  EventType = "access.privilege.escalation"

	// Firewall events
	EventFirewallBlock   EventType = "firewall.block"
	EventFirewallUnblock EventType = "firewall.unblock"
	EventFirewallRuleAdd EventType = "firewall.rule.add"
	EventFirewallFlush   EventType = "firewall.flush"

	// USB events
	EventUSBConnect    EventType = "usb.connect"
	EventUSBDisconnect EventType = "usb.disconnect"
	EventUSBBlocked    EventType = "usb.blocked"

	// Configuration events
	EventConfigChange EventType = "config.change"
	EventConfigReload EventType = "config.reload"

	// System events
	EventSystemStart    EventType = "system.start"
	EventSystemShutdown EventType = "system.shutdown"
	EventSystemError    EventType = "system.error"
	EventWatchdogAlert  EventType = "system.watchdog.alert"

	// Audit events
	EventAuditRotate EventType = "audit.rotate"
	EventAuditVerify EventType = "audit.verify"
	EventAuditTamper EventType = "audit.tamper.detected"
	EventAuditExport EventType = "audit.export"
)

// Severity represents the severity level of an audit event.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
	SeverityAlert    Severity = "alert"
)

// AuditEntry represents a single audit log entry.
type AuditEntry struct {
	// Unique identifier for this entry
	ID string `json:"id"`

	// Sequence number for ordering and gap detection
	Sequence uint64 `json:"sequence"`

	// Timestamp of the event
	Timestamp time.Time `json:"timestamp"`

	// Event type and severity
	Type     EventType `json:"type"`
	Severity Severity  `json:"severity"`

	// Event details
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data,omitempty"`

	// Actor information
	Actor     string `json:"actor,omitempty"`
	ActorIP   string `json:"actor_ip,omitempty"`
	ActorType string `json:"actor_type,omitempty"` // "user", "system", "api"

	// Target information
	Target     string `json:"target,omitempty"`
	TargetType string `json:"target_type,omitempty"`

	// Outcome
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`

	// Chain integrity
	PreviousHash string `json:"previous_hash"`
	EntryHash    string `json:"entry_hash"`
	Signature    string `json:"signature"`

	// Processing metadata
	Hostname  string `json:"hostname,omitempty"`
	ProcessID int    `json:"process_id,omitempty"`
}

// computeHash computes the hash of the entry (excluding signature and entry_hash).
func (e *AuditEntry) computeHash() string {
	h := sha256.New()

	// Hash all fields in deterministic order
	h.Write([]byte(e.ID))
	fmt.Fprintf(h, "%d", e.Sequence)
	h.Write([]byte(e.Timestamp.Format(time.RFC3339Nano)))
	h.Write([]byte(e.Type))
	h.Write([]byte(e.Severity))
	h.Write([]byte(e.Message))

	// Hash data keys in sorted order
	if len(e.Data) > 0 {
		keys := make([]string, 0, len(e.Data))
		for k := range e.Data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			h.Write([]byte(k))
			fmt.Fprintf(h, "%v", e.Data[k])
		}
	}

	h.Write([]byte(e.Actor))
	h.Write([]byte(e.ActorIP))
	h.Write([]byte(e.ActorType))
	h.Write([]byte(e.Target))
	h.Write([]byte(e.TargetType))
	fmt.Fprintf(h, "%t", e.Success)
	h.Write([]byte(e.Error))
	h.Write([]byte(e.PreviousHash))
	h.Write([]byte(e.Hostname))
	fmt.Fprintf(h, "%d", e.ProcessID)

	return hex.EncodeToString(h.Sum(nil))
}

// Sign signs the entry with the given HMAC key.
func (e *AuditEntry) Sign(key []byte) {
	e.EntryHash = e.computeHash()

	h := hmac.New(sha256.New, key)
	h.Write([]byte(e.EntryHash))
	h.Write([]byte(e.PreviousHash))
	e.Signature = hex.EncodeToString(h.Sum(nil))
}

// Verify verifies the entry signature.
func (e *AuditEntry) Verify(key []byte) bool {
	expectedHash := e.computeHash()
	if expectedHash != e.EntryHash {
		return false
	}

	h := hmac.New(sha256.New, key)
	h.Write([]byte(e.EntryHash))
	h.Write([]byte(e.PreviousHash))
	expected := hex.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(e.Signature), []byte(expected))
}

// AuditLoggerConfig configures the audit logger.
type AuditLoggerConfig struct {
	// LogPath is the directory for audit logs.
	LogPath string

	// MaxFileSize is the maximum size of a single log file before rotation.
	MaxFileSize int64

	// MaxFiles is the maximum number of log files to retain.
	MaxFiles int

	// FlushInterval is how often to flush entries to disk.
	FlushInterval time.Duration

	// VerifyInterval is how often to run integrity checks.
	VerifyInterval time.Duration

	// BufferSize is the size of the in-memory entry buffer.
	BufferSize int

	// EnableRemote enables forwarding to a remote syslog/SIEM.
	EnableRemote bool

	// RemoteAddress is the address of the remote syslog server.
	RemoteAddress string

	// RemoteProtocol is "tcp" or "udp" or "tls".
	RemoteProtocol string

	// Hostname to include in entries.
	Hostname string

	// OnTamperDetected is called when tampering is detected.
	OnTamperDetected func(entry *AuditEntry, err error)

	// KeyProvider optionally provides the HMAC signing key from an external
	// source (e.g., HashiCorp Vault, AWS KMS, or a secrets manager).
	// When set, the file-based key at LogPath/.audit.key is not used.
	// The function must return a 32-byte key.
	KeyProvider func() ([]byte, error)
}

// DefaultAuditLoggerConfig returns sensible defaults.
func DefaultAuditLoggerConfig() *AuditLoggerConfig {
	hostname, _ := os.Hostname()
	return &AuditLoggerConfig{
		LogPath:        "/var/log/boundary-siem/audit",
		MaxFileSize:    100 * 1024 * 1024, // 100MB
		MaxFiles:       90,                // 90 days
		FlushInterval:  1 * time.Second,
		VerifyInterval: 5 * time.Minute,
		BufferSize:     1000,
		EnableRemote:   false,
		Hostname:       hostname,
	}
}

// AuditLogger provides tamper-evident audit logging.
type AuditLogger struct {
	mu sync.RWMutex

	config  *AuditLoggerConfig
	hmacKey []byte
	logger  *slog.Logger

	// Current state
	sequence     uint64
	previousHash string
	currentFile  *os.File
	currentPath  string
	currentSize  int64

	// Lifecycle
	closed atomic.Bool

	// Background processing
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Retention cleanups started by rotate; cleanupMu serializes them.
	cleanupWG sync.WaitGroup
	cleanupMu sync.Mutex

	// verifyListHook, when non-nil, runs in VerifyIntegrity after the log
	// files are listed. It is nil outside tests, which use it to remove
	// files the way a concurrent retention cleanup would.
	verifyListHook func()

	// Immutable log support
	immutableMgr *ImmutableManager

	// Remote syslog forwarding
	syslogFwd *SyslogForwarder

	// Metrics
	written   uint64
	errors    uint64
	tampering uint64
}

// NewAuditLogger creates a new audit logger.
func NewAuditLogger(config *AuditLoggerConfig, logger *slog.Logger) (*AuditLogger, error) {
	if config == nil {
		config = DefaultAuditLoggerConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Ensure log directory exists
	if err := os.MkdirAll(config.LogPath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create audit log directory: %w", err)
	}

	// Load HMAC key: prefer external KeyProvider, fall back to file-based key
	var hmacKey []byte
	var err error
	if config.KeyProvider != nil {
		hmacKey, err = config.KeyProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to get HMAC key from provider: %w", err)
		}
		if len(hmacKey) != 32 {
			return nil, fmt.Errorf("HMAC key from provider must be 32 bytes, got %d", len(hmacKey))
		}
		logger.Info("audit HMAC key loaded from external provider")
	} else {
		hmacKey, err = loadOrGenerateHMACKey(config.LogPath)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize HMAC key: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	al := &AuditLogger{
		config:       config,
		hmacKey:      hmacKey,
		logger:       logger,
		previousHash: computeGenesisHash(),
		ctx:          ctx,
		cancel:       cancel,
	}

	// Try to recover state from existing logs
	if err := al.recoverState(); err != nil {
		logger.Warn("failed to recover audit state", "error", err)
	}

	// Open or create current log file
	if err := al.openLogFile(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	// Start background workers
	al.wg.Add(2)
	go al.flushWorker()
	go al.verifyWorker()

	logger.Info("audit logger initialized",
		"path", config.LogPath,
		"sequence", al.sequence)

	return al, nil
}

// loadOrGenerateHMACKey loads or generates the HMAC key.
func loadOrGenerateHMACKey(basePath string) ([]byte, error) {
	keyPath := filepath.Join(basePath, ".audit.key")

	// Try to load existing key
	if data, err := os.ReadFile(keyPath); err == nil && len(data) == 32 { // #nosec G304 -- keyPath is the operator-configured LogPath joined with the constant ".audit.key", not external input
		return data, nil
	}

	// Generate new key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	// Persist key with restricted permissions
	if err := os.WriteFile(keyPath, key, 0400); err != nil {
		return nil, err
	}

	return key, nil
}

// computeGenesisHash computes the genesis hash for the chain.
func computeGenesisHash() string {
	h := sha256.New()
	h.Write([]byte("boundary-siem-audit-genesis-v1"))
	return hex.EncodeToString(h.Sum(nil))
}

// Log file naming. Each day's first file is audit-<day>.log; files started
// later that day (by size rotation or a restart) are audit-<day>-<n>.log,
// where n is a Unix timestamp raised as needed so that it exceeds the n of
// every earlier file of the day.
const (
	logFilePrefix = "audit-"
	logFileSuffix = ".log"
	logDayLayout  = "2006-01-02"
)

// logFileKey is the position of a log file in rotation order.
type logFileKey struct {
	day      string // YYYY-MM-DD, compares chronologically as a string
	rotation int64  // -1 for the day's first file, else the numeric suffix
}

func (k logFileKey) less(o logFileKey) bool {
	if k.day != o.day {
		return k.day < o.day
	}
	return k.rotation < o.rotation
}

// parseLogFileName returns the rotation order key of a log file base name.
// ok is false for names this logger does not create.
func parseLogFileName(name string) (key logFileKey, ok bool) {
	if !strings.HasPrefix(name, logFilePrefix) || !strings.HasSuffix(name, logFileSuffix) {
		return key, false
	}
	core := name[len(logFilePrefix) : len(name)-len(logFileSuffix)]
	if len(core) < len(logDayLayout) {
		return key, false
	}
	day, rest := core[:len(logDayLayout)], core[len(logDayLayout):]
	if _, err := time.Parse(logDayLayout, day); err != nil {
		return key, false
	}
	if rest == "" {
		return logFileKey{day: day, rotation: -1}, true
	}
	// Require a digit after the separator so ParseInt sees no sign.
	if len(rest) < 2 || rest[0] != '-' || rest[1] < '0' || rest[1] > '9' {
		return key, false
	}
	n, err := strconv.ParseInt(rest[1:], 10, 64)
	if err != nil {
		return key, false
	}
	return logFileKey{day: day, rotation: n}, true
}

// sortLogFiles sorts log file paths into the order they were written:
// by day, then the day's first file, then rotated files by numeric suffix.
// Plain string order is wrong here, because "audit-<day>-<n>.log" sorts
// before "audit-<day>.log". Names the logger does not create sort first.
func sortLogFiles(files []string) {
	sort.SliceStable(files, func(i, j int) bool {
		ki, oki := parseLogFileName(filepath.Base(files[i]))
		kj, okj := parseLogFileName(filepath.Base(files[j]))
		switch {
		case oki != okj:
			return !oki
		case oki && ki != kj:
			return ki.less(kj)
		default:
			return files[i] < files[j]
		}
	})
}

// listLogFiles returns the audit-*.log files in LogPath in rotation order.
func (al *AuditLogger) listLogFiles() ([]string, error) {
	dirEntries, err := os.ReadDir(al.config.LogPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var files []string
	for _, e := range dirEntries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, logFilePrefix) || !strings.HasSuffix(name, logFileSuffix) {
			continue
		}
		files = append(files, filepath.Join(al.config.LogPath, name))
	}
	sortLogFiles(files)
	return files, nil
}

// latestLogFileOfDay returns the newest file of day among files, which must
// be in rotation order.
func latestLogFileOfDay(files []string, day string) (path string, key logFileKey, ok bool) {
	for i := len(files) - 1; i >= 0; i-- {
		if k, parsed := parseLogFileName(filepath.Base(files[i])); parsed && k.day == day {
			return files[i], k, true
		}
	}
	return "", logFileKey{}, false
}

// isSealed reports whether a log file was finished by rotate or Close, which
// write its checksum. Appending to a sealed file would invalidate it.
func isSealed(path string) bool {
	_, err := os.Stat(path + ".sha256")
	return err == nil
}

// recoverState recovers the sequence number and previous hash from existing logs.
func (al *AuditLogger) recoverState() error {
	files, err := al.listLogFiles()
	if err != nil {
		return err
	}

	// Continue from the last entry written. Walk back from the newest file:
	// it may hold no entries yet (for example a file opened by a run that
	// logged nothing before it was stopped).
	for i := len(files) - 1; i >= 0; i-- {
		lastEntry, err := al.readLastEntry(files[i])
		if err != nil {
			return err
		}
		if lastEntry != nil {
			al.sequence = lastEntry.Sequence
			al.previousHash = lastEntry.EntryHash
			return nil
		}
	}

	return nil
}

// readLastEntry reads the last entry from a log file.
func (al *AuditLogger) readLastEntry(path string) (*AuditEntry, error) {
	f, err := os.Open(path) // #nosec G304 -- path is an audit-*.log match globbed inside the operator-configured LogPath, not external input
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Seek to end and read backwards
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if stat.Size() == 0 {
		return nil, nil
	}

	// Read file in chunks from the end
	buf := make([]byte, 8192)
	var lastLine string

	for offset := stat.Size(); offset > 0; {
		readSize := int64(len(buf))
		if offset < readSize {
			readSize = offset
		}
		offset -= readSize

		if _, err := f.Seek(offset, 0); err != nil {
			return nil, err
		}

		n, err := f.Read(buf[:readSize])
		if err != nil && err != io.EOF {
			return nil, err
		}

		lines := strings.Split(string(buf[:n]), "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			line := strings.TrimSpace(lines[i])
			if line != "" {
				lastLine = line
				break
			}
		}

		if lastLine != "" {
			break
		}
	}

	if lastLine == "" {
		return nil, nil
	}

	var entry AuditEntry
	if err := json.Unmarshal([]byte(lastLine), &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}

// openLogFile opens the log file entries are written to at startup. It
// continues today's newest log file, so a restart after a same-day rotation
// keeps the chain in rotation order, unless that file is sealed: appending
// would invalidate its checksum (and fail if it is immutable), so a new file
// is started instead.
func (al *AuditLogger) openLogFile() error {
	now := time.Now()
	files, err := al.listLogFiles()
	if err != nil {
		return err
	}

	if latest, _, ok := latestLogFileOfDay(files, now.Format(logDayLayout)); ok && !isSealed(latest) {
		f, err := os.OpenFile(latest, os.O_APPEND|os.O_WRONLY, 0600) // #nosec G304 -- latest is a log file name listed inside the operator-configured LogPath, not external input
		if err == nil {
			return al.useLogFile(f, latest)
		}
		al.logger.Warn("cannot append to newest audit log file, starting a new one", "path", latest, "error", err)
	}

	return al.openNewLogFile(files, now)
}

// openNewLogFile creates the next log file of now's day and makes it current.
// Its name sorts after every existing file of that day (files must be the
// directory listing in rotation order), so rotation order is preserved even
// for several rotations within one second.
func (al *AuditLogger) openNewLogFile(files []string, now time.Time) error {
	day := now.Format(logDayLayout)
	filename := logFilePrefix + day + logFileSuffix
	if _, latest, ok := latestLogFileOfDay(files, day); ok {
		n := now.Unix()
		if n <= latest.rotation {
			n = latest.rotation + 1
		}
		filename = fmt.Sprintf("%s%s-%d%s", logFilePrefix, day, n, logFileSuffix)
	}
	path := filepath.Join(al.config.LogPath, filename)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) // #nosec G304 -- path is the operator-configured LogPath joined with a generated audit-<date>[-<n>].log name, not external input
	if err != nil {
		return err
	}
	return al.useLogFile(f, path)
}

// useLogFile makes f, opened at path, the current log file.
func (al *AuditLogger) useLogFile(f *os.File, path string) error {
	stat, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}

	al.currentFile = f
	al.currentPath = path
	al.currentSize = stat.Size()

	return nil
}

// Log logs an audit event.
// Note: This writes synchronously to maintain hash chain integrity.
func (al *AuditLogger) Log(ctx context.Context, eventType EventType, severity Severity, message string, data map[string]interface{}) error {
	if al.closed.Load() {
		return ErrLoggerClosed
	}

	// Create and write synchronously to maintain chain integrity
	// The hash chain requires strict ordering of entries
	return al.logEntry(eventType, severity, message, data)
}

// logEntry creates and writes an entry atomically.
func (al *AuditLogger) logEntry(eventType EventType, severity Severity, message string, data map[string]interface{}) error {
	al.mu.Lock()
	defer al.mu.Unlock()

	// Log's closed check runs before the lock is taken, so Close may have
	// closed and sealed the file in the meantime. Writing now would fail, or
	// rotate into a new file that nothing ever seals or closes.
	if al.closed.Load() {
		return ErrLoggerClosed
	}

	al.sequence++

	entry := &AuditEntry{
		ID:           generateEntryID(),
		Sequence:     al.sequence,
		Timestamp:    time.Now().UTC(),
		Type:         eventType,
		Severity:     severity,
		Message:      message,
		Data:         data,
		PreviousHash: al.previousHash,
		Hostname:     al.config.Hostname,
		ProcessID:    os.Getpid(),
		Success:      true,
	}

	entry.Sign(al.hmacKey)
	al.previousHash = entry.EntryHash

	// Write to local file
	if err := al.writeEntryLocked(entry); err != nil {
		return err
	}

	// Forward to remote syslog if configured
	if al.syslogFwd != nil {
		// Don't block or fail on syslog errors - it's async. The entry is
		// already persisted locally, and rejected entries are counted in the
		// forwarder's Dropped metric (see GetSyslogStatus).
		if err := al.syslogFwd.Forward(entry); err != nil {
			al.logger.Debug("audit entry not forwarded to remote syslog",
				"sequence", entry.Sequence,
				"error", err)
		}
	}

	return nil
}

// LogEvent logs a structured audit event.
func (al *AuditLogger) LogEvent(ctx context.Context, event *AuditEvent) error {
	return al.Log(ctx, event.Type, event.Severity, event.Message, event.Data)
}

// AuditEvent is a convenience struct for creating audit entries.
type AuditEvent struct {
	Type       EventType
	Severity   Severity
	Message    string
	Data       map[string]interface{}
	Actor      string
	ActorIP    string
	ActorType  string
	Target     string
	TargetType string
	Success    bool
	Error      string
}

// generateEntryID generates a unique entry ID.
func generateEntryID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-only if random fails
		return fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Nanosecond())
	}
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), hex.EncodeToString(b))
}

// writeEntryLocked writes an entry to the log file (caller must hold lock).
func (al *AuditLogger) writeEntryLocked(entry *AuditEntry) error {
	// Check if rotation needed
	if al.currentSize >= al.config.MaxFileSize {
		if err := al.rotate(); err != nil {
			al.logger.Error("failed to rotate audit log", "error", err)
		}
	}

	// Start a new file when the day changes. Files rotated earlier today
	// (audit-<today>-<n>.log) belong to today as well.
	if key, ok := parseLogFileName(filepath.Base(al.currentPath)); !ok || key.day != time.Now().Format(logDayLayout) {
		if err := al.rotate(); err != nil {
			return fmt.Errorf("failed to open new log file: %w", err)
		}
	}

	// Marshal entry
	data, err := json.Marshal(entry)
	if err != nil {
		atomic.AddUint64(&al.errors, 1)
		return fmt.Errorf("failed to marshal entry: %w", err)
	}

	// Write with newline
	data = append(data, '\n')
	n, err := al.currentFile.Write(data)
	if err != nil {
		atomic.AddUint64(&al.errors, 1)
		return fmt.Errorf("failed to write entry: %w", err)
	}

	al.currentSize += int64(n)
	atomic.AddUint64(&al.written, 1)

	return nil
}

// rotate rotates the current log file.
func (al *AuditLogger) rotate() error {
	rotatedPath := al.currentPath
	ctx := context.Background()

	if al.currentFile != nil {
		// Clear append-only attribute before closing (if immutable manager is enabled)
		if al.immutableMgr != nil {
			if err := al.immutableMgr.PrepareForRotation(ctx, al.currentPath); err != nil {
				al.logger.Warn("failed to clear append-only for rotation", "error", err)
			}
		}

		// Sync and close
		if err := al.currentFile.Sync(); err != nil {
			al.logger.Warn("failed to sync audit log before rotation", "path", rotatedPath, "error", err)
		}
		al.currentFile.Close()

		// Compute and write checksum
		if err := al.writeFileChecksum(al.currentPath); err != nil {
			al.logger.Warn("failed to write file checksum", "error", err)
		}

		// Set immutable on rotated file and its checksum
		if al.immutableMgr != nil {
			if err := al.immutableMgr.SetImmutable(ctx, rotatedPath); err != nil {
				al.logger.Warn("failed to set immutable on rotated file", "path", rotatedPath, "error", err)
			}
			checksumPath := rotatedPath + ".sha256"
			if err := al.immutableMgr.ProtectChecksumFile(ctx, checksumPath); err != nil {
				al.logger.Warn("failed to protect checksum file", "path", checksumPath, "error", err)
			}
		}
	}

	// Open the next file, named to sort after every existing file of today
	files, err := al.listLogFiles()
	if err != nil {
		return err
	}
	if err := al.openNewLogFile(files, time.Now()); err != nil {
		return err
	}
	path := al.currentPath

	// Set append-only on new file
	if al.immutableMgr != nil {
		if err := al.immutableMgr.SetAppendOnly(ctx, path); err != nil {
			al.logger.Warn("failed to set append-only on new file", "path", path, "error", err)
		}
	}

	// Clean up old files. The goroutine gets the manager and the active path
	// as arguments because it must not take al.mu: Close waits for it while
	// holding al.mu. rotate always runs under al.mu, so Add never races
	// Close's Wait.
	im := al.immutableMgr
	al.cleanupWG.Add(1)
	go func() {
		defer al.cleanupWG.Done()
		al.cleanupOldFiles(im, path)
	}()

	return nil
}

// writeFileChecksum writes a checksum file for integrity verification.
func (al *AuditLogger) writeFileChecksum(logPath string) error {
	f, err := os.Open(logPath) // #nosec G304 -- logPath is always al.currentPath, a generated file name inside the operator-configured LogPath
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	checksum := hex.EncodeToString(h.Sum(nil))
	checksumPath := logPath + ".sha256"

	return os.WriteFile(checksumPath, []byte(checksum), 0600)
}

// cleanupOldFiles enforces MaxFiles retention: it removes the oldest log
// files, in rotation order, together with their checksum files. Only files
// named by the logger count, and activePath (the file being written) is never
// removed. Rotated files are immutable when an ImmutableManager is in use, so
// im clears their attributes first; every failure is logged. MaxFiles <= 0
// disables retention.
func (al *AuditLogger) cleanupOldFiles(im *ImmutableManager, activePath string) {
	if al.config.MaxFiles <= 0 {
		return
	}

	// Rotations in quick succession must not remove the same files twice.
	al.cleanupMu.Lock()
	defer al.cleanupMu.Unlock()

	files, err := al.listLogFiles()
	if err != nil {
		al.logger.Warn("failed to list audit log files for retention", "path", al.config.LogPath, "error", err)
		return
	}
	managed := files[:0]
	for _, f := range files {
		if _, ok := parseLogFileName(filepath.Base(f)); ok {
			managed = append(managed, f)
		}
	}
	if len(managed) <= al.config.MaxFiles {
		return
	}

	ctx := context.Background()
	for _, f := range managed[:len(managed)-al.config.MaxFiles] {
		if f == activePath {
			continue
		}
		al.removeExpiredFile(ctx, im, f)
		al.removeExpiredFile(ctx, im, f+".sha256")
	}
}

// removeExpiredFile removes one file past retention, clearing its immutable
// and append-only attributes through im (when set) first. A file that does
// not exist is skipped.
func (al *AuditLogger) removeExpiredFile(ctx context.Context, im *ImmutableManager, path string) {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return
	}

	if im != nil {
		if err := im.ClearImmutable(ctx, path); err != nil {
			al.logger.Warn("failed to clear immutable attribute on expired audit log file", "path", path, "error", err)
		}
		if err := im.ClearAppendOnly(ctx, path); err != nil {
			al.logger.Warn("failed to clear append-only attribute on expired audit log file", "path", path, "error", err)
		}
	}

	if err := os.Remove(path); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			al.logger.Warn("failed to remove expired audit log file", "path", path, "error", err)
		}
		return
	}
	al.logger.Info("removed expired audit log file", "path", path)
}

// flushWorker periodically syncs the log file to disk.
func (al *AuditLogger) flushWorker() {
	defer al.wg.Done()

	ticker := time.NewTicker(al.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-al.ctx.Done():
			return
		case <-ticker.C:
			// Sync to disk
			al.mu.Lock()
			if al.currentFile != nil {
				if err := al.currentFile.Sync(); err != nil {
					al.logger.Warn("failed to sync audit log", "path", al.currentPath, "error", err)
				}
			}
			al.mu.Unlock()
		}
	}
}

// verifyWorker periodically verifies log integrity.
func (al *AuditLogger) verifyWorker() {
	defer al.wg.Done()

	if al.config.VerifyInterval <= 0 {
		return
	}

	ticker := time.NewTicker(al.config.VerifyInterval)
	defer ticker.Stop()

	for {
		select {
		case <-al.ctx.Done():
			return
		case <-ticker.C:
			al.runVerification()
		}
	}
}

// runVerification runs one periodic integrity check and reports a failure as
// tampering. A check cut short because Close cancelled it is not a failure.
func (al *AuditLogger) runVerification() {
	err := al.VerifyIntegrity(al.ctx)
	if err == nil {
		return
	}
	if ctxErr := al.ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
		return
	}

	al.logger.Error("audit log integrity check failed", "error", err)
	atomic.AddUint64(&al.tampering, 1)

	// Log the tamper detection as an audit event
	if logErr := al.Log(al.ctx, EventAuditTamper, SeverityAlert,
		"Audit log tampering detected", map[string]interface{}{
			"error": err.Error(),
		}); logErr != nil {
		al.logger.Error("failed to record audit tamper event", "error", logErr)
	}

	if al.config.OnTamperDetected != nil {
		al.config.OnTamperDetected(nil, err)
	}
}

// errLogFileVanished reports a listed log file that no longer exists, as
// when retention removes the oldest files while they are being verified.
var errLogFileVanished = errors.New("audit log file removed during verification")

// verifyAttempts bounds how often VerifyIntegrity starts over because a
// listed file was removed meanwhile.
const verifyAttempts = 3

// VerifyIntegrity verifies the integrity of all log files.
func (al *AuditLogger) VerifyIntegrity(ctx context.Context) error {
	// Retention can remove the oldest files after they were listed. Start
	// over on a fresh listing then: a pass over the remaining files accepts a
	// chain whose start was removed, but still reports a file missing from
	// the middle as a broken chain.
	var err error
	for attempt := 0; attempt < verifyAttempts; attempt++ {
		var files []string
		files, err = al.listLogFiles()
		if err != nil {
			return err
		}
		if al.verifyListHook != nil {
			al.verifyListHook()
		}
		err = al.verifyLogFiles(ctx, files)
		if !errors.Is(err, errLogFileVanished) {
			return err
		}
	}
	return err
}

// verifyLogFiles verifies the hash chain, signatures and checksums of files,
// which must be a listing of the log directory in rotation order. It returns
// an error wrapping errLogFileVanished if one of them no longer exists.
func (al *AuditLogger) verifyLogFiles(ctx context.Context, files []string) error {
	genesisHash := computeGenesisHash()
	active := al.activeExtent()

	var lastEntry *AuditEntry
	for _, file := range files {
		entries, err := al.readLogFileUpTo(file, active.readLimit(file))
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %s", errLogFileVanished, file)
		}
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", file, err)
		}

		for _, entry := range entries {
			// Verify signature
			if !entry.Verify(al.hmacKey) {
				return fmt.Errorf("%w at sequence %d in %s", ErrInvalidSignature, entry.Sequence, file)
			}

			// Verify chain link
			if lastEntry != nil {
				if entry.PreviousHash != lastEntry.EntryHash {
					return fmt.Errorf("%w at sequence %d in %s", ErrChainBroken, entry.Sequence, file)
				}

				// Check sequence
				if entry.Sequence != lastEntry.Sequence+1 {
					return fmt.Errorf("%w: expected %d, got %d in %s",
						ErrSequenceGap, lastEntry.Sequence+1, entry.Sequence, file)
				}

				// Check timestamp ordering
				if entry.Timestamp.Before(lastEntry.Timestamp) {
					return fmt.Errorf("%w at sequence %d in %s", ErrTimestampAnomaly, entry.Sequence, file)
				}
			} else if entry.Sequence == 1 && entry.PreviousHash != genesisHash {
				// First entry should chain from genesis. Only check genesis for
				// sequence 1: after retention cleanup the oldest remaining
				// entry legitimately links to a deleted predecessor.
				return fmt.Errorf("%w at sequence %d in %s: first entry does not chain from genesis",
					ErrChainBroken, entry.Sequence, file)
			}

			lastEntry = entry
		}

		// Verify file checksum if exists
		checksumPath := file + ".sha256"
		if _, err := os.Stat(checksumPath); err == nil {
			if err := al.verifyFileChecksum(file, checksumPath); err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("%w: %s", errLogFileVanished, file)
				}
				return err
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	return nil
}

// logExtent is the file entries are being written to and its size after
// the last completed write.
type logExtent struct {
	path string
	size int64
}

// activeExtent returns the current logExtent. Readers take it after listing
// the log files: a file that becomes active later is then not in their list,
// and the file it names only grows past size.
func (al *AuditLogger) activeExtent() logExtent {
	al.mu.RLock()
	defer al.mu.RUnlock()
	return logExtent{path: al.currentPath, size: al.currentSize}
}

// readLimit returns how many bytes of a listed log file hold completed
// entries, or -1 for all of them. Only the active file is limited: a reader
// can see part of a write still in progress past its last completed entry,
// and that is not corruption.
func (e logExtent) readLimit(file string) int64 {
	if e.path != "" && file == e.path {
		return e.size
	}
	return -1
}

// readLogFile reads all entries from a log file. If the file holds malformed
// data (such as a line torn by a crash mid-write), it returns the entries
// before it together with an error.
func (al *AuditLogger) readLogFile(path string) ([]*AuditEntry, error) {
	return al.readLogFileUpTo(path, -1)
}

// readLogFileUpTo is readLogFile limited to the first limit bytes of the
// file. A negative limit reads the whole file.
func (al *AuditLogger) readLogFileUpTo(path string, limit int64) ([]*AuditEntry, error) {
	f, err := os.Open(path) // #nosec G304 -- path is an audit-*.log match globbed inside the operator-configured LogPath, not external input
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var r io.Reader = f
	if limit >= 0 {
		r = io.LimitReader(f, limit)
	}

	var entries []*AuditEntry
	decoder := json.NewDecoder(r)

	for {
		var entry AuditEntry
		if err := decoder.Decode(&entry); err != nil {
			if err == io.EOF {
				break
			}
			// json.Decoder errors are sticky: decoding cannot resume after
			// malformed data, and retrying would loop forever.
			return entries, fmt.Errorf("malformed data after entry %d: %w", len(entries), err)
		}
		entries = append(entries, &entry)
	}

	return entries, nil
}

// verifyFileChecksum verifies a file's checksum.
func (al *AuditLogger) verifyFileChecksum(logPath, checksumPath string) error {
	expected, err := os.ReadFile(checksumPath) // #nosec G304 -- checksumPath is a globbed audit-*.log path inside the operator-configured LogPath plus ".sha256", not external input
	if err != nil {
		return err
	}

	f, err := os.Open(logPath) // #nosec G304 -- logPath is an audit-*.log match globbed inside the operator-configured LogPath, not external input
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	actual := hex.EncodeToString(h.Sum(nil))
	if string(expected) != actual {
		return fmt.Errorf("%w for %s", ErrChecksumMismatch, logPath)
	}

	return nil
}

// Close closes the audit logger.
func (al *AuditLogger) Close() error {
	if al.closed.Swap(true) {
		return nil
	}

	al.cancel()
	al.wg.Wait()

	al.mu.Lock()
	defer al.mu.Unlock()

	ctx := context.Background()

	// Wait for retention cleanups started by rotate. They never take al.mu,
	// and rotate runs under al.mu, so none can start during the wait.
	al.cleanupWG.Wait()

	// Close syslog forwarder first to flush any pending messages
	if al.syslogFwd != nil {
		if err := al.syslogFwd.Close(); err != nil {
			al.logger.Warn("failed to close syslog forwarder", "error", err)
		}
	}

	// Failing to persist the final entries is reported to the caller; the
	// checksum and attribute steps are best-effort, as in rotate.
	var errs []error
	if al.currentFile != nil {
		// Clear append-only before closing
		if al.immutableMgr != nil {
			if err := al.immutableMgr.ClearAppendOnly(ctx, al.currentPath); err != nil {
				al.logger.Warn("failed to clear append-only on current log", "path", al.currentPath, "error", err)
			}
		}

		if err := al.currentFile.Sync(); err != nil {
			errs = append(errs, fmt.Errorf("failed to sync audit log: %w", err))
		}
		if err := al.writeFileChecksum(al.currentPath); err != nil {
			al.logger.Warn("failed to write file checksum", "path", al.currentPath, "error", err)
		}
		if err := al.currentFile.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close audit log: %w", err))
		}

		// Set immutable on final file
		if al.immutableMgr != nil {
			if err := al.immutableMgr.SetImmutable(ctx, al.currentPath); err != nil {
				al.logger.Warn("failed to set immutable on final log file", "path", al.currentPath, "error", err)
			}
			checksumPath := al.currentPath + ".sha256"
			if err := al.immutableMgr.ProtectChecksumFile(ctx, checksumPath); err != nil {
				al.logger.Warn("failed to protect checksum file", "path", checksumPath, "error", err)
			}
		}
	}

	al.logger.Info("audit logger closed",
		"written", atomic.LoadUint64(&al.written),
		"errors", atomic.LoadUint64(&al.errors))

	return errors.Join(errs...)
}

// GetSyslogStatus returns the syslog forwarder status.
func (al *AuditLogger) GetSyslogStatus() *SyslogMetrics {
	al.mu.RLock()
	defer al.mu.RUnlock()

	if al.syslogFwd == nil {
		return nil
	}

	metrics := al.syslogFwd.Metrics()
	return &metrics
}

// GetImmutableStatus returns the immutable log status.
func (al *AuditLogger) GetImmutableStatus() *ImmutableStatus {
	al.mu.RLock()
	defer al.mu.RUnlock()

	if al.immutableMgr == nil {
		return nil
	}

	status := al.immutableMgr.GetStatus()
	return &status
}

// Metrics returns audit logger metrics.
func (al *AuditLogger) Metrics() AuditMetrics {
	al.mu.RLock()
	seq := al.sequence
	al.mu.RUnlock()
	return AuditMetrics{
		Written:          atomic.LoadUint64(&al.written),
		Errors:           atomic.LoadUint64(&al.errors),
		TamperDetections: atomic.LoadUint64(&al.tampering),
		CurrentSequence:  seq,
	}
}

// AuditMetrics contains audit logger statistics.
type AuditMetrics struct {
	Written          uint64
	Errors           uint64
	TamperDetections uint64
	CurrentSequence  uint64
}

// Query returns audit entries matching the criteria.
func (al *AuditLogger) Query(ctx context.Context, opts QueryOptions) ([]*AuditEntry, error) {
	files, err := al.listLogFiles()
	if err != nil {
		return nil, err
	}

	active := al.activeExtent()

	var results []*AuditEntry
	for _, file := range files {
		entries, err := al.readLogFileUpTo(file, active.readLimit(file))
		if err != nil {
			// Still search the entries read before the unreadable part.
			al.logger.Warn("failed to read audit log file", "path", file, "error", err)
		}

		for _, entry := range entries {
			if matchesQuery(entry, opts) {
				results = append(results, entry)
				if opts.Limit > 0 && len(results) >= opts.Limit {
					return results, nil
				}
			}
		}

		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}
	}

	return results, nil
}

// QueryOptions specifies query criteria.
type QueryOptions struct {
	StartTime  time.Time
	EndTime    time.Time
	Types      []EventType
	Severities []Severity
	Actor      string
	Target     string
	Limit      int
}

// matchesQuery checks if an entry matches the query options.
func matchesQuery(entry *AuditEntry, opts QueryOptions) bool {
	if !opts.StartTime.IsZero() && entry.Timestamp.Before(opts.StartTime) {
		return false
	}
	if !opts.EndTime.IsZero() && entry.Timestamp.After(opts.EndTime) {
		return false
	}

	if len(opts.Types) > 0 {
		found := false
		for _, t := range opts.Types {
			if entry.Type == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(opts.Severities) > 0 {
		found := false
		for _, s := range opts.Severities {
			if entry.Severity == s {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if opts.Actor != "" && entry.Actor != opts.Actor {
		return false
	}

	if opts.Target != "" && entry.Target != opts.Target {
		return false
	}

	return true
}

// Export exports audit entries to a writer.
func (al *AuditLogger) Export(ctx context.Context, w io.Writer, opts QueryOptions) error {
	entries, err := al.Query(ctx, opts)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	for _, entry := range entries {
		if err := encoder.Encode(entry); err != nil {
			return err
		}
	}

	// Log the export
	if err := al.Log(ctx, EventAuditExport, SeverityInfo, "Audit log exported", map[string]interface{}{
		"entries": len(entries),
	}); err != nil {
		return fmt.Errorf("failed to record audit export event: %w", err)
	}

	return nil
}

// ForceFlush forces an immediate sync to disk.
// Since writes are synchronous, this just ensures data is persisted.
func (al *AuditLogger) ForceFlush(ctx context.Context) error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.currentFile != nil {
		return al.currentFile.Sync()
	}
	return nil
}
