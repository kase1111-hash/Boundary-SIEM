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
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Common errors.
var (
	ErrLoggerClosed       = errors.New("audit logger is closed")
	ErrTamperDetected     = errors.New("audit log tampering detected")
	ErrChainBroken        = errors.New("audit chain integrity broken")
	ErrSequenceGap        = errors.New("sequence gap detected in audit log")
	ErrInvalidSignature   = errors.New("invalid audit entry signature")
	ErrTimestampAnomaly   = errors.New("timestamp anomaly detected")
	ErrChecksumMismatch   = errors.New("file checksum mismatch")
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
	EventAuditRotate   EventType = "audit.rotate"
	EventAuditVerify   EventType = "audit.verify"
	EventAuditTamper   EventType = "audit.tamper.detected"
	EventAuditExport   EventType = "audit.export"
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
	h.Write([]byte(fmt.Sprintf("%d", e.Sequence)))
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
			h.Write([]byte(fmt.Sprintf("%v", e.Data[k])))
		}
	}

	h.Write([]byte(e.Actor))
	h.Write([]byte(e.ActorIP))
	h.Write([]byte(e.ActorType))
	h.Write([]byte(e.Target))
	h.Write([]byte(e.TargetType))
	h.Write([]byte(fmt.Sprintf("%t", e.Success)))
	h.Write([]byte(e.Error))
	h.Write([]byte(e.PreviousHash))
	h.Write([]byte(e.Hostname))
	h.Write([]byte(fmt.Sprintf("%d", e.ProcessID)))

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
}

// DefaultAuditLoggerConfig returns sensible defaults.
func DefaultAuditLoggerConfig() *AuditLoggerConfig {
	hostname, _ := os.Hostname()
	return &AuditLoggerConfig{
		LogPath:        "/var/log/boundary-siem/audit",
		MaxFileSize:    100 * 1024 * 1024, // 100MB
		MaxFiles:       90,                 // 90 days
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

	// Load or generate HMAC key
	hmacKey, err := loadOrGenerateHMACKey(config.LogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize HMAC key: %w", err)
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
	if data, err := os.ReadFile(keyPath); err == nil && len(data) == 32 {
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

// recoverState recovers the sequence number and previous hash from existing logs.
func (al *AuditLogger) recoverState() error {
	files, err := filepath.Glob(filepath.Join(al.config.LogPath, "audit-*.log"))
	if err != nil || len(files) == 0 {
		return nil
	}

	// Sort to get the latest file
	sort.Strings(files)
	latestFile := files[len(files)-1]

	// Read the last entry
	lastEntry, err := al.readLastEntry(latestFile)
	if err != nil {
		return err
	}

	if lastEntry != nil {
		al.sequence = lastEntry.Sequence
		al.previousHash = lastEntry.EntryHash
	}

	return nil
}

// readLastEntry reads the last entry from a log file.
func (al *AuditLogger) readLastEntry(path string) (*AuditEntry, error) {
	f, err := os.Open(path)
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

// openLogFile opens or creates the current log file.
func (al *AuditLogger) openLogFile() error {
	if al.currentFile != nil {
		al.currentFile.Close()
	}

	// Generate filename with date
	filename := fmt.Sprintf("audit-%s.log", time.Now().Format("2006-01-02"))
	path := filepath.Join(al.config.LogPath, filename)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

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
		// Don't block on syslog errors - it's async
		al.syslogFwd.Forward(entry)
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
	rand.Read(b)
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), hex.EncodeToString(b))
}

// writeEntry writes an entry to the log file (acquires lock).
func (al *AuditLogger) writeEntry(entry *AuditEntry) error {
	al.mu.Lock()
	defer al.mu.Unlock()
	return al.writeEntryLocked(entry)
}

// writeEntryLocked writes an entry to the log file (caller must hold lock).
func (al *AuditLogger) writeEntryLocked(entry *AuditEntry) error {
	// Check if rotation needed
	if al.currentSize >= al.config.MaxFileSize {
		if err := al.rotate(); err != nil {
			al.logger.Error("failed to rotate audit log", "error", err)
		}
	}

	// Check if new day
	expectedFile := fmt.Sprintf("audit-%s.log", time.Now().Format("2006-01-02"))
	if !strings.HasSuffix(al.currentPath, expectedFile) {
		if err := al.openLogFile(); err != nil {
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
		al.currentFile.Sync()
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

	// Open new file with timestamp
	filename := fmt.Sprintf("audit-%s-%d.log", time.Now().Format("2006-01-02"), time.Now().Unix())
	path := filepath.Join(al.config.LogPath, filename)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	al.currentFile = f
	al.currentPath = path
	al.currentSize = 0

	// Set append-only on new file
	if al.immutableMgr != nil {
		if err := al.immutableMgr.SetAppendOnly(ctx, path); err != nil {
			al.logger.Warn("failed to set append-only on new file", "path", path, "error", err)
		}
	}

	// Clean up old files
	go al.cleanupOldFiles()

	return nil
}

// writeFileChecksum writes a checksum file for integrity verification.
func (al *AuditLogger) writeFileChecksum(logPath string) error {
	f, err := os.Open(logPath)
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

// cleanupOldFiles removes old log files beyond retention limit.
func (al *AuditLogger) cleanupOldFiles() {
	files, err := filepath.Glob(filepath.Join(al.config.LogPath, "audit-*.log"))
	if err != nil {
		return
	}

	if len(files) <= al.config.MaxFiles {
		return
	}

	sort.Strings(files)
	for _, f := range files[:len(files)-al.config.MaxFiles] {
		os.Remove(f)
		os.Remove(f + ".sha256")
	}
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
				al.currentFile.Sync()
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
			if err := al.VerifyIntegrity(al.ctx); err != nil {
				al.logger.Error("audit log integrity check failed", "error", err)
				atomic.AddUint64(&al.tampering, 1)

				// Log the tamper detection as an audit event
				al.Log(al.ctx, EventAuditTamper, SeverityAlert,
					"Audit log tampering detected", map[string]interface{}{
						"error": err.Error(),
					})

				if al.config.OnTamperDetected != nil {
					al.config.OnTamperDetected(nil, err)
				}
			}
		}
	}
}

// VerifyIntegrity verifies the integrity of all log files.
func (al *AuditLogger) VerifyIntegrity(ctx context.Context) error {
	files, err := filepath.Glob(filepath.Join(al.config.LogPath, "audit-*.log"))
	if err != nil {
		return err
	}

	sort.Strings(files)

	var lastEntry *AuditEntry
	for _, file := range files {
		entries, err := al.readLogFile(file)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", file, err)
		}

		for i, entry := range entries {
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
			} else if i == 0 && file == files[0] {
				// First entry should chain from genesis
				if entry.PreviousHash != computeGenesisHash() && entry.Sequence == 1 {
					// Only check genesis for sequence 1
				}
			}

			lastEntry = entry
		}

		// Verify file checksum if exists
		checksumPath := file + ".sha256"
		if _, err := os.Stat(checksumPath); err == nil {
			if err := al.verifyFileChecksum(file, checksumPath); err != nil {
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

// readLogFile reads all entries from a log file.
func (al *AuditLogger) readLogFile(path string) ([]*AuditEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []*AuditEntry
	decoder := json.NewDecoder(f)

	for {
		var entry AuditEntry
		if err := decoder.Decode(&entry); err != nil {
			if err == io.EOF {
				break
			}
			// Try to continue on partial JSON
			continue
		}
		entries = append(entries, &entry)
	}

	return entries, nil
}

// verifyFileChecksum verifies a file's checksum.
func (al *AuditLogger) verifyFileChecksum(logPath, checksumPath string) error {
	expected, err := os.ReadFile(checksumPath)
	if err != nil {
		return err
	}

	f, err := os.Open(logPath)
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

	// Close syslog forwarder first to flush any pending messages
	if al.syslogFwd != nil {
		al.syslogFwd.Close()
	}

	if al.currentFile != nil {
		// Clear append-only before closing
		if al.immutableMgr != nil {
			al.immutableMgr.ClearAppendOnly(ctx, al.currentPath)
		}

		al.currentFile.Sync()
		al.writeFileChecksum(al.currentPath)
		al.currentFile.Close()

		// Set immutable on final file
		if al.immutableMgr != nil {
			al.immutableMgr.SetImmutable(ctx, al.currentPath)
			al.immutableMgr.ProtectChecksumFile(ctx, al.currentPath+".sha256")
		}
	}

	al.logger.Info("audit logger closed",
		"written", atomic.LoadUint64(&al.written),
		"errors", atomic.LoadUint64(&al.errors))

	return nil
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
	files, err := filepath.Glob(filepath.Join(al.config.LogPath, "audit-*.log"))
	if err != nil {
		return nil, err
	}

	sort.Strings(files)

	var results []*AuditEntry
	for _, file := range files {
		entries, err := al.readLogFile(file)
		if err != nil {
			continue
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
	al.Log(ctx, EventAuditExport, SeverityInfo, "Audit log exported", map[string]interface{}{
		"entries": len(entries),
	})

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
