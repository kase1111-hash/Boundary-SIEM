// Package audit provides tamper-evident audit logging for security events.
// This file implements remote syslog forwarding to external SIEM systems.
package audit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Syslog facility and severity constants (RFC 5424)
const (
	// Facilities
	FacilityKern     = 0
	FacilityUser     = 1
	FacilityMail     = 2
	FacilityDaemon   = 3
	FacilityAuth     = 4
	FacilitySyslog   = 5
	FacilityLpr      = 6
	FacilityNews     = 7
	FacilityUucp     = 8
	FacilityCron     = 9
	FacilityAuthpriv = 10
	FacilityFtp      = 11
	FacilityLocal0   = 16
	FacilityLocal1   = 17
	FacilityLocal2   = 18
	FacilityLocal3   = 19
	FacilityLocal4   = 20
	FacilityLocal5   = 21
	FacilityLocal6   = 22
	FacilityLocal7   = 23

	// Severities (RFC 5424)
	SyslogEmergency = 0
	SyslogAlert     = 1
	SyslogCritical  = 2
	SyslogError     = 3
	SyslogWarning   = 4
	SyslogNotice    = 5
	SyslogInfo      = 6
	SyslogDebug     = 7
)

// Common errors for syslog operations.
var (
	ErrSyslogNotConnected = errors.New("syslog client not connected")
	ErrSyslogBufferFull   = errors.New("syslog buffer full")
	ErrSyslogClosed       = errors.New("syslog client closed")
)

// SyslogProtocol represents the transport protocol.
type SyslogProtocol string

const (
	ProtocolUDP SyslogProtocol = "udp"
	ProtocolTCP SyslogProtocol = "tcp"
	ProtocolTLS SyslogProtocol = "tls"
)

// SyslogFormat represents the message format.
type SyslogFormat string

const (
	FormatRFC3164 SyslogFormat = "rfc3164" // BSD syslog
	FormatRFC5424 SyslogFormat = "rfc5424" // Modern syslog
	FormatCEF     SyslogFormat = "cef"     // ArcSight CEF
	FormatJSON    SyslogFormat = "json"    // JSON over syslog
)

// SyslogConfig configures the syslog forwarder.
type SyslogConfig struct {
	// Enabled controls whether remote syslog is active.
	Enabled bool

	// Addresses is a list of syslog server addresses (host:port).
	// Multiple addresses enable failover.
	Addresses []string

	// Protocol is the transport protocol (udp, tcp, tls).
	Protocol SyslogProtocol

	// Format is the message format (rfc3164, rfc5424, cef, json).
	Format SyslogFormat

	// Facility is the syslog facility (default: local0).
	Facility int

	// AppName is the application name in syslog messages.
	AppName string

	// TLS configuration for secure connections.
	TLSConfig *TLSSyslogConfig

	// BufferSize is the number of messages to buffer.
	BufferSize int

	// FlushInterval is how often to flush buffered messages.
	FlushInterval time.Duration

	// RetryInterval is how long to wait before retrying failed sends.
	RetryInterval time.Duration

	// MaxRetries is the maximum number of retries per message.
	MaxRetries int

	// ConnectionTimeout for establishing connections.
	ConnectionTimeout time.Duration

	// WriteTimeout for write operations.
	WriteTimeout time.Duration

	// KeepAlive interval for TCP connections.
	KeepAlive time.Duration

	// Logger for diagnostic output.
	Logger *slog.Logger
}

// TLSSyslogConfig holds TLS settings for syslog.
type TLSSyslogConfig struct {
	// CertFile is the path to the client certificate.
	CertFile string

	// KeyFile is the path to the client private key.
	KeyFile string

	// CAFile is the path to the CA certificate for server verification.
	CAFile string

	// InsecureSkipVerify disables server certificate verification.
	InsecureSkipVerify bool

	// ServerName for SNI.
	ServerName string
}

// DefaultSyslogConfig returns sensible defaults.
func DefaultSyslogConfig() *SyslogConfig {
	hostname, _ := os.Hostname()
	return &SyslogConfig{
		Enabled:           false,
		Protocol:          ProtocolTCP,
		Format:            FormatRFC5424,
		Facility:          FacilityLocal0,
		AppName:           "boundary-siem",
		BufferSize:        10000,
		FlushInterval:     1 * time.Second,
		RetryInterval:     5 * time.Second,
		MaxRetries:        3,
		ConnectionTimeout: 10 * time.Second,
		WriteTimeout:      5 * time.Second,
		KeepAlive:         30 * time.Second,
		Logger:            slog.Default(),
		Addresses:         []string{hostname + ":514"},
	}
}

// SyslogForwarder forwards audit entries to remote syslog servers.
type SyslogForwarder struct {
	mu     sync.RWMutex
	config *SyslogConfig
	logger *slog.Logger

	// Connection state
	conn         net.Conn
	currentAddr  string
	addrIndex    int
	connected    atomic.Bool
	reconnecting atomic.Bool

	// Message buffer
	buffer chan *AuditEntry
	closed atomic.Bool

	// Background processing
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Metrics
	sent       uint64
	dropped    uint64
	errors     uint64
	reconnects uint64
}

// NewSyslogForwarder creates a new syslog forwarder.
func NewSyslogForwarder(config *SyslogConfig) (*SyslogForwarder, error) {
	if config == nil {
		config = DefaultSyslogConfig()
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	if !config.Enabled {
		return nil, nil // Not enabled, return nil forwarder
	}

	if len(config.Addresses) == 0 {
		return nil, errors.New("no syslog addresses configured")
	}

	ctx, cancel := context.WithCancel(context.Background())

	sf := &SyslogForwarder{
		config: config,
		logger: config.Logger,
		buffer: make(chan *AuditEntry, config.BufferSize),
		ctx:    ctx,
		cancel: cancel,
	}

	// Initial connection
	if err := sf.connect(); err != nil {
		sf.logger.Warn("initial syslog connection failed, will retry", "error", err)
	}

	// Start background workers
	sf.wg.Add(2)
	go sf.sendWorker()
	go sf.reconnectWorker()

	sf.logger.Info("syslog forwarder initialized",
		"addresses", config.Addresses,
		"protocol", config.Protocol,
		"format", config.Format)

	return sf, nil
}

// connect establishes a connection to a syslog server.
func (sf *SyslogForwarder) connect() error {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	// Close existing connection
	if sf.conn != nil {
		sf.conn.Close()
		sf.conn = nil
	}

	// Try each address in order
	var lastErr error
	for i := 0; i < len(sf.config.Addresses); i++ {
		idx := (sf.addrIndex + i) % len(sf.config.Addresses)
		addr := sf.config.Addresses[idx]

		conn, err := sf.dialAddress(addr)
		if err != nil {
			lastErr = err
			sf.logger.Debug("syslog connection failed", "address", addr, "error", err)
			continue
		}

		sf.conn = conn
		sf.currentAddr = addr
		sf.addrIndex = idx
		sf.connected.Store(true)
		atomic.AddUint64(&sf.reconnects, 1)

		sf.logger.Info("syslog connected", "address", addr, "protocol", sf.config.Protocol)
		return nil
	}

	sf.connected.Store(false)
	return fmt.Errorf("failed to connect to any syslog server: %w", lastErr)
}

// dialAddress connects to a specific address.
func (sf *SyslogForwarder) dialAddress(addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(sf.ctx, sf.config.ConnectionTimeout)
	defer cancel()

	var dialer net.Dialer
	dialer.Timeout = sf.config.ConnectionTimeout
	dialer.KeepAlive = sf.config.KeepAlive

	switch sf.config.Protocol {
	case ProtocolUDP:
		return dialer.DialContext(ctx, "udp", addr)

	case ProtocolTCP:
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		return conn, nil

	case ProtocolTLS:
		tlsConfig, err := sf.buildTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("TLS config error: %w", err)
		}

		conn, err := tls.DialWithDialer(&dialer, "tcp", addr, tlsConfig)
		if err != nil {
			return nil, err
		}
		return conn, nil

	default:
		return nil, fmt.Errorf("unsupported protocol: %s", sf.config.Protocol)
	}
}

// buildTLSConfig creates TLS configuration.
func (sf *SyslogForwarder) buildTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if sf.config.TLSConfig != nil {
		cfg := sf.config.TLSConfig

		if cfg.InsecureSkipVerify {
			tlsConfig.InsecureSkipVerify = true
		}

		if cfg.ServerName != "" {
			tlsConfig.ServerName = cfg.ServerName
		}

		// Load client certificate
		if cfg.CertFile != "" && cfg.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		// Load CA certificate
		if cfg.CAFile != "" {
			caCert, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA certificate: %w", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, errors.New("failed to parse CA certificate")
			}
			tlsConfig.RootCAs = caCertPool
		}
	}

	return tlsConfig, nil
}

// Forward sends an audit entry to the syslog server.
func (sf *SyslogForwarder) Forward(entry *AuditEntry) error {
	if sf.closed.Load() {
		return ErrSyslogClosed
	}

	select {
	case sf.buffer <- entry:
		return nil
	default:
		atomic.AddUint64(&sf.dropped, 1)
		return ErrSyslogBufferFull
	}
}

// sendWorker processes the message buffer.
func (sf *SyslogForwarder) sendWorker() {
	defer sf.wg.Done()

	ticker := time.NewTicker(sf.config.FlushInterval)
	defer ticker.Stop()

	batch := make([]*AuditEntry, 0, 100)

	for {
		select {
		case <-sf.ctx.Done():
			// Drain remaining messages
			sf.drainBuffer(batch)
			return

		case entry := <-sf.buffer:
			batch = append(batch, entry)
			if len(batch) >= 100 {
				sf.sendBatch(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				sf.sendBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

// drainBuffer sends any remaining messages.
func (sf *SyslogForwarder) drainBuffer(batch []*AuditEntry) {
	// Collect remaining messages
	for {
		select {
		case entry := <-sf.buffer:
			batch = append(batch, entry)
		default:
			if len(batch) > 0 {
				sf.sendBatch(batch)
			}
			return
		}
	}
}

// sendBatch sends a batch of messages.
func (sf *SyslogForwarder) sendBatch(batch []*AuditEntry) {
	for _, entry := range batch {
		if err := sf.sendEntry(entry); err != nil {
			sf.logger.Warn("failed to send syslog message",
				"error", err,
				"entry_id", entry.ID)
			atomic.AddUint64(&sf.errors, 1)
		} else {
			atomic.AddUint64(&sf.sent, 1)
		}
	}
}

// sendEntry sends a single entry with retries.
func (sf *SyslogForwarder) sendEntry(entry *AuditEntry) error {
	message := sf.formatMessage(entry)

	for retry := 0; retry <= sf.config.MaxRetries; retry++ {
		if !sf.connected.Load() {
			// Wait for reconnection
			time.Sleep(sf.config.RetryInterval)
			continue
		}

		sf.mu.RLock()
		conn := sf.conn
		sf.mu.RUnlock()

		if conn == nil {
			time.Sleep(sf.config.RetryInterval)
			continue
		}

		// Set write deadline
		if sf.config.WriteTimeout > 0 {
			conn.SetWriteDeadline(time.Now().Add(sf.config.WriteTimeout))
		}

		_, err := conn.Write(message)
		if err == nil {
			return nil
		}

		// Connection error, trigger reconnect
		sf.connected.Store(false)
		sf.logger.Debug("syslog write failed, will reconnect", "error", err)

		if retry < sf.config.MaxRetries {
			time.Sleep(sf.config.RetryInterval)
		}
	}

	return errors.New("max retries exceeded")
}

// formatMessage formats an audit entry for syslog.
func (sf *SyslogForwarder) formatMessage(entry *AuditEntry) []byte {
	switch sf.config.Format {
	case FormatRFC3164:
		return sf.formatRFC3164(entry)
	case FormatRFC5424:
		return sf.formatRFC5424(entry)
	case FormatCEF:
		return sf.formatCEF(entry)
	case FormatJSON:
		return sf.formatJSON(entry)
	default:
		return sf.formatRFC5424(entry)
	}
}

// formatRFC3164 formats a BSD-style syslog message.
func (sf *SyslogForwarder) formatRFC3164(entry *AuditEntry) []byte {
	pri := sf.config.Facility*8 + sf.severityToSyslog(entry.Severity)
	timestamp := entry.Timestamp.Format("Jan _2 15:04:05")
	hostname := entry.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	msg := fmt.Sprintf("<%d>%s %s %s: [%s] %s",
		pri,
		timestamp,
		hostname,
		sf.config.AppName,
		entry.Type,
		entry.Message)

	return []byte(msg + "\n")
}

// formatRFC5424 formats a modern syslog message (RFC 5424).
func (sf *SyslogForwarder) formatRFC5424(entry *AuditEntry) []byte {
	pri := sf.config.Facility*8 + sf.severityToSyslog(entry.Severity)
	version := 1
	timestamp := entry.Timestamp.Format(time.RFC3339Nano)
	hostname := entry.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	appName := sf.config.AppName
	procID := fmt.Sprintf("%d", entry.ProcessID)
	msgID := string(entry.Type)

	// Structured data
	sd := sf.buildStructuredData(entry)

	msg := fmt.Sprintf("<%d>%d %s %s %s %s %s %s %s",
		pri,
		version,
		timestamp,
		hostname,
		appName,
		procID,
		msgID,
		sd,
		entry.Message)

	return []byte(msg + "\n")
}

// buildStructuredData creates RFC 5424 structured data.
func (sf *SyslogForwarder) buildStructuredData(entry *AuditEntry) string {
	// Build structured data elements
	parts := []string{}

	// Main audit data
	auditSD := fmt.Sprintf("[audit@boundary id=\"%s\" seq=\"%d\" hash=\"%s\"]",
		entry.ID,
		entry.Sequence,
		entry.EntryHash)
	parts = append(parts, auditSD)

	// Actor data if present
	if entry.Actor != "" {
		actorSD := fmt.Sprintf("[actor@boundary name=\"%s\" ip=\"%s\" type=\"%s\"]",
			escapeSDValue(entry.Actor),
			entry.ActorIP,
			entry.ActorType)
		parts = append(parts, actorSD)
	}

	// Target data if present
	if entry.Target != "" {
		targetSD := fmt.Sprintf("[target@boundary name=\"%s\" type=\"%s\"]",
			escapeSDValue(entry.Target),
			entry.TargetType)
		parts = append(parts, targetSD)
	}

	if len(parts) == 0 {
		return "-" // NILVALUE
	}

	return strings.Join(parts, "")
}

// formatCEF formats a CEF (Common Event Format) message.
func (sf *SyslogForwarder) formatCEF(entry *AuditEntry) []byte {
	// CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
	pri := sf.config.Facility*8 + sf.severityToSyslog(entry.Severity)
	timestamp := entry.Timestamp.Format(time.RFC3339)

	hostname := entry.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	severity := sf.cefSeverity(entry.Severity)
	signatureID := string(entry.Type)
	name := entry.Message
	if len(name) > 128 {
		name = name[:128]
	}

	// Build extension fields
	ext := sf.buildCEFExtension(entry)

	cef := fmt.Sprintf("CEF:0|Boundary|SIEM|1.0|%s|%s|%d|%s",
		escapeFieldCEF(signatureID),
		escapeFieldCEF(name),
		severity,
		ext)

	// Wrap in syslog format
	msg := fmt.Sprintf("<%d>%s %s %s",
		pri,
		timestamp,
		hostname,
		cef)

	return []byte(msg + "\n")
}

// buildCEFExtension builds CEF extension fields.
func (sf *SyslogForwarder) buildCEFExtension(entry *AuditEntry) string {
	parts := []string{}

	// Standard CEF fields
	parts = append(parts, fmt.Sprintf("rt=%d", entry.Timestamp.UnixMilli()))
	parts = append(parts, fmt.Sprintf("dvchost=%s", entry.Hostname))
	parts = append(parts, fmt.Sprintf("dvcpid=%d", entry.ProcessID))

	// Audit-specific fields
	parts = append(parts, fmt.Sprintf("cs1=%s", entry.ID))
	parts = append(parts, "cs1Label=AuditID")
	parts = append(parts, fmt.Sprintf("cn1=%d", entry.Sequence))
	parts = append(parts, "cn1Label=Sequence")
	parts = append(parts, fmt.Sprintf("cs2=%s", entry.EntryHash))
	parts = append(parts, "cs2Label=EntryHash")

	// Actor fields
	if entry.Actor != "" {
		parts = append(parts, fmt.Sprintf("suser=%s", escapeFieldCEF(entry.Actor)))
	}
	if entry.ActorIP != "" {
		parts = append(parts, fmt.Sprintf("src=%s", entry.ActorIP))
	}

	// Target fields
	if entry.Target != "" {
		parts = append(parts, fmt.Sprintf("duser=%s", escapeFieldCEF(entry.Target)))
	}

	// Outcome
	if entry.Success {
		parts = append(parts, "outcome=Success")
	} else {
		parts = append(parts, "outcome=Failure")
		if entry.Error != "" {
			parts = append(parts, fmt.Sprintf("reason=%s", escapeFieldCEF(entry.Error)))
		}
	}

	return strings.Join(parts, " ")
}

// formatJSON formats entry as JSON wrapped in syslog.
func (sf *SyslogForwarder) formatJSON(entry *AuditEntry) []byte {
	pri := sf.config.Facility*8 + sf.severityToSyslog(entry.Severity)
	timestamp := entry.Timestamp.Format(time.RFC3339)

	hostname := entry.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	// Marshal entry to JSON
	jsonData, err := json.Marshal(entry)
	if err != nil {
		jsonData = []byte(fmt.Sprintf(`{"error":"marshal failed","id":"%s"}`, entry.ID))
	}

	msg := fmt.Sprintf("<%d>%s %s %s: %s",
		pri,
		timestamp,
		hostname,
		sf.config.AppName,
		string(jsonData))

	return []byte(msg + "\n")
}

// severityToSyslog converts our severity to syslog severity.
func (sf *SyslogForwarder) severityToSyslog(sev Severity) int {
	switch sev {
	case SeverityAlert:
		return SyslogAlert
	case SeverityCritical:
		return SyslogCritical
	case SeverityError:
		return SyslogError
	case SeverityWarning:
		return SyslogWarning
	case SeverityInfo:
		return SyslogInfo
	default:
		return SyslogNotice
	}
}

// cefSeverity converts our severity to CEF severity (0-10).
func (sf *SyslogForwarder) cefSeverity(sev Severity) int {
	switch sev {
	case SeverityAlert:
		return 10
	case SeverityCritical:
		return 8
	case SeverityError:
		return 6
	case SeverityWarning:
		return 4
	case SeverityInfo:
		return 2
	default:
		return 1
	}
}

// reconnectWorker handles reconnection attempts.
func (sf *SyslogForwarder) reconnectWorker() {
	defer sf.wg.Done()

	ticker := time.NewTicker(sf.config.RetryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sf.ctx.Done():
			return
		case <-ticker.C:
			if !sf.connected.Load() && !sf.reconnecting.Load() {
				sf.reconnecting.Store(true)
				if err := sf.connect(); err != nil {
					sf.logger.Debug("syslog reconnection failed", "error", err)
				}
				sf.reconnecting.Store(false)
			}
		}
	}
}

// Close closes the syslog forwarder.
func (sf *SyslogForwarder) Close() error {
	if sf.closed.Swap(true) {
		return nil
	}

	sf.cancel()
	sf.wg.Wait()

	sf.mu.Lock()
	defer sf.mu.Unlock()

	if sf.conn != nil {
		sf.conn.Close()
	}

	sf.logger.Info("syslog forwarder closed",
		"sent", atomic.LoadUint64(&sf.sent),
		"dropped", atomic.LoadUint64(&sf.dropped),
		"errors", atomic.LoadUint64(&sf.errors))

	return nil
}

// Metrics returns syslog forwarder metrics.
func (sf *SyslogForwarder) Metrics() SyslogMetrics {
	return SyslogMetrics{
		Sent:       atomic.LoadUint64(&sf.sent),
		Dropped:    atomic.LoadUint64(&sf.dropped),
		Errors:     atomic.LoadUint64(&sf.errors),
		Reconnects: atomic.LoadUint64(&sf.reconnects),
		Connected:  sf.connected.Load(),
		Address:    sf.currentAddr,
	}
}

// SyslogMetrics contains syslog forwarder statistics.
type SyslogMetrics struct {
	Sent       uint64
	Dropped    uint64
	Errors     uint64
	Reconnects uint64
	Connected  bool
	Address    string
}

// IsConnected returns whether the forwarder is connected.
func (sf *SyslogForwarder) IsConnected() bool {
	return sf.connected.Load()
}

// Helper functions

// escapeSDValue escapes a value for RFC 5424 structured data.
func escapeSDValue(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "]", "\\]")
	return s
}

// escapeFieldCEF escapes a CEF field value.
func escapeFieldCEF(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "=", "\\=")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}

// Integration helper for AuditLogger

// WithRemoteSyslog enables remote syslog forwarding on an AuditLogger.
func WithRemoteSyslog(al *AuditLogger, config *SyslogConfig) error {
	if config == nil {
		config = DefaultSyslogConfig()
	}
	config.Logger = al.logger

	sf, err := NewSyslogForwarder(config)
	if err != nil {
		return err
	}

	if sf == nil {
		// Not enabled
		return nil
	}

	al.mu.Lock()
	al.syslogFwd = sf
	al.mu.Unlock()

	al.logger.Info("remote syslog forwarding enabled",
		"addresses", config.Addresses,
		"protocol", config.Protocol,
		"format", config.Format)

	return nil
}
