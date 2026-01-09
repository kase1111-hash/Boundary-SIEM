// Package ingest provides secure ingestion servers for CEF events.
package ingest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"boundary-siem/internal/ingest/cef"
	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"

	"github.com/pion/dtls/v2"
)

// Common errors for DTLS server.
var (
	ErrDTLSCertRequired       = errors.New("DTLS requires certificate and key")
	ErrDTLSClientCertRequired = errors.New("mutual TLS requires CA certificate")
)

// DTLSServerConfig holds configuration for the DTLS server.
type DTLSServerConfig struct {
	// Address to listen on (e.g., ":5516")
	Address string

	// Certificate and key for DTLS
	CertFile string
	KeyFile  string

	// Optional: CA certificate for mutual TLS (client certificate validation)
	CAFile string

	// RequireClientCert enforces mutual TLS
	RequireClientCert bool

	// Workers for message processing
	Workers int

	// MaxMessageSize is the maximum UDP datagram size
	MaxMessageSize int

	// ConnectionTimeout is the timeout for DTLS handshake
	ConnectionTimeout time.Duration

	// IdleTimeout is the timeout for idle connections
	IdleTimeout time.Duration

	// AllowInsecure allows fallback to plain UDP (NOT RECOMMENDED)
	// When true, logs a security warning
	AllowInsecure bool
}

// DefaultDTLSServerConfig returns secure default configuration.
func DefaultDTLSServerConfig() DTLSServerConfig {
	return DTLSServerConfig{
		Address:           ":5516",
		Workers:           8,
		MaxMessageSize:    65535,
		ConnectionTimeout: 30 * time.Second,
		IdleTimeout:       5 * time.Minute,
		AllowInsecure:     false,
		RequireClientCert: false,
	}
}

// DTLSServerMetrics holds metrics for the DTLS server.
type DTLSServerMetrics struct {
	Connections    uint64
	Handshakes     uint64
	HandshakeErrs  uint64
	Received       uint64
	Parsed         uint64
	Normalized     uint64
	Queued         uint64
	Errors         uint64
	InsecureWarned bool
}

// DTLSServer receives CEF messages over DTLS (secure UDP).
type DTLSServer struct {
	config     DTLSServerConfig
	listener   net.Listener
	dtlsConfig *dtls.Config
	parser     *cef.Parser
	normalizer *cef.Normalizer
	validator  *schema.Validator
	queue      *queue.RingBuffer
	logger     *slog.Logger

	// For plain UDP fallback (insecure)
	udpConn *net.UDPConn

	wg   sync.WaitGroup
	done chan struct{}

	// Metrics
	connections    uint64
	handshakes     uint64
	handshakeErrs  uint64
	received       uint64
	parsed         uint64
	normalized     uint64
	queued         uint64
	errors         uint64
	insecureWarned bool
}

// NewDTLSServer creates a new DTLS server for secure CEF ingestion.
func NewDTLSServer(
	cfg DTLSServerConfig,
	parser *cef.Parser,
	normalizer *cef.Normalizer,
	validator *schema.Validator,
	q *queue.RingBuffer,
	logger *slog.Logger,
) (*DTLSServer, error) {
	if logger == nil {
		logger = slog.Default()
	}

	s := &DTLSServer{
		config:     cfg,
		parser:     parser,
		normalizer: normalizer,
		validator:  validator,
		queue:      q,
		logger:     logger,
		done:       make(chan struct{}),
	}

	// Validate configuration
	if !cfg.AllowInsecure {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, ErrDTLSCertRequired
		}
	}

	if cfg.RequireClientCert && cfg.CAFile == "" {
		return nil, ErrDTLSClientCertRequired
	}

	return s, nil
}

// Start starts the DTLS server.
func (s *DTLSServer) Start(ctx context.Context) error {
	// Check if we're running insecure
	if s.config.AllowInsecure && (s.config.CertFile == "" || s.config.KeyFile == "") {
		return s.startInsecure(ctx)
	}

	return s.startSecure(ctx)
}

// startSecure starts the server with DTLS encryption.
func (s *DTLSServer) startSecure(ctx context.Context) error {
	// Load certificate
	cert, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load DTLS certificate: %w", err)
	}

	// Build DTLS config
	dtlsConfig := &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(ctx, s.config.ConnectionTimeout)
		},
	}

	// Load CA for mutual TLS
	if s.config.RequireClientCert {
		caData, err := os.ReadFile(s.config.CAFile)
		if err != nil {
			return fmt.Errorf("failed to load CA certificate: %w", err)
		}

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caData) {
			return fmt.Errorf("failed to parse CA certificate")
		}

		dtlsConfig.ClientCAs = caPool
		dtlsConfig.ClientAuth = dtls.RequireAndVerifyClientCert
	}

	s.dtlsConfig = dtlsConfig

	// Resolve address
	addr, err := net.ResolveUDPAddr("udp", s.config.Address)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	// Create DTLS listener
	listener, err := dtls.Listen("udp", addr, dtlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start DTLS listener: %w", err)
	}

	s.listener = listener

	s.logger.Info("DTLS server started",
		"address", s.config.Address,
		"mutual_tls", s.config.RequireClientCert,
	)

	// Start accept loop
	s.wg.Add(1)
	go s.acceptLoop(ctx)

	return nil
}

// startInsecure starts the server in plain UDP mode (NOT RECOMMENDED).
func (s *DTLSServer) startInsecure(ctx context.Context) error {
	// Log security warning
	s.logger.Warn("SECURITY WARNING: Starting UDP server WITHOUT encryption",
		"address", s.config.Address,
		"recommendation", "Use DTLS with certificates for production",
	)
	s.logger.Warn("SECURITY WARNING: CEF events may contain sensitive data and will be transmitted in cleartext")
	s.insecureWarned = true

	addr, err := net.ResolveUDPAddr("udp", s.config.Address)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start UDP listener: %w", err)
	}

	s.udpConn = conn

	s.logger.Info("UDP server started (INSECURE)",
		"address", s.config.Address,
	)

	// Start receiver for plain UDP
	messages := make(chan dtlsMessage, s.config.Workers*100)

	for i := 0; i < s.config.Workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx, messages, i)
	}

	s.wg.Add(1)
	go s.insecureReceiver(ctx, messages)

	return nil
}

type dtlsMessage struct {
	data     []byte
	sourceIP string
	secure   bool
}

// acceptLoop accepts DTLS connections.
func (s *DTLSServer) acceptLoop(ctx context.Context) {
	defer s.wg.Done()

	messages := make(chan dtlsMessage, s.config.Workers*100)

	// Start workers
	for i := 0; i < s.config.Workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx, messages, i)
	}

	for {
		select {
		case <-ctx.Done():
			close(messages)
			return
		case <-s.done:
			close(messages)
			return
		default:
		}

		// Accept with deadline
		if dl, ok := s.listener.(interface{ SetDeadline(time.Time) error }); ok {
			dl.SetDeadline(time.Now().Add(100 * time.Millisecond))
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.done:
				return
			default:
				s.logger.Debug("DTLS accept error", "error", err)
				atomic.AddUint64(&s.handshakeErrs, 1)
				continue
			}
		}

		atomic.AddUint64(&s.connections, 1)
		atomic.AddUint64(&s.handshakes, 1)

		s.wg.Add(1)
		go s.handleConnection(ctx, conn, messages)
	}
}

// handleConnection handles a single DTLS connection.
func (s *DTLSServer) handleConnection(ctx context.Context, conn net.Conn, messages chan<- dtlsMessage) {
	defer s.wg.Done()
	defer conn.Close()

	var sourceIP string
	if addr := conn.RemoteAddr(); addr != nil {
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			sourceIP = udpAddr.IP.String()
		} else {
			sourceIP = addr.String()
		}
	}

	s.logger.Debug("new DTLS connection",
		"remote", conn.RemoteAddr(),
	)

	buffer := make([]byte, s.config.MaxMessageSize)

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		default:
		}

		// Set read deadline
		conn.SetReadDeadline(time.Now().Add(s.config.IdleTimeout))

		n, err := conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.logger.Debug("DTLS connection idle timeout", "remote", sourceIP)
				return
			}
			s.logger.Debug("DTLS read error", "error", err, "remote", sourceIP)
			return
		}

		atomic.AddUint64(&s.received, 1)

		// Copy data
		data := make([]byte, n)
		copy(data, buffer[:n])

		select {
		case messages <- dtlsMessage{data: data, sourceIP: sourceIP, secure: true}:
		default:
			atomic.AddUint64(&s.errors, 1)
			s.logger.Debug("message channel full, dropping message")
		}
	}
}

// insecureReceiver receives messages on plain UDP.
func (s *DTLSServer) insecureReceiver(ctx context.Context, messages chan<- dtlsMessage) {
	defer s.wg.Done()
	defer close(messages)

	buffer := make([]byte, s.config.MaxMessageSize)

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		default:
		}

		s.udpConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		n, remoteAddr, err := s.udpConn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.done:
				return
			default:
				s.logger.Debug("UDP read error", "error", err)
				continue
			}
		}

		atomic.AddUint64(&s.received, 1)

		data := make([]byte, n)
		copy(data, buffer[:n])

		select {
		case messages <- dtlsMessage{data: data, sourceIP: remoteAddr.IP.String(), secure: false}:
		default:
			atomic.AddUint64(&s.errors, 1)
		}
	}
}

// worker processes messages.
func (s *DTLSServer) worker(ctx context.Context, messages <-chan dtlsMessage, workerID int) {
	defer s.wg.Done()

	for msg := range messages {
		s.processMessage(ctx, msg)
	}
}

// processMessage processes a single CEF message.
func (s *DTLSServer) processMessage(ctx context.Context, msg dtlsMessage) {
	// Parse CEF
	cefEvent, err := s.parser.Parse(string(msg.data))
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		s.logger.Debug("CEF parse error",
			"error", err,
			"source", msg.sourceIP,
			"secure", msg.secure,
		)
		return
	}
	atomic.AddUint64(&s.parsed, 1)

	// Normalize
	event, err := s.normalizer.Normalize(cefEvent, msg.sourceIP)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		s.logger.Debug("CEF normalize error",
			"error", err,
			"source", msg.sourceIP,
		)
		return
	}
	atomic.AddUint64(&s.normalized, 1)

	// Validate
	if err := s.validator.Validate(event); err != nil {
		atomic.AddUint64(&s.errors, 1)
		s.logger.Debug("CEF validation error",
			"error", err,
			"source", msg.sourceIP,
		)
		return
	}

	// Queue
	if err := s.queue.Push(event); err != nil {
		atomic.AddUint64(&s.errors, 1)
		return
	}

	atomic.AddUint64(&s.queued, 1)
}

// Stop stops the DTLS server gracefully.
func (s *DTLSServer) Stop() {
	close(s.done)

	if s.listener != nil {
		s.listener.Close()
	}
	if s.udpConn != nil {
		s.udpConn.Close()
	}

	s.wg.Wait()

	s.logger.Info("DTLS server stopped",
		"connections", atomic.LoadUint64(&s.connections),
		"handshakes", atomic.LoadUint64(&s.handshakes),
		"handshake_errors", atomic.LoadUint64(&s.handshakeErrs),
		"received", atomic.LoadUint64(&s.received),
		"queued", atomic.LoadUint64(&s.queued),
		"errors", atomic.LoadUint64(&s.errors),
	)
}

// Metrics returns the current server metrics.
func (s *DTLSServer) Metrics() DTLSServerMetrics {
	return DTLSServerMetrics{
		Connections:    atomic.LoadUint64(&s.connections),
		Handshakes:     atomic.LoadUint64(&s.handshakes),
		HandshakeErrs:  atomic.LoadUint64(&s.handshakeErrs),
		Received:       atomic.LoadUint64(&s.received),
		Parsed:         atomic.LoadUint64(&s.parsed),
		Normalized:     atomic.LoadUint64(&s.normalized),
		Queued:         atomic.LoadUint64(&s.queued),
		Errors:         atomic.LoadUint64(&s.errors),
		InsecureWarned: s.insecureWarned,
	}
}

// IsSecure returns true if the server is running with DTLS encryption.
func (s *DTLSServer) IsSecure() bool {
	return s.listener != nil && s.udpConn == nil
}
