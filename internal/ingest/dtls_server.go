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

	"github.com/pion/dtls/v3"
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

	// MaxConnections caps the number of concurrent DTLS connections,
	// including those still in the handshake. Every new source address that
	// sends a handshake record gets a connection that lives for up to
	// ConnectionTimeout, so without a cap a flood of (easily spoofed)
	// datagrams could hold an unbounded number of handshakes open. Zero or a
	// negative value selects the default.
	MaxConnections int

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
		MaxConnections:    1000,
		IdleTimeout:       5 * time.Minute,
		AllowInsecure:     false,
		RequireClientCert: false,
	}
}

// DTLSServerMetrics holds metrics for the DTLS server.
type DTLSServerMetrics struct {
	Connections   uint64
	Handshakes    uint64
	HandshakeErrs uint64
	Received      uint64
	Parsed        uint64
	Normalized    uint64
	Queued        uint64
	// Errors counts every dropped message; the fields below break it down.
	Errors uint64
	// ParseErrors counts messages that are not valid CEF.
	ParseErrors uint64
	// ValidationErrors counts events that failed normalization or validation.
	ValidationErrors uint64
	InsecureWarned   bool

	// RejectedConnections counts connections closed at once because
	// MaxConnections connections were already open.
	RejectedConnections uint64
}

// DTLSServer receives CEF messages over DTLS (secure UDP).
type DTLSServer struct {
	config     DTLSServerConfig
	listener   net.Listener
	parser     *cef.Parser
	normalizer *cef.Normalizer
	validator  *schema.Validator
	queue      *queue.RingBuffer
	logger     *slog.Logger
	rejects    *cef.RejectLogger

	// For plain UDP fallback (insecure)
	udpConn *net.UDPConn

	wg       sync.WaitGroup
	done     chan struct{}
	cancel   context.CancelFunc // cancels the context the server runs with
	stopOnce sync.Once

	// Channel management for safe closing
	messagesClosed sync.Once

	// Open DTLS connections, closed on shutdown so that handlers blocked in
	// Read return at once instead of waiting for IdleTimeout.
	connsMu sync.Mutex
	conns   map[net.Conn]struct{}
	closing bool

	// Metrics
	connections      uint64
	handshakes       uint64
	handshakeErrs    uint64
	rejectedConns    uint64
	received         uint64
	parsed           uint64
	normalized       uint64
	queued           uint64
	errors           uint64
	parseErrors      uint64
	validationErrors uint64
	insecureWarned   atomic.Bool
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

	// Validate configuration
	if !cfg.AllowInsecure {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, ErrDTLSCertRequired
		}
	}

	if cfg.RequireClientCert && cfg.CAFile == "" {
		return nil, ErrDTLSClientCertRequired
	}

	// Zero values would disable the server in surprising ways (no workers,
	// an immediate handshake or idle timeout), so fall back to the defaults.
	defaults := DefaultDTLSServerConfig()
	if cfg.Workers <= 0 {
		cfg.Workers = defaults.Workers
	}
	if cfg.MaxMessageSize <= 0 {
		cfg.MaxMessageSize = defaults.MaxMessageSize
	}
	if cfg.ConnectionTimeout <= 0 {
		cfg.ConnectionTimeout = defaults.ConnectionTimeout
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaults.IdleTimeout
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = defaults.MaxConnections
	}

	return &DTLSServer{
		config:     cfg,
		parser:     parser,
		normalizer: normalizer,
		validator:  validator,
		queue:      q,
		logger:     logger,
		rejects:    cef.NewRejectLogger(logger, "dtls", cef.DefaultRejectLogInterval),
		done:       make(chan struct{}),
		conns:      make(map[net.Conn]struct{}),
	}, nil
}

// Start starts the DTLS server. The server runs until Stop is called or ctx
// is cancelled; Stop must be called in either case to release resources.
func (s *DTLSServer) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	var err error
	// Check if we're running insecure
	if s.config.AllowInsecure && (s.config.CertFile == "" || s.config.KeyFile == "") {
		err = s.startInsecure(ctx)
	} else {
		err = s.startSecure(ctx)
	}
	if err != nil {
		cancel()
	}
	return err
}

// startSecure starts the server with DTLS encryption.
func (s *DTLSServer) startSecure(ctx context.Context) error {
	// Load certificate
	cert, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load DTLS certificate: %w", err)
	}

	// Build DTLS options. The handshake timeout (ConnectionTimeout) is
	// applied per connection in handleConnection.
	opts := []dtls.ServerOption{
		dtls.WithCertificates(cert),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
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

		opts = append(opts,
			dtls.WithClientCAs(caPool),
			dtls.WithClientAuth(dtls.RequireAndVerifyClientCert),
		)
	}

	// Resolve address
	addr, err := net.ResolveUDPAddr("udp", s.config.Address)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	// Create DTLS listener
	listener, err := dtls.ListenWithOptions("udp", addr, opts...)
	if err != nil {
		return fmt.Errorf("failed to start DTLS listener: %w", err)
	}

	s.listener = listener

	s.logger.Info("DTLS server started",
		"address", s.config.Address,
		"mutual_tls", s.config.RequireClientCert,
	)

	// The DTLS listener has no accept deadline, so close it on shutdown to
	// unblock Accept.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		listener.Close()
	}()

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
	s.insecureWarned.Store(true)

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

	// Safe close function using sync.Once
	closeMessages := func() {
		s.messagesClosed.Do(func() {
			close(messages)
		})
	}

	for i := 0; i < s.config.Workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx, messages, i)
	}

	s.wg.Add(1)
	go func() {
		s.insecureReceiver(ctx, messages)
		closeMessages()
	}()

	return nil
}

type dtlsMessage struct {
	data     []byte
	sourceIP string
	secure   bool
}

// acceptLoop accepts DTLS connections until the listener is closed.
func (s *DTLSServer) acceptLoop(ctx context.Context) {
	defer s.wg.Done()

	messages := make(chan dtlsMessage, s.config.Workers*100)

	// Start workers; they exit once messages is closed and drained.
	for i := 0; i < s.config.Workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx, messages, i)
	}

	// Connection handlers send on messages, so it may only be closed after
	// every handler has returned.
	var handlers sync.WaitGroup
	defer func() {
		s.closeConns()
		handlers.Wait()
		s.messagesClosed.Do(func() {
			close(messages)
		})
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Debug("DTLS accept error", "error", err)
			// Avoid spinning if the listener keeps failing.
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}

		if err := s.trackConn(conn); err != nil {
			conn.Close()
			if errors.Is(err, errDTLSConnLimit) {
				atomic.AddUint64(&s.rejectedConns, 1)
				s.rejects.Reject("connection_limit", err, dtlsSourceIP(conn.RemoteAddr()), "")
				continue
			}
			return // shutting down
		}
		atomic.AddUint64(&s.connections, 1)

		handlers.Add(1)
		go func() {
			defer handlers.Done()
			s.handleConnection(ctx, conn, messages)
		}()
	}
}

// errDTLSConnLimit reports a connection refused because MaxConnections
// connections are already open.
var errDTLSConnLimit = errors.New("too many DTLS connections")

// errDTLSClosing reports a connection accepted while the server shuts down.
var errDTLSClosing = errors.New("DTLS server is shutting down")

// trackConn registers an accepted connection so that shutdown can close it.
// It fails once the server has started closing connections, or when
// MaxConnections connections are already open.
func (s *DTLSServer) trackConn(conn net.Conn) error {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if s.closing {
		return errDTLSClosing
	}
	if len(s.conns) >= s.config.MaxConnections {
		return errDTLSConnLimit
	}
	s.conns[conn] = struct{}{}
	return nil
}

// dtlsSourceIP returns the IP of a UDP peer address, or the address as a
// string for other address types.
func dtlsSourceIP(addr net.Addr) string {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return udpAddr.IP.String()
	}
	if addr == nil {
		return ""
	}
	return addr.String()
}

// untrackConn forgets and closes a connection.
func (s *DTLSServer) untrackConn(conn net.Conn) {
	s.connsMu.Lock()
	delete(s.conns, conn)
	s.connsMu.Unlock()
	conn.Close()
}

// closeConns closes every open connection and refuses new ones. A DTLS Close
// waits for an in-progress handshake, so the server context must already be
// cancelled; the connections are closed outside the lock.
func (s *DTLSServer) closeConns() {
	s.connsMu.Lock()
	s.closing = true
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.connsMu.Unlock()

	for _, conn := range conns {
		conn.Close()
	}
}

// handleConnection handles a single DTLS connection.
func (s *DTLSServer) handleConnection(ctx context.Context, conn net.Conn, messages chan<- dtlsMessage) {
	defer s.untrackConn(conn)

	sourceIP := dtlsSourceIP(conn.RemoteAddr())

	// Complete the handshake before reading so that it is bounded by
	// ConnectionTimeout and failures are counted.
	if dc, ok := conn.(*dtls.Conn); ok {
		hsCtx, cancel := context.WithTimeout(ctx, s.config.ConnectionTimeout)
		err := dc.HandshakeContext(hsCtx)
		cancel()
		if err != nil {
			atomic.AddUint64(&s.handshakeErrs, 1)
			if ctx.Err() == nil {
				s.rejects.Reject("handshake", err, sourceIP, "")
			}
			return
		}
	}
	atomic.AddUint64(&s.handshakes, 1)

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

		// Set read deadline. Without it the idle timeout cannot be enforced,
		// so drop the connection rather than block on it indefinitely.
		if err := conn.SetReadDeadline(time.Now().Add(s.config.IdleTimeout)); err != nil {
			s.logger.Debug("failed to set DTLS read deadline", "error", err, "remote", sourceIP)
			return
		}

		n, err := conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.logger.Debug("DTLS connection idle timeout", "remote", sourceIP)
				return
			}
			if ctx.Err() == nil {
				s.logger.Debug("DTLS read error", "error", err, "remote", sourceIP)
			}
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
			s.rejects.Reject("queue", errMessageChannelFull, sourceIP, "")
		}
	}
}

// insecureReceiver receives messages on plain UDP.
func (s *DTLSServer) insecureReceiver(ctx context.Context, messages chan<- dtlsMessage) {
	defer s.wg.Done()
	// Channel closing is handled by the caller via sync.Once

	buffer := make([]byte, s.config.MaxMessageSize)

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		default:
		}

		if err := s.udpConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			// The read below surfaces the underlying socket failure.
			s.logger.Debug("failed to set UDP read deadline", "error", err)
		}

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
			s.rejects.Reject("queue", errMessageChannelFull, remoteAddr.IP.String(), "")
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
	raw := string(msg.data)

	// Parse CEF
	cefEvent, err := s.parser.Parse(raw)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		atomic.AddUint64(&s.parseErrors, 1)
		s.rejects.Reject("parse", err, msg.sourceIP, raw)
		return
	}
	atomic.AddUint64(&s.parsed, 1)

	// Normalize
	event, err := s.normalizer.Normalize(cefEvent, msg.sourceIP)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		atomic.AddUint64(&s.validationErrors, 1)
		s.rejects.Reject("normalize", err, msg.sourceIP, raw)
		return
	}
	atomic.AddUint64(&s.normalized, 1)

	// Validate
	if err := s.validator.Validate(event); err != nil {
		atomic.AddUint64(&s.errors, 1)
		atomic.AddUint64(&s.validationErrors, 1)
		s.rejects.Reject("validate", err, msg.sourceIP, raw)
		return
	}

	// Queue
	if err := s.queue.Push(event); err != nil {
		atomic.AddUint64(&s.errors, 1)
		s.rejects.Reject("queue", err, msg.sourceIP, raw)
		return
	}

	atomic.AddUint64(&s.queued, 1)
}

// Stop stops the DTLS server gracefully: it stops accepting, closes open
// connections and waits for queued messages to be processed. It is safe to
// call more than once.
func (s *DTLSServer) Stop() {
	s.stopOnce.Do(func() {
		close(s.done)
		if s.cancel != nil {
			s.cancel()
		}

		if s.listener != nil {
			s.listener.Close()
		}
		if s.udpConn != nil {
			s.udpConn.Close()
		}
		s.closeConns()

		s.wg.Wait()

		s.logger.Info("DTLS server stopped",
			"connections", atomic.LoadUint64(&s.connections),
			"handshakes", atomic.LoadUint64(&s.handshakes),
			"handshake_errors", atomic.LoadUint64(&s.handshakeErrs),
			"rejected_connections", atomic.LoadUint64(&s.rejectedConns),
			"received", atomic.LoadUint64(&s.received),
			"queued", atomic.LoadUint64(&s.queued),
			"errors", atomic.LoadUint64(&s.errors),
			"parse_errors", atomic.LoadUint64(&s.parseErrors),
			"validation_errors", atomic.LoadUint64(&s.validationErrors),
		)
	})
}

// Metrics returns the current server metrics.
func (s *DTLSServer) Metrics() DTLSServerMetrics {
	return DTLSServerMetrics{
		Connections:         atomic.LoadUint64(&s.connections),
		Handshakes:          atomic.LoadUint64(&s.handshakes),
		HandshakeErrs:       atomic.LoadUint64(&s.handshakeErrs),
		RejectedConnections: atomic.LoadUint64(&s.rejectedConns),
		Received:            atomic.LoadUint64(&s.received),
		Parsed:              atomic.LoadUint64(&s.parsed),
		Normalized:          atomic.LoadUint64(&s.normalized),
		Queued:              atomic.LoadUint64(&s.queued),
		Errors:              atomic.LoadUint64(&s.errors),
		ParseErrors:         atomic.LoadUint64(&s.parseErrors),
		ValidationErrors:    atomic.LoadUint64(&s.validationErrors),
		InsecureWarned:      s.insecureWarned.Load(),
	}
}

// IsSecure returns true if the server is running with DTLS encryption.
func (s *DTLSServer) IsSecure() bool {
	return s.listener != nil && s.udpConn == nil
}
