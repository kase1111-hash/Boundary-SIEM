package ingest

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"boundary-siem/internal/ingest/cef"
	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
)

// TCPServerConfig holds configuration for the TCP server.
type TCPServerConfig struct {
	Address        string
	TLSEnabled     bool
	TLSCertFile    string
	TLSKeyFile     string
	MaxConnections int
	IdleTimeout    time.Duration
	MaxLineLength  int
}

// DefaultTCPServerConfig returns the default TCP server configuration.
func DefaultTCPServerConfig() TCPServerConfig {
	return TCPServerConfig{
		Address:        ":5515",
		TLSEnabled:     false,
		MaxConnections: 1000,
		IdleTimeout:    5 * time.Minute,
		MaxLineLength:  65535,
	}
}

// TCPServerMetrics holds metrics for the TCP server.
type TCPServerMetrics struct {
	Connections uint64
	Received    uint64
	Parsed      uint64
	Queued      uint64
	Errors      uint64
}

// TCPServer receives CEF messages over TCP.
type TCPServer struct {
	config     TCPServerConfig
	listener   net.Listener
	parser     *cef.Parser
	normalizer *cef.Normalizer
	validator  *schema.Validator
	queue      *queue.RingBuffer

	connCount int32
	wg        sync.WaitGroup
	done      chan struct{}

	// Metrics
	connections uint64
	received    uint64
	parsed      uint64
	queued      uint64
	errors      uint64
}

// NewTCPServer creates a new TCP server for CEF ingestion.
func NewTCPServer(
	cfg TCPServerConfig,
	parser *cef.Parser,
	normalizer *cef.Normalizer,
	validator *schema.Validator,
	q *queue.RingBuffer,
) *TCPServer {
	return &TCPServer{
		config:     cfg,
		parser:     parser,
		normalizer: normalizer,
		validator:  validator,
		queue:      q,
		done:       make(chan struct{}),
	}
}

// Start starts the TCP server.
func (s *TCPServer) Start(ctx context.Context) error {
	var listener net.Listener
	var err error

	if s.config.TLSEnabled {
		cert, err := tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile)
		if err != nil {
			return err
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		listener, err = tls.Listen("tcp", s.config.Address, tlsConfig)
		if err != nil {
			return err
		}
	} else {
		listener, err = net.Listen("tcp", s.config.Address)
		if err != nil {
			return err
		}
	}

	s.listener = listener

	slog.Info("TCP server started",
		"address", s.config.Address,
		"tls", s.config.TLSEnabled,
	)

	s.wg.Add(1)
	go s.acceptLoop(ctx)

	return nil
}

func (s *TCPServer) acceptLoop(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		default:
		}

		// Set accept deadline to allow periodic context checks
		if tcpListener, ok := s.listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(100 * time.Millisecond))
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
				slog.Debug("TCP accept error", "error", err)
				continue
			}
		}

		// Check connection limit
		if atomic.LoadInt32(&s.connCount) >= int32(s.config.MaxConnections) {
			slog.Warn("max connections reached, rejecting")
			conn.Close()
			continue
		}

		atomic.AddInt32(&s.connCount, 1)
		atomic.AddUint64(&s.connections, 1)

		s.wg.Add(1)
		go s.handleConnection(ctx, conn)
	}
}

func (s *TCPServer) handleConnection(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	defer atomic.AddInt32(&s.connCount, -1)
	defer conn.Close()

	var sourceIP string
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		sourceIP = tcpAddr.IP.String()
	} else {
		sourceIP = conn.RemoteAddr().String()
	}

	slog.Debug("new TCP connection", "remote", conn.RemoteAddr())

	reader := bufio.NewReaderSize(conn, s.config.MaxLineLength)

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

		// Read line (CEF messages are newline-delimited)
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return // Idle timeout
			}
			slog.Debug("TCP read error", "error", err)
			return
		}

		atomic.AddUint64(&s.received, 1)

		// Process message
		s.processMessage(ctx, line, sourceIP)
	}
}

func (s *TCPServer) processMessage(ctx context.Context, message string, sourceIP string) {
	// Parse CEF
	cefEvent, err := s.parser.Parse(message)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		slog.Debug("CEF parse error",
			"error", err,
			"source", sourceIP,
		)
		return
	}
	atomic.AddUint64(&s.parsed, 1)

	// Normalize
	event, err := s.normalizer.Normalize(cefEvent, sourceIP)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		slog.Debug("CEF normalize error",
			"error", err,
			"source", sourceIP,
		)
		return
	}

	// Validate
	if err := s.validator.Validate(event); err != nil {
		atomic.AddUint64(&s.errors, 1)
		slog.Debug("CEF validation error",
			"error", err,
			"source", sourceIP,
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

// Stop stops the TCP server gracefully.
func (s *TCPServer) Stop() {
	close(s.done)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	slog.Info("TCP server stopped",
		"connections", atomic.LoadUint64(&s.connections),
		"received", atomic.LoadUint64(&s.received),
		"queued", atomic.LoadUint64(&s.queued),
		"errors", atomic.LoadUint64(&s.errors),
	)
}

// Metrics returns the current server metrics.
func (s *TCPServer) Metrics() TCPServerMetrics {
	return TCPServerMetrics{
		Connections: atomic.LoadUint64(&s.connections),
		Received:    atomic.LoadUint64(&s.received),
		Parsed:      atomic.LoadUint64(&s.parsed),
		Queued:      atomic.LoadUint64(&s.queued),
		Errors:      atomic.LoadUint64(&s.errors),
	}
}

// ActiveConnections returns the number of currently active connections.
func (s *TCPServer) ActiveConnections() int {
	return int(atomic.LoadInt32(&s.connCount))
}
