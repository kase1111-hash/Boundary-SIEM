package ingest

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"boundary-siem/internal/ingest/cef"
	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
)

// UDPServerConfig holds configuration for the UDP server.
type UDPServerConfig struct {
	Address        string
	BufferSize     int
	Workers        int
	MaxMessageSize int
}

// DefaultUDPServerConfig returns the default UDP server configuration.
func DefaultUDPServerConfig() UDPServerConfig {
	return UDPServerConfig{
		Address:        ":5514",
		BufferSize:     16 * 1024 * 1024, // 16MB
		Workers:        8,
		MaxMessageSize: 65535,
	}
}

// UDPServerMetrics holds metrics for the UDP server.
type UDPServerMetrics struct {
	Received   uint64
	Parsed     uint64
	Normalized uint64
	Queued     uint64
	Errors     uint64
}

// UDPServer receives CEF messages over UDP.
type UDPServer struct {
	config     UDPServerConfig
	conn       *net.UDPConn
	parser     *cef.Parser
	normalizer *cef.Normalizer
	validator  *schema.Validator
	queue      *queue.RingBuffer

	wg   sync.WaitGroup
	done chan struct{}

	// Metrics
	received   uint64
	parsed     uint64
	normalized uint64
	queued     uint64
	errors     uint64
}

// NewUDPServer creates a new UDP server for CEF ingestion.
func NewUDPServer(
	cfg UDPServerConfig,
	parser *cef.Parser,
	normalizer *cef.Normalizer,
	validator *schema.Validator,
	q *queue.RingBuffer,
) *UDPServer {
	return &UDPServer{
		config:     cfg,
		parser:     parser,
		normalizer: normalizer,
		validator:  validator,
		queue:      q,
		done:       make(chan struct{}),
	}
}

// Start starts the UDP server.
// DEPRECATED: Use DTLSServer for secure UDP ingestion.
// Plain UDP transmits CEF events in cleartext without encryption.
func (s *UDPServer) Start(ctx context.Context) error {
	// Security warning for plain UDP
	slog.Warn("SECURITY WARNING: Plain UDP server does not provide encryption",
		"address", s.config.Address,
		"recommendation", "Use DTLSServer or TCPServer with TLS for production",
	)
	slog.Warn("SECURITY WARNING: CEF events may contain sensitive security data")

	addr, err := net.ResolveUDPAddr("udp", s.config.Address)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	// Set read buffer size
	if err := conn.SetReadBuffer(s.config.BufferSize); err != nil {
		slog.Warn("failed to set UDP read buffer", "error", err)
	}
	s.conn = conn

	slog.Info("UDP server started (INSECURE - no encryption)", "address", s.config.Address)

	// Start worker goroutines
	messages := make(chan udpMessage, s.config.Workers*100)

	for i := 0; i < s.config.Workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx, messages, i)
	}

	// Start receiver
	s.wg.Add(1)
	go s.receiver(ctx, messages)

	return nil
}

type udpMessage struct {
	data     []byte
	sourceIP string
}

func (s *UDPServer) receiver(ctx context.Context, messages chan<- udpMessage) {
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

		// Set read deadline to allow periodic context checks
		s.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		n, remoteAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.done:
				return
			default:
				slog.Debug("UDP read error", "error", err)
				continue
			}
		}

		atomic.AddUint64(&s.received, 1)

		// Copy data to avoid buffer reuse issues
		data := make([]byte, n)
		copy(data, buffer[:n])

		select {
		case messages <- udpMessage{data: data, sourceIP: remoteAddr.IP.String()}:
		default:
			// Channel full, drop message
			atomic.AddUint64(&s.errors, 1)
			slog.Debug("UDP message channel full, dropping message")
		}
	}
}

func (s *UDPServer) worker(ctx context.Context, messages <-chan udpMessage, workerID int) {
	defer s.wg.Done()

	for msg := range messages {
		s.processMessage(ctx, msg)
	}
}

func (s *UDPServer) processMessage(ctx context.Context, msg udpMessage) {
	// Parse CEF
	cefEvent, err := s.parser.Parse(string(msg.data))
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		slog.Debug("CEF parse error",
			"error", err,
			"source", msg.sourceIP,
		)
		return
	}
	atomic.AddUint64(&s.parsed, 1)

	// Normalize to canonical schema
	event, err := s.normalizer.Normalize(cefEvent, msg.sourceIP)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		slog.Debug("CEF normalize error",
			"error", err,
			"source", msg.sourceIP,
		)
		return
	}
	atomic.AddUint64(&s.normalized, 1)

	// Validate
	if err := s.validator.Validate(event); err != nil {
		atomic.AddUint64(&s.errors, 1)
		slog.Debug("CEF validation error",
			"error", err,
			"source", msg.sourceIP,
		)
		return
	}

	// Queue for storage
	if err := s.queue.Push(event); err != nil {
		atomic.AddUint64(&s.errors, 1)
		slog.Debug("queue push error", "error", err)
		return
	}

	atomic.AddUint64(&s.queued, 1)
}

// Stop stops the UDP server gracefully.
func (s *UDPServer) Stop() {
	close(s.done)
	if s.conn != nil {
		s.conn.Close()
	}
	s.wg.Wait()
	slog.Info("UDP server stopped",
		"received", atomic.LoadUint64(&s.received),
		"queued", atomic.LoadUint64(&s.queued),
		"errors", atomic.LoadUint64(&s.errors),
	)
}

// Metrics returns the current server metrics.
func (s *UDPServer) Metrics() UDPServerMetrics {
	return UDPServerMetrics{
		Received:   atomic.LoadUint64(&s.received),
		Parsed:     atomic.LoadUint64(&s.parsed),
		Normalized: atomic.LoadUint64(&s.normalized),
		Queued:     atomic.LoadUint64(&s.queued),
		Errors:     atomic.LoadUint64(&s.errors),
	}
}
