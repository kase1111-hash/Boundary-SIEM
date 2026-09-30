package ingest

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
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
	// IdleTimeout closes a connection that sends nothing for this long.
	// Zero or a negative value selects the default.
	IdleTimeout time.Duration
	// MaxLineLength is the longest accepted line in bytes, excluding the
	// newline. Longer lines are discarded. Zero or a negative value selects
	// the default.
	MaxLineLength int
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
	// Errors counts every dropped message; the fields below break it down.
	Errors uint64
	// ParseErrors counts lines that are not valid CEF.
	ParseErrors uint64
	// ValidationErrors counts events that failed normalization or validation.
	ValidationErrors uint64
	// OversizedLines counts lines longer than MaxLineLength.
	OversizedLines uint64
}

// errLineTooLong reports a line longer than MaxLineLength. The line has been
// consumed up to and including its newline, so the stream stays in sync.
var errLineTooLong = errors.New("line exceeds maximum length")

// TCPServer receives CEF messages over TCP.
type TCPServer struct {
	config     TCPServerConfig
	listener   net.Listener
	parser     *cef.Parser
	normalizer *cef.Normalizer
	validator  *schema.Validator
	queue      *queue.RingBuffer
	rejects    *cef.RejectLogger

	connCount int64
	wg        sync.WaitGroup
	done      chan struct{}
	stopOnce  sync.Once

	// Open client connections, closed by Stop so that handlers blocked in
	// Read return at once instead of waiting for IdleTimeout.
	connsMu sync.Mutex
	conns   map[net.Conn]struct{}
	closing bool

	// Metrics
	connections      uint64
	received         uint64
	parsed           uint64
	queued           uint64
	errors           uint64
	parseErrors      uint64
	validationErrors uint64
	oversized        uint64
}

// NewTCPServer creates a new TCP server for CEF ingestion.
func NewTCPServer(
	cfg TCPServerConfig,
	parser *cef.Parser,
	normalizer *cef.Normalizer,
	validator *schema.Validator,
	q *queue.RingBuffer,
) *TCPServer {
	defaults := DefaultTCPServerConfig()
	if cfg.MaxLineLength <= 0 {
		cfg.MaxLineLength = defaults.MaxLineLength
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaults.IdleTimeout
	}

	return &TCPServer{
		config:     cfg,
		parser:     parser,
		normalizer: normalizer,
		validator:  validator,
		queue:      q,
		rejects:    cef.NewRejectLogger(nil, "tcp", cef.DefaultRejectLogInterval),
		done:       make(chan struct{}),
		conns:      make(map[net.Conn]struct{}),
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
			s.closeConns()
			return
		case <-s.done:
			return
		default:
		}

		// Set accept deadline to allow periodic context checks
		if tcpListener, ok := s.listener.(*net.TCPListener); ok {
			if err := tcpListener.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				// Accept below surfaces the underlying listener failure.
				slog.Debug("failed to set TCP accept deadline", "error", err)
			}
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
		if atomic.LoadInt64(&s.connCount) >= int64(s.config.MaxConnections) {
			slog.Warn("max connections reached, rejecting")
			conn.Close()
			continue
		}

		if !s.trackConn(conn) {
			conn.Close() // server is stopping
			continue
		}

		atomic.AddInt64(&s.connCount, 1)
		atomic.AddUint64(&s.connections, 1)

		s.wg.Add(1)
		go s.handleConnection(ctx, conn)
	}
}

// trackConn registers an accepted connection so that Stop can close it. It
// returns false once the server has started closing connections.
func (s *TCPServer) trackConn(conn net.Conn) bool {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if s.closing {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

// untrackConn forgets and closes a connection.
func (s *TCPServer) untrackConn(conn net.Conn) {
	s.connsMu.Lock()
	delete(s.conns, conn)
	s.connsMu.Unlock()
	conn.Close()
}

// closeConns closes every open client connection and refuses new ones. The
// connections are closed outside the lock because closing a TLS connection
// may block briefly while it sends close_notify.
func (s *TCPServer) closeConns() {
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

func (s *TCPServer) handleConnection(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	defer atomic.AddInt64(&s.connCount, -1)
	defer s.untrackConn(conn)

	var sourceIP string
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		sourceIP = tcpAddr.IP.String()
	} else {
		sourceIP = conn.RemoteAddr().String()
	}

	slog.Debug("new TCP connection", "remote", conn.RemoteAddr())

	// The buffer holds one maximum-length line plus its newline; readLine
	// discards anything longer instead of growing it.
	reader := bufio.NewReaderSize(conn, s.config.MaxLineLength+1)

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
			slog.Debug("failed to set TCP read deadline", "error", err, "remote", sourceIP)
			return
		}

		// Read line (CEF messages are newline-delimited)
		line, err := readLine(reader)
		if errors.Is(err, errLineTooLong) {
			atomic.AddUint64(&s.received, 1)
			atomic.AddUint64(&s.oversized, 1)
			atomic.AddUint64(&s.errors, 1)
			s.rejects.Reject("oversize", err, sourceIP, line)
			continue
		}
		if err != nil && err != io.EOF {
			var netErr net.Error
			idle := errors.As(err, &netErr) && netErr.Timeout()
			if !idle && !s.stopping() {
				slog.Debug("TCP read error", "error", err, "remote", sourceIP)
			}
			return // idle timeout, Stop, or a broken connection
		}

		// A final line without a newline is still a message.
		if strings.TrimSpace(line) != "" {
			atomic.AddUint64(&s.received, 1)
			s.processMessage(ctx, line, sourceIP)
		}
		if err == io.EOF {
			return
		}
	}
}

// readLine returns the next newline-terminated line, or at EOF the final
// unterminated line together with io.EOF. A line that does not fit in the
// reader's buffer is discarded up to its newline and reported as
// errLineTooLong with the start of the line, so the server never buffers more
// than one maximum-length line per connection.
func readLine(r *bufio.Reader) (string, error) {
	data, err := r.ReadSlice('\n')
	if !errors.Is(err, bufio.ErrBufferFull) {
		return string(data), err
	}

	head := string(data[:min(len(data), 128)])
	for errors.Is(err, bufio.ErrBufferFull) {
		_, err = r.ReadSlice('\n')
	}
	if err != nil && err != io.EOF {
		return "", err
	}
	return head, errLineTooLong
}

func (s *TCPServer) stopping() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *TCPServer) processMessage(ctx context.Context, message string, sourceIP string) {
	// Parse CEF
	cefEvent, err := s.parser.Parse(message)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		atomic.AddUint64(&s.parseErrors, 1)
		s.rejects.Reject("parse", err, sourceIP, message)
		return
	}
	atomic.AddUint64(&s.parsed, 1)

	// Normalize
	event, err := s.normalizer.Normalize(cefEvent, sourceIP)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		atomic.AddUint64(&s.validationErrors, 1)
		s.rejects.Reject("normalize", err, sourceIP, message)
		return
	}

	// Validate
	if err := s.validator.Validate(event); err != nil {
		atomic.AddUint64(&s.errors, 1)
		atomic.AddUint64(&s.validationErrors, 1)
		s.rejects.Reject("validate", err, sourceIP, message)
		return
	}

	// Queue
	if err := s.queue.Push(event); err != nil {
		atomic.AddUint64(&s.errors, 1)
		s.rejects.Reject("queue", err, sourceIP, message)
		return
	}

	atomic.AddUint64(&s.queued, 1)
}

// Stop stops the TCP server gracefully. It closes the listener and every open
// client connection, then waits for the connection handlers to finish. It is
// safe to call more than once.
func (s *TCPServer) Stop() {
	s.stopOnce.Do(func() {
		close(s.done)
		if s.listener != nil {
			s.listener.Close()
		}
		s.closeConns()
		s.wg.Wait()
		slog.Info("TCP server stopped",
			"connections", atomic.LoadUint64(&s.connections),
			"received", atomic.LoadUint64(&s.received),
			"queued", atomic.LoadUint64(&s.queued),
			"errors", atomic.LoadUint64(&s.errors),
			"parse_errors", atomic.LoadUint64(&s.parseErrors),
			"validation_errors", atomic.LoadUint64(&s.validationErrors),
			"oversized_lines", atomic.LoadUint64(&s.oversized),
		)
	})
}

// Metrics returns the current server metrics.
func (s *TCPServer) Metrics() TCPServerMetrics {
	return TCPServerMetrics{
		Connections:      atomic.LoadUint64(&s.connections),
		Received:         atomic.LoadUint64(&s.received),
		Parsed:           atomic.LoadUint64(&s.parsed),
		Queued:           atomic.LoadUint64(&s.queued),
		Errors:           atomic.LoadUint64(&s.errors),
		ParseErrors:      atomic.LoadUint64(&s.parseErrors),
		ValidationErrors: atomic.LoadUint64(&s.validationErrors),
		OversizedLines:   atomic.LoadUint64(&s.oversized),
	}
}

// ActiveConnections returns the number of currently active connections.
func (s *TCPServer) ActiveConnections() int {
	return int(atomic.LoadInt64(&s.connCount))
}
