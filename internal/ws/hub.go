// Package ws implements the /ws/events live stream consumed by the web
// dashboard.
//
// Protocol (one JSON object per text frame):
//
//	client -> {"type":"auth","api_key":"<key, may be empty>"}   first frame, within AuthTimeout
//	server -> {"type":"auth_ok"}                                 or close 4401 with a reason
//	client -> {"type":"ping"}                                    every 30s
//	server -> {"type":"pong"}
//	server -> {"type":"alert","data":<alert as in GET /v1/alerts/{id}>}
//	server -> {"type":"stats","data":<GET /v1/stats response>}
//
// When authentication is enabled the key must be one of the configured API
// keys; otherwise any auth message is accepted. A first frame that is not an
// auth message, or no frame within AuthTimeout, closes the connection with
// 4401 "authentication required". Other client messages are ignored.
//
// Every client has a bounded send queue. A client that cannot keep up is
// disconnected (close code 1013) instead of slowing down the server, and
// every write has a deadline.
package ws

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// Message types of the protocol.
const (
	TypeAuth   = "auth"
	TypeAuthOK = "auth_ok"
	TypePing   = "ping"
	TypePong   = "pong"
	TypeAlert  = "alert"
	TypeStats  = "stats"
	TypeEvent  = "event"
)

// CloseAuthFailed is the close code sent when authentication fails. The
// dashboard treats it as final and asks the user for a new key.
const CloseAuthFailed = 4401

// Close reasons sent with CloseAuthFailed.
const (
	ReasonAuthRequired = "authentication required"
	ReasonMissingKey   = "missing API key"
	ReasonInvalidKey   = "invalid API key"
)

// Defaults for zero Config fields.
const (
	DefaultMaxClients     = 100
	DefaultSendQueueSize  = 64
	DefaultWriteTimeout   = 10 * time.Second
	DefaultAuthTimeout    = 10 * time.Second
	DefaultReadTimeout    = 75 * time.Second
	DefaultPingInterval   = 30 * time.Second
	DefaultMaxMessageSize = 4096
)

// closeWait bounds how long Close waits for connections to finish.
const closeWait = 3 * time.Second

// Config configures a Hub.
type Config struct {
	// AuthEnabled requires the auth message to carry one of APIKeys.
	AuthEnabled bool
	// APIKeyValid reports whether a key is valid. It must compare in
	// constant time.
	APIKeyValid func(key string) bool

	// Origin policy, consistent with the REST API's CORS settings: a
	// browser Origin is accepted when it is the server's own origin or,
	// with CORSEnabled, listed in AllowedOrigins ("*" allows any). Requests
	// without an Origin header (non-browser clients) are accepted.
	CORSEnabled    bool
	AllowedOrigins []string

	MaxClients     int
	SendQueueSize  int
	WriteTimeout   time.Duration
	AuthTimeout    time.Duration
	ReadTimeout    time.Duration // reset by every client message and pong
	PingInterval   time.Duration // WebSocket ping frames to detect dead peers
	MaxMessageSize int64         // largest accepted client frame
}

func (c *Config) applyDefaults() {
	if c.MaxClients <= 0 {
		c.MaxClients = DefaultMaxClients
	}
	if c.SendQueueSize <= 0 {
		c.SendQueueSize = DefaultSendQueueSize
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = DefaultWriteTimeout
	}
	if c.AuthTimeout <= 0 {
		c.AuthTimeout = DefaultAuthTimeout
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = DefaultReadTimeout
	}
	if c.PingInterval <= 0 {
		c.PingInterval = DefaultPingInterval
	}
	if c.MaxMessageSize <= 0 {
		c.MaxMessageSize = DefaultMaxMessageSize
	}
	if c.APIKeyValid == nil {
		c.APIKeyValid = func(string) bool { return false }
	}
}

// Hub accepts WebSocket connections and broadcasts messages to the
// authenticated ones.
type Hub struct {
	cfg      Config
	logger   *slog.Logger
	upgrader websocket.Upgrader

	mu      sync.RWMutex
	closed  bool
	all     map[*client]struct{} // every open connection
	authed  map[*client]struct{} // connections that completed auth
	wg      sync.WaitGroup       // one per open connection
	pending atomic.Int64         // connections counted against MaxClients

	connections  atomic.Uint64
	authFailures atomic.Uint64
	slowDropped  atomic.Uint64
	sent         atomic.Uint64
}

// NewHub creates a Hub.
func NewHub(cfg Config, logger *slog.Logger) *Hub {
	cfg.applyDefaults()
	if logger == nil {
		logger = slog.Default()
	}
	h := &Hub{
		cfg:    cfg,
		logger: logger,
		all:    make(map[*client]struct{}),
		authed: make(map[*client]struct{}),
	}
	h.upgrader = websocket.Upgrader{
		HandshakeTimeout: cfg.WriteTimeout,
		CheckOrigin:      h.checkOrigin,
	}
	return h
}

// checkOrigin applies the origin policy described on Config.
func (h *Hub) checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	if h.cfg.CORSEnabled {
		for _, allowed := range h.cfg.AllowedOrigins {
			if allowed == "*" || allowed == origin {
				return true
			}
		}
	}
	h.logger.Warn("WebSocket origin not allowed", "origin", origin, "host", r.Host)
	return false
}

// ServeHTTP upgrades the request and serves the connection until it closes.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		http.Error(w, "server shutting down", http.StatusServiceUnavailable)
		return
	}
	if h.pending.Add(1) > int64(h.cfg.MaxClients) {
		h.pending.Add(-1)
		h.mu.Unlock()
		h.logger.Warn("WebSocket connection refused: too many clients", "max_clients", h.cfg.MaxClients)
		http.Error(w, "too many WebSocket clients", http.StatusServiceUnavailable)
		return
	}
	h.wg.Add(1)
	h.mu.Unlock()
	defer h.wg.Done()
	defer h.pending.Add(-1)

	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade has already answered with an HTTP error.
		h.logger.Debug("WebSocket upgrade failed", "error", err)
		return
	}
	h.connections.Add(1)

	c := &client{
		hub:    h,
		conn:   conn,
		send:   make(chan []byte, h.cfg.SendQueueSize),
		done:   make(chan struct{}),
		closed: make(chan struct{}),
		remote: remoteIP(r),
	}
	if !h.track(c) {
		c.close(websocket.CloseGoingAway, "server shutting down")
		<-c.closed
		return
	}
	defer h.untrack(c)

	c.serve()
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (h *Hub) track(c *client) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return false
	}
	h.all[c] = struct{}{}
	return true
}

func (h *Hub) untrack(c *client) {
	h.mu.Lock()
	delete(h.all, c)
	delete(h.authed, c)
	h.mu.Unlock()
}

// register makes an authenticated client receive broadcasts.
func (h *Hub) register(c *client) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return false
	}
	h.authed[c] = struct{}{}
	return true
}

// envelope is one protocol message.
type envelope struct {
	Type string `json:"type"`
	Data any    `json:"data,omitempty"`
}

func encode(msgType string, data any) ([]byte, error) {
	return json.Marshal(envelope{Type: msgType, Data: data})
}

// Broadcast sends {"type":msgType,"data":data} to every authenticated
// client. It never blocks: clients whose send queue is full are
// disconnected.
func (h *Hub) Broadcast(msgType string, data any) error {
	payload, err := encode(msgType, data)
	if err != nil {
		return err
	}

	h.mu.RLock()
	clients := make([]*client, 0, len(h.authed))
	for c := range h.authed {
		clients = append(clients, c)
	}
	h.mu.RUnlock()

	for _, c := range clients {
		c.enqueue(payload)
	}
	return nil
}

// Clients returns the number of authenticated clients.
func (h *Hub) Clients() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.authed)
}

// Close disconnects every client (close code 1001) and refuses new
// connections. It waits a bounded time for the connections to finish and is
// safe to call more than once.
func (h *Hub) Close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	clients := make([]*client, 0, len(h.all))
	for c := range h.all {
		clients = append(clients, c)
	}
	h.mu.Unlock()

	for _, c := range clients {
		c.close(websocket.CloseGoingAway, "server shutting down")
	}

	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(closeWait):
		h.logger.Warn("WebSocket connections did not close in time")
	}
}

// Metrics returns hub statistics.
func (h *Hub) Metrics() Metrics {
	return Metrics{
		Clients:            h.Clients(),
		Connections:        h.connections.Load(),
		AuthFailures:       h.authFailures.Load(),
		SlowClientsDropped: h.slowDropped.Load(),
		MessagesSent:       h.sent.Load(),
	}
}

// Metrics holds Hub statistics.
type Metrics struct {
	Clients            int    `json:"clients"`
	Connections        uint64 `json:"connections"`
	AuthFailures       uint64 `json:"auth_failures"`
	SlowClientsDropped uint64 `json:"slow_clients_dropped"`
	MessagesSent       uint64 `json:"messages_sent"`
}

// client is one WebSocket connection.
type client struct {
	hub    *Hub
	conn   *websocket.Conn
	send   chan []byte
	remote string

	done      chan struct{} // closed when the client is shutting down
	closed    chan struct{} // closed once the connection is closed
	closeOnce sync.Once
}

// close sends a close frame (best effort, bounded by the write timeout) and
// closes the connection. It never blocks the caller.
func (c *client) close(code int, reason string) {
	c.closeOnce.Do(func() {
		close(c.done)
		go func() {
			defer close(c.closed)
			msg := websocket.FormatCloseMessage(code, reason)
			_ = c.conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(c.hub.cfg.WriteTimeout))
			_ = c.conn.Close()
		}()
	})
}

// enqueue queues a message without blocking. A full queue means the client
// cannot keep up; it is disconnected.
func (c *client) enqueue(msg []byte) bool {
	select {
	case <-c.done:
		return false
	default:
	}
	select {
	case c.send <- msg:
		return true
	default:
		c.hub.slowDropped.Add(1)
		c.hub.logger.Warn("WebSocket client too slow, disconnecting", "remote", c.remote, "queue", cap(c.send))
		c.close(websocket.CloseTryAgainLater, "client too slow")
		return false
	}
}

// serve runs the connection: authentication, then the read loop on this
// goroutine and the write loop on another.
func (c *client) serve() {
	defer func() {
		c.close(websocket.CloseNormalClosure, "")
		<-c.closed
	}()

	if !c.authenticate() {
		return
	}

	authOK, _ := encode(TypeAuthOK, nil)
	c.send <- authOK // the queue is empty: auth_ok always goes out first

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		c.writeLoop()
	}()
	defer func() { <-writerDone }()

	if !c.hub.register(c) {
		c.close(websocket.CloseGoingAway, "server shutting down")
		return
	}
	c.hub.logger.Debug("WebSocket client connected", "remote", c.remote)
	c.readLoop()
}

// authFrame is the first client message.
type authFrame struct {
	Type   string  `json:"type"`
	APIKey *string `json:"api_key"`
}

// authenticate reads the first frame and checks it. On failure it closes
// the connection with CloseAuthFailed.
func (c *client) authenticate() bool {
	conn := c.conn
	conn.SetReadLimit(c.hub.cfg.MaxMessageSize)
	_ = conn.SetReadDeadline(time.Now().Add(c.hub.cfg.AuthTimeout))

	fail := func(reason string) bool {
		c.hub.authFailures.Add(1)
		c.hub.logger.Warn("WebSocket authentication failed", "remote", c.remote, "reason", reason)
		c.close(CloseAuthFailed, reason)
		return false
	}

	msgType, data, err := conn.ReadMessage()
	if err != nil {
		select {
		case <-c.done: // closed by the hub
			return false
		default:
		}
		return fail(ReasonAuthRequired)
	}
	var frame authFrame
	if msgType != websocket.TextMessage || json.Unmarshal(data, &frame) != nil || frame.Type != TypeAuth {
		return fail(ReasonAuthRequired)
	}
	if c.hub.cfg.AuthEnabled {
		key := ""
		if frame.APIKey != nil {
			key = *frame.APIKey
		}
		if key == "" {
			return fail(ReasonMissingKey)
		}
		if !c.hub.cfg.APIKeyValid(key) {
			return fail(ReasonInvalidKey)
		}
	}
	return true
}

// readLoop handles client messages until the connection fails or closes.
func (c *client) readLoop() {
	conn := c.conn
	readTimeout := c.hub.cfg.ReadTimeout
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(readTimeout))
	})

	pong, _ := encode(TypePong, nil)
	for {
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		if msgType != websocket.TextMessage {
			continue
		}
		var msg struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(data, &msg) == nil && msg.Type == TypePing {
			if !c.enqueue(pong) {
				return
			}
		}
	}
}

// writeLoop sends queued messages and periodic pings, each with a write
// deadline.
func (c *client) writeLoop() {
	ticker := time.NewTicker(c.hub.cfg.PingInterval)
	defer ticker.Stop()
	timeout := c.hub.cfg.WriteTimeout

	for {
		select {
		case <-c.done:
			return
		case msg := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(timeout))
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				c.close(websocket.CloseInternalServerErr, "write failed")
				return
			}
			c.hub.sent.Add(1)
		case <-ticker.C:
			if err := c.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(timeout)); err != nil {
				c.close(websocket.CloseInternalServerErr, "ping failed")
				return
			}
		}
	}
}
