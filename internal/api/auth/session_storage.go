package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// SessionStorage defines the interface for session persistence.
type SessionStorage interface {
	// Store saves a session with optional TTL.
	Store(ctx context.Context, session *Session) error

	// Get retrieves a session by token.
	Get(ctx context.Context, token string) (*Session, error)

	// Delete removes a session by token.
	Delete(ctx context.Context, token string) error

	// DeleteByUserID removes all sessions for a user.
	DeleteByUserID(ctx context.Context, userID string) error

	// GetByUserID retrieves all sessions for a user.
	GetByUserID(ctx context.Context, userID string) ([]*Session, error)

	// UpdateActivity updates the last active time for a session.
	UpdateActivity(ctx context.Context, token string, lastActive time.Time) error

	// Count returns the total number of active sessions.
	Count(ctx context.Context) (int, error)

	// Close releases any resources.
	Close() error
}

var (
	// ErrSessionNotFound is returned when a session doesn't exist.
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionExpired is returned when a session has expired.
	ErrSessionExpired = errors.New("session expired")
)

// MemorySessionStorage implements SessionStorage using in-memory maps.
// This is suitable for single-instance deployments and testing.
type MemorySessionStorage struct {
	mu           sync.RWMutex
	sessions     map[string]*Session // token -> session
	userSessions map[string][]string // userID -> []token
	stopCleanup  chan struct{}
}

// NewMemorySessionStorage creates a new in-memory session storage.
// Starts a background goroutine to periodically clean up expired sessions.
func NewMemorySessionStorage() *MemorySessionStorage {
	m := &MemorySessionStorage{
		sessions:     make(map[string]*Session),
		userSessions: make(map[string][]string),
		stopCleanup:  make(chan struct{}),
	}

	go m.cleanupLoop()

	return m
}

// cleanupLoop periodically removes expired sessions to prevent memory leaks.
func (m *MemorySessionStorage) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCleanup:
			return
		case <-ticker.C:
			m.CleanupExpired(context.Background())
		}
	}
}

// Store saves a session.
func (m *MemorySessionStorage) Store(ctx context.Context, session *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store session by token
	m.sessions[session.Token] = session

	// Index by user ID
	if session.UserID != "" {
		m.userSessions[session.UserID] = append(m.userSessions[session.UserID], session.Token)
	}

	return nil
}

// Get retrieves a session by token.
func (m *MemorySessionStorage) Get(ctx context.Context, token string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[token]
	if !exists {
		return nil, ErrSessionNotFound
	}

	// Check if expired
	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	return session, nil
}

// Delete removes a session by token.
func (m *MemorySessionStorage) Delete(ctx context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[token]
	if !exists {
		return nil // Already deleted
	}

	// Remove from main map
	delete(m.sessions, token)

	// Remove from user index
	if session.UserID != "" {
		tokens := m.userSessions[session.UserID]
		for i, t := range tokens {
			if t == token {
				m.userSessions[session.UserID] = append(tokens[:i], tokens[i+1:]...)
				break
			}
		}
	}

	return nil
}

// DeleteByUserID removes all sessions for a user.
func (m *MemorySessionStorage) DeleteByUserID(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	tokens := m.userSessions[userID]
	for _, token := range tokens {
		delete(m.sessions, token)
	}
	delete(m.userSessions, userID)

	return nil
}

// GetByUserID retrieves all sessions for a user.
func (m *MemorySessionStorage) GetByUserID(ctx context.Context, userID string) ([]*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tokens := m.userSessions[userID]
	sessions := make([]*Session, 0, len(tokens))

	now := time.Now()
	for _, token := range tokens {
		if session, exists := m.sessions[token]; exists {
			// Skip expired sessions
			if now.Before(session.ExpiresAt) {
				sessions = append(sessions, session)
			}
		}
	}

	return sessions, nil
}

// UpdateActivity updates the last active time for a session.
func (m *MemorySessionStorage) UpdateActivity(ctx context.Context, token string, lastActive time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[token]
	if !exists {
		return ErrSessionNotFound
	}

	session.LastActiveAt = lastActive
	return nil
}

// Count returns the total number of active sessions.
func (m *MemorySessionStorage) Count(ctx context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, session := range m.sessions {
		if now.Before(session.ExpiresAt) {
			count++
		}
	}

	return count, nil
}

// Close releases resources and stops the background cleanup goroutine.
func (m *MemorySessionStorage) Close() error {
	close(m.stopCleanup)
	return nil
}

// CleanupExpired removes expired sessions (should be called periodically).
func (m *MemorySessionStorage) CleanupExpired(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	expiredTokens := make([]string, 0)

	// Find expired sessions
	for token, session := range m.sessions {
		if now.After(session.ExpiresAt) {
			expiredTokens = append(expiredTokens, token)
		}
	}

	// Delete expired sessions
	for _, token := range expiredTokens {
		session := m.sessions[token]
		delete(m.sessions, token)

		// Remove from user index
		if session.UserID != "" {
			tokens := m.userSessions[session.UserID]
			for i, t := range tokens {
				if t == token {
					m.userSessions[session.UserID] = append(tokens[:i], tokens[i+1:]...)
					break
				}
			}
		}
	}

	return nil
}

// RedisSessionStorage implements SessionStorage using Redis.
// This is suitable for production deployments with multiple instances.
type RedisSessionStorage struct {
	client RedisClient
	prefix string
	ttl    time.Duration
}

// RedisClient defines the interface for Redis operations.
// This allows for easy mocking and testing.
type RedisClient interface {
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, keys ...string) error
	SAdd(ctx context.Context, key string, members ...string) error
	SMembers(ctx context.Context, key string) ([]string, error)
	SRem(ctx context.Context, key string, members ...string) error
	Expire(ctx context.Context, key string, ttl time.Duration) error
	Exists(ctx context.Context, keys ...string) (int, error)
	DBSize(ctx context.Context) (int, error)
	Close() error
}

// RedisConfig holds Redis connection configuration.
type RedisConfig struct {
	Addr         string        `yaml:"addr"`           // Redis server address (host:port)
	Password     string        `yaml:"password"`       // Password for authentication
	DB           int           `yaml:"db"`             // Database number
	DialTimeout  time.Duration `yaml:"dial_timeout"`   // Connection timeout
	ReadTimeout  time.Duration `yaml:"read_timeout"`   // Read timeout
	WriteTimeout time.Duration `yaml:"write_timeout"`  // Write timeout
	PoolSize     int           `yaml:"pool_size"`      // Connection pool size
	MinIdleConns int           `yaml:"min_idle_conns"` // Minimum idle connections
	MaxRetries   int           `yaml:"max_retries"`    // Maximum retry attempts
	TLSEnabled   bool          `yaml:"tls_enabled"`    // Enable TLS
}

// DefaultRedisConfig returns sensible defaults.
func DefaultRedisConfig() RedisConfig {
	return RedisConfig{
		Addr:         "localhost:6379",
		Password:     "",
		DB:           0,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     10,
		MinIdleConns: 2,
		MaxRetries:   3,
		TLSEnabled:   false,
	}
}

// NewRedisSessionStorage creates a new Redis-backed session storage.
func NewRedisSessionStorage(client RedisClient, prefix string, ttl time.Duration) *RedisSessionStorage {
	if prefix == "" {
		prefix = "session"
	}
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	return &RedisSessionStorage{
		client: client,
		prefix: prefix,
		ttl:    ttl,
	}
}

// sessionKey returns the Redis key for a session token.
func (r *RedisSessionStorage) sessionKey(token string) string {
	return fmt.Sprintf("%s:token:%s", r.prefix, token)
}

// userSessionsKey returns the Redis key for user sessions set.
func (r *RedisSessionStorage) userSessionsKey(userID string) string {
	return fmt.Sprintf("%s:user:%s", r.prefix, userID)
}

// Store saves a session to Redis.
func (r *RedisSessionStorage) Store(ctx context.Context, session *Session) error {
	// Serialize session
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	// Calculate TTL based on expiration
	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return ErrSessionExpired
	}

	// Store session
	key := r.sessionKey(session.Token)
	if err := r.client.Set(ctx, key, data, ttl); err != nil {
		return fmt.Errorf("failed to store session: %w", err)
	}

	// Add to user sessions set
	if session.UserID != "" {
		userKey := r.userSessionsKey(session.UserID)
		if err := r.client.SAdd(ctx, userKey, session.Token); err != nil {
			return fmt.Errorf("failed to index session by user: %w", err)
		}
		// Set TTL on user sessions set
		if err := r.client.Expire(ctx, userKey, ttl); err != nil {
			return fmt.Errorf("failed to set TTL on user sessions: %w", err)
		}
	}

	return nil
}

// Get retrieves a session from Redis.
func (r *RedisSessionStorage) Get(ctx context.Context, token string) (*Session, error) {
	key := r.sessionKey(token)
	data, err := r.client.Get(ctx, key)
	if err != nil {
		return nil, ErrSessionNotFound
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	// Check if expired (defense in depth)
	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	return &session, nil
}

// Delete removes a session from Redis.
func (r *RedisSessionStorage) Delete(ctx context.Context, token string) error {
	// Get session first to get user ID
	session, err := r.Get(ctx, token)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return nil // Already deleted
		}
		return err
	}

	// Delete session
	key := r.sessionKey(token)
	if err := r.client.Delete(ctx, key); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	// Remove from user sessions set
	if session.UserID != "" {
		userKey := r.userSessionsKey(session.UserID)
		if err := r.client.SRem(ctx, userKey, token); err != nil {
			return fmt.Errorf("failed to remove from user sessions: %w", err)
		}
	}

	return nil
}

// DeleteByUserID removes all sessions for a user.
func (r *RedisSessionStorage) DeleteByUserID(ctx context.Context, userID string) error {
	// Get all session tokens for user
	userKey := r.userSessionsKey(userID)
	tokens, err := r.client.SMembers(ctx, userKey)
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	// Delete all session keys
	if len(tokens) > 0 {
		keys := make([]string, len(tokens))
		for i, token := range tokens {
			keys[i] = r.sessionKey(token)
		}
		if err := r.client.Delete(ctx, keys...); err != nil {
			return fmt.Errorf("failed to delete session keys: %w", err)
		}
	}

	// Delete user sessions set
	if err := r.client.Delete(ctx, userKey); err != nil {
		return fmt.Errorf("failed to delete user sessions set: %w", err)
	}

	return nil
}

// GetByUserID retrieves all sessions for a user.
func (r *RedisSessionStorage) GetByUserID(ctx context.Context, userID string) ([]*Session, error) {
	// Get all session tokens for user
	userKey := r.userSessionsKey(userID)
	tokens, err := r.client.SMembers(ctx, userKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}

	sessions := make([]*Session, 0, len(tokens))
	now := time.Now()

	for _, token := range tokens {
		session, err := r.Get(ctx, token)
		if err != nil {
			// Skip sessions that can't be retrieved (may have expired)
			continue
		}

		// Skip expired sessions
		if now.Before(session.ExpiresAt) {
			sessions = append(sessions, session)
		}
	}

	return sessions, nil
}

// UpdateActivity updates the last active time for a session.
func (r *RedisSessionStorage) UpdateActivity(ctx context.Context, token string, lastActive time.Time) error {
	// Get existing session
	session, err := r.Get(ctx, token)
	if err != nil {
		return err
	}

	// Update last active time
	session.LastActiveAt = lastActive

	// Re-store the session
	return r.Store(ctx, session)
}

// Count returns the approximate number of active sessions.
func (r *RedisSessionStorage) Count(ctx context.Context) (int, error) {
	// Note: This returns total keys in DB, not just sessions
	// For accurate count, would need to scan for session keys
	return r.client.DBSize(ctx)
}

// Close releases Redis client resources.
func (r *RedisSessionStorage) Close() error {
	return r.client.Close()
}
