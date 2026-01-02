package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// GoRedisClient wraps the go-redis client to implement our RedisClient interface.
type GoRedisClient struct {
	client *redis.Client
}

// NewGoRedisClient creates a new Redis client from configuration.
func NewGoRedisClient(cfg RedisConfig) (*GoRedisClient, error) {
	opts := &redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		MaxRetries:   cfg.MaxRetries,
	}

	// Configure TLS if enabled
	if cfg.TLSEnabled {
		opts.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &GoRedisClient{client: client}, nil
}

// Set stores a value with TTL.
func (g *GoRedisClient) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return g.client.Set(ctx, key, value, ttl).Err()
}

// Get retrieves a value.
func (g *GoRedisClient) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := g.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("key not found")
		}
		return nil, err
	}
	return []byte(val), nil
}

// Delete removes one or more keys.
func (g *GoRedisClient) Delete(ctx context.Context, keys ...string) error {
	return g.client.Del(ctx, keys...).Err()
}

// SAdd adds members to a set.
func (g *GoRedisClient) SAdd(ctx context.Context, key string, members ...string) error {
	// Convert to []interface{} for redis client
	vals := make([]interface{}, len(members))
	for i, m := range members {
		vals[i] = m
	}
	return g.client.SAdd(ctx, key, vals...).Err()
}

// SMembers returns all members of a set.
func (g *GoRedisClient) SMembers(ctx context.Context, key string) ([]string, error) {
	return g.client.SMembers(ctx, key).Result()
}

// SRem removes members from a set.
func (g *GoRedisClient) SRem(ctx context.Context, key string, members ...string) error {
	// Convert to []interface{} for redis client
	vals := make([]interface{}, len(members))
	for i, m := range members {
		vals[i] = m
	}
	return g.client.SRem(ctx, key, vals...).Err()
}

// Expire sets a TTL on a key.
func (g *GoRedisClient) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return g.client.Expire(ctx, key, ttl).Err()
}

// Exists checks if keys exist.
func (g *GoRedisClient) Exists(ctx context.Context, keys ...string) (int, error) {
	count, err := g.client.Exists(ctx, keys...).Result()
	return int(count), err
}

// DBSize returns the number of keys in the database.
func (g *GoRedisClient) DBSize(ctx context.Context) (int, error) {
	size, err := g.client.DBSize(ctx).Result()
	return int(size), err
}

// Close closes the Redis connection.
func (g *GoRedisClient) Close() error {
	return g.client.Close()
}

// MockRedisClient is a mock implementation for testing.
type MockRedisClient struct {
	data    map[string][]byte
	sets    map[string]map[string]bool
	expiry  map[string]time.Time
	mu      sync.RWMutex
	closed  bool
}

// NewMockRedisClient creates a new mock Redis client for testing.
func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{
		data:   make(map[string][]byte),
		sets:   make(map[string]map[string]bool),
		expiry: make(map[string]time.Time),
	}
}

// Set stores a value with TTL.
func (m *MockRedisClient) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("client closed")
	}

	m.data[key] = value
	if ttl > 0 {
		m.expiry[key] = time.Now().Add(ttl)
	}
	return nil
}

// Get retrieves a value.
func (m *MockRedisClient) Get(ctx context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, errors.New("client closed")
	}

	// Check expiry
	if exp, ok := m.expiry[key]; ok && time.Now().After(exp) {
		return nil, errors.New("key not found")
	}

	val, ok := m.data[key]
	if !ok {
		return nil, errors.New("key not found")
	}
	return val, nil
}

// Delete removes keys.
func (m *MockRedisClient) Delete(ctx context.Context, keys ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("client closed")
	}

	for _, key := range keys {
		delete(m.data, key)
		delete(m.expiry, key)
		delete(m.sets, key)
	}
	return nil
}

// SAdd adds members to a set.
func (m *MockRedisClient) SAdd(ctx context.Context, key string, members ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("client closed")
	}

	if m.sets[key] == nil {
		m.sets[key] = make(map[string]bool)
	}
	for _, member := range members {
		m.sets[key][member] = true
	}
	return nil
}

// SMembers returns all members of a set.
func (m *MockRedisClient) SMembers(ctx context.Context, key string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, errors.New("client closed")
	}

	set := m.sets[key]
	members := make([]string, 0, len(set))
	for member := range set {
		members = append(members, member)
	}
	return members, nil
}

// SRem removes members from a set.
func (m *MockRedisClient) SRem(ctx context.Context, key string, members ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("client closed")
	}

	if m.sets[key] == nil {
		return nil
	}
	for _, member := range members {
		delete(m.sets[key], member)
	}
	return nil
}

// Expire sets a TTL on a key.
func (m *MockRedisClient) Expire(ctx context.Context, key string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("client closed")
	}

	m.expiry[key] = time.Now().Add(ttl)
	return nil
}

// Exists checks if keys exist.
func (m *MockRedisClient) Exists(ctx context.Context, keys ...string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return 0, errors.New("client closed")
	}

	count := 0
	for _, key := range keys {
		if _, ok := m.data[key]; ok {
			count++
		}
	}
	return count, nil
}

// DBSize returns the number of keys.
func (m *MockRedisClient) DBSize(ctx context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return 0, errors.New("client closed")
	}

	return len(m.data), nil
}

// Close marks the client as closed.
func (m *MockRedisClient) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}
