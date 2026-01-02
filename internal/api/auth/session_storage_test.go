package auth

import (
	"context"
	"testing"
	"time"
)

// TestMemorySessionStorage_Store tests storing sessions in memory.
func TestMemorySessionStorage_Store(t *testing.T) {
	storage := NewMemorySessionStorage()
	ctx := context.Background()

	session := &Session{
		ID:           "session-123",
		UserID:       "user-456",
		Token:        "token-abc",
		RefreshToken: "refresh-xyz",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		LastActiveAt: time.Now(),
	}

	err := storage.Store(ctx, session)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify session can be retrieved
	retrieved, err := storage.Get(ctx, session.Token)
	if err != nil {
		t.Fatalf("expected to retrieve session, got error: %v", err)
	}

	if retrieved.ID != session.ID {
		t.Errorf("expected ID %s, got %s", session.ID, retrieved.ID)
	}
	if retrieved.UserID != session.UserID {
		t.Errorf("expected UserID %s, got %s", session.UserID, retrieved.UserID)
	}
}

// TestMemorySessionStorage_Get tests retrieving sessions.
func TestMemorySessionStorage_Get(t *testing.T) {
	storage := NewMemorySessionStorage()
	ctx := context.Background()

	// Test non-existent session
	_, err := storage.Get(ctx, "nonexistent-token")
	if err != ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}

	// Store and retrieve
	session := &Session{
		ID:        "session-123",
		Token:     "token-abc",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	storage.Store(ctx, session)

	retrieved, err := storage.Get(ctx, session.Token)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if retrieved.ID != session.ID {
		t.Errorf("expected ID %s, got %s", session.ID, retrieved.ID)
	}
}

// TestMemorySessionStorage_GetExpired tests expired session handling.
func TestMemorySessionStorage_GetExpired(t *testing.T) {
	storage := NewMemorySessionStorage()
	ctx := context.Background()

	// Create expired session
	session := &Session{
		ID:        "session-123",
		Token:     "token-abc",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}

	storage.Store(ctx, session)

	// Attempt to get expired session
	_, err := storage.Get(ctx, session.Token)
	if err != ErrSessionExpired {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}
}

// TestMemorySessionStorage_Delete tests deleting sessions.
func TestMemorySessionStorage_Delete(t *testing.T) {
	storage := NewMemorySessionStorage()
	ctx := context.Background()

	session := &Session{
		ID:        "session-123",
		UserID:    "user-456",
		Token:     "token-abc",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	storage.Store(ctx, session)

	// Verify session exists
	_, err := storage.Get(ctx, session.Token)
	if err != nil {
		t.Fatalf("expected session to exist, got error: %v", err)
	}

	// Delete session
	err = storage.Delete(ctx, session.Token)
	if err != nil {
		t.Fatalf("expected no error on delete, got %v", err)
	}

	// Verify session is gone
	_, err = storage.Get(ctx, session.Token)
	if err != ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound after delete, got %v", err)
	}
}

// TestMemorySessionStorage_DeleteByUserID tests deleting all user sessions.
func TestMemorySessionStorage_DeleteByUserID(t *testing.T) {
	storage := NewMemorySessionStorage()
	ctx := context.Background()

	userID := "user-123"

	// Create multiple sessions for the same user
	session1 := &Session{
		ID:        "session-1",
		UserID:    userID,
		Token:     "token-1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	session2 := &Session{
		ID:        "session-2",
		UserID:    userID,
		Token:     "token-2",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	session3 := &Session{
		ID:        "session-3",
		UserID:    "other-user",
		Token:     "token-3",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	storage.Store(ctx, session1)
	storage.Store(ctx, session2)
	storage.Store(ctx, session3)

	// Delete all sessions for user-123
	err := storage.DeleteByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify user-123 sessions are gone
	_, err = storage.Get(ctx, session1.Token)
	if err != ErrSessionNotFound {
		t.Error("expected session1 to be deleted")
	}
	_, err = storage.Get(ctx, session2.Token)
	if err != ErrSessionNotFound {
		t.Error("expected session2 to be deleted")
	}

	// Verify other user's session still exists
	_, err = storage.Get(ctx, session3.Token)
	if err != nil {
		t.Error("expected session3 to still exist")
	}
}

// TestMemorySessionStorage_GetByUserID tests retrieving user sessions.
func TestMemorySessionStorage_GetByUserID(t *testing.T) {
	storage := NewMemorySessionStorage()
	ctx := context.Background()

	userID := "user-123"

	// Create multiple sessions
	session1 := &Session{
		ID:        "session-1",
		UserID:    userID,
		Token:     "token-1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	session2 := &Session{
		ID:        "session-2",
		UserID:    userID,
		Token:     "token-2",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	session3 := &Session{
		ID:        "session-3",
		UserID:    "other-user",
		Token:     "token-3",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	storage.Store(ctx, session1)
	storage.Store(ctx, session2)
	storage.Store(ctx, session3)

	// Get sessions for user-123
	sessions, err := storage.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(sessions) != 2 {
		t.Errorf("expected 2 sessions, got %d", len(sessions))
	}

	// Verify correct sessions returned
	tokenMap := make(map[string]bool)
	for _, s := range sessions {
		tokenMap[s.Token] = true
	}
	if !tokenMap["token-1"] || !tokenMap["token-2"] {
		t.Error("expected sessions token-1 and token-2")
	}
	if tokenMap["token-3"] {
		t.Error("did not expect token-3 in results")
	}
}

// TestMemorySessionStorage_UpdateActivity tests updating session activity.
func TestMemorySessionStorage_UpdateActivity(t *testing.T) {
	storage := NewMemorySessionStorage()
	ctx := context.Background()

	initialTime := time.Now()
	session := &Session{
		ID:           "session-123",
		Token:        "token-abc",
		CreatedAt:    initialTime,
		ExpiresAt:    initialTime.Add(1 * time.Hour),
		LastActiveAt: initialTime,
	}

	storage.Store(ctx, session)

	// Wait a bit to ensure time difference
	time.Sleep(10 * time.Millisecond)

	// Update activity
	newTime := time.Now()
	err := storage.UpdateActivity(ctx, session.Token, newTime)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify update
	retrieved, _ := storage.Get(ctx, session.Token)
	if retrieved.LastActiveAt.Before(newTime) || retrieved.LastActiveAt.Equal(initialTime) {
		t.Error("expected LastActiveAt to be updated")
	}
}

// TestMemorySessionStorage_Count tests session counting.
func TestMemorySessionStorage_Count(t *testing.T) {
	storage := NewMemorySessionStorage()
	ctx := context.Background()

	// Initially empty
	count, err := storage.Count(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 0 {
		t.Errorf("expected count 0, got %d", count)
	}

	// Add some sessions
	for i := 0; i < 5; i++ {
		session := &Session{
			ID:        string(rune('0' + i)),
			Token:     string(rune('a' + i)),
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		storage.Store(ctx, session)
	}

	count, err = storage.Count(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 5 {
		t.Errorf("expected count 5, got %d", count)
	}

	// Add expired session (should not be counted)
	expiredSession := &Session{
		ID:        "expired",
		Token:     "expired-token",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	storage.Store(ctx, expiredSession)

	count, err = storage.Count(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 5 {
		t.Errorf("expected count 5 (excluding expired), got %d", count)
	}
}

// TestMemorySessionStorage_CleanupExpired tests cleanup of expired sessions.
func TestMemorySessionStorage_CleanupExpired(t *testing.T) {
	storage := NewMemorySessionStorage()
	ctx := context.Background()

	// Create mix of valid and expired sessions
	validSession := &Session{
		ID:        "valid",
		UserID:    "user-1",
		Token:     "valid-token",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	expiredSession := &Session{
		ID:        "expired",
		UserID:    "user-2",
		Token:     "expired-token",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	storage.Store(ctx, validSession)
	storage.Store(ctx, expiredSession)

	// Cleanup expired sessions
	err := storage.CleanupExpired(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Valid session should still exist
	_, err = storage.Get(ctx, validSession.Token)
	if err != nil {
		t.Error("expected valid session to still exist")
	}

	// Expired session should be gone (accessing the map directly)
	storage.mu.RLock()
	_, exists := storage.sessions[expiredSession.Token]
	storage.mu.RUnlock()
	if exists {
		t.Error("expected expired session to be cleaned up")
	}

	// User index should also be cleaned
	storage.mu.RLock()
	userSessions := storage.userSessions["user-2"]
	storage.mu.RUnlock()
	if len(userSessions) != 0 {
		t.Error("expected expired session to be removed from user index")
	}
}

// TestRedisSessionStorage_Mock tests Redis storage with mock client.
func TestRedisSessionStorage_Mock(t *testing.T) {
	mockClient := NewMockRedisClient()
	storage := NewRedisSessionStorage(mockClient, "test", 24*time.Hour)
	ctx := context.Background()

	session := &Session{
		ID:        "session-123",
		UserID:    "user-456",
		Token:     "token-abc",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Test Store
	err := storage.Store(ctx, session)
	if err != nil {
		t.Fatalf("expected no error storing session, got %v", err)
	}

	// Test Get
	retrieved, err := storage.Get(ctx, session.Token)
	if err != nil {
		t.Fatalf("expected no error getting session, got %v", err)
	}
	if retrieved.ID != session.ID {
		t.Errorf("expected ID %s, got %s", session.ID, retrieved.ID)
	}

	// Test Delete
	err = storage.Delete(ctx, session.Token)
	if err != nil {
		t.Fatalf("expected no error deleting session, got %v", err)
	}

	// Verify deleted
	_, err = storage.Get(ctx, session.Token)
	if err == nil {
		t.Error("expected error after deleting session")
	}
}

// TestRedisSessionStorage_GetByUserID tests getting sessions by user ID.
func TestRedisSessionStorage_GetByUserID(t *testing.T) {
	mockClient := NewMockRedisClient()
	storage := NewRedisSessionStorage(mockClient, "test", 24*time.Hour)
	ctx := context.Background()

	userID := "user-123"

	// Create multiple sessions
	session1 := &Session{
		ID:        "session-1",
		UserID:    userID,
		Token:     "token-1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	session2 := &Session{
		ID:        "session-2",
		UserID:    userID,
		Token:     "token-2",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	storage.Store(ctx, session1)
	storage.Store(ctx, session2)

	// Get sessions by user ID
	sessions, err := storage.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(sessions) != 2 {
		t.Errorf("expected 2 sessions, got %d", len(sessions))
	}
}

// TestRedisSessionStorage_DeleteByUserID tests deleting all user sessions.
func TestRedisSessionStorage_DeleteByUserID(t *testing.T) {
	mockClient := NewMockRedisClient()
	storage := NewRedisSessionStorage(mockClient, "test", 24*time.Hour)
	ctx := context.Background()

	userID := "user-123"

	// Create sessions
	session1 := &Session{
		ID:        "session-1",
		UserID:    userID,
		Token:     "token-1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	session2 := &Session{
		ID:        "session-2",
		UserID:    userID,
		Token:     "token-2",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	storage.Store(ctx, session1)
	storage.Store(ctx, session2)

	// Delete all user sessions
	err := storage.DeleteByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify deleted
	sessions, err := storage.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions after delete, got %d", len(sessions))
	}
}

// TestSessionStorage_Interface tests that both implementations satisfy the interface.
func TestSessionStorage_Interface(t *testing.T) {
	var _ SessionStorage = (*MemorySessionStorage)(nil)
	var _ SessionStorage = (*RedisSessionStorage)(nil)
}

// TestMockRedisClient_Closed tests mock client closed state.
func TestMockRedisClient_Closed(t *testing.T) {
	mockClient := NewMockRedisClient()
	ctx := context.Background()

	// Close client
	err := mockClient.Close()
	if err != nil {
		t.Fatalf("expected no error on close, got %v", err)
	}

	// Operations should fail after close
	err = mockClient.Set(ctx, "key", []byte("value"), 0)
	if err == nil {
		t.Error("expected error on Set after close")
	}

	_, err = mockClient.Get(ctx, "key")
	if err == nil {
		t.Error("expected error on Get after close")
	}
}
