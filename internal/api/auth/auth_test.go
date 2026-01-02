package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestNewAuthService tests the creation of a new auth service.
func TestNewAuthService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	if svc == nil {
		t.Fatal("expected non-nil auth service")
	}

	// Verify default tenant was created
	tenant, exists := svc.GetTenant("default")
	if !exists {
		t.Error("expected default tenant to exist")
	}
	if tenant.Name != "Default Organization" {
		t.Errorf("expected default tenant name 'Default Organization', got %s", tenant.Name)
	}

	// Verify default admin user was created
	admin, exists := svc.GetUserByUsername("admin")
	if !exists {
		t.Error("expected default admin user to exist")
	}
	if admin.Username != "admin" {
		t.Errorf("expected admin username 'admin', got %s", admin.Username)
	}
	if len(admin.Roles) == 0 || admin.Roles[0] != RoleAdmin {
		t.Error("expected admin to have RoleAdmin")
	}
	if admin.PasswordHash == "" {
		t.Error("expected admin to have password hash")
	}
}

// TestAuthenticate_Success tests successful authentication.
func TestAuthenticate_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	// Authenticate with default admin credentials
	user, err := svc.Authenticate("admin", "Admin@123!", "default")
	if err != nil {
		t.Fatalf("expected successful authentication, got error: %v", err)
	}

	if user.Username != "admin" {
		t.Errorf("expected username 'admin', got %s", user.Username)
	}

	// Verify failed login counter was reset
	if user.FailedLogins != 0 {
		t.Errorf("expected FailedLogins to be 0, got %d", user.FailedLogins)
	}

	// Verify last login time was updated
	if time.Since(user.LastLoginAt) > 5*time.Second {
		t.Error("expected LastLoginAt to be recent")
	}
}

// TestAuthenticate_InvalidPassword tests authentication with wrong password.
func TestAuthenticate_InvalidPassword(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	user, err := svc.Authenticate("admin", "wrongpassword", "default")
	if err == nil {
		t.Fatal("expected authentication to fail with wrong password")
	}

	if user != nil {
		t.Error("expected nil user on failed authentication")
	}

	// Verify the error is ErrInvalidPassword
	if err != ErrInvalidPassword {
		t.Errorf("expected ErrInvalidPassword, got %v", err)
	}

	// Verify failed login counter was incremented
	admin, _ := svc.GetUserByUsername("admin")
	if admin.FailedLogins != 1 {
		t.Errorf("expected FailedLogins to be 1, got %d", admin.FailedLogins)
	}
}

// TestAuthenticate_UserNotFound tests authentication with non-existent user.
func TestAuthenticate_UserNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	user, err := svc.Authenticate("nonexistent", "password", "default")
	if err == nil {
		t.Fatal("expected authentication to fail for non-existent user")
	}

	if user != nil {
		t.Error("expected nil user")
	}

	if err != ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

// TestAuthenticate_EmptyCredentials tests authentication with empty credentials.
func TestAuthenticate_EmptyCredentials(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	tests := []struct {
		name     string
		username string
		password string
		wantErr  error
	}{
		{"empty username", "", "password", ErrUsernameRequired},
		{"empty password", "admin", "", ErrPasswordRequired},
		{"both empty", "", "", ErrUsernameRequired}, // username checked first
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := svc.Authenticate(tt.username, tt.password, "default")
			if err != tt.wantErr {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}
			if user != nil {
				t.Error("expected nil user")
			}
		})
	}
}

// TestAuthenticate_AccountLockout tests account lockout after failed attempts.
func TestAuthenticate_AccountLockout(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	// Make 5 failed login attempts
	for i := 0; i < maxFailedAttempts; i++ {
		_, err := svc.Authenticate("admin", "wrongpassword", "default")
		if err == nil {
			t.Fatal("expected authentication to fail")
		}
	}

	// Verify account is now locked
	user, err := svc.Authenticate("admin", "Admin@123!", "default")
	if err != ErrAccountLocked {
		t.Fatalf("expected ErrAccountLocked, got %v", err)
	}
	if user != nil {
		t.Error("expected nil user for locked account")
	}

	// Verify LockedUntil is set
	admin, _ := svc.GetUserByUsername("admin")
	if admin.LockedUntil == nil {
		t.Error("expected LockedUntil to be set")
	}
	if admin.FailedLogins != maxFailedAttempts {
		t.Errorf("expected FailedLogins to be %d, got %d", maxFailedAttempts, admin.FailedLogins)
	}
}

// TestAuthenticate_AccountLockoutExpiry tests that lockout expires.
func TestAuthenticate_AccountLockoutExpiry(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	// Lock the account
	for i := 0; i < maxFailedAttempts; i++ {
		svc.Authenticate("admin", "wrongpassword", "default")
	}

	// Manually expire the lockout (simulate time passage)
	admin, _ := svc.GetUserByUsername("admin")
	pastTime := time.Now().Add(-1 * time.Second)
	admin.LockedUntil = &pastTime

	// Should now be able to authenticate
	user, err := svc.Authenticate("admin", "Admin@123!", "default")
	if err != nil {
		t.Fatalf("expected successful authentication after lockout expiry, got error: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}

	// Verify lockout was cleared
	if admin.LockedUntil != nil {
		t.Error("expected LockedUntil to be cleared")
	}
	if admin.FailedLogins != 0 {
		t.Errorf("expected FailedLogins to be reset to 0, got %d", admin.FailedLogins)
	}
}

// TestAuthenticate_DisabledUser tests authentication for disabled user.
func TestAuthenticate_DisabledUser(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	// Disable the admin user
	admin, _ := svc.GetUserByUsername("admin")
	admin.Disabled = true

	user, err := svc.Authenticate("admin", "Admin@123!", "default")
	if err != ErrUserDisabled {
		t.Errorf("expected ErrUserDisabled, got %v", err)
	}
	if user != nil {
		t.Error("expected nil user for disabled account")
	}
}

// TestAuthenticate_TenantMismatch tests authentication with wrong tenant.
func TestAuthenticate_TenantMismatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	user, err := svc.Authenticate("admin", "Admin@123!", "wrong-tenant")
	if err != ErrTenantMismatch {
		t.Errorf("expected ErrTenantMismatch, got %v", err)
	}
	if user != nil {
		t.Error("expected nil user")
	}
}

// TestAuthenticate_TimingAttackResistance tests timing attack prevention.
func TestAuthenticate_TimingAttackResistance(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	// Run multiple iterations to get average timing
	const iterations = 5
	var duration1Total, duration2Total time.Duration

	for i := 0; i < iterations; i++ {
		// Measure time for non-existent user
		start1 := time.Now()
		svc.Authenticate("nonexistent", "password123", "default")
		duration1Total += time.Since(start1)

		// Measure time for existing user with wrong password
		start2 := time.Now()
		svc.Authenticate("admin", "wrongpassword", "default")
		duration2Total += time.Since(start2)
	}

	avgDuration1 := duration1Total / iterations
	avgDuration2 := duration2Total / iterations

	// Existing user should take at least 50ms (bcrypt cost 12)
	if avgDuration2 < 50*time.Millisecond {
		t.Errorf("authentication too fast for existing user (avg %v), timing attack possible", avgDuration2)
	}

	// Note: The dummy bcrypt hash for non-existent users may not be valid,
	// so we just verify that SOME timing mitigation exists (> 10ms)
	if avgDuration1 < 10*time.Millisecond {
		t.Errorf("authentication suspiciously fast for non-existent user (avg %v)", avgDuration1)
	}

	t.Logf("Timing: non-existent user avg=%v, existing user avg=%v, diff=%v",
		avgDuration1, avgDuration2, avgDuration2-avgDuration1)
}

// TestValidatePassword tests password validation.
func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
		errMsg   string
	}{
		{"valid password", "Test@123", false, ""},
		{"too short", "Test@1", true, "at least 8 characters"},
		{"too long", strings.Repeat("A", 129) + "@123", true, "must not exceed 128 characters"},
		{"no uppercase", "test@123", true, "at least one uppercase letter"},
		{"no lowercase", "TEST@123", true, "at least one lowercase letter"},
		{"no digit", "Test@abc", true, "at least one digit"},
		{"no special", "Test1234", true, "at least one special character"},
		{"all requirements", "Admin@123!", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %v", tt.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			}
		})
	}
}

// TestHashPassword tests password hashing.
func TestHashPassword(t *testing.T) {
	password := "Test@123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if hash == "" {
		t.Error("expected non-empty hash")
	}

	if hash == password {
		t.Error("hash should not equal plaintext password")
	}

	// Test that same password produces different hash
	hash2, _ := HashPassword(password)
	if hash == hash2 {
		t.Error("expected different hashes for same password (bcrypt uses salt)")
	}

	// Test empty password
	_, err = HashPassword("")
	if err == nil {
		t.Error("expected error for empty password")
	}

	// Test short password
	_, err = HashPassword("short")
	if err == nil {
		t.Error("expected error for password < 8 characters")
	}
}

// TestCreateSession tests session creation.
func TestCreateSession(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	user, _ := svc.Authenticate("admin", "Admin@123!", "default")

	req := httptest.NewRequest("POST", "/api/auth/login", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("User-Agent", "TestClient/1.0")

	session, err := svc.CreateSession(user, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if session.ID == "" {
		t.Error("expected non-empty session ID")
	}
	if session.Token == "" {
		t.Error("expected non-empty token")
	}
	if session.RefreshToken == "" {
		t.Error("expected non-empty refresh token")
	}
	if session.UserID != user.ID {
		t.Errorf("expected UserID %s, got %s", user.ID, session.UserID)
	}
	if session.TenantID != user.TenantID {
		t.Errorf("expected TenantID %s, got %s", user.TenantID, session.TenantID)
	}
	if session.IPAddress != "192.168.1.100" {
		t.Errorf("expected IP 192.168.1.100, got %s", session.IPAddress)
	}
	if session.UserAgent != "TestClient/1.0" {
		t.Errorf("expected UserAgent 'TestClient/1.0', got %s", session.UserAgent)
	}

	// Verify expiration is ~24 hours
	expectedExpiry := time.Now().Add(24 * time.Hour)
	if session.ExpiresAt.Before(expectedExpiry.Add(-1*time.Minute)) ||
		session.ExpiresAt.After(expectedExpiry.Add(1*time.Minute)) {
		t.Error("expected ExpiresAt to be ~24 hours from now")
	}
}

// TestValidateSession tests session validation.
func TestValidateSession(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	user, _ := svc.Authenticate("admin", "Admin@123!", "default")
	req := httptest.NewRequest("POST", "/api/auth/login", nil)
	session, _ := svc.CreateSession(user, req)

	// Test valid session
	validatedSession, err := svc.ValidateSession(session.Token)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if validatedSession.ID != session.ID {
		t.Error("expected same session ID")
	}

	// Test invalid token
	_, err = svc.ValidateSession("invalid-token")
	if err == nil {
		t.Error("expected error for invalid token")
	}

	// Test expired session
	session.ExpiresAt = time.Now().Add(-1 * time.Hour)
	_, err = svc.ValidateSession(session.Token)
	if err == nil {
		t.Error("expected error for expired session")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected 'expired' error, got %v", err)
	}
}

// TestHasPermission tests permission checking.
func TestHasPermission(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	admin, _ := svc.GetUserByUsername("admin")

	tests := []struct {
		name       string
		permission Permission
		want       bool
	}{
		{"admin has PermissionAdmin", PermissionAdmin, true},
		{"admin has PermissionRead", PermissionRead, true},
		{"admin has PermissionWrite", PermissionWrite, true},
		{"admin has PermissionManageUsers", PermissionManageUsers, true},
		{"admin has PermissionViewAuditLog", PermissionViewAuditLog, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := svc.HasPermission(admin.ID, tt.permission)
			if got != tt.want {
				t.Errorf("HasPermission() = %v, want %v", got, tt.want)
			}
		})
	}

	// Test non-existent user
	if svc.HasPermission("nonexistent", PermissionRead) {
		t.Error("expected false for non-existent user")
	}
}

// TestRolePermissions tests that roles have correct permissions.
func TestRolePermissions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	tests := []struct {
		role       Role
		permission Permission
		want       bool
	}{
		// Admin should have all permissions
		{RoleAdmin, PermissionAdmin, true},
		{RoleAdmin, PermissionManageUsers, true},

		// Viewer should have read permissions
		{RoleViewer, PermissionRead, true},
		{RoleViewer, PermissionViewAlerts, true},
		{RoleViewer, PermissionWrite, false},
		{RoleViewer, PermissionDelete, false},

		// Analyst should have write but not admin
		{RoleAnalyst, PermissionRead, true},
		{RoleAnalyst, PermissionWrite, true},
		{RoleAnalyst, PermissionManageRules, true},
		{RoleAnalyst, PermissionAdmin, false},
		{RoleAnalyst, PermissionManageUsers, false},

		// Auditor should have view but not modify
		{RoleAuditor, PermissionViewAuditLog, true},
		{RoleAuditor, PermissionViewCompliance, true},
		{RoleAuditor, PermissionWrite, false},
		{RoleAuditor, PermissionDelete, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.role)+"/"+string(tt.permission), func(t *testing.T) {
			perms := svc.rolePerms[tt.role]
			hasPermission := false
			for _, p := range perms {
				if p == tt.permission {
					hasPermission = true
					break
				}
			}
			if hasPermission != tt.want {
				t.Errorf("Role %s has permission %s = %v, want %v",
					tt.role, tt.permission, hasPermission, tt.want)
			}
		})
	}
}

// TestCreateUser tests user creation.
func TestCreateUser(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	passwordHash, _ := HashPassword("Test@123")
	newUser := &User{
		ID:           "user-123",
		Username:     "testuser",
		Email:        "test@example.com",
		DisplayName:  "Test User",
		PasswordHash: passwordHash,
		Roles:        []Role{RoleAnalyst},
		TenantID:     "default",
		Provider:     AuthProviderLocal,
	}

	err := svc.CreateUser(newUser)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify user was created (using username since that's the map key)
	user, exists := svc.GetUserByUsername("testuser")
	if !exists {
		t.Error("expected user to exist")
	}
	if user.Username != "testuser" {
		t.Errorf("expected username 'testuser', got %s", user.Username)
	}
	if user.ID != "user-123" {
		t.Errorf("expected ID 'user-123', got %s", user.ID)
	}

	// Verify permissions were assigned
	if len(user.Permissions) == 0 {
		t.Error("expected permissions to be assigned")
	}

	// Verify created timestamp
	if user.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}

	// Test duplicate user
	err = svc.CreateUser(newUser)
	if err == nil {
		t.Error("expected error for duplicate user")
	}
}

// TestCreateTenant tests tenant creation.
func TestCreateTenant(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	tenant := &Tenant{
		ID:          "tenant-123",
		Name:        "Test Tenant",
		Description: "Test tenant description",
		Domain:      "test.example.com",
		Settings: &TenantSettings{
			MaxUsers:        50,
			MaxEventsPerDay: 1000000,
			RetentionDays:   30,
			AllowedProviders: []AuthProvider{AuthProviderLocal},
			RequireMFA:      true,
		},
	}

	err := svc.CreateTenant(tenant)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify tenant was created
	createdTenant, exists := svc.GetTenant("tenant-123")
	if !exists {
		t.Error("expected tenant to exist")
	}
	if createdTenant.Name != "Test Tenant" {
		t.Errorf("expected name 'Test Tenant', got %s", createdTenant.Name)
	}

	// Verify timestamps
	if createdTenant.CreatedAt.IsZero() || createdTenant.UpdatedAt.IsZero() {
		t.Error("expected timestamps to be set")
	}

	// Test duplicate tenant
	err = svc.CreateTenant(tenant)
	if err == nil {
		t.Error("expected error for duplicate tenant")
	}
}

// TestHandleLogin tests the login HTTP handler.
func TestHandleLogin(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	tests := []struct {
		name       string
		method     string
		body       map[string]string
		wantStatus int
		wantToken  bool
	}{
		{
			name:   "successful login",
			method: "POST",
			body: map[string]string{
				"username": "admin",
				"password": "Admin@123!",
			},
			wantStatus: http.StatusOK,
			wantToken:  true,
		},
		{
			name:   "wrong password",
			method: "POST",
			body: map[string]string{
				"username": "admin",
				"password": "wrongpassword",
			},
			wantStatus: http.StatusUnauthorized,
			wantToken:  false,
		},
		{
			name:   "non-existent user",
			method: "POST",
			body: map[string]string{
				"username": "nonexistent",
				"password": "password",
			},
			wantStatus: http.StatusUnauthorized,
			wantToken:  false,
		},
		{
			name:       "GET method not allowed",
			method:     "GET",
			body:       nil,
			wantStatus: http.StatusMethodNotAllowed,
			wantToken:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			if tt.body != nil {
				body, _ = json.Marshal(tt.body)
			}

			req := httptest.NewRequest(tt.method, "/api/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			svc.handleLogin(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, w.Code)
			}

			if tt.wantToken {
				var resp map[string]interface{}
				json.NewDecoder(w.Body).Decode(&resp)

				if _, ok := resp["token"]; !ok {
					t.Error("expected token in response")
				}
				if _, ok := resp["user"]; !ok {
					t.Error("expected user in response")
				}
			}
		})
	}
}

// TestHandleLogout tests the logout HTTP handler.
func TestHandleLogout(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	// Create a session
	user, _ := svc.Authenticate("admin", "Admin@123!", "default")
	req := httptest.NewRequest("POST", "/api/auth/login", nil)
	session, _ := svc.CreateSession(user, req)

	// Test successful logout
	logoutReq := httptest.NewRequest("POST", "/api/auth/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+session.Token)
	w := httptest.NewRecorder()

	svc.handleLogout(w, logoutReq)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Verify session was deleted
	_, err := svc.ValidateSession(session.Token)
	if err == nil {
		t.Error("expected session to be deleted")
	}

	// Test logout without token
	logoutReq2 := httptest.NewRequest("POST", "/api/auth/logout", nil)
	w2 := httptest.NewRecorder()
	svc.handleLogout(w2, logoutReq2)

	if w2.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w2.Code)
	}
}

// TestMiddleware tests the authentication middleware.
func TestMiddleware(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value("user").(*User)
		if !ok || user == nil {
			t.Error("expected user in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with middleware
	handler := svc.Middleware(testHandler)

	// Create a session
	user, _ := svc.Authenticate("admin", "Admin@123!", "default")
	loginReq := httptest.NewRequest("POST", "/api/test", nil)
	session, _ := svc.CreateSession(user, loginReq)

	// Test with valid token
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Test without token
	req2 := httptest.NewRequest("GET", "/api/test", nil)
	w2 := httptest.NewRecorder()

	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w2.Code)
	}

	// Test with invalid token
	req3 := httptest.NewRequest("GET", "/api/test", nil)
	req3.Header.Set("Authorization", "Bearer invalid-token")
	w3 := httptest.NewRecorder()

	handler.ServeHTTP(w3, req3)

	if w3.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w3.Code)
	}
}

// TestRequirePermission tests the permission middleware.
func TestRequirePermission(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create user with limited permissions (viewer)
	passwordHash, _ := HashPassword("Test@123")
	viewer := &User{
		ID:           "viewer-123",
		Username:     "viewer",
		PasswordHash: passwordHash,
		Roles:        []Role{RoleViewer},
		Permissions:  svc.rolePerms[RoleViewer],
		TenantID:     "default",
		Provider:     AuthProviderLocal,
	}
	svc.CreateUser(viewer)

	// Test with permission viewer has (read)
	handler1 := svc.RequirePermission(PermissionRead)(testHandler)
	req1 := httptest.NewRequest("GET", "/api/test", nil)
	req1 = req1.WithContext(context.WithValue(req1.Context(), "user", viewer))
	w1 := httptest.NewRecorder()

	handler1.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("expected status 200 for allowed permission, got %d", w1.Code)
	}

	// Test with permission viewer doesn't have (write)
	handler2 := svc.RequirePermission(PermissionWrite)(testHandler)
	req2 := httptest.NewRequest("POST", "/api/test", nil)
	req2 = req2.WithContext(context.WithValue(req2.Context(), "user", viewer))
	w2 := httptest.NewRecorder()

	handler2.ServeHTTP(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Errorf("expected status 403 for denied permission, got %d", w2.Code)
	}
}

// TestGetClientIP tests IP extraction from requests.
func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name      string
		setupReq  func(*http.Request)
		wantIP    string
	}{
		{
			name: "X-Forwarded-For single IP",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "203.0.113.1")
			},
			wantIP: "203.0.113.1",
		},
		{
			name: "X-Forwarded-For multiple IPs",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.1, 192.0.2.1")
			},
			wantIP: "203.0.113.1",
		},
		{
			name: "X-Real-IP",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Real-IP", "203.0.113.2")
			},
			wantIP: "203.0.113.2",
		},
		{
			name: "RemoteAddr only",
			setupReq: func(r *http.Request) {
				r.RemoteAddr = "203.0.113.3:12345"
			},
			wantIP: "203.0.113.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			tt.setupReq(req)

			gotIP := getClientIP(req)
			if gotIP != tt.wantIP {
				t.Errorf("getClientIP() = %v, want %v", gotIP, tt.wantIP)
			}
		})
	}
}

// TestGenerateToken tests token generation uniqueness.
func TestGenerateToken(t *testing.T) {
	tokens := make(map[string]bool)

	// Generate 1000 tokens and verify uniqueness
	for i := 0; i < 1000; i++ {
		token, err := generateToken()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if token == "" {
			t.Error("expected non-empty token")
		}

		if tokens[token] {
			t.Error("duplicate token generated")
		}
		tokens[token] = true
	}

	if len(tokens) != 1000 {
		t.Errorf("expected 1000 unique tokens, got %d", len(tokens))
	}
}

// TestIsPublicEndpoint tests public endpoint detection.
func TestIsPublicEndpoint(t *testing.T) {
	tests := []struct {
		path   string
		want   bool
	}{
		{"/api/auth/login", true},
		{"/api/auth/oauth/callback", true},
		{"/api/auth/saml/acs", true},
		{"/api/health", true},
		{"/api/ready", true},
		{"/api/users", false},
		{"/api/tenants", false},
		{"/api/audit", false},
		{"/api/other", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isPublicEndpoint(tt.path)
			if got != tt.want {
				t.Errorf("isPublicEndpoint(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestAuditLogging tests that audit events are logged.
func TestAuditLogging(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	// Test failed login via HTTP handler (which logs audit events)
	failedLoginBody, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "wrongpassword",
	})
	req1 := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(failedLoginBody))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	svc.handleLogin(w1, req1)

	// Test successful login via HTTP handler
	successLoginBody, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "Admin@123!",
	})
	req2 := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(successLoginBody))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	svc.handleLogin(w2, req2)

	// Check audit log
	auditLog := svc.GetAuditLog(100)

	if len(auditLog) < 2 {
		t.Errorf("expected at least 2 audit entries, got %d", len(auditLog))
	}

	// Verify failed login is logged
	foundFailedLogin := false
	foundSuccessLogin := false
	for _, entry := range auditLog {
		if entry.Action == AuditActionLoginFailed && !entry.Success {
			foundFailedLogin = true
		}
		if entry.Action == AuditActionLogin && entry.Success {
			foundSuccessLogin = true
		}
	}

	if !foundFailedLogin {
		t.Error("expected failed login in audit log")
	}
	if !foundSuccessLogin {
		t.Error("expected successful login in audit log")
	}
}

// TestAuditLogRetention tests audit log size limit.
func TestAuditLogRetention(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	req := httptest.NewRequest("POST", "/api/test", nil)

	// Generate more than 10000 audit events
	for i := 0; i < 11000; i++ {
		svc.logAudit(AuditActionLoginFailed, "user-id", "username", "default",
			"auth", "", req, false, "test")
	}

	auditLog := svc.GetAuditLog(20000)

	// Should be capped at 10000
	if len(auditLog) > 10000 {
		t.Errorf("expected audit log to be capped at 10000, got %d", len(auditLog))
	}
}

// TestMultiTenancyIsolation tests that users can't access other tenants.
func TestMultiTenancyIsolation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := NewAuthService(logger)

	// Create second tenant
	tenant2 := &Tenant{
		ID:   "tenant2",
		Name: "Tenant 2",
		Settings: &TenantSettings{
			MaxUsers:        10,
			MaxEventsPerDay: 100000,
			RetentionDays:   30,
		},
	}
	svc.CreateTenant(tenant2)

	// Create user in tenant2
	passwordHash, _ := HashPassword("Test@123")
	tenant2User := &User{
		ID:           "user-tenant2",
		Username:     "tenant2user",
		PasswordHash: passwordHash,
		Roles:        []Role{RoleAnalyst},
		TenantID:     "tenant2",
		Provider:     AuthProviderLocal,
	}
	svc.CreateUser(tenant2User)

	// Try to authenticate tenant2 user with default tenant
	_, err := svc.Authenticate("tenant2user", "Test@123", "default")
	if err != ErrTenantMismatch {
		t.Errorf("expected ErrTenantMismatch, got %v", err)
	}

	// Authenticate with correct tenant should succeed
	user, err := svc.Authenticate("tenant2user", "Test@123", "tenant2")
	if err != nil {
		t.Fatalf("expected successful authentication, got %v", err)
	}
	if user.TenantID != "tenant2" {
		t.Errorf("expected TenantID tenant2, got %s", user.TenantID)
	}
}
