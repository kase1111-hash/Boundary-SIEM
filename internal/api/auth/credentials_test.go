package auth

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// TestPasswordStrengthValidation tests the password strength validation function.
func TestPasswordStrengthValidation(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid strong password",
			password:    "MyP@ssw0rd123",
			expectError: false,
		},
		{
			name:        "too short",
			password:    "Short@1",
			expectError: true,
			errorMsg:    "at least 12 characters",
		},
		{
			name:        "no uppercase",
			password:    "mypassword@123",
			expectError: true,
			errorMsg:    "uppercase letter",
		},
		{
			name:        "no lowercase",
			password:    "MYPASSWORD@123",
			expectError: true,
			errorMsg:    "lowercase letter",
		},
		{
			name:        "no digit",
			password:    "MyPassword@Test",
			expectError: true,
			errorMsg:    "digit",
		},
		{
			name:        "no special character",
			password:    "MyPassword123",
			expectError: true,
			errorMsg:    "special character",
		},
		{
			name:        "exactly 12 characters - valid",
			password:    "MyP@ssw0rd12",
			expectError: false,
		},
		{
			name:        "very long password - valid",
			password:    "MyP@ssw0rd" + strings.Repeat("!", 100),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePasswordStrength(tt.password)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errorMsg)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			}
		})
	}
}

// TestGenerateSecurePassword tests secure password generation.
func TestGenerateSecurePassword(t *testing.T) {
	// Generate multiple passwords to test randomness
	passwords := make(map[string]bool)
	iterations := 10

	for i := 0; i < iterations; i++ {
		password, err := generateSecurePassword(24)
		if err != nil {
			t.Fatalf("failed to generate password: %v", err)
		}

		// Check password meets requirements
		if err := validatePasswordStrength(password); err != nil {
			t.Errorf("generated password failed validation: %v (password: %s)", err, password)
		}

		// Check length
		if len(password) != 24 {
			t.Errorf("expected password length 24, got %d", len(password))
		}

		// Check uniqueness
		if passwords[password] {
			t.Error("generated duplicate password - randomness issue")
		}
		passwords[password] = true
	}

	// Verify all passwords are unique
	if len(passwords) != iterations {
		t.Errorf("expected %d unique passwords, got %d", iterations, len(passwords))
	}
}

// TestGenerateSecurePassword_MinLength tests minimum password length enforcement.
func TestGenerateSecurePassword_MinLength(t *testing.T) {
	// Request very short password - should still get minimum length
	password, err := generateSecurePassword(5)
	if err != nil {
		t.Fatalf("failed to generate password: %v", err)
	}

	if len(password) < 12 {
		t.Errorf("expected password length >= 12, got %d", len(password))
	}

	// Password should still meet all requirements
	if err := validatePasswordStrength(password); err != nil {
		t.Errorf("generated password failed validation: %v", err)
	}
}

// TestInitDefaultUsers_WithConfig tests admin user initialization with explicit config.
func TestInitDefaultUsers_WithConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := &AuthService{
		users:     make(map[string]*User),
		rolePerms: initRolePermissions(),
		logger:    logger,
	}

	config := &AdminConfig{
		Username:              "testadmin",
		Password:              "TestP@ssw0rd123",
		Email:                 "test@example.com",
		RequirePasswordChange: true,
	}

	err := svc.initDefaultUsers(config)
	if err != nil {
		t.Fatalf("initDefaultUsers failed: %v", err)
	}

	// Verify user was created
	user, exists := svc.GetUserByUsername("testadmin")
	if !exists {
		t.Fatal("expected admin user to be created")
	}

	// Verify user properties
	if user.Email != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got %s", user.Email)
	}

	if !user.RequirePasswordChange {
		t.Error("expected RequirePasswordChange to be true")
	}

	// Verify password works
	testUser, err := svc.Authenticate("testadmin", "TestP@ssw0rd123", "default")
	if err != nil {
		t.Errorf("authentication failed: %v", err)
	}
	if testUser == nil {
		t.Error("expected non-nil user after authentication")
	}
}

// TestInitDefaultUsers_WithEnvironmentVariable tests loading password from env var.
func TestInitDefaultUsers_WithEnvironmentVariable(t *testing.T) {
	// Set environment variable
	testPassword := "EnvP@ssw0rd123"
	os.Setenv("BOUNDARY_ADMIN_PASSWORD", testPassword)
	defer os.Unsetenv("BOUNDARY_ADMIN_PASSWORD")

	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := &AuthService{
		users:     make(map[string]*User),
		rolePerms: initRolePermissions(),
		logger:    logger,
	}

	// Initialize with nil config - should read from env
	err := svc.initDefaultUsers(nil)
	if err != nil {
		t.Fatalf("initDefaultUsers failed: %v", err)
	}

	// Verify user was created with env password
	user, err := svc.Authenticate("admin", testPassword, "default")
	if err != nil {
		t.Errorf("authentication with env password failed: %v", err)
	}
	if user == nil {
		t.Error("expected non-nil user")
	}
}

// TestInitDefaultUsers_RandomPassword tests random password generation when no password provided.
func TestInitDefaultUsers_RandomPassword(t *testing.T) {
	// Ensure env var is not set
	os.Unsetenv("BOUNDARY_ADMIN_PASSWORD")

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	svc := &AuthService{
		users:     make(map[string]*User),
		rolePerms: initRolePermissions(),
		logger:    logger,
	}

	// Initialize with nil config and no env var - should generate random password
	err := svc.initDefaultUsers(nil)
	if err != nil {
		t.Fatalf("initDefaultUsers failed: %v", err)
	}

	// Verify user was created
	user, exists := svc.GetUserByUsername("admin")
	if !exists {
		t.Fatal("expected admin user to be created")
	}

	// Verify RequirePasswordChange is set
	if !user.RequirePasswordChange {
		t.Error("expected RequirePasswordChange to be true for random password")
	}

	// Verify password file save was logged (for first-time setup)
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "admin password saved to secure file") {
		t.Error("expected log message about generated password")
	}

	// Note: We can't easily test the actual password here since it's random
	// and only logged once, but we verified RequirePasswordChange is set
}

// TestInitDefaultUsers_WeakPassword tests validation rejects weak passwords.
func TestInitDefaultUsers_WeakPassword(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := &AuthService{
		users:     make(map[string]*User),
		rolePerms: initRolePermissions(),
		logger:    logger,
	}

	config := &AdminConfig{
		Username: "admin",
		Password: "weak", // Too short, missing requirements
		Email:    "admin@example.com",
	}

	err := svc.initDefaultUsers(config)
	if err == nil {
		t.Fatal("expected error for weak password, got nil")
	}

	if !strings.Contains(err.Error(), "password") {
		t.Errorf("expected password-related error, got: %v", err)
	}
}

// TestAdminConfig_Defaults tests default values for AdminConfig.
func TestAdminConfig_Defaults(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := &AuthService{
		users:     make(map[string]*User),
		rolePerms: initRolePermissions(),
		logger:    logger,
	}

	// Initialize with empty config
	config := &AdminConfig{
		Password: "ValidP@ssw0rd123",
	}

	err := svc.initDefaultUsers(config)
	if err != nil {
		t.Fatalf("initDefaultUsers failed: %v", err)
	}

	// Verify defaults were applied
	user, exists := svc.GetUserByUsername("admin")
	if !exists {
		t.Fatal("expected default admin user")
	}

	if user.Email != "admin@boundary-siem.local" {
		t.Errorf("expected default email, got %s", user.Email)
	}
}

// TestRequirePasswordChange_Field tests the RequirePasswordChange field on User.
func TestRequirePasswordChange_Field(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	svc := newTestAuthService(logger)

	admin, exists := svc.GetUserByUsername("admin")
	if !exists {
		t.Fatal("expected admin user")
	}

	// Test admin should not require password change (using known password)
	if admin.RequirePasswordChange {
		t.Error("expected RequirePasswordChange to be false for test admin")
	}

	// Create a user that requires password change
	svc2 := &AuthService{
		users:     make(map[string]*User),
		rolePerms: initRolePermissions(),
		logger:    logger,
	}

	config := &AdminConfig{
		Username:              "admin2",
		Password:              "TempP@ssw0rd123",
		Email:                 "admin2@example.com",
		RequirePasswordChange: true,
	}

	svc2.initDefaultUsers(config)

	admin2, exists := svc2.GetUserByUsername("admin2")
	if !exists {
		t.Fatal("expected admin2 user")
	}

	if !admin2.RequirePasswordChange {
		t.Error("expected RequirePasswordChange to be true")
	}
}
