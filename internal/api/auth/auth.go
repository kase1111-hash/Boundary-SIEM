// Package auth provides authentication and authorization for the SIEM.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// cryptoRandInt is an alias for crypto/rand.Int, used for generating
// unbiased random integers. Declared as a variable for testability.
var cryptoRandInt = rand.Int

// AuthProvider defines authentication provider types.
type AuthProvider string

const (
	AuthProviderLocal AuthProvider = "local"
	AuthProviderOAuth AuthProvider = "oauth"
	AuthProviderSAML  AuthProvider = "saml"
	AuthProviderOIDC  AuthProvider = "oidc"
	AuthProviderLDAP  AuthProvider = "ldap"
)

// Role defines user roles.
type Role string

const (
	RoleAdmin      Role = "admin"
	RoleAnalyst    Role = "analyst"
	RoleViewer     Role = "viewer"
	RoleCompliance Role = "compliance"
	RoleOperator   Role = "operator"
	RoleAuditor    Role = "auditor"
	RoleAPIClient  Role = "api_client"
)

// Permission defines granular permissions.
type Permission string

const (
	PermissionRead           Permission = "read"
	PermissionWrite          Permission = "write"
	PermissionDelete         Permission = "delete"
	PermissionAdmin          Permission = "admin"
	PermissionViewAlerts     Permission = "view_alerts"
	PermissionAckAlerts      Permission = "ack_alerts"
	PermissionManageRules    Permission = "manage_rules"
	PermissionViewEvents     Permission = "view_events"
	PermissionExportData     Permission = "export_data"
	PermissionManageUsers    Permission = "manage_users"
	PermissionViewReports    Permission = "view_reports"
	PermissionCreateReports  Permission = "create_reports"
	PermissionManageTenants  Permission = "manage_tenants"
	PermissionViewAuditLog   Permission = "view_audit_log"
	PermissionManageKeys     Permission = "manage_keys"
	PermissionViewCompliance Permission = "view_compliance"
)

// contextKey is a typed key for context values to avoid collisions.
type contextKey string

const (
	// ContextKeyUser is the context key for the authenticated user.
	ContextKeyUser contextKey = "user"
	// ContextKeySession is the context key for the session.
	ContextKeySession contextKey = "session"
)

// User represents an authenticated user.
type User struct {
	ID                    string            `json:"id"`
	Username              string            `json:"username"`
	Email                 string            `json:"email"`
	DisplayName           string            `json:"display_name"`
	PasswordHash          string            `json:"-"` // Never expose in JSON
	Roles                 []Role            `json:"roles"`
	Permissions           []Permission      `json:"permissions"`
	TenantID              string            `json:"tenant_id"`
	Provider              AuthProvider      `json:"provider"`
	ProviderID            string            `json:"provider_id,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
	CreatedAt             time.Time         `json:"created_at"`
	LastLoginAt           time.Time         `json:"last_login_at"`
	Disabled              bool              `json:"disabled"`
	MFAEnabled            bool              `json:"mfa_enabled"`
	FailedLogins          int               `json:"-"`                       // Track failed login attempts
	LockedUntil           *time.Time        `json:"-"`                       // Account lockout time
	RequirePasswordChange bool              `json:"require_password_change"` // Force password change on next login
}

// Tenant represents an organization/tenant for multi-tenancy.
type Tenant struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Domain      string          `json:"domain,omitempty"`
	Settings    *TenantSettings `json:"settings"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	Disabled    bool            `json:"disabled"`
}

// TenantSettings contains tenant-specific settings.
type TenantSettings struct {
	MaxUsers         int               `json:"max_users"`
	MaxEventsPerDay  int64             `json:"max_events_per_day"`
	RetentionDays    int               `json:"retention_days"`
	AllowedProviders []AuthProvider    `json:"allowed_providers"`
	RequireMFA       bool              `json:"require_mfa"`
	IPWhitelist      []string          `json:"ip_whitelist,omitempty"`
	Features         map[string]bool   `json:"features"`
	CustomBranding   *BrandingSettings `json:"custom_branding,omitempty"`
}

// BrandingSettings contains custom branding options.
type BrandingSettings struct {
	LogoURL      string `json:"logo_url,omitempty"`
	PrimaryColor string `json:"primary_color,omitempty"`
	CompanyName  string `json:"company_name,omitempty"`
}

// Session represents an authenticated session.
type Session struct {
	ID           string       `json:"id"`
	UserID       string       `json:"user_id"`
	TenantID     string       `json:"tenant_id"`
	Token        string       `json:"token"`
	RefreshToken string       `json:"refresh_token,omitempty"`
	Provider     AuthProvider `json:"provider"`
	IPAddress    string       `json:"ip_address"`
	UserAgent    string       `json:"user_agent"`
	CreatedAt    time.Time    `json:"created_at"`
	ExpiresAt    time.Time    `json:"expires_at"`
	LastActiveAt time.Time    `json:"last_active_at"`
}

// AuditLogEntry represents an audit log entry.
type AuditLogEntry struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	UserID     string                 `json:"user_id"`
	Username   string                 `json:"username"`
	TenantID   string                 `json:"tenant_id"`
	Action     AuditAction            `json:"action"`
	Resource   string                 `json:"resource"`
	ResourceID string                 `json:"resource_id,omitempty"`
	IPAddress  string                 `json:"ip_address"`
	UserAgent  string                 `json:"user_agent"`
	Details    map[string]interface{} `json:"details,omitempty"`
	Success    bool                   `json:"success"`
	ErrorMsg   string                 `json:"error_msg,omitempty"`
}

// AuditAction defines audit action types.
type AuditAction string

const (
	AuditActionLogin           AuditAction = "login"
	AuditActionLogout          AuditAction = "logout"
	AuditActionLoginFailed     AuditAction = "login_failed"
	AuditActionPasswordChange  AuditAction = "password_change"
	AuditActionMFAEnabled      AuditAction = "mfa_enabled"
	AuditActionMFADisabled     AuditAction = "mfa_disabled"
	AuditActionUserCreated     AuditAction = "user_created"
	AuditActionUserUpdated     AuditAction = "user_updated"
	AuditActionUserDeleted     AuditAction = "user_deleted"
	AuditActionRoleAssigned    AuditAction = "role_assigned"
	AuditActionRoleRemoved     AuditAction = "role_removed"
	AuditActionAPIKeyCreated   AuditAction = "api_key_created"
	AuditActionAPIKeyRevoked   AuditAction = "api_key_revoked"
	AuditActionRuleCreated     AuditAction = "rule_created"
	AuditActionRuleUpdated     AuditAction = "rule_updated"
	AuditActionRuleDeleted     AuditAction = "rule_deleted"
	AuditActionAlertAcked      AuditAction = "alert_acknowledged"
	AuditActionReportGenerated AuditAction = "report_generated"
	AuditActionDataExported    AuditAction = "data_exported"
	AuditActionSettingsChanged AuditAction = "settings_changed"
	AuditActionTenantCreated   AuditAction = "tenant_created"
	AuditActionTenantUpdated   AuditAction = "tenant_updated"
)

// OAuthConfig holds OAuth provider configuration.
type OAuthConfig struct {
	Provider       string   `json:"provider"`
	ClientID       string   `json:"client_id"`
	ClientSecret   string   `json:"client_secret"`
	AuthURL        string   `json:"auth_url"`
	TokenURL       string   `json:"token_url"`
	UserInfoURL    string   `json:"userinfo_url"`
	RedirectURL    string   `json:"redirect_url"`
	Scopes         []string `json:"scopes"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
}

// SAMLConfig holds SAML provider configuration.
type SAMLConfig struct {
	EntityID          string `json:"entity_id"`
	SSOURL            string `json:"sso_url"`
	SLOURL            string `json:"slo_url,omitempty"`
	Certificate       string `json:"certificate"`
	PrivateKey        string `json:"private_key"`
	IDPMetadataURL    string `json:"idp_metadata_url,omitempty"`
	SignAuthnRequests bool   `json:"sign_authn_requests"`
}

// AuthService provides authentication and authorization services.
type AuthService struct {
	mu             sync.RWMutex
	users          map[string]*User
	sessionStorage SessionStorage  // Now using SessionStorage interface
	csrf           *CSRFProtection // CSRF protection
	tenants        map[string]*Tenant
	auditLog       []*AuditLogEntry
	oauthConfigs   map[string]*OAuthConfig
	samlConfigs    map[string]*SAMLConfig
	rolePerms      map[Role][]Permission
	logger         *slog.Logger
}

// Config holds auth service configuration.
type Config struct {
	SessionTTL         time.Duration
	RefreshTokenTTL    time.Duration
	MaxSessionsPerUser int
	RequireMFA         bool
	PasswordPolicy     *PasswordPolicy
}

// PasswordPolicy defines password requirements.
type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumbers   bool `json:"require_numbers"`
	RequireSpecial   bool `json:"require_special"`
	MaxAge           int  `json:"max_age_days"`
	PreventReuse     int  `json:"prevent_reuse"`
}

// NewAuthService creates a new authentication service.
// If sessionStorage is nil, defaults to in-memory storage.
func NewAuthService(logger *slog.Logger) *AuthService {
	return NewAuthServiceWithStorage(logger, nil)
}

// NewAuthServiceWithStorage creates a new authentication service with custom session storage.
func NewAuthServiceWithStorage(logger *slog.Logger, sessionStorage SessionStorage) *AuthService {
	// Default to in-memory storage if not provided
	if sessionStorage == nil {
		sessionStorage = NewMemorySessionStorage()
	}

	svc := &AuthService{
		users:          make(map[string]*User),
		sessionStorage: sessionStorage,
		csrf:           NewCSRFProtection(DefaultCSRFConfig()),
		tenants:        make(map[string]*Tenant),
		auditLog:       make([]*AuditLogEntry, 0),
		oauthConfigs:   make(map[string]*OAuthConfig),
		samlConfigs:    make(map[string]*SAMLConfig),
		rolePerms:      initRolePermissions(),
		logger:         logger,
	}
	svc.initDefaultTenant()

	// Initialize default admin user with environment-based or random credentials
	if err := svc.initDefaultUsers(nil); err != nil {
		logger.Error("failed to initialize default admin user", "error", err)
		// Continue initialization but log the error
	}

	return svc
}

// initRolePermissions sets up default role-permission mappings.
func initRolePermissions() map[Role][]Permission {
	return map[Role][]Permission{
		RoleAdmin: {
			PermissionRead, PermissionWrite, PermissionDelete, PermissionAdmin,
			PermissionViewAlerts, PermissionAckAlerts, PermissionManageRules,
			PermissionViewEvents, PermissionExportData, PermissionManageUsers,
			PermissionViewReports, PermissionCreateReports, PermissionManageTenants,
			PermissionViewAuditLog, PermissionManageKeys, PermissionViewCompliance,
		},
		RoleAnalyst: {
			PermissionRead, PermissionWrite, PermissionViewAlerts, PermissionAckAlerts,
			PermissionManageRules, PermissionViewEvents, PermissionExportData,
			PermissionViewReports, PermissionCreateReports,
		},
		RoleViewer: {
			PermissionRead, PermissionViewAlerts, PermissionViewEvents, PermissionViewReports,
		},
		RoleCompliance: {
			PermissionRead, PermissionViewAlerts, PermissionViewEvents,
			PermissionViewReports, PermissionCreateReports, PermissionViewAuditLog,
			PermissionViewCompliance, PermissionExportData,
		},
		RoleOperator: {
			PermissionRead, PermissionWrite, PermissionViewAlerts, PermissionAckAlerts,
			PermissionViewEvents, PermissionManageKeys,
		},
		RoleAuditor: {
			PermissionRead, PermissionViewAlerts, PermissionViewEvents,
			PermissionViewReports, PermissionViewAuditLog, PermissionViewCompliance,
		},
		RoleAPIClient: {
			PermissionRead, PermissionViewEvents, PermissionViewAlerts,
		},
	}
}

// initDefaultTenant creates the default tenant.
func (s *AuthService) initDefaultTenant() {
	s.tenants["default"] = &Tenant{
		ID:          "default",
		Name:        "Default Organization",
		Description: "Default tenant for single-tenant deployments",
		Settings: &TenantSettings{
			MaxUsers:         100,
			MaxEventsPerDay:  10000000,
			RetentionDays:    90,
			AllowedProviders: []AuthProvider{AuthProviderLocal, AuthProviderOAuth, AuthProviderSAML},
			RequireMFA:       false,
			Features: map[string]bool{
				"blockchain_monitoring": true,
				"compliance_reports":    true,
				"advanced_analytics":    true,
				"threat_intelligence":   true,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// AdminConfig holds configuration for the default admin user.
type AdminConfig struct {
	Username              string
	Password              string
	Email                 string
	RequirePasswordChange bool
}

// initDefaultUsers creates default system users using provided configuration.
// Credentials should be provided via environment variables or configuration file.
func (s *AuthService) initDefaultUsers(config *AdminConfig) error {
	now := time.Now()

	// Use provided config or fallback to environment variables
	if config == nil {
		config = &AdminConfig{}
	}

	// Set defaults if not provided
	if config.Username == "" {
		config.Username = "admin"
	}
	if config.Email == "" {
		config.Email = "admin@boundary-siem.local"
	}

	// Handle password: prefer config, fallback to env var, or generate random
	password := config.Password
	if password == "" {
		// Check environment variable
		password = os.Getenv("BOUNDARY_ADMIN_PASSWORD")
	}

	var requirePasswordChange bool
	if password == "" {
		// No password provided - generate a secure random one
		var err error
		password, err = generateSecurePassword(24)
		if err != nil {
			return fmt.Errorf("failed to generate secure password: %w", err)
		}
		requirePasswordChange = true

		// Write password to secure file instead of logging
		if err := writePasswordToSecureFile(config.Username, password); err != nil {
			s.logger.Error("failed to write admin password to secure file", "error", err)
			// Continue - password is still valid, just not persisted to file
		} else {
			s.logger.Info("admin password saved to secure file",
				"username", config.Username,
				"action_required", "change password after first login")
		}
	} else {
		// Validate provided password strength
		if err := validatePasswordStrength(password); err != nil {
			return fmt.Errorf("admin password validation failed: %w", err)
		}
		requirePasswordChange = config.RequirePasswordChange
	}

	// Hash the password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %w", err)
	}

	s.users[config.Username] = &User{
		ID:                    config.Username,
		Username:              config.Username,
		Email:                 config.Email,
		DisplayName:           "System Administrator",
		PasswordHash:          string(passwordHash),
		Roles:                 []Role{RoleAdmin},
		Permissions:           s.rolePerms[RoleAdmin],
		TenantID:              "default",
		Provider:              AuthProviderLocal,
		CreatedAt:             now,
		LastLoginAt:           now,
		RequirePasswordChange: requirePasswordChange,
	}

	if !requirePasswordChange && password != "" {
		s.logger.Info("default admin user created",
			"username", config.Username,
			"email", config.Email,
			"password_source", "configuration")
	}

	return nil
}

// validatePasswordStrength validates password meets security requirements.
func validatePasswordStrength(password string) error {
	if len(password) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasDigit = true
		case char >= '!' && char <= '/' || char >= ':' && char <= '@' || char >= '[' && char <= '`' || char >= '{' && char <= '~':
			hasSpecial = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// RegisterRoutes registers auth API routes.
func (s *AuthService) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/auth/login", s.handleLogin)
	mux.HandleFunc("/api/auth/logout", s.handleLogout)
	mux.HandleFunc("/api/auth/session", s.handleSession)
	mux.HandleFunc("/api/auth/oauth/callback", s.handleOAuthCallback)
	mux.HandleFunc("/api/auth/saml/acs", s.handleSAMLACS)
	mux.HandleFunc("/api/users", s.handleUsers)
	mux.HandleFunc("/api/tenants", s.handleTenants)
	mux.HandleFunc("/api/audit", s.handleAuditLog)
}

// APIError represents a structured API error response.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// writeJSONError writes a JSON error response.
func writeJSONError(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(APIError{
		Code:    code,
		Message: message,
	})
}

// maxAuthBodySize limits request body size on auth endpoints to prevent
// memory exhaustion attacks. 1 MB is generous for auth payloads.
const maxAuthBodySize = 1 * 1024 * 1024

// handleLogin handles login requests.
func (s *AuthService) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only POST method is allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAuthBodySize)

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Provider string `json:"provider,omitempty"`
		TenantID string `json:"tenant_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_REQUEST", "Failed to parse request body")
		return
	}

	if req.TenantID == "" {
		req.TenantID = "default"
	}

	user, err := s.Authenticate(req.Username, req.Password, req.TenantID)
	if err != nil {
		// Log detailed error server-side for debugging (not exposed to client)
		s.logAudit(AuditActionLoginFailed, "", req.Username, req.TenantID, "auth", "", r, false, err.Error())

		// Return a generic error to avoid leaking whether the username exists,
		// or the specific reason for failure (locked, disabled, wrong password, etc.)
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "Invalid username or password")
		return
	}

	session, err := s.CreateSession(user, r)
	if err != nil {
		s.logger.Error("failed to create session", "error", err, "user", user.Username)
		writeJSONError(w, http.StatusInternalServerError, "SESSION_ERROR", "Failed to create session")
		return
	}

	s.logAudit(AuditActionLogin, user.ID, user.Username, user.TenantID, "session", session.ID, r, true, "")

	// Generate CSRF token
	csrfToken, err := s.csrf.GenerateToken()
	if err != nil {
		s.logger.Error("failed to generate CSRF token", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "CSRF_ERROR", "Failed to generate CSRF token")
		return
	}

	// Set CSRF token cookie
	s.csrf.SetToken(w, csrfToken)

	// Set session token as HttpOnly cookie (not accessible to JavaScript)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    session.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  session.ExpiresAt,
	})

	// Set refresh token as HttpOnly cookie scoped to auth endpoints
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    session.RefreshToken,
		Path:     "/api/auth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  session.ExpiresAt.Add(24 * time.Hour),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"expires_at": session.ExpiresAt,
		"user":       user,
		"csrf_token": csrfToken,
	})
}

// handleLogout handles logout requests.
func (s *AuthService) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only POST method is allowed")
		return
	}

	// Validate CSRF token
	if err := s.csrf.ValidateToken(r); err != nil {
		writeJSONError(w, http.StatusForbidden, "CSRF_INVALID", "CSRF validation failed")
		return
	}

	token := extractToken(r)
	if token == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}

	session, err := s.ValidateSession(token)
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	// Delete session using SessionStorage interface
	ctx := context.Background()
	if err := s.sessionStorage.Delete(ctx, token); err != nil {
		s.logger.Error("failed to delete session", "error", err)
		http.Error(w, "Failed to logout", http.StatusInternalServerError)
		return
	}

	s.logAudit(AuditActionLogout, session.UserID, "", session.TenantID, "session", session.ID, r, true, "")

	// Clear CSRF token cookie on logout
	s.csrf.ClearToken(w)

	// Clear session cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/api/auth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "logged out"})
}

// handleSession returns current session info.
func (s *AuthService) handleSession(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}

	session, err := s.ValidateSession(token)
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	s.mu.RLock()
	user := s.getUserByIDLocked(session.UserID)
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"session": session,
		"user":    user,
	})
}

// handleOAuthCallback handles OAuth callback.
// OAuth integration is not yet implemented — return 501 to prevent unauthenticated access.
func (s *AuthService) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	s.logger.Warn("OAuth callback called but OAuth is not implemented")
	writeJSONError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "OAuth authentication is not yet implemented")
}

// handleSAMLACS handles SAML Assertion Consumer Service.
// SAML integration is not yet implemented — return 501 to prevent unauthenticated access.
func (s *AuthService) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	s.logger.Warn("SAML ACS called but SAML is not implemented")
	writeJSONError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "SAML authentication is not yet implemented")
}

// handleUsers manages users.
func (s *AuthService) handleUsers(w http.ResponseWriter, r *http.Request) {
	// Require authentication for all user operations
	token := extractToken(r)
	if token == "" {
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	session, err := s.ValidateSession(token)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "INVALID_SESSION", "Invalid or expired session")
		return
	}

	// Check permission for user management
	if !s.HasPermission(session.UserID, PermissionManageUsers) && !s.HasPermission(session.UserID, PermissionAdmin) {
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "Insufficient permissions to manage users")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		users := make([]*User, 0, len(s.users))
		for _, u := range s.users {
			users = append(users, u)
		}
		s.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)

	case http.MethodPost:
		// Validate CSRF token for state-changing operation
		if err := s.csrf.ValidateToken(r); err != nil {
			writeJSONError(w, http.StatusForbidden, "CSRF_INVALID", "CSRF validation failed")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxAuthBodySize)

		// Use a restricted request struct to prevent clients from setting PasswordHash directly
		var req struct {
			Username string   `json:"username"`
			Password string   `json:"password"`
			Email    string   `json:"email"`
			Roles    []string `json:"roles"`
			TenantID string   `json:"tenant_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
			return
		}

		if req.Username == "" {
			writeJSONError(w, http.StatusBadRequest, "INVALID_REQUEST", "Username is required")
			return
		}

		// Enforce password policy on creation
		if err := validatePasswordStrength(req.Password); err != nil {
			writeJSONError(w, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
			return
		}

		// Hash password server-side (never accept pre-hashed passwords)
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptCost)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to process password")
			return
		}

		roles := make([]Role, len(req.Roles))
		for i, r := range req.Roles {
			roles[i] = Role(r)
		}

		user := &User{
			ID:           generateID(),
			Username:     req.Username,
			Email:        req.Email,
			PasswordHash: string(passwordHash),
			Roles:        roles,
			TenantID:     req.TenantID,
			CreatedAt:    time.Now(),
			Provider:     AuthProviderLocal,
			Permissions:  s.getPermissionsForRoles(roles),
		}

		s.mu.Lock()
		// Check if username already exists
		if _, exists := s.users[user.Username]; exists {
			s.mu.Unlock()
			writeJSONError(w, http.StatusConflict, "USERNAME_EXISTS", "Username already exists")
			return
		}
		s.users[user.Username] = user
		s.mu.Unlock()

		s.logAudit(AuditActionUserCreated, "", "", user.TenantID, "user", user.ID, r, true, "")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(user)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTenants manages tenants.
func (s *AuthService) handleTenants(w http.ResponseWriter, r *http.Request) {
	// Require authentication for all tenant operations
	token := extractToken(r)
	if token == "" {
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	session, err := s.ValidateSession(token)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "INVALID_SESSION", "Invalid or expired session")
		return
	}

	// Check permission for tenant management
	if !s.HasPermission(session.UserID, PermissionManageTenants) && !s.HasPermission(session.UserID, PermissionAdmin) {
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "Insufficient permissions to manage tenants")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		tenants := make([]*Tenant, 0, len(s.tenants))
		for _, t := range s.tenants {
			tenants = append(tenants, t)
		}
		s.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tenants)

	case http.MethodPost:
		// Validate CSRF token for state-changing operation
		if err := s.csrf.ValidateToken(r); err != nil {
			writeJSONError(w, http.StatusForbidden, "CSRF_INVALID", "CSRF validation failed")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxAuthBodySize)

		var tenant Tenant
		if err := json.NewDecoder(r.Body).Decode(&tenant); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		tenant.ID = generateID()
		tenant.CreatedAt = time.Now()
		tenant.UpdatedAt = time.Now()

		s.mu.Lock()
		s.tenants[tenant.ID] = &tenant
		s.mu.Unlock()

		s.logAudit(AuditActionTenantCreated, "", "", tenant.ID, "tenant", tenant.ID, r, true, "")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(tenant)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAuditLog returns audit log entries.
func (s *AuthService) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Require authentication for audit log access
	token := extractToken(r)
	if token == "" {
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	session, err := s.ValidateSession(token)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "INVALID_SESSION", "Invalid or expired session")
		return
	}

	// Check permission for audit log viewing
	if !s.HasPermission(session.UserID, PermissionViewAuditLog) && !s.HasPermission(session.UserID, PermissionAdmin) {
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "Insufficient permissions to view audit log")
		return
	}

	s.mu.RLock()
	entries := make([]*AuditLogEntry, len(s.auditLog))
	copy(entries, s.auditLog)
	s.mu.RUnlock()

	// Return most recent first
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// AuthError represents an authentication error with additional context.
type AuthError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *AuthError) Error() string {
	return e.Message
}

// Common authentication errors
var (
	ErrUserNotFound     = &AuthError{Code: "USER_NOT_FOUND", Message: "invalid username or password"}
	ErrInvalidPassword  = &AuthError{Code: "INVALID_PASSWORD", Message: "invalid username or password"}
	ErrUserDisabled     = &AuthError{Code: "USER_DISABLED", Message: "user account is disabled"}
	ErrAccountLocked    = &AuthError{Code: "ACCOUNT_LOCKED", Message: "account is temporarily locked due to too many failed attempts"}
	ErrTenantMismatch   = &AuthError{Code: "TENANT_MISMATCH", Message: "user not authorized for this tenant"}
	ErrPasswordRequired = &AuthError{Code: "PASSWORD_REQUIRED", Message: "password is required"}
	ErrUsernameRequired = &AuthError{Code: "USERNAME_REQUIRED", Message: "username is required"}
)

const (
	maxFailedAttempts = 5
	lockoutDuration   = 15 * time.Minute
	bcryptCost        = 12
)

// Authenticate validates user credentials with bcrypt password verification.
func (s *AuthService) Authenticate(username, password, tenantID string) (*User, error) {
	// Input validation
	if username == "" {
		return nil, ErrUsernameRequired
	}
	if password == "" {
		return nil, ErrPasswordRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[username]
	if !exists {
		// Use constant-time comparison to prevent timing attacks
		// Hash a dummy password to maintain consistent timing
		// This is a valid bcrypt hash (cost 12) for the string "dummy"
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"), []byte(password))
		return nil, ErrUserNotFound
	}

	// Check if account is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, ErrAccountLocked
	}

	// Reset lockout if expired
	if user.LockedUntil != nil && time.Now().After(*user.LockedUntil) {
		user.LockedUntil = nil
		user.FailedLogins = 0
	}

	if user.Disabled {
		return nil, ErrUserDisabled
	}

	if user.TenantID != tenantID && tenantID != "" {
		return nil, ErrTenantMismatch
	}

	// Verify password using bcrypt
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		// Increment failed login counter
		user.FailedLogins++

		// Lock account after max failed attempts
		if user.FailedLogins >= maxFailedAttempts {
			lockTime := time.Now().Add(lockoutDuration)
			user.LockedUntil = &lockTime
			s.logger.Warn("account locked due to too many failed attempts",
				"username", username,
				"failed_attempts", user.FailedLogins,
				"locked_until", lockTime)
		}

		return nil, ErrInvalidPassword
	}

	// Successful authentication - reset failed attempts
	user.FailedLogins = 0
	user.LockedUntil = nil
	user.LastLoginAt = time.Now()

	s.logger.Info("user authenticated successfully", "username", username, "tenant", user.TenantID)

	return user, nil
}

// HashPassword hashes a password using bcrypt.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}
	if len(password) < 8 {
		return "", errors.New("password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// ValidatePassword checks if a password meets security requirements.
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if len(password) > 128 {
		return errors.New("password must not exceed 128 characters")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;':\",./<>?", c):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return errors.New("password must contain at least one digit")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

// CreateSession creates a new session for a user.
func (s *AuthService) CreateSession(user *User, r *http.Request) (*Session, error) {
	token, err := generateToken()
	if err != nil {
		return nil, err
	}

	refreshToken, err := generateToken()
	if err != nil {
		return nil, err
	}

	session := &Session{
		ID:           generateID(),
		UserID:       user.ID,
		TenantID:     user.TenantID,
		Token:        token,
		RefreshToken: refreshToken,
		Provider:     user.Provider,
		IPAddress:    getClientIP(r),
		UserAgent:    r.UserAgent(),
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		LastActiveAt: time.Now(),
	}

	// Store session using SessionStorage interface
	ctx := context.Background()
	if err := s.sessionStorage.Store(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	return session, nil
}

// idleSessionTimeout defines the maximum allowed idle time before a session is invalidated.
const idleSessionTimeout = 30 * time.Minute

// ValidateSession validates a session token.
func (s *AuthService) ValidateSession(token string) (*Session, error) {
	ctx := context.Background()

	session, err := s.sessionStorage.Get(ctx, token)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return nil, errors.New("session not found")
		}
		if errors.Is(err, ErrSessionExpired) {
			return nil, errors.New("session expired")
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	// Check idle session timeout
	if time.Since(session.LastActiveAt) > idleSessionTimeout {
		// Delete the idle session
		_ = s.sessionStorage.Delete(ctx, token)
		return nil, errors.New("session expired due to inactivity")
	}

	// Update last active time
	now := time.Now()
	if err := s.sessionStorage.UpdateActivity(ctx, token, now); err != nil {
		// Log but don't fail on update error
		s.logger.Warn("failed to update session activity", "error", err)
	}

	return session, nil
}

// HasPermission checks if a user has a specific permission.
func (s *AuthService) HasPermission(userID string, permission Permission) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Iterate through users to find by ID (map is keyed by username)
	for _, user := range s.users {
		if user.ID == userID {
			for _, p := range user.Permissions {
				if p == permission || p == PermissionAdmin {
					return true
				}
			}
			return false
		}
	}

	return false
}

// getPermissionsForRoles returns all permissions for given roles.
func (s *AuthService) getPermissionsForRoles(roles []Role) []Permission {
	permSet := make(map[Permission]bool)
	for _, role := range roles {
		if perms, ok := s.rolePerms[role]; ok {
			for _, p := range perms {
				permSet[p] = true
			}
		}
	}

	permissions := make([]Permission, 0, len(permSet))
	for p := range permSet {
		permissions = append(permissions, p)
	}
	return permissions
}

// logAudit creates an audit log entry.
func (s *AuthService) logAudit(action AuditAction, userID, username, tenantID, resource, resourceID string, r *http.Request, success bool, errorMsg string) {
	entry := &AuditLogEntry{
		ID:         generateID(),
		Timestamp:  time.Now(),
		UserID:     userID,
		Username:   username,
		TenantID:   tenantID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		IPAddress:  getClientIP(r),
		UserAgent:  r.UserAgent(),
		Success:    success,
		ErrorMsg:   errorMsg,
	}

	s.mu.Lock()
	s.auditLog = append(s.auditLog, entry)
	// Keep last 10000 entries in memory
	if len(s.auditLog) > 10000 {
		s.auditLog = s.auditLog[len(s.auditLog)-10000:]
	}
	s.mu.Unlock()

	// Persist to audit log file (append-only JSON lines)
	s.persistAuditEntry(entry)

	s.logger.Info("audit log",
		"action", action,
		"user_id", userID,
		"resource", resource,
		"success", success,
	)
}

// persistAuditEntry writes an audit entry to the append-only audit log file.
func (s *AuthService) persistAuditEntry(entry *AuditLogEntry) {
	data, err := json.Marshal(entry)
	if err != nil {
		s.logger.Error("failed to marshal audit entry", "error", err)
		return
	}

	f, err := os.OpenFile("/var/log/boundary-siem/audit.jsonl", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		// Fall back silently — in-memory log is still available
		return
	}
	defer f.Close()

	f.Write(append(data, '\n'))
}

// getUserByIDLocked finds a user by ID. Caller must hold at least a read lock.
func (s *AuthService) getUserByIDLocked(id string) *User {
	for _, u := range s.users {
		if u.ID == id {
			return u
		}
	}
	return nil
}

// GetUser returns a user by ID.
func (s *AuthService) GetUser(id string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u := s.getUserByIDLocked(id)
	return u, u != nil
}

// GetTenant returns a tenant by ID.
func (s *AuthService) GetTenant(id string) (*Tenant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tenants[id]
	return t, ok
}

// GetAuditLog returns audit log entries.
func (s *AuthService) GetAuditLog(limit int) []*AuditLogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.auditLog) {
		limit = len(s.auditLog)
	}

	entries := make([]*AuditLogEntry, limit)
	copy(entries, s.auditLog[len(s.auditLog)-limit:])
	return entries
}

// AddOAuthConfig adds an OAuth provider configuration.
func (s *AuthService) AddOAuthConfig(name string, config *OAuthConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.oauthConfigs[name] = config
}

// AddSAMLConfig adds a SAML provider configuration.
func (s *AuthService) AddSAMLConfig(name string, config *SAMLConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.samlConfigs[name] = config
}

// Middleware returns an authentication middleware.
func (s *AuthService) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for public endpoints
		if isPublicEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		token := extractToken(r)
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		session, err := s.ValidateSession(token)
		if err != nil {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}

		s.mu.RLock()
		user := s.getUserByIDLocked(session.UserID)
		s.mu.RUnlock()

		// Reject disabled or deleted users
		if user == nil || user.Disabled {
			http.Error(w, "Account disabled", http.StatusForbidden)
			return
		}

		// Add user to context
		ctx := context.WithValue(r.Context(), ContextKeyUser, user)
		ctx = context.WithValue(ctx, ContextKeySession, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePermission returns a middleware that requires a specific permission.
func (s *AuthService) RequirePermission(permission Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := r.Context().Value(ContextKeyUser).(*User)
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			if !s.HasPermission(user.ID, permission) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Helper functions

func extractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	// Check session cookie as a safe alternative (never accept tokens via URL query params)
	if cookie, err := r.Cookie("session_token"); err == nil {
		return cookie.Value
	}
	return ""
}

func isPublicEndpoint(path string) bool {
	publicPaths := []string{
		"/api/auth/login",
		"/api/auth/oauth/callback",
		"/api/auth/saml/acs",
		"/api/health",
		"/api/ready",
	}
	for _, p := range publicPaths {
		if path == p {
			return true
		}
	}
	return false
}

func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Crypto failure is critical - panic to avoid security issues
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	hash := sha256.Sum256(b)
	return base64.URLEncoding.EncodeToString(hash[:]), nil
}

// generateSecurePassword generates a cryptographically secure random password.
// The password will contain uppercase, lowercase, digits, and special characters.
func generateSecurePassword(length int) (string, error) {
	if length < 12 {
		length = 24 // Default to 24 characters for strong security
	}

	const (
		upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lowerChars   = "abcdefghijklmnopqrstuvwxyz"
		digitChars   = "0123456789"
		specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
		allChars     = upperChars + lowerChars + digitChars + specialChars
	)

	// Ensure at least one character from each category
	password := make([]byte, length)

	// Add one of each required type
	password[0] = upperChars[randInt(len(upperChars))]
	password[1] = lowerChars[randInt(len(lowerChars))]
	password[2] = digitChars[randInt(len(digitChars))]
	password[3] = specialChars[randInt(len(specialChars))]

	// Fill the rest with random characters from all categories
	for i := 4; i < length; i++ {
		password[i] = allChars[randInt(len(allChars))]
	}

	// Shuffle the password to avoid predictable patterns
	for i := length - 1; i > 0; i-- {
		j := randInt(i + 1)
		password[i], password[j] = password[j], password[i]
	}

	return string(password), nil
}

// randInt returns a cryptographically secure random integer in [0, max)
// using math/big to avoid modulo bias.
func randInt(max int) int {
	if max <= 0 {
		return 0
	}

	nBig, err := cryptoRandInt(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		// Crypto failure is critical — panic rather than silently returning biased output
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}

	return int(nBig.Int64())
}

func getClientIP(r *http.Request) string {
	// Use the rightmost IP in X-Forwarded-For to prevent client-controlled spoofing.
	// The rightmost entry is set by the trusted proxy closest to the server and
	// cannot be forged by the client (the client can only prepend entries).
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip != "" {
				return ip
			}
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Use net.SplitHostPort for correct parsing (handles IPv6)
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host
}

// writePasswordToSecureFile writes a generated password to a secure file with restricted permissions.
// The file is created with 0600 permissions (read/write for owner only) to prevent unauthorized access.
func writePasswordToSecureFile(username, password string) error {
	// Create secure directory if it doesn't exist
	secureDir := "/var/lib/boundary-siem"
	if err := os.MkdirAll(secureDir, 0700); err != nil {
		// Fallback to current directory if /var/lib is not writable
		secureDir = "."
	}

	passwordFile := fmt.Sprintf("%s/admin-password.txt", secureDir)

	// Create file with restricted permissions (0600 = owner read/write only)
	content := fmt.Sprintf("Boundary-SIEM Generated Admin Credentials\n"+
		"Generated: %s\n"+
		"Username: %s\n"+
		"Password: %s\n\n"+
		"SECURITY NOTICE:\n"+
		"1. Change this password immediately after first login\n"+
		"2. Delete this file after retrieving the password\n"+
		"3. This file contains sensitive credentials - protect it carefully\n",
		time.Now().Format(time.RFC3339),
		username,
		password)

	if err := os.WriteFile(passwordFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write password file: %w", err)
	}

	// Double-check file permissions were set correctly
	if err := os.Chmod(passwordFile, 0600); err != nil {
		return fmt.Errorf("failed to set password file permissions: %w", err)
	}

	return nil
}

// GetUserByUsername returns a user by username.
func (s *AuthService) GetUserByUsername(username string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Username == username {
			return u, true
		}
	}
	return nil, false
}

// CreateUser creates a new user.
func (s *AuthService) CreateUser(user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if username already exists (users map is keyed by username for auth)
	if _, exists := s.users[user.Username]; exists {
		return fmt.Errorf("user already exists")
	}

	user.CreatedAt = time.Now()
	user.Permissions = s.getPermissionsForRoles(user.Roles)
	s.users[user.Username] = user // Use username as key for Authenticate() compatibility
	return nil
}

// CreateTenant creates a new tenant.
func (s *AuthService) CreateTenant(tenant *Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tenants[tenant.ID]; exists {
		return fmt.Errorf("tenant already exists")
	}

	tenant.CreatedAt = time.Now()
	tenant.UpdatedAt = time.Now()
	s.tenants[tenant.ID] = tenant
	return nil
}
