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
	"net/http"
	"strings"
	"sync"
	"time"
)

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
	RoleAdmin       Role = "admin"
	RoleAnalyst     Role = "analyst"
	RoleViewer      Role = "viewer"
	RoleCompliance  Role = "compliance"
	RoleOperator    Role = "operator"
	RoleAuditor     Role = "auditor"
	RoleAPIClient   Role = "api_client"
)

// Permission defines granular permissions.
type Permission string

const (
	PermissionRead          Permission = "read"
	PermissionWrite         Permission = "write"
	PermissionDelete        Permission = "delete"
	PermissionAdmin         Permission = "admin"
	PermissionViewAlerts    Permission = "view_alerts"
	PermissionAckAlerts     Permission = "ack_alerts"
	PermissionManageRules   Permission = "manage_rules"
	PermissionViewEvents    Permission = "view_events"
	PermissionExportData    Permission = "export_data"
	PermissionManageUsers   Permission = "manage_users"
	PermissionViewReports   Permission = "view_reports"
	PermissionCreateReports Permission = "create_reports"
	PermissionManageTenants Permission = "manage_tenants"
	PermissionViewAuditLog  Permission = "view_audit_log"
	PermissionManageKeys    Permission = "manage_keys"
	PermissionViewCompliance Permission = "view_compliance"
)

// User represents an authenticated user.
type User struct {
	ID           string            `json:"id"`
	Username     string            `json:"username"`
	Email        string            `json:"email"`
	DisplayName  string            `json:"display_name"`
	Roles        []Role            `json:"roles"`
	Permissions  []Permission      `json:"permissions"`
	TenantID     string            `json:"tenant_id"`
	Provider     AuthProvider      `json:"provider"`
	ProviderID   string            `json:"provider_id,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	LastLoginAt  time.Time         `json:"last_login_at"`
	Disabled     bool              `json:"disabled"`
	MFAEnabled   bool              `json:"mfa_enabled"`
}

// Tenant represents an organization/tenant for multi-tenancy.
type Tenant struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Domain      string    `json:"domain,omitempty"`
	Settings    *TenantSettings `json:"settings"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Disabled    bool      `json:"disabled"`
}

// TenantSettings contains tenant-specific settings.
type TenantSettings struct {
	MaxUsers            int               `json:"max_users"`
	MaxEventsPerDay     int64             `json:"max_events_per_day"`
	RetentionDays       int               `json:"retention_days"`
	AllowedProviders    []AuthProvider    `json:"allowed_providers"`
	RequireMFA          bool              `json:"require_mfa"`
	IPWhitelist         []string          `json:"ip_whitelist,omitempty"`
	Features            map[string]bool   `json:"features"`
	CustomBranding      *BrandingSettings `json:"custom_branding,omitempty"`
}

// BrandingSettings contains custom branding options.
type BrandingSettings struct {
	LogoURL       string `json:"logo_url,omitempty"`
	PrimaryColor  string `json:"primary_color,omitempty"`
	CompanyName   string `json:"company_name,omitempty"`
}

// Session represents an authenticated session.
type Session struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	TenantID     string    `json:"tenant_id"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Provider     AuthProvider `json:"provider"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastActiveAt time.Time `json:"last_active_at"`
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
	Provider      string   `json:"provider"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	AuthURL       string   `json:"auth_url"`
	TokenURL      string   `json:"token_url"`
	UserInfoURL   string   `json:"userinfo_url"`
	RedirectURL   string   `json:"redirect_url"`
	Scopes        []string `json:"scopes"`
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
	mu           sync.RWMutex
	users        map[string]*User
	sessions     map[string]*Session
	tenants      map[string]*Tenant
	auditLog     []*AuditLogEntry
	oauthConfigs map[string]*OAuthConfig
	samlConfigs  map[string]*SAMLConfig
	rolePerms    map[Role][]Permission
	logger       *slog.Logger
}

// Config holds auth service configuration.
type Config struct {
	SessionTTL        time.Duration
	RefreshTokenTTL   time.Duration
	MaxSessionsPerUser int
	RequireMFA        bool
	PasswordPolicy    *PasswordPolicy
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
func NewAuthService(logger *slog.Logger) *AuthService {
	svc := &AuthService{
		users:        make(map[string]*User),
		sessions:     make(map[string]*Session),
		tenants:      make(map[string]*Tenant),
		auditLog:     make([]*AuditLogEntry, 0),
		oauthConfigs: make(map[string]*OAuthConfig),
		samlConfigs:  make(map[string]*SAMLConfig),
		rolePerms:    initRolePermissions(),
		logger:       logger,
	}
	svc.initDefaultTenant()
	svc.initDefaultUsers()
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
			MaxUsers:        100,
			MaxEventsPerDay: 10000000,
			RetentionDays:   90,
			AllowedProviders: []AuthProvider{AuthProviderLocal, AuthProviderOAuth, AuthProviderSAML},
			RequireMFA:      false,
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

// initDefaultUsers creates default system users.
func (s *AuthService) initDefaultUsers() {
	now := time.Now()
	s.users["admin"] = &User{
		ID:          "admin",
		Username:    "admin",
		Email:       "admin@boundary-siem.local",
		DisplayName: "System Administrator",
		Roles:       []Role{RoleAdmin},
		Permissions: s.rolePerms[RoleAdmin],
		TenantID:    "default",
		Provider:    AuthProviderLocal,
		CreatedAt:   now,
		LastLoginAt: now,
	}
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

// handleLogin handles login requests.
func (s *AuthService) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Provider string `json:"provider,omitempty"`
		TenantID string `json:"tenant_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.TenantID == "" {
		req.TenantID = "default"
	}

	user, err := s.Authenticate(req.Username, req.Password, req.TenantID)
	if err != nil {
		s.logAudit(AuditActionLoginFailed, "", req.Username, req.TenantID, "auth", "", r, false, err.Error())
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	session, err := s.CreateSession(user, r)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	s.logAudit(AuditActionLogin, user.ID, user.Username, user.TenantID, "session", session.ID, r, true, "")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":         session.Token,
		"refresh_token": session.RefreshToken,
		"expires_at":    session.ExpiresAt,
		"user":          user,
	})
}

// handleLogout handles logout requests.
func (s *AuthService) handleLogout(w http.ResponseWriter, r *http.Request) {
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

	s.mu.Lock()
	delete(s.sessions, session.ID)
	s.mu.Unlock()

	s.logAudit(AuditActionLogout, session.UserID, "", session.TenantID, "session", session.ID, r, true, "")

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
	user := s.users[session.UserID]
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"session": session,
		"user":    user,
	})
}

// handleOAuthCallback handles OAuth callback.
func (s *AuthService) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	provider := r.URL.Query().Get("provider")

	if code == "" || state == "" {
		http.Error(w, "Missing OAuth parameters", http.StatusBadRequest)
		return
	}

	s.logger.Info("OAuth callback received", "provider", provider, "state", state)
	// OAuth token exchange would happen here
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// handleSAMLACS handles SAML Assertion Consumer Service.
func (s *AuthService) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	samlResponse := r.FormValue("SAMLResponse")
	if samlResponse == "" {
		http.Error(w, "Missing SAML response", http.StatusBadRequest)
		return
	}

	s.logger.Info("SAML ACS received")
	// SAML response validation would happen here
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// handleUsers manages users.
func (s *AuthService) handleUsers(w http.ResponseWriter, r *http.Request) {
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
		var user User
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		user.ID = generateID()
		user.CreatedAt = time.Now()
		user.Permissions = s.getPermissionsForRoles(user.Roles)

		s.mu.Lock()
		s.users[user.ID] = &user
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

// Authenticate validates user credentials.
func (s *AuthService) Authenticate(username, password, tenantID string) (*User, error) {
	s.mu.RLock()
	user, exists := s.users[username]
	s.mu.RUnlock()

	if !exists {
		return nil, errors.New("user not found")
	}

	if user.Disabled {
		return nil, errors.New("user is disabled")
	}

	if user.TenantID != tenantID {
		return nil, errors.New("user not in tenant")
	}

	// In production, verify password hash
	// For now, accept any password for demo
	user.LastLoginAt = time.Now()

	return user, nil
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

	s.mu.Lock()
	s.sessions[session.ID] = session
	s.mu.Unlock()

	return session, nil
}

// ValidateSession validates a session token.
func (s *AuthService) ValidateSession(token string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, session := range s.sessions {
		if session.Token == token {
			if time.Now().After(session.ExpiresAt) {
				return nil, errors.New("session expired")
			}
			session.LastActiveAt = time.Now()
			return session, nil
		}
	}

	return nil, errors.New("session not found")
}

// HasPermission checks if a user has a specific permission.
func (s *AuthService) HasPermission(userID string, permission Permission) bool {
	s.mu.RLock()
	user, exists := s.users[userID]
	s.mu.RUnlock()

	if !exists {
		return false
	}

	for _, p := range user.Permissions {
		if p == permission || p == PermissionAdmin {
			return true
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
	// Keep last 10000 entries
	if len(s.auditLog) > 10000 {
		s.auditLog = s.auditLog[len(s.auditLog)-10000:]
	}
	s.mu.Unlock()

	s.logger.Info("audit log",
		"action", action,
		"user_id", userID,
		"resource", resource,
		"success", success,
	)
}

// GetUser returns a user by ID.
func (s *AuthService) GetUser(id string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	return u, ok
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
		user := s.users[session.UserID]
		s.mu.RUnlock()

		// Add user to context
		ctx := context.WithValue(r.Context(), "user", user)
		ctx = context.WithValue(ctx, "session", session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePermission returns a middleware that requires a specific permission.
func (s *AuthService) RequirePermission(permission Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := r.Context().Value("user").(*User)
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
	return r.URL.Query().Get("token")
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
	rand.Read(b)
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

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return strings.Split(r.RemoteAddr, ":")[0]
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

	if _, exists := s.users[user.ID]; exists {
		return fmt.Errorf("user already exists")
	}

	user.CreatedAt = time.Now()
	user.Permissions = s.getPermissionsForRoles(user.Roles)
	s.users[user.ID] = user
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
