package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// CSRF protection using double-submit cookie pattern.
// This is stateless and works well with our session-based auth.

var (
	// ErrCSRFTokenMissing is returned when CSRF token is not provided.
	ErrCSRFTokenMissing = errors.New("CSRF token missing")

	// ErrCSRFTokenInvalid is returned when CSRF token doesn't match.
	ErrCSRFTokenInvalid = errors.New("CSRF token invalid")
)

const (
	// CSRFTokenLength is the length of CSRF tokens in bytes.
	CSRFTokenLength = 32

	// CSRFCookieName is the name of the CSRF cookie.
	CSRFCookieName = "XSRF-TOKEN"

	// CSRFHeaderName is the name of the CSRF header.
	CSRFHeaderName = "X-CSRF-Token"

	// CSRFFormFieldName is the name of the CSRF form field.
	CSRFFormFieldName = "csrf_token"
)

// CSRFConfig holds CSRF protection configuration.
type CSRFConfig struct {
	// CookieName is the name of the CSRF cookie (default: XSRF-TOKEN).
	CookieName string

	// HeaderName is the name of the CSRF header (default: X-CSRF-Token).
	HeaderName string

	// FormFieldName is the name of the CSRF form field (default: csrf_token).
	FormFieldName string

	// CookiePath is the path for the CSRF cookie (default: /).
	CookiePath string

	// CookieDomain is the domain for the CSRF cookie.
	CookieDomain string

	// CookieHTTPOnly sets the HttpOnly flag on the CSRF cookie (default: false).
	// Note: Must be false so JavaScript can read it for AJAX requests.
	CookieHTTPOnly bool

	// CookieSecure sets the Secure flag on the CSRF cookie (default: true).
	CookieSecure bool

	// CookieSameSite sets the SameSite attribute (default: Strict).
	CookieSameSite http.SameSite

	// SkipMethods are HTTP methods that skip CSRF validation (default: GET, HEAD, OPTIONS).
	SkipMethods []string

	// TrustedOrigins are origins allowed to make cross-origin requests.
	TrustedOrigins []string
}

// DefaultCSRFConfig returns the default CSRF configuration.
func DefaultCSRFConfig() *CSRFConfig {
	return &CSRFConfig{
		CookieName:     CSRFCookieName,
		HeaderName:     CSRFHeaderName,
		FormFieldName:  CSRFFormFieldName,
		CookiePath:     "/",
		CookieHTTPOnly: false, // Must be false for JavaScript access
		CookieSecure:   true,
		CookieSameSite: http.SameSiteStrictMode,
		SkipMethods:    []string{"GET", "HEAD", "OPTIONS"},
	}
}

// CSRFProtection provides CSRF protection middleware.
type CSRFProtection struct {
	config *CSRFConfig
}

// NewCSRFProtection creates a new CSRF protection instance.
func NewCSRFProtection(config *CSRFConfig) *CSRFProtection {
	if config == nil {
		config = DefaultCSRFConfig()
	}

	// Ensure defaults
	if config.CookieName == "" {
		config.CookieName = CSRFCookieName
	}
	if config.HeaderName == "" {
		config.HeaderName = CSRFHeaderName
	}
	if config.FormFieldName == "" {
		config.FormFieldName = CSRFFormFieldName
	}
	if config.CookiePath == "" {
		config.CookiePath = "/"
	}
	if len(config.SkipMethods) == 0 {
		config.SkipMethods = []string{"GET", "HEAD", "OPTIONS"}
	}

	return &CSRFProtection{
		config: config,
	}
}

// GenerateToken generates a new CSRF token.
func (c *CSRFProtection) GenerateToken() (string, error) {
	b := make([]byte, CSRFTokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// Middleware returns CSRF protection middleware.
func (c *CSRFProtection) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if method should be validated
		if c.shouldSkipValidation(r.Method) {
			// For safe methods, ensure token is set
			c.ensureToken(w, r)
			next.ServeHTTP(w, r)
			return
		}

		// Validate CSRF token for state-changing methods
		if err := c.ValidateToken(r); err != nil {
			http.Error(w, "CSRF validation failed", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// shouldSkipValidation checks if the method should skip CSRF validation.
func (c *CSRFProtection) shouldSkipValidation(method string) bool {
	for _, m := range c.config.SkipMethods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// ensureToken ensures a CSRF token is set in the cookie.
func (c *CSRFProtection) ensureToken(w http.ResponseWriter, r *http.Request) {
	// Check if token already exists
	if _, err := r.Cookie(c.config.CookieName); err == nil {
		return // Token already exists
	}

	// Generate and set new token
	token, err := c.GenerateToken()
	if err != nil {
		return // Silent fail for token generation
	}

	c.SetToken(w, token)
}

// SetToken sets the CSRF token cookie.
func (c *CSRFProtection) SetToken(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:     c.config.CookieName,
		Value:    token,
		Path:     c.config.CookiePath,
		Domain:   c.config.CookieDomain,
		HttpOnly: c.config.CookieHTTPOnly,
		Secure:   c.config.CookieSecure,
		SameSite: c.config.CookieSameSite,
		MaxAge:   86400, // 24 hours
	}
	http.SetCookie(w, cookie)
}

// ValidateToken validates the CSRF token from the request.
func (c *CSRFProtection) ValidateToken(r *http.Request) error {
	// Get token from cookie (double-submit pattern)
	cookie, err := r.Cookie(c.config.CookieName)
	if err != nil {
		return ErrCSRFTokenMissing
	}
	cookieToken := cookie.Value

	// Get token from header or form
	requestToken := c.extractToken(r)
	if requestToken == "" {
		return ErrCSRFTokenMissing
	}

	// Compare tokens using constant-time comparison
	if !c.tokensMatch(cookieToken, requestToken) {
		return ErrCSRFTokenInvalid
	}

	// Validate origin if configured
	if len(c.config.TrustedOrigins) > 0 {
		if err := c.validateOrigin(r); err != nil {
			return err
		}
	}

	return nil
}

// extractToken extracts the CSRF token from the request.
// Checks header first, then form field.
func (c *CSRFProtection) extractToken(r *http.Request) string {
	// Check header first
	token := r.Header.Get(c.config.HeaderName)
	if token != "" {
		return token
	}

	// Check form field
	if err := r.ParseForm(); err == nil {
		token = r.FormValue(c.config.FormFieldName)
	}

	return token
}

// tokensMatch compares two tokens using constant-time comparison.
func (c *CSRFProtection) tokensMatch(a, b string) bool {
	// Reject empty tokens
	if a == "" || b == "" {
		return false
	}

	// Decode tokens
	aBytes, err := base64.URLEncoding.DecodeString(a)
	if err != nil {
		return false
	}
	bBytes, err := base64.URLEncoding.DecodeString(b)
	if err != nil {
		return false
	}

	// Ensure tokens have proper length
	if len(aBytes) == 0 || len(bBytes) == 0 {
		return false
	}

	// Constant-time comparison
	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1
}

// validateOrigin validates the request origin against trusted origins.
func (c *CSRFProtection) validateOrigin(r *http.Request) error {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}

	if origin == "" {
		return nil // No origin to validate
	}

	// Parse the origin URL
	originURL, err := url.Parse(origin)
	if err != nil {
		return errors.New("invalid origin URL")
	}
	originHost := strings.ToLower(originURL.Scheme + "://" + originURL.Host)

	// Check if origin is trusted using exact match
	for _, trusted := range c.config.TrustedOrigins {
		trustedURL, err := url.Parse(trusted)
		if err != nil {
			// Fallback to exact string match if trusted origin is not a URL
			if strings.EqualFold(origin, trusted) || strings.EqualFold(originHost, trusted) {
				return nil
			}
			continue
		}
		trustedHost := strings.ToLower(trustedURL.Scheme + "://" + trustedURL.Host)

		// Exact match on scheme + host
		if originHost == trustedHost {
			return nil
		}
	}

	return errors.New("untrusted origin")
}

// GetToken retrieves the CSRF token from the request cookie.
func (c *CSRFProtection) GetToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie(c.config.CookieName)
	if err != nil {
		return "", ErrCSRFTokenMissing
	}
	return cookie.Value, nil
}

// ClearToken removes the CSRF token cookie.
func (c *CSRFProtection) ClearToken(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     c.config.CookieName,
		Value:    "",
		Path:     c.config.CookiePath,
		Domain:   c.config.CookieDomain,
		HttpOnly: c.config.CookieHTTPOnly,
		Secure:   c.config.CookieSecure,
		SameSite: c.config.CookieSameSite,
		MaxAge:   -1, // Delete immediately
	}
	http.SetCookie(w, cookie)
}

// ProtectedHandler wraps a handler with CSRF protection.
// This is useful for protecting individual handlers without middleware.
func (c *CSRFProtection) ProtectedHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip validation for safe methods
		if c.shouldSkipValidation(r.Method) {
			c.ensureToken(w, r)
			next(w, r)
			return
		}

		// Validate CSRF token
		if err := c.ValidateToken(r); err != nil {
			http.Error(w, "CSRF validation failed", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}

// TokenFromRequest extracts and validates the CSRF token from a request.
// Returns the token if valid, error otherwise.
func (c *CSRFProtection) TokenFromRequest(r *http.Request) (string, error) {
	cookie, err := r.Cookie(c.config.CookieName)
	if err != nil {
		return "", ErrCSRFTokenMissing
	}

	requestToken := c.extractToken(r)
	if requestToken == "" {
		return "", ErrCSRFTokenMissing
	}

	if !c.tokensMatch(cookie.Value, requestToken) {
		return "", ErrCSRFTokenInvalid
	}

	return cookie.Value, nil
}

// ExemptPath creates a middleware that exempts specific paths from CSRF protection.
func (c *CSRFProtection) ExemptPath(paths ...string) func(http.Handler) http.Handler {
	exemptPaths := make(map[string]bool)
	for _, path := range paths {
		exemptPaths[path] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path is exempt
			if exemptPaths[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			// Apply CSRF protection
			c.Middleware(next).ServeHTTP(w, r)
		})
	}
}
