package auth

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCSRFProtection_GenerateToken tests CSRF token generation.
func TestCSRFProtection_GenerateToken(t *testing.T) {
	csrf := NewCSRFProtection(nil)

	token1, err := csrf.GenerateToken()
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	if token1 == "" {
		t.Error("expected non-empty token")
	}

	// Verify token is valid base64
	decoded, err := base64.URLEncoding.DecodeString(token1)
	if err != nil {
		t.Errorf("token is not valid base64: %v", err)
	}

	// Verify token length
	if len(decoded) != CSRFTokenLength {
		t.Errorf("expected token length %d, got %d", CSRFTokenLength, len(decoded))
	}

	// Generate second token and verify uniqueness
	token2, err := csrf.GenerateToken()
	if err != nil {
		t.Fatalf("failed to generate second token: %v", err)
	}

	if token1 == token2 {
		t.Error("expected unique tokens, got identical")
	}
}

// TestCSRFProtection_Middleware_SkipSafeMethods tests that safe methods skip validation.
func TestCSRFProtection_Middleware_SkipSafeMethods(t *testing.T) {
	csrf := NewCSRFProtection(nil)

	handler := csrf.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	tests := []struct {
		name   string
		method string
		expect int
	}{
		{"GET request", http.MethodGet, http.StatusOK},
		{"HEAD request", http.MethodHead, http.StatusOK},
		{"OPTIONS request", http.MethodOptions, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/test", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tt.expect {
				t.Errorf("expected status %d, got %d", tt.expect, w.Code)
			}

			// Verify CSRF token cookie was set
			cookies := w.Result().Cookies()
			found := false
			for _, cookie := range cookies {
				if cookie.Name == CSRFCookieName {
					found = true
					break
				}
			}
			if !found {
				t.Error("expected CSRF cookie to be set")
			}
		})
	}
}

// TestCSRFProtection_Middleware_ValidatePOST tests POST request validation.
func TestCSRFProtection_Middleware_ValidatePOST(t *testing.T) {
	csrf := NewCSRFProtection(nil)

	handler := csrf.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	t.Run("POST without token fails", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected status %d, got %d", http.StatusForbidden, w.Code)
		}
	})

	t.Run("POST with valid token succeeds", func(t *testing.T) {
		token, _ := csrf.GenerateToken()

		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  CSRFCookieName,
			Value: token,
		})
		req.Header.Set(CSRFHeaderName, token)

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("POST with mismatched token fails", func(t *testing.T) {
		token1, _ := csrf.GenerateToken()
		token2, _ := csrf.GenerateToken()

		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  CSRFCookieName,
			Value: token1,
		})
		req.Header.Set(CSRFHeaderName, token2)

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected status %d, got %d", http.StatusForbidden, w.Code)
		}
	})
}

// TestCSRFProtection_ValidateToken tests token validation logic.
func TestCSRFProtection_ValidateToken(t *testing.T) {
	csrf := NewCSRFProtection(nil)
	token, _ := csrf.GenerateToken()

	tests := []struct {
		name        string
		setupReq    func() *http.Request
		expectError bool
	}{
		{
			name: "valid token in header",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/test", nil)
				req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
				req.Header.Set(CSRFHeaderName, token)
				return req
			},
			expectError: false,
		},
		{
			name: "valid token in form",
			setupReq: func() *http.Request {
				form := "csrf_token=" + token
				req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(form))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
				return req
			},
			expectError: false,
		},
		{
			name: "missing cookie",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/test", nil)
				req.Header.Set(CSRFHeaderName, token)
				return req
			},
			expectError: true,
		},
		{
			name: "missing header and form",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/test", nil)
				req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
				return req
			},
			expectError: true,
		},
		{
			name: "invalid token format",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/test", nil)
				req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "invalid!!!"})
				req.Header.Set(CSRFHeaderName, "invalid!!!")
				return req
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			err := csrf.ValidateToken(req)

			if tt.expectError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

// TestCSRFProtection_TokensMatch tests constant-time comparison.
func TestCSRFProtection_TokensMatch(t *testing.T) {
	csrf := NewCSRFProtection(nil)
	token1, _ := csrf.GenerateToken()
	token2, _ := csrf.GenerateToken()

	tests := []struct {
		name        string
		token1      string
		token2      string
		shouldMatch bool
	}{
		{"identical tokens", token1, token1, true},
		{"different tokens", token1, token2, false},
		{"invalid base64 token1", "invalid!!!", token2, false},
		{"invalid base64 token2", token1, "invalid!!!", false},
		{"both invalid", "invalid1", "invalid2", false},
		{"empty tokens", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := csrf.tokensMatch(tt.token1, tt.token2)
			if match != tt.shouldMatch {
				t.Errorf("expected match=%v, got %v", tt.shouldMatch, match)
			}
		})
	}
}

// TestCSRFProtection_SetToken tests cookie setting.
func TestCSRFProtection_SetToken(t *testing.T) {
	csrf := NewCSRFProtection(nil)
	token, _ := csrf.GenerateToken()

	w := httptest.NewRecorder()
	csrf.SetToken(w, token)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != CSRFCookieName {
		t.Errorf("expected cookie name %s, got %s", CSRFCookieName, cookie.Name)
	}
	if cookie.Value != token {
		t.Errorf("expected cookie value %s, got %s", token, cookie.Value)
	}
	if cookie.Path != "/" {
		t.Errorf("expected cookie path /, got %s", cookie.Path)
	}
	if cookie.HttpOnly {
		t.Error("expected HttpOnly=false for JavaScript access")
	}
	if !cookie.Secure {
		t.Error("expected Secure=true")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSite=Strict, got %v", cookie.SameSite)
	}
}

// TestCSRFProtection_GetToken tests retrieving token from request.
func TestCSRFProtection_GetToken(t *testing.T) {
	csrf := NewCSRFProtection(nil)
	token, _ := csrf.GenerateToken()

	t.Run("token exists", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})

		got, err := csrf.GetToken(req)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if got != token {
			t.Errorf("expected token %s, got %s", token, got)
		}
	})

	t.Run("token missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)

		_, err := csrf.GetToken(req)
		if err == nil {
			t.Error("expected error, got nil")
		}
		if err != ErrCSRFTokenMissing {
			t.Errorf("expected ErrCSRFTokenMissing, got %v", err)
		}
	})
}

// TestCSRFProtection_ClearToken tests token removal.
func TestCSRFProtection_ClearToken(t *testing.T) {
	csrf := NewCSRFProtection(nil)

	w := httptest.NewRecorder()
	csrf.ClearToken(w)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.MaxAge != -1 {
		t.Errorf("expected MaxAge=-1, got %d", cookie.MaxAge)
	}
	if cookie.Value != "" {
		t.Errorf("expected empty value, got %s", cookie.Value)
	}
}

// TestCSRFProtection_ProtectedHandler tests handler wrapper.
func TestCSRFProtection_ProtectedHandler(t *testing.T) {
	csrf := NewCSRFProtection(nil)
	token, _ := csrf.GenerateToken()

	handlerCalled := false
	handler := csrf.ProtectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	t.Run("GET passes through", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		if !handlerCalled {
			t.Error("expected handler to be called")
		}
		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("POST with valid token succeeds", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
		req.Header.Set(CSRFHeaderName, token)
		w := httptest.NewRecorder()

		handler(w, req)

		if !handlerCalled {
			t.Error("expected handler to be called")
		}
		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("POST without token fails", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		if handlerCalled {
			t.Error("expected handler not to be called")
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("expected status %d, got %d", http.StatusForbidden, w.Code)
		}
	})
}

// TestCSRFProtection_ExemptPath tests path exemption.
func TestCSRFProtection_ExemptPath(t *testing.T) {
	csrf := NewCSRFProtection(nil)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	// Create middleware with exempt paths
	middleware := csrf.ExemptPath("/api/public", "/api/webhook")
	wrappedHandler := middleware(handler)

	t.Run("exempt path skips validation", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest(http.MethodPost, "/api/public", nil)
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		if !handlerCalled {
			t.Error("expected handler to be called")
		}
		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("non-exempt path requires token", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest(http.MethodPost, "/api/protected", nil)
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		// Should fail CSRF validation
		if w.Code != http.StatusForbidden {
			t.Errorf("expected status %d, got %d", http.StatusForbidden, w.Code)
		}
	})
}

// TestCSRFProtection_CustomConfig tests custom configuration.
func TestCSRFProtection_CustomConfig(t *testing.T) {
	config := &CSRFConfig{
		CookieName:     "CUSTOM-CSRF",
		HeaderName:     "X-Custom-CSRF",
		FormFieldName:  "custom_csrf",
		CookiePath:     "/api",
		CookieHTTPOnly: false,
		CookieSecure:   true,
		CookieSameSite: http.SameSiteLaxMode,
		SkipMethods:    []string{"GET"},
	}

	csrf := NewCSRFProtection(config)
	token, _ := csrf.GenerateToken()

	t.Run("uses custom cookie name", func(t *testing.T) {
		w := httptest.NewRecorder()
		csrf.SetToken(w, token)

		cookies := w.Result().Cookies()
		if cookies[0].Name != "CUSTOM-CSRF" {
			t.Errorf("expected cookie name CUSTOM-CSRF, got %s", cookies[0].Name)
		}
	})

	t.Run("uses custom header name", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		req.AddCookie(&http.Cookie{Name: "CUSTOM-CSRF", Value: token})
		req.Header.Set("X-Custom-CSRF", token)

		err := csrf.ValidateToken(req)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("uses custom path", func(t *testing.T) {
		w := httptest.NewRecorder()
		csrf.SetToken(w, token)

		cookies := w.Result().Cookies()
		if cookies[0].Path != "/api" {
			t.Errorf("expected path /api, got %s", cookies[0].Path)
		}
	})
}

// TestCSRFProtection_TrustedOrigins tests origin validation.
func TestCSRFProtection_TrustedOrigins(t *testing.T) {
	config := DefaultCSRFConfig()
	config.TrustedOrigins = []string{
		"https://example.com",
		"https://trusted.example.com",
	}

	csrf := NewCSRFProtection(config)
	token, _ := csrf.GenerateToken()

	tests := []struct {
		name        string
		origin      string
		expectError bool
	}{
		{"trusted origin", "https://example.com", false},
		{"trusted subdomain", "https://trusted.example.com", false},
		{"untrusted origin", "https://evil.com", true},
		{"no origin header", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/test", nil)
			req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
			req.Header.Set(CSRFHeaderName, token)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}

			err := csrf.ValidateToken(req)

			if tt.expectError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

// TestCSRFProtection_MultipleRequests tests that tokens work across multiple requests.
func TestCSRFProtection_MultipleRequests(t *testing.T) {
	csrf := NewCSRFProtection(nil)

	handler := csrf.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request: GET to get token
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	// Extract token from response
	var token string
	for _, cookie := range w1.Result().Cookies() {
		if cookie.Name == CSRFCookieName {
			token = cookie.Value
			break
		}
	}

	if token == "" {
		t.Fatal("no CSRF token set on first request")
	}

	// Second request: POST with token
	req2 := httptest.NewRequest(http.MethodPost, "/test", nil)
	req2.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	req2.Header.Set(CSRFHeaderName, token)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w2.Code)
	}

	// Third request: Another POST with same token
	req3 := httptest.NewRequest(http.MethodPost, "/test", nil)
	req3.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	req3.Header.Set(CSRFHeaderName, token)
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)

	if w3.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w3.Code)
	}
}

// TestCSRFProtection_TokenFromRequest tests extracting and validating tokens.
func TestCSRFProtection_TokenFromRequest(t *testing.T) {
	csrf := NewCSRFProtection(nil)
	token, _ := csrf.GenerateToken()

	t.Run("valid token from header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
		req.Header.Set(CSRFHeaderName, token)

		got, err := csrf.TokenFromRequest(req)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if got != token {
			t.Errorf("expected token %s, got %s", token, got)
		}
	})

	t.Run("mismatched tokens", func(t *testing.T) {
		token2, _ := csrf.GenerateToken()
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
		req.Header.Set(CSRFHeaderName, token2)

		_, err := csrf.TokenFromRequest(req)
		if err != ErrCSRFTokenInvalid {
			t.Errorf("expected ErrCSRFTokenInvalid, got %v", err)
		}
	})
}

// Benchmark CSRF token generation.
func BenchmarkCSRFProtection_GenerateToken(b *testing.B) {
	csrf := NewCSRFProtection(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = csrf.GenerateToken()
	}
}

// Benchmark CSRF token validation.
func BenchmarkCSRFProtection_ValidateToken(b *testing.B) {
	csrf := NewCSRFProtection(nil)
	token, _ := csrf.GenerateToken()

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	req.Header.Set(CSRFHeaderName, token)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = csrf.ValidateToken(req)
	}
}

// Benchmark CSRF middleware.
func BenchmarkCSRFProtection_Middleware(b *testing.B) {
	csrf := NewCSRFProtection(nil)
	token, _ := csrf.GenerateToken()

	handler := csrf.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	req.Header.Set(CSRFHeaderName, token)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}
