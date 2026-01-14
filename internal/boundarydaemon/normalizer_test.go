package boundarydaemon

import (
	"testing"
	"time"

	"boundary-siem/internal/schema"
)

func TestNewNormalizer(t *testing.T) {
	cfg := NormalizerConfig{
		DefaultTenantID: "test-tenant",
		SourceHost:      "test-host",
		SourceVersion:   "2.0.0",
	}

	n := NewNormalizer(cfg)

	if n == nil {
		t.Fatal("NewNormalizer returned nil")
	}
	if n.defaultTenantID != "test-tenant" {
		t.Errorf("expected defaultTenantID 'test-tenant', got %s", n.defaultTenantID)
	}
	if n.sourceHost != "test-host" {
		t.Errorf("expected sourceHost 'test-host', got %s", n.sourceHost)
	}
	if n.sourceVersion != "2.0.0" {
		t.Errorf("expected sourceVersion '2.0.0', got %s", n.sourceVersion)
	}
	if n.sourceProduct != "boundary-daemon" {
		t.Errorf("expected sourceProduct 'boundary-daemon', got %s", n.sourceProduct)
	}
}

func TestDefaultNormalizerConfig(t *testing.T) {
	cfg := DefaultNormalizerConfig()

	if cfg.DefaultTenantID != "default" {
		t.Errorf("expected DefaultTenantID 'default', got %s", cfg.DefaultTenantID)
	}
	if cfg.SourceHost != "localhost" {
		t.Errorf("expected SourceHost 'localhost', got %s", cfg.SourceHost)
	}
	if cfg.SourceVersion != "1.0.0" {
		t.Errorf("expected SourceVersion '1.0.0', got %s", cfg.SourceVersion)
	}
}

func TestActionMappings(t *testing.T) {
	tests := []struct {
		eventType string
		expected  string
	}{
		{"session.created", "bd.session.created"},
		{"session.terminated", "bd.session.terminated"},
		{"auth.login", "bd.auth.login"},
		{"auth.failure", "bd.auth.failure"},
		{"access.granted", "bd.access.granted"},
		{"access.denied", "bd.access.denied"},
		{"threat.detected", "bd.threat.detected"},
		{"policy.violated", "bd.policy.violated"},
	}

	for _, tt := range tests {
		action, ok := ActionMappings[tt.eventType]
		if !ok {
			t.Errorf("ActionMappings missing key %s", tt.eventType)
			continue
		}
		if action != tt.expected {
			t.Errorf("ActionMappings[%s] = %s, expected %s", tt.eventType, action, tt.expected)
		}
	}
}

func TestNormalizeSessionEvent(t *testing.T) {
	n := NewNormalizer(DefaultNormalizerConfig())
	now := time.Now().UTC()

	tests := []struct {
		name     string
		input    *SessionEvent
		checkFn  func(*testing.T, *schema.Event)
	}{
		{
			name: "session created",
			input: &SessionEvent{
				ID:        "evt-123",
				Timestamp: now,
				EventType: "session.created",
				SessionID: "sess-456",
				UserID:    "user-789",
				Username:  "testuser",
				SourceIP:  "192.168.1.100",
				DestIP:    "10.0.0.50",
				Protocol:  "tcp",
				Port:      22,
			},
			checkFn: func(t *testing.T, ev *schema.Event) {
				if ev.Action != "bd.session.created" {
					t.Errorf("expected action 'bd.session.created', got %s", ev.Action)
				}
				if ev.Outcome != schema.OutcomeSuccess {
					t.Errorf("expected outcome 'success', got %s", ev.Outcome)
				}
				if ev.TenantID != "default" {
					t.Errorf("expected TenantID 'default', got %s", ev.TenantID)
				}
				if ev.Actor == nil || ev.Actor.ID != "user-789" {
					t.Error("expected actor with ID 'user-789'")
				}
				if ev.Network == nil || ev.Network.SourceIP != "192.168.1.100" {
					t.Error("expected Network with SourceIP '192.168.1.100'")
				}
			},
		},
		{
			name: "session terminated with forced reason",
			input: &SessionEvent{
				ID:         "evt-124",
				Timestamp:  now,
				EventType:  "session.terminated",
				SessionID:  "sess-457",
				UserID:     "user-790",
				Username:   "testuser2",
				TermReason: "forced",
			},
			checkFn: func(t *testing.T, ev *schema.Event) {
				if ev.Severity != 5 { // Warning for forced termination
					t.Errorf("expected severity 5 for forced termination, got %d", ev.Severity)
				}
				termReason, ok := ev.Metadata["bd_termination_reason"]
				if !ok || termReason != "forced" {
					t.Error("expected metadata bd_termination_reason to be 'forced'")
				}
			},
		},
		{
			name: "session expired",
			input: &SessionEvent{
				ID:        "evt-125",
				Timestamp: now,
				EventType: "session.expired",
				SessionID: "sess-458",
				UserID:    "user-791",
			},
			checkFn: func(t *testing.T, ev *schema.Event) {
				if ev.Outcome != schema.OutcomeFailure {
					t.Errorf("expected outcome 'failure' for expired session, got %s", ev.Outcome)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := n.NormalizeSessionEvent(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if event == nil {
				t.Fatal("expected non-nil event")
			}
			tt.checkFn(t, event)
		})
	}
}

func TestNormalizeAuthEvent(t *testing.T) {
	n := NewNormalizer(DefaultNormalizerConfig())
	now := time.Now().UTC()

	tests := []struct {
		name    string
		input   *AuthEvent
		checkFn func(*testing.T, *schema.Event)
	}{
		{
			name: "successful login",
			input: &AuthEvent{
				ID:         "auth-001",
				Timestamp:  now,
				EventType:  "auth.login",
				UserID:     "user-100",
				Username:   "admin",
				SourceIP:   "10.0.0.1",
				AuthMethod: "password",
				Success:    true,
				SessionID:  "sess-100",
			},
			checkFn: func(t *testing.T, ev *schema.Event) {
				if ev.Action != "bd.auth.login" {
					t.Errorf("expected action 'bd.auth.login', got %s", ev.Action)
				}
				if ev.Outcome != schema.OutcomeSuccess {
					t.Errorf("expected outcome 'success', got %s", ev.Outcome)
				}
				if ev.Severity != 2 { // Informational for success
					t.Errorf("expected severity 2 for successful login, got %d", ev.Severity)
				}
			},
		},
		{
			name: "failed login",
			input: &AuthEvent{
				ID:         "auth-002",
				Timestamp:  now,
				EventType:  "auth.failure",
				UserID:     "user-101",
				Username:   "attacker",
				SourceIP:   "192.168.1.50",
				AuthMethod: "password",
				Success:    false,
				FailReason: "invalid_password",
			},
			checkFn: func(t *testing.T, ev *schema.Event) {
				if ev.Outcome != schema.OutcomeFailure {
					t.Errorf("expected outcome 'failure', got %s", ev.Outcome)
				}
				if ev.Severity != 5 { // Warning for auth failure
					t.Errorf("expected severity 5 for auth failure, got %d", ev.Severity)
				}
				failReason, ok := ev.Metadata["bd_failure_reason"]
				if !ok || failReason != "invalid_password" {
					t.Error("expected metadata bd_failure_reason to be 'invalid_password'")
				}
			},
		},
		{
			name: "MFA failure",
			input: &AuthEvent{
				ID:        "auth-003",
				Timestamp: now,
				EventType: "auth.mfa_failure",
				UserID:    "user-102",
				Username:  "user",
				SourceIP:  "10.0.0.5",
				Success:   false,
				MFAType:   "totp",
			},
			checkFn: func(t *testing.T, ev *schema.Event) {
				if ev.Severity != 6 { // High for MFA failure
					t.Errorf("expected severity 6 for MFA failure, got %d", ev.Severity)
				}
				mfaType, ok := ev.Metadata["bd_mfa_type"]
				if !ok || mfaType != "totp" {
					t.Error("expected metadata bd_mfa_type to be 'totp'")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := n.NormalizeAuthEvent(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if event == nil {
				t.Fatal("expected non-nil event")
			}
			tt.checkFn(t, event)
		})
	}
}

func TestNormalizeAccessEvent(t *testing.T) {
	n := NewNormalizer(DefaultNormalizerConfig())
	now := time.Now().UTC()

	tests := []struct {
		name    string
		input   *AccessEvent
		checkFn func(*testing.T, *schema.Event)
	}{
		{
			name: "access granted",
			input: &AccessEvent{
				ID:        "acc-001",
				Timestamp: now,
				EventType: "access.granted",
				UserID:    "user-200",
				Username:  "developer",
				SessionID: "sess-200",
				Resource:  "/api/admin/users",
				Action:    "read",
				Granted:   true,
			},
			checkFn: func(t *testing.T, ev *schema.Event) {
				if ev.Outcome != schema.OutcomeSuccess {
					t.Errorf("expected outcome 'success', got %s", ev.Outcome)
				}
				if ev.Severity != 2 { // Informational for granted
					t.Errorf("expected severity 2 for granted access, got %d", ev.Severity)
				}
				if ev.Target != "/api/admin/users" {
					t.Errorf("expected target '/api/admin/users', got %s", ev.Target)
				}
			},
		},
		{
			name: "access denied",
			input: &AccessEvent{
				ID:         "acc-002",
				Timestamp:  now,
				EventType:  "access.denied",
				UserID:     "user-201",
				Username:   "guest",
				SessionID:  "sess-201",
				Resource:   "/api/admin/config",
				Action:     "write",
				Granted:    false,
				DenyReason: "insufficient_permissions",
				PolicyID:   "policy-001",
			},
			checkFn: func(t *testing.T, ev *schema.Event) {
				if ev.Outcome != schema.OutcomeFailure {
					t.Errorf("expected outcome 'failure', got %s", ev.Outcome)
				}
				if ev.Severity != 5 { // Warning for denied
					t.Errorf("expected severity 5 for denied access, got %d", ev.Severity)
				}
				denyReason, ok := ev.Metadata["bd_deny_reason"]
				if !ok || denyReason != "insufficient_permissions" {
					t.Error("expected metadata bd_deny_reason to be 'insufficient_permissions'")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := n.NormalizeAccessEvent(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if event == nil {
				t.Fatal("expected non-nil event")
			}
			tt.checkFn(t, event)
		})
	}
}

func TestNormalizeThreatEvent(t *testing.T) {
	n := NewNormalizer(DefaultNormalizerConfig())
	now := time.Now().UTC()

	tests := []struct {
		name    string
		input   *ThreatEvent
		checkFn func(*testing.T, *schema.Event)
	}{
		{
			name: "critical threat blocked",
			input: &ThreatEvent{
				ID:          "threat-001",
				Timestamp:   now,
				EventType:   "threat.blocked",
				ThreatType:  "malware",
				Severity:    "critical",
				SourceIP:    "203.0.113.50",
				DestIP:      "192.168.1.100",
				ProcessName: "evil.exe",
				ProcessPath: "/tmp/evil.exe",
				Description: "Malware detected and blocked",
				ActionTaken: "quarantine",
				Blocked:     true,
				Indicators:  []string{"hash:abc123", "domain:evil.com"},
				MITREAttack: []string{"T1059", "T1204"},
			},
			checkFn: func(t *testing.T, ev *schema.Event) {
				if ev.Severity != 10 { // Critical
					t.Errorf("expected severity 10 for critical threat, got %d", ev.Severity)
				}
				if ev.Outcome != schema.OutcomeSuccess { // Successfully blocked
					t.Errorf("expected outcome 'success' for blocked threat, got %s", ev.Outcome)
				}
				if ev.Network == nil || ev.Network.SourceIP != "203.0.113.50" {
					t.Error("expected Network with SourceIP")
				}
				if ev.Target != "process:evil.exe" {
					t.Errorf("expected target 'process:evil.exe', got %s", ev.Target)
				}
			},
		},
		{
			name: "low severity threat not blocked",
			input: &ThreatEvent{
				ID:          "threat-002",
				Timestamp:   now,
				EventType:   "threat.detected",
				ThreatType:  "anomaly",
				Severity:    "low",
				UserID:      "user-300",
				Description: "Unusual network activity",
				ActionTaken: "alert",
				Blocked:     false,
			},
			checkFn: func(t *testing.T, ev *schema.Event) {
				if ev.Severity != 3 { // Low
					t.Errorf("expected severity 3 for low threat, got %d", ev.Severity)
				}
				if ev.Outcome != schema.OutcomeFailure { // Not blocked
					t.Errorf("expected outcome 'failure' for unblocked threat, got %s", ev.Outcome)
				}
			},
		},
		{
			name: "high severity threat with network only",
			input: &ThreatEvent{
				ID:          "threat-003",
				Timestamp:   now,
				EventType:   "threat.detected",
				ThreatType:  "intrusion",
				Severity:    "high",
				DestIP:      "192.168.1.50",
				Description: "Port scan detected",
				ActionTaken: "alert",
				Blocked:     false,
			},
			checkFn: func(t *testing.T, ev *schema.Event) {
				if ev.Severity != 8 { // High
					t.Errorf("expected severity 8 for high threat, got %d", ev.Severity)
				}
				if ev.Target != "host:192.168.1.50" {
					t.Errorf("expected target 'host:192.168.1.50', got %s", ev.Target)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := n.NormalizeThreatEvent(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if event == nil {
				t.Fatal("expected non-nil event")
			}
			tt.checkFn(t, event)
		})
	}
}

func TestNormalizePolicyEvent(t *testing.T) {
	n := NewNormalizer(DefaultNormalizerConfig())
	now := time.Now().UTC()

	tests := []struct {
		name    string
		input   *PolicyEvent
		checkFn func(*testing.T, *schema.Event)
	}{
		{
			name: "policy violated",
			input: &PolicyEvent{
				ID:         "policy-evt-001",
				Timestamp:  now,
				EventType:  "policy.violated",
				PolicyID:   "pol-001",
				PolicyName: "No USB Storage",
				PolicyType: "usb",
				Action:     "block",
				Target:     "/dev/sdb1",
				UserID:     "user-400",
				Enforced:   true,
			},
			checkFn: func(t *testing.T, ev *schema.Event) {
				if ev.Severity != 6 { // High for violation
					t.Errorf("expected severity 6 for policy violation, got %d", ev.Severity)
				}
				if ev.Outcome != schema.OutcomeFailure {
					t.Errorf("expected outcome 'failure' for violation, got %s", ev.Outcome)
				}
			},
		},
		{
			name: "policy applied",
			input: &PolicyEvent{
				ID:         "policy-evt-002",
				Timestamp:  now,
				EventType:  "policy.applied",
				PolicyID:   "pol-002",
				PolicyName: "Network Access Control",
				PolicyType: "network",
				Action:     "allow",
				Target:     "192.168.1.0/24",
				Enforced:   true,
			},
			checkFn: func(t *testing.T, ev *schema.Event) {
				if ev.Severity != 2 { // Informational
					t.Errorf("expected severity 2 for policy applied, got %d", ev.Severity)
				}
				if ev.Outcome != schema.OutcomeSuccess {
					t.Errorf("expected outcome 'success' for applied policy, got %s", ev.Outcome)
				}
			},
		},
		{
			name: "policy changed",
			input: &PolicyEvent{
				ID:         "policy-evt-003",
				Timestamp:  now,
				EventType:  "policy.changed",
				PolicyID:   "pol-003",
				PolicyName: "Admin Access",
				PolicyType: "access",
				Action:     "modify",
				Target:     "role:admin",
				UserID:     "admin-001",
				Enforced:   true,
			},
			checkFn: func(t *testing.T, ev *schema.Event) {
				if ev.Severity != 4 { // Medium for change
					t.Errorf("expected severity 4 for policy change, got %d", ev.Severity)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := n.NormalizePolicyEvent(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if event == nil {
				t.Fatal("expected non-nil event")
			}
			tt.checkFn(t, event)
		})
	}
}

func TestNormalizeAuditLog(t *testing.T) {
	n := NewNormalizer(DefaultNormalizerConfig())
	now := time.Now().UTC()

	tests := []struct {
		name    string
		input   *AuditLogEntry
		checkFn func(*testing.T, *schema.Event)
	}{
		{
			name: "verified audit log success",
			input: &AuditLogEntry{
				ID:            "audit-001",
				Timestamp:     now,
				EventType:     "config.changed",
				Actor:         "admin",
				Action:        "update",
				Target:        "/etc/boundary/config.yaml",
				Outcome:       "success",
				ContentHash:   "sha256:abc123",
				PreviousHash:  "sha256:def456",
				Signature:     "sig:xyz789",
				SignatureAlgo: "ed25519",
				Verified:      true,
			},
			checkFn: func(t *testing.T, ev *schema.Event) {
				if ev.Action != "bd.audit.verified" {
					t.Errorf("expected action 'bd.audit.verified', got %s", ev.Action)
				}
				if ev.Outcome != schema.OutcomeSuccess {
					t.Errorf("expected outcome 'success', got %s", ev.Outcome)
				}
				if ev.Severity != 2 { // Informational
					t.Errorf("expected severity 2, got %d", ev.Severity)
				}
				verified, ok := ev.Metadata["bd_verified"]
				if !ok || verified != true {
					t.Error("expected metadata bd_verified to be true")
				}
			},
		},
		{
			name: "unverified audit log failure",
			input: &AuditLogEntry{
				ID:        "audit-002",
				Timestamp: now,
				EventType: "auth.failed",
				Actor:     "unknown",
				Action:    "login",
				Target:    "system",
				Outcome:   "failure",
				Verified:  false,
			},
			checkFn: func(t *testing.T, ev *schema.Event) {
				if ev.Action != "bd.audit.created" {
					t.Errorf("expected action 'bd.audit.created', got %s", ev.Action)
				}
				if ev.Outcome != schema.OutcomeFailure {
					t.Errorf("expected outcome 'failure', got %s", ev.Outcome)
				}
				if ev.Severity != 4 { // Higher for failure
					t.Errorf("expected severity 4 for failure, got %d", ev.Severity)
				}
			},
		},
		{
			name: "partial outcome",
			input: &AuditLogEntry{
				ID:        "audit-003",
				Timestamp: now,
				EventType: "batch.operation",
				Actor:     "system",
				Action:    "sync",
				Target:    "database",
				Outcome:   "partial",
				Verified:  false,
			},
			checkFn: func(t *testing.T, ev *schema.Event) {
				if ev.Outcome != schema.OutcomeUnknown {
					t.Errorf("expected outcome 'unknown' for partial, got %s", ev.Outcome)
				}
				if ev.Severity != 3 { // Notice for partial
					t.Errorf("expected severity 3 for partial, got %d", ev.Severity)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := n.NormalizeAuditLog(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if event == nil {
				t.Fatal("expected non-nil event")
			}
			tt.checkFn(t, event)
		})
	}
}

func TestMapThreatSeverity(t *testing.T) {
	n := NewNormalizer(DefaultNormalizerConfig())

	tests := []struct {
		severity string
		expected int
	}{
		{"critical", 10},
		{"high", 8},
		{"medium", 5},
		{"low", 3},
		{"unknown", 5}, // Default
	}

	for _, tt := range tests {
		result := n.mapThreatSeverity(tt.severity)
		if result != tt.expected {
			t.Errorf("mapThreatSeverity(%s) = %d, expected %d", tt.severity, result, tt.expected)
		}
	}
}

func TestMapAction_UnknownType(t *testing.T) {
	n := NewNormalizer(DefaultNormalizerConfig())

	action := n.mapAction("unknown.event.type")
	expected := "bd.event.unknown.event.type"
	if action != expected {
		t.Errorf("expected action %s for unknown type, got %s", expected, action)
	}
}

func TestDetermineThreatTarget(t *testing.T) {
	n := NewNormalizer(DefaultNormalizerConfig())

	tests := []struct {
		name     string
		input    *ThreatEvent
		expected string
	}{
		{
			name:     "process name takes priority",
			input:    &ThreatEvent{ID: "t1", ProcessName: "malware.exe", DestIP: "10.0.0.1", UserID: "user-1"},
			expected: "process:malware.exe",
		},
		{
			name:     "dest IP as fallback",
			input:    &ThreatEvent{ID: "t2", DestIP: "10.0.0.1", UserID: "user-1"},
			expected: "host:10.0.0.1",
		},
		{
			name:     "user ID as fallback",
			input:    &ThreatEvent{ID: "t3", UserID: "user-1"},
			expected: "user:user-1",
		},
		{
			name:     "threat ID as last resort",
			input:    &ThreatEvent{ID: "threat-xyz"},
			expected: "threat:threat-xyz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := n.determineThreatTarget(tt.input)
			if result != tt.expected {
				t.Errorf("expected target %s, got %s", tt.expected, result)
			}
		})
	}
}
