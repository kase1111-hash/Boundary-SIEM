package kernel

import (
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestDefaultEnforcementConfig(t *testing.T) {
	config := DefaultEnforcementConfig()

	if config.RequiredType != EnforcementNone {
		t.Errorf("expected RequiredType=EnforcementNone, got %s", config.RequiredType)
	}
	if config.RequiredMode != ModeEnforcing {
		t.Errorf("expected RequiredMode=ModeEnforcing, got %s", config.RequiredMode)
	}
	if config.ExpectedSELinuxDomain != "boundary_siem_t" {
		t.Errorf("unexpected SELinux domain: %s", config.ExpectedSELinuxDomain)
	}
	if config.ExpectedAppArmorProfile != "boundary-siem" {
		t.Errorf("unexpected AppArmor profile: %s", config.ExpectedAppArmorProfile)
	}
	if config.CheckInterval != 30*time.Second {
		t.Errorf("unexpected check interval: %v", config.CheckInterval)
	}
}

func TestEnforcementVerifier_DetectType(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	verifier := NewEnforcementVerifier(nil, logger)

	enfType := verifier.detectEnforcementType()

	// Just verify it returns a valid type
	switch enfType {
	case EnforcementSELinux, EnforcementAppArmor, EnforcementNone:
		// Valid
	default:
		t.Errorf("unexpected enforcement type: %s", enfType)
	}
}

func TestEnforcementVerifier_GetStatus_BeforeCheck(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	verifier := NewEnforcementVerifier(nil, logger)

	status := verifier.GetStatus()

	if status.Type != EnforcementUnknown {
		t.Errorf("expected unknown type before check, got %s", status.Type)
	}
	if status.Healthy {
		t.Error("expected unhealthy status before check")
	}
	if status.Error == "" {
		t.Error("expected error message before check")
	}
}

func TestEnforcementVerifier_Check(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultEnforcementConfig()
	config.RequiredType = EnforcementNone // Don't require specific type for test
	config.FailOnMismatch = false

	verifier := NewEnforcementVerifier(config, logger)

	err := verifier.Check()
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	status := verifier.GetStatus()
	if status.LastCheck.IsZero() {
		t.Error("expected LastCheck to be set")
	}
}

func TestEnforcementVerifier_OnChange(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultEnforcementConfig()
	config.RequiredType = EnforcementNone

	verifier := NewEnforcementVerifier(config, logger)

	var receivedStatus *EnforcementStatus
	verifier.SetOnChange(func(status *EnforcementStatus) {
		receivedStatus = status
	})

	err := verifier.Check()
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	if receivedStatus == nil {
		t.Error("expected onChange to be called")
	}
}

func TestEnforcementVerifier_StartStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultEnforcementConfig()
	config.RequiredType = EnforcementNone
	config.CheckInterval = 50 * time.Millisecond

	verifier := NewEnforcementVerifier(config, logger)

	err := verifier.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Wait for a periodic check
	time.Sleep(100 * time.Millisecond)

	verifier.Stop()

	// Verify status was updated
	status := verifier.GetStatus()
	if status.Type == EnforcementUnknown {
		t.Error("expected type to be determined after start")
	}
}

func TestParseSELinuxContext(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	verifier := NewEnforcementVerifier(nil, logger)

	tests := []struct {
		input    string
		expected *SecurityContext
	}{
		{
			input: "system_u:system_r:boundary_siem_t:s0",
			expected: &SecurityContext{
				User:  "system_u",
				Role:  "system_r",
				Type:  "boundary_siem_t",
				Level: "s0",
			},
		},
		{
			input: "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
			expected: &SecurityContext{
				User:     "unconfined_u",
				Role:     "unconfined_r",
				Type:     "unconfined_t",
				Level:    "s0-s0",
				Category: "c0.c1023",
			},
		},
		{
			input: "user_u",
			expected: &SecurityContext{
				User: "user_u",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ctx := verifier.parseSELinuxContext(tt.input)
			if ctx.User != tt.expected.User {
				t.Errorf("User: got %s, want %s", ctx.User, tt.expected.User)
			}
			if ctx.Role != tt.expected.Role {
				t.Errorf("Role: got %s, want %s", ctx.Role, tt.expected.Role)
			}
			if ctx.Type != tt.expected.Type {
				t.Errorf("Type: got %s, want %s", ctx.Type, tt.expected.Type)
			}
			if ctx.Level != tt.expected.Level {
				t.Errorf("Level: got %s, want %s", ctx.Level, tt.expected.Level)
			}
			if ctx.Category != tt.expected.Category {
				t.Errorf("Category: got %s, want %s", ctx.Category, tt.expected.Category)
			}
		})
	}
}

func TestParseAppArmorProfile(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	verifier := NewEnforcementVerifier(nil, logger)

	tests := []struct {
		input        string
		expectedName string
		expectedMode string
	}{
		{
			input:        "boundary-siem (enforce)",
			expectedName: "boundary-siem",
			expectedMode: "enforce",
		},
		{
			input:        "/usr/local/bin/boundary-siem (complain)",
			expectedName: "/usr/local/bin/boundary-siem",
			expectedMode: "complain",
		},
		{
			input:        "unconfined",
			expectedName: "unconfined",
			expectedMode: "",
		},
		{
			input:        "docker-default",
			expectedName: "docker-default",
			expectedMode: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			name, mode := verifier.parseAppArmorProfile(tt.input)
			if name != tt.expectedName {
				t.Errorf("Name: got %s, want %s", name, tt.expectedName)
			}
			if mode != tt.expectedMode {
				t.Errorf("Mode: got %s, want %s", mode, tt.expectedMode)
			}
		})
	}
}

func TestStatusEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        *EnforcementStatus
		b        *EnforcementStatus
		expected bool
	}{
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: true,
		},
		{
			name:     "one nil",
			a:        &EnforcementStatus{Type: EnforcementSELinux},
			b:        nil,
			expected: false,
		},
		{
			name: "equal",
			a: &EnforcementStatus{
				Type:         EnforcementSELinux,
				Mode:         ModeEnforcing,
				PolicyLoaded: true,
				Healthy:      true,
			},
			b: &EnforcementStatus{
				Type:         EnforcementSELinux,
				Mode:         ModeEnforcing,
				PolicyLoaded: true,
				Healthy:      true,
			},
			expected: true,
		},
		{
			name: "different type",
			a: &EnforcementStatus{
				Type: EnforcementSELinux,
			},
			b: &EnforcementStatus{
				Type: EnforcementAppArmor,
			},
			expected: false,
		},
		{
			name: "different mode",
			a: &EnforcementStatus{
				Type: EnforcementSELinux,
				Mode: ModeEnforcing,
			},
			b: &EnforcementStatus{
				Type: EnforcementSELinux,
				Mode: ModePermissive,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := statusEqual(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("statusEqual() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestAuditLogWatcher(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("SELinux patterns", func(t *testing.T) {
		watcher := NewAuditLogWatcher(EnforcementSELinux, logger)

		line := `type=AVC msg=audit(1234567890.123:456): avc:  denied  { read } for  pid=1234 comm="boundary-siem" name="test" scontext=system_u:system_r:boundary_siem_t:s0 tcontext=system_u:object_r:etc_t:s0`
		entry := watcher.parseLine(line)

		if entry == nil {
			t.Fatal("expected entry to be parsed")
		}
		if entry.Type != "AVC" {
			t.Errorf("Type: got %s, want AVC", entry.Type)
		}
		if entry.Result != "denied" {
			t.Errorf("Result: got %s, want denied", entry.Result)
		}
	})

	t.Run("AppArmor patterns", func(t *testing.T) {
		watcher := NewAuditLogWatcher(EnforcementAppArmor, logger)

		line := `apparmor="DENIED" operation="open" profile="boundary-siem" name="/etc/passwd"`
		entry := watcher.parseLine(line)

		if entry == nil {
			t.Fatal("expected entry to be parsed")
		}
		if entry.Type != "APPARMOR" {
			t.Errorf("Type: got %s, want APPARMOR", entry.Type)
		}
		if entry.Result != "DENIED" {
			t.Errorf("Result: got %s, want DENIED", entry.Result)
		}
		if entry.Action != "open" {
			t.Errorf("Action: got %s, want open", entry.Action)
		}
	})
}

func TestAuditLogWatcher_StartStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	watcher := NewAuditLogWatcher(EnforcementSELinux, logger)

	err := watcher.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)

	watcher.Stop()
}

func TestEnforcementConstants(t *testing.T) {
	// Verify string values are as expected
	if string(EnforcementSELinux) != "selinux" {
		t.Errorf("EnforcementSELinux = %s", EnforcementSELinux)
	}
	if string(EnforcementAppArmor) != "apparmor" {
		t.Errorf("EnforcementAppArmor = %s", EnforcementAppArmor)
	}
	if string(ModeEnforcing) != "enforcing" {
		t.Errorf("ModeEnforcing = %s", ModeEnforcing)
	}
	if string(ModePermissive) != "permissive" {
		t.Errorf("ModePermissive = %s", ModePermissive)
	}
	if string(ModeComplain) != "complain" {
		t.Errorf("ModeComplain = %s", ModeComplain)
	}
}

func TestEnforcementVerifier_FailOnMismatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Configure to require SELinux but likely not running in test env
	config := &EnforcementConfig{
		RequiredType:   EnforcementSELinux,
		RequiredMode:   ModeEnforcing,
		FailOnMismatch: true,
	}

	verifier := NewEnforcementVerifier(config, logger)

	// Detect actual type
	actualType := verifier.detectEnforcementType()

	if actualType != EnforcementSELinux {
		// Should fail if SELinux isn't available
		err := verifier.Check()
		if err == nil {
			t.Error("expected error when SELinux not available but required")
		}
	}
}

func TestPolicyInstaller(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	installer := NewPolicyInstaller(logger)

	if installer == nil {
		t.Fatal("expected non-nil installer")
	}

	// VerifyInstallation should work (it just runs Check internally)
	// In most test environments, this will pass with EnforcementNone
	// since SELinux/AppArmor usually aren't active
}

func BenchmarkEnforcementCheck(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	config := DefaultEnforcementConfig()
	config.RequiredType = EnforcementNone
	verifier := NewEnforcementVerifier(config, logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifier.Check()
	}
}

func BenchmarkParseSELinuxContext(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	verifier := NewEnforcementVerifier(nil, logger)
	contextStr := "system_u:system_r:boundary_siem_t:s0-s0:c0.c1023"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifier.parseSELinuxContext(contextStr)
	}
}
