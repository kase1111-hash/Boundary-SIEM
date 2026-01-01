package schema

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateAction(t *testing.T) {
	tests := []struct {
		name   string
		action string
		want   bool
	}{
		{"simple action", "auth", true},
		{"dotted action", "auth.login", true},
		{"multi-dotted action", "auth.mfa.challenge", true},
		{"with underscore", "auth_attempt", true},
		{"with numbers", "auth2.login", true},
		{"complex valid", "user.session.created", true},
		{"uppercase invalid", "Auth.Login", false},
		{"space invalid", "auth login", false},
		{"starts with number", "2auth", false},
		{"hyphen invalid", "auth-login", false},
		{"empty string", "", false},
		{"just dot", ".", false},
		{"trailing dot", "auth.", false},
		{"leading dot", ".auth", false},
		{"double dot", "auth..login", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateAction(tt.action); got != tt.want {
				t.Errorf("ValidateAction(%q) = %v, want %v", tt.action, got, tt.want)
			}
		})
	}
}

func TestValidator_Validate(t *testing.T) {
	validator := NewValidator()
	now := time.Now().UTC()

	validEvent := func() *Event {
		return &Event{
			EventID:   uuid.New(),
			Timestamp: now,
			Source: Source{
				Product: "test-product",
				Host:    "test-host",
			},
			Action:   "test.action",
			Outcome:  OutcomeSuccess,
			Severity: 5,
		}
	}

	t.Run("valid event", func(t *testing.T) {
		event := validEvent()
		if err := validator.Validate(event); err != nil {
			t.Errorf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("missing source product", func(t *testing.T) {
		event := validEvent()
		event.Source.Product = ""
		if err := validator.Validate(event); err == nil {
			t.Error("Validate() should fail for missing source.product")
		}
	})

	t.Run("invalid action format", func(t *testing.T) {
		event := validEvent()
		event.Action = "INVALID ACTION"
		if err := validator.Validate(event); err == nil {
			t.Error("Validate() should fail for invalid action format")
		}
	})

	t.Run("invalid outcome", func(t *testing.T) {
		event := validEvent()
		event.Outcome = "invalid"
		if err := validator.Validate(event); err == nil {
			t.Error("Validate() should fail for invalid outcome")
		}
	})

	t.Run("severity too low", func(t *testing.T) {
		event := validEvent()
		event.Severity = 0
		if err := validator.Validate(event); err == nil {
			t.Error("Validate() should fail for severity < 1")
		}
	})

	t.Run("severity too high", func(t *testing.T) {
		event := validEvent()
		event.Severity = 11
		if err := validator.Validate(event); err == nil {
			t.Error("Validate() should fail for severity > 10")
		}
	})

	t.Run("timestamp too old", func(t *testing.T) {
		event := validEvent()
		event.Timestamp = now.Add(-8 * 24 * time.Hour) // 8 days ago
		if err := validator.Validate(event); err == nil {
			t.Error("Validate() should fail for timestamp too old")
		}
	})

	t.Run("timestamp in future", func(t *testing.T) {
		event := validEvent()
		event.Timestamp = now.Add(10 * time.Minute) // 10 min in future
		if err := validator.Validate(event); err == nil {
			t.Error("Validate() should fail for timestamp in future")
		}
	})

	t.Run("zero timestamp", func(t *testing.T) {
		event := validEvent()
		event.Timestamp = time.Time{}
		if err := validator.Validate(event); err == nil {
			t.Error("Validate() should fail for zero timestamp")
		}
	})

	t.Run("valid with actor", func(t *testing.T) {
		event := validEvent()
		event.Actor = &Actor{
			Type:      ActorUser,
			ID:        "user123",
			Name:      "John Doe",
			IPAddress: "192.168.1.100",
		}
		if err := validator.Validate(event); err != nil {
			t.Errorf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("invalid actor email", func(t *testing.T) {
		event := validEvent()
		event.Actor = &Actor{
			Type:  ActorUser,
			Email: "not-an-email",
		}
		if err := validator.Validate(event); err == nil {
			t.Error("Validate() should fail for invalid email")
		}
	})

	t.Run("invalid actor IP", func(t *testing.T) {
		event := validEvent()
		event.Actor = &Actor{
			Type:      ActorUser,
			IPAddress: "not-an-ip",
		}
		if err := validator.Validate(event); err == nil {
			t.Error("Validate() should fail for invalid IP address")
		}
	})
}

func TestValidatorWithConfig(t *testing.T) {
	now := time.Now().UTC()

	cfg := ValidatorConfig{
		MaxAge:    1 * time.Hour,
		MaxFuture: 1 * time.Minute,
	}
	validator := NewValidatorWithConfig(cfg)

	t.Run("custom max age", func(t *testing.T) {
		event := &Event{
			EventID:   uuid.New(),
			Timestamp: now.Add(-2 * time.Hour), // 2 hours ago
			Source:    Source{Product: "test"},
			Action:    "test.action",
			Outcome:   OutcomeSuccess,
			Severity:  5,
		}
		if err := validator.Validate(event); err == nil {
			t.Error("Validate() should fail for timestamp older than custom max age")
		}
	})

	t.Run("custom max future", func(t *testing.T) {
		event := &Event{
			EventID:   uuid.New(),
			Timestamp: now.Add(2 * time.Minute), // 2 min in future
			Source:    Source{Product: "test"},
			Action:    "test.action",
			Outcome:   OutcomeSuccess,
			Severity:  5,
		}
		if err := validator.Validate(event); err == nil {
			t.Error("Validate() should fail for timestamp beyond custom max future")
		}
	})
}

func TestOutcome_IsValid(t *testing.T) {
	tests := []struct {
		outcome Outcome
		want    bool
	}{
		{OutcomeSuccess, true},
		{OutcomeFailure, true},
		{OutcomeUnknown, true},
		{Outcome("invalid"), false},
		{Outcome(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.outcome), func(t *testing.T) {
			if got := tt.outcome.IsValid(); got != tt.want {
				t.Errorf("Outcome.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestActorType_IsValid(t *testing.T) {
	tests := []struct {
		actorType ActorType
		want      bool
	}{
		{ActorUser, true},
		{ActorProcess, true},
		{ActorService, true},
		{ActorSystem, true},
		{ActorUnknown, true},
		{ActorType("invalid"), false},
		{ActorType(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.actorType), func(t *testing.T) {
			if got := tt.actorType.IsValid(); got != tt.want {
				t.Errorf("ActorType.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}
