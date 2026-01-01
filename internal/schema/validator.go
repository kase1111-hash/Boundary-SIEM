package schema

import (
	"fmt"
	"regexp"
	"time"

	"github.com/go-playground/validator/v10"
)

// actionPattern defines the valid format for action strings.
// Actions must be lowercase, start with a letter, and use dots as separators.
// Examples: "auth.login", "session.created", "file.accessed"
var actionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)

// Validator handles validation of events against the canonical schema.
type Validator struct {
	validate  *validator.Validate
	maxAge    time.Duration
	maxFuture time.Duration
}

// ValidatorConfig holds configuration for the validator.
type ValidatorConfig struct {
	MaxAge    time.Duration
	MaxFuture time.Duration
}

// DefaultValidatorConfig returns the default validator configuration.
func DefaultValidatorConfig() ValidatorConfig {
	return ValidatorConfig{
		MaxAge:    7 * 24 * time.Hour, // 7 days
		MaxFuture: 5 * time.Minute,
	}
}

// NewValidator creates a new Validator with default configuration.
func NewValidator() *Validator {
	return NewValidatorWithConfig(DefaultValidatorConfig())
}

// NewValidatorWithConfig creates a new Validator with the specified configuration.
func NewValidatorWithConfig(cfg ValidatorConfig) *Validator {
	v := validator.New()

	// Register custom validation for action format
	v.RegisterValidation("action_format", func(fl validator.FieldLevel) bool {
		return actionPattern.MatchString(fl.Field().String())
	})

	return &Validator{
		validate:  v,
		maxAge:    cfg.MaxAge,
		maxFuture: cfg.MaxFuture,
	}
}

// Validate validates an event against the canonical schema.
// Returns an error if validation fails.
func (v *Validator) Validate(event *Event) error {
	// Struct validation using go-playground/validator
	if err := v.validate.Struct(event); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Timestamp bounds check
	now := time.Now().UTC()

	if event.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required")
	}

	if event.Timestamp.Before(now.Add(-v.maxAge)) {
		return fmt.Errorf("timestamp too old: %v (max age: %v)", event.Timestamp, v.maxAge)
	}

	if event.Timestamp.After(now.Add(v.maxFuture)) {
		return fmt.Errorf("timestamp in future: %v (max future: %v)", event.Timestamp, v.maxFuture)
	}

	// Validate source
	if event.Source.Product == "" {
		return fmt.Errorf("source.product is required")
	}

	return nil
}

// ValidateAction checks if an action string matches the required format.
func ValidateAction(action string) bool {
	return actionPattern.MatchString(action)
}
