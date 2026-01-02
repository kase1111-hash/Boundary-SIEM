// Package schema defines the canonical event schema for Boundary-SIEM.
// All ingested events are normalized to this structure before storage.
package schema

import (
	"time"

	"github.com/google/uuid"
)

// Event represents the canonical SIEM event format.
// All ingested events are normalized to this structure.
type Event struct {
	// Required fields
	EventID   uuid.UUID `json:"event_id" validate:"required"`
	Timestamp time.Time `json:"timestamp" validate:"required"`
	Source    Source    `json:"source" validate:"required"`
	Action    string    `json:"action" validate:"required,action_format"`
	Outcome   Outcome   `json:"outcome" validate:"required,oneof=success failure unknown"`
	Severity  int       `json:"severity" validate:"required,min=1,max=10"`

	// Optional fields
	Actor    *Actor         `json:"actor,omitempty"`
	Target   string         `json:"target,omitempty" validate:"max=1024"`
	Raw      string         `json:"raw,omitempty" validate:"max=65536"`
	Metadata map[string]any `json:"metadata,omitempty"`

	// Internal fields (set by system)
	SchemaVersion string    `json:"schema_version"`
	ReceivedAt    time.Time `json:"received_at"`
	TenantID      string    `json:"tenant_id"`
}

// Source identifies where the event originated.
type Source struct {
	Product    string `json:"product" validate:"required,max=256"`
	Host       string `json:"host,omitempty" validate:"max=256"`
	InstanceID string `json:"instance_id,omitempty" validate:"max=128"`
	Version    string `json:"version,omitempty" validate:"max=64"`
}

// Actor represents the entity that performed the action.
type Actor struct {
	Type      ActorType `json:"type,omitempty" validate:"omitempty,oneof=user process service system unknown"`
	ID        string    `json:"id,omitempty" validate:"max=256"`
	Name      string    `json:"name,omitempty" validate:"max=256"`
	Email     string    `json:"email,omitempty" validate:"omitempty,email"`
	IPAddress string    `json:"ip_address,omitempty" validate:"omitempty,ip"`
}

// Outcome represents the result of an action.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeUnknown Outcome = "unknown"
)

// IsValid checks if the outcome is a valid value.
func (o Outcome) IsValid() bool {
	switch o {
	case OutcomeSuccess, OutcomeFailure, OutcomeUnknown:
		return true
	}
	return false
}

// ActorType represents the type of entity that performed an action.
type ActorType string

const (
	ActorUser    ActorType = "user"
	ActorProcess ActorType = "process"
	ActorService ActorType = "service"
	ActorSystem  ActorType = "system"
	ActorUnknown ActorType = "unknown"
)

// IsValid checks if the actor type is a valid value.
func (a ActorType) IsValid() bool {
	switch a {
	case ActorUser, ActorProcess, ActorService, ActorSystem, ActorUnknown:
		return true
	}
	return false
}

// SchemaVersionCurrent is the current version of the event schema.
const SchemaVersionCurrent = "1.0.0"

// CanonicalEvent is an alias for Event for backward compatibility.
type CanonicalEvent = Event
