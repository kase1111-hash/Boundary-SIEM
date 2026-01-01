// Package privilege provides re-entrant privilege verification for security operations.
// It ensures privileges are verified before each sensitive operation and detects
// unexpected privilege changes during execution.
package privilege

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Common errors.
var (
	ErrInsufficientPrivileges = errors.New("insufficient privileges for operation")
	ErrPrivilegeChanged       = errors.New("privileges changed unexpectedly")
	ErrCapabilityMissing      = errors.New("required capability missing")
	ErrVerificationFailed     = errors.New("privilege verification failed")
	ErrNotRoot                = errors.New("root privileges required")
	ErrRootRequired           = errors.New("operation requires root")
)

// Capability represents a Linux capability.
type Capability int

// Linux capabilities (subset of most commonly used).
const (
	CAP_NET_BIND_SERVICE Capability = 10
	CAP_NET_ADMIN        Capability = 12
	CAP_NET_RAW          Capability = 13
	CAP_SYS_ADMIN        Capability = 21
	CAP_SYS_RESOURCE     Capability = 24
	CAP_SETUID           Capability = 7
	CAP_SETGID           Capability = 6
	CAP_DAC_READ_SEARCH  Capability = 2
	CAP_DAC_OVERRIDE     Capability = 1
	CAP_CHOWN            Capability = 0
	CAP_FOWNER           Capability = 3
	CAP_KILL             Capability = 5
	CAP_SYS_PTRACE       Capability = 19
)

// CapabilityName returns the name of a capability.
func (c Capability) String() string {
	names := map[Capability]string{
		CAP_NET_BIND_SERVICE: "CAP_NET_BIND_SERVICE",
		CAP_NET_ADMIN:        "CAP_NET_ADMIN",
		CAP_NET_RAW:          "CAP_NET_RAW",
		CAP_SYS_ADMIN:        "CAP_SYS_ADMIN",
		CAP_SYS_RESOURCE:     "CAP_SYS_RESOURCE",
		CAP_SETUID:           "CAP_SETUID",
		CAP_SETGID:           "CAP_SETGID",
		CAP_DAC_READ_SEARCH:  "CAP_DAC_READ_SEARCH",
		CAP_DAC_OVERRIDE:     "CAP_DAC_OVERRIDE",
		CAP_CHOWN:            "CAP_CHOWN",
		CAP_FOWNER:           "CAP_FOWNER",
		CAP_KILL:             "CAP_KILL",
		CAP_SYS_PTRACE:       "CAP_SYS_PTRACE",
	}
	if name, ok := names[c]; ok {
		return name
	}
	return fmt.Sprintf("CAP_%d", int(c))
}

// PrivilegeState captures the current privilege state of the process.
type PrivilegeState struct {
	UID         int           `json:"uid"`
	GID         int           `json:"gid"`
	EUID        int           `json:"euid"`
	EGID        int           `json:"egid"`
	Groups      []int         `json:"groups"`
	Capabilities []Capability `json:"capabilities"`
	CapturedAt  time.Time     `json:"captured_at"`
	NoNewPrivs  bool          `json:"no_new_privs"`
}

// String returns a string representation of the privilege state.
func (ps *PrivilegeState) String() string {
	caps := make([]string, len(ps.Capabilities))
	for i, c := range ps.Capabilities {
		caps[i] = c.String()
	}
	return fmt.Sprintf("UID=%d GID=%d EUID=%d EGID=%d caps=[%s]",
		ps.UID, ps.GID, ps.EUID, ps.EGID, strings.Join(caps, ","))
}

// IsRoot returns true if the process has root privileges.
func (ps *PrivilegeState) IsRoot() bool {
	return ps.EUID == 0
}

// HasCapability checks if a capability is present.
func (ps *PrivilegeState) HasCapability(cap Capability) bool {
	for _, c := range ps.Capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// Requirement defines a privilege requirement for an operation.
type Requirement struct {
	Name            string       `json:"name"`
	RequireRoot     bool         `json:"require_root"`
	RequiredCaps    []Capability `json:"required_caps"`
	AllowedUIDs     []int        `json:"allowed_uids,omitempty"`
	AllowedGIDs     []int        `json:"allowed_gids,omitempty"`
	RequireNoNewPrivs bool       `json:"require_no_new_privs"`
}

// Verifier handles privilege verification before operations.
type Verifier struct {
	mu sync.RWMutex

	// Initial state captured at startup
	initialState *PrivilegeState

	// Current requirements by operation name
	requirements map[string]*Requirement

	// Verification history for audit
	history []VerificationResult

	// Configuration
	config *VerifierConfig

	// Logger
	logger *slog.Logger

	// Callbacks
	onViolation func(op string, required, actual *PrivilegeState)
}

// VerifierConfig configures the privilege verifier.
type VerifierConfig struct {
	// MaxHistorySize is the maximum number of verification results to keep.
	MaxHistorySize int
	// VerifyOnEachCall re-verifies privileges on every operation.
	VerifyOnEachCall bool
	// StrictMode fails operations if any check fails.
	StrictMode bool
	// AuditAll logs all verification attempts.
	AuditAll bool
	// DetectChanges monitors for unexpected privilege changes.
	DetectChanges bool
}

// DefaultVerifierConfig returns sensible defaults.
func DefaultVerifierConfig() *VerifierConfig {
	return &VerifierConfig{
		MaxHistorySize:   1000,
		VerifyOnEachCall: true,
		StrictMode:       true,
		AuditAll:         true,
		DetectChanges:    true,
	}
}

// VerificationResult records the outcome of a verification.
type VerificationResult struct {
	Operation    string        `json:"operation"`
	Timestamp    time.Time     `json:"timestamp"`
	Success      bool          `json:"success"`
	State        *PrivilegeState `json:"state"`
	Required     *Requirement  `json:"required,omitempty"`
	Error        string        `json:"error,omitempty"`
	CallerFile   string        `json:"caller_file,omitempty"`
	CallerLine   int           `json:"caller_line,omitempty"`
}

// NewVerifier creates a new privilege verifier.
func NewVerifier(config *VerifierConfig, logger *slog.Logger) (*Verifier, error) {
	if config == nil {
		config = DefaultVerifierConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	v := &Verifier{
		requirements: make(map[string]*Requirement),
		history:      make([]VerificationResult, 0, config.MaxHistorySize),
		config:       config,
		logger:       logger,
	}

	// Capture initial state
	state, err := v.CaptureState()
	if err != nil {
		return nil, fmt.Errorf("failed to capture initial state: %w", err)
	}
	v.initialState = state

	v.logger.Info("privilege verifier initialized",
		"initial_state", state.String(),
		"strict_mode", config.StrictMode)

	return v, nil
}

// CaptureState captures the current privilege state.
func (v *Verifier) CaptureState() (*PrivilegeState, error) {
	state := &PrivilegeState{
		UID:        syscall.Getuid(),
		GID:        syscall.Getgid(),
		EUID:       syscall.Geteuid(),
		EGID:       syscall.Getegid(),
		CapturedAt: time.Now(),
	}

	// Get supplementary groups
	groups, err := syscall.Getgroups()
	if err == nil {
		state.Groups = groups
	}

	// Get capabilities from /proc
	caps, err := v.readCapabilities()
	if err == nil {
		state.Capabilities = caps
	}

	// Check no_new_privs
	state.NoNewPrivs = v.checkNoNewPrivs()

	return state, nil
}

// readCapabilities reads the effective capabilities from /proc.
func (v *Verifier) readCapabilities() ([]Capability, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil, err
	}

	var caps []Capability
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "CapEff:") {
			hexCaps := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			capBits, err := strconv.ParseUint(hexCaps, 16, 64)
			if err != nil {
				return nil, err
			}

			// Check each capability bit
			for i := 0; i < 64; i++ {
				if capBits&(1<<uint(i)) != 0 {
					caps = append(caps, Capability(i))
				}
			}
			break
		}
	}

	return caps, nil
}

// checkNoNewPrivs checks if PR_SET_NO_NEW_PRIVS is set.
func (v *Verifier) checkNoNewPrivs() bool {
	// Read from /proc/self/status
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "NoNewPrivs:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "NoNewPrivs:"))
			return val == "1"
		}
	}

	return false
}

// RegisterRequirement registers a privilege requirement for an operation.
func (v *Verifier) RegisterRequirement(req *Requirement) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.requirements[req.Name] = req
	v.logger.Debug("registered privilege requirement",
		"operation", req.Name,
		"require_root", req.RequireRoot,
		"caps", len(req.RequiredCaps))
}

// Verify checks if the current process has the required privileges for an operation.
func (v *Verifier) Verify(ctx context.Context, operation string) error {
	result := v.verify(ctx, operation)

	// Record result
	v.recordResult(result)

	if !result.Success {
		if v.onViolation != nil && result.Required != nil {
			v.onViolation(operation, nil, result.State)
		}
		return fmt.Errorf("%w: %s", ErrVerificationFailed, result.Error)
	}

	return nil
}

// verify performs the actual verification.
func (v *Verifier) verify(ctx context.Context, operation string) VerificationResult {
	result := VerificationResult{
		Operation: operation,
		Timestamp: time.Now(),
		Success:   true,
	}

	// Capture caller info for audit
	if _, file, line, ok := runtime.Caller(2); ok {
		result.CallerFile = file
		result.CallerLine = line
	}

	// Always capture current state
	state, err := v.CaptureState()
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("failed to capture state: %v", err)
		return result
	}
	result.State = state

	// Check for unexpected privilege changes
	if v.config.DetectChanges && v.initialState != nil {
		if changed, msg := v.detectChanges(state); changed {
			v.logger.Warn("privilege state changed",
				"operation", operation,
				"change", msg)
			if v.config.StrictMode {
				result.Success = false
				result.Error = fmt.Sprintf("privilege changed: %s", msg)
				return result
			}
		}
	}

	// Get requirement for this operation
	v.mu.RLock()
	req, hasReq := v.requirements[operation]
	v.mu.RUnlock()

	if !hasReq {
		// No specific requirement - just capture state
		if v.config.AuditAll {
			v.logger.Debug("verified operation (no requirement)",
				"operation", operation,
				"state", state.String())
		}
		return result
	}

	result.Required = req

	// Verify against requirement
	if req.RequireRoot && !state.IsRoot() {
		result.Success = false
		result.Error = "root privileges required"
		return result
	}

	// Check required capabilities
	for _, cap := range req.RequiredCaps {
		if !state.HasCapability(cap) {
			result.Success = false
			result.Error = fmt.Sprintf("missing capability: %s", cap)
			return result
		}
	}

	// Check allowed UIDs
	if len(req.AllowedUIDs) > 0 {
		allowed := false
		for _, uid := range req.AllowedUIDs {
			if state.EUID == uid {
				allowed = true
				break
			}
		}
		if !allowed {
			result.Success = false
			result.Error = fmt.Sprintf("UID %d not in allowed list", state.EUID)
			return result
		}
	}

	// Check allowed GIDs
	if len(req.AllowedGIDs) > 0 {
		allowed := false
		for _, gid := range req.AllowedGIDs {
			if state.EGID == gid {
				allowed = true
				break
			}
		}
		if !allowed {
			result.Success = false
			result.Error = fmt.Sprintf("GID %d not in allowed list", state.EGID)
			return result
		}
	}

	// Check no_new_privs if required
	if req.RequireNoNewPrivs && !state.NoNewPrivs {
		result.Success = false
		result.Error = "no_new_privs not set"
		return result
	}

	if v.config.AuditAll {
		v.logger.Debug("verified operation",
			"operation", operation,
			"state", state.String())
	}

	return result
}

// detectChanges checks if privileges have changed from initial state.
func (v *Verifier) detectChanges(current *PrivilegeState) (bool, string) {
	if v.initialState == nil {
		return false, ""
	}

	var changes []string

	if current.EUID != v.initialState.EUID {
		changes = append(changes, fmt.Sprintf("EUID: %d -> %d", v.initialState.EUID, current.EUID))
	}
	if current.EGID != v.initialState.EGID {
		changes = append(changes, fmt.Sprintf("EGID: %d -> %d", v.initialState.EGID, current.EGID))
	}

	// Check for capability loss
	for _, cap := range v.initialState.Capabilities {
		if !current.HasCapability(cap) {
			changes = append(changes, fmt.Sprintf("lost %s", cap))
		}
	}

	// Check for capability gain (suspicious)
	for _, cap := range current.Capabilities {
		found := false
		for _, initCap := range v.initialState.Capabilities {
			if cap == initCap {
				found = true
				break
			}
		}
		if !found {
			changes = append(changes, fmt.Sprintf("gained %s", cap))
		}
	}

	if len(changes) > 0 {
		return true, strings.Join(changes, "; ")
	}
	return false, ""
}

// recordResult records a verification result.
func (v *Verifier) recordResult(result VerificationResult) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Evict oldest if at capacity
	if len(v.history) >= v.config.MaxHistorySize {
		v.history = v.history[1:]
	}

	v.history = append(v.history, result)

	// Log failures
	if !result.Success {
		v.logger.Warn("privilege verification failed",
			"operation", result.Operation,
			"error", result.Error,
			"caller_file", result.CallerFile,
			"caller_line", result.CallerLine)
	}
}

// GetHistory returns recent verification results.
func (v *Verifier) GetHistory(count int) []VerificationResult {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if count > len(v.history) {
		count = len(v.history)
	}

	result := make([]VerificationResult, count)
	copy(result, v.history[len(v.history)-count:])
	return result
}

// GetFailures returns recent failed verifications.
func (v *Verifier) GetFailures() []VerificationResult {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var failures []VerificationResult
	for _, r := range v.history {
		if !r.Success {
			failures = append(failures, r)
		}
	}
	return failures
}

// OnViolation sets a callback for privilege violations.
func (v *Verifier) OnViolation(callback func(op string, required, actual *PrivilegeState)) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.onViolation = callback
}

// GetInitialState returns the initial privilege state.
func (v *Verifier) GetInitialState() *PrivilegeState {
	return v.initialState
}

// RequireRoot verifies root privileges before executing a function.
func (v *Verifier) RequireRoot(ctx context.Context, operation string, fn func() error) error {
	state, err := v.CaptureState()
	if err != nil {
		return fmt.Errorf("failed to capture state: %w", err)
	}

	if !state.IsRoot() {
		v.recordResult(VerificationResult{
			Operation: operation,
			Timestamp: time.Now(),
			Success:   false,
			State:     state,
			Error:     "root required",
		})
		return ErrNotRoot
	}

	return fn()
}

// RequireCaps verifies capabilities before executing a function.
func (v *Verifier) RequireCaps(ctx context.Context, operation string, caps []Capability, fn func() error) error {
	state, err := v.CaptureState()
	if err != nil {
		return fmt.Errorf("failed to capture state: %w", err)
	}

	for _, cap := range caps {
		if !state.HasCapability(cap) {
			v.recordResult(VerificationResult{
				Operation: operation,
				Timestamp: time.Now(),
				Success:   false,
				State:     state,
				Error:     fmt.Sprintf("missing %s", cap),
			})
			return fmt.Errorf("%w: %s", ErrCapabilityMissing, cap)
		}
	}

	v.recordResult(VerificationResult{
		Operation: operation,
		Timestamp: time.Now(),
		Success:   true,
		State:     state,
	})

	return fn()
}

// WithPrivilegeCheck wraps a function with privilege verification.
func WithPrivilegeCheck[T any](v *Verifier, ctx context.Context, operation string, fn func() (T, error)) (T, error) {
	var zero T

	if err := v.Verify(ctx, operation); err != nil {
		return zero, err
	}

	return fn()
}

// PrivilegedOperation wraps a function to verify privileges on each call.
type PrivilegedOperation struct {
	verifier  *Verifier
	operation string
	req       *Requirement
}

// NewPrivilegedOperation creates a new privileged operation wrapper.
func NewPrivilegedOperation(v *Verifier, operation string, req *Requirement) *PrivilegedOperation {
	if req != nil {
		v.RegisterRequirement(req)
	}
	return &PrivilegedOperation{
		verifier:  v,
		operation: operation,
		req:       req,
	}
}

// Execute runs the operation with privilege verification.
func (po *PrivilegedOperation) Execute(ctx context.Context, fn func() error) error {
	if err := po.verifier.Verify(ctx, po.operation); err != nil {
		return err
	}
	return fn()
}

// Common requirements for SIEM operations.
var (
	RequireFirewallAdmin = &Requirement{
		Name:         "firewall_admin",
		RequiredCaps: []Capability{CAP_NET_ADMIN, CAP_NET_RAW},
	}

	RequireBindLowPort = &Requirement{
		Name:         "bind_low_port",
		RequiredCaps: []Capability{CAP_NET_BIND_SERVICE},
	}

	RequireFileAdmin = &Requirement{
		Name:         "file_admin",
		RequiredCaps: []Capability{CAP_DAC_READ_SEARCH, CAP_CHOWN, CAP_FOWNER},
	}

	RequireProcessAdmin = &Requirement{
		Name:         "process_admin",
		RequiredCaps: []Capability{CAP_KILL, CAP_SYS_PTRACE},
	}

	RequireRootOnly = &Requirement{
		Name:        "root_only",
		RequireRoot: true,
	}

	RequireSecureExec = &Requirement{
		Name:              "secure_exec",
		RequireNoNewPrivs: true,
	}
)

// DefaultFirewallVerifier creates a verifier configured for firewall operations.
func DefaultFirewallVerifier(logger *slog.Logger) (*Verifier, error) {
	v, err := NewVerifier(DefaultVerifierConfig(), logger)
	if err != nil {
		return nil, err
	}

	v.RegisterRequirement(RequireFirewallAdmin)
	v.RegisterRequirement(&Requirement{
		Name:         "nft_execute",
		RequiredCaps: []Capability{CAP_NET_ADMIN},
	})
	v.RegisterRequirement(&Requirement{
		Name:         "iptables_execute",
		RequiredCaps: []Capability{CAP_NET_ADMIN, CAP_NET_RAW},
	})

	return v, nil
}

// DefaultSIEMVerifier creates a verifier configured for SIEM operations.
func DefaultSIEMVerifier(logger *slog.Logger) (*Verifier, error) {
	v, err := NewVerifier(DefaultVerifierConfig(), logger)
	if err != nil {
		return nil, err
	}

	// Register common SIEM requirements
	v.RegisterRequirement(RequireBindLowPort)
	v.RegisterRequirement(RequireFileAdmin)
	v.RegisterRequirement(RequireSecureExec)

	v.RegisterRequirement(&Requirement{
		Name:         "ingest_syslog",
		RequiredCaps: []Capability{CAP_NET_BIND_SERVICE},
	})
	v.RegisterRequirement(&Requirement{
		Name:         "read_system_logs",
		RequiredCaps: []Capability{CAP_DAC_READ_SEARCH},
	})
	v.RegisterRequirement(&Requirement{
		Name:         "set_resource_limits",
		RequiredCaps: []Capability{CAP_SYS_RESOURCE},
	})

	return v, nil
}
