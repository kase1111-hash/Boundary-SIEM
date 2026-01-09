// Package commitment provides cryptographic state commitments for mode transitions.
// It creates tamper-evident proofs of state before and after security mode changes,
// enabling detection of unauthorized modifications and providing an audit trail.
package commitment

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Common errors.
var (
	ErrInvalidCommitment     = errors.New("invalid commitment")
	ErrCommitmentMismatch    = errors.New("commitment verification failed")
	ErrChainBroken           = errors.New("commitment chain broken")
	ErrNoActiveTransition    = errors.New("no active mode transition")
	ErrTransitionInProgress  = errors.New("mode transition already in progress")
	ErrStateModified         = errors.New("state was modified during transition")
	ErrPersistenceFailed     = errors.New("persistence verification failed")
	ErrCorruptedState        = errors.New("persisted state is corrupted")
	ErrConfirmationRequired  = errors.New("human confirmation required")
	ErrConfirmationExpired   = errors.New("confirmation code expired")
	ErrInvalidConfirmation   = errors.New("invalid confirmation code")
	ErrTooManyAttempts       = errors.New("too many confirmation attempts")
	ErrInsufficientApprovers = errors.New("insufficient approvers for this transition")
	ErrDuplicateApprover     = errors.New("approver has already approved this transition")
)

// SecurityMode represents a security mode.
type SecurityMode string

const (
	ModeNormal    SecurityMode = "normal"
	ModeElevated  SecurityMode = "elevated"
	ModeLockdown  SecurityMode = "lockdown"
	ModeColdroom  SecurityMode = "coldroom"
	ModeEmergency SecurityMode = "emergency"
)

// String returns the mode name.
func (m SecurityMode) String() string {
	return string(m)
}

// Level returns the security level (higher = more restrictive).
func (m SecurityMode) Level() int {
	levels := map[SecurityMode]int{
		ModeNormal:    0,
		ModeElevated:  1,
		ModeLockdown:  2,
		ModeColdroom:  3,
		ModeEmergency: 4,
	}
	if level, ok := levels[m]; ok {
		return level
	}
	return -1
}

// StateEntry represents a key-value pair in the state.
type StateEntry struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	Timestamp time.Time `json:"timestamp"`
}

// State represents the system state to be committed.
type State struct {
	Mode      SecurityMode `json:"mode"`
	Version   int          `json:"version"`
	Entries   []StateEntry `json:"entries"`
	Timestamp time.Time    `json:"timestamp"`
	Nonce     string       `json:"nonce"`
}

// Hash computes the SHA-256 hash of the state.
func (s *State) Hash() string {
	h := sha256.New()

	// Deterministic serialization
	h.Write([]byte(s.Mode))
	h.Write([]byte(fmt.Sprintf("%d", s.Version)))

	// Sort entries for deterministic ordering
	entries := make([]StateEntry, len(s.Entries))
	copy(entries, s.Entries)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Key < entries[j].Key
	})

	for _, e := range entries {
		h.Write([]byte(e.Key))
		h.Write([]byte(e.Value))
	}

	h.Write([]byte(s.Timestamp.Format(time.RFC3339Nano)))
	h.Write([]byte(s.Nonce))

	return hex.EncodeToString(h.Sum(nil))
}

// Commitment represents a cryptographic commitment to a state.
type Commitment struct {
	ID             string       `json:"id"`
	StateHash      string       `json:"state_hash"`
	PreviousHash   string       `json:"previous_hash,omitempty"`
	Mode           SecurityMode `json:"mode"`
	Version        int          `json:"version"`
	Timestamp      time.Time    `json:"timestamp"`
	Signature      string       `json:"signature"` // HMAC signature
	MerkleRoot     string       `json:"merkle_root,omitempty"`
	TransitionID   string       `json:"transition_id,omitempty"`
	CommitmentType string       `json:"commitment_type"` // "pre", "post", "checkpoint"
}

// Verify verifies the commitment signature.
func (c *Commitment) Verify(key []byte) bool {
	expected := c.computeSignature(key)
	return hmac.Equal([]byte(c.Signature), []byte(expected))
}

// computeSignature computes the HMAC signature.
func (c *Commitment) computeSignature(key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(c.ID))
	h.Write([]byte(c.StateHash))
	h.Write([]byte(c.PreviousHash))
	h.Write([]byte(c.Mode))
	h.Write([]byte(fmt.Sprintf("%d", c.Version)))
	h.Write([]byte(c.Timestamp.Format(time.RFC3339Nano)))
	h.Write([]byte(c.MerkleRoot))
	h.Write([]byte(c.TransitionID))
	h.Write([]byte(c.CommitmentType))
	return hex.EncodeToString(h.Sum(nil))
}

// Sign signs the commitment with the given key.
func (c *Commitment) Sign(key []byte) {
	c.Signature = c.computeSignature(key)
}

// ModeTransition represents a mode transition with before/after commitments.
type ModeTransition struct {
	ID             string       `json:"id"`
	FromMode       SecurityMode `json:"from_mode"`
	ToMode         SecurityMode `json:"to_mode"`
	PreCommitment  *Commitment  `json:"pre_commitment"`
	PostCommitment *Commitment  `json:"post_commitment,omitempty"`
	StartTime      time.Time    `json:"start_time"`
	EndTime        *time.Time   `json:"end_time,omitempty"`
	Status         string       `json:"status"` // "pending", "completed", "failed", "rolled_back", "awaiting_confirmation"
	Reason         string       `json:"reason,omitempty"`
	Initiator      string       `json:"initiator,omitempty"`
	Approved       bool         `json:"approved"`
	ApprovedBy     string       `json:"approved_by,omitempty"`

	// Human confirmation fields
	Confirmation *TransitionConfirmation `json:"confirmation,omitempty"`
}

// TransitionConfirmation holds human confirmation state for a transition.
type TransitionConfirmation struct {
	Code           string           `json:"code"`                      // The confirmation code
	CodeHash       string           `json:"code_hash"`                 // SHA-256 hash of the code
	ExpiresAt      time.Time        `json:"expires_at"`                // When the code expires
	CreatedAt      time.Time        `json:"created_at"`                // When the code was created
	Attempts       int              `json:"attempts"`                  // Number of confirmation attempts
	MaxAttempts    int              `json:"max_attempts"`              // Maximum allowed attempts
	RequiredCount  int              `json:"required_count"`            // Number of approvers required
	Approvers      []ApprovalRecord `json:"approvers"`                 // List of approvers
	Verified       bool             `json:"verified"`                  // Whether code was verified
	VerifiedAt     *time.Time       `json:"verified_at,omitempty"`     // When verification succeeded
	NotificationID string           `json:"notification_id,omitempty"` // ID for out-of-band notification
}

// ApprovalRecord records an individual approval.
type ApprovalRecord struct {
	Approver   string    `json:"approver"`
	ApprovedAt time.Time `json:"approved_at"`
	Method     string    `json:"method"` // "code", "signature", "mfa"
	Signature  string    `json:"signature,omitempty"`
}

// Duration returns the transition duration.
func (mt *ModeTransition) Duration() time.Duration {
	if mt.EndTime == nil {
		return time.Since(mt.StartTime)
	}
	return mt.EndTime.Sub(mt.StartTime)
}

// IsEscalation returns true if this is a security escalation.
func (mt *ModeTransition) IsEscalation() bool {
	return mt.ToMode.Level() > mt.FromMode.Level()
}

// IsDeescalation returns true if this is a security de-escalation.
func (mt *ModeTransition) IsDeescalation() bool {
	return mt.ToMode.Level() < mt.FromMode.Level()
}

// CommitmentChain maintains a chain of commitments for audit.
type CommitmentChain struct {
	Commitments []Commitment `json:"commitments"`
	GenesisHash string       `json:"genesis_hash"`
}

// Verify verifies the entire chain integrity.
func (cc *CommitmentChain) Verify(key []byte) error {
	if len(cc.Commitments) == 0 {
		return nil
	}

	// Verify genesis
	if cc.Commitments[0].PreviousHash != cc.GenesisHash {
		return fmt.Errorf("%w: genesis hash mismatch", ErrChainBroken)
	}

	// Verify chain links and signatures
	for i, c := range cc.Commitments {
		// Verify signature
		if !c.Verify(key) {
			return fmt.Errorf("%w: invalid signature at index %d", ErrInvalidCommitment, i)
		}

		// Verify chain link
		if i > 0 {
			expected := cc.Commitments[i-1].StateHash
			if c.PreviousHash != expected {
				return fmt.Errorf("%w: link broken at index %d", ErrChainBroken, i)
			}
		}
	}

	return nil
}

// LatestHash returns the hash of the latest commitment.
func (cc *CommitmentChain) LatestHash() string {
	if len(cc.Commitments) == 0 {
		return cc.GenesisHash
	}
	return cc.Commitments[len(cc.Commitments)-1].StateHash
}

// StateManager manages cryptographic state commitments.
type StateManager struct {
	mu sync.RWMutex

	// Current state
	currentState *State
	currentMode  SecurityMode

	// Commitment chain
	chain *CommitmentChain

	// Active transition
	activeTransition *ModeTransition

	// History
	transitions []ModeTransition

	// Configuration
	config *StateManagerConfig

	// HMAC key for signatures
	hmacKey []byte

	// Logger
	logger *slog.Logger

	// Callbacks
	onTransitionStart func(transition *ModeTransition)
	onTransitionEnd   func(transition *ModeTransition)
}

// StateManagerConfig configures the state manager.
type StateManagerConfig struct {
	// PersistPath is the path to persist commitments.
	PersistPath string
	// MaxTransitionHistory is the maximum transitions to keep in memory.
	MaxTransitionHistory int
	// RequireApprovalForDeescalation requires approval for security downgrades.
	RequireApprovalForDeescalation bool
	// HashAlgorithm is the hash algorithm to use.
	HashAlgorithm string
	// AutoCheckpoint creates checkpoints at regular intervals.
	AutoCheckpoint bool
	// CheckpointInterval is the interval between auto checkpoints.
	CheckpointInterval time.Duration
	// RequirePersistence requires successful persistence before completing transitions.
	RequirePersistence bool
	// PersistenceVerifyRetries is the number of retries for persistence verification.
	PersistenceVerifyRetries int
	// SyncToDisk forces fsync after writes for durability.
	SyncToDisk bool

	// Human confirmation settings
	// RequireHumanConfirmation requires a confirmation code for de-escalations.
	RequireHumanConfirmation bool
	// ConfirmationCodeLength is the length of confirmation codes.
	ConfirmationCodeLength int
	// ConfirmationTimeout is how long confirmation codes remain valid.
	ConfirmationTimeout time.Duration
	// ConfirmationMaxAttempts is the maximum failed attempts before lockout.
	ConfirmationMaxAttempts int
	// RequiredApprovers is the number of approvers required for critical downgrades.
	RequiredApprovers int
	// CriticalModeThreshold is the mode level above which multi-approval is required.
	CriticalModeThreshold int
	// OnConfirmationRequired is called when confirmation is needed (for out-of-band notification).
	OnConfirmationRequired func(transition *ModeTransition, code string)
}

// PersistedState represents the complete persisted state.
type PersistedState struct {
	State       *State           `json:"state"`
	Chain       *CommitmentChain `json:"chain"`
	Transitions []ModeTransition `json:"transitions"`
	Checksum    string           `json:"checksum"`
	Version     int              `json:"version"`
	Timestamp   time.Time        `json:"timestamp"`
}

// DefaultStateManagerConfig returns sensible defaults.
func DefaultStateManagerConfig() *StateManagerConfig {
	return &StateManagerConfig{
		PersistPath:                    "/var/lib/boundary-siem/commitments",
		MaxTransitionHistory:           1000,
		RequireApprovalForDeescalation: true,
		HashAlgorithm:                  "sha256",
		AutoCheckpoint:                 true,
		CheckpointInterval:             1 * time.Hour,
		RequirePersistence:             true,
		PersistenceVerifyRetries:       3,
		SyncToDisk:                     true,
		// Human confirmation defaults
		RequireHumanConfirmation: true,
		ConfirmationCodeLength:   8,
		ConfirmationTimeout:      5 * time.Minute,
		ConfirmationMaxAttempts:  3,
		RequiredApprovers:        1,
		CriticalModeThreshold:    2, // Lockdown and above require multi-approval
	}
}

// NewStateManager creates a new state manager.
func NewStateManager(config *StateManagerConfig, logger *slog.Logger) (*StateManager, error) {
	if config == nil {
		config = DefaultStateManagerConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Generate or load HMAC key
	hmacKey, err := loadOrGenerateKey(config.PersistPath)
	if err != nil {
		logger.Warn("using ephemeral HMAC key", "error", err)
		hmacKey = make([]byte, 32)
		rand.Read(hmacKey)
	}

	// Initialize genesis
	genesisHash := computeGenesisHash()

	sm := &StateManager{
		currentMode: ModeNormal,
		currentState: &State{
			Mode:      ModeNormal,
			Version:   1,
			Entries:   make([]StateEntry, 0),
			Timestamp: time.Now(),
			Nonce:     generateNonce(),
		},
		chain: &CommitmentChain{
			Commitments: make([]Commitment, 0),
			GenesisHash: genesisHash,
		},
		transitions: make([]ModeTransition, 0),
		config:      config,
		hmacKey:     hmacKey,
		logger:      logger,
	}

	// Try to load persisted state
	if ps, err := sm.loadPersistedState(); err != nil {
		logger.Warn("failed to load persisted state, starting fresh",
			"error", err)
	} else if ps != nil {
		// Restore state from persistence
		if ps.State != nil {
			sm.currentState = ps.State
			sm.currentMode = ps.State.Mode
		}
		if ps.Chain != nil {
			sm.chain = ps.Chain
		}
		if ps.Transitions != nil {
			sm.transitions = ps.Transitions
		}
		logger.Info("restored state from persistence",
			"mode", sm.currentMode,
			"chain_length", len(sm.chain.Commitments),
			"transitions", len(sm.transitions))
	} else {
		// No persisted state - create initial commitment
		if err := sm.createCheckpoint("initial"); err != nil {
			logger.Warn("failed to create initial checkpoint", "error", err)
		}
	}

	logger.Info("state manager initialized",
		"mode", sm.currentMode,
		"genesis_hash", sm.chain.GenesisHash[:16]+"...")

	return sm, nil
}

// loadOrGenerateKey loads or generates the HMAC key.
func loadOrGenerateKey(basePath string) ([]byte, error) {
	keyPath := filepath.Join(basePath, "hmac.key")

	// Try to load existing key
	if data, err := os.ReadFile(keyPath); err == nil && len(data) == 32 {
		return data, nil
	}

	// Generate new key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	// Try to persist
	if err := os.MkdirAll(basePath, 0700); err == nil {
		os.WriteFile(keyPath, key, 0600)
	}

	return key, nil
}

// persistState persists the current state to disk with verification.
func (sm *StateManager) persistState() error {
	if sm.config.PersistPath == "" {
		return nil // Persistence disabled
	}

	// Create persisted state structure
	ps := &PersistedState{
		State:       sm.currentState,
		Chain:       sm.chain,
		Transitions: sm.transitions,
		Version:     1,
		Timestamp:   time.Now(),
	}

	// Compute checksum before marshaling
	ps.Checksum = sm.computeStateChecksum(ps)

	// Marshal to JSON
	data, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(sm.config.PersistPath, 0700); err != nil {
		return fmt.Errorf("failed to create persist directory: %w", err)
	}

	statePath := filepath.Join(sm.config.PersistPath, "state.json")
	tempPath := statePath + ".tmp"
	backupPath := statePath + ".bak"

	// Write to temp file first (atomic write pattern)
	if err := sm.writeFileWithSync(tempPath, data); err != nil {
		return fmt.Errorf("failed to write temp state file: %w", err)
	}

	// Backup existing file if present
	if _, err := os.Stat(statePath); err == nil {
		if err := os.Rename(statePath, backupPath); err != nil {
			sm.logger.Warn("failed to backup state file", "error", err)
		}
	}

	// Rename temp to final (atomic on POSIX)
	if err := os.Rename(tempPath, statePath); err != nil {
		// Try to restore backup
		if _, bakErr := os.Stat(backupPath); bakErr == nil {
			os.Rename(backupPath, statePath)
		}
		return fmt.Errorf("failed to finalize state file: %w", err)
	}

	sm.logger.Debug("state persisted successfully",
		"path", statePath,
		"checksum", ps.Checksum[:16]+"...")

	return nil
}

// writeFileWithSync writes data to a file with optional fsync.
func (sm *StateManager) writeFileWithSync(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return err
	}

	if sm.config.SyncToDisk {
		if err := f.Sync(); err != nil {
			return fmt.Errorf("fsync failed: %w", err)
		}
	}

	return nil
}

// loadPersistedState loads the persisted state from disk.
func (sm *StateManager) loadPersistedState() (*PersistedState, error) {
	if sm.config.PersistPath == "" {
		return nil, nil // Persistence disabled
	}

	statePath := filepath.Join(sm.config.PersistPath, "state.json")

	data, err := os.ReadFile(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No persisted state
		}
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	var ps PersistedState
	if err := json.Unmarshal(data, &ps); err != nil {
		return nil, fmt.Errorf("%w: failed to parse state file: %v", ErrCorruptedState, err)
	}

	// Verify checksum
	savedChecksum := ps.Checksum
	ps.Checksum = "" // Clear for recalculation
	expectedChecksum := sm.computeStateChecksum(&ps)

	if savedChecksum != expectedChecksum {
		return nil, fmt.Errorf("%w: checksum mismatch (expected %s, got %s)",
			ErrCorruptedState, expectedChecksum[:16], savedChecksum[:16])
	}

	ps.Checksum = savedChecksum
	return &ps, nil
}

// computeStateChecksum computes a checksum of the persisted state.
func (sm *StateManager) computeStateChecksum(ps *PersistedState) string {
	h := sha256.New()

	// Hash state
	if ps.State != nil {
		h.Write([]byte(ps.State.Hash()))
	}

	// Hash chain
	if ps.Chain != nil {
		h.Write([]byte(ps.Chain.GenesisHash))
		for _, c := range ps.Chain.Commitments {
			h.Write([]byte(c.ID))
			h.Write([]byte(c.StateHash))
			h.Write([]byte(c.Signature))
		}
	}

	// Hash transitions count (not full content for performance)
	h.Write([]byte(fmt.Sprintf("transitions:%d", len(ps.Transitions))))

	// Hash version and timestamp
	h.Write([]byte(fmt.Sprintf("v%d", ps.Version)))
	h.Write([]byte(ps.Timestamp.Format(time.RFC3339Nano)))

	return hex.EncodeToString(h.Sum(nil))
}

// verifyPersistence verifies that the current state matches persisted state.
func (sm *StateManager) verifyPersistence() error {
	if sm.config.PersistPath == "" {
		return nil // Persistence disabled
	}

	ps, err := sm.loadPersistedState()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPersistenceFailed, err)
	}

	if ps == nil {
		return fmt.Errorf("%w: no persisted state found", ErrPersistenceFailed)
	}

	// Verify state hash matches
	if ps.State != nil {
		persistedHash := ps.State.Hash()
		currentHash := sm.currentState.Hash()
		if persistedHash != currentHash {
			return fmt.Errorf("%w: state hash mismatch (persisted: %s, current: %s)",
				ErrPersistenceFailed, persistedHash[:16], currentHash[:16])
		}
	}

	// Verify chain length
	if ps.Chain != nil && len(ps.Chain.Commitments) != len(sm.chain.Commitments) {
		return fmt.Errorf("%w: chain length mismatch (persisted: %d, current: %d)",
			ErrPersistenceFailed, len(ps.Chain.Commitments), len(sm.chain.Commitments))
	}

	return nil
}

// persistAndVerify persists state and verifies it was written correctly.
func (sm *StateManager) persistAndVerify() error {
	if !sm.config.RequirePersistence {
		return sm.persistState() // Just persist, no verification
	}

	maxRetries := sm.config.PersistenceVerifyRetries
	if maxRetries <= 0 {
		maxRetries = 1
	}

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Persist
		if err := sm.persistState(); err != nil {
			lastErr = err
			sm.logger.Warn("persistence attempt failed",
				"attempt", attempt,
				"max_retries", maxRetries,
				"error", err)
			continue
		}

		// Verify
		if err := sm.verifyPersistence(); err != nil {
			lastErr = err
			sm.logger.Warn("persistence verification failed",
				"attempt", attempt,
				"max_retries", maxRetries,
				"error", err)
			continue
		}

		sm.logger.Debug("persistence verified successfully", "attempt", attempt)
		return nil
	}

	return fmt.Errorf("%w after %d attempts: %v", ErrPersistenceFailed, maxRetries, lastErr)
}

// computeGenesisHash computes the genesis hash.
func computeGenesisHash() string {
	h := sha256.New()
	h.Write([]byte("boundary-siem-genesis-v1"))
	h.Write([]byte(time.Now().Format("2006-01-02")))
	return hex.EncodeToString(h.Sum(nil))
}

// generateNonce generates a random nonce.
func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// generateID generates a unique ID.
func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), hex.EncodeToString(b))
}

// SetState sets a state entry.
func (sm *StateManager) SetState(key, value string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Update or add entry
	found := false
	for i, e := range sm.currentState.Entries {
		if e.Key == key {
			sm.currentState.Entries[i].Value = value
			sm.currentState.Entries[i].Timestamp = time.Now()
			found = true
			break
		}
	}

	if !found {
		sm.currentState.Entries = append(sm.currentState.Entries, StateEntry{
			Key:       key,
			Value:     value,
			Timestamp: time.Now(),
		})
	}

	sm.currentState.Version++
	sm.currentState.Timestamp = time.Now()
	sm.currentState.Nonce = generateNonce()
}

// GetState gets a state entry.
func (sm *StateManager) GetState(key string) (string, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	for _, e := range sm.currentState.Entries {
		if e.Key == key {
			return e.Value, true
		}
	}
	return "", false
}

// GetCurrentMode returns the current security mode.
func (sm *StateManager) GetCurrentMode() SecurityMode {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.currentMode
}

// BeginTransition begins a mode transition.
// For de-escalations when RequireHumanConfirmation is enabled, the transition
// will be set to "awaiting_confirmation" status and a confirmation code will
// be generated. Call GetPendingConfirmationCode() to retrieve the code.
func (sm *StateManager) BeginTransition(ctx context.Context, toMode SecurityMode, reason, initiator string) (*ModeTransition, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.activeTransition != nil {
		return nil, ErrTransitionInProgress
	}

	// Create pre-commitment
	preCommitment := sm.createCommitment("pre")

	transition := &ModeTransition{
		ID:            generateID(),
		FromMode:      sm.currentMode,
		ToMode:        toMode,
		PreCommitment: preCommitment,
		StartTime:     time.Now(),
		Status:        "pending",
		Reason:        reason,
		Initiator:     initiator,
	}

	sm.activeTransition = transition

	// Check if this transition requires human confirmation
	if sm.requiresHumanConfirmation(transition) {
		// Generate confirmation code
		code := sm.generateConfirmationCode()
		codeHash := sm.hashConfirmationCode(code)
		now := time.Now()

		transition.Confirmation = &TransitionConfirmation{
			Code:          code, // Temporarily store for GetPendingConfirmationCode
			CodeHash:      codeHash,
			ExpiresAt:     now.Add(sm.config.ConfirmationTimeout),
			CreatedAt:     now,
			Attempts:      0,
			MaxAttempts:   sm.config.ConfirmationMaxAttempts,
			RequiredCount: sm.getRequiredApprovers(transition),
			Approvers:     make([]ApprovalRecord, 0),
			Verified:      false,
		}
		transition.Status = "awaiting_confirmation"

		sm.logger.Info("mode de-escalation requires confirmation",
			"transition_id", transition.ID,
			"from_mode", transition.FromMode,
			"to_mode", transition.ToMode,
			"required_approvers", transition.Confirmation.RequiredCount,
			"expires_at", transition.Confirmation.ExpiresAt)

		// Notify callback
		if sm.config.OnConfirmationRequired != nil {
			go sm.config.OnConfirmationRequired(transition, code)
		}
	}

	sm.logger.Info("mode transition started",
		"transition_id", transition.ID,
		"from_mode", transition.FromMode,
		"to_mode", transition.ToMode,
		"reason", reason,
		"requires_confirmation", transition.Status == "awaiting_confirmation")

	if sm.onTransitionStart != nil {
		go sm.onTransitionStart(transition)
	}

	return transition, nil
}

// GetPendingConfirmationCode retrieves the confirmation code for a pending transition.
// This should only be called immediately after BeginTransition for de-escalations.
// The code is cleared after this call for security.
func (sm *StateManager) GetPendingConfirmationCode(transitionID string) (string, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.activeTransition == nil || sm.activeTransition.ID != transitionID {
		return "", ErrNoActiveTransition
	}

	if sm.activeTransition.Confirmation == nil {
		return "", nil // No confirmation required
	}

	code := sm.activeTransition.Confirmation.Code
	// Clear the plaintext code after retrieval
	sm.activeTransition.Confirmation.Code = ""

	return code, nil
}

// createCommitment creates a new commitment.
func (sm *StateManager) createCommitment(commitType string) *Commitment {
	c := &Commitment{
		ID:             generateID(),
		StateHash:      sm.currentState.Hash(),
		PreviousHash:   sm.chain.LatestHash(),
		Mode:           sm.currentMode,
		Version:        sm.currentState.Version,
		Timestamp:      time.Now(),
		CommitmentType: commitType,
	}

	if sm.activeTransition != nil {
		c.TransitionID = sm.activeTransition.ID
	}

	// Compute Merkle root of state entries
	c.MerkleRoot = sm.computeMerkleRoot()

	// Sign the commitment
	c.Sign(sm.hmacKey)

	return c
}

// computeMerkleRoot computes a Merkle root of state entries.
func (sm *StateManager) computeMerkleRoot() string {
	if len(sm.currentState.Entries) == 0 {
		return ""
	}

	// Hash each entry
	hashes := make([][]byte, len(sm.currentState.Entries))
	for i, e := range sm.currentState.Entries {
		h := sha256.Sum256([]byte(e.Key + ":" + e.Value))
		hashes[i] = h[:]
	}

	// Build Merkle tree
	for len(hashes) > 1 {
		var newLevel [][]byte
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				combined := append(hashes[i], hashes[i+1]...)
				h := sha256.Sum256(combined)
				newLevel = append(newLevel, h[:])
			} else {
				newLevel = append(newLevel, hashes[i])
			}
		}
		hashes = newLevel
	}

	return hex.EncodeToString(hashes[0])
}

// ApproveTransition approves a pending transition (required for de-escalations).
func (sm *StateManager) ApproveTransition(ctx context.Context, transitionID, approver string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.activeTransition == nil || sm.activeTransition.ID != transitionID {
		return ErrNoActiveTransition
	}

	sm.activeTransition.Approved = true
	sm.activeTransition.ApprovedBy = approver

	sm.logger.Info("transition approved",
		"transition_id", transitionID,
		"approver", approver)

	return nil
}

// CommitTransition commits the mode transition.
func (sm *StateManager) CommitTransition(ctx context.Context) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.activeTransition == nil {
		return ErrNoActiveTransition
	}

	transition := sm.activeTransition

	// Check human confirmation for de-escalations
	if sm.config.RequireHumanConfirmation && transition.IsDeescalation() {
		if transition.Confirmation == nil {
			return ErrConfirmationRequired
		}
		if !transition.Confirmation.Verified {
			// Check if expired
			if time.Now().After(transition.Confirmation.ExpiresAt) {
				return ErrConfirmationExpired
			}
			// Check if too many attempts
			if transition.Confirmation.Attempts >= transition.Confirmation.MaxAttempts {
				return ErrTooManyAttempts
			}
			// Check if we have enough approvers
			if len(transition.Confirmation.Approvers) < transition.Confirmation.RequiredCount {
				return ErrInsufficientApprovers
			}
			return ErrConfirmationRequired
		}
	}

	// Legacy approval check (for backwards compatibility)
	if sm.config.RequireApprovalForDeescalation && transition.IsDeescalation() {
		if !transition.Approved {
			return fmt.Errorf("de-escalation requires approval")
		}
	}

	// Verify pre-commitment state hasn't changed unexpectedly
	currentHash := sm.currentState.Hash()
	if currentHash != transition.PreCommitment.StateHash {
		// State changed during transition - this may be expected
		sm.logger.Warn("state modified during transition",
			"pre_hash", transition.PreCommitment.StateHash[:16],
			"current_hash", currentHash[:16])
	}

	// Save previous state in case we need to rollback due to persistence failure
	previousMode := sm.currentMode
	previousStateMode := sm.currentState.Mode
	previousVersion := sm.currentState.Version
	previousTimestamp := sm.currentState.Timestamp
	previousNonce := sm.currentState.Nonce
	previousChainLen := len(sm.chain.Commitments)

	// Apply mode change
	sm.currentMode = transition.ToMode
	sm.currentState.Mode = transition.ToMode
	sm.currentState.Version++
	sm.currentState.Timestamp = time.Now()
	sm.currentState.Nonce = generateNonce()

	// Create post-commitment
	postCommitment := sm.createCommitment("post")
	transition.PostCommitment = postCommitment

	// Add to chain
	sm.chain.Commitments = append(sm.chain.Commitments, *transition.PreCommitment)
	sm.chain.Commitments = append(sm.chain.Commitments, *postCommitment)

	// Complete transition
	now := time.Now()
	transition.EndTime = &now
	transition.Status = "completed"

	// Record in history
	sm.transitions = append(sm.transitions, *transition)
	if len(sm.transitions) > sm.config.MaxTransitionHistory {
		sm.transitions = sm.transitions[1:]
	}

	// CRITICAL: Persist and verify state before finalizing
	// If persistence fails, we must rollback the in-memory changes
	if sm.config.RequirePersistence && sm.config.PersistPath != "" {
		if err := sm.persistAndVerify(); err != nil {
			// Rollback in-memory state
			sm.logger.Error("persistence failed, rolling back transition",
				"transition_id", transition.ID,
				"error", err)

			// Restore previous state
			sm.currentMode = previousMode
			sm.currentState.Mode = previousStateMode
			sm.currentState.Version = previousVersion
			sm.currentState.Timestamp = previousTimestamp
			sm.currentState.Nonce = previousNonce

			// Remove added commitments
			if len(sm.chain.Commitments) > previousChainLen {
				sm.chain.Commitments = sm.chain.Commitments[:previousChainLen]
			}

			// Remove from history
			if len(sm.transitions) > 0 {
				sm.transitions = sm.transitions[:len(sm.transitions)-1]
			}

			// Mark transition as failed
			transition.Status = "failed"
			transition.Reason = fmt.Sprintf("persistence failed: %v", err)

			return fmt.Errorf("transition failed: %w", err)
		}

		sm.logger.Info("transition state persisted and verified",
			"transition_id", transition.ID)
	}

	sm.activeTransition = nil

	sm.logger.Info("mode transition committed",
		"transition_id", transition.ID,
		"from_mode", transition.FromMode,
		"to_mode", transition.ToMode,
		"duration", transition.Duration(),
		"persisted", sm.config.RequirePersistence)

	if sm.onTransitionEnd != nil {
		go sm.onTransitionEnd(transition)
	}

	return nil
}

// RollbackTransition rolls back an active transition.
func (sm *StateManager) RollbackTransition(ctx context.Context, reason string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.activeTransition == nil {
		return ErrNoActiveTransition
	}

	transition := sm.activeTransition
	now := time.Now()
	transition.EndTime = &now
	transition.Status = "rolled_back"
	transition.Reason = reason

	// Record in history
	sm.transitions = append(sm.transitions, *transition)

	sm.activeTransition = nil

	sm.logger.Info("mode transition rolled back",
		"transition_id", transition.ID,
		"reason", reason)

	if sm.onTransitionEnd != nil {
		go sm.onTransitionEnd(transition)
	}

	return nil
}

// createCheckpoint creates a checkpoint commitment.
func (sm *StateManager) createCheckpoint(reason string) error {
	c := sm.createCommitment("checkpoint")

	// Add to chain
	sm.chain.Commitments = append(sm.chain.Commitments, *c)

	sm.logger.Debug("checkpoint created",
		"commitment_id", c.ID,
		"state_hash", c.StateHash[:16]+"...",
		"reason", reason)

	return nil
}

// CreateCheckpoint creates a manual checkpoint with optional persistence.
func (sm *StateManager) CreateCheckpoint(ctx context.Context, reason string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if err := sm.createCheckpoint(reason); err != nil {
		return err
	}

	// Persist checkpoint if required
	if sm.config.RequirePersistence && sm.config.PersistPath != "" {
		if err := sm.persistAndVerify(); err != nil {
			sm.logger.Warn("failed to persist checkpoint",
				"reason", reason,
				"error", err)
			// For checkpoints, we don't fail - just warn
		}
	}

	return nil
}

// ForcePersist forces a state persistence and verification.
// Use this to ensure critical state changes are durably stored.
func (sm *StateManager) ForcePersist(ctx context.Context) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.persistAndVerify()
}

// IsPersisted checks if the current state is persisted and verified.
func (sm *StateManager) IsPersisted() (bool, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.config.PersistPath == "" {
		return false, nil // Persistence disabled
	}

	ps, err := sm.loadPersistedState()
	if err != nil {
		return false, err
	}

	if ps == nil {
		return false, nil
	}

	// Check if persisted state matches current state
	if ps.State != nil {
		persistedHash := ps.State.Hash()
		currentHash := sm.currentState.Hash()
		return persistedHash == currentHash, nil
	}

	return false, nil
}

// generateConfirmationCode generates a cryptographically secure confirmation code.
func (sm *StateManager) generateConfirmationCode() string {
	length := sm.config.ConfirmationCodeLength
	if length <= 0 {
		length = 8
	}

	// Use uppercase letters and digits for readability (avoid confusing chars like 0/O, 1/I)
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	code := make([]byte, length)

	// Read random bytes
	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to less secure but functional approach
		for i := range code {
			code[i] = charset[time.Now().UnixNano()%int64(len(charset))]
		}
		return string(code)
	}

	for i := range code {
		code[i] = charset[int(randomBytes[i])%len(charset)]
	}

	return string(code)
}

// hashConfirmationCode creates a secure hash of the confirmation code.
func (sm *StateManager) hashConfirmationCode(code string) string {
	h := sha256.New()
	h.Write(sm.hmacKey)
	h.Write([]byte(code))
	return hex.EncodeToString(h.Sum(nil))
}

// requiresHumanConfirmation checks if a transition requires human confirmation.
func (sm *StateManager) requiresHumanConfirmation(transition *ModeTransition) bool {
	if !sm.config.RequireHumanConfirmation {
		return false
	}

	// De-escalations always require confirmation
	if transition.IsDeescalation() {
		return true
	}

	return false
}

// getRequiredApprovers returns the number of approvers needed for a transition.
func (sm *StateManager) getRequiredApprovers(transition *ModeTransition) int {
	if !sm.config.RequireHumanConfirmation {
		return 0
	}

	// For critical mode transitions (from high security modes), require more approvers
	if transition.FromMode.Level() >= sm.config.CriticalModeThreshold {
		return max(sm.config.RequiredApprovers, 2) // At least 2 for critical
	}

	return sm.config.RequiredApprovers
}

// max returns the larger of two ints.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// InitiateConfirmation creates a confirmation request for a transition.
// Returns the confirmation code that must be provided to complete the transition.
// The code should be communicated out-of-band to the approver(s).
func (sm *StateManager) InitiateConfirmation(ctx context.Context, transitionID string) (string, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.activeTransition == nil || sm.activeTransition.ID != transitionID {
		return "", ErrNoActiveTransition
	}

	transition := sm.activeTransition

	// Generate confirmation code
	code := sm.generateConfirmationCode()
	codeHash := sm.hashConfirmationCode(code)
	now := time.Now()

	// Create confirmation record
	transition.Confirmation = &TransitionConfirmation{
		Code:          "", // Don't store plaintext code in state
		CodeHash:      codeHash,
		ExpiresAt:     now.Add(sm.config.ConfirmationTimeout),
		CreatedAt:     now,
		Attempts:      0,
		MaxAttempts:   sm.config.ConfirmationMaxAttempts,
		RequiredCount: sm.getRequiredApprovers(transition),
		Approvers:     make([]ApprovalRecord, 0),
		Verified:      false,
	}

	transition.Status = "awaiting_confirmation"

	sm.logger.Info("confirmation initiated for transition",
		"transition_id", transitionID,
		"from_mode", transition.FromMode,
		"to_mode", transition.ToMode,
		"expires_at", transition.Confirmation.ExpiresAt,
		"required_approvers", transition.Confirmation.RequiredCount)

	// Call notification callback if configured
	if sm.config.OnConfirmationRequired != nil {
		go sm.config.OnConfirmationRequired(transition, code)
	}

	// Return the code for out-of-band delivery
	return code, nil
}

// ConfirmTransition validates a confirmation code and records an approval.
// Returns nil when sufficient approvals have been collected.
func (sm *StateManager) ConfirmTransition(ctx context.Context, transitionID, code, approver, method string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.activeTransition == nil || sm.activeTransition.ID != transitionID {
		return ErrNoActiveTransition
	}

	transition := sm.activeTransition
	confirmation := transition.Confirmation

	if confirmation == nil {
		return ErrConfirmationRequired
	}

	// Check if already verified
	if confirmation.Verified {
		return nil // Already confirmed
	}

	// Check expiration
	if time.Now().After(confirmation.ExpiresAt) {
		return ErrConfirmationExpired
	}

	// Check attempts
	if confirmation.Attempts >= confirmation.MaxAttempts {
		return ErrTooManyAttempts
	}

	confirmation.Attempts++

	// Verify code
	providedHash := sm.hashConfirmationCode(code)
	if providedHash != confirmation.CodeHash {
		sm.logger.Warn("invalid confirmation code attempt",
			"transition_id", transitionID,
			"approver", approver,
			"attempt", confirmation.Attempts,
			"max_attempts", confirmation.MaxAttempts)
		return ErrInvalidConfirmation
	}

	// Check for duplicate approver
	for _, a := range confirmation.Approvers {
		if a.Approver == approver {
			return ErrDuplicateApprover
		}
	}

	// Record approval
	approval := ApprovalRecord{
		Approver:   approver,
		ApprovedAt: time.Now(),
		Method:     method,
	}
	confirmation.Approvers = append(confirmation.Approvers, approval)

	sm.logger.Info("approval recorded for transition",
		"transition_id", transitionID,
		"approver", approver,
		"method", method,
		"approvals", len(confirmation.Approvers),
		"required", confirmation.RequiredCount)

	// Check if we have enough approvals
	if len(confirmation.Approvers) >= confirmation.RequiredCount {
		now := time.Now()
		confirmation.Verified = true
		confirmation.VerifiedAt = &now
		transition.Approved = true
		transition.ApprovedBy = approver // Last approver

		sm.logger.Info("transition confirmation complete",
			"transition_id", transitionID,
			"total_approvers", len(confirmation.Approvers))
	}

	return nil
}

// GetConfirmationStatus returns the confirmation status for an active transition.
func (sm *StateManager) GetConfirmationStatus(transitionID string) (*TransitionConfirmation, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.activeTransition == nil || sm.activeTransition.ID != transitionID {
		return nil, ErrNoActiveTransition
	}

	if sm.activeTransition.Confirmation == nil {
		return nil, ErrConfirmationRequired
	}

	// Return a copy to prevent external modification
	conf := *sm.activeTransition.Confirmation
	return &conf, nil
}

// CancelConfirmation cancels a pending confirmation request.
func (sm *StateManager) CancelConfirmation(ctx context.Context, transitionID, reason string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.activeTransition == nil || sm.activeTransition.ID != transitionID {
		return ErrNoActiveTransition
	}

	transition := sm.activeTransition

	if transition.Confirmation == nil {
		return nil // Nothing to cancel
	}

	sm.logger.Info("confirmation cancelled",
		"transition_id", transitionID,
		"reason", reason)

	// Clear confirmation
	transition.Confirmation = nil
	transition.Status = "pending"

	return nil
}

// VerifyChain verifies the commitment chain integrity.
func (sm *StateManager) VerifyChain() error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.chain.Verify(sm.hmacKey)
}

// VerifyCurrentState verifies the current state against the latest commitment.
func (sm *StateManager) VerifyCurrentState() error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if len(sm.chain.Commitments) == 0 {
		return nil
	}

	latest := sm.chain.Commitments[len(sm.chain.Commitments)-1]
	currentHash := sm.currentState.Hash()

	// For checkpoints and post-commitments, verify hash matches
	if latest.CommitmentType == "checkpoint" || latest.CommitmentType == "post" {
		if latest.StateHash != currentHash {
			return fmt.Errorf("%w: expected %s, got %s",
				ErrCommitmentMismatch, latest.StateHash[:16], currentHash[:16])
		}
	}

	return nil
}

// GetTransitionHistory returns the transition history.
func (sm *StateManager) GetTransitionHistory(count int) []ModeTransition {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if count > len(sm.transitions) {
		count = len(sm.transitions)
	}

	result := make([]ModeTransition, count)
	copy(result, sm.transitions[len(sm.transitions)-count:])
	return result
}

// GetCommitmentChain returns a copy of the commitment chain.
func (sm *StateManager) GetCommitmentChain() *CommitmentChain {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	chain := &CommitmentChain{
		GenesisHash: sm.chain.GenesisHash,
		Commitments: make([]Commitment, len(sm.chain.Commitments)),
	}
	copy(chain.Commitments, sm.chain.Commitments)
	return chain
}

// ExportChain exports the chain to JSON.
func (sm *StateManager) ExportChain() ([]byte, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return json.MarshalIndent(sm.chain, "", "  ")
}

// OnTransitionStart sets a callback for transition start.
func (sm *StateManager) OnTransitionStart(fn func(transition *ModeTransition)) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.onTransitionStart = fn
}

// OnTransitionEnd sets a callback for transition end.
func (sm *StateManager) OnTransitionEnd(fn func(transition *ModeTransition)) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.onTransitionEnd = fn
}

// GetActiveTransition returns the active transition if any.
func (sm *StateManager) GetActiveTransition() *ModeTransition {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.activeTransition
}

// Hasher provides different hash algorithms.
type Hasher struct {
	algorithm string
}

// NewHasher creates a new hasher.
func NewHasher(algorithm string) *Hasher {
	return &Hasher{algorithm: strings.ToLower(algorithm)}
}

// Hash returns the hash function.
func (h *Hasher) Hash() hash.Hash {
	switch h.algorithm {
	case "sha512":
		return sha512.New()
	case "sha384":
		return sha512.New384()
	default:
		return sha256.New()
	}
}

// HashBytes hashes bytes.
func (h *Hasher) HashBytes(data []byte) string {
	hash := h.Hash()
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

// HashString hashes a string.
func (h *Hasher) HashString(s string) string {
	return h.HashBytes([]byte(s))
}

// StateProof provides proof of state at a point in time.
type StateProof struct {
	StateHash  string            `json:"state_hash"`
	MerkleRoot string            `json:"merkle_root"`
	MerklePath []string          `json:"merkle_path,omitempty"`
	Timestamp  time.Time         `json:"timestamp"`
	Mode       SecurityMode      `json:"mode"`
	Version    int               `json:"version"`
	Signature  string            `json:"signature"`
	Entries    map[string]string `json:"entries,omitempty"`
}

// GenerateStateProof generates a proof of the current state.
func (sm *StateManager) GenerateStateProof(ctx context.Context, includeEntries bool) (*StateProof, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	proof := &StateProof{
		StateHash:  sm.currentState.Hash(),
		MerkleRoot: sm.computeMerkleRoot(),
		Timestamp:  time.Now(),
		Mode:       sm.currentMode,
		Version:    sm.currentState.Version,
	}

	if includeEntries {
		proof.Entries = make(map[string]string)
		for _, e := range sm.currentState.Entries {
			proof.Entries[e.Key] = e.Value
		}
	}

	// Sign the proof
	h := hmac.New(sha256.New, sm.hmacKey)
	h.Write([]byte(proof.StateHash))
	h.Write([]byte(proof.MerkleRoot))
	h.Write([]byte(proof.Timestamp.Format(time.RFC3339Nano)))
	proof.Signature = hex.EncodeToString(h.Sum(nil))

	return proof, nil
}

// VerifyStateProof verifies a state proof.
func (sm *StateManager) VerifyStateProof(proof *StateProof) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	h := hmac.New(sha256.New, sm.hmacKey)
	h.Write([]byte(proof.StateHash))
	h.Write([]byte(proof.MerkleRoot))
	h.Write([]byte(proof.Timestamp.Format(time.RFC3339Nano)))
	expected := hex.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(proof.Signature), []byte(expected))
}
