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
	ErrInvalidCommitment   = errors.New("invalid commitment")
	ErrCommitmentMismatch  = errors.New("commitment verification failed")
	ErrChainBroken         = errors.New("commitment chain broken")
	ErrNoActiveTransition  = errors.New("no active mode transition")
	ErrTransitionInProgress = errors.New("mode transition already in progress")
	ErrStateModified       = errors.New("state was modified during transition")
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
	Mode       SecurityMode `json:"mode"`
	Version    int          `json:"version"`
	Entries    []StateEntry `json:"entries"`
	Timestamp  time.Time    `json:"timestamp"`
	Nonce      string       `json:"nonce"`
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
	ID              string       `json:"id"`
	StateHash       string       `json:"state_hash"`
	PreviousHash    string       `json:"previous_hash,omitempty"`
	Mode            SecurityMode `json:"mode"`
	Version         int          `json:"version"`
	Timestamp       time.Time    `json:"timestamp"`
	Signature       string       `json:"signature"` // HMAC signature
	MerkleRoot      string       `json:"merkle_root,omitempty"`
	TransitionID    string       `json:"transition_id,omitempty"`
	CommitmentType  string       `json:"commitment_type"` // "pre", "post", "checkpoint"
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
	ID            string       `json:"id"`
	FromMode      SecurityMode `json:"from_mode"`
	ToMode        SecurityMode `json:"to_mode"`
	PreCommitment *Commitment  `json:"pre_commitment"`
	PostCommitment *Commitment `json:"post_commitment,omitempty"`
	StartTime     time.Time    `json:"start_time"`
	EndTime       *time.Time   `json:"end_time,omitempty"`
	Status        string       `json:"status"` // "pending", "completed", "failed", "rolled_back"
	Reason        string       `json:"reason,omitempty"`
	Initiator     string       `json:"initiator,omitempty"`
	Approved      bool         `json:"approved"`
	ApprovedBy    string       `json:"approved_by,omitempty"`
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

	// Create initial commitment
	if err := sm.createCheckpoint("initial"); err != nil {
		logger.Warn("failed to create initial checkpoint", "error", err)
	}

	logger.Info("state manager initialized",
		"mode", sm.currentMode,
		"genesis_hash", genesisHash[:16]+"...")

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

	sm.logger.Info("mode transition started",
		"transition_id", transition.ID,
		"from_mode", transition.FromMode,
		"to_mode", transition.ToMode,
		"reason", reason)

	if sm.onTransitionStart != nil {
		go sm.onTransitionStart(transition)
	}

	return transition, nil
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

	// Check approval for de-escalation
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

	sm.activeTransition = nil

	sm.logger.Info("mode transition committed",
		"transition_id", transition.ID,
		"from_mode", transition.FromMode,
		"to_mode", transition.ToMode,
		"duration", transition.Duration())

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

// CreateCheckpoint creates a manual checkpoint.
func (sm *StateManager) CreateCheckpoint(ctx context.Context, reason string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.createCheckpoint(reason)
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
	StateHash   string            `json:"state_hash"`
	MerkleRoot  string            `json:"merkle_root"`
	MerklePath  []string          `json:"merkle_path,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
	Mode        SecurityMode      `json:"mode"`
	Version     int               `json:"version"`
	Signature   string            `json:"signature"`
	Entries     map[string]string `json:"entries,omitempty"`
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
