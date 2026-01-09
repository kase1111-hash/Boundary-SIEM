// Package trust provides hardware trust gating for policy decisions.
// It interfaces with TPM, secure boot, and platform integrity to gate
// security-critical operations based on hardware trust levels.
package trust

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Common errors.
var (
	ErrTPMNotAvailable    = errors.New("TPM not available")
	ErrSecureBootDisabled = errors.New("secure boot not enabled")
	ErrTrustLevelTooLow   = errors.New("trust level insufficient for operation")
	ErrPCRMismatch        = errors.New("PCR measurement mismatch")
	ErrPlatformTampered   = errors.New("platform integrity compromised")
	ErrAttestationFailed  = errors.New("hardware attestation failed")
)

// TrustLevel represents the hardware trust level of the platform.
type TrustLevel int

const (
	// TrustLevelUnknown indicates trust level could not be determined.
	TrustLevelUnknown TrustLevel = iota
	// TrustLevelNone indicates no hardware trust (virtual/emulated).
	TrustLevelNone
	// TrustLevelBasic indicates basic UEFI but no TPM.
	TrustLevelBasic
	// TrustLevelTPM indicates TPM present but secure boot disabled.
	TrustLevelTPM
	// TrustLevelSecure indicates TPM + secure boot enabled.
	TrustLevelSecure
	// TrustLevelFull indicates TPM + secure boot + verified measurements.
	TrustLevelFull
)

// String returns the trust level name.
func (t TrustLevel) String() string {
	names := []string{"unknown", "none", "basic", "tpm", "secure", "full"}
	if int(t) < len(names) {
		return names[t]
	}
	return "invalid"
}

// TPMVersion represents the TPM version.
type TPMVersion int

const (
	TPMVersionUnknown TPMVersion = iota
	TPMVersion12
	TPMVersion20
)

// String returns the TPM version string.
func (v TPMVersion) String() string {
	switch v {
	case TPMVersion12:
		return "1.2"
	case TPMVersion20:
		return "2.0"
	default:
		return "unknown"
	}
}

// PCRBank represents a PCR hash algorithm bank.
type PCRBank string

const (
	PCRBankSHA1   PCRBank = "sha1"
	PCRBankSHA256 PCRBank = "sha256"
	PCRBankSHA384 PCRBank = "sha384"
)

// PCRValue represents a PCR measurement.
type PCRValue struct {
	Index   int     `json:"index"`
	Bank    PCRBank `json:"bank"`
	Value   string  `json:"value"` // Hex-encoded
	Purpose string  `json:"purpose,omitempty"`
}

// PlatformState represents the current platform trust state.
type PlatformState struct {
	TrustLevel     TrustLevel `json:"trust_level"`
	TPMAvailable   bool       `json:"tpm_available"`
	TPMVersion     TPMVersion `json:"tpm_version,omitempty"`
	SecureBootOn   bool       `json:"secure_boot_on"`
	MeasuredBoot   bool       `json:"measured_boot"`
	PCRValues      []PCRValue `json:"pcr_values,omitempty"`
	BootHash       string     `json:"boot_hash,omitempty"`
	KernelLockdown string     `json:"kernel_lockdown,omitempty"`
	IMAEnabled     bool       `json:"ima_enabled"`
	CapturedAt     time.Time  `json:"captured_at"`
}

// TrustRequirement defines trust requirements for an operation.
type TrustRequirement struct {
	Name                string         `json:"name"`
	MinTrustLevel       TrustLevel     `json:"min_trust_level"`
	RequireTPM          bool           `json:"require_tpm"`
	RequireSecureBoot   bool           `json:"require_secure_boot"`
	RequireMeasuredBoot bool           `json:"require_measured_boot"`
	RequiredPCRs        []int          `json:"required_pcrs,omitempty"`
	ExpectedPCRs        map[int]string `json:"expected_pcrs,omitempty"` // PCR index -> expected value
	AllowDegraded       bool           `json:"allow_degraded"`          // Allow operation with warning if requirement not met
}

// GateResult represents the result of a trust gate check.
type GateResult struct {
	Allowed       bool              `json:"allowed"`
	TrustLevel    TrustLevel        `json:"trust_level"`
	Requirement   *TrustRequirement `json:"requirement,omitempty"`
	PlatformState *PlatformState    `json:"platform_state,omitempty"`
	Degraded      bool              `json:"degraded"` // Operation allowed but in degraded mode
	Reason        string            `json:"reason,omitempty"`
	Timestamp     time.Time         `json:"timestamp"`
}

// TrustGate manages hardware trust verification for policy decisions.
type TrustGate struct {
	mu sync.RWMutex

	// Current platform state
	platformState *PlatformState

	// Registered requirements
	requirements map[string]*TrustRequirement

	// Gate history for audit
	history []GateResult

	// Configuration
	config *TrustGateConfig

	// Logger
	logger *slog.Logger

	// Callbacks
	onDegraded func(op string, result *GateResult)
	onDenied   func(op string, result *GateResult)
}

// TrustGateConfig configures the trust gate.
type TrustGateConfig struct {
	// RefreshInterval is how often to refresh platform state.
	RefreshInterval time.Duration
	// MaxHistorySize is the maximum number of gate results to keep.
	MaxHistorySize int
	// EnforceMode enables enforcement (deny if requirements not met).
	EnforceMode bool
	// AllowEmulation allows running without real hardware trust.
	AllowEmulation bool
	// TPMDevicePath is the path to the TPM device.
	TPMDevicePath string
	// PCRsToVerify is the list of PCR indices to read and verify.
	PCRsToVerify []int
}

// DefaultTrustGateConfig returns sensible defaults.
func DefaultTrustGateConfig() *TrustGateConfig {
	return &TrustGateConfig{
		RefreshInterval: 5 * time.Minute,
		MaxHistorySize:  1000,
		EnforceMode:     true,
		AllowEmulation:  false,
		TPMDevicePath:   "/dev/tpm0",
		PCRsToVerify:    []int{0, 1, 2, 3, 4, 5, 6, 7}, // Standard PCRs
	}
}

// NewTrustGate creates a new trust gate.
func NewTrustGate(config *TrustGateConfig, logger *slog.Logger) (*TrustGate, error) {
	if config == nil {
		config = DefaultTrustGateConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	tg := &TrustGate{
		requirements: make(map[string]*TrustRequirement),
		history:      make([]GateResult, 0, config.MaxHistorySize),
		config:       config,
		logger:       logger,
	}

	// Capture initial platform state
	state, err := tg.capturePlatformState()
	if err != nil {
		logger.Warn("failed to capture initial platform state", "error", err)
		// Continue with unknown state if emulation allowed
		if !config.AllowEmulation {
			return nil, fmt.Errorf("failed to capture platform state: %w", err)
		}
		state = &PlatformState{
			TrustLevel: TrustLevelUnknown,
			CapturedAt: time.Now(),
		}
	}
	tg.platformState = state

	logger.Info("trust gate initialized",
		"trust_level", state.TrustLevel.String(),
		"tpm_available", state.TPMAvailable,
		"secure_boot", state.SecureBootOn,
		"enforce_mode", config.EnforceMode)

	return tg, nil
}

// capturePlatformState reads the current platform trust state.
func (tg *TrustGate) capturePlatformState() (*PlatformState, error) {
	state := &PlatformState{
		TrustLevel: TrustLevelNone,
		CapturedAt: time.Now(),
	}

	// Check TPM availability
	if tg.checkTPMAvailable() {
		state.TPMAvailable = true
		state.TPMVersion = tg.detectTPMVersion()
		state.TrustLevel = TrustLevelTPM

		// Read PCR values
		pcrs, err := tg.readPCRValues()
		if err == nil {
			state.PCRValues = pcrs
			state.MeasuredBoot = len(pcrs) > 0
		}
	}

	// Check secure boot status
	secureBoot, err := tg.checkSecureBoot()
	if err == nil && secureBoot {
		state.SecureBootOn = true
		if state.TPMAvailable {
			state.TrustLevel = TrustLevelSecure
		}
	}

	// Check kernel lockdown mode
	state.KernelLockdown = tg.getKernelLockdown()

	// Check IMA (Integrity Measurement Architecture)
	state.IMAEnabled = tg.checkIMA()

	// Compute boot hash from key PCRs
	if len(state.PCRValues) > 0 {
		state.BootHash = tg.computeBootHash(state.PCRValues)
	}

	// Determine final trust level
	if state.TPMAvailable && state.SecureBootOn && state.MeasuredBoot {
		state.TrustLevel = TrustLevelFull
	}

	return state, nil
}

// checkTPMAvailable checks if TPM is available.
func (tg *TrustGate) checkTPMAvailable() bool {
	// Check for TPM device
	if _, err := os.Stat(tg.config.TPMDevicePath); err == nil {
		return true
	}

	// Check for TPM resource manager
	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		return true
	}

	// Check sysfs
	if _, err := os.Stat("/sys/class/tpm/tpm0"); err == nil {
		return true
	}

	return false
}

// detectTPMVersion detects the TPM version.
func (tg *TrustGate) detectTPMVersion() TPMVersion {
	// Check TPM 2.0 interface
	data, err := os.ReadFile("/sys/class/tpm/tpm0/tpm_version_major")
	if err == nil {
		version := strings.TrimSpace(string(data))
		if version == "2" {
			return TPMVersion20
		}
		if version == "1" {
			return TPMVersion12
		}
	}

	// Check device interface version
	if _, err := os.Stat("/sys/class/tpm/tpm0/device/caps"); err == nil {
		return TPMVersion12
	}

	return TPMVersionUnknown
}

// readPCRValues reads PCR values from the TPM.
func (tg *TrustGate) readPCRValues() ([]PCRValue, error) {
	var pcrs []PCRValue

	// Read from sysfs if available
	pcrDir := "/sys/class/tpm/tpm0/pcr-sha256"
	if _, err := os.Stat(pcrDir); err == nil {
		for _, idx := range tg.config.PCRsToVerify {
			pcrPath := filepath.Join(pcrDir, strconv.Itoa(idx))
			data, err := os.ReadFile(pcrPath)
			if err != nil {
				continue
			}
			pcrs = append(pcrs, PCRValue{
				Index:   idx,
				Bank:    PCRBankSHA256,
				Value:   strings.TrimSpace(string(data)),
				Purpose: getPCRPurpose(idx),
			})
		}
	}

	// Try SHA1 bank if SHA256 not available
	if len(pcrs) == 0 {
		pcrDir = "/sys/class/tpm/tpm0/pcr-sha1"
		if _, err := os.Stat(pcrDir); err == nil {
			for _, idx := range tg.config.PCRsToVerify {
				pcrPath := filepath.Join(pcrDir, strconv.Itoa(idx))
				data, err := os.ReadFile(pcrPath)
				if err != nil {
					continue
				}
				pcrs = append(pcrs, PCRValue{
					Index:   idx,
					Bank:    PCRBankSHA1,
					Value:   strings.TrimSpace(string(data)),
					Purpose: getPCRPurpose(idx),
				})
			}
		}
	}

	return pcrs, nil
}

// getPCRPurpose returns the purpose of a PCR index.
func getPCRPurpose(index int) string {
	purposes := map[int]string{
		0:  "SRTM, BIOS, Host Platform Extensions",
		1:  "Host Platform Configuration",
		2:  "Option ROM Code",
		3:  "Option ROM Configuration and Data",
		4:  "IPL Code (MBR)",
		5:  "IPL Code Configuration and Data",
		6:  "State Transition and Wake Events",
		7:  "Host Platform Manufacturer Specific",
		8:  "GRUB: Command Line",
		9:  "GRUB: Files Loaded",
		14: "Shim/MOK",
	}
	if purpose, ok := purposes[index]; ok {
		return purpose
	}
	return fmt.Sprintf("PCR %d", index)
}

// checkSecureBoot checks if secure boot is enabled.
func (tg *TrustGate) checkSecureBoot() (bool, error) {
	// Check EFI variable
	data, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if err != nil {
		// Try alternative path
		data, err = os.ReadFile("/sys/firmware/efi/vars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c/data")
		if err != nil {
			return false, err
		}
	}

	// Secure boot variable: attributes (4 bytes) + data (1 byte, 0x01 = enabled)
	if len(data) >= 5 {
		return data[4] == 0x01, nil
	}
	if len(data) >= 1 {
		return data[0] == 0x01, nil
	}

	return false, nil
}

// getKernelLockdown returns the kernel lockdown mode.
func (tg *TrustGate) getKernelLockdown() string {
	data, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err != nil {
		return "none"
	}

	content := strings.TrimSpace(string(data))
	// Format: "[none] integrity confidentiality"
	if strings.Contains(content, "[none]") {
		return "none"
	}
	if strings.Contains(content, "[integrity]") {
		return "integrity"
	}
	if strings.Contains(content, "[confidentiality]") {
		return "confidentiality"
	}

	return "unknown"
}

// checkIMA checks if IMA is enabled.
func (tg *TrustGate) checkIMA() bool {
	// Check for IMA measurement log
	if _, err := os.Stat("/sys/kernel/security/ima/ascii_runtime_measurements"); err == nil {
		return true
	}
	return false
}

// computeBootHash computes a hash of the boot measurements.
func (tg *TrustGate) computeBootHash(pcrs []PCRValue) string {
	h := sha256.New()
	for _, pcr := range pcrs {
		h.Write([]byte(fmt.Sprintf("%d:%s:%s", pcr.Index, pcr.Bank, pcr.Value)))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// RegisterRequirement registers a trust requirement for an operation.
func (tg *TrustGate) RegisterRequirement(req *TrustRequirement) {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	tg.requirements[req.Name] = req
	tg.logger.Debug("registered trust requirement",
		"operation", req.Name,
		"min_level", req.MinTrustLevel.String(),
		"require_tpm", req.RequireTPM)
}

// Gate checks if an operation is allowed based on trust requirements.
func (tg *TrustGate) Gate(ctx context.Context, operation string) (*GateResult, error) {
	tg.mu.RLock()
	req, hasReq := tg.requirements[operation]
	state := tg.platformState
	tg.mu.RUnlock()

	result := &GateResult{
		Allowed:       true,
		TrustLevel:    state.TrustLevel,
		PlatformState: state,
		Timestamp:     time.Now(),
	}

	if !hasReq {
		// No requirement - allow by default
		tg.recordResult(result)
		return result, nil
	}

	result.Requirement = req

	// Check minimum trust level
	if state.TrustLevel < req.MinTrustLevel {
		result.Allowed = false
		result.Reason = fmt.Sprintf("trust level %s below required %s",
			state.TrustLevel.String(), req.MinTrustLevel.String())
	}

	// Check TPM requirement
	if req.RequireTPM && !state.TPMAvailable {
		result.Allowed = false
		result.Reason = "TPM required but not available"
	}

	// Check secure boot requirement
	if req.RequireSecureBoot && !state.SecureBootOn {
		result.Allowed = false
		result.Reason = "secure boot required but disabled"
	}

	// Check measured boot requirement
	if req.RequireMeasuredBoot && !state.MeasuredBoot {
		result.Allowed = false
		result.Reason = "measured boot required but not available"
	}

	// Check expected PCR values
	if len(req.ExpectedPCRs) > 0 {
		for idx, expected := range req.ExpectedPCRs {
			found := false
			for _, pcr := range state.PCRValues {
				if pcr.Index == idx {
					found = true
					if pcr.Value != expected {
						result.Allowed = false
						result.Reason = fmt.Sprintf("PCR %d mismatch: expected %s, got %s",
							idx, expected, pcr.Value)
					}
					break
				}
			}
			if !found {
				result.Allowed = false
				result.Reason = fmt.Sprintf("required PCR %d not available", idx)
			}
		}
	}

	// Handle degraded mode
	if !result.Allowed && req.AllowDegraded {
		result.Allowed = true
		result.Degraded = true
		if tg.onDegraded != nil {
			tg.onDegraded(operation, result)
		}
		tg.logger.Warn("operation allowed in degraded mode",
			"operation", operation,
			"reason", result.Reason)
	}

	// Handle denied operations
	if !result.Allowed {
		if tg.onDenied != nil {
			tg.onDenied(operation, result)
		}
		tg.logger.Warn("operation denied by trust gate",
			"operation", operation,
			"reason", result.Reason)

		if tg.config.EnforceMode {
			tg.recordResult(result)
			return result, fmt.Errorf("%w: %s", ErrTrustLevelTooLow, result.Reason)
		}
	}

	tg.recordResult(result)
	return result, nil
}

// recordResult records a gate result.
func (tg *TrustGate) recordResult(result *GateResult) {
	tg.mu.Lock()
	defer tg.mu.Unlock()

	// Evict oldest if at capacity
	if len(tg.history) >= tg.config.MaxHistorySize {
		tg.history = tg.history[1:]
	}

	tg.history = append(tg.history, *result)
}

// GetPlatformState returns the current platform state.
func (tg *TrustGate) GetPlatformState() *PlatformState {
	tg.mu.RLock()
	defer tg.mu.RUnlock()
	return tg.platformState
}

// RefreshPlatformState refreshes the platform state.
func (tg *TrustGate) RefreshPlatformState() error {
	state, err := tg.capturePlatformState()
	if err != nil {
		return err
	}

	tg.mu.Lock()
	oldLevel := tg.platformState.TrustLevel
	tg.platformState = state
	tg.mu.Unlock()

	if state.TrustLevel != oldLevel {
		tg.logger.Warn("trust level changed",
			"old_level", oldLevel.String(),
			"new_level", state.TrustLevel.String())
	}

	return nil
}

// GetHistory returns recent gate results.
func (tg *TrustGate) GetHistory(count int) []GateResult {
	tg.mu.RLock()
	defer tg.mu.RUnlock()

	if count > len(tg.history) {
		count = len(tg.history)
	}

	result := make([]GateResult, count)
	copy(result, tg.history[len(tg.history)-count:])
	return result
}

// GetDenied returns denied gate results.
func (tg *TrustGate) GetDenied() []GateResult {
	tg.mu.RLock()
	defer tg.mu.RUnlock()

	var denied []GateResult
	for _, r := range tg.history {
		if !r.Allowed {
			denied = append(denied, r)
		}
	}
	return denied
}

// OnDegraded sets a callback for degraded mode operations.
func (tg *TrustGate) OnDegraded(callback func(op string, result *GateResult)) {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	tg.onDegraded = callback
}

// OnDenied sets a callback for denied operations.
func (tg *TrustGate) OnDenied(callback func(op string, result *GateResult)) {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	tg.onDenied = callback
}

// RequireLevel gates an operation based on trust level.
func (tg *TrustGate) RequireLevel(ctx context.Context, operation string, minLevel TrustLevel, fn func() error) error {
	tg.RegisterRequirement(&TrustRequirement{
		Name:          operation,
		MinTrustLevel: minLevel,
	})

	result, err := tg.Gate(ctx, operation)
	if err != nil {
		return err
	}

	if !result.Allowed {
		return fmt.Errorf("%w: operation %s requires trust level %s",
			ErrTrustLevelTooLow, operation, minLevel.String())
	}

	return fn()
}

// Common requirements for SIEM operations.
var (
	RequireFullTrust = &TrustRequirement{
		Name:                "full_trust",
		MinTrustLevel:       TrustLevelFull,
		RequireTPM:          true,
		RequireSecureBoot:   true,
		RequireMeasuredBoot: true,
	}

	RequireSecureTrust = &TrustRequirement{
		Name:              "secure_trust",
		MinTrustLevel:     TrustLevelSecure,
		RequireTPM:        true,
		RequireSecureBoot: true,
	}

	RequireTPMTrust = &TrustRequirement{
		Name:          "tpm_trust",
		MinTrustLevel: TrustLevelTPM,
		RequireTPM:    true,
	}

	RequireBasicTrust = &TrustRequirement{
		Name:          "basic_trust",
		MinTrustLevel: TrustLevelBasic,
		AllowDegraded: true,
	}

	// Policy-specific requirements
	RequirePolicyChange = &TrustRequirement{
		Name:              "policy_change",
		MinTrustLevel:     TrustLevelSecure,
		RequireTPM:        true,
		RequireSecureBoot: true,
		AllowDegraded:     false,
	}

	RequireModeTransition = &TrustRequirement{
		Name:          "mode_transition",
		MinTrustLevel: TrustLevelTPM,
		RequireTPM:    true,
		AllowDegraded: true,
	}

	RequireKeyOperation = &TrustRequirement{
		Name:                "key_operation",
		MinTrustLevel:       TrustLevelFull,
		RequireTPM:          true,
		RequireSecureBoot:   true,
		RequireMeasuredBoot: true,
		AllowDegraded:       false,
	}
)

// DefaultSIEMTrustGate creates a trust gate configured for SIEM operations.
func DefaultSIEMTrustGate(logger *slog.Logger) (*TrustGate, error) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true // Allow running without real TPM for testing

	tg, err := NewTrustGate(config, logger)
	if err != nil {
		return nil, err
	}

	// Register common requirements
	tg.RegisterRequirement(RequirePolicyChange)
	tg.RegisterRequirement(RequireModeTransition)
	tg.RegisterRequirement(RequireKeyOperation)

	return tg, nil
}

// PolicyGate wraps a function with trust gating for policy operations.
type PolicyGate struct {
	trustGate   *TrustGate
	operation   string
	requirement *TrustRequirement
}

// NewPolicyGate creates a new policy gate.
func NewPolicyGate(tg *TrustGate, operation string, req *TrustRequirement) *PolicyGate {
	if req != nil {
		tg.RegisterRequirement(req)
	}
	return &PolicyGate{
		trustGate:   tg,
		operation:   operation,
		requirement: req,
	}
}

// Execute runs the operation with trust gating.
func (pg *PolicyGate) Execute(ctx context.Context, fn func() error) error {
	result, err := pg.trustGate.Gate(ctx, pg.operation)
	if err != nil {
		return err
	}

	if !result.Allowed {
		return fmt.Errorf("%w: %s", ErrTrustLevelTooLow, result.Reason)
	}

	return fn()
}

// WithTrustGate wraps a function with trust verification.
func WithTrustGate[T any](tg *TrustGate, ctx context.Context, operation string, fn func() (T, error)) (T, error) {
	var zero T

	result, err := tg.Gate(ctx, operation)
	if err != nil {
		return zero, err
	}

	if !result.Allowed {
		return zero, fmt.Errorf("%w: %s", ErrTrustLevelTooLow, result.Reason)
	}

	return fn()
}
