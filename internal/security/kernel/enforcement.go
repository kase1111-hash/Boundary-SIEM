// Package kernel provides kernel-level security enforcement verification
// for SELinux and AppArmor mandatory access control systems.
package kernel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// EnforcementType represents the type of kernel enforcement.
type EnforcementType string

const (
	EnforcementSELinux   EnforcementType = "selinux"
	EnforcementAppArmor  EnforcementType = "apparmor"
	EnforcementNone      EnforcementType = "none"
	EnforcementUnknown   EnforcementType = "unknown"
)

// EnforcementMode represents the enforcement mode.
type EnforcementMode string

const (
	ModeEnforcing  EnforcementMode = "enforcing"
	ModePermissive EnforcementMode = "permissive"
	ModeDisabled   EnforcementMode = "disabled"
	ModeComplain   EnforcementMode = "complain" // AppArmor equivalent of permissive
)

// SecurityContext represents the current security context.
type SecurityContext struct {
	User     string `json:"user"`
	Role     string `json:"role"`
	Type     string `json:"type"`
	Level    string `json:"level"`
	Category string `json:"category"`
}

// EnforcementStatus represents the current enforcement status.
type EnforcementStatus struct {
	Type           EnforcementType  `json:"type"`
	Mode           EnforcementMode  `json:"mode"`
	PolicyLoaded   bool             `json:"policy_loaded"`
	PolicyVersion  string           `json:"policy_version"`
	Context        *SecurityContext `json:"context,omitempty"`
	ProfileName    string           `json:"profile_name,omitempty"`
	ProfileMode    string           `json:"profile_mode,omitempty"`
	LastCheck      time.Time        `json:"last_check"`
	Healthy        bool             `json:"healthy"`
	Error          string           `json:"error,omitempty"`
}

// EnforcementConfig configures the enforcement verifier.
type EnforcementConfig struct {
	RequiredType          EnforcementType `json:"required_type"`
	RequiredMode          EnforcementMode `json:"required_mode"`
	ExpectedSELinuxDomain string          `json:"expected_selinux_domain"`
	ExpectedAppArmorProfile string        `json:"expected_apparmor_profile"`
	CheckInterval         time.Duration   `json:"check_interval"`
	FailOnMismatch        bool            `json:"fail_on_mismatch"`
}

// DefaultEnforcementConfig returns the default configuration.
func DefaultEnforcementConfig() *EnforcementConfig {
	return &EnforcementConfig{
		RequiredType:            EnforcementNone, // Allow any by default
		RequiredMode:            ModeEnforcing,
		ExpectedSELinuxDomain:   "boundary_siem_t",
		ExpectedAppArmorProfile: "boundary-siem",
		CheckInterval:           30 * time.Second,
		FailOnMismatch:          false,
	}
}

// EnforcementVerifier verifies kernel-level security enforcement.
type EnforcementVerifier struct {
	mu       sync.RWMutex
	config   *EnforcementConfig
	status   *EnforcementStatus
	logger   *slog.Logger
	ctx      context.Context
	cancel   context.CancelFunc
	onChange func(status *EnforcementStatus)
}

// NewEnforcementVerifier creates a new enforcement verifier.
func NewEnforcementVerifier(config *EnforcementConfig, logger *slog.Logger) *EnforcementVerifier {
	if config == nil {
		config = DefaultEnforcementConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())

	return &EnforcementVerifier{
		config: config,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start begins periodic enforcement verification.
func (v *EnforcementVerifier) Start() error {
	// Initial check
	if err := v.Check(); err != nil {
		return err
	}

	// Start periodic checks
	go v.periodicCheck()

	return nil
}

// Stop stops the enforcement verifier.
func (v *EnforcementVerifier) Stop() {
	v.cancel()
}

// SetOnChange sets a callback for status changes.
func (v *EnforcementVerifier) SetOnChange(fn func(status *EnforcementStatus)) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.onChange = fn
}

// Check performs an enforcement status check.
func (v *EnforcementVerifier) Check() error {
	status := &EnforcementStatus{
		LastCheck: time.Now(),
	}

	// Detect enforcement type
	enfType := v.detectEnforcementType()
	status.Type = enfType

	var err error
	switch enfType {
	case EnforcementSELinux:
		err = v.checkSELinux(status)
	case EnforcementAppArmor:
		err = v.checkAppArmor(status)
	case EnforcementNone:
		status.Mode = ModeDisabled
		status.Healthy = true
		if v.config.RequiredType != EnforcementNone {
			status.Healthy = false
			status.Error = fmt.Sprintf("required enforcement type %s not available", v.config.RequiredType)
		}
	default:
		status.Healthy = false
		status.Error = "unable to determine enforcement type"
	}

	if err != nil {
		status.Healthy = false
		status.Error = err.Error()
	}

	// Validate against requirements
	if v.config.RequiredType != EnforcementNone && status.Type != v.config.RequiredType {
		status.Healthy = false
		status.Error = fmt.Sprintf("enforcement type mismatch: got %s, want %s", status.Type, v.config.RequiredType)
	}

	// Update status
	v.mu.Lock()
	oldStatus := v.status
	v.status = status
	onChange := v.onChange
	v.mu.Unlock()

	// Notify on change
	if onChange != nil && (oldStatus == nil || !statusEqual(oldStatus, status)) {
		onChange(status)
	}

	// Log status
	if status.Healthy {
		v.logger.Info("enforcement check passed",
			"type", status.Type,
			"mode", status.Mode,
			"policy_loaded", status.PolicyLoaded,
		)
	} else {
		v.logger.Warn("enforcement check warning",
			"type", status.Type,
			"mode", status.Mode,
			"error", status.Error,
		)
	}

	// Fail if configured
	if v.config.FailOnMismatch && !status.Healthy {
		return fmt.Errorf("enforcement verification failed: %s", status.Error)
	}

	return nil
}

// GetStatus returns the current enforcement status.
func (v *EnforcementVerifier) GetStatus() *EnforcementStatus {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.status == nil {
		return &EnforcementStatus{
			Type:    EnforcementUnknown,
			Healthy: false,
			Error:   "status not yet checked",
		}
	}
	// Return a copy
	status := *v.status
	return &status
}

// detectEnforcementType detects which MAC system is active.
func (v *EnforcementVerifier) detectEnforcementType() EnforcementType {
	// Check SELinux first
	if _, err := os.Stat("/sys/fs/selinux"); err == nil {
		return EnforcementSELinux
	}

	// Check AppArmor
	if _, err := os.Stat("/sys/kernel/security/apparmor"); err == nil {
		return EnforcementAppArmor
	}

	// Check for LSM info
	lsmData, err := os.ReadFile("/sys/kernel/security/lsm")
	if err == nil {
		lsm := string(lsmData)
		if strings.Contains(lsm, "selinux") {
			return EnforcementSELinux
		}
		if strings.Contains(lsm, "apparmor") {
			return EnforcementAppArmor
		}
	}

	return EnforcementNone
}

// checkSELinux checks SELinux enforcement status.
func (v *EnforcementVerifier) checkSELinux(status *EnforcementStatus) error {
	// Check enforcement mode
	enforceData, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil {
		return fmt.Errorf("failed to read SELinux enforce: %w", err)
	}

	enforceMode := strings.TrimSpace(string(enforceData))
	if enforceMode == "1" {
		status.Mode = ModeEnforcing
	} else {
		status.Mode = ModePermissive
	}

	// Check if policy is loaded
	policyData, err := os.ReadFile("/sys/fs/selinux/policyvers")
	if err == nil {
		status.PolicyLoaded = true
		status.PolicyVersion = strings.TrimSpace(string(policyData))
	}

	// Get current process context
	contextData, err := os.ReadFile("/proc/self/attr/current")
	if err == nil {
		context := v.parseSELinuxContext(strings.TrimSpace(string(contextData)))
		status.Context = context

		// Verify domain
		if v.config.ExpectedSELinuxDomain != "" && context.Type != v.config.ExpectedSELinuxDomain {
			status.Healthy = false
			status.Error = fmt.Sprintf("unexpected SELinux domain: got %s, want %s",
				context.Type, v.config.ExpectedSELinuxDomain)
			return nil
		}
	}

	// Verify mode
	if v.config.RequiredMode == ModeEnforcing && status.Mode != ModeEnforcing {
		status.Healthy = false
		status.Error = "SELinux is not in enforcing mode"
		return nil
	}

	status.Healthy = true
	return nil
}

// parseSELinuxContext parses an SELinux context string.
func (v *EnforcementVerifier) parseSELinuxContext(contextStr string) *SecurityContext {
	// Format: user:role:type:level or user:role:type:level:category
	parts := strings.Split(contextStr, ":")
	ctx := &SecurityContext{}

	if len(parts) >= 1 {
		ctx.User = parts[0]
	}
	if len(parts) >= 2 {
		ctx.Role = parts[1]
	}
	if len(parts) >= 3 {
		ctx.Type = parts[2]
	}
	if len(parts) >= 4 {
		ctx.Level = parts[3]
	}
	if len(parts) >= 5 {
		ctx.Category = parts[4]
	}

	return ctx
}

// checkAppArmor checks AppArmor enforcement status.
func (v *EnforcementVerifier) checkAppArmor(status *EnforcementStatus) error {
	// Get current profile
	attrData, err := os.ReadFile("/proc/self/attr/current")
	if err != nil {
		return fmt.Errorf("failed to read AppArmor profile: %w", err)
	}

	profileStr := strings.TrimSpace(string(attrData))
	status.ProfileName, status.ProfileMode = v.parseAppArmorProfile(profileStr)

	// Determine mode
	switch status.ProfileMode {
	case "enforce":
		status.Mode = ModeEnforcing
	case "complain":
		status.Mode = ModeComplain
	default:
		if status.ProfileName == "unconfined" {
			status.Mode = ModeDisabled
		} else {
			status.Mode = ModeEnforcing
		}
	}

	// Check if profiles are loaded
	profilesPath := "/sys/kernel/security/apparmor/profiles"
	if profiles, err := os.ReadFile(profilesPath); err == nil {
		status.PolicyLoaded = len(profiles) > 0
	}

	// Verify profile
	if v.config.ExpectedAppArmorProfile != "" {
		expectedProfile := v.config.ExpectedAppArmorProfile
		if !strings.HasPrefix(status.ProfileName, expectedProfile) && status.ProfileName != expectedProfile {
			status.Healthy = false
			status.Error = fmt.Sprintf("unexpected AppArmor profile: got %s, want %s",
				status.ProfileName, expectedProfile)
			return nil
		}
	}

	// Verify mode
	if v.config.RequiredMode == ModeEnforcing && status.Mode != ModeEnforcing {
		status.Healthy = false
		status.Error = "AppArmor is not in enforcing mode"
		return nil
	}

	status.Healthy = true
	return nil
}

// parseAppArmorProfile parses an AppArmor profile string.
func (v *EnforcementVerifier) parseAppArmorProfile(profileStr string) (name, mode string) {
	// Format: "profile_name (mode)" or just "profile_name" or "unconfined"
	re := regexp.MustCompile(`^(.+?)\s*\((\w+)\)$`)
	matches := re.FindStringSubmatch(profileStr)
	if len(matches) == 3 {
		return matches[1], matches[2]
	}
	return profileStr, ""
}

// periodicCheck performs periodic enforcement checks.
func (v *EnforcementVerifier) periodicCheck() {
	ticker := time.NewTicker(v.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-v.ctx.Done():
			return
		case <-ticker.C:
			if err := v.Check(); err != nil {
				v.logger.Error("periodic enforcement check failed", "error", err)
			}
		}
	}
}

// statusEqual compares two enforcement statuses for equality.
func statusEqual(a, b *EnforcementStatus) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Type == b.Type &&
		a.Mode == b.Mode &&
		a.PolicyLoaded == b.PolicyLoaded &&
		a.Healthy == b.Healthy &&
		a.Error == b.Error
}

// AuditLogEntry represents an SELinux/AppArmor audit log entry.
type AuditLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Type       string    `json:"type"`
	Action     string    `json:"action"`
	Result     string    `json:"result"`
	Subject    string    `json:"subject"`
	Object     string    `json:"object"`
	Executable string    `json:"executable"`
	Permission string    `json:"permission"`
	Raw        string    `json:"raw"`
}

// AuditLogWatcher watches for MAC audit log entries.
type AuditLogWatcher struct {
	logger     *slog.Logger
	ctx        context.Context
	cancel     context.CancelFunc
	entries    chan *AuditLogEntry
	patterns   []*regexp.Regexp
	enfType    EnforcementType
}

// NewAuditLogWatcher creates a new audit log watcher.
func NewAuditLogWatcher(enfType EnforcementType, logger *slog.Logger) *AuditLogWatcher {
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())

	w := &AuditLogWatcher{
		logger:  logger,
		ctx:     ctx,
		cancel:  cancel,
		entries: make(chan *AuditLogEntry, 100),
		enfType: enfType,
	}

	// Compile patterns for log parsing
	w.compilePatterns()

	return w
}

// compilePatterns compiles regex patterns for log parsing.
func (w *AuditLogWatcher) compilePatterns() {
	switch w.enfType {
	case EnforcementSELinux:
		w.patterns = []*regexp.Regexp{
			regexp.MustCompile(`type=AVC msg=audit\(([^)]+)\): avc:\s+(\w+)\s+\{([^}]+)\}.*scontext=([^\s]+)\s+tcontext=([^\s]+)`),
			regexp.MustCompile(`type=SELINUX_ERR.*`),
		}
	case EnforcementAppArmor:
		w.patterns = []*regexp.Regexp{
			regexp.MustCompile(`apparmor="(\w+)" operation="([^"]+)" profile="([^"]+)" name="([^"]+)"`),
			regexp.MustCompile(`apparmor="(\w+)" operation="([^"]+)" profile="([^"]+)"`),
		}
	}
}

// Start begins watching the audit log.
func (w *AuditLogWatcher) Start() error {
	go w.watchAuditLog()
	return nil
}

// Stop stops the audit log watcher.
func (w *AuditLogWatcher) Stop() {
	w.cancel()
	close(w.entries)
}

// Entries returns the channel of audit log entries.
func (w *AuditLogWatcher) Entries() <-chan *AuditLogEntry {
	return w.entries
}

// watchAuditLog watches the audit log for MAC-related entries.
func (w *AuditLogWatcher) watchAuditLog() {
	// Try different audit log locations
	logPaths := []string{
		"/var/log/audit/audit.log",
		"/var/log/kern.log",
		"/var/log/syslog",
		"/var/log/messages",
	}

	var logPath string
	for _, path := range logPaths {
		if _, err := os.Stat(path); err == nil {
			logPath = path
			break
		}
	}

	if logPath == "" {
		w.logger.Warn("no audit log found, falling back to dmesg")
		w.watchDmesg()
		return
	}

	w.watchFile(logPath)
}

// watchFile watches a specific log file.
func (w *AuditLogWatcher) watchFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		w.logger.Error("failed to open audit log", "path", path, "error", err)
		return
	}
	defer file.Close()

	// Seek to end
	file.Seek(0, 2)

	scanner := bufio.NewScanner(file)
	for {
		select {
		case <-w.ctx.Done():
			return
		default:
			if scanner.Scan() {
				line := scanner.Text()
				if entry := w.parseLine(line); entry != nil {
					select {
					case w.entries <- entry:
					default:
						// Channel full, log and drop entry
						w.logger.Warn("audit log entry channel full, dropping entry",
							"type", entry.Type,
							"action", entry.Action,
						)
					}
				}
			} else {
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

// watchDmesg watches dmesg for MAC-related entries.
func (w *AuditLogWatcher) watchDmesg() {
	for {
		select {
		case <-w.ctx.Done():
			return
		default:
			cmd := exec.CommandContext(w.ctx, "dmesg", "-w")
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				w.logger.Error("failed to start dmesg", "error", err)
				time.Sleep(5 * time.Second)
				continue
			}

			if err := cmd.Start(); err != nil {
				w.logger.Error("failed to start dmesg", "error", err)
				time.Sleep(5 * time.Second)
				continue
			}

			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				line := scanner.Text()
				if entry := w.parseLine(line); entry != nil {
					select {
					case w.entries <- entry:
					default:
						// Channel full, log and drop entry
						w.logger.Warn("audit log entry channel full, dropping entry",
							"type", entry.Type,
							"action", entry.Action,
						)
					}
				}
			}

			cmd.Wait()
			time.Sleep(1 * time.Second)
		}
	}
}

// parseLine parses a log line into an audit entry.
func (w *AuditLogWatcher) parseLine(line string) *AuditLogEntry {
	for _, pattern := range w.patterns {
		if matches := pattern.FindStringSubmatch(line); matches != nil {
			entry := &AuditLogEntry{
				Timestamp: time.Now(),
				Raw:       line,
			}

			switch w.enfType {
			case EnforcementSELinux:
				if len(matches) >= 5 {
					entry.Type = "AVC"
					entry.Result = matches[2]
					entry.Permission = matches[3]
					entry.Subject = matches[4]
					entry.Object = matches[5]
				}
			case EnforcementAppArmor:
				if len(matches) >= 4 {
					entry.Type = "APPARMOR"
					entry.Result = matches[1]
					entry.Action = matches[2]
					entry.Subject = matches[3]
					if len(matches) >= 5 {
						entry.Object = matches[4]
					}
				}
			}

			return entry
		}
	}
	return nil
}

// PolicyInstaller handles installation of security policies.
type PolicyInstaller struct {
	logger *slog.Logger
}

// NewPolicyInstaller creates a new policy installer.
func NewPolicyInstaller(logger *slog.Logger) *PolicyInstaller {
	if logger == nil {
		logger = slog.Default()
	}
	return &PolicyInstaller{logger: logger}
}

// InstallSELinuxPolicy installs the SELinux policy module.
func (p *PolicyInstaller) InstallSELinuxPolicy(policyDir string) error {
	teFile := filepath.Join(policyDir, "boundary_siem.te")
	modFile := filepath.Join(policyDir, "boundary_siem.mod")
	ppFile := filepath.Join(policyDir, "boundary_siem.pp")

	// Compile type enforcement
	cmd := exec.Command("checkmodule", "-M", "-m", "-o", modFile, teFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("checkmodule failed: %s: %w", string(output), err)
	}
	p.logger.Info("compiled SELinux policy module", "file", modFile)

	// Package policy
	cmd = exec.Command("semodule_package", "-o", ppFile, "-m", modFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("semodule_package failed: %s: %w", string(output), err)
	}
	p.logger.Info("packaged SELinux policy", "file", ppFile)

	// Install policy
	cmd = exec.Command("semodule", "-i", ppFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("semodule install failed: %s: %w", string(output), err)
	}
	p.logger.Info("installed SELinux policy")

	// Apply file contexts
	fcFile := filepath.Join(policyDir, "boundary_siem.fc")
	if _, err := os.Stat(fcFile); err == nil {
		cmd = exec.Command("semanage", "fcontext", "-a", "-t", "boundary_siem_exec_t", "/usr/local/bin/boundary-siem")
		cmd.Run() // Ignore errors if already exists

		cmd = exec.Command("restorecon", "-Rv", "/usr/local/bin/boundary-siem", "/etc/boundary-siem", "/var/log/boundary-siem", "/var/lib/boundary-siem")
		cmd.Run()
		p.logger.Info("applied SELinux file contexts")
	}

	return nil
}

// InstallAppArmorProfile installs the AppArmor profile.
func (p *PolicyInstaller) InstallAppArmorProfile(profilePath string) error {
	// Check if profile exists
	if _, err := os.Stat(profilePath); err != nil {
		return fmt.Errorf("profile not found: %w", err)
	}

	// Copy to AppArmor directory
	destPath := "/etc/apparmor.d/boundary-siem"
	input, err := os.ReadFile(profilePath)
	if err != nil {
		return fmt.Errorf("failed to read profile: %w", err)
	}

	if err := os.WriteFile(destPath, input, 0644); err != nil {
		return fmt.Errorf("failed to write profile: %w", err)
	}
	p.logger.Info("copied AppArmor profile", "dest", destPath)

	// Load the profile
	cmd := exec.Command("apparmor_parser", "-r", destPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("apparmor_parser failed: %s: %w", string(output), err)
	}
	p.logger.Info("loaded AppArmor profile")

	return nil
}

// VerifyInstallation verifies that policies are correctly installed.
func (p *PolicyInstaller) VerifyInstallation() error {
	verifier := NewEnforcementVerifier(nil, p.logger)
	if err := verifier.Check(); err != nil {
		return err
	}

	status := verifier.GetStatus()
	if !status.Healthy {
		return errors.New(status.Error)
	}

	return nil
}
