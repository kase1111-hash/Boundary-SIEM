// Package firewall provides independent firewall rule management
// using nftables or iptables, without daemon dependency.
package firewall

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Backend represents the firewall backend type.
type Backend string

const (
	BackendNftables Backend = "nftables"
	BackendIptables Backend = "iptables"
	BackendNone     Backend = "none"
)

// RuleAction represents the action to take on matched traffic.
type RuleAction string

const (
	ActionAccept RuleAction = "accept"
	ActionDrop   RuleAction = "drop"
	ActionReject RuleAction = "reject"
	ActionLog    RuleAction = "log"
)

// Protocol represents network protocol.
type Protocol string

const (
	ProtocolTCP  Protocol = "tcp"
	ProtocolUDP  Protocol = "udp"
	ProtocolICMP Protocol = "icmp"
	ProtocolAny  Protocol = "any"
)

// Direction represents traffic direction.
type Direction string

const (
	DirectionInput   Direction = "input"
	DirectionOutput  Direction = "output"
	DirectionForward Direction = "forward"
)

// Rule represents a firewall rule.
type Rule struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Direction   Direction  `json:"direction"`
	Protocol    Protocol   `json:"protocol"`
	SourceIP    string     `json:"source_ip,omitempty"`
	DestIP      string     `json:"dest_ip,omitempty"`
	SourcePort  int        `json:"source_port,omitempty"`
	DestPort    int        `json:"dest_port,omitempty"`
	Action      RuleAction `json:"action"`
	RateLimit   string     `json:"rate_limit,omitempty"` // e.g., "10/second"
	Comment     string     `json:"comment,omitempty"`
	Order       int        `json:"order"`
}

// BlockedIP represents a blocked IP address.
type BlockedIP struct {
	IP        net.IP    `json:"ip"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
	Expires   time.Time `json:"expires"`
}

// Status represents the firewall status.
type Status struct {
	Backend    Backend   `json:"backend"`
	Active     bool      `json:"active"`
	RulesCount int       `json:"rules_count"`
	BlockedIPs int       `json:"blocked_ips"`
	LastUpdate time.Time `json:"last_update"`
	Error      string    `json:"error,omitempty"`
}

// Config holds firewall configuration.
type Config struct {
	Backend          Backend       `json:"backend"`
	NftablesPath     string        `json:"nftables_path"`
	IptablesPath     string        `json:"iptables_path"`
	RulesFile        string        `json:"rules_file"`
	BlocklistTimeout time.Duration `json:"blocklist_timeout"`
	EnableLogging    bool          `json:"enable_logging"`
	LogPrefix        string        `json:"log_prefix"`
	TrustedNetworks  []string      `json:"trusted_networks"`
	PublicPorts      []int         `json:"public_ports"`
	ManagementPorts  []int         `json:"management_ports"`
}

// DefaultConfig returns default firewall configuration.
func DefaultConfig() *Config {
	return &Config{
		Backend:          BackendNone, // Auto-detect
		NftablesPath:     "/usr/sbin/nft",
		IptablesPath:     "/sbin/iptables",
		RulesFile:        "/etc/nftables.d/boundary-siem.nft",
		BlocklistTimeout: 1 * time.Hour,
		EnableLogging:    true,
		LogPrefix:        "BOUNDARY-SIEM",
		TrustedNetworks: []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		},
		PublicPorts:     []int{8443, 5514, 6514, 8080},
		ManagementPorts: []int{9090, 22, 9100, 6060},
	}
}

// Manager manages firewall rules.
type Manager struct {
	mu             sync.RWMutex
	backendMu      sync.RWMutex // Protects backend field
	detectMu       sync.Mutex   // Ensures only one detection runs at a time
	config         *Config
	backend        Backend
	backendChecked bool // Whether backend has been detected
	detecting      bool // Whether detection is in progress
	logger         *slog.Logger
	blockedIPs     map[string]*BlockedIP
	rules          []*Rule
	ctx            context.Context
	cancel         context.CancelFunc
}

// NewManager creates a new firewall manager.
func NewManager(config *Config, logger *slog.Logger) (*Manager, error) {
	if config == nil {
		config = DefaultConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		config:     config,
		logger:     logger,
		blockedIPs: make(map[string]*BlockedIP),
		rules:      make([]*Rule, 0),
		ctx:        ctx,
		cancel:     cancel,
	}

	// Detect backend
	backend, err := m.detectBackend()
	if err != nil {
		cancel()
		return nil, err
	}
	m.backend = backend

	logger.Info("firewall manager initialized",
		"backend", backend,
	)

	return m, nil
}

// detectBackend detects the available firewall backend with mutual exclusion.
// This ensures only one detection can run at a time to prevent race conditions.
func (m *Manager) detectBackend() (Backend, error) {
	// Acquire detection mutex to ensure exclusive access
	m.detectMu.Lock()
	defer m.detectMu.Unlock()

	// Check if already detected (double-check under lock)
	m.backendMu.RLock()
	if m.backendChecked {
		backend := m.backend
		m.backendMu.RUnlock()
		return backend, nil
	}
	m.backendMu.RUnlock()

	// Mark detection as in progress
	m.backendMu.Lock()
	if m.detecting {
		m.backendMu.Unlock()
		// Another goroutine is detecting, wait and return result
		m.detectMu.Lock() // This will block until other detection completes
		m.detectMu.Unlock()
		m.backendMu.RLock()
		backend := m.backend
		m.backendMu.RUnlock()
		return backend, nil
	}
	m.detecting = true
	m.backendMu.Unlock()

	// Perform actual detection
	var detectedBackend Backend
	var detectionErr error

	// Check if nftables is available
	if m.config.Backend == BackendNftables || m.config.Backend == BackendNone {
		if _, err := exec.LookPath(m.config.NftablesPath); err == nil {
			// Verify nftables is working
			cmd := exec.Command(m.config.NftablesPath, "list", "ruleset")
			if err := cmd.Run(); err == nil {
				detectedBackend = BackendNftables
			}
		}
	}

	// Check if iptables is available (only if nftables not found)
	if detectedBackend == "" {
		if m.config.Backend == BackendIptables || m.config.Backend == BackendNone {
			if _, err := exec.LookPath(m.config.IptablesPath); err == nil {
				// Verify iptables is working
				cmd := exec.Command(m.config.IptablesPath, "-L", "-n")
				if err := cmd.Run(); err == nil {
					detectedBackend = BackendIptables
				}
			}
		}
	}

	if detectedBackend == "" {
		detectedBackend = BackendNone
		detectionErr = errors.New("no firewall backend available")
	}

	// Store result under write lock
	m.backendMu.Lock()
	m.backend = detectedBackend
	m.backendChecked = true
	m.detecting = false
	m.backendMu.Unlock()

	if m.logger != nil && detectedBackend != BackendNone {
		m.logger.Debug("backend detection completed", "backend", detectedBackend)
	}

	return detectedBackend, detectionErr
}

// GetBackend returns the detected backend with thread-safe access.
func (m *Manager) GetBackend() Backend {
	m.backendMu.RLock()
	defer m.backendMu.RUnlock()
	return m.backend
}

// Start begins firewall management.
func (m *Manager) Start() error {
	// Start blocklist cleanup goroutine
	go m.cleanupBlocklist()

	return nil
}

// Stop stops the firewall manager.
func (m *Manager) Stop() {
	m.cancel()
}

// GetStatus returns the current firewall status.
func (m *Manager) GetStatus() *Status {
	m.mu.RLock()
	rulesCount := len(m.rules)
	blockedIPsCount := len(m.blockedIPs)
	m.mu.RUnlock()

	// Get backend with proper locking
	backend := m.GetBackend()

	status := &Status{
		Backend:    backend,
		Active:     false,
		RulesCount: rulesCount,
		BlockedIPs: blockedIPsCount,
		LastUpdate: time.Now(),
	}

	// Check if rules are loaded
	var err error
	switch backend {
	case BackendNftables:
		status.Active, err = m.checkNftablesActive()
	case BackendIptables:
		status.Active, err = m.checkIptablesActive()
	}

	if err != nil {
		status.Error = err.Error()
	}

	return status
}

// checkNftablesActive checks if nftables rules are loaded.
func (m *Manager) checkNftablesActive() (bool, error) {
	cmd := exec.Command(m.config.NftablesPath, "list", "table", "inet", "boundary_siem")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil // Table doesn't exist, not an error
	}
	return strings.Contains(string(output), "boundary_siem"), nil
}

// checkIptablesActive checks if iptables rules are loaded.
func (m *Manager) checkIptablesActive() (bool, error) {
	cmd := exec.Command(m.config.IptablesPath, "-L", "SIEM_SERVICES", "-n")
	if err := cmd.Run(); err != nil {
		return false, nil // Chain doesn't exist
	}
	return true, nil
}

// LoadRules loads firewall rules from the configuration file.
func (m *Manager) LoadRules(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	backend := m.GetBackend()
	m.logger.Info("loading firewall rules", "backend", backend)

	switch backend {
	case BackendNftables:
		return m.loadNftablesRules(ctx)
	case BackendIptables:
		return m.loadIptablesRules(ctx)
	default:
		return errors.New("no firewall backend available")
	}
}

// loadNftablesRules loads nftables rules.
func (m *Manager) loadNftablesRules(ctx context.Context) error {
	rulesFile := m.config.RulesFile
	if _, err := os.Stat(rulesFile); os.IsNotExist(err) {
		return fmt.Errorf("rules file not found: %s", rulesFile)
	}

	cmd := exec.CommandContext(ctx, m.config.NftablesPath, "-f", rulesFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to load nftables rules: %s: %w", string(output), err)
	}

	m.logger.Info("nftables rules loaded successfully", "file", rulesFile)
	return nil
}

// loadIptablesRules loads iptables rules.
func (m *Manager) loadIptablesRules(ctx context.Context) error {
	rulesFile := strings.Replace(m.config.RulesFile, ".nft", ".iptables", 1)
	if _, err := os.Stat(rulesFile); os.IsNotExist(err) {
		// Try default location
		rulesFile = "/etc/iptables/boundary-siem.rules"
	}

	if _, err := os.Stat(rulesFile); os.IsNotExist(err) {
		return fmt.Errorf("rules file not found: %s", rulesFile)
	}

	file, err := os.Open(rulesFile)
	if err != nil {
		return fmt.Errorf("failed to open rules file: %w", err)
	}
	defer file.Close()

	cmd := exec.CommandContext(ctx, "/sbin/iptables-restore")
	cmd.Stdin = file
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to load iptables rules: %s: %w", string(output), err)
	}

	m.logger.Info("iptables rules loaded successfully", "file", rulesFile)
	return nil
}

// BlockIP adds an IP to the blocklist.
func (m *Manager) BlockIP(ctx context.Context, ip net.IP, reason string, duration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ipStr := ip.String()

	// Validate IP
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return errors.New("invalid IP address")
	}

	// Check if already blocked
	if _, exists := m.blockedIPs[ipStr]; exists {
		return nil
	}

	// Add to in-memory blocklist
	blocked := &BlockedIP{
		IP:        ip,
		Reason:    reason,
		Timestamp: time.Now(),
		Expires:   time.Now().Add(duration),
	}
	m.blockedIPs[ipStr] = blocked

	// Add to firewall
	var err error
	backend := m.GetBackend()
	switch backend {
	case BackendNftables:
		err = m.nftablesBlockIP(ctx, ip, duration)
	case BackendIptables:
		err = m.iptablesBlockIP(ctx, ip)
	}

	if err != nil {
		delete(m.blockedIPs, ipStr)
		return fmt.Errorf("failed to block IP: %w", err)
	}

	m.logger.Warn("blocked IP address",
		"ip", ipStr,
		"reason", reason,
		"duration", duration,
	)

	return nil
}

// nftablesBlockIP blocks an IP using nftables.
func (m *Manager) nftablesBlockIP(ctx context.Context, ip net.IP, timeout time.Duration) error {
	setName := "blocked_ips"
	if ip.To4() == nil {
		setName = "blocked_ips_v6"
	}

	// Add to set with timeout
	cmd := exec.CommandContext(ctx, m.config.NftablesPath, "add", "element",
		"inet", "boundary_siem", setName,
		fmt.Sprintf("{ %s timeout %ds }", ip.String(), int(timeout.Seconds())))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nftables add element failed: %s: %w", string(output), err)
	}

	return nil
}

// iptablesBlockIP blocks an IP using iptables.
func (m *Manager) iptablesBlockIP(ctx context.Context, ip net.IP) error {
	ipVersion := "-4"
	iptablesCmd := m.config.IptablesPath
	if ip.To4() == nil {
		ipVersion = "-6"
		iptablesCmd = "/sbin/ip6tables"
	}

	cmd := exec.CommandContext(ctx, iptablesCmd, ipVersion, "-I", "INPUT", "1",
		"-s", ip.String(), "-j", "DROP",
		"-m", "comment", "--comment", "boundary-siem-blocked")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables block failed: %s: %w", string(output), err)
	}

	return nil
}

// UnblockIP removes an IP from the blocklist.
func (m *Manager) UnblockIP(ctx context.Context, ip net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ipStr := ip.String()

	if _, exists := m.blockedIPs[ipStr]; !exists {
		return nil
	}

	// Remove from firewall
	var err error
	backend := m.GetBackend()
	switch backend {
	case BackendNftables:
		err = m.nftablesUnblockIP(ctx, ip)
	case BackendIptables:
		err = m.iptablesUnblockIP(ctx, ip)
	}

	if err != nil {
		return fmt.Errorf("failed to unblock IP: %w", err)
	}

	delete(m.blockedIPs, ipStr)

	m.logger.Info("unblocked IP address", "ip", ipStr)
	return nil
}

// nftablesUnblockIP unblocks an IP using nftables.
func (m *Manager) nftablesUnblockIP(ctx context.Context, ip net.IP) error {
	setName := "blocked_ips"
	if ip.To4() == nil {
		setName = "blocked_ips_v6"
	}

	cmd := exec.CommandContext(ctx, m.config.NftablesPath, "delete", "element",
		"inet", "boundary_siem", setName,
		fmt.Sprintf("{ %s }", ip.String()))

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Element might not exist
		if strings.Contains(string(output), "does not exist") {
			return nil
		}
		return fmt.Errorf("nftables delete element failed: %s: %w", string(output), err)
	}

	return nil
}

// iptablesUnblockIP unblocks an IP using iptables.
func (m *Manager) iptablesUnblockIP(ctx context.Context, ip net.IP) error {
	iptablesCmd := m.config.IptablesPath
	if ip.To4() == nil {
		iptablesCmd = "/sbin/ip6tables"
	}

	// Delete all matching rules
	for {
		cmd := exec.CommandContext(ctx, iptablesCmd, "-D", "INPUT",
			"-s", ip.String(), "-j", "DROP")

		if err := cmd.Run(); err != nil {
			break // No more rules to delete
		}
	}

	return nil
}

// GetBlockedIPs returns the list of blocked IPs.
func (m *Manager) GetBlockedIPs() []*BlockedIP {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*BlockedIP, 0, len(m.blockedIPs))
	for _, blocked := range m.blockedIPs {
		result = append(result, blocked)
	}
	return result
}

// cleanupBlocklist removes expired entries from the blocklist.
func (m *Manager) cleanupBlocklist() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			now := time.Now()
			for ipStr, blocked := range m.blockedIPs {
				if now.After(blocked.Expires) {
					delete(m.blockedIPs, ipStr)
					m.logger.Info("blocklist entry expired", "ip", ipStr)
				}
			}
			m.mu.Unlock()
		}
	}
}

// AddTrustedNetwork adds a network to the trusted list.
func (m *Manager) AddTrustedNetwork(ctx context.Context, cidr string) error {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}

	backend := m.GetBackend()
	switch backend {
	case BackendNftables:
		setName := "trusted_mgmt"
		if network.IP.To4() == nil {
			setName = "trusted_mgmt_v6"
		}

		cmd := exec.CommandContext(ctx, m.config.NftablesPath, "add", "element",
			"inet", "boundary_siem", setName,
			fmt.Sprintf("{ %s }", cidr))

		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to add trusted network: %s: %w", string(output), err)
		}

	case BackendIptables:
		// Add to MGMT_SERVICES chain
		for _, port := range m.config.ManagementPorts {
			cmd := exec.CommandContext(ctx, m.config.IptablesPath,
				"-A", "MGMT_SERVICES",
				"-s", cidr,
				"-p", "tcp", "--dport", fmt.Sprintf("%d", port),
				"-j", "ACCEPT")
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to add trusted network: %w", err)
			}
		}
	}

	m.config.TrustedNetworks = append(m.config.TrustedNetworks, cidr)
	m.logger.Info("added trusted network", "cidr", cidr)

	return nil
}

// RemoveTrustedNetwork removes a network from the trusted list.
func (m *Manager) RemoveTrustedNetwork(ctx context.Context, cidr string) error {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}

	backend := m.GetBackend()
	switch backend {
	case BackendNftables:
		setName := "trusted_mgmt"
		if network.IP.To4() == nil {
			setName = "trusted_mgmt_v6"
		}

		cmd := exec.CommandContext(ctx, m.config.NftablesPath, "delete", "element",
			"inet", "boundary_siem", setName,
			fmt.Sprintf("{ %s }", cidr))

		if output, err := cmd.CombinedOutput(); err != nil {
			if !strings.Contains(string(output), "does not exist") {
				return fmt.Errorf("failed to remove trusted network: %s: %w", string(output), err)
			}
		}

	case BackendIptables:
		for _, port := range m.config.ManagementPorts {
			exec.CommandContext(ctx, m.config.IptablesPath,
				"-D", "MGMT_SERVICES",
				"-s", cidr,
				"-p", "tcp", "--dport", fmt.Sprintf("%d", port),
				"-j", "ACCEPT").Run()
		}
	}

	// Remove from config
	networks := make([]string, 0)
	for _, n := range m.config.TrustedNetworks {
		if n != cidr {
			networks = append(networks, n)
		}
	}
	m.config.TrustedNetworks = networks

	m.logger.Info("removed trusted network", "cidr", cidr)
	return nil
}

// GetRuleStats returns statistics about firewall rules.
func (m *Manager) GetRuleStats(ctx context.Context) (map[string]interface{}, error) {
	backend := m.GetBackend()
	stats := make(map[string]interface{})
	stats["backend"] = string(backend)
	stats["timestamp"] = time.Now()

	switch backend {
	case BackendNftables:
		return m.getNftablesStats(ctx, stats)
	case BackendIptables:
		return m.getIptablesStats(ctx, stats)
	}

	return stats, nil
}

// getNftablesStats gets nftables statistics.
func (m *Manager) getNftablesStats(ctx context.Context, stats map[string]interface{}) (map[string]interface{}, error) {
	cmd := exec.CommandContext(ctx, m.config.NftablesPath, "-j", "list", "counters", "table", "inet", "boundary_siem")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return stats, nil // Table might not have counters
	}

	stats["counters"] = string(output)
	return stats, nil
}

// getIptablesStats gets iptables statistics.
func (m *Manager) getIptablesStats(ctx context.Context, stats map[string]interface{}) (map[string]interface{}, error) {
	cmd := exec.CommandContext(ctx, m.config.IptablesPath, "-L", "-n", "-v", "-x")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return stats, err
	}

	stats["rules"] = string(output)
	return stats, nil
}

// ValidateInterfaceName validates a network interface name to prevent injection.
func ValidateInterfaceName(name string) error {
	if name == "" {
		return errors.New("interface name cannot be empty")
	}

	if len(name) > 15 {
		return errors.New("interface name too long (max 15 characters)")
	}

	// Only allow alphanumeric, dash, and underscore
	validName := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !validName.MatchString(name) {
		return errors.New("interface name contains invalid characters")
	}

	// Block dangerous patterns
	dangerous := []string{
		";", "|", "&", "$", "`", "(", ")", "{", "}", "[", "]",
		"<", ">", "\\", "'", "\"", "\n", "\r", "\t",
	}
	for _, char := range dangerous {
		if strings.Contains(name, char) {
			return fmt.Errorf("interface name contains forbidden character: %s", char)
		}
	}

	return nil
}

// SaveRules saves current rules to a file.
func (m *Manager) SaveRules(ctx context.Context, path string) error {
	backend := m.GetBackend()
	switch backend {
	case BackendNftables:
		cmd := exec.CommandContext(ctx, m.config.NftablesPath, "list", "table", "inet", "boundary_siem")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to list rules: %w", err)
		}

		return os.WriteFile(path, output, 0600)

	case BackendIptables:
		cmd := exec.CommandContext(ctx, "/sbin/iptables-save")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to save rules: %w", err)
		}

		return os.WriteFile(path, output, 0600)
	}

	return errors.New("no backend available")
}

// RestoreRules restores rules from a backup file.
func (m *Manager) RestoreRules(ctx context.Context, path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("backup file not found: %s", path)
	}

	backend := m.GetBackend()
	switch backend {
	case BackendNftables:
		cmd := exec.CommandContext(ctx, m.config.NftablesPath, "-f", path)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to restore rules: %s: %w", string(output), err)
		}

	case BackendIptables:
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		cmd := exec.CommandContext(ctx, "/sbin/iptables-restore")
		cmd.Stdin = file
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to restore rules: %s: %w", string(output), err)
		}
	}

	m.logger.Info("restored firewall rules from backup", "path", path)
	return nil
}

// Flush removes all boundary-siem rules.
func (m *Manager) Flush(ctx context.Context) error {
	m.logger.Warn("flushing all boundary-siem firewall rules")

	backend := m.GetBackend()
	switch backend {
	case BackendNftables:
		exec.CommandContext(ctx, m.config.NftablesPath, "delete", "table", "inet", "boundary_siem").Run()
		exec.CommandContext(ctx, m.config.NftablesPath, "delete", "table", "inet", "boundary_ratelimit").Run()

	case BackendIptables:
		// Delete chains
		for _, chain := range []string{"SIEM_SERVICES", "MGMT_SERVICES", "LOGGING"} {
			exec.CommandContext(ctx, m.config.IptablesPath, "-F", chain).Run()
			exec.CommandContext(ctx, m.config.IptablesPath, "-X", chain).Run()
		}
	}

	return nil
}
