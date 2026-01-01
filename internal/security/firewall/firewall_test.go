package firewall

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Backend != BackendNone {
		t.Errorf("expected BackendNone, got %s", config.Backend)
	}
	if config.BlocklistTimeout != 1*time.Hour {
		t.Errorf("unexpected blocklist timeout: %v", config.BlocklistTimeout)
	}
	if len(config.TrustedNetworks) != 3 {
		t.Errorf("expected 3 trusted networks, got %d", len(config.TrustedNetworks))
	}
	if len(config.PublicPorts) != 4 {
		t.Errorf("expected 4 public ports, got %d", len(config.PublicPorts))
	}
	if len(config.ManagementPorts) != 4 {
		t.Errorf("expected 4 management ports, got %d", len(config.ManagementPorts))
	}
}

func TestValidateInterfaceName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid simple",
			input:   "eth0",
			wantErr: false,
		},
		{
			name:    "valid with dash",
			input:   "br-docker0",
			wantErr: false,
		},
		{
			name:    "valid with underscore",
			input:   "veth_abc123",
			wantErr: false,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: true,
		},
		{
			name:    "too long",
			input:   "verylonginterfacename",
			wantErr: true,
		},
		{
			name:    "command injection semicolon",
			input:   "eth0;rm -rf",
			wantErr: true,
		},
		{
			name:    "command injection pipe",
			input:   "eth0|cat /etc/passwd",
			wantErr: true,
		},
		{
			name:    "command injection backtick",
			input:   "eth`id`",
			wantErr: true,
		},
		{
			name:    "command injection dollar",
			input:   "eth$(whoami)",
			wantErr: true,
		},
		{
			name:    "newline injection",
			input:   "eth0\nmalicious",
			wantErr: true,
		},
		{
			name:    "space",
			input:   "eth 0",
			wantErr: true,
		},
		{
			name:    "quote",
			input:   "eth'0",
			wantErr: true,
		},
		{
			name:    "double quote",
			input:   `eth"0`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateInterfaceName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateInterfaceName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestBlockedIP(t *testing.T) {
	ip := net.ParseIP("192.168.1.100")
	blocked := &BlockedIP{
		IP:        ip,
		Reason:    "Test block",
		Timestamp: time.Now(),
		Expires:   time.Now().Add(1 * time.Hour),
	}

	if blocked.IP.String() != "192.168.1.100" {
		t.Errorf("unexpected IP: %s", blocked.IP.String())
	}
	if blocked.Reason != "Test block" {
		t.Errorf("unexpected reason: %s", blocked.Reason)
	}
}

func TestRule(t *testing.T) {
	rule := &Rule{
		Name:        "allow-https",
		Description: "Allow HTTPS traffic",
		Direction:   DirectionInput,
		Protocol:    ProtocolTCP,
		DestPort:    443,
		Action:      ActionAccept,
		Comment:     "HTTPS ingress",
		Order:       1,
	}

	if rule.Name != "allow-https" {
		t.Errorf("unexpected name: %s", rule.Name)
	}
	if rule.Direction != DirectionInput {
		t.Errorf("unexpected direction: %s", rule.Direction)
	}
	if rule.Protocol != ProtocolTCP {
		t.Errorf("unexpected protocol: %s", rule.Protocol)
	}
	if rule.Action != ActionAccept {
		t.Errorf("unexpected action: %s", rule.Action)
	}
}

func TestStatus(t *testing.T) {
	status := &Status{
		Backend:    BackendNftables,
		Active:     true,
		RulesCount: 10,
		BlockedIPs: 5,
		LastUpdate: time.Now(),
	}

	if status.Backend != BackendNftables {
		t.Errorf("unexpected backend: %s", status.Backend)
	}
	if !status.Active {
		t.Error("expected active status")
	}
	if status.RulesCount != 10 {
		t.Errorf("unexpected rules count: %d", status.RulesCount)
	}
	if status.BlockedIPs != 5 {
		t.Errorf("unexpected blocked IPs: %d", status.BlockedIPs)
	}
}

func TestBackendConstants(t *testing.T) {
	if string(BackendNftables) != "nftables" {
		t.Errorf("BackendNftables = %s", BackendNftables)
	}
	if string(BackendIptables) != "iptables" {
		t.Errorf("BackendIptables = %s", BackendIptables)
	}
	if string(BackendNone) != "none" {
		t.Errorf("BackendNone = %s", BackendNone)
	}
}

func TestActionConstants(t *testing.T) {
	if string(ActionAccept) != "accept" {
		t.Errorf("ActionAccept = %s", ActionAccept)
	}
	if string(ActionDrop) != "drop" {
		t.Errorf("ActionDrop = %s", ActionDrop)
	}
	if string(ActionReject) != "reject" {
		t.Errorf("ActionReject = %s", ActionReject)
	}
	if string(ActionLog) != "log" {
		t.Errorf("ActionLog = %s", ActionLog)
	}
}

func TestProtocolConstants(t *testing.T) {
	if string(ProtocolTCP) != "tcp" {
		t.Errorf("ProtocolTCP = %s", ProtocolTCP)
	}
	if string(ProtocolUDP) != "udp" {
		t.Errorf("ProtocolUDP = %s", ProtocolUDP)
	}
	if string(ProtocolICMP) != "icmp" {
		t.Errorf("ProtocolICMP = %s", ProtocolICMP)
	}
}

func TestDirectionConstants(t *testing.T) {
	if string(DirectionInput) != "input" {
		t.Errorf("DirectionInput = %s", DirectionInput)
	}
	if string(DirectionOutput) != "output" {
		t.Errorf("DirectionOutput = %s", DirectionOutput)
	}
	if string(DirectionForward) != "forward" {
		t.Errorf("DirectionForward = %s", DirectionForward)
	}
}

func TestNewManager(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Test with nil config (should use defaults)
	manager, err := NewManager(nil, logger)

	// May fail if no firewall backend is available in test environment
	if err != nil {
		t.Logf("NewManager error (expected in test env without firewall): %v", err)
		return
	}

	if manager == nil {
		t.Fatal("expected non-nil manager")
	}

	backend := manager.GetBackend()
	if backend != BackendNftables && backend != BackendIptables {
		t.Errorf("unexpected backend: %s", backend)
	}

	manager.Stop()
}

func TestManager_GetStatus(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultConfig()

	manager, err := NewManager(config, logger)
	if err != nil {
		t.Skipf("firewall not available: %v", err)
	}
	defer manager.Stop()

	status := manager.GetStatus()

	if status == nil {
		t.Fatal("expected non-nil status")
	}
	if status.Backend != manager.GetBackend() {
		t.Errorf("backend mismatch: got %s, want %s", status.Backend, manager.GetBackend())
	}
	if status.LastUpdate.IsZero() {
		t.Error("expected LastUpdate to be set")
	}
}

func TestManager_GetBlockedIPs_Empty(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	manager, err := NewManager(nil, logger)
	if err != nil {
		t.Skipf("firewall not available: %v", err)
	}
	defer manager.Stop()

	blocked := manager.GetBlockedIPs()
	if len(blocked) != 0 {
		t.Errorf("expected empty blocklist, got %d entries", len(blocked))
	}
}

func TestManager_StartStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	manager, err := NewManager(nil, logger)
	if err != nil {
		t.Skipf("firewall not available: %v", err)
	}

	err = manager.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)

	manager.Stop()
}

func TestManager_BlockIP_InvalidIP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	manager, err := NewManager(nil, logger)
	if err != nil {
		t.Skipf("firewall not available: %v", err)
	}
	defer manager.Stop()

	ctx := context.Background()

	// Try to block nil IP
	err = manager.BlockIP(ctx, nil, "test", 1*time.Hour)
	if err == nil {
		t.Error("expected error for nil IP")
	}

	// Try to block loopback
	err = manager.BlockIP(ctx, net.ParseIP("127.0.0.1"), "test", 1*time.Hour)
	if err == nil {
		t.Error("expected error for loopback IP")
	}
}

func TestIPValidation(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		isValid  bool
		isIPv4   bool
		isIPv6   bool
		isLoopback bool
	}{
		{"valid IPv4", "192.168.1.1", true, true, false, false},
		{"valid IPv6", "2001:db8::1", true, false, true, false},
		{"loopback IPv4", "127.0.0.1", true, true, false, true},
		{"loopback IPv6", "::1", true, false, true, true},
		{"invalid", "not-an-ip", false, false, false, false},
		{"empty", "", false, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)

			if tt.isValid && ip == nil {
				t.Errorf("expected valid IP, got nil")
			}
			if !tt.isValid && ip != nil {
				t.Errorf("expected invalid IP, got %s", ip)
			}

			if ip != nil {
				isV4 := ip.To4() != nil
				if isV4 != tt.isIPv4 {
					t.Errorf("IPv4 check: got %v, want %v", isV4, tt.isIPv4)
				}

				if ip.IsLoopback() != tt.isLoopback {
					t.Errorf("loopback check: got %v, want %v", ip.IsLoopback(), tt.isLoopback)
				}
			}
		})
	}
}

func BenchmarkValidateInterfaceName(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ValidateInterfaceName("eth0")
	}
}

func BenchmarkValidateInterfaceName_Long(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ValidateInterfaceName("br-docker0_veth")
	}
}

func BenchmarkValidateInterfaceName_Invalid(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ValidateInterfaceName("eth0;rm -rf")
	}
}
