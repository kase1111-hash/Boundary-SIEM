package usb

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDeviceClassNames(t *testing.T) {
	tests := []struct {
		class DeviceClass
		name  string
	}{
		{ClassMassStorage, "Mass Storage"},
		{ClassHID, "Human Interface Device"},
		{ClassHub, "Hub"},
		{ClassAudio, "Audio"},
		{ClassVideo, "Video"},
		{ClassWireless, "Wireless"},
		{ClassPrinter, "Printer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeviceClassNames[tt.class]
			if got != tt.name {
				t.Errorf("DeviceClassNames[%d] = %q, want %q", tt.class, got, tt.name)
			}
		})
	}
}

func TestDevice_DeviceID(t *testing.T) {
	device := &Device{
		VendorID:  0x1234,
		ProductID: 0x5678,
	}

	expected := "1234:5678"
	if got := device.DeviceID(); got != expected {
		t.Errorf("DeviceID() = %q, want %q", got, expected)
	}
}

func TestDevice_FullID_WithSerial(t *testing.T) {
	device := &Device{
		VendorID:  0x1234,
		ProductID: 0x5678,
		Serial:    "ABC123",
	}

	expected := "1234:5678:ABC123"
	if got := device.FullID(); got != expected {
		t.Errorf("FullID() = %q, want %q", got, expected)
	}
}

func TestDevice_FullID_WithoutSerial(t *testing.T) {
	device := &Device{
		VendorID:  0x1234,
		ProductID: 0x5678,
		BusNum:    1,
		DevNum:    2,
	}

	expected := "1234:5678:1-2"
	if got := device.FullID(); got != expected {
		t.Errorf("FullID() = %q, want %q", got, expected)
	}
}

func TestDevice_ClassName(t *testing.T) {
	tests := []struct {
		class    DeviceClass
		expected string
	}{
		{ClassMassStorage, "Mass Storage"},
		{ClassHID, "Human Interface Device"},
		{DeviceClass(0x99), "Unknown (0x99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			device := &Device{DeviceClass: tt.class}
			if got := device.ClassName(); got != tt.expected {
				t.Errorf("ClassName() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestDefaultPolicy(t *testing.T) {
	policy := DefaultPolicy()

	if policy.Name != "default" {
		t.Errorf("Name = %q, want %q", policy.Name, "default")
	}
	if !policy.AllowHubs {
		t.Error("AllowHubs should be true")
	}
	if !policy.AllowHID {
		t.Error("AllowHID should be true")
	}
	if policy.AllowStorage {
		t.Error("AllowStorage should be false")
	}
	if policy.DefaultAction != PolicyBlock {
		t.Errorf("DefaultAction = %q, want %q", policy.DefaultAction, PolicyBlock)
	}
	if len(policy.BlockedClasses) == 0 {
		t.Error("BlockedClasses should not be empty")
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.SysfsPath != "/sys/bus/usb/devices" {
		t.Errorf("SysfsPath = %q, want %q", config.SysfsPath, "/sys/bus/usb/devices")
	}
	if config.PollInterval != 100*time.Millisecond {
		t.Errorf("PollInterval = %v, want %v", config.PollInterval, 100*time.Millisecond)
	}
	if !config.UseNetlink {
		t.Error("UseNetlink should be true")
	}
	if config.Policy == nil {
		t.Error("Policy should not be nil")
	}
}

func TestThreatLevel(t *testing.T) {
	if ThreatNone != 0 {
		t.Errorf("ThreatNone = %d, want 0", ThreatNone)
	}
	if ThreatCritical != 4 {
		t.Errorf("ThreatCritical = %d, want 4", ThreatCritical)
	}
}

func TestEventType(t *testing.T) {
	if string(EventAdd) != "add" {
		t.Errorf("EventAdd = %q, want %q", EventAdd, "add")
	}
	if string(EventRemove) != "remove" {
		t.Errorf("EventRemove = %q, want %q", EventRemove, "remove")
	}
	if string(EventBlock) != "block" {
		t.Errorf("EventBlock = %q, want %q", EventBlock, "block")
	}
}

func TestPolicyAction(t *testing.T) {
	if string(PolicyAllow) != "allow" {
		t.Errorf("PolicyAllow = %q, want %q", PolicyAllow, "allow")
	}
	if string(PolicyBlock) != "block" {
		t.Errorf("PolicyBlock = %q, want %q", PolicyBlock, "block")
	}
	if string(PolicyAudit) != "audit" {
		t.Errorf("PolicyAudit = %q, want %q", PolicyAudit, "audit")
	}
}

// createMockSysfs creates a mock sysfs structure for testing
func createMockSysfs(t *testing.T) string {
	tmpDir, err := os.MkdirTemp("", "usb-test-sysfs-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	// Create mock USB device directory
	device1 := filepath.Join(tmpDir, "1-1")
	if err := os.MkdirAll(device1, 0755); err != nil {
		t.Fatalf("failed to create device dir: %v", err)
	}

	// Write mock sysfs files
	writeFile(t, device1, "idVendor", "046d")  // Logitech
	writeFile(t, device1, "idProduct", "c52b") // Unifying Receiver
	writeFile(t, device1, "bDeviceClass", "00")
	writeFile(t, device1, "busnum", "1")
	writeFile(t, device1, "devnum", "2")
	writeFile(t, device1, "manufacturer", "Logitech")
	writeFile(t, device1, "product", "USB Receiver")
	writeFile(t, device1, "serial", "1234567890")
	writeFile(t, device1, "speed", "12")
	writeFile(t, device1, "authorized", "1")

	// Create a hub device
	hub := filepath.Join(tmpDir, "usb1")
	if err := os.MkdirAll(hub, 0755); err != nil {
		t.Fatalf("failed to create hub dir: %v", err)
	}

	writeFile(t, hub, "idVendor", "1d6b")  // Linux Foundation
	writeFile(t, hub, "idProduct", "0002") // Root Hub
	writeFile(t, hub, "bDeviceClass", "09") // Hub
	writeFile(t, hub, "busnum", "1")
	writeFile(t, hub, "devnum", "1")
	writeFile(t, hub, "manufacturer", "Linux")
	writeFile(t, hub, "product", "xHCI Host Controller")
	writeFile(t, hub, "authorized", "1")

	// Create a mass storage device
	storage := filepath.Join(tmpDir, "2-1")
	if err := os.MkdirAll(storage, 0755); err != nil {
		t.Fatalf("failed to create storage dir: %v", err)
	}

	writeFile(t, storage, "idVendor", "0781")  // SanDisk
	writeFile(t, storage, "idProduct", "5567") // USB Flash Drive
	writeFile(t, storage, "bDeviceClass", "08") // Mass Storage
	writeFile(t, storage, "busnum", "2")
	writeFile(t, storage, "devnum", "1")
	writeFile(t, storage, "manufacturer", "SanDisk")
	writeFile(t, storage, "product", "Cruzer Blade")
	writeFile(t, storage, "serial", "ABCD1234")
	writeFile(t, storage, "authorized", "1")

	return tmpDir
}

func writeFile(t *testing.T, dir, name, content string) {
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

func TestNewMonitor_WithMockSysfs(t *testing.T) {
	sysfsPath := createMockSysfs(t)
	defer os.RemoveAll(sysfsPath)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		SysfsPath:    sysfsPath,
		PollInterval: 100 * time.Millisecond,
		UseNetlink:   false, // Disable netlink for testing
		Policy:       DefaultPolicy(),
	}

	monitor, err := NewMonitor(config, logger)
	if err != nil {
		t.Fatalf("NewMonitor() error = %v", err)
	}
	defer monitor.Stop()

	// Should have found devices
	devices := monitor.GetDevices()
	if len(devices) == 0 {
		t.Error("expected to find devices")
	}

	t.Logf("Found %d devices", len(devices))
	for _, d := range devices {
		t.Logf("  - %s: %s (%s)", d.DeviceID(), d.Product, d.ClassName())
	}
}

func TestMonitor_GetDevice(t *testing.T) {
	sysfsPath := createMockSysfs(t)
	defer os.RemoveAll(sysfsPath)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		SysfsPath:    sysfsPath,
		PollInterval: 100 * time.Millisecond,
		UseNetlink:   false,
		Policy:       DefaultPolicy(),
	}

	monitor, err := NewMonitor(config, logger)
	if err != nil {
		t.Fatalf("NewMonitor() error = %v", err)
	}
	defer monitor.Stop()

	// Get specific device
	device1Path := filepath.Join(sysfsPath, "1-1")
	device := monitor.GetDevice(device1Path)
	if device == nil {
		t.Fatal("expected to find device 1-1")
	}

	if device.VendorID != 0x046d {
		t.Errorf("VendorID = %04x, want %04x", device.VendorID, 0x046d)
	}
	if device.ProductID != 0xc52b {
		t.Errorf("ProductID = %04x, want %04x", device.ProductID, 0xc52b)
	}
	if device.Manufacturer != "Logitech" {
		t.Errorf("Manufacturer = %q, want %q", device.Manufacturer, "Logitech")
	}
}

func TestMonitor_DevicesByClass(t *testing.T) {
	sysfsPath := createMockSysfs(t)
	defer os.RemoveAll(sysfsPath)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		SysfsPath:    sysfsPath,
		PollInterval: 100 * time.Millisecond,
		UseNetlink:   false,
		Policy:       DefaultPolicy(),
	}

	monitor, err := NewMonitor(config, logger)
	if err != nil {
		t.Fatalf("NewMonitor() error = %v", err)
	}
	defer monitor.Stop()

	// Should find the hub
	hubs := monitor.DevicesByClass(ClassHub)
	if len(hubs) != 1 {
		t.Errorf("found %d hubs, want 1", len(hubs))
	}

	// Should find the storage device
	storage := monitor.StorageDevices()
	if len(storage) != 1 {
		t.Errorf("found %d storage devices, want 1", len(storage))
	}
}

func TestMonitor_DeviceCount(t *testing.T) {
	sysfsPath := createMockSysfs(t)
	defer os.RemoveAll(sysfsPath)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		SysfsPath:    sysfsPath,
		PollInterval: 100 * time.Millisecond,
		UseNetlink:   false,
		Policy:       DefaultPolicy(),
	}

	monitor, err := NewMonitor(config, logger)
	if err != nil {
		t.Fatalf("NewMonitor() error = %v", err)
	}
	defer monitor.Stop()

	count := monitor.DeviceCount()
	if count != 3 {
		t.Errorf("DeviceCount() = %d, want 3", count)
	}
}

func TestMonitor_GetDeviceByVendorProduct(t *testing.T) {
	sysfsPath := createMockSysfs(t)
	defer os.RemoveAll(sysfsPath)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		SysfsPath:    sysfsPath,
		PollInterval: 100 * time.Millisecond,
		UseNetlink:   false,
		Policy:       DefaultPolicy(),
	}

	monitor, err := NewMonitor(config, logger)
	if err != nil {
		t.Fatalf("NewMonitor() error = %v", err)
	}
	defer monitor.Stop()

	// Find Logitech device
	device := monitor.GetDeviceByVendorProduct(0x046d, 0xc52b)
	if device == nil {
		t.Fatal("expected to find Logitech device")
	}
	if device.Manufacturer != "Logitech" {
		t.Errorf("Manufacturer = %q, want %q", device.Manufacturer, "Logitech")
	}

	// Non-existent device
	device = monitor.GetDeviceByVendorProduct(0x0000, 0x0000)
	if device != nil {
		t.Error("expected nil for non-existent device")
	}
}

func TestMonitor_CheckPolicy(t *testing.T) {
	sysfsPath := createMockSysfs(t)
	defer os.RemoveAll(sysfsPath)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	policy := &Policy{
		Name:          "test",
		AllowHubs:     true,
		AllowHID:      true,
		AllowStorage:  false,
		DefaultAction: PolicyBlock,
		BlockedClasses: []DeviceClass{
			ClassMassStorage,
		},
	}

	config := &Config{
		SysfsPath:    sysfsPath,
		PollInterval: 100 * time.Millisecond,
		UseNetlink:   false,
		Policy:       policy,
	}

	monitor, err := NewMonitor(config, logger)
	if err != nil {
		t.Fatalf("NewMonitor() error = %v", err)
	}
	defer monitor.Stop()

	// Hub should be allowed
	hubDevice := &Device{DeviceClass: ClassHub}
	action, _ := monitor.checkPolicy(hubDevice)
	if action != PolicyAllow {
		t.Errorf("hub policy = %v, want %v", action, PolicyAllow)
	}

	// Storage should be blocked
	storageDevice := &Device{DeviceClass: ClassMassStorage}
	action, reason := monitor.checkPolicy(storageDevice)
	if action != PolicyBlock {
		t.Errorf("storage policy = %v, want %v", action, PolicyBlock)
	}
	if reason == "" {
		t.Error("expected reason for blocking")
	}
}

func TestMonitor_SetPolicy(t *testing.T) {
	sysfsPath := createMockSysfs(t)
	defer os.RemoveAll(sysfsPath)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		SysfsPath:    sysfsPath,
		PollInterval: 100 * time.Millisecond,
		UseNetlink:   false,
		Policy:       DefaultPolicy(),
	}

	monitor, err := NewMonitor(config, logger)
	if err != nil {
		t.Fatalf("NewMonitor() error = %v", err)
	}
	defer monitor.Stop()

	// Update policy
	newPolicy := &Policy{
		Name:          "strict",
		AllowHubs:     true,
		AllowHID:      false,
		AllowStorage:  false,
		DefaultAction: PolicyBlock,
	}

	monitor.SetPolicy(newPolicy)

	// Now HID should be blocked
	hidDevice := &Device{DeviceClass: ClassHID}
	action, _ := monitor.checkPolicy(hidDevice)
	if action != PolicyBlock {
		t.Errorf("HID policy after update = %v, want %v", action, PolicyBlock)
	}
}

func TestMonitor_SetOnEvent(t *testing.T) {
	sysfsPath := createMockSysfs(t)
	defer os.RemoveAll(sysfsPath)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		SysfsPath:    sysfsPath,
		PollInterval: 100 * time.Millisecond,
		UseNetlink:   false,
		Policy:       DefaultPolicy(),
	}

	monitor, err := NewMonitor(config, logger)
	if err != nil {
		t.Fatalf("NewMonitor() error = %v", err)
	}
	defer monitor.Stop()

	eventReceived := make(chan *Event, 1)
	monitor.SetOnEvent(func(e *Event) {
		select {
		case eventReceived <- e:
		default:
		}
	})

	// Emit a test event
	testEvent := &Event{
		Type:      EventAdd,
		Device:    &Device{VendorID: 0x1234, ProductID: 0x5678},
		Timestamp: time.Now(),
	}

	monitor.emitEvent(testEvent)

	select {
	case event := <-eventReceived:
		if event.Type != EventAdd {
			t.Errorf("event type = %v, want %v", event.Type, EventAdd)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for event")
	}
}

func TestMonitor_StartStop(t *testing.T) {
	sysfsPath := createMockSysfs(t)
	defer os.RemoveAll(sysfsPath)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		SysfsPath:    sysfsPath,
		PollInterval: 50 * time.Millisecond,
		UseNetlink:   false,
		Policy:       DefaultPolicy(),
	}

	monitor, err := NewMonitor(config, logger)
	if err != nil {
		t.Fatalf("NewMonitor() error = %v", err)
	}

	err = monitor.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Let it run briefly
	time.Sleep(100 * time.Millisecond)

	monitor.Stop()
}

func TestMonitor_DetectNewDevice(t *testing.T) {
	sysfsPath := createMockSysfs(t)
	defer os.RemoveAll(sysfsPath)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		SysfsPath:    sysfsPath,
		PollInterval: 50 * time.Millisecond,
		UseNetlink:   false,
		Policy:       DefaultPolicy(),
	}

	monitor, err := NewMonitor(config, logger)
	if err != nil {
		t.Fatalf("NewMonitor() error = %v", err)
	}
	defer monitor.Stop()

	initialCount := monitor.DeviceCount()

	// Start monitoring
	err = monitor.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Add a new device
	newDevice := filepath.Join(sysfsPath, "3-1")
	if err := os.MkdirAll(newDevice, 0755); err != nil {
		t.Fatalf("failed to create device dir: %v", err)
	}

	writeFile(t, newDevice, "idVendor", "dead")
	writeFile(t, newDevice, "idProduct", "beef")
	writeFile(t, newDevice, "bDeviceClass", "00")
	writeFile(t, newDevice, "busnum", "3")
	writeFile(t, newDevice, "devnum", "1")
	writeFile(t, newDevice, "manufacturer", "Test")
	writeFile(t, newDevice, "product", "New Device")
	writeFile(t, newDevice, "authorized", "1")

	// Wait for poll to detect it
	time.Sleep(200 * time.Millisecond)

	newCount := monitor.DeviceCount()
	if newCount != initialCount+1 {
		t.Errorf("DeviceCount() = %d, want %d", newCount, initialCount+1)
	}
}

func TestMonitor_DetectRemovedDevice(t *testing.T) {
	sysfsPath := createMockSysfs(t)
	defer os.RemoveAll(sysfsPath)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		SysfsPath:    sysfsPath,
		PollInterval: 50 * time.Millisecond,
		UseNetlink:   false,
		Policy:       DefaultPolicy(),
	}

	monitor, err := NewMonitor(config, logger)
	if err != nil {
		t.Fatalf("NewMonitor() error = %v", err)
	}
	defer monitor.Stop()

	initialCount := monitor.DeviceCount()

	// Start monitoring
	err = monitor.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Remove a device
	device1Path := filepath.Join(sysfsPath, "1-1")
	if err := os.RemoveAll(device1Path); err != nil {
		t.Fatalf("failed to remove device: %v", err)
	}

	// Wait for poll to detect it
	time.Sleep(200 * time.Millisecond)

	newCount := monitor.DeviceCount()
	if newCount != initialCount-1 {
		t.Errorf("DeviceCount() = %d, want %d", newCount, initialCount-1)
	}
}

func TestMonitor_AssessThreat(t *testing.T) {
	sysfsPath := createMockSysfs(t)
	defer os.RemoveAll(sysfsPath)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		SysfsPath:    sysfsPath,
		PollInterval: 100 * time.Millisecond,
		UseNetlink:   false,
		Policy:       DefaultPolicy(),
	}

	monitor, err := NewMonitor(config, logger)
	if err != nil {
		t.Fatalf("NewMonitor() error = %v", err)
	}
	defer monitor.Stop()

	tests := []struct {
		class    DeviceClass
		expected ThreatLevel
	}{
		{ClassMassStorage, ThreatHigh},
		{ClassWireless, ThreatHigh},
		{ClassHID, ThreatMedium},
		{ClassVendorSpecific, ThreatMedium},
		{ClassHub, ThreatLow},
		{ClassAudio, ThreatLow},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Class_%d", tt.class), func(t *testing.T) {
			device := &Device{DeviceClass: tt.class}
			threat := monitor.assessThreat(device)
			if threat != tt.expected {
				t.Errorf("assessThreat(class=%d) = %d, want %d", tt.class, threat, tt.expected)
			}
		})
	}
}

func TestNewMonitor_MissingSysfs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		SysfsPath:    "/nonexistent/path/usb",
		PollInterval: 100 * time.Millisecond,
		UseNetlink:   false,
		Policy:       DefaultPolicy(),
	}

	_, err := NewMonitor(config, logger)
	if err == nil {
		t.Error("expected error for missing sysfs path")
	}
}

func BenchmarkDeviceEnumeration(b *testing.B) {
	sysfsPath := createMockSysfsBench(b)
	defer os.RemoveAll(sysfsPath)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	config := &Config{
		SysfsPath:    sysfsPath,
		PollInterval: 100 * time.Millisecond,
		UseNetlink:   false,
		Policy:       DefaultPolicy(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		monitor, _ := NewMonitor(config, logger)
		monitor.Stop()
	}
}

func createMockSysfsBench(b *testing.B) string {
	tmpDir, err := os.MkdirTemp("", "usb-bench-sysfs-*")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}

	// Create 10 mock devices
	for i := 0; i < 10; i++ {
		device := filepath.Join(tmpDir, fmt.Sprintf("%d-%d", i/5+1, i%5+1))
		if err := os.MkdirAll(device, 0755); err != nil {
			b.Fatalf("failed to create device dir: %v", err)
		}

		os.WriteFile(filepath.Join(device, "idVendor"), []byte(fmt.Sprintf("%04x", i*0x100)), 0644)
		os.WriteFile(filepath.Join(device, "idProduct"), []byte(fmt.Sprintf("%04x", i*0x10)), 0644)
		os.WriteFile(filepath.Join(device, "bDeviceClass"), []byte("00"), 0644)
		os.WriteFile(filepath.Join(device, "busnum"), []byte(fmt.Sprintf("%d", i/5+1)), 0644)
		os.WriteFile(filepath.Join(device, "devnum"), []byte(fmt.Sprintf("%d", i%5+1)), 0644)
		os.WriteFile(filepath.Join(device, "authorized"), []byte("1"), 0644)
	}

	return tmpDir
}
