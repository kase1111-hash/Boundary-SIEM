// Package usb provides USB device detection, monitoring, and policy enforcement.
// This implementation properly enumerates USB devices and monitors for changes.
package usb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// DeviceClass represents USB device class.
type DeviceClass uint8

const (
	ClassUnspecified    DeviceClass = 0x00
	ClassAudio          DeviceClass = 0x01
	ClassCDC            DeviceClass = 0x02 // Communications
	ClassHID            DeviceClass = 0x03 // Human Interface Device
	ClassPhysical       DeviceClass = 0x05
	ClassImage          DeviceClass = 0x06
	ClassPrinter        DeviceClass = 0x07
	ClassMassStorage    DeviceClass = 0x08
	ClassHub            DeviceClass = 0x09
	ClassCDCData        DeviceClass = 0x0A
	ClassSmartCard      DeviceClass = 0x0B
	ClassContentSec     DeviceClass = 0x0D
	ClassVideo          DeviceClass = 0x0E
	ClassHealthcare     DeviceClass = 0x0F
	ClassAVDevice       DeviceClass = 0x10
	ClassBillboard      DeviceClass = 0x11
	ClassTypeCBridge    DeviceClass = 0x12
	ClassDiagnostic     DeviceClass = 0xDC
	ClassWireless       DeviceClass = 0xE0
	ClassMisc           DeviceClass = 0xEF
	ClassAppSpecific    DeviceClass = 0xFE
	ClassVendorSpecific DeviceClass = 0xFF
)

// DeviceClassNames maps device class to human-readable name.
var DeviceClassNames = map[DeviceClass]string{
	ClassUnspecified:    "Unspecified",
	ClassAudio:          "Audio",
	ClassCDC:            "Communications",
	ClassHID:            "Human Interface Device",
	ClassPhysical:       "Physical",
	ClassImage:          "Imaging",
	ClassPrinter:        "Printer",
	ClassMassStorage:    "Mass Storage",
	ClassHub:            "Hub",
	ClassCDCData:        "CDC Data",
	ClassSmartCard:      "Smart Card",
	ClassContentSec:     "Content Security",
	ClassVideo:          "Video",
	ClassHealthcare:     "Healthcare",
	ClassAVDevice:       "Audio/Video",
	ClassBillboard:      "Billboard",
	ClassTypeCBridge:    "Type-C Bridge",
	ClassDiagnostic:     "Diagnostic",
	ClassWireless:       "Wireless",
	ClassMisc:           "Miscellaneous",
	ClassAppSpecific:    "Application Specific",
	ClassVendorSpecific: "Vendor Specific",
}

// ThreatLevel represents the security threat level of a device.
type ThreatLevel int

const (
	ThreatNone     ThreatLevel = 0
	ThreatLow      ThreatLevel = 1
	ThreatMedium   ThreatLevel = 2
	ThreatHigh     ThreatLevel = 3
	ThreatCritical ThreatLevel = 4
)

// Device represents a USB device.
type Device struct {
	BusNum       int         `json:"bus_num"`
	DevNum       int         `json:"dev_num"`
	Port         string      `json:"port"`
	VendorID     uint16      `json:"vendor_id"`
	ProductID    uint16      `json:"product_id"`
	DeviceClass  DeviceClass `json:"device_class"`
	Manufacturer string      `json:"manufacturer"`
	Product      string      `json:"product"`
	Serial       string      `json:"serial"`
	Speed        string      `json:"speed"`
	Driver       string      `json:"driver"`
	SysPath      string      `json:"sys_path"`
	Authorized   bool        `json:"authorized"`
	FirstSeen    time.Time   `json:"first_seen"`
	ThreatLevel  ThreatLevel `json:"threat_level"`
}

// DeviceID returns a unique identifier for the device.
func (d *Device) DeviceID() string {
	return fmt.Sprintf("%04x:%04x", d.VendorID, d.ProductID)
}

// FullID returns a fully qualified device identifier.
func (d *Device) FullID() string {
	if d.Serial != "" {
		return fmt.Sprintf("%04x:%04x:%s", d.VendorID, d.ProductID, d.Serial)
	}
	return fmt.Sprintf("%04x:%04x:%d-%d", d.VendorID, d.ProductID, d.BusNum, d.DevNum)
}

// ClassName returns the human-readable class name.
func (d *Device) ClassName() string {
	if name, ok := DeviceClassNames[d.DeviceClass]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%02X)", d.DeviceClass)
}

// Event represents a USB device event.
type Event struct {
	Type      EventType `json:"type"`
	Device    *Device   `json:"device"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Blocked   bool      `json:"blocked"`
	Reason    string    `json:"reason,omitempty"`
}

// EventType represents the type of USB event.
type EventType string

const (
	EventAdd       EventType = "add"
	EventRemove    EventType = "remove"
	EventBind      EventType = "bind"
	EventUnbind    EventType = "unbind"
	EventChange    EventType = "change"
	EventAuthorize EventType = "authorize"
	EventBlock     EventType = "block"
)

// Policy represents a USB device policy.
type Policy struct {
	Name           string        `json:"name"`
	AllowedVendors []uint16      `json:"allowed_vendors,omitempty"`
	AllowedDevices []string      `json:"allowed_devices,omitempty"` // "vendor:product" format
	BlockedClasses []DeviceClass `json:"blocked_classes,omitempty"`
	AllowedClasses []DeviceClass `json:"allowed_classes,omitempty"`
	AllowHubs      bool          `json:"allow_hubs"`
	AllowHID       bool          `json:"allow_hid"`
	AllowStorage   bool          `json:"allow_storage"`
	DefaultAction  PolicyAction  `json:"default_action"`
}

// PolicyAction represents the action to take on a device.
type PolicyAction string

const (
	PolicyAllow PolicyAction = "allow"
	PolicyBlock PolicyAction = "block"
	PolicyAudit PolicyAction = "audit"
)

// DefaultPolicy returns a restrictive default policy.
func DefaultPolicy() *Policy {
	return &Policy{
		Name:          "default",
		AllowHubs:     true,
		AllowHID:      true, // Keyboard/mouse
		AllowStorage:  false,
		DefaultAction: PolicyBlock,
		BlockedClasses: []DeviceClass{
			ClassMassStorage,
			ClassWireless,
			ClassVideo,
		},
	}
}

// Monitor monitors USB devices and enforces policies.
type Monitor struct {
	mu           sync.RWMutex
	devices      map[string]*Device
	policy       *Policy
	logger       *slog.Logger
	events       chan *Event
	ctx          context.Context
	cancel       context.CancelFunc
	sysfsPath    string
	pollInterval time.Duration
	netlink      *netlinkSocket
	onEvent      func(*Event)
}

// Config holds monitor configuration.
type Config struct {
	SysfsPath    string        `json:"sysfs_path"`
	PollInterval time.Duration `json:"poll_interval"`
	UseNetlink   bool          `json:"use_netlink"`
	Policy       *Policy       `json:"policy"`
}

// DefaultConfig returns default monitor configuration.
func DefaultConfig() *Config {
	return &Config{
		SysfsPath:    "/sys/bus/usb/devices",
		PollInterval: 100 * time.Millisecond, // Fast polling to catch race conditions
		UseNetlink:   true,
		Policy:       DefaultPolicy(),
	}
}

// NewMonitor creates a new USB monitor.
func NewMonitor(config *Config, logger *slog.Logger) (*Monitor, error) {
	if config == nil {
		config = DefaultConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := &Monitor{
		devices:      make(map[string]*Device),
		policy:       config.Policy,
		logger:       logger,
		events:       make(chan *Event, 100),
		ctx:          ctx,
		cancel:       cancel,
		sysfsPath:    config.SysfsPath,
		pollInterval: config.PollInterval,
	}

	// Verify sysfs is accessible
	if _, err := os.Stat(m.sysfsPath); os.IsNotExist(err) {
		cancel()
		return nil, fmt.Errorf("USB sysfs not found at %s", m.sysfsPath)
	}

	// Try to set up netlink for real-time events
	if config.UseNetlink {
		nl, err := newNetlinkSocket()
		if err != nil {
			logger.Warn("netlink not available, falling back to polling", "error", err)
		} else {
			m.netlink = nl
		}
	}

	// Initial device enumeration
	if err := m.enumerate(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to enumerate USB devices: %w", err)
	}

	logger.Info("USB monitor initialized",
		"devices", len(m.devices),
		"netlink", m.netlink != nil,
	)

	return m, nil
}

// Start begins monitoring USB devices.
func (m *Monitor) Start() error {
	if m.netlink != nil {
		go m.netlinkLoop()
	}

	// Always run polling as backup
	go m.pollLoop()

	m.logger.Info("USB monitoring started")
	return nil
}

// Stop stops the USB monitor.
func (m *Monitor) Stop() {
	m.cancel()
	if m.netlink != nil {
		m.netlink.close()
	}
	close(m.events)
}

// Events returns the event channel.
func (m *Monitor) Events() <-chan *Event {
	return m.events
}

// SetOnEvent sets an event callback.
func (m *Monitor) SetOnEvent(fn func(*Event)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onEvent = fn
}

// GetDevices returns all currently connected devices.
func (m *Monitor) GetDevices() []*Device {
	m.mu.RLock()
	defer m.mu.RUnlock()

	devices := make([]*Device, 0, len(m.devices))
	for _, dev := range m.devices {
		devices = append(devices, dev)
	}
	return devices
}

// GetDevice returns a specific device by path.
func (m *Monitor) GetDevice(sysPath string) *Device {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.devices[sysPath]
}

// SetPolicy updates the USB policy.
func (m *Monitor) SetPolicy(policy *Policy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policy = policy
	m.logger.Info("USB policy updated", "policy", policy.Name)
}

// enumerate scans sysfs for USB devices.
func (m *Monitor) enumerate() error {
	entries, err := os.ReadDir(m.sysfsPath)
	if err != nil {
		return fmt.Errorf("failed to read sysfs: %w", err)
	}

	// USB device pattern: busnum-port.port... (e.g., "1-1", "1-1.2", "usb1")
	devicePattern := regexp.MustCompile(`^(\d+-[\d.]+|usb\d+)$`)

	for _, entry := range entries {
		name := entry.Name()
		if !devicePattern.MatchString(name) {
			continue
		}

		devPath := filepath.Join(m.sysfsPath, name)
		device, err := m.readDevice(devPath)
		if err != nil {
			m.logger.Debug("failed to read device", "path", devPath, "error", err)
			continue
		}

		m.mu.Lock()
		m.devices[devPath] = device
		m.mu.Unlock()

		m.logger.Debug("found USB device",
			"path", devPath,
			"vendor", fmt.Sprintf("%04x", device.VendorID),
			"product", fmt.Sprintf("%04x", device.ProductID),
			"class", device.ClassName(),
		)
	}

	return nil
}

// readDevice reads device information from sysfs.
func (m *Monitor) readDevice(sysPath string) (*Device, error) {
	device := &Device{
		SysPath:   sysPath,
		FirstSeen: time.Now(),
	}

	// Read vendor ID
	if vid, err := m.readSysfsHex(sysPath, "idVendor"); err == nil {
		device.VendorID = uint16(vid)
	}

	// Read product ID
	if pid, err := m.readSysfsHex(sysPath, "idProduct"); err == nil {
		device.ProductID = uint16(pid)
	}

	// Read device class
	if class, err := m.readSysfsHex(sysPath, "bDeviceClass"); err == nil {
		device.DeviceClass = DeviceClass(class)
	}

	// Read bus and device number
	if busnum, err := m.readSysfsInt(sysPath, "busnum"); err == nil {
		device.BusNum = busnum
	}
	if devnum, err := m.readSysfsInt(sysPath, "devnum"); err == nil {
		device.DevNum = devnum
	}

	// Read strings
	device.Manufacturer = m.readSysfsString(sysPath, "manufacturer")
	device.Product = m.readSysfsString(sysPath, "product")
	device.Serial = m.readSysfsString(sysPath, "serial")
	device.Speed = m.readSysfsString(sysPath, "speed")

	// Read authorization status
	if auth, err := m.readSysfsInt(sysPath, "authorized"); err == nil {
		device.Authorized = auth == 1
	}

	// Determine driver
	driverLink := filepath.Join(sysPath, "driver")
	if target, err := os.Readlink(driverLink); err == nil {
		device.Driver = filepath.Base(target)
	}

	// Calculate threat level
	device.ThreatLevel = m.assessThreat(device)

	return device, nil
}

// readSysfsHex reads a hex value from sysfs.
func (m *Monitor) readSysfsHex(basePath, attr string) (uint64, error) {
	data, err := os.ReadFile(filepath.Join(basePath, attr))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 16, 64)
}

// readSysfsInt reads an integer from sysfs.
func (m *Monitor) readSysfsInt(basePath, attr string) (int, error) {
	data, err := os.ReadFile(filepath.Join(basePath, attr))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// readSysfsString reads a string from sysfs.
func (m *Monitor) readSysfsString(basePath, attr string) string {
	data, err := os.ReadFile(filepath.Join(basePath, attr))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// assessThreat calculates the threat level for a device.
func (m *Monitor) assessThreat(device *Device) ThreatLevel {
	// Mass storage devices are higher risk
	if device.DeviceClass == ClassMassStorage {
		return ThreatHigh
	}

	// Wireless devices are concerning
	if device.DeviceClass == ClassWireless {
		return ThreatHigh
	}

	// HID devices can be used for BadUSB attacks
	if device.DeviceClass == ClassHID {
		// But if we've seen it before and it's a known vendor, lower risk
		return ThreatMedium
	}

	// Vendor-specific class might be anything
	if device.DeviceClass == ClassVendorSpecific {
		return ThreatMedium
	}

	// Hubs are generally safe
	if device.DeviceClass == ClassHub {
		return ThreatLow
	}

	return ThreatLow
}

// pollLoop periodically checks for device changes.
func (m *Monitor) pollLoop() {
	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkForChanges()
		}
	}
}

// checkForChanges compares current devices with known devices.
func (m *Monitor) checkForChanges() {
	entries, err := os.ReadDir(m.sysfsPath)
	if err != nil {
		m.logger.Error("failed to read sysfs", "error", err)
		return
	}

	devicePattern := regexp.MustCompile(`^(\d+-[\d.]+|usb\d+)$`)
	currentDevices := make(map[string]bool)

	for _, entry := range entries {
		name := entry.Name()
		if !devicePattern.MatchString(name) {
			continue
		}

		devPath := filepath.Join(m.sysfsPath, name)
		currentDevices[devPath] = true

		m.mu.RLock()
		_, exists := m.devices[devPath]
		m.mu.RUnlock()

		if !exists {
			// New device
			device, err := m.readDevice(devPath)
			if err != nil {
				continue
			}

			m.mu.Lock()
			m.devices[devPath] = device
			m.mu.Unlock()

			m.handleNewDevice(device)
		}
	}

	// Check for removed devices
	m.mu.Lock()
	for path, device := range m.devices {
		if !currentDevices[path] {
			delete(m.devices, path)
			m.mu.Unlock()
			m.handleRemovedDevice(device)
			m.mu.Lock()
		}
	}
	m.mu.Unlock()
}

// handleNewDevice processes a newly connected device.
func (m *Monitor) handleNewDevice(device *Device) {
	m.logger.Info("USB device connected",
		"path", device.SysPath,
		"vendor", fmt.Sprintf("%04x", device.VendorID),
		"product", fmt.Sprintf("%04x", device.ProductID),
		"class", device.ClassName(),
		"manufacturer", device.Manufacturer,
		"product_name", device.Product,
	)

	// Check policy
	action, reason := m.checkPolicy(device)

	event := &Event{
		Type:      EventAdd,
		Device:    device,
		Timestamp: time.Now(),
		Action:    string(action),
	}

	if action == PolicyBlock {
		event.Blocked = true
		event.Reason = reason
		m.blockDevice(device)
	}

	m.emitEvent(event)
}

// handleRemovedDevice processes a disconnected device.
func (m *Monitor) handleRemovedDevice(device *Device) {
	m.logger.Info("USB device disconnected",
		"path", device.SysPath,
		"vendor", fmt.Sprintf("%04x", device.VendorID),
		"product", fmt.Sprintf("%04x", device.ProductID),
	)

	event := &Event{
		Type:      EventRemove,
		Device:    device,
		Timestamp: time.Now(),
	}

	m.emitEvent(event)
}

// checkPolicy evaluates a device against the current policy.
func (m *Monitor) checkPolicy(device *Device) (PolicyAction, string) {
	m.mu.RLock()
	policy := m.policy
	m.mu.RUnlock()

	if policy == nil {
		return PolicyAllow, ""
	}

	// Check allowed vendors
	for _, vid := range policy.AllowedVendors {
		if device.VendorID == vid {
			return PolicyAllow, ""
		}
	}

	// Check allowed devices
	deviceID := device.DeviceID()
	for _, allowed := range policy.AllowedDevices {
		if deviceID == allowed {
			return PolicyAllow, ""
		}
	}

	// Check blocked classes
	for _, class := range policy.BlockedClasses {
		if device.DeviceClass == class {
			return PolicyBlock, fmt.Sprintf("device class %s is blocked", device.ClassName())
		}
	}

	// Check allowed classes
	if len(policy.AllowedClasses) > 0 {
		allowed := false
		for _, class := range policy.AllowedClasses {
			if device.DeviceClass == class {
				allowed = true
				break
			}
		}
		if !allowed {
			return PolicyBlock, fmt.Sprintf("device class %s is not in allowed list", device.ClassName())
		}
	}

	// Special handling for common device types
	if device.DeviceClass == ClassHub && policy.AllowHubs {
		return PolicyAllow, ""
	}
	if device.DeviceClass == ClassHID && policy.AllowHID {
		return PolicyAllow, ""
	}
	if device.DeviceClass == ClassMassStorage && policy.AllowStorage {
		return PolicyAllow, ""
	}
	if device.DeviceClass == ClassMassStorage && !policy.AllowStorage {
		return PolicyBlock, "mass storage devices are blocked"
	}

	return policy.DefaultAction, "default policy"
}

// blockDevice deauthorizes a USB device.
func (m *Monitor) blockDevice(device *Device) {
	authPath := filepath.Join(device.SysPath, "authorized")
	if err := os.WriteFile(authPath, []byte("0"), 0644); err != nil {
		m.logger.Error("failed to block device",
			"path", device.SysPath,
			"error", err,
		)
		return
	}

	device.Authorized = false
	m.logger.Warn("blocked USB device",
		"path", device.SysPath,
		"vendor", fmt.Sprintf("%04x", device.VendorID),
		"product", fmt.Sprintf("%04x", device.ProductID),
	)
}

// AuthorizeDevice authorizes a previously blocked device.
func (m *Monitor) AuthorizeDevice(sysPath string) error {
	device := m.GetDevice(sysPath)
	if device == nil {
		return errors.New("device not found")
	}

	authPath := filepath.Join(sysPath, "authorized")
	if err := os.WriteFile(authPath, []byte("1"), 0644); err != nil {
		return fmt.Errorf("failed to authorize device: %w", err)
	}

	device.Authorized = true

	event := &Event{
		Type:      EventAuthorize,
		Device:    device,
		Timestamp: time.Now(),
	}
	m.emitEvent(event)

	m.logger.Info("authorized USB device", "path", sysPath)
	return nil
}

// emitEvent sends an event to listeners.
func (m *Monitor) emitEvent(event *Event) {
	// Send to channel (non-blocking)
	select {
	case m.events <- event:
	default:
		m.logger.Warn("event channel full, dropping event")
	}

	// Call callback if set
	m.mu.RLock()
	callback := m.onEvent
	m.mu.RUnlock()

	if callback != nil {
		callback(event)
	}
}

// netlinkSocket wraps a netlink socket for udev events.
type netlinkSocket struct {
	fd int
}

// newNetlinkSocket creates a netlink socket for udev events.
func newNetlinkSocket() (*netlinkSocket, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, 15) // NETLINK_KOBJECT_UEVENT = 15
	if err != nil {
		return nil, fmt.Errorf("failed to create netlink socket: %w", err)
	}

	addr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: 1, // UDEV_MONITOR_KERNEL group
	}

	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to bind netlink socket: %w", err)
	}

	return &netlinkSocket{fd: fd}, nil
}

// close closes the netlink socket.
func (n *netlinkSocket) close() {
	syscall.Close(n.fd)
}

// netlinkLoop reads netlink events.
func (m *Monitor) netlinkLoop() {
	buf := make([]byte, 8192)

	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		// Set read deadline
		tv := syscall.Timeval{Sec: 1, Usec: 0}
		syscall.SetsockoptTimeval(m.netlink.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

		n, err := syscall.Read(m.netlink.fd, buf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			m.logger.Error("netlink read error", "error", err)
			continue
		}

		m.parseNetlinkMessage(buf[:n])
	}
}

// parseNetlinkMessage parses a netlink uevent message.
func (m *Monitor) parseNetlinkMessage(data []byte) {
	if len(data) < 8 {
		return
	}

	// Skip netlink header
	msg := string(data)
	lines := strings.Split(msg, "\x00")

	var action, devpath, subsystem string
	for _, line := range lines {
		if strings.HasPrefix(line, "ACTION=") {
			action = strings.TrimPrefix(line, "ACTION=")
		} else if strings.HasPrefix(line, "DEVPATH=") {
			devpath = strings.TrimPrefix(line, "DEVPATH=")
		} else if strings.HasPrefix(line, "SUBSYSTEM=") {
			subsystem = strings.TrimPrefix(line, "SUBSYSTEM=")
		}
	}

	// Only process USB events
	if subsystem != "usb" {
		return
	}

	m.logger.Debug("netlink USB event",
		"action", action,
		"devpath", devpath,
	)

	// Trigger a check - the poll loop will handle the actual processing
	// This ensures we don't miss anything
	m.checkForChanges()
}

// GetDeviceByVendorProduct finds a device by vendor and product ID.
func (m *Monitor) GetDeviceByVendorProduct(vendorID, productID uint16) *Device {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, device := range m.devices {
		if device.VendorID == vendorID && device.ProductID == productID {
			return device
		}
	}
	return nil
}

// DeviceCount returns the number of connected devices.
func (m *Monitor) DeviceCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.devices)
}

// DevicesByClass returns devices matching a specific class.
func (m *Monitor) DevicesByClass(class DeviceClass) []*Device {
	m.mu.RLock()
	defer m.mu.RUnlock()

	devices := make([]*Device, 0)
	for _, device := range m.devices {
		if device.DeviceClass == class {
			devices = append(devices, device)
		}
	}
	return devices
}

// StorageDevices returns all connected storage devices.
func (m *Monitor) StorageDevices() []*Device {
	return m.DevicesByClass(ClassMassStorage)
}

// HIDDevices returns all connected HID devices (keyboards, mice, etc).
func (m *Monitor) HIDDevices() []*Device {
	return m.DevicesByClass(ClassHID)
}
