// Package watchdog provides systemd watchdog integration and process protection.
// This ensures the process is automatically restarted if it hangs or is killed.
package watchdog

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// State represents the service state for systemd notification.
type State string

const (
	StateReady     State = "READY=1"
	StateReloading State = "RELOADING=1"
	StateStopping  State = "STOPPING=1"
	StateWatchdog  State = "WATCHDOG=1"
	StateStatus    State = "STATUS="
	StateErrno     State = "ERRNO="
	StateBusError  State = "BUSERROR="
	StateMainPID   State = "MAINPID="
)

// Health represents the health check result.
type Health struct {
	Healthy   bool      `json:"healthy"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Checks    []Check   `json:"checks"`
}

// Check represents an individual health check.
type Check struct {
	Name    string        `json:"name"`
	Healthy bool          `json:"healthy"`
	Message string        `json:"message"`
	Latency time.Duration `json:"latency"`
}

// HealthChecker is a function that performs a health check.
type HealthChecker func(ctx context.Context) *Check

// Config holds watchdog configuration.
type Config struct {
	// Interval for watchdog notifications (should be < WatchdogSec/2)
	Interval time.Duration `json:"interval"`

	// HealthCheckInterval for running health checks
	HealthCheckInterval time.Duration `json:"health_check_interval"`

	// HealthCheckTimeout for individual health checks
	HealthCheckTimeout time.Duration `json:"health_check_timeout"`

	// NotifySocket path (usually from NOTIFY_SOCKET env)
	NotifySocket string `json:"notify_socket"`

	// WatchdogUSec from WATCHDOG_USEC env (microseconds)
	WatchdogUSec uint64 `json:"watchdog_usec"`

	// FailOnUnhealthy stops watchdog notifications if unhealthy
	FailOnUnhealthy bool `json:"fail_on_unhealthy"`
}

// DefaultConfig returns the default watchdog configuration.
func DefaultConfig() *Config {
	config := &Config{
		Interval:            2 * time.Second,
		HealthCheckInterval: 5 * time.Second,
		HealthCheckTimeout:  3 * time.Second,
		FailOnUnhealthy:     true,
	}

	// Read from environment
	if socket := os.Getenv("NOTIFY_SOCKET"); socket != "" {
		config.NotifySocket = socket
	}

	if usec := os.Getenv("WATCHDOG_USEC"); usec != "" {
		if val, err := strconv.ParseUint(usec, 10, 64); err == nil {
			config.WatchdogUSec = val
			// Set interval to half the watchdog timeout
			config.Interval = time.Duration(val/2) * time.Microsecond
		}
	}

	return config
}

// Watchdog provides systemd watchdog integration.
type Watchdog struct {
	mu           sync.RWMutex
	config       *Config
	logger       *slog.Logger
	conn         net.Conn
	ctx          context.Context
	cancel       context.CancelFunc
	healthy      atomic.Bool
	lastHealth   *Health
	checkers     []HealthChecker
	onStateChange func(health *Health)
	started      atomic.Bool
}

// New creates a new watchdog instance.
func New(config *Config, logger *slog.Logger) (*Watchdog, error) {
	if config == nil {
		config = DefaultConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	w := &Watchdog{
		config:   config,
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
		checkers: make([]HealthChecker, 0),
	}

	// Connect to systemd notify socket
	if config.NotifySocket != "" {
		conn, err := w.connectNotifySocket()
		if err != nil {
			logger.Warn("failed to connect to notify socket", "error", err)
		} else {
			w.conn = conn
		}
	}

	w.healthy.Store(true)

	return w, nil
}

// connectNotifySocket connects to the systemd notification socket.
func (w *Watchdog) connectNotifySocket() (net.Conn, error) {
	socket := w.config.NotifySocket

	// Handle abstract sockets (start with @)
	if strings.HasPrefix(socket, "@") {
		socket = "\x00" + socket[1:]
	}

	conn, err := net.Dial("unixgram", socket)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to notify socket: %w", err)
	}

	return conn, nil
}

// AddHealthChecker adds a health check function.
func (w *Watchdog) AddHealthChecker(checker HealthChecker) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.checkers = append(w.checkers, checker)
}

// SetOnStateChange sets a callback for health state changes.
func (w *Watchdog) SetOnStateChange(fn func(health *Health)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onStateChange = fn
}

// Start begins the watchdog service.
func (w *Watchdog) Start() error {
	if w.started.Swap(true) {
		return errors.New("watchdog already started")
	}

	w.logger.Info("starting watchdog",
		"interval", w.config.Interval,
		"watchdog_usec", w.config.WatchdogUSec,
		"socket", w.config.NotifySocket,
	)

	// Start watchdog notification loop
	go w.notifyLoop()

	// Start health check loop
	go w.healthCheckLoop()

	// Notify systemd we're ready
	if err := w.NotifyReady(); err != nil {
		w.logger.Warn("failed to notify ready", "error", err)
	}

	return nil
}

// Stop stops the watchdog service.
func (w *Watchdog) Stop() error {
	w.logger.Info("stopping watchdog")

	// Notify systemd we're stopping
	if err := w.notify(StateStopping); err != nil {
		w.logger.Warn("failed to notify stopping", "error", err)
	}

	w.cancel()

	if w.conn != nil {
		w.conn.Close()
	}

	return nil
}

// NotifyReady notifies systemd that the service is ready.
func (w *Watchdog) NotifyReady() error {
	return w.notify(StateReady)
}

// NotifyReloading notifies systemd that the service is reloading.
func (w *Watchdog) NotifyReloading() error {
	return w.notify(StateReloading)
}

// NotifyWatchdog sends a watchdog notification.
func (w *Watchdog) NotifyWatchdog() error {
	return w.notify(StateWatchdog)
}

// NotifyStatus sends a status message to systemd.
func (w *Watchdog) NotifyStatus(status string) error {
	return w.notify(State(string(StateStatus) + status))
}

// notify sends a notification to systemd.
func (w *Watchdog) notify(state State) error {
	if w.conn == nil {
		return nil // Not running under systemd
	}

	_, err := w.conn.Write([]byte(state))
	if err != nil {
		return fmt.Errorf("failed to send notification: %w", err)
	}

	return nil
}

// notifyLoop periodically sends watchdog notifications.
func (w *Watchdog) notifyLoop() {
	ticker := time.NewTicker(w.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			// Only notify if healthy (or not configured to fail)
			if w.healthy.Load() || !w.config.FailOnUnhealthy {
				if err := w.NotifyWatchdog(); err != nil {
					w.logger.Error("watchdog notification failed", "error", err)
				}
			} else {
				w.logger.Warn("skipping watchdog notification due to unhealthy state")
			}
		}
	}
}

// healthCheckLoop periodically runs health checks.
func (w *Watchdog) healthCheckLoop() {
	ticker := time.NewTicker(w.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			health := w.runHealthChecks()

			w.mu.Lock()
			oldHealth := w.lastHealth
			w.lastHealth = health
			callback := w.onStateChange
			w.mu.Unlock()

			// Update healthy status
			w.healthy.Store(health.Healthy)

			// Notify status to systemd
			status := "healthy"
			if !health.Healthy {
				status = "unhealthy: " + health.Message
			}
			w.NotifyStatus(status)

			// Call callback on state change
			if callback != nil {
				if oldHealth == nil || oldHealth.Healthy != health.Healthy {
					callback(health)
				}
			}

			if !health.Healthy {
				w.logger.Warn("health check failed",
					"message", health.Message,
					"checks", len(health.Checks),
				)
			}
		}
	}
}

// runHealthChecks executes all registered health checks.
func (w *Watchdog) runHealthChecks() *Health {
	w.mu.RLock()
	checkers := make([]HealthChecker, len(w.checkers))
	copy(checkers, w.checkers)
	w.mu.RUnlock()

	health := &Health{
		Healthy:   true,
		Timestamp: time.Now(),
		Checks:    make([]Check, 0, len(checkers)),
	}

	for _, checker := range checkers {
		ctx, cancel := context.WithTimeout(w.ctx, w.config.HealthCheckTimeout)
		check := checker(ctx)
		cancel()

		if check != nil {
			health.Checks = append(health.Checks, *check)
			if !check.Healthy {
				health.Healthy = false
				if health.Message == "" {
					health.Message = check.Message
				} else {
					health.Message += "; " + check.Message
				}
			}
		}
	}

	if len(health.Checks) == 0 {
		health.Message = "no health checks registered"
	} else if health.Healthy {
		health.Message = fmt.Sprintf("all %d checks passed", len(health.Checks))
	}

	return health
}

// IsHealthy returns the current health status.
func (w *Watchdog) IsHealthy() bool {
	return w.healthy.Load()
}

// GetHealth returns the last health check result.
func (w *Watchdog) GetHealth() *Health {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.lastHealth
}

// IsEnabled returns true if watchdog is enabled (running under systemd).
func (w *Watchdog) IsEnabled() bool {
	return w.conn != nil
}

// SignalHandler handles OS signals for graceful shutdown.
type SignalHandler struct {
	watchdog    *Watchdog
	logger      *slog.Logger
	onShutdown  func()
	onReload    func()
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewSignalHandler creates a new signal handler.
func NewSignalHandler(watchdog *Watchdog, logger *slog.Logger) *SignalHandler {
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &SignalHandler{
		watchdog: watchdog,
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// SetOnShutdown sets the shutdown callback.
func (s *SignalHandler) SetOnShutdown(fn func()) {
	s.onShutdown = fn
}

// SetOnReload sets the reload callback.
func (s *SignalHandler) SetOnReload(fn func()) {
	s.onReload = fn
}

// Start begins listening for signals.
func (s *SignalHandler) Start() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGUSR1)

	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			case sig := <-sigChan:
				s.handleSignal(sig)
			}
		}
	}()
}

// Stop stops the signal handler.
func (s *SignalHandler) Stop() {
	s.cancel()
}

// handleSignal processes received signals.
func (s *SignalHandler) handleSignal(sig os.Signal) {
	switch sig {
	case syscall.SIGTERM, syscall.SIGINT:
		s.logger.Info("received shutdown signal", "signal", sig)
		if s.watchdog != nil {
			s.watchdog.Stop()
		}
		if s.onShutdown != nil {
			s.onShutdown()
		}

	case syscall.SIGHUP:
		s.logger.Info("received reload signal")
		if s.watchdog != nil {
			s.watchdog.NotifyReloading()
		}
		if s.onReload != nil {
			s.onReload()
		}
		if s.watchdog != nil {
			s.watchdog.NotifyReady()
		}

	case syscall.SIGUSR1:
		// Trigger health check
		s.logger.Info("received health check signal")
		if s.watchdog != nil {
			health := s.watchdog.GetHealth()
			if health != nil {
				s.logger.Info("health status",
					"healthy", health.Healthy,
					"message", health.Message,
				)
			}
		}
	}
}

// ProcessProtector provides additional process protection mechanisms.
type ProcessProtector struct {
	logger *slog.Logger
}

// NewProcessProtector creates a new process protector.
func NewProcessProtector(logger *slog.Logger) *ProcessProtector {
	if logger == nil {
		logger = slog.Default()
	}
	return &ProcessProtector{logger: logger}
}

// SetOOMScore sets the OOM killer score adjustment.
func (p *ProcessProtector) SetOOMScore(score int) error {
	// Valid range is -1000 to 1000
	if score < -1000 || score > 1000 {
		return errors.New("OOM score must be between -1000 and 1000")
	}

	path := fmt.Sprintf("/proc/%d/oom_score_adj", os.Getpid())
	if err := os.WriteFile(path, []byte(strconv.Itoa(score)), 0644); err != nil {
		return fmt.Errorf("failed to set OOM score: %w", err)
	}

	p.logger.Info("set OOM score adjustment", "score", score)
	return nil
}

// SetSchedulerPriority sets the process scheduler priority.
func (p *ProcessProtector) SetSchedulerPriority(nice int) error {
	// Nice values: -20 (highest priority) to 19 (lowest priority)
	if nice < -20 || nice > 19 {
		return errors.New("nice value must be between -20 and 19")
	}

	if err := syscall.Setpriority(syscall.PRIO_PROCESS, 0, nice); err != nil {
		return fmt.Errorf("failed to set priority: %w", err)
	}

	p.logger.Info("set scheduler priority", "nice", nice)
	return nil
}

// LockMemory locks current memory pages to prevent swapping.
func (p *ProcessProtector) LockMemory() error {
	// MCL_CURRENT = 1, MCL_FUTURE = 2
	err := syscall.Mlockall(1 | 2)
	if err != nil {
		return fmt.Errorf("failed to lock memory: %w", err)
	}

	p.logger.Info("locked process memory")
	return nil
}

// SetResourceLimits sets resource limits for the process.
func (p *ProcessProtector) SetResourceLimits() error {
	// Set NOFILE limit (max open files)
	var rLimit syscall.Rlimit
	rLimit.Cur = 65535
	rLimit.Max = 65535
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		p.logger.Warn("failed to set NOFILE limit", "error", err)
	}

	// Set MEMLOCK limit (locked memory)
	rLimit.Cur = 1024 * 1024 * 1024 // 1GB
	rLimit.Max = 1024 * 1024 * 1024
	if err := syscall.Setrlimit(8, &rLimit); err != nil { // RLIMIT_MEMLOCK = 8
		p.logger.Warn("failed to set MEMLOCK limit", "error", err)
	}

	// Set CORE limit (disable core dumps for security)
	rLimit.Cur = 0
	rLimit.Max = 0
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &rLimit); err != nil {
		p.logger.Warn("failed to disable core dumps", "error", err)
	}

	p.logger.Info("set resource limits")
	return nil
}

// DropPrivileges drops privileges after initialization.
func (p *ProcessProtector) DropPrivileges(uid, gid int) error {
	// Set supplementary groups
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("failed to set groups: %w", err)
	}

	// Set GID first
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("failed to set GID: %w", err)
	}

	// Set UID last
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("failed to set UID: %w", err)
	}

	p.logger.Info("dropped privileges", "uid", uid, "gid", gid)
	return nil
}

// Common health checkers

// MemoryChecker checks memory usage.
func MemoryChecker(threshold float64) HealthChecker {
	return func(ctx context.Context) *Check {
		start := time.Now()
		check := &Check{
			Name:    "memory",
			Healthy: true,
		}

		// Read memory stats
		data, err := os.ReadFile("/proc/meminfo")
		if err != nil {
			check.Healthy = false
			check.Message = fmt.Sprintf("failed to read meminfo: %v", err)
			check.Latency = time.Since(start)
			return check
		}

		var memTotal, memAvailable uint64
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal:") {
				fmt.Sscanf(line, "MemTotal: %d kB", &memTotal)
			} else if strings.HasPrefix(line, "MemAvailable:") {
				fmt.Sscanf(line, "MemAvailable: %d kB", &memAvailable)
			}
		}

		if memTotal > 0 {
			usedPercent := float64(memTotal-memAvailable) / float64(memTotal)
			if usedPercent > threshold {
				check.Healthy = false
				check.Message = fmt.Sprintf("memory usage %.1f%% exceeds threshold %.1f%%",
					usedPercent*100, threshold*100)
			} else {
				check.Message = fmt.Sprintf("memory usage %.1f%%", usedPercent*100)
			}
		}

		check.Latency = time.Since(start)
		return check
	}
}

// DiskChecker checks disk space.
func DiskChecker(path string, threshold float64) HealthChecker {
	return func(ctx context.Context) *Check {
		start := time.Now()
		check := &Check{
			Name:    "disk:" + path,
			Healthy: true,
		}

		var stat syscall.Statfs_t
		if err := syscall.Statfs(path, &stat); err != nil {
			check.Healthy = false
			check.Message = fmt.Sprintf("failed to stat %s: %v", path, err)
			check.Latency = time.Since(start)
			return check
		}

		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bfree * uint64(stat.Bsize)
		usedPercent := float64(total-free) / float64(total)

		if usedPercent > threshold {
			check.Healthy = false
			check.Message = fmt.Sprintf("disk usage %.1f%% exceeds threshold %.1f%%",
				usedPercent*100, threshold*100)
		} else {
			check.Message = fmt.Sprintf("disk usage %.1f%%", usedPercent*100)
		}

		check.Latency = time.Since(start)
		return check
	}
}

// TCPChecker checks TCP connectivity.
func TCPChecker(name, address string, timeout time.Duration) HealthChecker {
	return func(ctx context.Context) *Check {
		start := time.Now()
		check := &Check{
			Name:    "tcp:" + name,
			Healthy: true,
		}

		conn, err := net.DialTimeout("tcp", address, timeout)
		if err != nil {
			check.Healthy = false
			check.Message = fmt.Sprintf("failed to connect to %s: %v", address, err)
		} else {
			conn.Close()
			check.Message = fmt.Sprintf("connected to %s", address)
		}

		check.Latency = time.Since(start)
		return check
	}
}

// FileChecker checks if a file exists and is readable.
func FileChecker(path string) HealthChecker {
	return func(ctx context.Context) *Check {
		start := time.Now()
		check := &Check{
			Name:    "file:" + path,
			Healthy: true,
		}

		info, err := os.Stat(path)
		if err != nil {
			check.Healthy = false
			check.Message = fmt.Sprintf("file not accessible: %v", err)
		} else {
			check.Message = fmt.Sprintf("file size %d bytes", info.Size())
		}

		check.Latency = time.Since(start)
		return check
	}
}
