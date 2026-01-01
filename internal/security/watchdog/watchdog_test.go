package watchdog

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Interval != 2*time.Second {
		t.Errorf("Interval = %v, want %v", config.Interval, 2*time.Second)
	}
	if config.HealthCheckInterval != 5*time.Second {
		t.Errorf("HealthCheckInterval = %v, want %v", config.HealthCheckInterval, 5*time.Second)
	}
	if config.HealthCheckTimeout != 3*time.Second {
		t.Errorf("HealthCheckTimeout = %v, want %v", config.HealthCheckTimeout, 3*time.Second)
	}
	if !config.FailOnUnhealthy {
		t.Error("FailOnUnhealthy should be true by default")
	}
}

func TestDefaultConfig_WithEnv(t *testing.T) {
	// Set environment variables
	os.Setenv("NOTIFY_SOCKET", "/run/test.sock")
	os.Setenv("WATCHDOG_USEC", "10000000")
	defer func() {
		os.Unsetenv("NOTIFY_SOCKET")
		os.Unsetenv("WATCHDOG_USEC")
	}()

	config := DefaultConfig()

	if config.NotifySocket != "/run/test.sock" {
		t.Errorf("NotifySocket = %q, want %q", config.NotifySocket, "/run/test.sock")
	}
	if config.WatchdogUSec != 10000000 {
		t.Errorf("WatchdogUSec = %d, want %d", config.WatchdogUSec, 10000000)
	}
	// Interval should be half of watchdog timeout
	expectedInterval := 5 * time.Second
	if config.Interval != expectedInterval {
		t.Errorf("Interval = %v, want %v", config.Interval, expectedInterval)
	}
}

func TestNew(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		Interval:            1 * time.Second,
		HealthCheckInterval: 2 * time.Second,
		HealthCheckTimeout:  1 * time.Second,
	}

	watchdog, err := New(config, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer watchdog.Stop()

	if watchdog == nil {
		t.Fatal("expected non-nil watchdog")
	}
	if !watchdog.IsHealthy() {
		t.Error("watchdog should be healthy by default")
	}
}

func TestWatchdog_AddHealthChecker(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	watchdog, err := New(nil, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer watchdog.Stop()

	// Add a simple health checker
	watchdog.AddHealthChecker(func(ctx context.Context) *Check {
		return &Check{
			Name:    "test",
			Healthy: true,
			Message: "test passed",
		}
	})

	if len(watchdog.checkers) != 1 {
		t.Errorf("expected 1 checker, got %d", len(watchdog.checkers))
	}
}

func TestWatchdog_RunHealthChecks(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	watchdog, err := New(nil, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer watchdog.Stop()

	// Add passing checker
	watchdog.AddHealthChecker(func(ctx context.Context) *Check {
		return &Check{
			Name:    "pass",
			Healthy: true,
			Message: "ok",
		}
	})

	health := watchdog.runHealthChecks()

	if !health.Healthy {
		t.Error("expected healthy result")
	}
	if len(health.Checks) != 1 {
		t.Errorf("expected 1 check, got %d", len(health.Checks))
	}
}

func TestWatchdog_RunHealthChecks_Failure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	watchdog, err := New(nil, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer watchdog.Stop()

	// Add failing checker
	watchdog.AddHealthChecker(func(ctx context.Context) *Check {
		return &Check{
			Name:    "fail",
			Healthy: false,
			Message: "something is wrong",
		}
	})

	health := watchdog.runHealthChecks()

	if health.Healthy {
		t.Error("expected unhealthy result")
	}
	if health.Message != "something is wrong" {
		t.Errorf("Message = %q, want %q", health.Message, "something is wrong")
	}
}

func TestWatchdog_StartStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		Interval:            50 * time.Millisecond,
		HealthCheckInterval: 100 * time.Millisecond,
		HealthCheckTimeout:  50 * time.Millisecond,
	}

	watchdog, err := New(config, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = watchdog.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Double start should fail
	err = watchdog.Start()
	if err == nil {
		t.Error("expected error on double start")
	}

	// Let it run briefly
	time.Sleep(200 * time.Millisecond)

	err = watchdog.Stop()
	if err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestWatchdog_SetOnStateChange(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		Interval:            50 * time.Millisecond,
		HealthCheckInterval: 50 * time.Millisecond,
		HealthCheckTimeout:  25 * time.Millisecond,
	}

	watchdog, err := New(config, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer watchdog.Stop()

	callbackCalled := make(chan bool, 1)
	watchdog.SetOnStateChange(func(health *Health) {
		select {
		case callbackCalled <- true:
		default:
		}
	})

	// Add a checker
	watchdog.AddHealthChecker(func(ctx context.Context) *Check {
		return &Check{Name: "test", Healthy: true}
	})

	watchdog.Start()

	select {
	case <-callbackCalled:
		// Success
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for callback")
	}
}

func TestWatchdog_IsEnabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Without notify socket
	watchdog, _ := New(nil, logger)
	defer watchdog.Stop()

	if watchdog.IsEnabled() {
		t.Error("watchdog should not be enabled without notify socket")
	}
}

func TestWatchdog_GetHealth(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	watchdog, err := New(nil, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer watchdog.Stop()

	// Before any health check
	health := watchdog.GetHealth()
	if health != nil {
		t.Error("expected nil health before checks")
	}

	// Run health checks
	watchdog.AddHealthChecker(func(ctx context.Context) *Check {
		return &Check{Name: "test", Healthy: true, Message: "ok"}
	})

	// runHealthChecks returns the result but doesn't store it
	// GetHealth only returns stored results from healthCheckLoop
	result := watchdog.runHealthChecks()
	if result == nil {
		t.Fatal("expected non-nil health from runHealthChecks")
	}
	if !result.Healthy {
		t.Error("expected healthy status")
	}
	if len(result.Checks) != 1 {
		t.Errorf("expected 1 check, got %d", len(result.Checks))
	}
}

func TestStateConstants(t *testing.T) {
	if string(StateReady) != "READY=1" {
		t.Errorf("StateReady = %q", StateReady)
	}
	if string(StateReloading) != "RELOADING=1" {
		t.Errorf("StateReloading = %q", StateReloading)
	}
	if string(StateStopping) != "STOPPING=1" {
		t.Errorf("StateStopping = %q", StateStopping)
	}
	if string(StateWatchdog) != "WATCHDOG=1" {
		t.Errorf("StateWatchdog = %q", StateWatchdog)
	}
}

func TestMemoryChecker(t *testing.T) {
	checker := MemoryChecker(0.99) // Very high threshold
	check := checker(context.Background())

	if check == nil {
		t.Fatal("expected non-nil check")
	}
	if check.Name != "memory" {
		t.Errorf("Name = %q, want %q", check.Name, "memory")
	}
	// Should be healthy with 99% threshold
	if !check.Healthy {
		t.Errorf("expected healthy, got: %s", check.Message)
	}
	if check.Latency == 0 {
		t.Error("expected non-zero latency")
	}
}

func TestMemoryChecker_LowThreshold(t *testing.T) {
	checker := MemoryChecker(0.01) // Very low threshold - should fail
	check := checker(context.Background())

	if check == nil {
		t.Fatal("expected non-nil check")
	}
	// System likely uses more than 1% memory
	// This is environment-dependent
	t.Logf("Memory check result: healthy=%v, message=%s", check.Healthy, check.Message)
}

func TestDiskChecker(t *testing.T) {
	checker := DiskChecker("/", 0.99) // Very high threshold
	check := checker(context.Background())

	if check == nil {
		t.Fatal("expected non-nil check")
	}
	if check.Name != "disk:/" {
		t.Errorf("Name = %q, want %q", check.Name, "disk:/")
	}
	// Should be healthy with 99% threshold
	if !check.Healthy {
		t.Errorf("expected healthy, got: %s", check.Message)
	}
}

func TestDiskChecker_InvalidPath(t *testing.T) {
	checker := DiskChecker("/nonexistent/path/that/should/not/exist", 0.5)
	check := checker(context.Background())

	if check == nil {
		t.Fatal("expected non-nil check")
	}
	if check.Healthy {
		t.Error("expected unhealthy for invalid path")
	}
}

func TestTCPChecker_Success(t *testing.T) {
	// This test might fail if nothing is listening on localhost
	// We'll skip if it fails to avoid flakiness
	checker := TCPChecker("localhost", "127.0.0.1:80", 100*time.Millisecond)
	check := checker(context.Background())

	if check == nil {
		t.Fatal("expected non-nil check")
	}
	if check.Name != "tcp:localhost" {
		t.Errorf("Name = %q, want %q", check.Name, "tcp:localhost")
	}
	// Result depends on whether something is listening
	t.Logf("TCP check result: healthy=%v, message=%s", check.Healthy, check.Message)
}

func TestTCPChecker_Failure(t *testing.T) {
	// Use a port that's very unlikely to be in use
	checker := TCPChecker("closed", "127.0.0.1:59999", 100*time.Millisecond)
	check := checker(context.Background())

	if check == nil {
		t.Fatal("expected non-nil check")
	}
	if check.Healthy {
		t.Error("expected unhealthy for closed port")
	}
}

func TestFileChecker_Success(t *testing.T) {
	// Create a temp file
	tmpFile, err := os.CreateTemp("", "watchdog-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpFile.WriteString("test content")
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	checker := FileChecker(tmpFile.Name())
	check := checker(context.Background())

	if check == nil {
		t.Fatal("expected non-nil check")
	}
	if !check.Healthy {
		t.Errorf("expected healthy, got: %s", check.Message)
	}
}

func TestFileChecker_Failure(t *testing.T) {
	checker := FileChecker("/nonexistent/file/that/should/not/exist")
	check := checker(context.Background())

	if check == nil {
		t.Fatal("expected non-nil check")
	}
	if check.Healthy {
		t.Error("expected unhealthy for missing file")
	}
}

func TestSignalHandler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	handler := NewSignalHandler(nil, logger)

	handler.SetOnShutdown(func() {
		// Would be called on SIGTERM/SIGINT
	})

	handler.SetOnReload(func() {
		// Would be called on SIGHUP
	})

	handler.Start()
	defer handler.Stop()

	// Just verify it starts without error
	time.Sleep(50 * time.Millisecond)
}

func TestProcessProtector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	protector := NewProcessProtector(logger)

	if protector == nil {
		t.Fatal("expected non-nil protector")
	}
}

func TestProcessProtector_SetOOMScore_Invalid(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	protector := NewProcessProtector(logger)

	err := protector.SetOOMScore(-1001)
	if err == nil {
		t.Error("expected error for invalid OOM score")
	}

	err = protector.SetOOMScore(1001)
	if err == nil {
		t.Error("expected error for invalid OOM score")
	}
}

func TestProcessProtector_SetSchedulerPriority_Invalid(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	protector := NewProcessProtector(logger)

	err := protector.SetSchedulerPriority(-21)
	if err == nil {
		t.Error("expected error for invalid nice value")
	}

	err = protector.SetSchedulerPriority(20)
	if err == nil {
		t.Error("expected error for invalid nice value")
	}
}

func TestHealth(t *testing.T) {
	health := &Health{
		Healthy:   true,
		Message:   "all good",
		Timestamp: time.Now(),
		Checks: []Check{
			{Name: "test1", Healthy: true, Message: "ok", Latency: time.Millisecond},
			{Name: "test2", Healthy: true, Message: "ok", Latency: 2 * time.Millisecond},
		},
	}

	if !health.Healthy {
		t.Error("expected healthy")
	}
	if len(health.Checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(health.Checks))
	}
	if health.Checks[0].Name != "test1" {
		t.Errorf("first check name = %q", health.Checks[0].Name)
	}
}

func TestCheck(t *testing.T) {
	check := &Check{
		Name:    "test",
		Healthy: false,
		Message: "test failed",
		Latency: 5 * time.Millisecond,
	}

	if check.Healthy {
		t.Error("expected unhealthy")
	}
	if check.Latency != 5*time.Millisecond {
		t.Errorf("Latency = %v", check.Latency)
	}
}

func BenchmarkHealthCheck(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	watchdog, _ := New(nil, logger)
	defer watchdog.Stop()

	watchdog.AddHealthChecker(func(ctx context.Context) *Check {
		return &Check{Name: "bench", Healthy: true}
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		watchdog.runHealthChecks()
	}
}

func BenchmarkMemoryChecker(b *testing.B) {
	checker := MemoryChecker(0.9)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker(ctx)
	}
}

func BenchmarkDiskChecker(b *testing.B) {
	checker := DiskChecker("/", 0.9)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker(ctx)
	}
}
