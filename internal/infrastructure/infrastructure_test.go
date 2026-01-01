package infrastructure

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"boundary-siem/internal/infrastructure/cloud"
	"boundary-siem/internal/infrastructure/keys"
	"boundary-siem/internal/infrastructure/metrics"
	"boundary-siem/internal/infrastructure/rpc"
)

func TestMetricsCollector(t *testing.T) {
	config := metrics.DefaultCollectorConfig()
	collector := metrics.NewCollector(config)

	// Record some metrics
	collector.RecordMetric(&metrics.Metric{
		Type:      metrics.MetricCPU,
		Name:      "usage",
		Value:     75.5,
		Unit:      "percent",
		Host:      "node-1",
		Timestamp: time.Now(),
		Tags: map[string]string{
			"core": "all",
		},
	})

	collector.RecordMetric(&metrics.Metric{
		Type:      metrics.MetricMemory,
		Name:      "usage",
		Value:     60.0,
		Unit:      "percent",
		Host:      "node-1",
		Timestamp: time.Now(),
	})

	// Check stats
	stats := collector.GetStats()
	if stats["total_data_points"].(int) < 2 {
		t.Errorf("expected at least 2 data points, got %d", stats["total_data_points"])
	}
}

func TestMetricsThresholds(t *testing.T) {
	config := metrics.DefaultCollectorConfig()
	config.Thresholds = []metrics.Threshold{
		{
			Metric:   "cpu.usage",
			Operator: "gte",
			Value:    90.0,
			Severity: "critical",
			Duration: 0, // Immediate
		},
	}

	collector := metrics.NewCollector(config)

	// Track alerts
	var alertCount int32
	collector.AddHandler(func(ctx context.Context, alert *metrics.Alert) error {
		atomic.AddInt32(&alertCount, 1)
		if alert.Metric != "cpu.usage" {
			t.Errorf("expected cpu.usage alert, got %s", alert.Metric)
		}
		return nil
	})

	// Record metric that triggers threshold
	collector.RecordMetric(&metrics.Metric{
		Type:      metrics.MetricCPU,
		Name:      "usage",
		Value:     95.0,
		Host:      "node-1",
		Timestamp: time.Now(),
	})

	// Allow time for async threshold check
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&alertCount) == 0 {
		t.Error("expected threshold alert to be triggered")
	}
}

func TestMetricsNormalization(t *testing.T) {
	config := metrics.DefaultCollectorConfig()
	collector := metrics.NewCollector(config)

	metric := &metrics.Metric{
		Type:      metrics.MetricCPU,
		Name:      "usage",
		Value:     85.0,
		Unit:      "percent",
		Host:      "node-1",
		Timestamp: time.Now(),
	}

	event := collector.NormalizeToEvent(metric, "tenant-1")

	if event.Action != "metric.cpu.usage" {
		t.Errorf("Action = %v, want metric.cpu.usage", event.Action)
	}

	if event.TenantID != "tenant-1" {
		t.Errorf("TenantID = %v, want tenant-1", event.TenantID)
	}
}

func TestCloudAWSParser(t *testing.T) {
	parser := cloud.NewParser(cloud.ProviderAWS)

	// Sample CloudTrail log
	cloudTrailLog := `{
		"eventVersion": "1.08",
		"userIdentity": {
			"type": "IAMUser",
			"principalId": "AIDAEXAMPLE",
			"arn": "arn:aws:iam::123456789012:user/admin",
			"accountId": "123456789012",
			"userName": "admin"
		},
		"eventTime": "2024-01-01T12:00:00Z",
		"eventSource": "ec2.amazonaws.com",
		"eventName": "RunInstances",
		"awsRegion": "us-east-1",
		"sourceIPAddress": "192.168.1.1",
		"userAgent": "aws-cli/2.0",
		"requestID": "abc123",
		"eventID": "event-123",
		"eventType": "AwsApiCall"
	}`

	log, err := parser.Parse(cloudTrailLog)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if log.Provider != cloud.ProviderAWS {
		t.Errorf("Provider = %v, want AWS", log.Provider)
	}

	if log.EventName != "RunInstances" {
		t.Errorf("EventName = %v, want RunInstances", log.EventName)
	}

	if log.SourceIP != "192.168.1.1" {
		t.Errorf("SourceIP = %v, want 192.168.1.1", log.SourceIP)
	}
}

func TestCloudGCPParser(t *testing.T) {
	parser := cloud.NewParser(cloud.ProviderGCP)

	// Sample GCP Audit Log
	gcpLog := `{
		"protoPayload": {
			"@type": "type.googleapis.com/google.cloud.audit.AuditLog",
			"serviceName": "compute.googleapis.com",
			"methodName": "v1.compute.instances.insert",
			"authenticationInfo": {
				"principalEmail": "user@example.com"
			},
			"requestMetadata": {
				"callerIp": "10.0.0.1"
			}
		},
		"insertId": "insert-123",
		"resource": {
			"type": "gce_instance",
			"labels": {
				"project_id": "my-project"
			}
		},
		"timestamp": "2024-01-01T12:00:00Z",
		"severity": "NOTICE",
		"logName": "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity"
	}`

	log, err := parser.Parse(gcpLog)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if log.Provider != cloud.ProviderGCP {
		t.Errorf("Provider = %v, want GCP", log.Provider)
	}

	if log.EventName != "v1.compute.instances.insert" {
		t.Errorf("EventName = %v, want v1.compute.instances.insert", log.EventName)
	}
}

func TestCloudAzureParser(t *testing.T) {
	parser := cloud.NewParser(cloud.ProviderAzure)

	// Sample Azure Activity Log
	azureLog := `{
		"time": "2024-01-01T12:00:00Z",
		"resourceId": "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
		"operationName": "Microsoft.Compute/virtualMachines/write",
		"category": "Administrative",
		"resultType": "Success",
		"callerIpAddress": "10.0.0.2",
		"identity": {
			"claims": {
				"name": "Azure User"
			}
		},
		"properties": {
			"statusCode": "Created"
		},
		"tenantId": "tenant-123",
		"correlationId": "corr-123"
	}`

	log, err := parser.Parse(azureLog)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if log.Provider != cloud.ProviderAzure {
		t.Errorf("Provider = %v, want Azure", log.Provider)
	}

	if log.EventName != "Microsoft.Compute/virtualMachines/write" {
		t.Errorf("EventName = %v, want Microsoft.Compute/virtualMachines/write", log.EventName)
	}

	if log.SourceIP != "10.0.0.2" {
		t.Errorf("SourceIP = %v, want 10.0.0.2", log.SourceIP)
	}
}

func TestCloudSecurityClassification(t *testing.T) {
	parser := cloud.NewParser(cloud.ProviderAWS)

	// High severity event (IAM policy change)
	iamLog := `{
		"eventVersion": "1.08",
		"userIdentity": {
			"type": "IAMUser",
			"accountId": "123456789012"
		},
		"eventTime": "2024-01-01T12:00:00Z",
		"eventSource": "iam.amazonaws.com",
		"eventName": "AttachUserPolicy",
		"awsRegion": "us-east-1",
		"sourceIPAddress": "192.168.1.1",
		"eventID": "event-123"
	}`

	log, err := parser.Parse(iamLog)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if log.Severity < 5 {
		t.Errorf("IAM policy attach should have high severity, got %d", log.Severity)
	}
}

func TestCloudNormalization(t *testing.T) {
	parser := cloud.NewParser(cloud.ProviderAWS)

	cloudTrailLog := `{
		"eventVersion": "1.08",
		"userIdentity": {
			"type": "IAMUser",
			"accountId": "123456789012",
			"userName": "admin"
		},
		"eventTime": "2024-01-01T12:00:00Z",
		"eventSource": "ec2.amazonaws.com",
		"eventName": "TerminateInstances",
		"awsRegion": "us-east-1",
		"sourceIPAddress": "192.168.1.1",
		"eventID": "event-123"
	}`

	log, err := parser.Parse(cloudTrailLog)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	event, err := parser.Normalize(log, "tenant-1")
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if event.TenantID != "tenant-1" {
		t.Errorf("TenantID = %v, want tenant-1", event.TenantID)
	}

	if event.Source.Product != "aws-logs" {
		t.Errorf("Source.Product = %v, want aws-logs", event.Source.Product)
	}
}

func TestRPCMonitor(t *testing.T) {
	config := rpc.DefaultMonitorConfig()
	config.DefaultRateLimit = 100
	monitor := rpc.NewMonitor(config)

	// Test allowed request
	req := &rpc.RPCRequest{
		ID:        "1",
		Type:      rpc.RPCTypeJSONRPC,
		Method:    "eth_blockNumber",
		Params:    json.RawMessage(`[]`),
		SourceIP:  "192.168.1.1",
		Timestamp: time.Now(),
	}

	result := monitor.ProcessRequest(req)
	if !result.Allowed {
		t.Error("eth_blockNumber should be allowed")
	}
}

func TestRPCBlockedMethods(t *testing.T) {
	config := rpc.DefaultMonitorConfig()
	monitor := rpc.NewMonitor(config)

	// Test blocked methods
	blockedMethods := []string{
		"admin_addPeer",
		"debug_traceTransaction",
		"personal_unlockAccount",
		"miner_start",
	}

	for _, method := range blockedMethods {
		req := &rpc.RPCRequest{
			ID:        "1",
			Type:      rpc.RPCTypeJSONRPC,
			Method:    method,
			Params:    json.RawMessage(`[]`),
			SourceIP:  "192.168.1.1",
			Timestamp: time.Now(),
		}

		result := monitor.ProcessRequest(req)
		if result.Allowed {
			t.Errorf("%s should be blocked", method)
		}
		if result.BlockReason == "" {
			t.Errorf("expected block reason for %s", method)
		}
	}
}

func TestRPCRateLimiting(t *testing.T) {
	config := rpc.DefaultMonitorConfig()
	config.DefaultRateLimit = 5 // 5 requests per minute
	monitor := rpc.NewMonitor(config)

	clientIP := "192.168.1.100"

	// Send requests up to the limit
	for i := 0; i < 5; i++ {
		req := &rpc.RPCRequest{
			ID:        "1",
			Type:      rpc.RPCTypeJSONRPC,
			Method:    "eth_getBalance",
			Params:    json.RawMessage(`["0x1234", "latest"]`),
			SourceIP:  clientIP,
			Timestamp: time.Now(),
		}
		result := monitor.ProcessRequest(req)
		if !result.Allowed {
			t.Errorf("request %d should be allowed (within rate limit)", i+1)
		}
	}

	// Next request should be rate limited
	req := &rpc.RPCRequest{
		ID:        "1",
		Type:      rpc.RPCTypeJSONRPC,
		Method:    "eth_getBalance",
		Params:    json.RawMessage(`["0x1234", "latest"]`),
		SourceIP:  clientIP,
		Timestamp: time.Now(),
	}
	result := monitor.ProcessRequest(req)
	if result.Allowed {
		t.Error("request should be rate limited")
	}
}

func TestRPCStats(t *testing.T) {
	config := rpc.DefaultMonitorConfig()
	monitor := rpc.NewMonitor(config)

	// Process a few requests
	for i := 0; i < 5; i++ {
		req := &rpc.RPCRequest{
			ID:        "1",
			Type:      rpc.RPCTypeJSONRPC,
			Method:    "eth_blockNumber",
			SourceIP:  "192.168.1.1",
			Timestamp: time.Now(),
		}
		monitor.ProcessRequest(req)
	}

	stats := monitor.GetStats()
	if stats["total_requests"].(int64) != 5 {
		t.Errorf("expected 5 total requests, got %d", stats["total_requests"])
	}
}

func TestKeyManagementMonitor(t *testing.T) {
	config := keys.DefaultMonitorConfig()
	monitor := keys.NewMonitor(config)

	// Test key operation
	op := &keys.KeyOperation{
		ID:        "op-1",
		Timestamp: time.Now(),
		KeyID:     "validator-key-1",
		KeyType:   keys.KeyTypeValidator,
		Operation: keys.OpSign,
		Source:    "HSM",
		Actor:     "validator-service",
		Success:   true,
		Metadata: map[string]interface{}{
			"message_type": "attestation",
		},
	}

	monitor.ProcessOperation(op)

	// Check stats
	stats := monitor.GetStats()
	if stats["total_operations"].(int64) != 1 {
		t.Errorf("expected 1 operation, got %d", stats["total_operations"])
	}
}

func TestVaultAuditLogParsing(t *testing.T) {
	// Sample Vault audit log
	vaultLog := `{
		"time": "2024-01-01T12:00:00Z",
		"type": "request",
		"auth": {
			"client_token": "token-abc",
			"accessor": "accessor-123",
			"display_name": "validator-service",
			"policies": ["validator-signing"],
			"metadata": {
				"username": "validator-service"
			}
		},
		"request": {
			"id": "req-123",
			"operation": "create",
			"path": "transit/sign/validator-key",
			"data": {
				"input": "base64data"
			},
			"remote_address": "10.0.0.1"
		}
	}`

	vaultAudit, err := keys.ParseVaultAuditLog(vaultLog)
	if err != nil {
		t.Fatalf("ParseVaultAuditLog() error = %v", err)
	}

	op := keys.VaultLogToOperation(vaultAudit)

	if op.Source != "vault" {
		t.Errorf("Source = %v, want vault", op.Source)
	}

	if op.Operation != keys.OpSign {
		t.Errorf("Operation = %v, want sign", op.Operation)
	}

	if op.Actor != "validator-service" {
		t.Errorf("Actor = %v, want validator-service", op.Actor)
	}
}

func TestHSMAuditLogParsing(t *testing.T) {
	// Sample HSM audit log (JSON format)
	hsmLog := `{
		"timestamp": "2024-01-01T12:00:00Z",
		"session_id": "session-123",
		"user_id": "operator01",
		"operation": "C_Sign",
		"key_handle": "0x1234",
		"key_label": "validator-key-1",
		"mechanism": "CKM_ECDSA",
		"result": 0,
		"source_ip": "10.0.0.2"
	}`

	hsmAudit, err := keys.ParseHSMLog(hsmLog)
	if err != nil {
		t.Fatalf("ParseHSMLog() error = %v", err)
	}

	op := keys.HSMLogToOperation(hsmAudit)

	if op.Source != "hsm" {
		t.Errorf("Source = %v, want hsm", op.Source)
	}

	if op.Operation != keys.OpSign {
		t.Errorf("Operation = %v, want sign", op.Operation)
	}

	if !op.Success {
		t.Error("Operation should be successful (result=0)")
	}
}

func TestSigningPatternAnalysis(t *testing.T) {
	config := keys.DefaultMonitorConfig()
	config.EnablePatternAnalysis = true
	config.AnomalyWindow = 5 * time.Minute
	monitor := keys.NewMonitor(config)

	// Record normal signing pattern
	baseTime := time.Now()
	for i := 0; i < 50; i++ {
		op := &keys.KeyOperation{
			ID:        "op-" + string(rune('a'+i%26)),
			Timestamp: baseTime.Add(time.Duration(i*12) * time.Second),
			KeyID:     "validator-key-1",
			KeyType:   keys.KeyTypeValidator,
			Operation: keys.OpSign,
			Source:    "HSM",
			Actor:     "validator-service",
			Success:   true,
		}
		monitor.ProcessOperation(op)
	}

	// Check pattern analysis
	pattern, found := monitor.GetPattern("validator-key-1")
	if !found {
		t.Fatal("expected signing pattern to be tracked")
	}

	if pattern.TotalSignings < 50 {
		t.Errorf("expected at least 50 signings, got %d", pattern.TotalSignings)
	}
}

func TestHighRiskOperationAlerts(t *testing.T) {
	config := keys.DefaultMonitorConfig()
	monitor := keys.NewMonitor(config)

	var alertCount int32
	monitor.AddHandler(func(ctx context.Context, alert *keys.Alert) error {
		atomic.AddInt32(&alertCount, 1)
		return nil
	})

	// Record high-risk operation (key export)
	op := &keys.KeyOperation{
		ID:        "export-1",
		Timestamp: time.Now(),
		KeyID:     "validator-key-1",
		KeyType:   keys.KeyTypeValidator,
		Operation: keys.OpExport,
		Source:    "HSM",
		Actor:     "unknown-user",
		Success:   true,
	}

	monitor.ProcessOperation(op)

	// Allow time for alert processing
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&alertCount) == 0 {
		t.Error("expected high-risk operation alert")
	}
}

func TestKeyNormalization(t *testing.T) {
	config := keys.DefaultMonitorConfig()
	monitor := keys.NewMonitor(config)

	op := &keys.KeyOperation{
		ID:        "op-1",
		Timestamp: time.Now(),
		KeyID:     "validator-key-1",
		KeyType:   keys.KeyTypeValidator,
		Operation: keys.OpSign,
		Source:    "HSM",
		Actor:     "validator-service",
		Success:   true,
	}

	event := monitor.NormalizeToEvent(op, "tenant-1")

	if event.Action != "key.sign" {
		t.Errorf("Action = %v, want key.sign", event.Action)
	}

	if event.TenantID != "tenant-1" {
		t.Errorf("TenantID = %v, want tenant-1", event.TenantID)
	}

	if event.Target != "validator-key-1" {
		t.Errorf("Target = %v, want validator-key-1", event.Target)
	}
}

func TestKeyRotationTracking(t *testing.T) {
	config := keys.DefaultMonitorConfig()
	monitor := keys.NewMonitor(config)

	// Record key rotation
	op := &keys.KeyOperation{
		ID:        "rotate-1",
		Timestamp: time.Now(),
		KeyID:     "validator-key-1",
		KeyType:   keys.KeyTypeValidator,
		Operation: keys.OpRotate,
		Source:    "Vault",
		Actor:     "key-manager",
		Success:   true,
		Metadata: map[string]interface{}{
			"old_version": 1,
			"new_version": 2,
		},
	}

	monitor.ProcessOperation(op)

	// Check sensitive operation was tracked
	stats := monitor.GetStats()
	if stats["sensitive_ops"].(int64) != 1 {
		t.Errorf("expected 1 sensitive operation, got %d", stats["sensitive_ops"])
	}
}

func TestCloudCorrelationRules(t *testing.T) {
	rules := cloud.CreateCorrelationRules()

	if len(rules) == 0 {
		t.Error("expected cloud correlation rules, got none")
	}

	// Check for specific rule types
	ruleIDs := make(map[string]bool)
	for _, rule := range rules {
		ruleIDs[rule.ID] = true
	}

	expectedRules := []string{
		"cloud-unauthorized-access",
		"cloud-iam-change",
		"cloud-resource-deletion",
	}

	for _, expected := range expectedRules {
		if !ruleIDs[expected] {
			t.Errorf("expected rule %s not found", expected)
		}
	}
}

func TestRPCCorrelationRules(t *testing.T) {
	rules := rpc.CreateCorrelationRules()

	if len(rules) == 0 {
		t.Error("expected RPC correlation rules, got none")
	}

	// Check for specific rule types
	ruleIDs := make(map[string]bool)
	for _, rule := range rules {
		ruleIDs[rule.ID] = true
	}

	expectedRules := []string{
		"rpc-blocked-method-access",
		"rpc-enumeration",
		"rpc-rate-limit-violation",
	}

	for _, expected := range expectedRules {
		if !ruleIDs[expected] {
			t.Errorf("expected rule %s not found", expected)
		}
	}
}

func TestKeysCorrelationRules(t *testing.T) {
	rules := keys.CreateCorrelationRules()

	if len(rules) == 0 {
		t.Error("expected key management correlation rules, got none")
	}

	// Check for specific rule types
	ruleIDs := make(map[string]bool)
	for _, rule := range rules {
		ruleIDs[rule.ID] = true
	}

	expectedRules := []string{
		"key-export-attempt",
		"key-signing-anomaly",
		"key-operation-failures",
	}

	for _, expected := range expectedRules {
		if !ruleIDs[expected] {
			t.Errorf("expected rule %s not found", expected)
		}
	}
}

func TestMetricsCorrelationRules(t *testing.T) {
	rules := metrics.CreateCorrelationRules()

	if len(rules) == 0 {
		t.Error("expected metrics correlation rules, got none")
	}

	// Check for specific rule types
	ruleIDs := make(map[string]bool)
	for _, rule := range rules {
		ruleIDs[rule.ID] = true
	}

	expectedRules := []string{
		"infra-high-cpu",
		"infra-memory-exhaustion",
		"infra-disk-full",
	}

	for _, expected := range expectedRules {
		if !ruleIDs[expected] {
			t.Errorf("expected rule %s not found", expected)
		}
	}
}

func BenchmarkMetricsRecord(b *testing.B) {
	config := metrics.DefaultCollectorConfig()
	collector := metrics.NewCollector(config)

	metric := &metrics.Metric{
		Type:      metrics.MetricCPU,
		Name:      "usage",
		Value:     75.5,
		Timestamp: time.Now(),
		Host:      "node-1",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.RecordMetric(metric)
	}
}

func BenchmarkRPCProcess(b *testing.B) {
	config := rpc.DefaultMonitorConfig()
	config.DefaultRateLimit = 1000000 // High limit for benchmark
	monitor := rpc.NewMonitor(config)

	req := &rpc.RPCRequest{
		ID:        "1",
		Type:      rpc.RPCTypeJSONRPC,
		Method:    "eth_blockNumber",
		Params:    json.RawMessage(`[]`),
		SourceIP:  "192.168.1.1",
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		monitor.ProcessRequest(req)
	}
}

func BenchmarkCloudParse(b *testing.B) {
	parser := cloud.NewParser(cloud.ProviderAWS)

	cloudTrailLog := `{
		"eventVersion": "1.08",
		"userIdentity": {
			"type": "IAMUser",
			"accountId": "123456789012"
		},
		"eventTime": "2024-01-01T12:00:00Z",
		"eventSource": "ec2.amazonaws.com",
		"eventName": "RunInstances",
		"awsRegion": "us-east-1",
		"sourceIPAddress": "192.168.1.1",
		"eventID": "event-123"
	}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.Parse(cloudTrailLog)
	}
}

func BenchmarkKeyOperation(b *testing.B) {
	config := keys.DefaultMonitorConfig()
	monitor := keys.NewMonitor(config)

	op := &keys.KeyOperation{
		ID:        "op-1",
		Timestamp: time.Now(),
		KeyID:     "validator-key-1",
		KeyType:   keys.KeyTypeValidator,
		Operation: keys.OpSign,
		Source:    "HSM",
		Actor:     "validator-service",
		Success:   true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		monitor.ProcessOperation(op)
	}
}
