package s3

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Region == "" {
		t.Error("expected default region")
	}
	if cfg.Bucket == "" {
		t.Error("expected default bucket")
	}
	if cfg.PartSize < 5*1024*1024 {
		t.Error("expected part size >= 5MB")
	}
	if cfg.Concurrency < 1 {
		t.Error("expected concurrency >= 1")
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{
			name:    "valid config",
			modify:  func(c *Config) {},
			wantErr: false,
		},
		{
			name: "empty region",
			modify: func(c *Config) {
				c.Region = ""
			},
			wantErr: true,
		},
		{
			name: "empty bucket",
			modify: func(c *Config) {
				c.Bucket = ""
			},
			wantErr: true,
		},
		{
			name: "part size too small",
			modify: func(c *Config) {
				c.PartSize = 1024 // 1KB, less than 5MB minimum
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)

			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetStorageClass(t *testing.T) {
	tests := []struct {
		class    string
		expected string
	}{
		{"STANDARD", "STANDARD"},
		{"INTELLIGENT_TIERING", "INTELLIGENT_TIERING"},
		{"GLACIER", "GLACIER"},
		{"DEEP_ARCHIVE", "DEEP_ARCHIVE"},
		{"standard", "STANDARD"},
		{"unknown", "STANDARD"}, // Default
	}

	for _, tt := range tests {
		t.Run(tt.class, func(t *testing.T) {
			cfg := &Config{StorageClass: tt.class}
			result := cfg.GetStorageClass()
			if string(result) != tt.expected {
				t.Errorf("GetStorageClass() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDefaultArchiverConfig(t *testing.T) {
	cfg := DefaultArchiverConfig()

	if cfg.BatchSize < 1 {
		t.Error("expected batch size >= 1")
	}
	if cfg.FlushInterval < time.Second {
		t.Error("expected flush interval >= 1s")
	}
	if cfg.Compression == "" {
		t.Error("expected default compression")
	}
	if cfg.PathTemplate == "" {
		t.Error("expected path template")
	}
}

func TestCompress(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	archiver := &Archiver{
		config: &ArchiverConfig{
			Compression: CompressionGzip,
		},
		logger: logger,
	}

	data := []byte("test data for compression test data for compression")

	compressed, err := archiver.compress(data)
	if err != nil {
		t.Fatalf("compress() error = %v", err)
	}

	// Compressed should be smaller for repetitive data
	if len(compressed) >= len(data) {
		t.Logf("compression didn't reduce size (original: %d, compressed: %d)", len(data), len(compressed))
	}

	// Decompress should return original
	decompressed, err := archiver.decompress(compressed, CompressionGzip)
	if err != nil {
		t.Fatalf("decompress() error = %v", err)
	}

	if !bytes.Equal(data, decompressed) {
		t.Error("decompressed data doesn't match original")
	}
}

func TestCompressNone(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	archiver := &Archiver{
		config: &ArchiverConfig{
			Compression: CompressionNone,
		},
		logger: logger,
	}

	data := []byte("test data")

	compressed, err := archiver.compress(data)
	if err != nil {
		t.Fatalf("compress() error = %v", err)
	}

	if !bytes.Equal(data, compressed) {
		t.Error("CompressionNone should return identical data")
	}
}

func TestGenerateKey(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	archiver := &Archiver{
		config: &ArchiverConfig{
			PathTemplate: "archives/{type}/{id}.json.gz",
		},
		logger: logger,
	}

	key := archiver.generateKey("events", "batch-123")

	if key == "" {
		t.Error("expected non-empty key")
	}
}

func TestSplitIntoBatches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	archiver := &Archiver{
		config: &ArchiverConfig{
			BatchSize:   10,
			Compression: CompressionGzip,
		},
		logger: logger,
	}

	// Create 25 records
	records := make([]ArchiveRecord, 25)
	for i := range records {
		records[i] = ArchiveRecord{
			ID:        string(rune('a' + i)),
			Timestamp: time.Now(),
			Type:      "test",
			Data:      map[string]interface{}{"index": i},
		}
	}

	batches := archiver.splitIntoBatches("archive-1", "events", records)

	// Should have 3 batches: 10, 10, 5
	if len(batches) != 3 {
		t.Errorf("expected 3 batches, got %d", len(batches))
	}

	if batches[0].RecordCount != 10 {
		t.Errorf("first batch should have 10 records, got %d", batches[0].RecordCount)
	}

	if batches[2].RecordCount != 5 {
		t.Errorf("last batch should have 5 records, got %d", batches[2].RecordCount)
	}
}

func getTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func skipIfNoS3(t *testing.T) {
	t.Helper()
	bucket := os.Getenv("S3_TEST_BUCKET")
	if bucket == "" {
		t.Skip("S3_TEST_BUCKET not set, skipping integration test")
	}
}

// Integration tests - skipped if S3 is not available
func TestS3ClientIntegration(t *testing.T) {
	skipIfNoS3(t)

	ctx := context.Background()
	cfg := &Config{
		Region:       os.Getenv("AWS_REGION"),
		Bucket:       os.Getenv("S3_TEST_BUCKET"),
		Prefix:       "test/",
		StorageClass: "STANDARD",
		PartSize:     5 * 1024 * 1024,
	}

	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}

	client, err := NewClient(ctx, cfg, getTestLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Test health check
	status := client.HealthCheck(ctx)
	if !status.Healthy {
		t.Errorf("expected healthy, got error: %s", status.Error)
	}

	// Test upload
	testKey := "integration-test-" + time.Now().Format("20060102150405")
	testData := []byte("test data for integration test")

	output, err := client.Upload(ctx, &UploadInput{
		Key:         testKey,
		Body:        bytes.NewReader(testData),
		ContentType: "text/plain",
		Metadata: map[string]string{
			"test": "true",
		},
	})
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}

	if output.Key == "" {
		t.Error("expected key in upload output")
	}

	// Test exists
	exists, err := client.Exists(ctx, testKey)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if !exists {
		t.Error("expected object to exist")
	}

	// Test download
	downloadOutput, err := client.Download(ctx, testKey)
	if err != nil {
		t.Fatalf("Download() error = %v", err)
	}
	defer downloadOutput.Body.Close()

	if downloadOutput.Size != int64(len(testData)) {
		t.Errorf("expected size %d, got %d", len(testData), downloadOutput.Size)
	}

	// Test list
	objects, err := client.List(ctx, "integration-test-", 10)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	found := false
	for _, obj := range objects {
		if obj.Key == cfg.Prefix+testKey {
			found = true
			break
		}
	}
	if !found {
		t.Error("uploaded object not found in list")
	}

	// Cleanup - delete test object
	err = client.Delete(ctx, testKey)
	if err != nil {
		t.Errorf("Delete() error = %v", err)
	}

	// Verify deleted
	exists, err = client.Exists(ctx, testKey)
	if err != nil {
		t.Fatalf("Exists() after delete error = %v", err)
	}
	if exists {
		t.Error("object should not exist after delete")
	}
}

func TestArchiverIntegration(t *testing.T) {
	skipIfNoS3(t)

	ctx := context.Background()
	cfg := &Config{
		Region:       os.Getenv("AWS_REGION"),
		Bucket:       os.Getenv("S3_TEST_BUCKET"),
		Prefix:       "test/",
		StorageClass: "STANDARD",
		PartSize:     5 * 1024 * 1024,
	}

	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}

	client, err := NewClient(ctx, cfg, getTestLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	archiver := NewArchiver(client, DefaultArchiverConfig(), getTestLogger())

	// Create test records
	records := make([]ArchiveRecord, 100)
	for i := range records {
		records[i] = ArchiveRecord{
			ID:        string(rune(i)),
			Timestamp: time.Now().Add(-time.Duration(i) * time.Hour),
			Type:      "test-event",
			Data: map[string]interface{}{
				"index":   i,
				"message": "test message for integration test",
			},
		}
	}

	// Archive records
	manifest, err := archiver.Archive(ctx, "integration-test", records)
	if err != nil {
		t.Fatalf("Archive() error = %v", err)
	}

	if manifest.TotalRecords != 100 {
		t.Errorf("expected 100 records, got %d", manifest.TotalRecords)
	}

	// Restore records
	restored, err := archiver.Restore(ctx, manifest.ID)
	if err != nil {
		t.Fatalf("Restore() error = %v", err)
	}

	if len(restored) != len(records) {
		t.Errorf("expected %d restored records, got %d", len(records), len(restored))
	}

	// Cleanup
	err = archiver.DeleteArchive(ctx, manifest.ID)
	if err != nil {
		t.Errorf("DeleteArchive() error = %v", err)
	}
}

func TestMetrics(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Test client metrics
	client := &Client{
		metrics: &clientMetrics{},
		logger:  logger,
	}

	client.metrics.bytesUploaded.Store(1000)
	client.metrics.objectsUploaded.Store(10)

	metrics := client.GetMetrics()
	if metrics.BytesUploaded != 1000 {
		t.Errorf("expected 1000 bytes uploaded, got %d", metrics.BytesUploaded)
	}
	if metrics.ObjectsUploaded != 10 {
		t.Errorf("expected 10 objects uploaded, got %d", metrics.ObjectsUploaded)
	}

	// Test archiver metrics
	archiver := &Archiver{
		metrics: &archiverMetrics{},
		logger:  logger,
	}

	archiver.metrics.recordsArchived.Store(5000)
	archiver.metrics.batchesCreated.Store(5)

	archiverMetrics := archiver.GetMetrics()
	if archiverMetrics.RecordsArchived != 5000 {
		t.Errorf("expected 5000 records, got %d", archiverMetrics.RecordsArchived)
	}
	if archiverMetrics.BatchesCreated != 5 {
		t.Errorf("expected 5 batches, got %d", archiverMetrics.BatchesCreated)
	}
}
