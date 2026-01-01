// Package retention provides data retention and archival for the SIEM.
package retention

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"boundary-siem/internal/storage/s3"
)

// StorageTier defines storage tiers.
type StorageTier string

const (
	TierHot      StorageTier = "hot"       // Fast SSD, recent data
	TierWarm     StorageTier = "warm"      // Standard storage, older data
	TierCold     StorageTier = "cold"      // S3/object storage, archived
	TierFrozen   StorageTier = "frozen"    // Glacier/deep archive
)

// RetentionPolicy defines data retention rules.
type RetentionPolicy struct {
	ID                      string          `json:"id"`
	Name                    string          `json:"name"`
	Description             string          `json:"description,omitempty"`
	DataType                string          `json:"data_type"`
	Enabled                 bool            `json:"enabled"`
	Rules                   []RetentionRule `json:"rules"`
	RequireBackupBeforePurge bool           `json:"require_backup_before_purge"` // Safety: require archive before delete
	CreatedAt               time.Time       `json:"created_at"`
	UpdatedAt               time.Time       `json:"updated_at"`
}

// RetentionRule defines a single retention rule.
type RetentionRule struct {
	Tier            StorageTier   `json:"tier"`
	MaxAge          time.Duration `json:"max_age"`
	MinAge          time.Duration `json:"min_age,omitempty"`
	Compression     string        `json:"compression,omitempty"`
	DownsampleRatio int           `json:"downsample_ratio,omitempty"`
}

// ArchiveConfig configures data archival.
type ArchiveConfig struct {
	Enabled          bool          `json:"enabled"`
	Provider         string        `json:"provider"` // s3, gcs, azure
	Bucket           string        `json:"bucket"`
	Prefix           string        `json:"prefix"`
	Region           string        `json:"region"`
	Endpoint         string        `json:"endpoint,omitempty"`
	AccessKeyID      string        `json:"access_key_id,omitempty"`
	SecretAccessKey  string        `json:"secret_access_key,omitempty"`
	StorageClass     string        `json:"storage_class"`
	EncryptionKey    string        `json:"encryption_key,omitempty"`
	CompressionCodec string        `json:"compression_codec"`
	BatchSize        int           `json:"batch_size"`
	BatchInterval    time.Duration `json:"batch_interval"`
}

// ArchiveJob represents an archive job.
type ArchiveJob struct {
	ID            string        `json:"id"`
	PolicyID      string        `json:"policy_id"`
	Status        JobStatus     `json:"status"`
	SourceTier    StorageTier   `json:"source_tier"`
	TargetTier    StorageTier   `json:"target_tier"`
	DataType      string        `json:"data_type"`
	StartTime     time.Time     `json:"start_time"`
	EndTime       *time.Time    `json:"end_time,omitempty"`
	RecordsTotal  int64         `json:"records_total"`
	RecordsMoved  int64         `json:"records_moved"`
	BytesTotal    int64         `json:"bytes_total"`
	BytesMoved    int64         `json:"bytes_moved"`
	Error         string        `json:"error,omitempty"`
}

// JobStatus defines job status.
type JobStatus string

const (
	JobStatusPending   JobStatus = "pending"
	JobStatusRunning   JobStatus = "running"
	JobStatusCompleted JobStatus = "completed"
	JobStatusFailed    JobStatus = "failed"
	JobStatusCancelled JobStatus = "cancelled"
)

// StorageStats represents storage statistics.
type StorageStats struct {
	Tier            StorageTier `json:"tier"`
	TotalBytes      int64       `json:"total_bytes"`
	UsedBytes       int64       `json:"used_bytes"`
	AvailableBytes  int64       `json:"available_bytes"`
	RecordCount     int64       `json:"record_count"`
	OldestRecord    time.Time   `json:"oldest_record"`
	NewestRecord    time.Time   `json:"newest_record"`
	CompressionRatio float64    `json:"compression_ratio"`
}

// RetentionManager manages data retention.
type RetentionManager struct {
	mu            sync.RWMutex
	policies      map[string]*RetentionPolicy
	archiveConfig *ArchiveConfig
	jobs          map[string]*ArchiveJob
	stats         map[StorageTier]*StorageStats
	logger        *slog.Logger
	ctx           context.Context
	cancel        context.CancelFunc
	s3Client      *s3.Client
	archiver      *s3.Archiver
}

// NewRetentionManager creates a new retention manager.
func NewRetentionManager(archiveConfig *ArchiveConfig, logger *slog.Logger) *RetentionManager {
	ctx, cancel := context.WithCancel(context.Background())

	rm := &RetentionManager{
		policies:      make(map[string]*RetentionPolicy),
		archiveConfig: archiveConfig,
		jobs:          make(map[string]*ArchiveJob),
		stats:         make(map[StorageTier]*StorageStats),
		logger:        logger,
		ctx:           ctx,
		cancel:        cancel,
	}

	rm.initDefaultPolicies()
	rm.initStorageStats()

	// Initialize S3 client if archival is enabled
	if archiveConfig != nil && archiveConfig.Enabled && archiveConfig.Provider == "s3" {
		if err := rm.initS3Client(ctx); err != nil {
			logger.Error("failed to initialize S3 client", "error", err)
		}
	}

	return rm
}

// initS3Client initializes the S3 client and archiver.
func (rm *RetentionManager) initS3Client(ctx context.Context) error {
	cfg := &s3.Config{
		Region:          rm.archiveConfig.Region,
		Bucket:          rm.archiveConfig.Bucket,
		Prefix:          rm.archiveConfig.Prefix,
		Endpoint:        rm.archiveConfig.Endpoint,
		AccessKeyID:     rm.archiveConfig.AccessKeyID,
		SecretAccessKey: rm.archiveConfig.SecretAccessKey,
		StorageClass:    rm.archiveConfig.StorageClass,
		PartSize:        5 * 1024 * 1024, // 5MB
		Concurrency:     5,
	}

	client, err := s3.NewClient(ctx, cfg, rm.logger)
	if err != nil {
		return fmt.Errorf("failed to create S3 client: %w", err)
	}
	rm.s3Client = client

	// Determine compression type
	compression := s3.CompressionGzip
	switch rm.archiveConfig.CompressionCodec {
	case "none":
		compression = s3.CompressionNone
	case "gzip":
		compression = s3.CompressionGzip
	case "zstd":
		compression = s3.CompressionZstd
	case "lz4":
		compression = s3.CompressionLZ4
	}

	archiverConfig := &s3.ArchiverConfig{
		BatchSize:     rm.archiveConfig.BatchSize,
		MaxBatchBytes: 100 * 1024 * 1024, // 100MB
		FlushInterval: rm.archiveConfig.BatchInterval,
		Compression:   compression,
		StorageClass:  rm.archiveConfig.StorageClass,
		PathTemplate:  "archives/{type}/{date}/{id}.json.gz",
	}

	rm.archiver = s3.NewArchiver(client, archiverConfig, rm.logger)

	rm.logger.Info("S3 archival initialized",
		"bucket", cfg.Bucket,
		"region", cfg.Region,
		"compression", compression,
	)

	return nil
}

// initDefaultPolicies creates default retention policies.
func (rm *RetentionManager) initDefaultPolicies() {
	now := time.Now()

	policies := []*RetentionPolicy{
		{
			ID:                       "events-default",
			Name:                     "Default Event Retention",
			Description:              "Standard retention for security events",
			DataType:                 "events",
			Enabled:                  true,
			RequireBackupBeforePurge: true, // Safety: never purge without archive
			Rules: []RetentionRule{
				{Tier: TierHot, MinAge: 0, MaxAge: 7 * 24 * time.Hour, Compression: "none"},
				{Tier: TierWarm, MinAge: 7 * 24 * time.Hour, MaxAge: 30 * 24 * time.Hour, Compression: "lz4"},
				{Tier: TierCold, MinAge: 30 * 24 * time.Hour, MaxAge: 365 * 24 * time.Hour, Compression: "zstd", DownsampleRatio: 10},
				{Tier: TierFrozen, MinAge: 365 * 24 * time.Hour, MaxAge: 7 * 365 * 24 * time.Hour, Compression: "zstd"},
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:                       "alerts-default",
			Name:                     "Default Alert Retention",
			Description:              "Standard retention for alerts",
			DataType:                 "alerts",
			Enabled:                  true,
			RequireBackupBeforePurge: true, // Safety: never purge without archive
			Rules: []RetentionRule{
				{Tier: TierHot, MinAge: 0, MaxAge: 30 * 24 * time.Hour, Compression: "none"},
				{Tier: TierWarm, MinAge: 30 * 24 * time.Hour, MaxAge: 90 * 24 * time.Hour, Compression: "lz4"},
				{Tier: TierCold, MinAge: 90 * 24 * time.Hour, MaxAge: 3 * 365 * 24 * time.Hour, Compression: "zstd"},
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:                       "audit-logs",
			Name:                     "Audit Log Retention",
			Description:              "Long-term retention for audit logs (compliance)",
			DataType:                 "audit",
			Enabled:                  true,
			RequireBackupBeforePurge: true, // Safety: never purge without archive
			Rules: []RetentionRule{
				{Tier: TierHot, MinAge: 0, MaxAge: 90 * 24 * time.Hour, Compression: "none"},
				{Tier: TierCold, MinAge: 90 * 24 * time.Hour, MaxAge: 7 * 365 * 24 * time.Hour, Compression: "zstd"},
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:                       "metrics-default",
			Name:                     "Metrics Retention",
			Description:              "Retention for time-series metrics",
			DataType:                 "metrics",
			Enabled:                  true,
			RequireBackupBeforePurge: true, // Safety: never purge without archive
			Rules: []RetentionRule{
				{Tier: TierHot, MinAge: 0, MaxAge: 24 * time.Hour, Compression: "none"},
				{Tier: TierWarm, MinAge: 24 * time.Hour, MaxAge: 7 * 24 * time.Hour, Compression: "lz4", DownsampleRatio: 5},
				{Tier: TierCold, MinAge: 7 * 24 * time.Hour, MaxAge: 30 * 24 * time.Hour, Compression: "zstd", DownsampleRatio: 60},
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:                       "blockchain-events",
			Name:                     "Blockchain Event Retention",
			Description:              "Retention for blockchain-specific events",
			DataType:                 "blockchain",
			Enabled:                  true,
			RequireBackupBeforePurge: true, // Safety: never purge without archive
			Rules: []RetentionRule{
				{Tier: TierHot, MinAge: 0, MaxAge: 14 * 24 * time.Hour, Compression: "none"},
				{Tier: TierWarm, MinAge: 14 * 24 * time.Hour, MaxAge: 90 * 24 * time.Hour, Compression: "lz4"},
				{Tier: TierCold, MinAge: 90 * 24 * time.Hour, MaxAge: 5 * 365 * 24 * time.Hour, Compression: "zstd"},
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:                       "compliance-data",
			Name:                     "Compliance Data Retention",
			Description:              "Extended retention for regulatory compliance",
			DataType:                 "compliance",
			Enabled:                  true,
			RequireBackupBeforePurge: true, // Safety: never purge without archive
			Rules: []RetentionRule{
				{Tier: TierHot, MinAge: 0, MaxAge: 30 * 24 * time.Hour, Compression: "none"},
				{Tier: TierCold, MinAge: 30 * 24 * time.Hour, MaxAge: 10 * 365 * 24 * time.Hour, Compression: "zstd"},
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
	}

	for _, p := range policies {
		rm.policies[p.ID] = p
	}
}

// initStorageStats initializes storage statistics.
func (rm *RetentionManager) initStorageStats() {
	now := time.Now()

	rm.stats[TierHot] = &StorageStats{
		Tier:             TierHot,
		TotalBytes:       500 * 1024 * 1024 * 1024, // 500GB
		UsedBytes:        125 * 1024 * 1024 * 1024, // 125GB
		AvailableBytes:   375 * 1024 * 1024 * 1024,
		RecordCount:      50000000,
		OldestRecord:     now.AddDate(0, 0, -7),
		NewestRecord:     now,
		CompressionRatio: 1.0,
	}

	rm.stats[TierWarm] = &StorageStats{
		Tier:             TierWarm,
		TotalBytes:       2 * 1024 * 1024 * 1024 * 1024, // 2TB
		UsedBytes:        800 * 1024 * 1024 * 1024,      // 800GB
		AvailableBytes:   1200 * 1024 * 1024 * 1024,
		RecordCount:      500000000,
		OldestRecord:     now.AddDate(0, -1, 0),
		NewestRecord:     now.AddDate(0, 0, -7),
		CompressionRatio: 3.5,
	}

	rm.stats[TierCold] = &StorageStats{
		Tier:             TierCold,
		TotalBytes:       100 * 1024 * 1024 * 1024 * 1024, // 100TB (S3)
		UsedBytes:        15 * 1024 * 1024 * 1024 * 1024,  // 15TB
		AvailableBytes:   85 * 1024 * 1024 * 1024 * 1024,
		RecordCount:      5000000000,
		OldestRecord:     now.AddDate(-1, 0, 0),
		NewestRecord:     now.AddDate(0, -1, 0),
		CompressionRatio: 8.0,
	}

	rm.stats[TierFrozen] = &StorageStats{
		Tier:             TierFrozen,
		TotalBytes:       1000 * 1024 * 1024 * 1024 * 1024, // 1PB (Glacier)
		UsedBytes:        50 * 1024 * 1024 * 1024 * 1024,   // 50TB
		AvailableBytes:   950 * 1024 * 1024 * 1024 * 1024,
		RecordCount:      50000000000,
		OldestRecord:     now.AddDate(-5, 0, 0),
		NewestRecord:     now.AddDate(-1, 0, 0),
		CompressionRatio: 10.0,
	}
}

// Start starts the retention manager.
func (rm *RetentionManager) Start() error {
	rm.logger.Info("starting retention manager")

	// Start background jobs
	go rm.runRetentionLoop()
	go rm.runArchiveLoop()

	return nil
}

// Stop stops the retention manager.
func (rm *RetentionManager) Stop() error {
	rm.logger.Info("stopping retention manager")
	rm.cancel()
	return nil
}

// runRetentionLoop runs periodic retention checks.
func (rm *RetentionManager) runRetentionLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-rm.ctx.Done():
			return
		case <-ticker.C:
			rm.enforceRetention()
		}
	}
}

// runArchiveLoop runs periodic archive operations.
func (rm *RetentionManager) runArchiveLoop() {
	if rm.archiveConfig == nil || !rm.archiveConfig.Enabled {
		return
	}

	ticker := time.NewTicker(rm.archiveConfig.BatchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rm.ctx.Done():
			return
		case <-ticker.C:
			rm.processArchiveQueue()
		}
	}
}

// enforceRetention applies retention policies.
func (rm *RetentionManager) enforceRetention() {
	rm.mu.RLock()
	policies := make([]*RetentionPolicy, 0, len(rm.policies))
	for _, p := range rm.policies {
		if p.Enabled {
			policies = append(policies, p)
		}
	}
	rm.mu.RUnlock()

	for _, policy := range policies {
		rm.logger.Debug("enforcing retention policy", "policy_id", policy.ID, "data_type", policy.DataType)
		rm.applyPolicy(policy)
	}
}

// applyPolicy applies a single retention policy.
func (rm *RetentionManager) applyPolicy(policy *RetentionPolicy) {
	for i, rule := range policy.Rules {
		if i < len(policy.Rules)-1 {
			nextRule := policy.Rules[i+1]
			rm.moveData(policy.DataType, rule.Tier, nextRule.Tier, rule.MaxAge)
		}
	}

	// Delete data past final tier's max age
	if len(policy.Rules) > 0 {
		lastRule := policy.Rules[len(policy.Rules)-1]

		// Safety check: require backup before purge (default behavior)
		if policy.RequireBackupBeforePurge {
			if !rm.verifyDataArchived(policy.DataType, lastRule.Tier, lastRule.MaxAge) {
				rm.logger.Warn("skipping purge: data not archived",
					"policy_id", policy.ID,
					"data_type", policy.DataType,
					"tier", lastRule.Tier,
				)
				return
			}
		}

		rm.deleteOldData(policy.DataType, lastRule.Tier, lastRule.MaxAge)
	}
}

// verifyDataArchived checks if data has been archived before allowing purge.
func (rm *RetentionManager) verifyDataArchived(dataType string, tier StorageTier, maxAge time.Duration) bool {
	// Check if S3 archiver is configured and healthy
	if rm.archiver == nil {
		rm.logger.Warn("archiver not configured, cannot verify backup",
			"data_type", dataType,
		)
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	health := rm.archiver.GetHealthStatus(ctx)
	if health == nil || !health.Healthy {
		rm.logger.Warn("archiver unhealthy, cannot verify backup",
			"data_type", dataType,
		)
		return false
	}

	// Verify recent archive exists for this data type
	archives, err := rm.archiver.ListArchives(ctx, dataType)
	if err != nil {
		rm.logger.Warn("failed to list archives",
			"data_type", dataType,
			"error", err,
		)
		return false
	}

	if len(archives) == 0 {
		rm.logger.Warn("no archives found for data type",
			"data_type", dataType,
		)
		return false
	}

	// Check if the most recent archive covers the data being purged
	cutoffTime := time.Now().Add(-maxAge)
	for _, archive := range archives {
		if archive.EndTime.After(cutoffTime) {
			rm.logger.Debug("verified archive exists for purge",
				"data_type", dataType,
				"archive_id", archive.ID,
				"archive_end_time", archive.EndTime,
			)
			return true
		}
	}

	rm.logger.Warn("no recent archive covers data being purged",
		"data_type", dataType,
		"cutoff_time", cutoffTime,
	)
	return false
}

// moveData moves data between tiers.
func (rm *RetentionManager) moveData(dataType string, sourceTier, targetTier StorageTier, maxAge time.Duration) {
	rm.logger.Debug("moving data between tiers",
		"data_type", dataType,
		"source", sourceTier,
		"target", targetTier,
		"max_age", maxAge,
	)
}

// deleteOldData deletes data past retention.
func (rm *RetentionManager) deleteOldData(dataType string, tier StorageTier, maxAge time.Duration) {
	rm.logger.Debug("deleting old data",
		"data_type", dataType,
		"tier", tier,
		"max_age", maxAge,
	)
}

// processArchiveQueue processes pending archive jobs.
func (rm *RetentionManager) processArchiveQueue() {
	rm.mu.RLock()
	pendingJobs := make([]*ArchiveJob, 0)
	for _, job := range rm.jobs {
		if job.Status == JobStatusPending {
			pendingJobs = append(pendingJobs, job)
		}
	}
	rm.mu.RUnlock()

	for _, job := range pendingJobs {
		rm.executeArchiveJob(job)
	}
}

// executeArchiveJob executes an archive job.
func (rm *RetentionManager) executeArchiveJob(job *ArchiveJob) {
	rm.mu.Lock()
	job.Status = JobStatusRunning
	job.StartTime = time.Now()
	rm.mu.Unlock()

	rm.logger.Info("executing archive job",
		"job_id", job.ID,
		"source", job.SourceTier,
		"target", job.TargetTier,
		"data_type", job.DataType,
	)

	// Check if S3 archiver is available
	if rm.archiver == nil {
		rm.mu.Lock()
		job.Status = JobStatusFailed
		job.Error = "S3 archiver not initialized"
		now := time.Now()
		job.EndTime = &now
		rm.mu.Unlock()
		rm.logger.Error("archive job failed: S3 archiver not initialized", "job_id", job.ID)
		return
	}

	// Create sample records for archival (in production, these would come from ClickHouse)
	records := rm.fetchRecordsForArchival(job.DataType, job.RecordsTotal)

	// Archive to S3
	manifest, err := rm.archiver.Archive(rm.ctx, job.DataType, records)
	if err != nil {
		rm.mu.Lock()
		job.Status = JobStatusFailed
		job.Error = err.Error()
		now := time.Now()
		job.EndTime = &now
		rm.mu.Unlock()
		rm.logger.Error("archive job failed", "job_id", job.ID, "error", err)
		return
	}

	// Update job with results
	rm.mu.Lock()
	job.Status = JobStatusCompleted
	now := time.Now()
	job.EndTime = &now
	job.RecordsMoved = manifest.TotalRecords
	job.BytesMoved = manifest.TotalBytes
	rm.mu.Unlock()

	rm.logger.Info("archive job completed",
		"job_id", job.ID,
		"archive_id", manifest.ID,
		"records", manifest.TotalRecords,
		"bytes", manifest.TotalBytes,
	)
}

// fetchRecordsForArchival fetches records to archive.
// In production, this would query ClickHouse for records matching the criteria.
func (rm *RetentionManager) fetchRecordsForArchival(dataType string, count int64) []s3.ArchiveRecord {
	records := make([]s3.ArchiveRecord, 0, count)
	now := time.Now()

	// Generate sample records (in production, fetch from database)
	for i := int64(0); i < count && i < 1000; i++ {
		records = append(records, s3.ArchiveRecord{
			ID:        fmt.Sprintf("%s-%d", dataType, i),
			Timestamp: now.Add(-time.Duration(i) * time.Hour),
			Type:      dataType,
			Data: map[string]interface{}{
				"index":     i,
				"data_type": dataType,
				"archived":  true,
			},
		})
	}

	return records
}

// ArchiveRecords archives the given records to S3.
func (rm *RetentionManager) ArchiveRecords(ctx context.Context, dataType string, records []s3.ArchiveRecord) (*s3.ArchiveManifest, error) {
	if rm.archiver == nil {
		return nil, fmt.Errorf("S3 archiver not initialized")
	}

	return rm.archiver.Archive(ctx, dataType, records)
}

// RestoreArchive restores records from an S3 archive.
func (rm *RetentionManager) RestoreArchive(ctx context.Context, archiveID string) ([]s3.ArchiveRecord, error) {
	if rm.archiver == nil {
		return nil, fmt.Errorf("S3 archiver not initialized")
	}

	return rm.archiver.Restore(ctx, archiveID)
}

// ListArchives lists all archives for a data type.
func (rm *RetentionManager) ListArchives(ctx context.Context, dataType string) ([]s3.ArchiveManifest, error) {
	if rm.archiver == nil {
		return nil, fmt.Errorf("S3 archiver not initialized")
	}

	return rm.archiver.ListArchives(ctx, dataType)
}

// DeleteArchive deletes an archive from S3.
func (rm *RetentionManager) DeleteArchive(ctx context.Context, archiveID string) error {
	if rm.archiver == nil {
		return fmt.Errorf("S3 archiver not initialized")
	}

	return rm.archiver.DeleteArchive(ctx, archiveID)
}

// GetS3HealthStatus returns the S3 health status.
func (rm *RetentionManager) GetS3HealthStatus(ctx context.Context) *s3.HealthStatus {
	if rm.s3Client == nil {
		return &s3.HealthStatus{
			Healthy: false,
			Error:   "S3 client not initialized",
		}
	}

	status := rm.s3Client.HealthCheck(ctx)
	return &status
}

// GetArchiverMetrics returns archiver metrics.
func (rm *RetentionManager) GetArchiverMetrics() *s3.ArchiverMetrics {
	if rm.archiver == nil {
		return nil
	}

	metrics := rm.archiver.GetMetrics()
	return &metrics
}

// GetPolicy returns a retention policy by ID.
func (rm *RetentionManager) GetPolicy(id string) (*RetentionPolicy, bool) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	p, ok := rm.policies[id]
	return p, ok
}

// GetAllPolicies returns all retention policies.
func (rm *RetentionManager) GetAllPolicies() []*RetentionPolicy {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	policies := make([]*RetentionPolicy, 0, len(rm.policies))
	for _, p := range rm.policies {
		policies = append(policies, p)
	}
	return policies
}

// CreatePolicy creates a new retention policy.
func (rm *RetentionManager) CreatePolicy(policy *RetentionPolicy) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.policies[policy.ID]; exists {
		return fmt.Errorf("policy already exists: %s", policy.ID)
	}

	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	rm.policies[policy.ID] = policy

	rm.logger.Info("created retention policy", "policy_id", policy.ID)
	return nil
}

// UpdatePolicy updates a retention policy.
func (rm *RetentionManager) UpdatePolicy(policy *RetentionPolicy) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.policies[policy.ID]; !exists {
		return fmt.Errorf("policy not found: %s", policy.ID)
	}

	policy.UpdatedAt = time.Now()
	rm.policies[policy.ID] = policy

	rm.logger.Info("updated retention policy", "policy_id", policy.ID)
	return nil
}

// DeletePolicy deletes a retention policy.
func (rm *RetentionManager) DeletePolicy(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.policies[id]; !exists {
		return fmt.Errorf("policy not found: %s", id)
	}

	delete(rm.policies, id)
	rm.logger.Info("deleted retention policy", "policy_id", id)
	return nil
}

// GetStorageStats returns storage statistics for a tier.
func (rm *RetentionManager) GetStorageStats(tier StorageTier) (*StorageStats, bool) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	stats, ok := rm.stats[tier]
	return stats, ok
}

// GetAllStorageStats returns all storage statistics.
func (rm *RetentionManager) GetAllStorageStats() map[StorageTier]*StorageStats {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	result := make(map[StorageTier]*StorageStats)
	for tier, stats := range rm.stats {
		result[tier] = stats
	}
	return result
}

// CreateArchiveJob creates a new archive job.
func (rm *RetentionManager) CreateArchiveJob(policyID string, sourceTier, targetTier StorageTier) (*ArchiveJob, error) {
	rm.mu.RLock()
	policy, exists := rm.policies[policyID]
	rm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}

	job := &ArchiveJob{
		ID:           fmt.Sprintf("job-%d", time.Now().UnixNano()),
		PolicyID:     policyID,
		Status:       JobStatusPending,
		SourceTier:   sourceTier,
		TargetTier:   targetTier,
		DataType:     policy.DataType,
		RecordsTotal: 1000000,
		BytesTotal:   1024 * 1024 * 1024,
	}

	rm.mu.Lock()
	rm.jobs[job.ID] = job
	rm.mu.Unlock()

	rm.logger.Info("created archive job", "job_id", job.ID)
	return job, nil
}

// GetArchiveJob returns an archive job by ID.
func (rm *RetentionManager) GetArchiveJob(id string) (*ArchiveJob, bool) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	job, ok := rm.jobs[id]
	return job, ok
}

// GetArchiveJobs returns all archive jobs.
func (rm *RetentionManager) GetArchiveJobs() []*ArchiveJob {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	jobs := make([]*ArchiveJob, 0, len(rm.jobs))
	for _, job := range rm.jobs {
		jobs = append(jobs, job)
	}
	return jobs
}

// Archive archives data to S3/object storage.
func (rm *RetentionManager) Archive(dataType string, startTime, endTime time.Time) (*ArchiveJob, error) {
	if rm.archiveConfig == nil || !rm.archiveConfig.Enabled {
		return nil, fmt.Errorf("archival is not configured")
	}

	job := &ArchiveJob{
		ID:           fmt.Sprintf("archive-%d", time.Now().UnixNano()),
		Status:       JobStatusPending,
		SourceTier:   TierWarm,
		TargetTier:   TierCold,
		DataType:     dataType,
		RecordsTotal: 10000000,
		BytesTotal:   10 * 1024 * 1024 * 1024,
	}

	rm.mu.Lock()
	rm.jobs[job.ID] = job
	rm.mu.Unlock()

	rm.logger.Info("created archive job",
		"job_id", job.ID,
		"data_type", dataType,
		"start", startTime,
		"end", endTime,
	)

	return job, nil
}

// Restore restores data from archive.
func (rm *RetentionManager) Restore(jobID string, targetTier StorageTier) error {
	rm.mu.RLock()
	job, exists := rm.jobs[jobID]
	rm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("job not found: %s", jobID)
	}

	rm.logger.Info("restoring from archive",
		"job_id", jobID,
		"target_tier", targetTier,
		"data_type", job.DataType,
	)

	return nil
}

// DefaultArchiveConfig returns default archive configuration.
func DefaultArchiveConfig() *ArchiveConfig {
	return &ArchiveConfig{
		Enabled:          true,
		Provider:         "s3",
		Bucket:           "boundary-siem-archive",
		Prefix:           "data/",
		Region:           "us-east-1",
		StorageClass:     "INTELLIGENT_TIERING",
		CompressionCodec: "zstd",
		BatchSize:        10000,
		BatchInterval:    15 * time.Minute,
	}
}

// MarshalJSON implements json.Marshaler for StorageStats.
func (s *StorageStats) MarshalJSON() ([]byte, error) {
	type Alias StorageStats
	return json.Marshal(&struct {
		*Alias
		OldestRecord string `json:"oldest_record"`
		NewestRecord string `json:"newest_record"`
	}{
		Alias:        (*Alias)(s),
		OldestRecord: s.OldestRecord.Format(time.RFC3339),
		NewestRecord: s.NewestRecord.Format(time.RFC3339),
	})
}
