// Package s3 provides S3 storage integration for data archival and retrieval.
package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Config holds S3 connection and behavior configuration.
type Config struct {
	// Region is the AWS region.
	Region string `json:"region" yaml:"region"`

	// Bucket is the S3 bucket name.
	Bucket string `json:"bucket" yaml:"bucket"`

	// Prefix is the key prefix for all objects.
	Prefix string `json:"prefix" yaml:"prefix"`

	// Endpoint is an optional custom endpoint (for S3-compatible storage).
	Endpoint string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`

	// AccessKeyID for static credentials (optional, uses IAM if not set).
	AccessKeyID string `json:"access_key_id,omitempty" yaml:"access_key_id,omitempty"`

	// SecretAccessKey for static credentials.
	SecretAccessKey string `json:"secret_access_key,omitempty" yaml:"secret_access_key,omitempty"`

	// SessionToken for temporary credentials.
	SessionToken string `json:"session_token,omitempty" yaml:"session_token,omitempty"`

	// StorageClass for uploaded objects (STANDARD, INTELLIGENT_TIERING, GLACIER, etc.).
	StorageClass string `json:"storage_class" yaml:"storage_class"`

	// ServerSideEncryption type (AES256 or aws:kms).
	ServerSideEncryption string `json:"server_side_encryption,omitempty" yaml:"server_side_encryption,omitempty"`

	// KMSKeyID for KMS encryption.
	KMSKeyID string `json:"kms_key_id,omitempty" yaml:"kms_key_id,omitempty"`

	// UsePathStyle forces path-style addressing (for MinIO, etc.).
	UsePathStyle bool `json:"use_path_style" yaml:"use_path_style"`

	// PartSize for multipart uploads (default 5MB).
	PartSize int64 `json:"part_size" yaml:"part_size"`

	// Concurrency for multipart uploads (default 5).
	Concurrency int `json:"concurrency" yaml:"concurrency"`

	// RetryMaxAttempts for failed operations.
	RetryMaxAttempts int `json:"retry_max_attempts" yaml:"retry_max_attempts"`

	// Timeout for operations.
	Timeout time.Duration `json:"timeout" yaml:"timeout"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Region:           "us-east-1",
		Bucket:           "boundary-siem-archive",
		Prefix:           "data/",
		StorageClass:     "INTELLIGENT_TIERING",
		PartSize:         5 * 1024 * 1024, // 5MB
		Concurrency:      5,
		RetryMaxAttempts: 3,
		Timeout:          30 * time.Minute,
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.Region == "" {
		return errors.New("s3: region is required")
	}
	if c.Bucket == "" {
		return errors.New("s3: bucket is required")
	}
	if c.PartSize < 5*1024*1024 {
		return errors.New("s3: part size must be at least 5MB")
	}
	return nil
}

// GetStorageClass returns the S3 storage class type.
func (c *Config) GetStorageClass() types.StorageClass {
	switch strings.ToUpper(c.StorageClass) {
	case "STANDARD":
		return types.StorageClassStandard
	case "REDUCED_REDUNDANCY":
		return types.StorageClassReducedRedundancy
	case "STANDARD_IA":
		return types.StorageClassStandardIa
	case "ONEZONE_IA":
		return types.StorageClassOnezoneIa
	case "INTELLIGENT_TIERING":
		return types.StorageClassIntelligentTiering
	case "GLACIER":
		return types.StorageClassGlacier
	case "DEEP_ARCHIVE":
		return types.StorageClassDeepArchive
	case "GLACIER_IR":
		return types.StorageClassGlacierIr
	default:
		return types.StorageClassStandard
	}
}

// Client is an S3 client for archive operations.
type Client struct {
	client  *s3.Client
	config  *Config
	logger  *slog.Logger
	metrics *clientMetrics
}

type clientMetrics struct {
	bytesUploaded   atomic.Int64
	bytesDownloaded atomic.Int64
	objectsUploaded atomic.Int64
	objectsDeleted  atomic.Int64
	errors          atomic.Int64
}

// NewClient creates a new S3 client.
func NewClient(ctx context.Context, cfg *Config, logger *slog.Logger) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Build AWS config options
	var opts []func(*config.LoadOptions) error
	opts = append(opts, config.WithRegion(cfg.Region))

	// Use static credentials if provided
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		creds := credentials.NewStaticCredentialsProvider(
			cfg.AccessKeyID,
			cfg.SecretAccessKey,
			cfg.SessionToken,
		)
		opts = append(opts, config.WithCredentialsProvider(creds))
	}

	// Set retry attempts
	if cfg.RetryMaxAttempts > 0 {
		opts = append(opts, config.WithRetryMaxAttempts(cfg.RetryMaxAttempts))
	}

	// Load AWS config
	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("s3: failed to load AWS config: %w", err)
	}

	// Build S3 client options
	var s3Opts []func(*s3.Options)

	// Custom endpoint (for MinIO, LocalStack, etc.)
	if cfg.Endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		})
	}

	// Path-style addressing
	if cfg.UsePathStyle {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	// Create S3 client
	s3Client := s3.NewFromConfig(awsCfg, s3Opts...)

	c := &Client{
		client:  s3Client,
		config:  cfg,
		logger:  logger,
		metrics: &clientMetrics{},
	}

	logger.Info("s3 client initialized",
		"bucket", cfg.Bucket,
		"region", cfg.Region,
		"storage_class", cfg.StorageClass,
	)

	return c, nil
}

// UploadInput contains parameters for uploading an object.
type UploadInput struct {
	Key          string
	Body         io.Reader
	ContentType  string
	Metadata     map[string]string
	StorageClass string // Override default storage class
}

// UploadOutput contains the result of an upload operation.
type UploadOutput struct {
	Key      string
	ETag     string
	Location string
	Size     int64
}

// Upload uploads an object to S3.
func (c *Client) Upload(ctx context.Context, input *UploadInput) (*UploadOutput, error) {
	key := c.config.Prefix + input.Key

	// Read all data to get size (needed for single-part upload)
	data, err := io.ReadAll(input.Body)
	if err != nil {
		c.metrics.errors.Add(1)
		return nil, fmt.Errorf("s3: failed to read upload data: %w", err)
	}

	size := int64(len(data))

	// Determine storage class
	storageClass := c.config.GetStorageClass()
	if input.StorageClass != "" {
		tempCfg := &Config{StorageClass: input.StorageClass}
		storageClass = tempCfg.GetStorageClass()
	}

	// Build PutObject input
	putInput := &s3.PutObjectInput{
		Bucket:       aws.String(c.config.Bucket),
		Key:          aws.String(key),
		Body:         strings.NewReader(string(data)),
		StorageClass: storageClass,
	}

	if input.ContentType != "" {
		putInput.ContentType = aws.String(input.ContentType)
	}

	if len(input.Metadata) > 0 {
		putInput.Metadata = input.Metadata
	}

	// Server-side encryption
	if c.config.ServerSideEncryption != "" {
		switch c.config.ServerSideEncryption {
		case "AES256":
			putInput.ServerSideEncryption = types.ServerSideEncryptionAes256
		case "aws:kms":
			putInput.ServerSideEncryption = types.ServerSideEncryptionAwsKms
			if c.config.KMSKeyID != "" {
				putInput.SSEKMSKeyId = aws.String(c.config.KMSKeyID)
			}
		}
	}

	// Execute upload
	result, err := c.client.PutObject(ctx, putInput)
	if err != nil {
		c.metrics.errors.Add(1)
		return nil, fmt.Errorf("s3: failed to upload object %s: %w", key, err)
	}

	c.metrics.bytesUploaded.Add(size)
	c.metrics.objectsUploaded.Add(1)

	c.logger.Debug("uploaded object",
		"key", key,
		"size", size,
		"storage_class", storageClass,
	)

	return &UploadOutput{
		Key:      key,
		ETag:     aws.ToString(result.ETag),
		Location: fmt.Sprintf("s3://%s/%s", c.config.Bucket, key),
		Size:     size,
	}, nil
}

// DownloadOutput contains the result of a download operation.
type DownloadOutput struct {
	Key          string
	Body         io.ReadCloser
	ContentType  string
	Size         int64
	LastModified time.Time
	Metadata     map[string]string
}

// Download downloads an object from S3.
func (c *Client) Download(ctx context.Context, key string) (*DownloadOutput, error) {
	fullKey := c.config.Prefix + key

	result, err := c.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.config.Bucket),
		Key:    aws.String(fullKey),
	})
	if err != nil {
		c.metrics.errors.Add(1)
		return nil, fmt.Errorf("s3: failed to download object %s: %w", fullKey, err)
	}

	size := aws.ToInt64(result.ContentLength)
	c.metrics.bytesDownloaded.Add(size)

	c.logger.Debug("downloaded object",
		"key", fullKey,
		"size", size,
	)

	return &DownloadOutput{
		Key:          fullKey,
		Body:         result.Body,
		ContentType:  aws.ToString(result.ContentType),
		Size:         size,
		LastModified: aws.ToTime(result.LastModified),
		Metadata:     result.Metadata,
	}, nil
}

// Delete deletes an object from S3.
func (c *Client) Delete(ctx context.Context, key string) error {
	fullKey := c.config.Prefix + key

	_, err := c.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(c.config.Bucket),
		Key:    aws.String(fullKey),
	})
	if err != nil {
		c.metrics.errors.Add(1)
		return fmt.Errorf("s3: failed to delete object %s: %w", fullKey, err)
	}

	c.metrics.objectsDeleted.Add(1)

	c.logger.Debug("deleted object", "key", fullKey)
	return nil
}

// DeleteBatch deletes multiple objects from S3.
func (c *Client) DeleteBatch(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}

	// S3 DeleteObjects supports up to 1000 keys per request
	const batchSize = 1000

	for i := 0; i < len(keys); i += batchSize {
		end := i + batchSize
		if end > len(keys) {
			end = len(keys)
		}

		batch := keys[i:end]
		objects := make([]types.ObjectIdentifier, len(batch))
		for j, key := range batch {
			fullKey := c.config.Prefix + key
			objects[j] = types.ObjectIdentifier{
				Key: aws.String(fullKey),
			}
		}

		_, err := c.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(c.config.Bucket),
			Delete: &types.Delete{
				Objects: objects,
				Quiet:   aws.Bool(true),
			},
		})
		if err != nil {
			c.metrics.errors.Add(1)
			return fmt.Errorf("s3: failed to delete batch: %w", err)
		}

		c.metrics.objectsDeleted.Add(int64(len(batch)))
	}

	c.logger.Debug("deleted batch", "count", len(keys))
	return nil
}

// ObjectInfo contains information about an S3 object.
type ObjectInfo struct {
	Key          string
	Size         int64
	LastModified time.Time
	ETag         string
	StorageClass string
}

// List lists objects with the given prefix.
func (c *Client) List(ctx context.Context, prefix string, maxKeys int) ([]ObjectInfo, error) {
	fullPrefix := c.config.Prefix + prefix

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(c.config.Bucket),
		Prefix: aws.String(fullPrefix),
	}

	if maxKeys > 0 {
		input.MaxKeys = aws.Int32(int32(maxKeys))
	}

	var objects []ObjectInfo
	paginator := s3.NewListObjectsV2Paginator(c.client, input)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			c.metrics.errors.Add(1)
			return nil, fmt.Errorf("s3: failed to list objects: %w", err)
		}

		for _, obj := range page.Contents {
			objects = append(objects, ObjectInfo{
				Key:          aws.ToString(obj.Key),
				Size:         aws.ToInt64(obj.Size),
				LastModified: aws.ToTime(obj.LastModified),
				ETag:         aws.ToString(obj.ETag),
				StorageClass: string(obj.StorageClass),
			})
		}

		if maxKeys > 0 && len(objects) >= maxKeys {
			objects = objects[:maxKeys]
			break
		}
	}

	return objects, nil
}

// Exists checks if an object exists.
func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	fullKey := c.config.Prefix + key

	_, err := c.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(c.config.Bucket),
		Key:    aws.String(fullKey),
	})
	if err != nil {
		// Check if it's a not found error
		var notFound *types.NotFound
		if errors.As(err, &notFound) {
			return false, nil
		}
		return false, fmt.Errorf("s3: failed to check object existence: %w", err)
	}

	return true, nil
}

// CopyInput contains parameters for copying an object.
type CopyInput struct {
	SourceKey      string
	DestKey        string
	StorageClass   string
	DeleteSource   bool
}

// Copy copies an object within S3.
func (c *Client) Copy(ctx context.Context, input *CopyInput) error {
	sourceKey := c.config.Prefix + input.SourceKey
	destKey := c.config.Prefix + input.DestKey

	copyInput := &s3.CopyObjectInput{
		Bucket:     aws.String(c.config.Bucket),
		CopySource: aws.String(fmt.Sprintf("%s/%s", c.config.Bucket, sourceKey)),
		Key:        aws.String(destKey),
	}

	if input.StorageClass != "" {
		tempCfg := &Config{StorageClass: input.StorageClass}
		copyInput.StorageClass = tempCfg.GetStorageClass()
	}

	_, err := c.client.CopyObject(ctx, copyInput)
	if err != nil {
		c.metrics.errors.Add(1)
		return fmt.Errorf("s3: failed to copy object: %w", err)
	}

	// Delete source if requested (move operation)
	if input.DeleteSource {
		if err := c.Delete(ctx, input.SourceKey); err != nil {
			return fmt.Errorf("s3: copy succeeded but failed to delete source: %w", err)
		}
	}

	c.logger.Debug("copied object",
		"source", sourceKey,
		"dest", destKey,
	)

	return nil
}

// RestoreInput contains parameters for restoring an archived object.
type RestoreInput struct {
	Key           string
	Days          int    // Number of days to keep restored copy
	Tier          string // Standard, Bulk, Expedited
}

// Restore initiates restoration of an archived object.
func (c *Client) Restore(ctx context.Context, input *RestoreInput) error {
	fullKey := c.config.Prefix + input.Key

	tier := types.TierStandard
	switch strings.ToLower(input.Tier) {
	case "bulk":
		tier = types.TierBulk
	case "expedited":
		tier = types.TierExpedited
	}

	_, err := c.client.RestoreObject(ctx, &s3.RestoreObjectInput{
		Bucket: aws.String(c.config.Bucket),
		Key:    aws.String(fullKey),
		RestoreRequest: &types.RestoreRequest{
			Days: aws.Int32(int32(input.Days)),
			GlacierJobParameters: &types.GlacierJobParameters{
				Tier: tier,
			},
		},
	})
	if err != nil {
		c.metrics.errors.Add(1)
		return fmt.Errorf("s3: failed to restore object %s: %w", fullKey, err)
	}

	c.logger.Info("initiated restore",
		"key", fullKey,
		"days", input.Days,
		"tier", tier,
	)

	return nil
}

// Metrics contains S3 client metrics.
type Metrics struct {
	BytesUploaded   int64
	BytesDownloaded int64
	ObjectsUploaded int64
	ObjectsDeleted  int64
	Errors          int64
}

// GetMetrics returns current client metrics.
func (c *Client) GetMetrics() Metrics {
	return Metrics{
		BytesUploaded:   c.metrics.bytesUploaded.Load(),
		BytesDownloaded: c.metrics.bytesDownloaded.Load(),
		ObjectsUploaded: c.metrics.objectsUploaded.Load(),
		ObjectsDeleted:  c.metrics.objectsDeleted.Load(),
		Errors:          c.metrics.errors.Load(),
	}
}

// HealthStatus represents the health of the S3 client.
type HealthStatus struct {
	Healthy       bool          `json:"healthy"`
	BucketExists  bool          `json:"bucket_exists"`
	Latency       time.Duration `json:"latency"`
	Error         string        `json:"error,omitempty"`
}

// HealthCheck verifies connectivity to S3.
func (c *Client) HealthCheck(ctx context.Context) HealthStatus {
	status := HealthStatus{}
	start := time.Now()

	_, err := c.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(c.config.Bucket),
	})

	status.Latency = time.Since(start)

	if err != nil {
		status.Error = err.Error()
		return status
	}

	status.Healthy = true
	status.BucketExists = true
	return status
}

// GetBucket returns the configured bucket name.
func (c *Client) GetBucket() string {
	return c.config.Bucket
}

// GetPrefix returns the configured key prefix.
func (c *Client) GetPrefix() string {
	return c.config.Prefix
}

// Pool manages a pool of S3 clients for concurrent operations.
type Pool struct {
	clients []*Client
	current atomic.Int32
	mu      sync.RWMutex
}

// NewPool creates a new client pool.
func NewPool(ctx context.Context, cfg *Config, logger *slog.Logger, size int) (*Pool, error) {
	if size < 1 {
		size = 1
	}

	clients := make([]*Client, size)
	for i := 0; i < size; i++ {
		client, err := NewClient(ctx, cfg, logger.With("pool_index", i))
		if err != nil {
			return nil, fmt.Errorf("s3: failed to create pool client %d: %w", i, err)
		}
		clients[i] = client
	}

	return &Pool{clients: clients}, nil
}

// Get returns a client from the pool using round-robin.
func (p *Pool) Get() *Client {
	p.mu.RLock()
	defer p.mu.RUnlock()

	idx := p.current.Add(1) % int32(len(p.clients))
	return p.clients[idx]
}
