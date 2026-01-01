package kafka

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/segmentio/kafka-go"
)

// Admin provides administrative operations for Kafka.
type Admin struct {
	config *Config
	logger *slog.Logger
}

// NewAdmin creates a new Kafka admin client.
func NewAdmin(config *Config, logger *slog.Logger) (*Admin, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &Admin{
		config: config,
		logger: logger,
	}, nil
}

// TopicConfig defines configuration for topic creation.
type TopicConfig struct {
	Name              string
	Partitions        int
	ReplicationFactor int
	RetentionMs       int64
	CleanupPolicy     string // "delete" or "compact"
	MinInsyncReplicas int
	MaxMessageBytes   int
}

// CreateTopic creates a new Kafka topic.
func (a *Admin) CreateTopic(ctx context.Context, cfg TopicConfig) error {
	dialer, err := a.config.GetDialer()
	if err != nil {
		return fmt.Errorf("kafka: failed to create dialer: %w", err)
	}

	conn, err := dialer.DialContext(ctx, "tcp", a.config.Brokers[0])
	if err != nil {
		return fmt.Errorf("kafka: failed to connect to broker: %w", err)
	}
	defer conn.Close()

	// Get controller
	controller, err := conn.Controller()
	if err != nil {
		return fmt.Errorf("kafka: failed to get controller: %w", err)
	}

	// Connect to controller
	controllerConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(controller.Host, fmt.Sprintf("%d", controller.Port)))
	if err != nil {
		return fmt.Errorf("kafka: failed to connect to controller: %w", err)
	}
	defer controllerConn.Close()

	// Build topic config entries
	configEntries := []kafka.ConfigEntry{
		{ConfigName: "retention.ms", ConfigValue: fmt.Sprintf("%d", cfg.RetentionMs)},
	}

	if cfg.CleanupPolicy != "" {
		configEntries = append(configEntries, kafka.ConfigEntry{
			ConfigName:  "cleanup.policy",
			ConfigValue: cfg.CleanupPolicy,
		})
	}

	if cfg.MinInsyncReplicas > 0 {
		configEntries = append(configEntries, kafka.ConfigEntry{
			ConfigName:  "min.insync.replicas",
			ConfigValue: fmt.Sprintf("%d", cfg.MinInsyncReplicas),
		})
	}

	if cfg.MaxMessageBytes > 0 {
		configEntries = append(configEntries, kafka.ConfigEntry{
			ConfigName:  "max.message.bytes",
			ConfigValue: fmt.Sprintf("%d", cfg.MaxMessageBytes),
		})
	}

	// Create topic
	err = controllerConn.CreateTopics(kafka.TopicConfig{
		Topic:             cfg.Name,
		NumPartitions:     cfg.Partitions,
		ReplicationFactor: cfg.ReplicationFactor,
		ConfigEntries:     configEntries,
	})

	if err != nil {
		return fmt.Errorf("kafka: failed to create topic %s: %w", cfg.Name, err)
	}

	a.logger.Info("kafka topic created",
		"topic", cfg.Name,
		"partitions", cfg.Partitions,
		"replication_factor", cfg.ReplicationFactor,
	)

	return nil
}

// DeleteTopic deletes a Kafka topic.
func (a *Admin) DeleteTopic(ctx context.Context, topic string) error {
	dialer, err := a.config.GetDialer()
	if err != nil {
		return fmt.Errorf("kafka: failed to create dialer: %w", err)
	}

	conn, err := dialer.DialContext(ctx, "tcp", a.config.Brokers[0])
	if err != nil {
		return fmt.Errorf("kafka: failed to connect to broker: %w", err)
	}
	defer conn.Close()

	// Get controller
	controller, err := conn.Controller()
	if err != nil {
		return fmt.Errorf("kafka: failed to get controller: %w", err)
	}

	// Connect to controller
	controllerConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(controller.Host, fmt.Sprintf("%d", controller.Port)))
	if err != nil {
		return fmt.Errorf("kafka: failed to connect to controller: %w", err)
	}
	defer controllerConn.Close()

	if err := controllerConn.DeleteTopics(topic); err != nil {
		return fmt.Errorf("kafka: failed to delete topic %s: %w", topic, err)
	}

	a.logger.Info("kafka topic deleted", "topic", topic)
	return nil
}

// ListTopics returns all topics in the cluster.
func (a *Admin) ListTopics(ctx context.Context) ([]string, error) {
	dialer, err := a.config.GetDialer()
	if err != nil {
		return nil, fmt.Errorf("kafka: failed to create dialer: %w", err)
	}

	conn, err := dialer.DialContext(ctx, "tcp", a.config.Brokers[0])
	if err != nil {
		return nil, fmt.Errorf("kafka: failed to connect to broker: %w", err)
	}
	defer conn.Close()

	partitions, err := conn.ReadPartitions()
	if err != nil {
		return nil, fmt.Errorf("kafka: failed to read partitions: %w", err)
	}

	topicMap := make(map[string]bool)
	for _, p := range partitions {
		topicMap[p.Topic] = true
	}

	topics := make([]string, 0, len(topicMap))
	for topic := range topicMap {
		topics = append(topics, topic)
	}

	return topics, nil
}

// TopicInfo contains information about a topic.
type TopicInfo struct {
	Name       string
	Partitions []PartitionInfo
}

// PartitionInfo contains information about a partition.
type PartitionInfo struct {
	ID       int
	Leader   int
	Replicas []int
	ISR      []int
}

// DescribeTopic returns detailed information about a topic.
func (a *Admin) DescribeTopic(ctx context.Context, topic string) (*TopicInfo, error) {
	dialer, err := a.config.GetDialer()
	if err != nil {
		return nil, fmt.Errorf("kafka: failed to create dialer: %w", err)
	}

	conn, err := dialer.DialContext(ctx, "tcp", a.config.Brokers[0])
	if err != nil {
		return nil, fmt.Errorf("kafka: failed to connect to broker: %w", err)
	}
	defer conn.Close()

	partitions, err := conn.ReadPartitions(topic)
	if err != nil {
		return nil, fmt.Errorf("kafka: failed to read partitions for %s: %w", topic, err)
	}

	info := &TopicInfo{
		Name:       topic,
		Partitions: make([]PartitionInfo, len(partitions)),
	}

	for i, p := range partitions {
		replicas := make([]int, len(p.Replicas))
		for j, r := range p.Replicas {
			replicas[j] = r.ID
		}

		isr := make([]int, len(p.Isr))
		for j, r := range p.Isr {
			isr[j] = r.ID
		}

		info.Partitions[i] = PartitionInfo{
			ID:       p.ID,
			Leader:   p.Leader.ID,
			Replicas: replicas,
			ISR:      isr,
		}
	}

	return info, nil
}

// BrokerInfo contains information about a broker.
type BrokerInfo struct {
	ID   int
	Host string
	Port int
}

// ListBrokers returns all brokers in the cluster.
func (a *Admin) ListBrokers(ctx context.Context) ([]BrokerInfo, error) {
	dialer, err := a.config.GetDialer()
	if err != nil {
		return nil, fmt.Errorf("kafka: failed to create dialer: %w", err)
	}

	conn, err := dialer.DialContext(ctx, "tcp", a.config.Brokers[0])
	if err != nil {
		return nil, fmt.Errorf("kafka: failed to connect to broker: %w", err)
	}
	defer conn.Close()

	brokers, err := conn.Brokers()
	if err != nil {
		return nil, fmt.Errorf("kafka: failed to get brokers: %w", err)
	}

	result := make([]BrokerInfo, len(brokers))
	for i, b := range brokers {
		result[i] = BrokerInfo{
			ID:   b.ID,
			Host: b.Host,
			Port: b.Port,
		}
	}

	return result, nil
}

// GetOffsets returns the earliest and latest offsets for a topic partition.
func (a *Admin) GetOffsets(ctx context.Context, topic string, partition int) (earliest, latest int64, err error) {
	dialer, err := a.config.GetDialer()
	if err != nil {
		return 0, 0, fmt.Errorf("kafka: failed to create dialer: %w", err)
	}

	conn, err := dialer.DialLeader(ctx, "tcp", a.config.Brokers[0], topic, partition)
	if err != nil {
		return 0, 0, fmt.Errorf("kafka: failed to connect to partition leader: %w", err)
	}
	defer conn.Close()

	earliest, err = conn.ReadFirstOffset()
	if err != nil {
		return 0, 0, fmt.Errorf("kafka: failed to read first offset: %w", err)
	}

	latest, err = conn.ReadLastOffset()
	if err != nil {
		return 0, 0, fmt.Errorf("kafka: failed to read last offset: %w", err)
	}

	return earliest, latest, nil
}

// ConsumerGroupInfo contains information about a consumer group.
type ConsumerGroupInfo struct {
	GroupID     string
	State       string
	Members     int
	Coordinator BrokerInfo
}

// EnsureTopic creates a topic if it doesn't exist.
func (a *Admin) EnsureTopic(ctx context.Context, cfg TopicConfig) error {
	topics, err := a.ListTopics(ctx)
	if err != nil {
		return err
	}

	for _, t := range topics {
		if t == cfg.Name {
			a.logger.Debug("topic already exists", "topic", cfg.Name)
			return nil
		}
	}

	return a.CreateTopic(ctx, cfg)
}

// HealthCheck performs a health check on the Kafka cluster.
func (a *Admin) HealthCheck(ctx context.Context) HealthStatus {
	status := HealthStatus{
		LastCheck: time.Now(),
	}

	start := time.Now()

	brokers, err := a.ListBrokers(ctx)
	if err != nil {
		status.Error = err.Error()
		return status
	}

	status.Latency = time.Since(start)
	status.Connected = true
	status.Healthy = len(brokers) > 0
	status.BrokerCount = len(brokers)

	return status
}
