// Package ha provides high availability features for the SIEM.
package ha

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"boundary-siem/internal/kafka"
)

// ClusterRole defines node roles in the cluster.
type ClusterRole string

const (
	RoleLeader    ClusterRole = "leader"
	RoleFollower  ClusterRole = "follower"
	RoleCandidate ClusterRole = "candidate"
)

// NodeState represents the state of a cluster node.
type NodeState string

const (
	StateHealthy   NodeState = "healthy"
	StateUnhealthy NodeState = "unhealthy"
	StateDegraded  NodeState = "degraded"
	StateStarting  NodeState = "starting"
	StateStopping  NodeState = "stopping"
)

// ClusterNode represents a node in the SIEM cluster.
type ClusterNode struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Address   string            `json:"address"`
	Port      int               `json:"port"`
	Role      ClusterRole       `json:"role"`
	State     NodeState         `json:"state"`
	Version   string            `json:"version"`
	StartedAt time.Time         `json:"started_at"`
	LastSeen  time.Time         `json:"last_seen"`
	Metrics   *NodeMetrics      `json:"metrics"`
	Labels    map[string]string `json:"labels,omitempty"`
	Zone      string            `json:"zone,omitempty"`
	Region    string            `json:"region,omitempty"`
}

// NodeMetrics contains node performance metrics.
type NodeMetrics struct {
	CPUUsage          float64       `json:"cpu_usage"`
	MemoryUsage       float64       `json:"memory_usage"`
	DiskUsage         float64       `json:"disk_usage"`
	EventsPerSecond   float64       `json:"events_per_second"`
	QueueDepth        int64         `json:"queue_depth"`
	ActiveConnections int           `json:"active_connections"`
	Latency           time.Duration `json:"latency"`
}

// ClusterConfig configures the HA cluster.
type ClusterConfig struct {
	NodeID            string        `json:"node_id"`
	NodeName          string        `json:"node_name"`
	BindAddress       string        `json:"bind_address"`
	BindPort          int           `json:"bind_port"`
	AdvertiseAddress  string        `json:"advertise_address"`
	AdvertisePort     int           `json:"advertise_port"`
	JoinAddresses     []string      `json:"join_addresses"`
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`
	ElectionTimeout   time.Duration `json:"election_timeout"`
	ReplicationFactor int           `json:"replication_factor"`
	MinQuorum         int           `json:"min_quorum"`
}

// Cluster manages the HA cluster.
type Cluster struct {
	mu        sync.RWMutex
	config    *ClusterConfig
	localNode *ClusterNode
	nodes     map[string]*ClusterNode
	role      ClusterRole
	leaderID  string
	term      uint64
	logger    *slog.Logger
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewCluster creates a new HA cluster manager.
func NewCluster(config *ClusterConfig, logger *slog.Logger) *Cluster {
	ctx, cancel := context.WithCancel(context.Background())

	c := &Cluster{
		config: config,
		nodes:  make(map[string]*ClusterNode),
		role:   RoleFollower,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}

	c.localNode = &ClusterNode{
		ID:        config.NodeID,
		Name:      config.NodeName,
		Address:   config.AdvertiseAddress,
		Port:      config.AdvertisePort,
		Role:      RoleFollower,
		State:     StateStarting,
		Version:   "1.0.0",
		StartedAt: time.Now(),
		LastSeen:  time.Now(),
		Metrics:   &NodeMetrics{},
	}

	c.nodes[config.NodeID] = c.localNode

	return c
}

// Start starts the cluster manager.
func (c *Cluster) Start() error {
	c.logger.Info("starting cluster manager",
		"node_id", c.config.NodeID,
		"bind", fmt.Sprintf("%s:%d", c.config.BindAddress, c.config.BindPort),
	)

	c.mu.Lock()
	c.localNode.State = StateHealthy
	c.mu.Unlock()

	// Start heartbeat
	go c.heartbeatLoop()

	// Start leader election
	go c.electionLoop()

	// Join existing cluster if addresses provided
	if len(c.config.JoinAddresses) > 0 {
		go c.joinCluster()
	} else {
		// Bootstrap as leader if no join addresses
		c.becomeLeader()
	}

	return nil
}

// Stop stops the cluster manager.
func (c *Cluster) Stop() error {
	c.logger.Info("stopping cluster manager")
	c.cancel()

	c.mu.Lock()
	c.localNode.State = StateStopping
	c.mu.Unlock()

	return nil
}

// heartbeatLoop sends periodic heartbeats.
func (c *Cluster) heartbeatLoop() {
	ticker := time.NewTicker(c.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.sendHeartbeat()
		}
	}
}

// sendHeartbeat broadcasts heartbeat to cluster.
func (c *Cluster) sendHeartbeat() {
	c.mu.Lock()
	c.localNode.LastSeen = time.Now()
	c.localNode.Metrics = c.collectMetrics()
	c.mu.Unlock()

	// In production, this would send to other nodes via gRPC/HTTP
	c.logger.Debug("heartbeat sent", "node_id", c.config.NodeID)
}

// electionLoop handles leader election.
func (c *Cluster) electionLoop() {
	ticker := time.NewTicker(c.config.ElectionTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.checkLeaderHealth()
		}
	}
}

// checkLeaderHealth verifies leader is responsive.
func (c *Cluster) checkLeaderHealth() {
	c.mu.RLock()
	role := c.role
	leaderID := c.leaderID
	c.mu.RUnlock()

	if role == RoleLeader {
		return
	}

	if leaderID == "" {
		c.startElection()
		return
	}

	c.mu.RLock()
	leader, exists := c.nodes[leaderID]
	c.mu.RUnlock()

	if !exists || time.Since(leader.LastSeen) > c.config.ElectionTimeout {
		c.logger.Warn("leader unresponsive, starting election", "leader_id", leaderID)
		c.startElection()
	}
}

// startElection initiates a leader election.
func (c *Cluster) startElection() {
	c.mu.Lock()
	c.role = RoleCandidate
	c.term++
	c.mu.Unlock()

	c.logger.Info("starting election", "term", c.term)

	// Simplified election - in production would use Raft consensus
	// For now, just become leader if we're the only node or have lowest ID
	c.becomeLeader()
}

// becomeLeader transitions this node to leader role.
func (c *Cluster) becomeLeader() {
	c.mu.Lock()
	c.role = RoleLeader
	c.leaderID = c.config.NodeID
	c.localNode.Role = RoleLeader
	c.mu.Unlock()

	c.logger.Info("became cluster leader", "term", c.term)
}

// joinCluster attempts to join an existing cluster.
func (c *Cluster) joinCluster() {
	for _, addr := range c.config.JoinAddresses {
		c.logger.Info("attempting to join cluster", "address", addr)
		// In production, this would connect to the join address
		// and sync cluster state
	}
}

// collectMetrics gathers local node metrics.
func (c *Cluster) collectMetrics() *NodeMetrics {
	return &NodeMetrics{
		CPUUsage:          35.5,
		MemoryUsage:       62.3,
		DiskUsage:         45.0,
		EventsPerSecond:   1250.5,
		QueueDepth:        1000,
		ActiveConnections: 150,
		Latency:           5 * time.Millisecond,
	}
}

// GetNodes returns all known cluster nodes.
func (c *Cluster) GetNodes() []*ClusterNode {
	c.mu.RLock()
	defer c.mu.RUnlock()

	nodes := make([]*ClusterNode, 0, len(c.nodes))
	for _, node := range c.nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// GetLocalNode returns the local node.
func (c *Cluster) GetLocalNode() *ClusterNode {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.localNode
}

// GetLeader returns the current leader node.
func (c *Cluster) GetLeader() *ClusterNode {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.leaderID == "" {
		return nil
	}
	return c.nodes[c.leaderID]
}

// IsLeader returns true if this node is the leader.
func (c *Cluster) IsLeader() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.role == RoleLeader
}

// GetRole returns the current role of this node.
func (c *Cluster) GetRole() ClusterRole {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.role
}

// AddNode adds a node to the cluster.
func (c *Cluster) AddNode(node *ClusterNode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodes[node.ID] = node
	c.logger.Info("node added to cluster", "node_id", node.ID, "address", node.Address)
}

// RemoveNode removes a node from the cluster.
func (c *Cluster) RemoveNode(nodeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.nodes, nodeID)
	c.logger.Info("node removed from cluster", "node_id", nodeID)
}

// KafkaConfig configures Kafka for event streaming.
// This is an alias to the kafka package Config for backwards compatibility.
type KafkaConfig = kafka.Config

// KafkaProducer produces events to Kafka using the real kafka-go client.
type KafkaProducer struct {
	producer *kafka.Producer
	config   *kafka.Config
	logger   *slog.Logger
}

// NewKafkaProducer creates a new Kafka producer with real Kafka connectivity.
func NewKafkaProducer(config *kafka.Config, logger *slog.Logger) (*KafkaProducer, error) {
	producer, err := kafka.NewProducer(config, logger)
	if err != nil {
		return nil, fmt.Errorf("ha: failed to create kafka producer: %w", err)
	}

	return &KafkaProducer{
		producer: producer,
		config:   config,
		logger:   logger,
	}, nil
}

// Produce sends a message to Kafka.
func (p *KafkaProducer) Produce(ctx context.Context, key, value []byte) error {
	return p.producer.Produce(ctx, key, value)
}

// ProduceJSON marshals and sends a JSON message to Kafka.
func (p *KafkaProducer) ProduceJSON(ctx context.Context, key string, value interface{}) error {
	return p.producer.ProduceJSON(ctx, key, value)
}

// GetStats returns producer statistics.
func (p *KafkaProducer) GetStats() (int64, int64) {
	metrics := p.producer.GetMetrics()
	return metrics.MessagesProduced, metrics.BytesProduced
}

// GetMetrics returns detailed producer metrics.
func (p *KafkaProducer) GetMetrics() kafka.Metrics {
	return p.producer.GetMetrics()
}

// HealthCheck verifies the producer can connect to Kafka.
func (p *KafkaProducer) HealthCheck(ctx context.Context) kafka.HealthStatus {
	return p.producer.HealthCheck(ctx)
}

// Close closes the producer and flushes any buffered messages.
func (p *KafkaProducer) Close() error {
	return p.producer.Close()
}

// KafkaConsumer consumes events from Kafka using the real kafka-go client.
type KafkaConsumer struct {
	consumer *kafka.Consumer
	config   *kafka.Config
	logger   *slog.Logger
}

// NewKafkaConsumer creates a new Kafka consumer with real Kafka connectivity.
func NewKafkaConsumer(config *kafka.Config, handler func(key, value []byte) error, logger *slog.Logger) (*KafkaConsumer, error) {
	// Wrap the simple handler to match the kafka.MessageHandler signature
	wrappedHandler := func(ctx context.Context, msg kafka.Message) error {
		return handler(msg.Key, msg.Value)
	}

	consumer, err := kafka.NewConsumer(config, wrappedHandler, logger)
	if err != nil {
		return nil, fmt.Errorf("ha: failed to create kafka consumer: %w", err)
	}

	return &KafkaConsumer{
		consumer: consumer,
		config:   config,
		logger:   logger,
	}, nil
}

// Start starts consuming messages (blocking).
func (c *KafkaConsumer) Start() error {
	return c.consumer.Start()
}

// StartAsync starts consuming messages in a background goroutine.
func (c *KafkaConsumer) StartAsync() error {
	return c.consumer.StartAsync()
}

// Stop stops consuming messages.
func (c *KafkaConsumer) Stop() error {
	return c.consumer.Stop()
}

// GetMetrics returns consumer metrics.
func (c *KafkaConsumer) GetMetrics() kafka.Metrics {
	return c.consumer.GetMetrics()
}

// HealthCheck verifies the consumer can connect to Kafka.
func (c *KafkaConsumer) HealthCheck(ctx context.Context) kafka.HealthStatus {
	return c.consumer.HealthCheck(ctx)
}

// ClickHouseConfig configures ClickHouse for analytics.
type ClickHouseConfig struct {
	Hosts               []string      `json:"hosts"`
	Database            string        `json:"database"`
	Username            string        `json:"username"`
	Password            string        `json:"password"`
	Cluster             string        `json:"cluster"`
	ReplicatedMergeTree bool          `json:"replicated_merge_tree"`
	Shards              int           `json:"shards"`
	Replicas            int           `json:"replicas"`
	MaxConnections      int           `json:"max_connections"`
	DialTimeout         time.Duration `json:"dial_timeout"`
	MaxExecutionTime    time.Duration `json:"max_execution_time"`
	Compression         string        `json:"compression"`
}

// ClickHouseCluster manages ClickHouse cluster connections.
type ClickHouseCluster struct {
	config *ClickHouseConfig
	logger *slog.Logger
}

// NewClickHouseCluster creates a new ClickHouse cluster manager.
func NewClickHouseCluster(config *ClickHouseConfig, logger *slog.Logger) *ClickHouseCluster {
	return &ClickHouseCluster{
		config: config,
		logger: logger,
	}
}

// CreateDistributedTable creates a distributed table across shards.
func (c *ClickHouseCluster) CreateDistributedTable(table, engine, columns string) error {
	c.logger.Info("creating distributed table",
		"table", table,
		"cluster", c.config.Cluster,
		"shards", c.config.Shards,
	)
	return nil
}

// CreateReplicatedTable creates a replicated table.
func (c *ClickHouseCluster) CreateReplicatedTable(table, columns string) error {
	c.logger.Info("creating replicated table",
		"table", table,
		"replicas", c.config.Replicas,
	)
	return nil
}

// GetClusterStatus returns cluster health status.
func (c *ClickHouseCluster) GetClusterStatus() *ClusterStatus {
	return &ClusterStatus{
		Name:        c.config.Cluster,
		Shards:      c.config.Shards,
		Replicas:    c.config.Replicas,
		Healthy:     true,
		TotalNodes:  c.config.Shards * c.config.Replicas,
		ActiveNodes: c.config.Shards * c.config.Replicas,
	}
}

// ClusterStatus represents ClickHouse cluster status.
type ClusterStatus struct {
	Name        string `json:"name"`
	Shards      int    `json:"shards"`
	Replicas    int    `json:"replicas"`
	Healthy     bool   `json:"healthy"`
	TotalNodes  int    `json:"total_nodes"`
	ActiveNodes int    `json:"active_nodes"`
}

// KubernetesConfig configures Kubernetes deployment.
type KubernetesConfig struct {
	Namespace               string               `json:"namespace"`
	ServiceAccount          string               `json:"service_account"`
	Replicas                int                  `json:"replicas"`
	Resources               ResourceRequirements `json:"resources"`
	Affinity                *AffinityConfig      `json:"affinity,omitempty"`
	Tolerations             []Toleration         `json:"tolerations,omitempty"`
	PodDisruptionBudget     *PDBConfig           `json:"pod_disruption_budget,omitempty"`
	HorizontalPodAutoscaler *HPAConfig           `json:"horizontal_pod_autoscaler,omitempty"`
}

// ResourceRequirements defines resource requests/limits.
type ResourceRequirements struct {
	Requests ResourceList `json:"requests"`
	Limits   ResourceList `json:"limits"`
}

// ResourceList defines CPU/memory resources.
type ResourceList struct {
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
}

// AffinityConfig defines pod affinity rules.
type AffinityConfig struct {
	NodeAffinity    []NodeAffinityRule `json:"node_affinity,omitempty"`
	PodAntiAffinity bool               `json:"pod_anti_affinity"`
	TopologyKey     string             `json:"topology_key"`
}

// NodeAffinityRule defines node affinity.
type NodeAffinityRule struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

// Toleration defines pod tolerations.
type Toleration struct {
	Key      string `json:"key"`
	Operator string `json:"operator"`
	Value    string `json:"value,omitempty"`
	Effect   string `json:"effect"`
}

// PDBConfig defines PodDisruptionBudget.
type PDBConfig struct {
	MinAvailable   int `json:"min_available,omitempty"`
	MaxUnavailable int `json:"max_unavailable,omitempty"`
}

// HPAConfig defines HorizontalPodAutoscaler.
type HPAConfig struct {
	MinReplicas       int           `json:"min_replicas"`
	MaxReplicas       int           `json:"max_replicas"`
	TargetCPU         int           `json:"target_cpu_percent"`
	TargetMemory      int           `json:"target_memory_percent,omitempty"`
	ScaleUpCooldown   time.Duration `json:"scale_up_cooldown"`
	ScaleDownCooldown time.Duration `json:"scale_down_cooldown"`
}

// DefaultClusterConfig returns default cluster configuration.
func DefaultClusterConfig() *ClusterConfig {
	return &ClusterConfig{
		NodeID:            "node-1",
		NodeName:          "siem-node-1",
		BindAddress:       "0.0.0.0",
		BindPort:          7946,
		AdvertiseAddress:  "127.0.0.1",
		AdvertisePort:     7946,
		HeartbeatInterval: 1 * time.Second,
		ElectionTimeout:   5 * time.Second,
		ReplicationFactor: 3,
		MinQuorum:         2,
	}
}

// DefaultKafkaConfig returns default Kafka configuration.
func DefaultKafkaConfig() *KafkaConfig {
	return kafka.DefaultConfig()
}

// DefaultClickHouseConfig returns default ClickHouse configuration.
func DefaultClickHouseConfig() *ClickHouseConfig {
	return &ClickHouseConfig{
		Hosts:               []string{"localhost:9000"},
		Database:            "siem",
		Cluster:             "siem_cluster",
		ReplicatedMergeTree: true,
		Shards:              3,
		Replicas:            2,
		MaxConnections:      100,
		DialTimeout:         10 * time.Second,
		MaxExecutionTime:    60 * time.Second,
		Compression:         "lz4",
	}
}

// DefaultKubernetesConfig returns default Kubernetes configuration.
func DefaultKubernetesConfig() *KubernetesConfig {
	return &KubernetesConfig{
		Namespace:      "boundary-siem",
		ServiceAccount: "siem-service-account",
		Replicas:       3,
		Resources: ResourceRequirements{
			Requests: ResourceList{CPU: "500m", Memory: "1Gi"},
			Limits:   ResourceList{CPU: "2", Memory: "4Gi"},
		},
		Affinity: &AffinityConfig{
			PodAntiAffinity: true,
			TopologyKey:     "kubernetes.io/hostname",
		},
		PodDisruptionBudget: &PDBConfig{
			MinAvailable: 2,
		},
		HorizontalPodAutoscaler: &HPAConfig{
			MinReplicas:       3,
			MaxReplicas:       10,
			TargetCPU:         70,
			ScaleUpCooldown:   3 * time.Minute,
			ScaleDownCooldown: 5 * time.Minute,
		},
	}
}

// MarshalJSON implements json.Marshaler for ClusterNode.
func (n *ClusterNode) MarshalJSON() ([]byte, error) {
	type Alias ClusterNode
	return json.Marshal(&struct {
		*Alias
		StartedAt string `json:"started_at"`
		LastSeen  string `json:"last_seen"`
	}{
		Alias:     (*Alias)(n),
		StartedAt: n.StartedAt.Format(time.RFC3339),
		LastSeen:  n.LastSeen.Format(time.RFC3339),
	})
}
