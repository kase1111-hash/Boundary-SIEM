package enterprise

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"boundary-siem/internal/enterprise/api"
	"boundary-siem/internal/enterprise/ha"
	"boundary-siem/internal/enterprise/retention"
)

// High Availability Tests

func TestCluster(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	config := ha.DefaultClusterConfig()
	config.NodeID = "test-node-1"
	config.NodeName = "test-node-1"

	cluster := ha.NewCluster(config, logger)

	t.Run("Start", func(t *testing.T) {
		err := cluster.Start()
		if err != nil {
			t.Fatalf("failed to start cluster: %v", err)
		}
		defer cluster.Stop()

		// Give time for initialization
		time.Sleep(100 * time.Millisecond)

		if cluster.GetRole() != ha.RoleLeader {
			t.Errorf("expected role leader, got %s", cluster.GetRole())
		}
	})

	t.Run("GetLocalNode", func(t *testing.T) {
		node := cluster.GetLocalNode()
		if node == nil {
			t.Fatal("expected local node, got nil")
		}
		if node.ID != "test-node-1" {
			t.Errorf("expected node ID 'test-node-1', got '%s'", node.ID)
		}
	})

	t.Run("GetNodes", func(t *testing.T) {
		nodes := cluster.GetNodes()
		if len(nodes) == 0 {
			t.Error("expected at least one node")
		}
	})

	t.Run("IsLeader", func(t *testing.T) {
		if !cluster.IsLeader() {
			t.Error("expected to be leader")
		}
	})

	t.Run("AddNode", func(t *testing.T) {
		newNode := &ha.ClusterNode{
			ID:      "test-node-2",
			Name:    "test-node-2",
			Address: "127.0.0.2",
			Port:    7946,
			Role:    ha.RoleFollower,
			State:   ha.StateHealthy,
		}
		cluster.AddNode(newNode)

		nodes := cluster.GetNodes()
		if len(nodes) != 2 {
			t.Errorf("expected 2 nodes, got %d", len(nodes))
		}
	})

	t.Run("RemoveNode", func(t *testing.T) {
		cluster.RemoveNode("test-node-2")
		nodes := cluster.GetNodes()
		if len(nodes) != 1 {
			t.Errorf("expected 1 node, got %d", len(nodes))
		}
	})
}

func TestKafkaProducer(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	config := ha.DefaultKafkaConfig()

	producer := ha.NewKafkaProducer(config, logger)

	t.Run("Produce", func(t *testing.T) {
		err := producer.Produce([]byte("key"), []byte("value"))
		if err != nil {
			t.Fatalf("failed to produce: %v", err)
		}
	})

	t.Run("GetStats", func(t *testing.T) {
		msgCount, byteCount := producer.GetStats()
		if msgCount != 1 {
			t.Errorf("expected 1 message, got %d", msgCount)
		}
		if byteCount != 5 {
			t.Errorf("expected 5 bytes, got %d", byteCount)
		}
	})
}

func TestClickHouseCluster(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	config := ha.DefaultClickHouseConfig()

	chCluster := ha.NewClickHouseCluster(config, logger)

	t.Run("GetClusterStatus", func(t *testing.T) {
		status := chCluster.GetClusterStatus()
		if status == nil {
			t.Fatal("expected status, got nil")
		}
		if status.Shards != 3 {
			t.Errorf("expected 3 shards, got %d", status.Shards)
		}
		if status.Replicas != 2 {
			t.Errorf("expected 2 replicas, got %d", status.Replicas)
		}
	})

	t.Run("CreateDistributedTable", func(t *testing.T) {
		err := chCluster.CreateDistributedTable("events", "MergeTree", "id, timestamp, action")
		if err != nil {
			t.Fatalf("failed to create table: %v", err)
		}
	})
}

func TestDefaultConfigs(t *testing.T) {
	t.Run("ClusterConfig", func(t *testing.T) {
		config := ha.DefaultClusterConfig()
		if config.ReplicationFactor != 3 {
			t.Errorf("expected replication factor 3, got %d", config.ReplicationFactor)
		}
	})

	t.Run("KafkaConfig", func(t *testing.T) {
		config := ha.DefaultKafkaConfig()
		if config.Partitions != 12 {
			t.Errorf("expected 12 partitions, got %d", config.Partitions)
		}
	})

	t.Run("ClickHouseConfig", func(t *testing.T) {
		config := ha.DefaultClickHouseConfig()
		if config.Shards != 3 {
			t.Errorf("expected 3 shards, got %d", config.Shards)
		}
	})

	t.Run("KubernetesConfig", func(t *testing.T) {
		config := ha.DefaultKubernetesConfig()
		if config.Replicas != 3 {
			t.Errorf("expected 3 replicas, got %d", config.Replicas)
		}
		if config.HorizontalPodAutoscaler == nil {
			t.Error("expected HPA config")
		}
	})
}

// Retention Tests

func TestRetentionManager(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	archiveConfig := retention.DefaultArchiveConfig()

	rm := retention.NewRetentionManager(archiveConfig, logger)

	t.Run("GetAllPolicies", func(t *testing.T) {
		policies := rm.GetAllPolicies()
		if len(policies) < 5 {
			t.Errorf("expected at least 5 policies, got %d", len(policies))
		}
	})

	t.Run("GetPolicy", func(t *testing.T) {
		policy, exists := rm.GetPolicy("events-default")
		if !exists {
			t.Error("expected policy to exist")
		}
		if policy != nil && len(policy.Rules) == 0 {
			t.Error("expected policy to have rules")
		}
	})

	t.Run("CreatePolicy", func(t *testing.T) {
		policy := &retention.RetentionPolicy{
			ID:       "test-policy",
			Name:     "Test Policy",
			DataType: "test",
			Enabled:  true,
			Rules: []retention.RetentionRule{
				{Tier: retention.TierHot, MaxAge: 24 * time.Hour},
			},
		}
		err := rm.CreatePolicy(policy)
		if err != nil {
			t.Fatalf("failed to create policy: %v", err)
		}

		created, exists := rm.GetPolicy("test-policy")
		if !exists {
			t.Error("expected created policy to exist")
		}
		if created != nil && created.Name != "Test Policy" {
			t.Errorf("expected name 'Test Policy', got '%s'", created.Name)
		}
	})

	t.Run("UpdatePolicy", func(t *testing.T) {
		policy, _ := rm.GetPolicy("test-policy")
		policy.Name = "Updated Test Policy"
		err := rm.UpdatePolicy(policy)
		if err != nil {
			t.Fatalf("failed to update policy: %v", err)
		}

		updated, _ := rm.GetPolicy("test-policy")
		if updated.Name != "Updated Test Policy" {
			t.Errorf("expected name 'Updated Test Policy', got '%s'", updated.Name)
		}
	})

	t.Run("DeletePolicy", func(t *testing.T) {
		err := rm.DeletePolicy("test-policy")
		if err != nil {
			t.Fatalf("failed to delete policy: %v", err)
		}

		_, exists := rm.GetPolicy("test-policy")
		if exists {
			t.Error("expected policy to be deleted")
		}
	})

	t.Run("GetStorageStats", func(t *testing.T) {
		stats, exists := rm.GetStorageStats(retention.TierHot)
		if !exists {
			t.Error("expected hot tier stats to exist")
		}
		if stats != nil && stats.TotalBytes == 0 {
			t.Error("expected non-zero total bytes")
		}
	})

	t.Run("GetAllStorageStats", func(t *testing.T) {
		allStats := rm.GetAllStorageStats()
		if len(allStats) < 4 {
			t.Errorf("expected 4 tiers, got %d", len(allStats))
		}
	})

	t.Run("CreateArchiveJob", func(t *testing.T) {
		job, err := rm.CreateArchiveJob("events-default", retention.TierWarm, retention.TierCold)
		if err != nil {
			t.Fatalf("failed to create archive job: %v", err)
		}
		if job.Status != retention.JobStatusPending {
			t.Errorf("expected status 'pending', got '%s'", job.Status)
		}
	})

	t.Run("Archive", func(t *testing.T) {
		job, err := rm.Archive("events", time.Now().AddDate(0, -1, 0), time.Now())
		if err != nil {
			t.Fatalf("failed to create archive: %v", err)
		}
		if job == nil {
			t.Error("expected job, got nil")
		}
	})
}

func TestStorageTiers(t *testing.T) {
	tiers := []retention.StorageTier{
		retention.TierHot,
		retention.TierWarm,
		retention.TierCold,
		retention.TierFrozen,
	}

	for _, tier := range tiers {
		if tier == "" {
			t.Errorf("empty tier name")
		}
	}
}

func TestRetentionRules(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	rm := retention.NewRetentionManager(nil, logger)

	policies := rm.GetAllPolicies()
	for _, policy := range policies {
		t.Run(policy.ID, func(t *testing.T) {
			if len(policy.Rules) == 0 {
				t.Error("expected policy to have rules")
			}
			for _, rule := range policy.Rules {
				if rule.MaxAge == 0 {
					t.Error("expected non-zero max age")
				}
			}
		})
	}
}

// API Framework Tests

func TestRouter(t *testing.T) {
	router := api.NewRouter(api.APIVersionV1)

	t.Run("AddRoutes", func(t *testing.T) {
		router.GET("/events", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("events"))
		}, api.WithDescription("Get events"), api.WithTags("events"))

		router.POST("/alerts", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("created"))
		}, api.WithAuth(true, "create_alerts"))

		routes := router.GetRoutes()
		if len(routes) != 2 {
			t.Errorf("expected 2 routes, got %d", len(routes))
		}
	})

	t.Run("ServeHTTP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/events", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
		if rec.Body.String() != "events" {
			t.Errorf("expected 'events', got '%s'", rec.Body.String())
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/unknown", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", rec.Code)
		}
	})
}

func TestGraphQLSchema(t *testing.T) {
	schema := api.NewSIEMGraphQLSchema()

	t.Run("Query", func(t *testing.T) {
		if schema.Query == nil {
			t.Fatal("expected query object")
		}
		if len(schema.Query.Fields) == 0 {
			t.Error("expected query fields")
		}

		expectedFields := []string{"events", "alerts", "validators", "incidents", "complianceScore", "threatLevel"}
		for _, field := range expectedFields {
			if _, exists := schema.Query.Fields[field]; !exists {
				t.Errorf("expected query field '%s'", field)
			}
		}
	})

	t.Run("Mutation", func(t *testing.T) {
		if schema.Mutation == nil {
			t.Fatal("expected mutation object")
		}
		if len(schema.Mutation.Fields) == 0 {
			t.Error("expected mutation fields")
		}
	})

	t.Run("Subscription", func(t *testing.T) {
		if schema.Subscription == nil {
			t.Fatal("expected subscription object")
		}
		if len(schema.Subscription.Fields) == 0 {
			t.Error("expected subscription fields")
		}
	})

	t.Run("Types", func(t *testing.T) {
		if len(schema.Types) == 0 {
			t.Error("expected types")
		}

		eventType, exists := schema.Types["Event"]
		if !exists {
			t.Error("expected Event type")
		}
		if eventType != nil && len(eventType.Fields) == 0 {
			t.Error("expected Event fields")
		}
	})
}

func TestGraphQLHandler(t *testing.T) {
	schema := api.NewSIEMGraphQLSchema()
	handler := api.NewGraphQLHandler(schema)

	t.Run("POST", func(t *testing.T) {
		body := `{"query": "{ events { id } }"}`
		req := httptest.NewRequest("POST", "/graphql", nil)
		req.Body = http.NoBody
		req = httptest.NewRequest("POST", "/graphql", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
	})

	t.Run("GET", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/graphql?query={events{id}}", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
	})
}

func TestSDKGenerator(t *testing.T) {
	schema := api.NewSIEMGraphQLSchema()
	routes := []*api.Route{
		{Method: "GET", Path: "/events", Description: "Get events"},
		{Method: "POST", Path: "/alerts", Description: "Create alert"},
	}
	generator := api.NewSDKGenerator(schema, routes)

	languages := api.SupportedLanguages()
	for _, lang := range languages {
		t.Run(lang, func(t *testing.T) {
			config := &api.SDKConfig{
				Language:    lang,
				PackageName: "siem",
				Version:     "1.0.0",
			}
			sdk, err := generator.Generate(config)
			if err != nil {
				t.Fatalf("failed to generate %s SDK: %v", lang, err)
			}
			if len(sdk.Files) == 0 {
				t.Errorf("expected SDK files for %s", lang)
			}
		})
	}
}

func TestOpenAPISpec(t *testing.T) {
	routes := []*api.Route{
		{Method: "GET", Path: "/events", Description: "Get events", Tags: []string{"events"}},
		{Method: "POST", Path: "/alerts", Description: "Create alert", Tags: []string{"alerts"}},
	}

	spec := api.GenerateOpenAPISpec(routes)

	if spec["openapi"] != "3.0.3" {
		t.Errorf("expected OpenAPI version 3.0.3")
	}

	paths, ok := spec["paths"].(map[string]interface{})
	if !ok {
		t.Fatal("expected paths in spec")
	}

	if _, exists := paths["/events"]; !exists {
		t.Error("expected /events path")
	}
	if _, exists := paths["/alerts"]; !exists {
		t.Error("expected /alerts path")
	}
}

func TestPaginationParams(t *testing.T) {
	params := api.PaginationParams{
		Page:    1,
		PerPage: 50,
		Sort:    "timestamp",
		Order:   "desc",
	}

	if params.Page != 1 {
		t.Errorf("expected page 1, got %d", params.Page)
	}
	if params.PerPage != 50 {
		t.Errorf("expected per_page 50, got %d", params.PerPage)
	}
}

// Integration test
func TestEnterpriseIntegration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("HAWithRetention", func(t *testing.T) {
		// Create cluster
		clusterConfig := ha.DefaultClusterConfig()
		cluster := ha.NewCluster(clusterConfig, logger)
		cluster.Start()
		defer cluster.Stop()

		// Create retention manager
		archiveConfig := retention.DefaultArchiveConfig()
		rm := retention.NewRetentionManager(archiveConfig, logger)

		// Verify both are operational
		if !cluster.IsLeader() {
			t.Error("expected cluster to be leader")
		}

		policies := rm.GetAllPolicies()
		if len(policies) == 0 {
			t.Error("expected retention policies")
		}
	})

	t.Run("APIWithGraphQL", func(t *testing.T) {
		// Create router
		router := api.NewRouter(api.APIVersionV1)
		router.GET("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("ok"))
		})

		// Create GraphQL handler
		schema := api.NewSIEMGraphQLSchema()
		gqlHandler := api.NewGraphQLHandler(schema)

		// Test router
		req := httptest.NewRequest("GET", "/health", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}

		// Test GraphQL
		gqlReq := httptest.NewRequest("GET", "/graphql?query={events{id}}", nil)
		gqlRec := httptest.NewRecorder()
		gqlHandler.ServeHTTP(gqlRec, gqlReq)
		if gqlRec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", gqlRec.Code)
		}
	})
}
