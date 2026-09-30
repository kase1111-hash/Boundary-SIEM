package search

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"boundary-siem/internal/schema"
	"boundary-siem/internal/storage"

	"github.com/google/uuid"
)

// Integration test against a real ClickHouse server: migrate a fresh
// database, insert events through storage.BatchWriter, and query them through
// the Executor and the HTTP Handler. It runs only when CLICKHOUSE_TEST_ADDR is
// set to a native-protocol address, e.g.
//
//	CLICKHOUSE_TEST_ADDR=127.0.0.1:9000 go test ./internal/search -run Integration
//
// CLICKHOUSE_TEST_USER and CLICKHOUSE_TEST_PASSWORD override the credentials.

type integrationFixture struct {
	client  *storage.ClickHouseClient
	handler *Handler
	exec    *Executor

	defaultEvents []*schema.Event
	otherEvent    *schema.Event
}

func newIntegrationFixture(t *testing.T) *integrationFixture {
	t.Helper()
	addr := os.Getenv("CLICKHOUSE_TEST_ADDR")
	if addr == "" {
		t.Skip("CLICKHOUSE_TEST_ADDR not set; skipping ClickHouse integration test")
	}

	cfg := storage.DefaultClickHouseConfig()
	cfg.Hosts = []string{addr}
	if user := os.Getenv("CLICKHOUSE_TEST_USER"); user != "" {
		cfg.Username = user
	}
	cfg.Password = os.Getenv("CLICKHOUSE_TEST_PASSWORD")
	cfg.Database = "siem_search_it_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]

	client, err := storage.NewClickHouseClient(cfg)
	if err != nil {
		t.Fatalf("NewClickHouseClient() error = %v", err)
	}
	t.Cleanup(func() {
		if err := client.Exec(context.Background(), "DROP DATABASE IF EXISTS `"+cfg.Database+"`"); err != nil {
			t.Logf("cleanup: %v", err)
		}
		client.Close()
	})

	ctx := context.Background()
	if err := storage.NewMigrator(client).Run(ctx); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	f := &integrationFixture{client: client}
	now := time.Now().UTC().Truncate(time.Microsecond)
	mk := func(tenant, action, actorID, actorName string, outcome schema.Outcome, sev int, age time.Duration) *schema.Event {
		return &schema.Event{
			EventID:       uuid.New(),
			Timestamp:     now.Add(-age),
			ReceivedAt:    now,
			Source:        schema.Source{Product: "rt-single", Host: "10.1.2.3", InstanceID: "sig-1", Version: "2.1"},
			Actor:         &schema.Actor{Type: schema.ActorUser, ID: actorID, Name: actorName, Email: actorName + "@example.com", IPAddress: "192.0.2.10"},
			Action:        action,
			Target:        "server-1",
			Outcome:       outcome,
			Severity:      sev,
			SchemaVersion: schema.SchemaVersionCurrent,
			TenantID:      tenant,
			RequestID:     "req-42",
			Raw:           fmt.Sprintf(`msg=say "hi" %s`, action),
			Metadata:      map[string]any{"device_vendor": "Acme", "gas": 150},
		}
	}
	// Ingested without a tenant, so stored under the default tenant.
	f.defaultEvents = []*schema.Event{
		mk("", "auth.login", "000123", "voilà", schema.OutcomeSuccess, 3, time.Minute),
		mk("", "auth.login", "u2", "bob", schema.OutcomeFailure, 7, 2*time.Minute),
		mk("", "auth.logout", "u3", "carol", schema.OutcomeSuccess, 2, 3*time.Minute),
		mk("", "file.delete", "u4", "dave", schema.OutcomeFailure, 9, 4*time.Minute),
	}
	f.otherEvent = mk("other", "auth.login", "000123", "voilà", schema.OutcomeSuccess, 3, time.Minute)

	bw := storage.NewBatchWriter(client, storage.BatchWriterConfig{BatchSize: 100, FlushInterval: time.Hour, RetryDelay: time.Millisecond})
	for _, ev := range append(append([]*schema.Event(nil), f.defaultEvents...), f.otherEvent) {
		if err := bw.Write(ev); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("BatchWriter.Close() error = %v", err)
	}

	f.exec = NewExecutor(client.DB())
	f.handler = NewHandler(f.exec)
	return f
}

func (f *integrationFixture) do(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	mux := http.NewServeMux()
	f.handler.RegisterRoutes(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
	return w.Code, w.Body.Bytes()
}

func TestIntegrationSearchAPI(t *testing.T) {
	f := newIntegrationFixture(t)

	t.Run("POST search", func(t *testing.T) {
		code, body := f.do(t, http.MethodPost, "/v1/search", `{"query":"action:auth.login"}`)
		if code != http.StatusOK {
			t.Fatalf("status = %d: %s", code, body)
		}
		var resp SearchResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.TotalCount != 2 || len(resp.Results) != 2 {
			t.Fatalf("total = %d, results = %d, want 2 default-tenant logins", resp.TotalCount, len(resp.Results))
		}
		r := resp.Results[0] // newest first
		want := f.defaultEvents[0]
		if r.EventID != want.EventID || r.TenantID != "default" || r.SourceHost != "10.1.2.3" ||
			r.SourceIP != "10.1.2.3" || r.SourceVendor != "Acme" || r.SourceInstanceID != "sig-1" ||
			r.SourceVersion != "2.1" || r.ActorID != "000123" || r.ActorName != "voilà" ||
			r.ActorEmail != "voilà@example.com" || r.ActorType != "user" || r.RequestID != "req-42" ||
			r.Severity != 3 || !r.Timestamp.Equal(want.Timestamp) {
			t.Errorf("result = %+v", r)
		}
	})

	t.Run("GET search", func(t *testing.T) {
		code, body := f.do(t, http.MethodGet, "/v1/search?q=source_product:rt-single&limit=2&order=asc", "")
		if code != http.StatusOK {
			t.Fatalf("status = %d: %s", code, body)
		}
		var resp SearchResponse
		_ = json.Unmarshal(body, &resp)
		if resp.TotalCount != 4 || len(resp.Results) != 2 || resp.Results[0].EventID != f.defaultEvents[3].EventID {
			t.Errorf("total = %d results = %d, want 4 total, 2 returned oldest first", resp.TotalCount, len(resp.Results))
		}
	})

	t.Run("get event", func(t *testing.T) {
		code, body := f.do(t, http.MethodGet, "/v1/events/"+f.defaultEvents[1].EventID.String(), "")
		if code != http.StatusOK || !strings.Contains(string(body), `"actor_id":"u2"`) {
			t.Errorf("status = %d: %s", code, body)
		}
		// Another tenant's event is not visible.
		if code, _ := f.do(t, http.MethodGet, "/v1/events/"+f.otherEvent.EventID.String(), ""); code != http.StatusNotFound {
			t.Errorf("other tenant's event: status = %d, want 404", code)
		}
	})

	for _, tc := range []struct {
		name, path, body, contains string
	}{
		{"terms aggregation", "/v1/aggregations", `{"field":"action","type":"terms"}`, `"key":"auth.login","count":2`},
		{"count aggregation", "/v1/aggregations", `{"field":"outcome","type":"count"}`, `"total":4`},
		{"sum aggregation", "/v1/aggregations", `{"field":"severity","type":"sum"}`, `"value":21`},
		{"histogram aggregation", "/v1/aggregations", `{"field":"timestamp","type":"histogram","interval":"1m"}`, `"total":4`},
		{"field values", "/v1/fields/outcome/values", "", `"total":4`},
		{"stats", "/v1/stats", "", `"total_events":4`},
		{"explain", "/v1/search/explain", `{"query":"action:auth.login"}`, `"plan":[`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method := http.MethodPost
			if tc.body == "" {
				method = http.MethodGet
			}
			code, body := f.do(t, method, tc.path, tc.body)
			if code != http.StatusOK || !strings.Contains(string(body), tc.contains) {
				t.Errorf("status = %d, want 200 containing %s: %s", code, tc.contains, body)
			}
		})
	}
}

// Query semantics against real rows: each query must return exactly the
// listed default-tenant events.
func TestIntegrationQuerySemantics(t *testing.T) {
	f := newIntegrationFixture(t)
	ev := f.defaultEvents

	tests := []struct {
		query string
		want  []int // indices into defaultEvents
	}{
		{"action:auth.login", []int{0, 1}},
		{"NOT action:auth.login", []int{2, 3}},
		{"NOT (action:auth.login OR action:auth.logout)", []int{3}},
		{"NOT severity>5", []int{0, 2}},
		{"severity>=7", []int{1, 3}},
		{"action:auth.* outcome:failure", []int{1}},
		{"action:auth.* outcome:failure OR severity>8", []int{1, 3}},
		{"action:auth.* NOT (outcome:failure OR severity<3)", []int{0}},
		{`actor.id:"000123"`, []int{0}},
		{"actor.id:000123", []int{0}},
		{"user=voilà", []int{0}},
		{"vendor:Acme severity<3", []int{2}},
		{"metadata.gas>100 action:file.delete", []int{3}},
		{"source.ip:10.1.2.3 outcome:success", []int{0, 2}},
		{`raw~"say \"hi\" auth.logout"`, []int{2}},
		{"request_id:req-42 action!=auth.login", []int{2, 3}},
		{"timestamp>now-150s", []int{0, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			q, err := ParseQuery(tt.query)
			if err != nil {
				t.Fatalf("ParseQuery error = %v", err)
			}
			q.TenantID = "default"
			resp, err := f.exec.Search(context.Background(), q)
			if err != nil {
				t.Fatalf("Search() error = %v", err)
			}
			got := map[uuid.UUID]bool{}
			for _, r := range resp.Results {
				got[r.EventID] = true
			}
			if len(got) != len(tt.want) || int(resp.TotalCount) != len(tt.want) {
				t.Errorf("got %d results (total %d), want %d", len(got), resp.TotalCount, len(tt.want))
			}
			for _, i := range tt.want {
				if !got[ev[i].EventID] {
					t.Errorf("missing event %d (%s %s)", i, ev[i].Action, ev[i].Outcome)
				}
			}
		})
	}
}
