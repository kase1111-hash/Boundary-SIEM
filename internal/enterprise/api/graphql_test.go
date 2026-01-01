package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLexer(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []Token
	}{
		{
			name:  "simple query",
			input: "query { events }",
			expected: []Token{
				{Type: TokenName, Value: "query"},
				{Type: TokenPunctuation, Value: "{"},
				{Type: TokenName, Value: "events"},
				{Type: TokenPunctuation, Value: "}"},
				{Type: TokenEOF},
			},
		},
		{
			name:  "with arguments",
			input: `events(first: 10, filter: "test")`,
			expected: []Token{
				{Type: TokenName, Value: "events"},
				{Type: TokenPunctuation, Value: "("},
				{Type: TokenName, Value: "first"},
				{Type: TokenPunctuation, Value: ":"},
				{Type: TokenInt, Value: "10"},
				{Type: TokenName, Value: "filter"},
				{Type: TokenPunctuation, Value: ":"},
				{Type: TokenString, Value: "test"},
				{Type: TokenPunctuation, Value: ")"},
				{Type: TokenEOF},
			},
		},
		{
			name:  "with spread",
			input: "...FragmentName",
			expected: []Token{
				{Type: TokenSpread, Value: "..."},
				{Type: TokenName, Value: "FragmentName"},
				{Type: TokenEOF},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lexer := NewLexer(tt.input)
			for i, exp := range tt.expected {
				tok := lexer.NextToken()
				if tok.Type != exp.Type {
					t.Errorf("token %d: expected type %d, got %d", i, exp.Type, tok.Type)
				}
				if tok.Value != exp.Value {
					t.Errorf("token %d: expected value %q, got %q", i, exp.Value, tok.Value)
				}
			}
		})
	}
}

func TestParser(t *testing.T) {
	tests := []struct {
		name          string
		query         string
		expectError   bool
		opCount       int
		opType        string
		opName        string
	}{
		{
			name:        "simple query",
			query:       "query { events { id } }",
			expectError: false,
			opCount:     1,
			opType:      "query",
		},
		{
			name:        "named query",
			query:       "query GetEvents { events { id } }",
			expectError: false,
			opCount:     1,
			opType:      "query",
			opName:      "GetEvents",
		},
		{
			name:        "mutation",
			query:       "mutation { acknowledgeAlert(id: \"123\") { id } }",
			expectError: false,
			opCount:     1,
			opType:      "mutation",
		},
		{
			name:        "anonymous query",
			query:       "{ events { id } }",
			expectError: false,
			opCount:     1,
			opType:      "query",
		},
		{
			name:        "with variables",
			query:       "query GetEvents($first: Int = 10) { events(first: $first) { id } }",
			expectError: false,
			opCount:     1,
			opType:      "query",
			opName:      "GetEvents",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser(tt.query)
			doc, err := parser.Parse()

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(doc.Operations) != tt.opCount {
				t.Errorf("expected %d operations, got %d", tt.opCount, len(doc.Operations))
			}

			if tt.opCount > 0 {
				op := doc.Operations[0]
				if op.Type != tt.opType {
					t.Errorf("expected operation type %s, got %s", tt.opType, op.Type)
				}
				if tt.opName != "" && op.Name != tt.opName {
					t.Errorf("expected operation name %s, got %s", tt.opName, op.Name)
				}
			}
		})
	}
}

func TestParserWithFragments(t *testing.T) {
	query := `
		fragment EventFields on Event {
			id
			timestamp
			action
		}

		query GetEvents {
			events {
				...EventFields
			}
		}
	`

	parser := NewParser(query)
	doc, err := parser.Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(doc.Fragments) != 1 {
		t.Errorf("expected 1 fragment, got %d", len(doc.Fragments))
	}

	frag, ok := doc.Fragments["EventFields"]
	if !ok {
		t.Error("fragment 'EventFields' not found")
	}

	if frag.TypeCondition != "Event" {
		t.Errorf("expected type condition 'Event', got %s", frag.TypeCondition)
	}
}

func TestExecutor(t *testing.T) {
	schema := NewSIEMGraphQLSchema()
	executor := NewExecutor(schema)
	ctx := context.Background()

	tests := []struct {
		name      string
		query     string
		variables map[string]interface{}
		checkData func(t *testing.T, data interface{})
	}{
		{
			name:  "query events",
			query: "query { events { id timestamp action } }",
			checkData: func(t *testing.T, data interface{}) {
				dataMap, ok := data.(map[string]interface{})
				if !ok {
					t.Fatal("expected data to be a map")
				}
				events, ok := dataMap["events"].([]interface{})
				if !ok {
					t.Fatal("expected events to be an array")
				}
				if len(events) == 0 {
					t.Error("expected at least one event")
				}
			},
		},
		{
			name:  "query alerts with filter",
			query: `query { alerts(severity: "CRITICAL") { id severity status } }`,
			checkData: func(t *testing.T, data interface{}) {
				dataMap, ok := data.(map[string]interface{})
				if !ok {
					t.Fatal("expected data to be a map")
				}
				_, ok = dataMap["alerts"].([]interface{})
				if !ok {
					t.Fatal("expected alerts to be an array")
				}
			},
		},
		{
			name:  "query compliance score",
			query: "query { complianceScore { overall trend } }",
			checkData: func(t *testing.T, data interface{}) {
				dataMap, ok := data.(map[string]interface{})
				if !ok {
					t.Fatal("expected data to be a map")
				}
				score, ok := dataMap["complianceScore"].(map[string]interface{})
				if !ok {
					t.Fatal("expected complianceScore to be a map")
				}
				if _, ok := score["overall"]; !ok {
					t.Error("expected 'overall' field in complianceScore")
				}
			},
		},
		{
			name:  "mutation acknowledge alert",
			query: `mutation { acknowledgeAlert(id: "alert-1", comment: "Reviewed") { id status } }`,
			checkData: func(t *testing.T, data interface{}) {
				dataMap, ok := data.(map[string]interface{})
				if !ok {
					t.Fatal("expected data to be a map")
				}
				alert, ok := dataMap["acknowledgeAlert"].(map[string]interface{})
				if !ok {
					t.Fatal("expected acknowledgeAlert to be a map")
				}
				if alert["status"] != "ACKNOWLEDGED" {
					t.Errorf("expected status ACKNOWLEDGED, got %v", alert["status"])
				}
			},
		},
		{
			name:  "query with alias",
			query: "query { e: events { id } a: alerts { id } }",
			checkData: func(t *testing.T, data interface{}) {
				dataMap, ok := data.(map[string]interface{})
				if !ok {
					t.Fatal("expected data to be a map")
				}
				if _, ok := dataMap["e"]; !ok {
					t.Error("expected alias 'e' in response")
				}
				if _, ok := dataMap["a"]; !ok {
					t.Error("expected alias 'a' in response")
				}
			},
		},
		{
			name:  "query with variables",
			query: "query GetEvents($limit: Int) { events(first: $limit) { id } }",
			variables: map[string]interface{}{
				"limit": int64(5),
			},
			checkData: func(t *testing.T, data interface{}) {
				dataMap, ok := data.(map[string]interface{})
				if !ok {
					t.Fatal("expected data to be a map")
				}
				events, ok := dataMap["events"].([]interface{})
				if !ok {
					t.Fatal("expected events to be an array")
				}
				if len(events) > 5 {
					t.Errorf("expected at most 5 events, got %d", len(events))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := GraphQLRequest{
				Query:     tt.query,
				Variables: tt.variables,
			}

			resp := executor.Execute(ctx, req)

			if len(resp.Errors) > 0 {
				t.Errorf("unexpected errors: %v", resp.Errors)
			}

			if tt.checkData != nil && resp.Data != nil {
				tt.checkData(t, resp.Data)
			}
		})
	}
}

func TestComplexityAnalysis(t *testing.T) {
	schema := NewSIEMGraphQLSchema()
	executor := NewExecutor(schema)

	tests := []struct {
		name          string
		query         string
		config        *ComplexityConfig
		expectErrors  bool
	}{
		{
			name:  "simple query within limits",
			query: "query { events { id } }",
			config: &ComplexityConfig{
				MaxDepth:      10,
				MaxComplexity: 100,
				MaxFields:     50,
			},
			expectErrors: false,
		},
		{
			name:  "deeply nested query",
			query: "query { events { source { host } } alerts { events { source { host } } } }",
			config: &ComplexityConfig{
				MaxDepth:      2,
				MaxComplexity: 100,
				MaxFields:     50,
			},
			expectErrors: true,
		},
		{
			name:  "too many fields",
			query: "query { events { id } alerts { id } validators { id } incidents { id } complianceScore { overall } threatLevel { level } }",
			config: &ComplexityConfig{
				MaxDepth:      10,
				MaxComplexity: 100,
				MaxFields:     3,
			},
			expectErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errors := executor.AnalyzeComplexity(tt.query, tt.config)
			hasErrors := len(errors) > 0

			if hasErrors != tt.expectErrors {
				t.Errorf("expected errors: %v, got errors: %v", tt.expectErrors, errors)
			}
		})
	}
}

func TestValidation(t *testing.T) {
	schema := NewSIEMGraphQLSchema()
	executor := NewExecutor(schema)

	tests := []struct {
		name         string
		query        string
		expectErrors bool
	}{
		{
			name:         "valid query",
			query:        "query { events { id } }",
			expectErrors: false,
		},
		{
			name:         "invalid field",
			query:        "query { unknownField { id } }",
			expectErrors: true,
		},
		{
			name:         "introspection allowed",
			query:        "query { __schema { types { name } } }",
			expectErrors: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := executor.ValidateQuery(tt.query)
			hasErrors := len(errors) > 0

			if hasErrors != tt.expectErrors {
				t.Errorf("expected errors: %v, got: %v", tt.expectErrors, errors)
			}
		})
	}
}

func TestGraphQLHandler(t *testing.T) {
	schema := NewSIEMGraphQLSchema()
	handler := NewGraphQLHandler(schema)

	tests := []struct {
		name           string
		method         string
		body           string
		query          string
		expectedStatus int
		checkResponse  func(t *testing.T, resp *GraphQLResponse)
	}{
		{
			name:           "POST query",
			method:         "POST",
			body:           `{"query": "query { events { id } }"}`,
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp *GraphQLResponse) {
				if resp.Data == nil {
					t.Error("expected data in response")
				}
			},
		},
		{
			name:           "GET query",
			method:         "GET",
			query:          "query=%7B%20events%20%7B%20id%20%7D%20%7D", // { events { id } }
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST without query",
			method:         "POST",
			body:           `{}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid method",
			method:         "PUT",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "invalid JSON",
			method:         "POST",
			body:           `invalid json`,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.method == "POST" {
				req = httptest.NewRequest(tt.method, "/graphql", bytes.NewBufferString(tt.body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				url := "/graphql"
				if tt.query != "" {
					url += "?" + tt.query
				}
				req = httptest.NewRequest(tt.method, url, nil)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if tt.checkResponse != nil && rr.Code == http.StatusOK {
				var resp GraphQLResponse
				if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				tt.checkResponse(t, &resp)
			}
		})
	}
}

func TestCustomResolver(t *testing.T) {
	schema := NewSIEMGraphQLSchema()
	handler := NewGraphQLHandler(schema)

	// Register custom resolver
	customCalled := false
	handler.RegisterResolver("Query", "events", func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		customCalled = true
		return []interface{}{
			map[string]interface{}{
				"id":     "custom-event-1",
				"action": "custom",
			},
		}, nil
	})

	req := GraphQLRequest{
		Query: "query { events { id action } }",
	}

	resp := handler.Execute(context.Background(), req)

	if !customCalled {
		t.Error("custom resolver was not called")
	}

	if len(resp.Errors) > 0 {
		t.Errorf("unexpected errors: %v", resp.Errors)
	}

	if resp.Data != nil {
		dataMap := resp.Data.(map[string]interface{})
		events := dataMap["events"].([]interface{})
		if len(events) > 0 {
			event := events[0].(map[string]interface{})
			if event["id"] != "custom-event-1" {
				t.Error("expected custom event data")
			}
		}
	}
}

func TestSanitizeQuery(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "remove comments",
			input:    "query {\n  # This is a comment\n  events { id }\n}",
			expected: "query {\n  \n  events { id }\n}",
		},
		{
			name:     "no comments",
			input:    "query { events { id } }",
			expected: "query { events { id } }",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeQuery(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestIntrospection(t *testing.T) {
	schema := NewSIEMGraphQLSchema()
	executor := NewExecutor(schema)

	schemaData := executor.introspectSchema()

	// Check that we have types
	types, ok := schemaData["types"].([]interface{})
	if !ok || len(types) == 0 {
		t.Error("expected types in schema introspection")
	}

	// Check query type
	if queryType, ok := schemaData["queryType"].(map[string]interface{}); ok {
		if queryType["name"] != "Query" {
			t.Errorf("expected query type name 'Query', got %v", queryType["name"])
		}
	} else {
		t.Error("expected queryType in schema introspection")
	}

	// Check mutation type
	if mutationType, ok := schemaData["mutationType"].(map[string]interface{}); ok {
		if mutationType["name"] != "Mutation" {
			t.Errorf("expected mutation type name 'Mutation', got %v", mutationType["name"])
		}
	} else {
		t.Error("expected mutationType in schema introspection")
	}
}

func TestResolverMap(t *testing.T) {
	rm := NewResolverMap()

	// Test Set and Get
	resolver := func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return "test", nil
	}

	rm.Set("Query", "test", resolver)

	got, ok := rm.Get("Query", "test")
	if !ok {
		t.Error("expected resolver to be found")
	}

	result, _ := got(context.Background(), nil)
	if result != "test" {
		t.Errorf("expected 'test', got %v", result)
	}

	// Test not found
	_, ok = rm.Get("Query", "notfound")
	if ok {
		t.Error("expected resolver not to be found")
	}
}

func TestNestedSelectionSet(t *testing.T) {
	schema := NewSIEMGraphQLSchema()
	executor := NewExecutor(schema)
	ctx := context.Background()

	query := `
		query {
			alerts {
				id
				severity
				events {
					id
					timestamp
					source {
						host
						ip
					}
				}
			}
		}
	`

	req := GraphQLRequest{Query: query}
	resp := executor.Execute(ctx, req)

	if len(resp.Errors) > 0 {
		t.Errorf("unexpected errors: %v", resp.Errors)
	}

	// Verify nested structure
	if resp.Data != nil {
		dataMap := resp.Data.(map[string]interface{})
		alerts, ok := dataMap["alerts"].([]interface{})
		if !ok || len(alerts) == 0 {
			t.Fatal("expected alerts array")
		}

		alert := alerts[0].(map[string]interface{})
		events, ok := alert["events"].([]interface{})
		if !ok || len(events) == 0 {
			t.Fatal("expected events array in alert")
		}

		event := events[0].(map[string]interface{})
		if _, ok := event["source"]; !ok {
			t.Error("expected source in event")
		}
	}
}

func TestVariableDefaultValues(t *testing.T) {
	schema := NewSIEMGraphQLSchema()
	executor := NewExecutor(schema)
	ctx := context.Background()

	query := `
		query GetEvents($first: Int = 5) {
			events(first: $first) {
				id
			}
		}
	`

	// Without providing variable - should use default
	req := GraphQLRequest{Query: query}
	resp := executor.Execute(ctx, req)

	if len(resp.Errors) > 0 {
		t.Errorf("unexpected errors: %v", resp.Errors)
	}

	// With provided variable
	req = GraphQLRequest{
		Query: query,
		Variables: map[string]interface{}{
			"first": int64(3),
		},
	}
	resp = executor.Execute(ctx, req)

	if len(resp.Errors) > 0 {
		t.Errorf("unexpected errors: %v", resp.Errors)
	}
}

func TestMultipleOperations(t *testing.T) {
	schema := NewSIEMGraphQLSchema()
	executor := NewExecutor(schema)
	ctx := context.Background()

	query := `
		query GetEvents {
			events { id }
		}

		query GetAlerts {
			alerts { id }
		}
	`

	// Execute specific operation
	req := GraphQLRequest{
		Query:         query,
		OperationName: "GetAlerts",
	}
	resp := executor.Execute(ctx, req)

	if len(resp.Errors) > 0 {
		t.Errorf("unexpected errors: %v", resp.Errors)
	}

	// Check that only alerts are returned (not events)
	if resp.Data != nil {
		dataMap := resp.Data.(map[string]interface{})
		if _, ok := dataMap["events"]; ok {
			t.Error("expected only alerts, not events")
		}
		if _, ok := dataMap["alerts"]; !ok {
			t.Error("expected alerts in response")
		}
	}
}

func TestOperationNotFound(t *testing.T) {
	schema := NewSIEMGraphQLSchema()
	executor := NewExecutor(schema)
	ctx := context.Background()

	query := `query GetEvents { events { id } }`

	req := GraphQLRequest{
		Query:         query,
		OperationName: "NonExistentOperation",
	}
	resp := executor.Execute(ctx, req)

	if len(resp.Errors) == 0 {
		t.Error("expected error for non-existent operation")
	}

	if !strings.Contains(resp.Errors[0].Message, "not found") {
		t.Errorf("expected 'not found' error, got: %s", resp.Errors[0].Message)
	}
}
