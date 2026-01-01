// Package api provides REST and GraphQL API framework for the SIEM.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"
)

// APIVersion defines API versions.
type APIVersion string

const (
	APIVersionV1 APIVersion = "v1"
	APIVersionV2 APIVersion = "v2"
)

// Router manages API routing.
type Router struct {
	mu           sync.RWMutex
	routes       map[string]*Route
	middleware   []Middleware
	errorHandler ErrorHandler
	version      APIVersion
}

// Route represents an API route.
type Route struct {
	Method      string
	Path        string
	Handler     http.HandlerFunc
	Description string
	Tags        []string
	Deprecated  bool
	RateLimit   *RateLimitConfig
	Auth        *AuthConfig
}

// Middleware defines middleware function.
type Middleware func(http.Handler) http.Handler

// ErrorHandler handles API errors.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// RateLimitConfig configures rate limiting.
type RateLimitConfig struct {
	RequestsPerSecond int           `json:"requests_per_second"`
	Burst             int           `json:"burst"`
	Window            time.Duration `json:"window"`
}

// AuthConfig configures authentication.
type AuthConfig struct {
	Required    bool     `json:"required"`
	Permissions []string `json:"permissions,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
}

// APIResponse is a standard API response.
type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     *APIError   `json:"error,omitempty"`
	Meta      *APIMeta    `json:"meta,omitempty"`
	RequestID string      `json:"request_id,omitempty"`
}

// APIError represents an API error.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// APIMeta contains response metadata.
type APIMeta struct {
	Page       int   `json:"page,omitempty"`
	PerPage    int   `json:"per_page,omitempty"`
	Total      int64 `json:"total,omitempty"`
	TotalPages int   `json:"total_pages,omitempty"`
}

// PaginationParams represents pagination parameters.
type PaginationParams struct {
	Page    int    `json:"page"`
	PerPage int    `json:"per_page"`
	Sort    string `json:"sort,omitempty"`
	Order   string `json:"order,omitempty"`
}

// NewRouter creates a new API router.
func NewRouter(version APIVersion) *Router {
	return &Router{
		routes:  make(map[string]*Route),
		version: version,
		errorHandler: defaultErrorHandler,
	}
}

// defaultErrorHandler is the default error handler.
func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	resp := &APIResponse{
		Success: false,
		Error: &APIError{
			Code:    "INTERNAL_ERROR",
			Message: err.Error(),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(resp)
}

// Use adds middleware to the router.
func (r *Router) Use(middleware Middleware) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.middleware = append(r.middleware, middleware)
}

// AddRoute adds a route to the router.
func (r *Router) AddRoute(route *Route) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := fmt.Sprintf("%s:%s", route.Method, route.Path)
	r.routes[key] = route
}

// GET adds a GET route.
func (r *Router) GET(path string, handler http.HandlerFunc, opts ...RouteOption) {
	route := &Route{Method: "GET", Path: path, Handler: handler}
	for _, opt := range opts {
		opt(route)
	}
	r.AddRoute(route)
}

// POST adds a POST route.
func (r *Router) POST(path string, handler http.HandlerFunc, opts ...RouteOption) {
	route := &Route{Method: "POST", Path: path, Handler: handler}
	for _, opt := range opts {
		opt(route)
	}
	r.AddRoute(route)
}

// PUT adds a PUT route.
func (r *Router) PUT(path string, handler http.HandlerFunc, opts ...RouteOption) {
	route := &Route{Method: "PUT", Path: path, Handler: handler}
	for _, opt := range opts {
		opt(route)
	}
	r.AddRoute(route)
}

// DELETE adds a DELETE route.
func (r *Router) DELETE(path string, handler http.HandlerFunc, opts ...RouteOption) {
	route := &Route{Method: "DELETE", Path: path, Handler: handler}
	for _, opt := range opts {
		opt(route)
	}
	r.AddRoute(route)
}

// PATCH adds a PATCH route.
func (r *Router) PATCH(path string, handler http.HandlerFunc, opts ...RouteOption) {
	route := &Route{Method: "PATCH", Path: path, Handler: handler}
	for _, opt := range opts {
		opt(route)
	}
	r.AddRoute(route)
}

// RouteOption configures a route.
type RouteOption func(*Route)

// WithDescription sets route description.
func WithDescription(desc string) RouteOption {
	return func(r *Route) { r.Description = desc }
}

// WithTags sets route tags.
func WithTags(tags ...string) RouteOption {
	return func(r *Route) { r.Tags = tags }
}

// WithRateLimit sets rate limiting.
func WithRateLimit(rps, burst int) RouteOption {
	return func(r *Route) {
		r.RateLimit = &RateLimitConfig{
			RequestsPerSecond: rps,
			Burst:             burst,
			Window:            time.Second,
		}
	}
}

// WithAuth sets authentication requirements.
func WithAuth(required bool, permissions ...string) RouteOption {
	return func(r *Route) {
		r.Auth = &AuthConfig{
			Required:    required,
			Permissions: permissions,
		}
	}
}

// ServeHTTP implements http.Handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	key := fmt.Sprintf("%s:%s", req.Method, req.URL.Path)
	route, exists := r.routes[key]
	middleware := r.middleware
	r.mu.RUnlock()

	if !exists {
		http.NotFound(w, req)
		return
	}

	// Build handler chain
	handler := http.Handler(route.Handler)
	for i := len(middleware) - 1; i >= 0; i-- {
		handler = middleware[i](handler)
	}

	handler.ServeHTTP(w, req)
}

// GetRoutes returns all registered routes.
func (r *Router) GetRoutes() []*Route {
	r.mu.RLock()
	defer r.mu.RUnlock()

	routes := make([]*Route, 0, len(r.routes))
	for _, route := range r.routes {
		routes = append(routes, route)
	}
	return routes
}

// GraphQL types and schema

// GraphQLSchema represents a GraphQL schema.
type GraphQLSchema struct {
	Query        *GraphQLObject
	Mutation     *GraphQLObject
	Subscription *GraphQLObject
	Types        map[string]*GraphQLType
}

// GraphQLObject represents a GraphQL object type.
type GraphQLObject struct {
	Name        string
	Description string
	Fields      map[string]*GraphQLField
}

// GraphQLField represents a GraphQL field.
type GraphQLField struct {
	Name        string
	Description string
	Type        string
	Args        map[string]*GraphQLArg
	Resolver    GraphQLResolver
}

// GraphQLArg represents a GraphQL argument.
type GraphQLArg struct {
	Name         string
	Description  string
	Type         string
	DefaultValue interface{}
	Required     bool
}

// GraphQLType represents a GraphQL type.
type GraphQLType struct {
	Name        string
	Description string
	Kind        string // OBJECT, SCALAR, ENUM, INPUT_OBJECT, etc.
	Fields      map[string]*GraphQLField
	EnumValues  []string
}

// GraphQLResolver is a field resolver function.
type GraphQLResolver func(ctx context.Context, args map[string]interface{}) (interface{}, error)

// GraphQLRequest represents a GraphQL request.
type GraphQLRequest struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
}

// GraphQLResponse represents a GraphQL response.
type GraphQLResponse struct {
	Data   interface{}     `json:"data,omitempty"`
	Errors []GraphQLError  `json:"errors,omitempty"`
}

// GraphQLError represents a GraphQL error.
type GraphQLError struct {
	Message   string                 `json:"message"`
	Locations []GraphQLLocation      `json:"locations,omitempty"`
	Path      []interface{}          `json:"path,omitempty"`
	Extensions map[string]interface{} `json:"extensions,omitempty"`
}

// GraphQLLocation represents error location.
type GraphQLLocation struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// GraphQLHandler handles GraphQL requests.
type GraphQLHandler struct {
	schema           *GraphQLSchema
	executor         *Executor
	complexityConfig *ComplexityConfig
}

// NewGraphQLHandler creates a new GraphQL handler.
func NewGraphQLHandler(schema *GraphQLSchema) *GraphQLHandler {
	return &GraphQLHandler{
		schema:           schema,
		executor:         NewExecutor(schema),
		complexityConfig: DefaultComplexityConfig(),
	}
}

// SetComplexityConfig sets the complexity configuration.
func (h *GraphQLHandler) SetComplexityConfig(config *ComplexityConfig) {
	h.complexityConfig = config
}

// RegisterResolver registers a custom resolver for a field.
func (h *GraphQLHandler) RegisterResolver(typeName, fieldName string, resolver GraphQLResolver) {
	h.executor.RegisterResolver(typeName, fieldName, resolver)
}

// ServeHTTP implements http.Handler.
func (h *GraphQLHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req GraphQLRequest

	if r.Method == "POST" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.writeError(w, "Invalid request body", http.StatusBadRequest)
			return
		}
	} else if r.Method == "GET" {
		req.Query = r.URL.Query().Get("query")
		req.OperationName = r.URL.Query().Get("operationName")
		if vars := r.URL.Query().Get("variables"); vars != "" {
			json.Unmarshal([]byte(vars), &req.Variables)
		}
	} else {
		h.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if req.Query == "" {
		h.writeError(w, "Query is required", http.StatusBadRequest)
		return
	}

	resp := h.Execute(r.Context(), req)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *GraphQLHandler) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(&GraphQLResponse{
		Errors: []GraphQLError{{Message: message}},
	})
}

// Execute executes a GraphQL request.
func (h *GraphQLHandler) Execute(ctx context.Context, req GraphQLRequest) *GraphQLResponse {
	// Sanitize the query
	query := SanitizeQuery(req.Query)
	req.Query = query

	// Check complexity limits
	if h.complexityConfig != nil {
		_, complexityErrors := h.executor.AnalyzeComplexity(query, h.complexityConfig)
		if len(complexityErrors) > 0 {
			return &GraphQLResponse{Errors: complexityErrors}
		}
	}

	// Validate the query
	validationErrors := h.executor.ValidateQuery(query)
	if len(validationErrors) > 0 {
		return &GraphQLResponse{Errors: validationErrors}
	}

	// Execute the query
	return h.executor.Execute(ctx, req)
}

// ValidateQuery validates a GraphQL query without executing it.
func (h *GraphQLHandler) ValidateQuery(query string) []GraphQLError {
	return h.executor.ValidateQuery(query)
}

// GetSchema returns the GraphQL schema for introspection.
func (h *GraphQLHandler) GetSchema() *GraphQLSchema {
	return h.schema
}

// NewSIEMGraphQLSchema creates the SIEM GraphQL schema.
func NewSIEMGraphQLSchema() *GraphQLSchema {
	return &GraphQLSchema{
		Query: &GraphQLObject{
			Name:        "Query",
			Description: "Root query type",
			Fields: map[string]*GraphQLField{
				"events": {
					Name:        "events",
					Description: "Query security events",
					Type:        "[Event!]!",
					Args: map[string]*GraphQLArg{
						"filter": {Name: "filter", Type: "EventFilter"},
						"first":  {Name: "first", Type: "Int", DefaultValue: 100},
						"after":  {Name: "after", Type: "String"},
					},
				},
				"alerts": {
					Name:        "alerts",
					Description: "Query security alerts",
					Type:        "[Alert!]!",
					Args: map[string]*GraphQLArg{
						"severity": {Name: "severity", Type: "Severity"},
						"status":   {Name: "status", Type: "AlertStatus"},
						"first":    {Name: "first", Type: "Int", DefaultValue: 50},
					},
				},
				"validators": {
					Name:        "validators",
					Description: "Query validator status",
					Type:        "[Validator!]!",
					Args: map[string]*GraphQLArg{
						"status": {Name: "status", Type: "ValidatorStatus"},
					},
				},
				"incidents": {
					Name:        "incidents",
					Description: "Query security incidents",
					Type:        "[Incident!]!",
					Args: map[string]*GraphQLArg{
						"status": {Name: "status", Type: "IncidentStatus"},
						"first":  {Name: "first", Type: "Int", DefaultValue: 20},
					},
				},
				"complianceScore": {
					Name:        "complianceScore",
					Description: "Get compliance score",
					Type:        "ComplianceScore!",
				},
				"threatLevel": {
					Name:        "threatLevel",
					Description: "Get current threat level",
					Type:        "ThreatLevel!",
				},
			},
		},
		Mutation: &GraphQLObject{
			Name:        "Mutation",
			Description: "Root mutation type",
			Fields: map[string]*GraphQLField{
				"acknowledgeAlert": {
					Name:        "acknowledgeAlert",
					Description: "Acknowledge an alert",
					Type:        "Alert!",
					Args: map[string]*GraphQLArg{
						"id":      {Name: "id", Type: "ID!", Required: true},
						"comment": {Name: "comment", Type: "String"},
					},
				},
				"createIncident": {
					Name:        "createIncident",
					Description: "Create a new incident",
					Type:        "Incident!",
					Args: map[string]*GraphQLArg{
						"input": {Name: "input", Type: "CreateIncidentInput!", Required: true},
					},
				},
				"updateRule": {
					Name:        "updateRule",
					Description: "Update a detection rule",
					Type:        "Rule!",
					Args: map[string]*GraphQLArg{
						"id":    {Name: "id", Type: "ID!", Required: true},
						"input": {Name: "input", Type: "UpdateRuleInput!", Required: true},
					},
				},
			},
		},
		Subscription: &GraphQLObject{
			Name:        "Subscription",
			Description: "Root subscription type",
			Fields: map[string]*GraphQLField{
				"eventStream": {
					Name:        "eventStream",
					Description: "Subscribe to real-time events",
					Type:        "Event!",
					Args: map[string]*GraphQLArg{
						"filter": {Name: "filter", Type: "EventFilter"},
					},
				},
				"alertStream": {
					Name:        "alertStream",
					Description: "Subscribe to real-time alerts",
					Type:        "Alert!",
					Args: map[string]*GraphQLArg{
						"severity": {Name: "severity", Type: "Severity"},
					},
				},
			},
		},
		Types: map[string]*GraphQLType{
			"Event": {
				Name:        "Event",
				Description: "Security event",
				Kind:        "OBJECT",
				Fields: map[string]*GraphQLField{
					"id":        {Name: "id", Type: "ID!"},
					"timestamp": {Name: "timestamp", Type: "DateTime!"},
					"action":    {Name: "action", Type: "String!"},
					"outcome":   {Name: "outcome", Type: "Outcome!"},
					"severity":  {Name: "severity", Type: "Int!"},
					"source":    {Name: "source", Type: "Source!"},
					"target":    {Name: "target", Type: "String"},
					"metadata":  {Name: "metadata", Type: "JSON"},
				},
			},
			"Alert": {
				Name:        "Alert",
				Description: "Security alert",
				Kind:        "OBJECT",
				Fields: map[string]*GraphQLField{
					"id":        {Name: "id", Type: "ID!"},
					"ruleId":    {Name: "ruleId", Type: "String!"},
					"ruleName":  {Name: "ruleName", Type: "String!"},
					"severity":  {Name: "severity", Type: "Severity!"},
					"status":    {Name: "status", Type: "AlertStatus!"},
					"events":    {Name: "events", Type: "[Event!]!"},
					"createdAt": {Name: "createdAt", Type: "DateTime!"},
				},
			},
			"Severity": {
				Name:        "Severity",
				Description: "Alert severity levels",
				Kind:        "ENUM",
				EnumValues:  []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
			},
			"AlertStatus": {
				Name:        "AlertStatus",
				Description: "Alert status",
				Kind:        "ENUM",
				EnumValues:  []string{"OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "CLOSED"},
			},
		},
	}
}

// SDK types

// SDKConfig configures SDK generation.
type SDKConfig struct {
	Language    string   `json:"language"`
	OutputPath  string   `json:"output_path"`
	PackageName string   `json:"package_name"`
	Version     string   `json:"version"`
	Endpoints   []string `json:"endpoints"`
}

// SDK represents a generated SDK.
type SDK struct {
	Language    string
	Version     string
	PackageName string
	Files       map[string]string
}

// SDKGenerator generates SDKs for various languages.
type SDKGenerator struct {
	schema  *GraphQLSchema
	routes  []*Route
}

// NewSDKGenerator creates a new SDK generator.
func NewSDKGenerator(schema *GraphQLSchema, routes []*Route) *SDKGenerator {
	return &SDKGenerator{
		schema: schema,
		routes: routes,
	}
}

// Generate generates an SDK for the specified language.
func (g *SDKGenerator) Generate(config *SDKConfig) (*SDK, error) {
	sdk := &SDK{
		Language:    config.Language,
		Version:     config.Version,
		PackageName: config.PackageName,
		Files:       make(map[string]string),
	}

	switch config.Language {
	case "go":
		sdk.Files["client.go"] = g.generateGoClient(config)
		sdk.Files["types.go"] = g.generateGoTypes(config)
	case "python":
		sdk.Files["client.py"] = g.generatePythonClient(config)
		sdk.Files["types.py"] = g.generatePythonTypes(config)
	case "typescript":
		sdk.Files["client.ts"] = g.generateTypeScriptClient(config)
		sdk.Files["types.ts"] = g.generateTypeScriptTypes(config)
	case "java":
		sdk.Files["Client.java"] = g.generateJavaClient(config)
		sdk.Files["Types.java"] = g.generateJavaTypes(config)
	default:
		return nil, fmt.Errorf("unsupported language: %s", config.Language)
	}

	return sdk, nil
}

func (g *SDKGenerator) generateGoClient(config *SDKConfig) string {
	return fmt.Sprintf(`// Package %s provides a Go client for the Boundary SIEM API.
package %s

import (
	"context"
	"encoding/json"
	"net/http"
)

// Client is the Boundary SIEM API client.
type Client struct {
	baseURL    string
	httpClient *http.Client
	apiKey     string
}

// NewClient creates a new API client.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{},
		apiKey:     apiKey,
	}
}

// GetEvents retrieves security events.
func (c *Client) GetEvents(ctx context.Context, filter *EventFilter) ([]Event, error) {
	// Implementation
	return nil, nil
}

// GetAlerts retrieves security alerts.
func (c *Client) GetAlerts(ctx context.Context, filter *AlertFilter) ([]Alert, error) {
	// Implementation
	return nil, nil
}

// AcknowledgeAlert acknowledges an alert.
func (c *Client) AcknowledgeAlert(ctx context.Context, id, comment string) (*Alert, error) {
	// Implementation
	return nil, nil
}
`, config.PackageName, config.PackageName)
}

func (g *SDKGenerator) generateGoTypes(config *SDKConfig) string {
	return fmt.Sprintf(`// Package %s provides types for the Boundary SIEM API.
package %s

import "time"

// Event represents a security event.
type Event struct {
	ID        string                 %sjson:"id"%s
	Timestamp time.Time              %sjson:"timestamp"%s
	Action    string                 %sjson:"action"%s
	Outcome   string                 %sjson:"outcome"%s
	Severity  int                    %sjson:"severity"%s
	Source    Source                 %sjson:"source"%s
	Target    string                 %sjson:"target,omitempty"%s
	Metadata  map[string]interface{} %sjson:"metadata,omitempty"%s
}

// Alert represents a security alert.
type Alert struct {
	ID        string    %sjson:"id"%s
	RuleID    string    %sjson:"rule_id"%s
	RuleName  string    %sjson:"rule_name"%s
	Severity  string    %sjson:"severity"%s
	Status    string    %sjson:"status"%s
	Events    []Event   %sjson:"events"%s
	CreatedAt time.Time %sjson:"created_at"%s
}

// EventFilter filters events.
type EventFilter struct {
	StartTime time.Time
	EndTime   time.Time
	Actions   []string
	Sources   []string
	MinSeverity int
}

// AlertFilter filters alerts.
type AlertFilter struct {
	Status   string
	Severity string
	RuleID   string
}

// Source represents an event source.
type Source struct {
	Host string %sjson:"host"%s
	IP   string %sjson:"ip,omitempty"%s
	Type string %sjson:"type"%s
}
`, config.PackageName, config.PackageName, "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`")
}

func (g *SDKGenerator) generatePythonClient(config *SDKConfig) string {
	return fmt.Sprintf(`"""Boundary SIEM Python Client."""

from typing import List, Optional, Dict, Any
import requests

class Client:
    """Boundary SIEM API client."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {api_key}"

    def get_events(self, filter: Optional[Dict[str, Any]] = None) -> List[Dict]:
        """Get security events."""
        response = self.session.get(f"{self.base_url}/api/v1/events", params=filter)
        response.raise_for_status()
        return response.json()["data"]

    def get_alerts(self, filter: Optional[Dict[str, Any]] = None) -> List[Dict]:
        """Get security alerts."""
        response = self.session.get(f"{self.base_url}/api/v1/alerts", params=filter)
        response.raise_for_status()
        return response.json()["data"]

    def acknowledge_alert(self, alert_id: str, comment: str = "") -> Dict:
        """Acknowledge an alert."""
        response = self.session.post(
            f"{self.base_url}/api/v1/alerts/{alert_id}/acknowledge",
            json={"comment": comment}
        )
        response.raise_for_status()
        return response.json()["data"]
`)
}

func (g *SDKGenerator) generatePythonTypes(config *SDKConfig) string {
	return `"""Boundary SIEM Types."""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Dict, Any

@dataclass
class Source:
    """Event source."""
    host: str
    ip: Optional[str] = None
    type: str = ""

@dataclass
class Event:
    """Security event."""
    id: str
    timestamp: datetime
    action: str
    outcome: str
    severity: int
    source: Source
    target: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class Alert:
    """Security alert."""
    id: str
    rule_id: str
    rule_name: str
    severity: str
    status: str
    events: List[Event]
    created_at: datetime
`
}

func (g *SDKGenerator) generateTypeScriptClient(config *SDKConfig) string {
	return fmt.Sprintf(`/**
 * Boundary SIEM TypeScript Client
 */

export class Client {
  private baseURL: string;
  private apiKey: string;

  constructor(baseURL: string, apiKey: string) {
    this.baseURL = baseURL;
    this.apiKey = apiKey;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const response = await fetch(this.baseURL + path, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + this.apiKey,
        ...options.headers,
      },
    });
    if (!response.ok) {
      throw new Error('API request failed');
    }
    const json = await response.json();
    return json.data;
  }

  async getEvents(filter?: EventFilter): Promise<Event[]> {
    const params = new URLSearchParams(filter as any).toString();
    return this.request('/api/v1/events?' + params);
  }

  async getAlerts(filter?: AlertFilter): Promise<Alert[]> {
    const params = new URLSearchParams(filter as any).toString();
    return this.request('/api/v1/alerts?' + params);
  }

  async acknowledgeAlert(id: string, comment?: string): Promise<Alert> {
    return this.request('/api/v1/alerts/' + id + '/acknowledge', {
      method: 'POST',
      body: JSON.stringify({ comment }),
    });
  }
}
`)
}

func (g *SDKGenerator) generateTypeScriptTypes(config *SDKConfig) string {
	return `/**
 * Boundary SIEM TypeScript Types
 */

export interface Source {
  host: string;
  ip?: string;
  type: string;
}

export interface Event {
  id: string;
  timestamp: string;
  action: string;
  outcome: string;
  severity: number;
  source: Source;
  target?: string;
  metadata?: Record<string, unknown>;
}

export interface Alert {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: 'open' | 'acknowledged' | 'investigating' | 'resolved' | 'closed';
  events: Event[];
  created_at: string;
}

export interface EventFilter {
  start_time?: string;
  end_time?: string;
  actions?: string[];
  sources?: string[];
  min_severity?: number;
}

export interface AlertFilter {
  status?: string;
  severity?: string;
  rule_id?: string;
}
`
}

func (g *SDKGenerator) generateJavaClient(config *SDKConfig) string {
	return fmt.Sprintf(`package %s;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.util.List;

/**
 * Boundary SIEM Java Client.
 */
public class Client {
    private final String baseURL;
    private final String apiKey;
    private final HttpClient httpClient;

    public Client(String baseURL, String apiKey) {
        this.baseURL = baseURL;
        this.apiKey = apiKey;
        this.httpClient = HttpClient.newHttpClient();
    }

    public List<Event> getEvents(EventFilter filter) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseURL + "/api/v1/events"))
            .header("Authorization", "Bearer " + apiKey)
            .GET()
            .build();
        HttpResponse<String> response = httpClient.send(request,
            HttpResponse.BodyHandlers.ofString());
        // Parse and return events
        return null;
    }

    public List<Alert> getAlerts(AlertFilter filter) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseURL + "/api/v1/alerts"))
            .header("Authorization", "Bearer " + apiKey)
            .GET()
            .build();
        HttpResponse<String> response = httpClient.send(request,
            HttpResponse.BodyHandlers.ofString());
        // Parse and return alerts
        return null;
    }

    public Alert acknowledgeAlert(String id, String comment) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseURL + "/api/v1/alerts/" + id + "/acknowledge"))
            .header("Authorization", "Bearer " + apiKey)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString("{\"comment\":\"" + comment + "\"}"))
            .build();
        HttpResponse<String> response = httpClient.send(request,
            HttpResponse.BodyHandlers.ofString());
        // Parse and return alert
        return null;
    }
}
`, config.PackageName)
}

func (g *SDKGenerator) generateJavaTypes(config *SDKConfig) string {
	return fmt.Sprintf(`package %s;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Boundary SIEM Types.
 */
public class Types {

    public static class Source {
        public String host;
        public String ip;
        public String type;
    }

    public static class Event {
        public String id;
        public Instant timestamp;
        public String action;
        public String outcome;
        public int severity;
        public Source source;
        public String target;
        public Map<String, Object> metadata;
    }

    public static class Alert {
        public String id;
        public String ruleId;
        public String ruleName;
        public String severity;
        public String status;
        public List<Event> events;
        public Instant createdAt;
    }

    public static class EventFilter {
        public Instant startTime;
        public Instant endTime;
        public List<String> actions;
        public List<String> sources;
        public int minSeverity;
    }

    public static class AlertFilter {
        public String status;
        public String severity;
        public String ruleId;
    }
}
`, config.PackageName)
}

// SupportedLanguages returns supported SDK languages.
func SupportedLanguages() []string {
	return []string{"go", "python", "typescript", "java"}
}

// OpenAPI generates OpenAPI specification.
func GenerateOpenAPISpec(routes []*Route) map[string]interface{} {
	paths := make(map[string]interface{})

	for _, route := range routes {
		pathKey := route.Path
		if _, exists := paths[pathKey]; !exists {
			paths[pathKey] = make(map[string]interface{})
		}

		method := strings.ToLower(route.Method)
		paths[pathKey].(map[string]interface{})[method] = map[string]interface{}{
			"summary":     route.Description,
			"tags":        route.Tags,
			"deprecated":  route.Deprecated,
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Successful response",
				},
			},
		}
	}

	return map[string]interface{}{
		"openapi": "3.0.3",
		"info": map[string]interface{}{
			"title":       "Boundary SIEM API",
			"description": "Security Information and Event Management API",
			"version":     "1.0.0",
		},
		"paths": paths,
	}
}

// Helper to get type name via reflection
func getTypeName(v interface{}) string {
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t.Name()
}
