package search

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SearchResult represents a single event in search results.
type SearchResult struct {
	EventID          uuid.UUID `json:"event_id"`
	Timestamp        time.Time `json:"timestamp"`
	ReceivedAt       time.Time `json:"received_at"`
	TenantID         string    `json:"tenant_id"`
	Action           string    `json:"action"`
	Outcome          string    `json:"outcome"`
	Severity         int       `json:"severity"`
	Target           string    `json:"target,omitempty"`
	Raw              string    `json:"raw,omitempty"`
	SourceProduct    string    `json:"source_product"`
	SourceHost       string    `json:"source_host,omitempty"`
	SourceInstanceID string    `json:"source_instance_id,omitempty"`
	SourceVersion    string    `json:"source_version,omitempty"`
	// SourceVendor is metadata["device_vendor"] (set by the CEF normalizer);
	// the events table has no vendor column.
	SourceVendor string `json:"source_vendor"`
	// SourceIP is SourceHost when that is an IP address; the events table has
	// no separate source IP column.
	SourceIP      string                 `json:"source_ip,omitempty"`
	ActorType     string                 `json:"actor_type,omitempty"`
	ActorName     string                 `json:"actor_name,omitempty"`
	ActorID       string                 `json:"actor_id,omitempty"`
	ActorEmail    string                 `json:"actor_email,omitempty"`
	ActorIP       string                 `json:"actor_ip,omitempty"`
	SchemaVersion string                 `json:"schema_version,omitempty"`
	RequestID     string                 `json:"request_id,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// SearchResponse represents the response from a search query.
type SearchResponse struct {
	Query      string          `json:"query"`
	TotalCount int64           `json:"total_count"`
	Results    []*SearchResult `json:"results"`
	Took       time.Duration   `json:"took_ms"`
	Limit      int             `json:"limit"`
	Offset     int             `json:"offset"`
}

// AggregationResult represents aggregation query results.
type AggregationResult struct {
	Buckets []AggregationBucket `json:"buckets"`
	Total   int64               `json:"total"`
}

// AggregationBucket represents a single aggregation bucket.
type AggregationBucket struct {
	Key   interface{} `json:"key"`
	Count int64       `json:"count"`
	Value float64     `json:"value,omitempty"`
}

// truncateForLog truncates a string for safe inclusion in log messages.
func truncateForLog(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "...[truncated]"
	}
	return s
}

// Executor executes search queries against ClickHouse.
//
// SQL text is only ever assembled from string constants, identifiers resolved
// through the allowlists below, and clauses from buildWhereClause. Every value
// that originates from a request (condition values, tenant ID, time range,
// limits and offsets) is passed to the driver as a bound argument.
type Executor struct {
	db *sql.DB
}

// NewExecutor creates a new search executor.
func NewExecutor(db *sql.DB) *Executor {
	return &Executor{db: db}
}

// eventColumnList is the projection returned by Search and GetEvent, in the
// order scanEvent reads it. Every entry must be a column of the events table
// (TestEventColumnsExistInMigrations checks this against the migrations).
var eventColumnList = []string{
	"event_id", "timestamp", "received_at", "tenant_id", "action", "outcome", "severity",
	"target", "raw", "source_product", "source_host", "source_instance_id", "source_version",
	"actor_type", "actor_name", "actor_id", "actor_email", "actor_ip",
	"schema_version", "request_id", "metadata",
}

// eventColumns is eventColumnList as a SELECT list.
var eventColumns = strings.Join(eventColumnList, ", ")

// rowScanner is implemented by *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanEvent reads one row selected with eventColumns.
func scanEvent(row rowScanner) (*SearchResult, error) {
	var r SearchResult
	var metadataJSON string

	if err := row.Scan(
		&r.EventID,
		&r.Timestamp,
		&r.ReceivedAt,
		&r.TenantID,
		&r.Action,
		&r.Outcome,
		&r.Severity,
		&r.Target,
		&r.Raw,
		&r.SourceProduct,
		&r.SourceHost,
		&r.SourceInstanceID,
		&r.SourceVersion,
		&r.ActorType,
		&r.ActorName,
		&r.ActorID,
		&r.ActorEmail,
		&r.ActorIP,
		&r.SchemaVersion,
		&r.RequestID,
		&metadataJSON,
	); err != nil {
		return nil, err
	}

	if metadataJSON != "" {
		r.Metadata = make(map[string]interface{})
		if err := json.Unmarshal([]byte(metadataJSON), &r.Metadata); err != nil {
			slog.Warn("failed to unmarshal event metadata", "event_id", r.EventID, "error", err)
		}
	}

	// Compatibility fields for API clients written against source_vendor and
	// source_ip.
	if vendor, ok := r.Metadata["device_vendor"].(string); ok {
		r.SourceVendor = vendor
	}
	if net.ParseIP(r.SourceHost) != nil {
		r.SourceIP = r.SourceHost
	}

	return &r, nil
}

// joinSQL assembles a statement from SQL fragments separated by spaces,
// skipping empty ones. Each fragment must be a string constant, an identifier
// resolved through one of the allowlists in this file, or a clause produced
// by buildWhereClause; request values must be passed as bound arguments.
func joinSQL(fragments ...string) string {
	var sb strings.Builder
	for _, f := range fragments {
		if f == "" {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(f)
	}
	return sb.String()
}

// withArgs returns a new argument slice with extra appended, leaving args
// untouched so it can be reused for other statements.
func withArgs(args []interface{}, extra ...interface{}) []interface{} {
	out := make([]interface{}, 0, len(args)+len(extra))
	out = append(out, args...)
	return append(out, extra...)
}

// Search executes a search query and returns results.
// The query must have TenantID set for tenant isolation.
func (e *Executor) Search(ctx context.Context, query *Query) (*SearchResponse, error) {
	if query.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required for search queries")
	}

	start := time.Now()

	// Build WHERE clause
	whereClause, args, err := e.buildWhereClause(query)
	if err != nil {
		return nil, fmt.Errorf("invalid search query: %w", err)
	}

	// Build count query
	countSQL := joinSQL("SELECT count(*) FROM events", whereClause)

	var totalCount int64
	if err := e.db.QueryRowContext(ctx, countSQL, args...).Scan(&totalCount); err != nil {
		return nil, fmt.Errorf("count query failed: %w", err)
	}

	// Build search query
	searchSQL := joinSQL(
		"SELECT", eventColumns,
		"FROM events",
		whereClause,
		"ORDER BY", e.sanitizeOrderBy(query.OrderBy), e.orderDirection(query.OrderDesc),
		"LIMIT ? OFFSET ?",
	)

	rows, err := e.db.QueryContext(ctx, searchSQL, withArgs(args, query.Limit, query.Offset)...)
	if err != nil {
		return nil, fmt.Errorf("search query failed: %w", err)
	}
	defer rows.Close()

	var results []*SearchResult
	for rows.Next() {
		r, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		results = append(results, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration failed: %w", err)
	}

	return &SearchResponse{
		Query:      query.String(),
		TotalCount: totalCount,
		Results:    results,
		Took:       time.Since(start),
		Limit:      query.Limit,
		Offset:     query.Offset,
	}, nil
}

// Aggregate executes an aggregation query.
// The query must have TenantID set for tenant isolation.
func (e *Executor) Aggregate(ctx context.Context, query *Query, field string, aggType string) (*AggregationResult, error) {
	if query.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required for aggregation queries")
	}

	// Build WHERE clause
	whereClause, args, err := e.buildWhereClause(query)
	if err != nil {
		return nil, fmt.Errorf("invalid aggregation query: %w", err)
	}

	aggType = strings.ToLower(aggType)
	singleValue := false

	// The field expression comes first in the statement, so its bound
	// arguments (a metadata key) precede the WHERE clause arguments.
	var sqlQuery string
	switch aggType {
	case "count", "terms":
		limit := "LIMIT 100"
		if aggType == "terms" {
			limit = "LIMIT 20"
		}
		expr, exprArgs := e.fieldExpr(field, false)
		args = withArgs(exprArgs, args...)
		sqlQuery = joinSQL(
			"SELECT", expr, "AS key, count(*) AS cnt",
			"FROM events",
			whereClause,
			"GROUP BY key",
			"ORDER BY cnt DESC",
			limit,
		)

	case "sum", "avg", "min", "max":
		safeFn, ok := sanitizeAggFunction(aggType)
		if !ok {
			return nil, fmt.Errorf("unsupported aggregation function: %s", aggType)
		}
		singleValue = true
		expr, exprArgs := e.fieldExpr(field, true)
		args = withArgs(exprArgs, args...)
		sqlQuery = joinSQL(
			"SELECT", safeFn+"("+expr+") AS value",
			"FROM events",
			whereClause,
		)

	case "histogram":
		// Time-based histogram
		sqlQuery = joinSQL(
			"SELECT toStartOfHour(timestamp) AS key, count(*) AS cnt",
			"FROM events",
			whereClause,
			"GROUP BY key",
			"ORDER BY key",
		)

	default:
		return nil, fmt.Errorf("unsupported aggregation type: %s", truncateForLog(aggType, 100))
	}

	rows, err := e.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("aggregation query failed: %w", err)
	}
	defer rows.Close()

	result := &AggregationResult{}

	if singleValue {
		// Single value aggregation
		if rows.Next() {
			var value float64
			if err := rows.Scan(&value); err != nil {
				return nil, err
			}
			result.Buckets = append(result.Buckets, AggregationBucket{
				Key:   aggType,
				Value: value,
			})
		}
	} else {
		// Bucket aggregation
		for rows.Next() {
			var bucket AggregationBucket
			var key interface{}
			var count int64

			if err := rows.Scan(&key, &count); err != nil {
				return nil, err
			}

			bucket.Key = key
			bucket.Count = count
			result.Total += count
			result.Buckets = append(result.Buckets, bucket)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

// GetEvent retrieves a single event of the given tenant by ID. It returns
// nil, nil when the tenant has no such event, including when the ID belongs
// to another tenant.
func (e *Executor) GetEvent(ctx context.Context, tenantID string, eventID uuid.UUID) (*SearchResult, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required for event lookups")
	}

	query := joinSQL(
		"SELECT", eventColumns,
		"FROM events",
		"WHERE tenant_id = ? AND event_id = ?",
		"LIMIT 1",
	)

	r, err := scanEvent(e.db.QueryRowContext(ctx, query, tenantID, eventID.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	return r, nil
}

// buildWhereClause builds a SQL WHERE clause from query conditions.
// Supports parenthetical grouping via OpenParens/CloseParens on conditions.
//
// The tenant and time-range filters are always ANDed with the user
// conditions, which are wrapped in their own parentheses so that a top-level
// OR in the search expression cannot widen the result beyond the tenant.
func (e *Executor) buildWhereClause(query *Query) (string, []interface{}, error) {
	var parts []string
	var args []interface{}

	// Enforce tenant isolation — always filter by tenant_id when set
	if query.TenantID != "" {
		parts = append(parts, "tenant_id = ?")
		args = append(args, query.TenantID)
	}

	// Add time range if specified
	if query.TimeRange != nil {
		if !query.TimeRange.Start.IsZero() {
			parts = append(parts, "timestamp >= ?")
			args = append(args, query.TimeRange.Start)
		}
		if !query.TimeRange.End.IsZero() {
			parts = append(parts, "timestamp <= ?")
			args = append(args, query.TimeRange.End)
		}
	}

	condExpr, condArgs, err := e.buildConditionExpr(query)
	if err != nil {
		return "", nil, err
	}
	if condExpr != "" {
		if len(parts) > 0 {
			condExpr = "(" + condExpr + ")"
		}
		parts = append(parts, condExpr)
		args = append(args, condArgs...)
	}

	if len(parts) == 0 {
		return "", nil, nil
	}

	return "WHERE " + strings.Join(parts, " AND "), args, nil
}

// buildConditionExpr joins the query's conditions with their AND/OR
// connectives and parenthetical grouping. Connectives must be AND or OR and
// parentheses must balance: either would otherwise let a condition alter the
// structure of the surrounding WHERE clause.
func (e *Executor) buildConditionExpr(query *Query) (string, []interface{}, error) {
	var sb strings.Builder
	var args []interface{}
	depth := 0

	for i, cond := range query.Conditions {
		if i > 0 {
			logic := "AND"
			if i-1 < len(query.Logic) {
				op, ok := logicOperators[strings.ToUpper(query.Logic[i-1])]
				if !ok {
					return "", nil, fmt.Errorf("unsupported logical operator %q", truncateForLog(query.Logic[i-1], 20))
				}
				logic = op
			}
			sb.WriteString(" ")
			sb.WriteString(logic)
			sb.WriteString(" ")
		}

		if cond.OpenParens < 0 || cond.CloseParens < 0 {
			return "", nil, errUnbalancedParens
		}

		// Metadata conditions address the JSON column through a bound key and
		// never use the column identifier. Fields aliased to a metadata key
		// (e.g. vendor) are metadata conditions even when the Query was built
		// without ParseQuery.
		if !cond.IsMetadata {
			if key, ok := metadataKey(cond.Field); ok {
				cond.IsMetadata, cond.MetadataKey = true, key
			}
		}
		var column string
		if !cond.IsMetadata {
			mapped, _ := MapField(cond.Field)
			column = e.sanitizeColumn(mapped)
		}
		clause, clauseArgs := e.buildConditionClause(column, cond)

		sb.WriteString(strings.Repeat("(", cond.OpenParens))
		sb.WriteString(clause)
		sb.WriteString(strings.Repeat(")", cond.CloseParens))
		args = append(args, clauseArgs...)

		depth += cond.OpenParens - cond.CloseParens
		if depth < 0 {
			return "", nil, errUnbalancedParens
		}
	}

	if depth != 0 {
		return "", nil, errUnbalancedParens
	}

	return sb.String(), args, nil
}

// buildConditionClause builds a SQL clause for a single condition.
func (e *Executor) buildConditionClause(column string, cond Condition) (string, []interface{}) {
	// Handle metadata field queries: metadata.key → JSON extraction
	if cond.IsMetadata {
		return e.buildMetadataClause(cond)
	}

	switch cond.Operator {
	case OpEquals:
		if cond.IsRegex {
			// Validate regex pattern length to prevent resource exhaustion in ClickHouse
			if tooLongPattern(cond.Value) {
				return "1=0", nil // reject overly long patterns
			}
			return fmt.Sprintf("match(%s, ?)", column), []interface{}{cond.Value}
		}
		if cond.IsPhrase {
			// Phrase search: use position() for exact phrase match
			return fmt.Sprintf("position(%s, ?) > 0", column), []interface{}{cond.Value}
		}
		return fmt.Sprintf("%s = ?", column), []interface{}{cond.Value}

	case OpNotEquals:
		// The complement of each OpEquals form (NOT pushes down to here).
		if cond.IsRegex {
			if tooLongPattern(cond.Value) {
				return "1=0", nil
			}
			return fmt.Sprintf("NOT match(%s, ?)", column), []interface{}{cond.Value}
		}
		if cond.IsPhrase {
			return fmt.Sprintf("position(%s, ?) = 0", column), []interface{}{cond.Value}
		}
		return fmt.Sprintf("%s != ?", column), []interface{}{cond.Value}

	case OpGreater:
		return fmt.Sprintf("%s > ?", column), []interface{}{cond.Value}

	case OpGreaterEq:
		return fmt.Sprintf("%s >= ?", column), []interface{}{cond.Value}

	case OpLess:
		return fmt.Sprintf("%s < ?", column), []interface{}{cond.Value}

	case OpLessEq:
		return fmt.Sprintf("%s <= ?", column), []interface{}{cond.Value}

	case OpContains:
		return fmt.Sprintf("position(%s, ?) > 0", column), []interface{}{cond.Value}

	case OpNotContains:
		return fmt.Sprintf("position(%s, ?) = 0", column), []interface{}{cond.Value}

	case OpExists:
		return fmt.Sprintf("%s != ''", column), nil

	case OpNotExists:
		return fmt.Sprintf("%s = ''", column), nil

	default:
		return fmt.Sprintf("%s = ?", column), []interface{}{cond.Value}
	}
}

// tooLongPattern reports whether a regex value exceeds the accepted length.
func tooLongPattern(value interface{}) bool {
	pattern, ok := value.(string)
	return ok && len(pattern) > 1024
}

// buildMetadataClause builds a SQL clause for a metadata JSON field query.
func (e *Executor) buildMetadataClause(cond Condition) (string, []interface{}) {
	jsonPath := cond.MetadataKey

	switch cond.Operator {
	case OpEquals:
		if cond.IsRegex {
			if tooLongPattern(cond.Value) {
				return "1=0", nil
			}
			return "match(JSONExtractString(metadata, ?), ?)", []interface{}{jsonPath, cond.Value}
		}
		if cond.IsPhrase {
			return "position(JSONExtractString(metadata, ?), ?) > 0", []interface{}{jsonPath, cond.Value}
		}
		return "JSONExtractString(metadata, ?) = ?", []interface{}{jsonPath, cond.Value}
	case OpNotEquals:
		if cond.IsRegex {
			if tooLongPattern(cond.Value) {
				return "1=0", nil
			}
			return "NOT match(JSONExtractString(metadata, ?), ?)", []interface{}{jsonPath, cond.Value}
		}
		if cond.IsPhrase {
			return "position(JSONExtractString(metadata, ?), ?) = 0", []interface{}{jsonPath, cond.Value}
		}
		return "JSONExtractString(metadata, ?) != ?", []interface{}{jsonPath, cond.Value}
	case OpGreater:
		return "JSONExtractFloat(metadata, ?) > ?", []interface{}{jsonPath, cond.Value}
	case OpGreaterEq:
		return "JSONExtractFloat(metadata, ?) >= ?", []interface{}{jsonPath, cond.Value}
	case OpLess:
		return "JSONExtractFloat(metadata, ?) < ?", []interface{}{jsonPath, cond.Value}
	case OpLessEq:
		return "JSONExtractFloat(metadata, ?) <= ?", []interface{}{jsonPath, cond.Value}
	case OpContains:
		return "position(JSONExtractString(metadata, ?), ?) > 0", []interface{}{jsonPath, cond.Value}
	case OpNotContains:
		return "position(JSONExtractString(metadata, ?), ?) = 0", []interface{}{jsonPath, cond.Value}
	case OpExists:
		return "JSONHas(metadata, ?) = 1", []interface{}{jsonPath}
	case OpNotExists:
		return "JSONHas(metadata, ?) = 0", []interface{}{jsonPath}
	default:
		return "JSONExtractString(metadata, ?) = ?", []interface{}{jsonPath, cond.Value}
	}
}

// errUnbalancedParens is returned when a query's grouping parentheses do not
// pair up.
var errUnbalancedParens = errors.New("unbalanced parentheses in query")

// The allowlists below map accepted input to the exact text written into SQL.
// Lookups return the map value (a compile-time constant), so no part of the
// caller-supplied string ever becomes part of a statement.

// logicOperators maps accepted (upper-cased) connectives to SQL keywords.
var logicOperators = map[string]string{
	"AND": "AND",
	"OR":  "OR",
}

// validAggFunctions is an allowlist of valid SQL aggregation functions.
var validAggFunctions = map[string]string{
	"SUM": "SUM", "AVG": "AVG", "MIN": "MIN", "MAX": "MAX",
	"COUNT": "COUNT", "COUNT_DISTINCT": "COUNT_DISTINCT",
}

// sanitizeAggFunction validates and returns a safe aggregation function name.
func sanitizeAggFunction(fn string) (string, bool) {
	safe, ok := validAggFunctions[strings.ToUpper(fn)]
	return safe, ok
}

// validColumns is an allowlist of known safe column names for SQL queries.
// Every entry must be a column of the events table (checked against the
// migrations by TestEventColumnsExistInMigrations).
var validColumns = map[string]string{
	"event_id":           "event_id",
	"timestamp":          "timestamp",
	"received_at":        "received_at",
	"tenant_id":          "tenant_id",
	"action":             "action",
	"outcome":            "outcome",
	"severity":           "severity",
	"target":             "target",
	"raw":                "raw",
	"source_product":     "source_product",
	"source_host":        "source_host",
	"source_instance_id": "source_instance_id",
	"source_version":     "source_version",
	"actor_name":         "actor_name",
	"actor_id":           "actor_id",
	"actor_type":         "actor_type",
	"actor_email":        "actor_email",
	"actor_ip":           "actor_ip",
	"metadata":           "metadata",
	"schema_version":     "schema_version",
	"request_id":         "request_id",
}

// validOrderByColumns is the subset of columns results may be sorted by.
var validOrderByColumns = map[string]string{
	"timestamp":      "timestamp",
	"received_at":    "received_at",
	"severity":       "severity",
	"action":         "action",
	"source_product": "source_product",
	"actor_name":     "actor_name",
}

// sanitizeColumn ensures column name is a known valid column.
// Returns "timestamp" as safe fallback for unknown columns.
func (e *Executor) sanitizeColumn(column string) string {
	if safe, ok := validColumns[column]; ok {
		return safe
	}
	slog.Warn("unknown column name rejected, using safe fallback",
		"requested", truncateForLog(column, 100),
		"fallback", "timestamp",
	)
	return "timestamp"
}

// fieldExpr returns the SQL expression that aggregations group or aggregate
// a field by, with its bound arguments. Metadata fields (metadata.<key>,
// meta.<key>, and aliases stored in metadata such as vendor) are extracted
// from the metadata JSON with the key bound as an argument — as a string, or
// as a number when numeric is set. Other fields resolve to an allowlisted
// column (see sanitizeColumn).
func (e *Executor) fieldExpr(field string, numeric bool) (string, []interface{}) {
	if key, ok := metadataKey(field); ok {
		if numeric {
			return "JSONExtractFloat(metadata, ?)", []interface{}{key}
		}
		return "JSONExtractString(metadata, ?)", []interface{}{key}
	}
	column, _ := MapField(field)
	return e.sanitizeColumn(column), nil
}

// sanitizeOrderBy ensures order by column is valid.
func (e *Executor) sanitizeOrderBy(orderBy string) string {
	if safe, ok := validOrderByColumns[e.sanitizeColumn(orderBy)]; ok {
		return safe
	}
	return "timestamp"
}

// orderDirection returns ASC or DESC.
func (e *Executor) orderDirection(desc bool) string {
	if desc {
		return "DESC"
	}
	return "ASC"
}

// TimeHistogram returns event counts over time.
// The query must have TenantID set for tenant isolation.
func (e *Executor) TimeHistogram(ctx context.Context, query *Query, interval string) (*AggregationResult, error) {
	if query.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required for time histogram queries")
	}

	// Map interval to ClickHouse function
	var intervalFunc string
	switch strings.ToLower(interval) {
	case "minute", "1m":
		intervalFunc = "toStartOfMinute"
	case "5m":
		intervalFunc = "toStartOfFiveMinutes"
	case "15m":
		intervalFunc = "toStartOfFifteenMinutes"
	case "hour", "1h":
		intervalFunc = "toStartOfHour"
	case "day", "1d":
		intervalFunc = "toStartOfDay"
	case "week", "1w":
		intervalFunc = "toStartOfWeek"
	case "month", "1M":
		intervalFunc = "toStartOfMonth"
	default:
		intervalFunc = "toStartOfHour"
	}

	whereClause, args, err := e.buildWhereClause(query)
	if err != nil {
		return nil, fmt.Errorf("invalid histogram query: %w", err)
	}

	sqlQuery := joinSQL(
		"SELECT", intervalFunc+"(timestamp) AS bucket, count(*) AS cnt",
		"FROM events",
		whereClause,
		"GROUP BY bucket",
		"ORDER BY bucket",
	)

	rows, err := e.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("histogram query failed: %w", err)
	}
	defer rows.Close()

	result := &AggregationResult{}
	for rows.Next() {
		var bucket time.Time
		var count int64

		if err := rows.Scan(&bucket, &count); err != nil {
			return nil, err
		}

		result.Buckets = append(result.Buckets, AggregationBucket{
			Key:   bucket,
			Count: count,
		})
		result.Total += count
	}

	return result, rows.Err()
}

// MaxTopN is the configurable upper bound for TopN queries.
// Can be changed at startup if needed.
var MaxTopN = 10000

// TopN returns top N values for a field.
// The query must have TenantID set for tenant isolation.
func (e *Executor) TopN(ctx context.Context, query *Query, field string, n int) (*AggregationResult, error) {
	if query.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required for top-n queries")
	}

	if n <= 0 || n > MaxTopN {
		n = 10
	}

	whereClause, args, err := e.buildWhereClause(query)
	if err != nil {
		return nil, fmt.Errorf("invalid top-n query: %w", err)
	}

	expr, exprArgs := e.fieldExpr(field, false)
	sqlQuery := joinSQL(
		"SELECT", expr, "AS key, count(*) AS cnt",
		"FROM events",
		whereClause,
		"GROUP BY key",
		"ORDER BY cnt DESC",
		"LIMIT ?",
	)

	args = withArgs(withArgs(exprArgs, args...), n)
	rows, err := e.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("top-n query failed: %w", err)
	}
	defer rows.Close()

	result := &AggregationResult{}
	for rows.Next() {
		var key interface{}
		var count int64

		if err := rows.Scan(&key, &count); err != nil {
			return nil, err
		}

		result.Buckets = append(result.Buckets, AggregationBucket{
			Key:   key,
			Count: count,
		})
		result.Total += count
	}

	return result, rows.Err()
}

// ExplainResult contains the ClickHouse EXPLAIN output for a query.
type ExplainResult struct {
	Query   string   `json:"query"`
	Plan    []string `json:"plan"`
	Indexes []string `json:"indexes,omitempty"`
}

// Explain returns the ClickHouse query plan for a search query.
// The query must have TenantID set for tenant isolation.
func (e *Executor) Explain(ctx context.Context, query *Query) (*ExplainResult, error) {
	if query.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required for explain queries")
	}

	whereClause, args, err := e.buildWhereClause(query)
	if err != nil {
		return nil, fmt.Errorf("invalid explain query: %w", err)
	}

	selectSQL := joinSQL(
		"SELECT event_id, timestamp, action, severity",
		"FROM events",
		whereClause,
		"ORDER BY", e.sanitizeOrderBy(query.OrderBy), e.orderDirection(query.OrderDesc),
		"LIMIT ? OFFSET ?",
	)
	args = withArgs(args, query.Limit, query.Offset)

	// EXPLAIN PLAN
	explainSQL := joinSQL("EXPLAIN PLAN", selectSQL)
	rows, err := e.db.QueryContext(ctx, explainSQL, args...)
	if err != nil {
		return nil, fmt.Errorf("explain query failed: %w", err)
	}
	defer rows.Close()

	result := &ExplainResult{Query: selectSQL}
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, err
		}
		result.Plan = append(result.Plan, line)
	}

	// EXPLAIN INDEXES
	indexSQL := joinSQL("EXPLAIN INDEXES = 1", selectSQL)
	indexRows, err := e.db.QueryContext(ctx, indexSQL, args...)
	if err == nil {
		defer indexRows.Close()
		for indexRows.Next() {
			var line string
			if err := indexRows.Scan(&line); err != nil {
				break
			}
			result.Indexes = append(result.Indexes, line)
		}
	}

	return result, nil
}
