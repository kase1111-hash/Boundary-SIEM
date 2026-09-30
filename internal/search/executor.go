package search

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SearchResult represents a single event in search results.
type SearchResult struct {
	EventID       uuid.UUID              `json:"event_id"`
	Timestamp     time.Time              `json:"timestamp"`
	ReceivedAt    time.Time              `json:"received_at"`
	TenantID      string                 `json:"tenant_id"`
	Action        string                 `json:"action"`
	Outcome       string                 `json:"outcome"`
	Severity      int                    `json:"severity"`
	Target        string                 `json:"target,omitempty"`
	Raw           string                 `json:"raw,omitempty"`
	SourceProduct string                 `json:"source_product"`
	SourceVendor  string                 `json:"source_vendor"`
	SourceIP      string                 `json:"source_ip,omitempty"`
	ActorName     string                 `json:"actor_name,omitempty"`
	ActorID       string                 `json:"actor_id,omitempty"`
	ActorIP       string                 `json:"actor_ip,omitempty"`
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

// eventColumns is the projection returned by Search and GetEvent.
const eventColumns = `event_id, timestamp, received_at, tenant_id, action, outcome, severity,
		target, raw, source_product, source_vendor, source_ip,
		actor_name, actor_id, actor_ip, metadata`

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
		var r SearchResult
		var metadataJSON string
		var target, raw, sourceIP, actorName, actorID, actorIP sql.NullString

		err := rows.Scan(
			&r.EventID,
			&r.Timestamp,
			&r.ReceivedAt,
			&r.TenantID,
			&r.Action,
			&r.Outcome,
			&r.Severity,
			&target,
			&raw,
			&r.SourceProduct,
			&r.SourceVendor,
			&sourceIP,
			&actorName,
			&actorID,
			&actorIP,
			&metadataJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}

		r.Target = target.String
		r.Raw = raw.String
		r.SourceIP = sourceIP.String
		r.ActorName = actorName.String
		r.ActorID = actorID.String
		r.ActorIP = actorIP.String

		if metadataJSON != "" {
			r.Metadata = make(map[string]interface{})
			if err := json.Unmarshal([]byte(metadataJSON), &r.Metadata); err != nil {
				slog.Warn("failed to unmarshal event metadata", "event_id", r.EventID, "error", err)
			}
		}

		results = append(results, &r)
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

	// Map field name to column
	column, _ := MapField(field)
	column = e.sanitizeColumn(column)

	// Build WHERE clause
	whereClause, args, err := e.buildWhereClause(query)
	if err != nil {
		return nil, fmt.Errorf("invalid aggregation query: %w", err)
	}

	aggType = strings.ToLower(aggType)
	singleValue := false

	var sqlQuery string
	switch aggType {
	case "count":
		sqlQuery = joinSQL(
			"SELECT", column, "AS key, count(*) AS cnt",
			"FROM events",
			whereClause,
			"GROUP BY", column,
			"ORDER BY cnt DESC",
			"LIMIT 100",
		)

	case "sum", "avg", "min", "max":
		safeFn, ok := sanitizeAggFunction(aggType)
		if !ok {
			return nil, fmt.Errorf("unsupported aggregation function: %s", aggType)
		}
		singleValue = true
		sqlQuery = joinSQL(
			"SELECT", safeFn+"("+column+") AS value",
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

	case "terms":
		sqlQuery = joinSQL(
			"SELECT", column, "AS key, count(*) AS cnt",
			"FROM events",
			whereClause,
			"GROUP BY", column,
			"ORDER BY cnt DESC",
			"LIMIT 20",
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

// GetEvent retrieves a single event by ID.
func (e *Executor) GetEvent(ctx context.Context, eventID uuid.UUID) (*SearchResult, error) {
	query := `
		SELECT
			event_id,
			timestamp,
			received_at,
			tenant_id,
			action,
			outcome,
			severity,
			target,
			raw,
			source_product,
			source_vendor,
			source_ip,
			actor_name,
			actor_id,
			actor_ip,
			metadata
		FROM events
		WHERE event_id = ?
		LIMIT 1
	`

	var r SearchResult
	var metadataJSON string
	var target, raw, sourceIP, actorName, actorID, actorIP sql.NullString

	err := e.db.QueryRowContext(ctx, query, eventID.String()).Scan(
		&r.EventID,
		&r.Timestamp,
		&r.ReceivedAt,
		&r.TenantID,
		&r.Action,
		&r.Outcome,
		&r.Severity,
		&target,
		&raw,
		&r.SourceProduct,
		&r.SourceVendor,
		&sourceIP,
		&actorName,
		&actorID,
		&actorIP,
		&metadataJSON,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	r.Target = target.String
	r.Raw = raw.String
	r.SourceIP = sourceIP.String
	r.ActorName = actorName.String
	r.ActorID = actorID.String
	r.ActorIP = actorIP.String

	if metadataJSON != "" {
		r.Metadata = make(map[string]interface{})
		if err := json.Unmarshal([]byte(metadataJSON), &r.Metadata); err != nil {
			slog.Warn("failed to unmarshal event metadata", "event_id", r.EventID, "error", err)
		}
	}

	return &r, nil
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
		// never use the column identifier.
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
			if pattern, ok := cond.Value.(string); ok && len(pattern) > 1024 {
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

// buildMetadataClause builds a SQL clause for a metadata JSON field query.
func (e *Executor) buildMetadataClause(cond Condition) (string, []interface{}) {
	jsonPath := cond.MetadataKey

	switch cond.Operator {
	case OpEquals:
		return "JSONExtractString(metadata, ?) = ?", []interface{}{jsonPath, cond.Value}
	case OpNotEquals:
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
var validColumns = map[string]string{
	"event_id":        "event_id",
	"timestamp":       "timestamp",
	"received_at":     "received_at",
	"tenant_id":       "tenant_id",
	"action":          "action",
	"outcome":         "outcome",
	"severity":        "severity",
	"target":          "target",
	"raw":             "raw",
	"source_product":  "source_product",
	"source_vendor":   "source_vendor",
	"source_version":  "source_version",
	"source_hostname": "source_hostname",
	"source_ip":       "source_ip",
	"actor_name":      "actor_name",
	"actor_id":        "actor_id",
	"actor_type":      "actor_type",
	"actor_ip":        "actor_ip",
	"metadata":        "metadata",
	"schema_version":  "schema_version",
	"request_id":      "request_id",
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

	column, _ := MapField(field)
	column = e.sanitizeColumn(column)

	if n <= 0 || n > MaxTopN {
		n = 10
	}

	whereClause, args, err := e.buildWhereClause(query)
	if err != nil {
		return nil, fmt.Errorf("invalid top-n query: %w", err)
	}

	sqlQuery := joinSQL(
		"SELECT", column, "AS key, count(*) AS cnt",
		"FROM events",
		whereClause,
		"GROUP BY key",
		"ORDER BY cnt DESC",
		"LIMIT ?",
	)

	rows, err := e.db.QueryContext(ctx, sqlQuery, withArgs(args, n)...)
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
