package search

import (
	"context"
	"database/sql"
	"fmt"
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

// Executor executes search queries against ClickHouse.
type Executor struct {
	db *sql.DB
}

// NewExecutor creates a new search executor.
func NewExecutor(db *sql.DB) *Executor {
	return &Executor{db: db}
}

// Search executes a search query and returns results.
func (e *Executor) Search(ctx context.Context, query *Query) (*SearchResponse, error) {
	start := time.Now()

	// Build WHERE clause
	whereClause, args := e.buildWhereClause(query)

	// Build count query
	countSQL := fmt.Sprintf("SELECT count(*) FROM events %s", whereClause)

	var totalCount int64
	if err := e.db.QueryRowContext(ctx, countSQL, args...).Scan(&totalCount); err != nil {
		return nil, fmt.Errorf("count query failed: %w", err)
	}

	// Build search query
	searchSQL := fmt.Sprintf(`
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
		%s
		ORDER BY %s %s
		LIMIT %d OFFSET %d
	`, whereClause, e.sanitizeOrderBy(query.OrderBy), e.orderDirection(query.OrderDesc),
		query.Limit, query.Offset)

	rows, err := e.db.QueryContext(ctx, searchSQL, args...)
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
func (e *Executor) Aggregate(ctx context.Context, query *Query, field string, aggType string) (*AggregationResult, error) {
	// Map field name to column
	column, _ := MapField(field)
	column = e.sanitizeColumn(column)

	// Build WHERE clause
	whereClause, args := e.buildWhereClause(query)

	var sqlQuery string
	switch strings.ToLower(aggType) {
	case "count":
		sqlQuery = fmt.Sprintf(`
			SELECT %s as key, count(*) as cnt
			FROM events
			%s
			GROUP BY %s
			ORDER BY cnt DESC
			LIMIT 100
		`, column, whereClause, column)

	case "sum", "avg", "min", "max":
		sqlQuery = fmt.Sprintf(`
			SELECT %s(%s) as value
			FROM events
			%s
		`, strings.ToUpper(aggType), column, whereClause)

	case "histogram":
		// Time-based histogram
		sqlQuery = fmt.Sprintf(`
			SELECT
				toStartOfHour(timestamp) as key,
				count(*) as cnt
			FROM events
			%s
			GROUP BY key
			ORDER BY key
		`, whereClause)

	case "terms":
		sqlQuery = fmt.Sprintf(`
			SELECT %s as key, count(*) as cnt
			FROM events
			%s
			GROUP BY %s
			ORDER BY cnt DESC
			LIMIT 20
		`, column, whereClause, column)

	default:
		return nil, fmt.Errorf("unsupported aggregation type: %s", aggType)
	}

	rows, err := e.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("aggregation query failed: %w", err)
	}
	defer rows.Close()

	result := &AggregationResult{}

	if aggType == "sum" || aggType == "avg" || aggType == "min" || aggType == "max" {
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

	return &r, nil
}

// buildWhereClause builds a SQL WHERE clause from query conditions.
func (e *Executor) buildWhereClause(query *Query) (string, []interface{}) {
	if len(query.Conditions) == 0 && query.TimeRange == nil {
		return "", nil
	}

	var clauses []string
	var args []interface{}

	// Add time range if specified
	if query.TimeRange != nil {
		if !query.TimeRange.Start.IsZero() {
			clauses = append(clauses, "timestamp >= ?")
			args = append(args, query.TimeRange.Start)
		}
		if !query.TimeRange.End.IsZero() {
			clauses = append(clauses, "timestamp <= ?")
			args = append(args, query.TimeRange.End)
		}
	}

	// Add conditions
	for i, cond := range query.Conditions {
		column, _ := MapField(cond.Field)
		column = e.sanitizeColumn(column)

		clause, clauseArgs := e.buildConditionClause(column, cond)
		clauses = append(clauses, clause)
		args = append(args, clauseArgs...)

		// Add logic operator
		if i < len(query.Logic) {
			// Logic is applied between current and next condition
			// We'll handle this in clause joining
		}
	}

	if len(clauses) == 0 {
		return "", nil
	}

	// Join clauses with logic operators
	var result strings.Builder
	result.WriteString("WHERE ")

	for i, clause := range clauses {
		if i > 0 {
			logic := "AND"
			if i-1 < len(query.Logic) {
				logic = query.Logic[i-1]
			}
			result.WriteString(" " + logic + " ")
		}
		result.WriteString(clause)
	}

	return result.String(), args
}

// buildConditionClause builds a SQL clause for a single condition.
func (e *Executor) buildConditionClause(column string, cond Condition) (string, []interface{}) {
	switch cond.Operator {
	case OpEquals:
		if cond.IsRegex {
			return fmt.Sprintf("match(%s, ?)", column), []interface{}{cond.Value}
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

// sanitizeColumn ensures column name is safe for SQL.
func (e *Executor) sanitizeColumn(column string) string {
	// Allow only alphanumeric and underscore
	var result strings.Builder
	for _, r := range column {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// sanitizeOrderBy ensures order by column is valid.
func (e *Executor) sanitizeOrderBy(orderBy string) string {
	validColumns := map[string]bool{
		"timestamp":      true,
		"received_at":    true,
		"severity":       true,
		"action":         true,
		"source_product": true,
		"actor_name":     true,
	}

	col := e.sanitizeColumn(orderBy)
	if validColumns[col] {
		return col
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
func (e *Executor) TimeHistogram(ctx context.Context, query *Query, interval string) (*AggregationResult, error) {
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

	whereClause, args := e.buildWhereClause(query)

	sqlQuery := fmt.Sprintf(`
		SELECT
			%s(timestamp) as bucket,
			count(*) as cnt
		FROM events
		%s
		GROUP BY bucket
		ORDER BY bucket
	`, intervalFunc, whereClause)

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

// TopN returns top N values for a field.
func (e *Executor) TopN(ctx context.Context, query *Query, field string, n int) (*AggregationResult, error) {
	column, _ := MapField(field)
	column = e.sanitizeColumn(column)

	if n <= 0 || n > 1000 {
		n = 10
	}

	whereClause, args := e.buildWhereClause(query)

	sqlQuery := fmt.Sprintf(`
		SELECT
			%s as key,
			count(*) as cnt
		FROM events
		%s
		GROUP BY key
		ORDER BY cnt DESC
		LIMIT %d
	`, column, whereClause, n)

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
