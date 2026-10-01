package search

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
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
	// Took is the search duration; the API reports it in milliseconds as
	// took_ms. (Encoding the Duration itself as took_ms reported
	// nanoseconds.)
	Took   time.Duration `json:"-"`
	TookMs int64         `json:"took_ms"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
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
		return nil, err // wraps ErrInvalidQuery
	}

	orderBy, err := e.sanitizeOrderBy(query.OrderBy)
	if err != nil {
		return nil, err
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
		"ORDER BY", orderBy, e.orderDirection(query.OrderDesc),
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

	took := time.Since(start)
	return &SearchResponse{
		Query:      query.String(),
		TotalCount: totalCount,
		Results:    results,
		Took:       took,
		TookMs:     took.Milliseconds(),
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
		return nil, err // wraps ErrInvalidQuery
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
		expr, exprArgs, err := e.fieldExpr(field, false)
		if err != nil {
			return nil, err
		}
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
			return nil, invalidQueryf("unsupported aggregation function %q", aggType)
		}
		singleValue = true
		expr, exprArgs, err := e.fieldExpr(field, true)
		if err != nil {
			return nil, err
		}
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
		return nil, invalidQueryf("unsupported aggregation type %q (use count, terms, sum, avg, min, max or histogram)",
			truncateForLog(aggType, 100))
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
					return "", nil, invalidQueryf("unsupported logical operator %q", truncateForLog(query.Logic[i-1], 20))
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
		// without ParseQuery. Free-text conditions search several columns.
		if !cond.IsMetadata && !cond.IsFreeText {
			if key, ok := metadataKey(cond.Field); ok {
				cond.IsMetadata, cond.MetadataKey = true, key
			}
		}
		var column string
		if !cond.IsMetadata && !cond.IsFreeText {
			var err error
			if column, err = e.fieldColumn(cond.Field); err != nil {
				return "", nil, err
			}
		}
		clause, clauseArgs, err := e.buildConditionClause(column, cond)
		if err != nil {
			return "", nil, err
		}

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

// buildConditionClause builds a SQL clause for a single condition on column
// (unused for metadata and free-text conditions). The operator and value
// must fit the column's type; otherwise the error wraps ErrInvalidQuery,
// where ClickHouse would fail the whole query (position() on a DateTime,
// 'bar' compared with a UInt8, ...).
func (e *Executor) buildConditionClause(column string, cond Condition) (string, []interface{}, error) {
	if cond.IsFreeText {
		return buildFreeTextClause(cond)
	}
	if cond.IsMetadata {
		return e.buildMetadataClause(cond)
	}
	if kind, typed := columnKinds[column]; typed {
		return typedConditionClause(column, kind, cond)
	}

	switch cond.Operator {
	case OpEquals:
		if cond.IsRegex {
			// Validate regex pattern length to prevent resource exhaustion in ClickHouse
			if tooLongPattern(cond.Value) {
				return "1=0", nil, nil // reject overly long patterns
			}
			return fmt.Sprintf("match(%s, ?)", column), []interface{}{cond.Value}, nil
		}
		if cond.IsPhrase {
			// Phrase search: use position() for exact phrase match
			return fmt.Sprintf("position(%s, ?) > 0", column), []interface{}{cond.Value}, nil
		}
		return fmt.Sprintf("%s = ?", column), []interface{}{cond.Value}, nil

	case OpNotEquals:
		// The complement of each OpEquals form (NOT pushes down to here).
		if cond.IsRegex {
			if tooLongPattern(cond.Value) {
				return "1=0", nil, nil
			}
			return fmt.Sprintf("NOT match(%s, ?)", column), []interface{}{cond.Value}, nil
		}
		if cond.IsPhrase {
			return fmt.Sprintf("position(%s, ?) = 0", column), []interface{}{cond.Value}, nil
		}
		return fmt.Sprintf("%s != ?", column), []interface{}{cond.Value}, nil

	case OpGreater:
		return fmt.Sprintf("%s > ?", column), []interface{}{cond.Value}, nil

	case OpGreaterEq:
		return fmt.Sprintf("%s >= ?", column), []interface{}{cond.Value}, nil

	case OpLess:
		return fmt.Sprintf("%s < ?", column), []interface{}{cond.Value}, nil

	case OpLessEq:
		return fmt.Sprintf("%s <= ?", column), []interface{}{cond.Value}, nil

	case OpContains:
		return fmt.Sprintf("position(%s, ?) > 0", column), []interface{}{cond.Value}, nil

	case OpNotContains:
		return fmt.Sprintf("position(%s, ?) = 0", column), []interface{}{cond.Value}, nil

	case OpExists:
		return fmt.Sprintf("%s != ''", column), nil, nil

	case OpNotExists:
		return fmt.Sprintf("%s = ''", column), nil, nil

	default:
		return "", nil, unsupportedOperator(cond)
	}
}

// unsupportedOperator is the error for an operator a condition cannot use.
func unsupportedOperator(cond Condition) error {
	return invalidQueryf("operator %q is not supported on field %q",
		truncateForLog(string(cond.Operator), 20), truncateForLog(cond.Field, 100))
}

// comparisonOperators are the operators numeric, time and UUID columns
// accept, mapped to their SQL text.
var comparisonOperators = map[Operator]string{
	OpEquals: "=", OpNotEquals: "!=",
	OpGreater: ">", OpGreaterEq: ">=", OpLess: "<", OpLessEq: "<=",
}

// typedConditionClause builds the clause for a numeric, time or UUID column:
// a comparison against a value converted to the column's type.
func typedConditionClause(column string, kind columnKind, cond Condition) (string, []interface{}, error) {
	field := truncateForLog(cond.Field, 100)
	if cond.IsRegex || cond.IsPhrase {
		return "", nil, invalidQueryf("field %q is not a text field; wildcards and phrases do not apply to it", field)
	}
	op, ok := comparisonOperators[cond.Operator]
	if !ok || (kind == kindUUID && cond.Operator != OpEquals && cond.Operator != OpNotEquals) {
		return "", nil, unsupportedOperator(cond)
	}

	var value interface{}
	switch kind {
	case kindNumber:
		switch v := cond.Value.(type) {
		case int, int64, float64:
			value = v
		case string:
			n, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return "", nil, invalidQueryf("field %q needs a number, got %q", field, truncateForLog(v, 100))
			}
			value = n
		default:
			return "", nil, invalidQueryf("field %q needs a number", field)
		}
	case kindTime:
		switch v := cond.Value.(type) {
		case time.Time:
			value = v
		case int64:
			value = unixTime(v)
		case string:
			t, err := parseTimeString(v)
			if err != nil {
				return "", nil, invalidQueryf("field %q needs a time (RFC 3339, YYYY-MM-DD, Unix seconds or now-1h), got %q",
					field, truncateForLog(v, 100))
			}
			value = t
		default:
			return "", nil, invalidQueryf("field %q needs a time", field)
		}
	case kindUUID:
		s, _ := cond.Value.(string)
		id, err := uuid.Parse(s)
		if err != nil {
			return "", nil, invalidQueryf("field %q needs a UUID, got %q", field, truncateForLog(s, 100))
		}
		value = id.String()
	}
	return fmt.Sprintf("%s %s ?", column, op), []interface{}{value}, nil
}

// buildFreeTextClause builds the clause for a term without a field: it
// matches when any of freeTextColumns contains the term (ignoring case), or
// for a wildcard term, matches its case-insensitive pattern.
func buildFreeTextClause(cond Condition) (string, []interface{}, error) {
	pred := "positionCaseInsensitiveUTF8(%s, ?) > 0"
	if cond.IsRegex {
		if tooLongPattern(cond.Value) {
			return "", nil, invalidQueryf("search term is too long")
		}
		pred = "match(%s, ?)"
	}
	parts := make([]string, len(freeTextColumns))
	args := make([]interface{}, len(freeTextColumns))
	for i, column := range freeTextColumns {
		parts[i] = fmt.Sprintf(pred, column)
		args[i] = cond.Value
	}
	clause := "(" + strings.Join(parts, " OR ") + ")"
	switch cond.Operator {
	case OpContains:
		return clause, args, nil
	case OpNotContains:
		return "NOT " + clause, args, nil
	default:
		return "", nil, unsupportedOperator(cond)
	}
}

// tooLongPattern reports whether a regex value exceeds the accepted length.
func tooLongPattern(value interface{}) bool {
	pattern, ok := value.(string)
	return ok && len(pattern) > 1024
}

// buildMetadataClause builds a SQL clause for a metadata JSON field query.
func (e *Executor) buildMetadataClause(cond Condition) (string, []interface{}, error) {
	jsonPath := cond.MetadataKey

	switch cond.Operator {
	case OpEquals:
		if cond.IsRegex {
			if tooLongPattern(cond.Value) {
				return "1=0", nil, nil
			}
			return "match(JSONExtractString(metadata, ?), ?)", []interface{}{jsonPath, cond.Value}, nil
		}
		if cond.IsPhrase {
			return "position(JSONExtractString(metadata, ?), ?) > 0", []interface{}{jsonPath, cond.Value}, nil
		}
		return "JSONExtractString(metadata, ?) = ?", []interface{}{jsonPath, cond.Value}, nil
	case OpNotEquals:
		if cond.IsRegex {
			if tooLongPattern(cond.Value) {
				return "1=0", nil, nil
			}
			return "NOT match(JSONExtractString(metadata, ?), ?)", []interface{}{jsonPath, cond.Value}, nil
		}
		if cond.IsPhrase {
			return "position(JSONExtractString(metadata, ?), ?) = 0", []interface{}{jsonPath, cond.Value}, nil
		}
		return "JSONExtractString(metadata, ?) != ?", []interface{}{jsonPath, cond.Value}, nil
	case OpGreater:
		return "JSONExtractFloat(metadata, ?) > ?", []interface{}{jsonPath, cond.Value}, nil
	case OpGreaterEq:
		return "JSONExtractFloat(metadata, ?) >= ?", []interface{}{jsonPath, cond.Value}, nil
	case OpLess:
		return "JSONExtractFloat(metadata, ?) < ?", []interface{}{jsonPath, cond.Value}, nil
	case OpLessEq:
		return "JSONExtractFloat(metadata, ?) <= ?", []interface{}{jsonPath, cond.Value}, nil
	case OpContains:
		return "position(JSONExtractString(metadata, ?), ?) > 0", []interface{}{jsonPath, cond.Value}, nil
	case OpNotContains:
		return "position(JSONExtractString(metadata, ?), ?) = 0", []interface{}{jsonPath, cond.Value}, nil
	case OpExists:
		return "JSONHas(metadata, ?) = 1", []interface{}{jsonPath}, nil
	case OpNotExists:
		return "JSONHas(metadata, ?) = 0", []interface{}{jsonPath}, nil
	default:
		return "", nil, unsupportedOperator(cond)
	}
}

// ErrInvalidQuery marks errors caused by the request itself: an unknown
// field, an operator or value that does not fit the field, an unsupported
// aggregation or interval. Handlers answer them with 400; every other
// executor error is a server-side failure.
var ErrInvalidQuery = errors.New("invalid query")

// invalidQueryf returns an error wrapping ErrInvalidQuery.
func invalidQueryf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidQuery, fmt.Sprintf(format, args...))
}

// errUnbalancedParens is returned when a query's grouping parentheses do not
// pair up.
var errUnbalancedParens = fmt.Errorf("%w: unbalanced parentheses", ErrInvalidQuery)

// columnKind is the type of an events column, which decides the operators
// and values a condition on it may use.
type columnKind int

const (
	kindString columnKind = iota
	kindNumber
	kindTime
	kindUUID
)

// columnKinds lists the non-string columns of validColumns.
var columnKinds = map[string]columnKind{
	"severity":    kindNumber,
	"timestamp":   kindTime,
	"received_at": kindTime,
	"event_id":    kindUUID,
}

// freeTextColumns are searched by a term without a field ("alice",
// "\"failed login\""): the term matches when one of them contains it,
// ignoring case.
var freeTextColumns = []string{
	"raw", "action", "target", "actor_name", "actor_id", "actor_email", "actor_ip",
	"source_product", "source_host", "metadata",
}

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

// sanitizeColumn returns the allowlisted column named column, or an error
// wrapping ErrInvalidQuery for anything else. (Unknown columns used to be
// replaced with timestamp, which turned foo:bar into timestamp = 'bar', a
// 500, and aggregations on an unknown field into timestamp buckets.)
func (e *Executor) sanitizeColumn(column string) (string, error) {
	if safe, ok := validColumns[column]; ok {
		return safe, nil
	}
	return "", invalidQueryf("unknown field %q", truncateForLog(column, 100))
}

// fieldColumn resolves a query field name (with its aliases, see MapField)
// to an allowlisted column.
// Column names themselves (source_product) are accepted too.
func (e *Executor) fieldColumn(field string) (string, error) {
	column, _ := MapField(field)
	if safe, ok := validColumns[column]; ok {
		return safe, nil
	}
	return "", invalidQueryf("unknown field %q", truncateForLog(field, 100))
}

// fieldExpr returns the SQL expression that aggregations group or aggregate
// a field by, with its bound arguments. Metadata fields (metadata.<key>,
// meta.<key>, and aliases stored in metadata such as vendor) are extracted
// from the metadata JSON with the key bound as an argument — as a string, or
// as a number when numeric is set. Other fields resolve to an allowlisted
// column; with numeric set, that column must be numeric. An unknown field is
// an error wrapping ErrInvalidQuery.
func (e *Executor) fieldExpr(field string, numeric bool) (string, []interface{}, error) {
	if key, ok := metadataKey(field); ok {
		if key == "" {
			return "", nil, invalidQueryf("metadata field %q names no key", truncateForLog(field, 100))
		}
		if numeric {
			return "JSONExtractFloat(metadata, ?)", []interface{}{key}, nil
		}
		return "JSONExtractString(metadata, ?)", []interface{}{key}, nil
	}
	column, err := e.fieldColumn(field)
	if err != nil {
		return "", nil, err
	}
	if numeric && columnKinds[column] != kindNumber {
		return "", nil, invalidQueryf("field %q is not numeric", truncateForLog(field, 100))
	}
	return column, nil, nil
}

// sanitizeOrderBy returns the column to sort by: timestamp when orderBy is
// empty, otherwise the sortable column orderBy names (aliases allowed), or
// an error wrapping ErrInvalidQuery.
func (e *Executor) sanitizeOrderBy(orderBy string) (string, error) {
	if orderBy == "" {
		return "timestamp", nil
	}
	column, _ := MapField(orderBy)
	if safe, ok := validOrderByColumns[column]; ok {
		return safe, nil
	}
	return "", invalidQueryf("cannot sort by %q; sortable fields are timestamp, received_at, severity, action, source.product and actor.name",
		truncateForLog(orderBy, 100))
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
	case "":
		intervalFunc = "toStartOfHour"
	default:
		return nil, invalidQueryf("unsupported histogram interval %q (use 1m, 5m, 15m, 1h, 1d, 1w or 1M)",
			truncateForLog(interval, 20))
	}

	whereClause, args, err := e.buildWhereClause(query)
	if err != nil {
		return nil, err // wraps ErrInvalidQuery
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
		return nil, err // wraps ErrInvalidQuery
	}

	expr, exprArgs, err := e.fieldExpr(field, false)
	if err != nil {
		return nil, err
	}
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
		return nil, err // wraps ErrInvalidQuery
	}

	orderBy, err := e.sanitizeOrderBy(query.OrderBy)
	if err != nil {
		return nil, err
	}
	selectSQL := joinSQL(
		"SELECT event_id, timestamp, action, severity",
		"FROM events",
		whereClause,
		"ORDER BY", orderBy, e.orderDirection(query.OrderDesc),
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
