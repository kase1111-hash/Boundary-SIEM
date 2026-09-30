// Package search provides query parsing and execution for event search.
package search

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// TokenType represents the type of a query token.
type TokenType int

const (
	TokenField TokenType = iota
	TokenOperator
	TokenValue
	TokenAnd
	TokenOr
	TokenNot
	TokenLParen
	TokenRParen
	TokenEOF
)

// Token represents a parsed query token.
type Token struct {
	Type  TokenType
	Value string
	// Quoted is true for a value written in quotes; its Value has the
	// quotes removed and \" (or \') and \\ unescaped.
	Quoted bool
}

// Operator represents a comparison operator.
type Operator string

const (
	OpEquals      Operator = "="
	OpNotEquals   Operator = "!="
	OpGreater     Operator = ">"
	OpGreaterEq   Operator = ">="
	OpLess        Operator = "<"
	OpLessEq      Operator = "<="
	OpContains    Operator = "~"
	OpNotContains Operator = "!~"
	OpExists      Operator = "exists"
	OpNotExists   Operator = "!exists"
)

// negatedOperators maps each operator to its logical complement.
var negatedOperators = map[Operator]Operator{
	OpEquals:      OpNotEquals,
	OpNotEquals:   OpEquals,
	OpGreater:     OpLessEq,
	OpLessEq:      OpGreater,
	OpGreaterEq:   OpLess,
	OpLess:        OpGreaterEq,
	OpContains:    OpNotContains,
	OpNotContains: OpContains,
	OpExists:      OpNotExists,
	OpNotExists:   OpExists,
}

// Condition represents a single search condition.
type Condition struct {
	Field       string
	Operator    Operator
	Value       interface{}
	IsRegex     bool
	IsPhrase    bool   // true when value was a quoted phrase
	IsMetadata  bool   // true when field is metadata.* or meta.*
	MetadataKey string // the JSON key within metadata (e.g., "chain_id")
	OpenParens  int    // number of opening parens before this condition
	CloseParens int    // number of closing parens after this condition
}

// Query represents a parsed search query.
//
// Conditions are joined by Logic: Logic[i] connects Conditions[i] and
// Conditions[i+1], so ParseQuery always returns len(Logic) ==
// len(Conditions)-1. AND binds tighter than OR, as in SQL; OpenParens and
// CloseParens group conditions explicitly.
type Query struct {
	Conditions []Condition
	Logic      []string // "AND" or "OR" between conditions
	TimeRange  *TimeRange
	TenantID   string // Required for tenant isolation; must be set by caller
	Limit      int
	Offset     int
	OrderBy    string
	OrderDesc  bool
}

// TimeRange represents a time-based filter.
type TimeRange struct {
	Start time.Time
	End   time.Time
}

// Lexer tokenizes a query string. The input is decoded as UTF-8; pos is the
// byte offset of current.
type Lexer struct {
	input   string
	pos     int
	width   int // byte width of current
	current rune
}

// NewLexer creates a new lexer for the input string.
func NewLexer(input string) *Lexer {
	l := &Lexer{input: input}
	l.decode()
	return l
}

// decode loads the rune at pos into current.
func (l *Lexer) decode() {
	if l.pos >= len(l.input) {
		l.current, l.width = 0, 0
		return
	}
	l.current, l.width = utf8.DecodeRuneInString(l.input[l.pos:])
}

func (l *Lexer) advance() {
	l.pos += l.width
	l.decode()
}

func (l *Lexer) peek() rune {
	next := l.pos + l.width
	if next >= len(l.input) {
		return 0
	}
	r, _ := utf8.DecodeRuneInString(l.input[next:])
	return r
}

func (l *Lexer) skipWhitespace() {
	for unicode.IsSpace(l.current) {
		l.advance()
	}
}

// NextToken returns the next token from the input.
func (l *Lexer) NextToken() Token {
	l.skipWhitespace()

	if l.current == 0 {
		return Token{Type: TokenEOF}
	}

	// Parentheses
	if l.current == '(' {
		l.advance()
		return Token{Type: TokenLParen, Value: "("}
	}
	if l.current == ')' {
		l.advance()
		return Token{Type: TokenRParen, Value: ")"}
	}

	// Check for operators
	if l.current == ':' || l.current == '=' || l.current == '!' ||
		l.current == '>' || l.current == '<' || l.current == '~' {
		return l.readOperator()
	}

	// Check for quoted string
	if l.current == '"' || l.current == '\'' {
		return l.readQuotedString()
	}

	// Read identifier or keyword
	return l.readIdentifier()
}

func (l *Lexer) readOperator() Token {
	start := l.pos
	switch l.current {
	case ':':
		l.advance()
		return Token{Type: TokenOperator, Value: "="}
	case '=':
		l.advance()
		return Token{Type: TokenOperator, Value: "="}
	case '!':
		l.advance()
		if l.current == '=' {
			l.advance()
			return Token{Type: TokenOperator, Value: "!="}
		}
		if l.current == '~' {
			l.advance()
			return Token{Type: TokenOperator, Value: "!~"}
		}
		return Token{Type: TokenNot, Value: "NOT"}
	case '>':
		l.advance()
		if l.current == '=' {
			l.advance()
			return Token{Type: TokenOperator, Value: ">="}
		}
		return Token{Type: TokenOperator, Value: ">"}
	case '<':
		l.advance()
		if l.current == '=' {
			l.advance()
			return Token{Type: TokenOperator, Value: "<="}
		}
		return Token{Type: TokenOperator, Value: "<"}
	case '~':
		l.advance()
		return Token{Type: TokenOperator, Value: "~"}
	}
	return Token{Type: TokenOperator, Value: l.input[start:l.pos]}
}

// readQuotedString reads a quoted value. A backslash escapes the quote
// character and itself; any other backslash is kept literally.
func (l *Lexer) readQuotedString() Token {
	quote := l.current
	l.advance()

	var sb strings.Builder
	for l.current != 0 && l.current != quote {
		if l.current == '\\' {
			if next := l.peek(); next == quote || next == '\\' {
				l.advance()
			}
		}
		// Copy the source bytes so invalid UTF-8 is preserved as-is.
		sb.WriteString(l.input[l.pos : l.pos+l.width])
		l.advance()
	}

	if l.current == quote {
		l.advance()
	}
	return Token{Type: TokenValue, Value: sb.String(), Quoted: true}
}

func (l *Lexer) readIdentifier() Token {
	start := l.pos

	for l.current != 0 && !unicode.IsSpace(l.current) &&
		l.current != '(' && l.current != ')' &&
		l.current != ':' && l.current != '=' &&
		l.current != '!' && l.current != '>' &&
		l.current != '<' && l.current != '~' {
		l.advance()
	}

	value := l.input[start:l.pos]
	upper := strings.ToUpper(value)

	switch upper {
	case "AND", "&&":
		return Token{Type: TokenAnd, Value: "AND"}
	case "OR", "||":
		return Token{Type: TokenOr, Value: "OR"}
	case "NOT":
		return Token{Type: TokenNot, Value: "NOT"}
	}

	// Check if this looks like a field name (followed by operator)
	l.skipWhitespace()
	if l.current == ':' || l.current == '=' || l.current == '!' ||
		l.current == '>' || l.current == '<' || l.current == '~' {
		return Token{Type: TokenField, Value: value}
	}

	return Token{Type: TokenValue, Value: value}
}

// maxQueryDepth limits parenthesis nesting.
const maxQueryDepth = 64

// Parser parses query tokens into a Query structure.
//
// Grammar (AND binds tighter than OR; adjacent terms are implicitly ANDed):
//
//	query   = or
//	or      = and { OR and }
//	and     = unary { [AND] unary }
//	unary   = { NOT } primary
//	primary = "(" or ")" | condition
//
// The expression tree is flattened into Query.Conditions and Query.Logic.
// NOT is pushed down to the conditions (De Morgan), negating each operator.
type Parser struct {
	lexer   *Lexer
	current Token
	depth   int
}

// NewParser creates a new parser for the query string.
func NewParser(query string) *Parser {
	p := &Parser{lexer: NewLexer(query)}
	p.advance()
	return p
}

func (p *Parser) advance() {
	p.current = p.lexer.NextToken()
}

// exprNode is a node of the boolean expression tree: a condition (op == "")
// or an AND/OR of two or more children.
type exprNode struct {
	op       string
	cond     Condition
	children []*exprNode
}

// Parse parses the query string into a Query structure.
func (p *Parser) Parse() (*Query, error) {
	query := &Query{
		Limit:     100,
		OrderBy:   "timestamp",
		OrderDesc: true,
	}

	root, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.current.Type == TokenRParen {
		return nil, errors.New("unbalanced parentheses: unexpected ')'")
	}

	f := flattener{query: query}
	f.emit(root, "")
	return query, nil
}

func (p *Parser) parseOr() (*exprNode, error) {
	var children []*exprNode
	for {
		n, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		if n != nil {
			children = append(children, n)
		}
		if p.current.Type != TokenOr {
			return combine("OR", children), nil
		}
		p.advance()
	}
}

func (p *Parser) parseAnd() (*exprNode, error) {
	var children []*exprNode
	for {
		switch p.current.Type {
		case TokenEOF, TokenRParen, TokenOr:
			return combine("AND", children), nil
		case TokenAnd:
			// An explicit AND; with nothing on one side it is ignored.
			p.advance()
			continue
		}

		n, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		if n != nil {
			children = append(children, n)
		}
	}
}

func (p *Parser) parseUnary() (*exprNode, error) {
	negate := false
	for p.current.Type == TokenNot {
		negate = !negate
		p.advance()
		switch p.current.Type {
		case TokenEOF, TokenRParen, TokenAnd, TokenOr:
			return nil, errors.New("NOT must be followed by a condition or a parenthesized group")
		}
	}

	n, err := p.parsePrimary()
	if err != nil || !negate {
		return n, err
	}
	return negateExpr(n)
}

func (p *Parser) parsePrimary() (*exprNode, error) {
	switch p.current.Type {
	case TokenLParen:
		if p.depth >= maxQueryDepth {
			return nil, fmt.Errorf("query nests parentheses deeper than %d", maxQueryDepth)
		}
		p.depth++
		p.advance()
		n, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.current.Type != TokenRParen {
			return nil, errors.New("unbalanced parentheses: missing ')'")
		}
		p.depth--
		p.advance()
		return n, nil

	case TokenField:
		cond, err := p.parseCondition()
		if err != nil {
			return nil, err
		}
		return &exprNode{cond: cond}, nil

	default:
		// Bare values and stray operators name no field; they are ignored.
		p.advance()
		return nil, nil
	}
}

// combine joins children with op; nil when there are none.
func combine(op string, children []*exprNode) *exprNode {
	switch len(children) {
	case 0:
		return nil
	case 1:
		return children[0]
	}
	return &exprNode{op: op, children: children}
}

// negateExpr returns the negation of n, pushing NOT down to the conditions:
// NOT (a OR b) = NOT a AND NOT b, NOT (a AND b) = NOT a OR NOT b, and NOT a
// negates a's operator.
func negateExpr(n *exprNode) (*exprNode, error) {
	if n == nil {
		return nil, nil
	}
	if n.op == "" {
		cond := n.cond
		negated, ok := negatedOperators[cond.Operator]
		if !ok {
			return nil, fmt.Errorf("cannot negate operator %q", cond.Operator)
		}
		cond.Operator = negated
		return &exprNode{cond: cond}, nil
	}

	out := &exprNode{op: "AND"}
	if n.op == "AND" {
		out.op = "OR"
	}
	for _, child := range n.children {
		c, err := negateExpr(child)
		if err != nil {
			return nil, err
		}
		out.children = append(out.children, c)
	}
	return out, nil
}

// flattener writes an expression tree into a Query's flat condition list.
type flattener struct {
	query       *Query
	pendingOpen int
}

// emit appends n's conditions and connectives. An OR inside an AND is
// wrapped in parentheses; every other nesting already has the right
// precedence without them.
func (f *flattener) emit(n *exprNode, parentOp string) {
	if n == nil {
		return
	}
	if n.op == "" {
		cond := n.cond
		cond.OpenParens, cond.CloseParens = f.pendingOpen, 0
		f.pendingOpen = 0
		f.query.Conditions = append(f.query.Conditions, cond)
		return
	}

	grouped := n.op == "OR" && parentOp == "AND"
	if grouped {
		f.pendingOpen++
	}
	for i, child := range n.children {
		if i > 0 {
			f.query.Logic = append(f.query.Logic, n.op)
		}
		f.emit(child, n.op)
	}
	if grouped {
		f.query.Conditions[len(f.query.Conditions)-1].CloseParens++
	}
}

func (p *Parser) parseCondition() (Condition, error) {
	cond := Condition{
		Field:    p.current.Value,
		Operator: OpEquals,
	}

	// Detect metadata fields (metadata.key, meta.key, or an alias such as
	// vendor that is stored in metadata).
	cond.MetadataKey, cond.IsMetadata = metadataKey(cond.Field)

	p.advance()

	// Parse operator
	if p.current.Type == TokenOperator {
		cond.Operator = Operator(p.current.Value)
		p.advance()
	}

	// Parse value
	if p.current.Type == TokenValue || p.current.Type == TokenField {
		setConditionValue(&cond, p.current)
		p.advance()
	}

	return cond, nil
}

// setConditionValue interprets a value token for cond.
//
// A quoted value is always a literal string: no wildcards, numbers or
// relative times. An unquoted value containing '*' is a wildcard pattern.
// Otherwise the value is typed by the field: strings for string columns and
// for metadata equality/contains, numbers or relative times ("now-1h") for
// numeric and time columns, metadata comparisons, and unknown fields.
func setConditionValue(cond *Condition, tok Token) {
	value := tok.Value

	if tok.Quoted {
		cond.Value = value
		cond.IsPhrase = strings.Contains(value, " ")
		return
	}

	if strings.Contains(value, "*") {
		cond.IsRegex = true
		value = "^" + regexp.QuoteMeta(value)
		value = strings.ReplaceAll(value, "\\*", ".*")
		cond.Value = value + "$"
		return
	}

	if isStringValued(*cond) {
		cond.Value = value
		return
	}

	if num, err := strconv.ParseInt(value, 10, 64); err == nil {
		cond.Value = num
	} else if num, err := strconv.ParseFloat(value, 64); err == nil {
		cond.Value = num
	} else if dur, ok := parseDuration(value); ok {
		// Handle relative time like "now-1h"
		cond.Value = time.Now().Add(-dur)
	} else {
		cond.Value = value
	}
}

// numericColumns and timeColumns are the non-string columns of the events
// table that conditions can address.
var (
	numericColumns = map[string]bool{"severity": true}
	timeColumns    = map[string]bool{"timestamp": true, "received_at": true}
)

// isStringValued reports whether cond compares against a string, so that a
// value like 000123 must not be turned into a number.
func isStringValued(cond Condition) bool {
	if cond.IsMetadata {
		switch cond.Operator {
		case OpGreater, OpGreaterEq, OpLess, OpLessEq:
			return false // compared with JSONExtractFloat
		}
		return true
	}
	column, known := MapField(cond.Field)
	return known && !numericColumns[column] && !timeColumns[column]
}

// parseDuration parses relative time expressions like "now-1h", "now-24h"
func parseDuration(s string) (time.Duration, bool) {
	s = strings.ToLower(s)
	if !strings.HasPrefix(s, "now") {
		return 0, false
	}

	s = strings.TrimPrefix(s, "now")
	if s == "" {
		return 0, true
	}

	switch s[0] {
	case '-', '+':
		s = s[1:]
	default:
		return 0, false
	}

	// Parse duration
	dur, err := time.ParseDuration(s)
	if err != nil {
		// Try parsing with day suffix
		if strings.HasSuffix(s, "d") {
			days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
			if err == nil {
				return time.Duration(days) * 24 * time.Hour, true
			}
		}
		return 0, false
	}

	return dur, true
}

// ParseQuery is a convenience function to parse a query string.
func ParseQuery(query string) (*Query, error) {
	parser := NewParser(query)
	return parser.Parse()
}

// metadataColumnPrefix marks a FieldMapping target stored as a key of the
// metadata JSON column rather than as a column of its own.
const metadataColumnPrefix = "metadata."

// FieldMapping maps query field names to database columns. Every target is a
// column of the events table (see internal/storage/migrations) or
// "metadata.<key>" for a value stored in the metadata JSON.
var FieldMapping = map[string]string{
	"event_id":       "event_id",
	"id":             "event_id",
	"timestamp":      "timestamp",
	"time":           "timestamp",
	"ts":             "timestamp",
	"received_at":    "received_at",
	"tenant_id":      "tenant_id",
	"tenant":         "tenant_id",
	"action":         "action",
	"outcome":        "outcome",
	"severity":       "severity",
	"target":         "target",
	"raw":            "raw",
	"schema_version": "schema_version",
	"request_id":     "request_id",
	// Source fields. The events table has no vendor or source IP column:
	// the CEF normalizer keeps the vendor in metadata.device_vendor and the
	// device host or IP address in source_host.
	"source.product":     "source_product",
	"source.host":        "source_host",
	"source.hostname":    "source_host",
	"source.ip":          "source_host",
	"source.instance_id": "source_instance_id",
	"source.version":     "source_version",
	"source.vendor":      "metadata.device_vendor",
	"product":            "source_product",
	"vendor":             "metadata.device_vendor",
	"host":               "source_host",
	"hostname":           "source_host",
	// Actor fields
	"actor.name":       "actor_name",
	"actor.id":         "actor_id",
	"actor.type":       "actor_type",
	"actor.email":      "actor_email",
	"actor.ip":         "actor_ip",
	"actor.ip_address": "actor_ip",
	"user":             "actor_name",
	"username":         "actor_name",
	// Common shortcuts
	"src":   "actor_ip",
	"dst":   "target",
	"suser": "actor_name",
}

// MapField maps a query field name to a database column.
func MapField(field string) (string, bool) {
	if col, ok := FieldMapping[strings.ToLower(field)]; ok {
		return col, true
	}
	// Check if it's a metadata field
	if strings.HasPrefix(field, "metadata.") || strings.HasPrefix(field, "meta.") {
		return field, true
	}
	return field, false
}

// metadataKey returns the metadata JSON key a field addresses: the part after
// "metadata." or "meta.", or the key of an alias mapped to "metadata.<key>".
func metadataKey(field string) (string, bool) {
	lower := strings.ToLower(field)
	switch {
	case strings.HasPrefix(lower, "metadata."):
		return field[len("metadata."):], true
	case strings.HasPrefix(lower, "meta."):
		return field[len("meta."):], true
	}
	if col, ok := FieldMapping[lower]; ok && strings.HasPrefix(col, metadataColumnPrefix) {
		return col[len(metadataColumnPrefix):], true
	}
	return "", false
}

// String returns a string representation of the query.
func (q *Query) String() string {
	var parts []string
	for i, cond := range q.Conditions {
		part := fmt.Sprintf("%s%s%v", cond.Field, cond.Operator, cond.Value)
		parts = append(parts, part)
		if i < len(q.Logic) {
			parts = append(parts, q.Logic[i])
		}
	}
	return strings.Join(parts, " ")
}
