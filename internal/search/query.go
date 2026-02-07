// Package search provides query parsing and execution for event search.
package search

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
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
type Query struct {
	Conditions []Condition
	Logic      []string // "AND" or "OR" between conditions
	TimeRange  *TimeRange
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

// Lexer tokenizes a query string.
type Lexer struct {
	input   string
	pos     int
	current rune
}

// NewLexer creates a new lexer for the input string.
func NewLexer(input string) *Lexer {
	l := &Lexer{input: input}
	if len(input) > 0 {
		l.current = rune(input[0])
	}
	return l
}

func (l *Lexer) advance() {
	l.pos++
	if l.pos < len(l.input) {
		l.current = rune(l.input[l.pos])
	} else {
		l.current = 0
	}
}

func (l *Lexer) peek() rune {
	if l.pos+1 < len(l.input) {
		return rune(l.input[l.pos+1])
	}
	return 0
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

func (l *Lexer) readQuotedString() Token {
	quote := l.current
	l.advance()
	start := l.pos

	for l.current != 0 && l.current != quote {
		if l.current == '\\' && l.peek() == quote {
			l.advance()
		}
		l.advance()
	}

	value := l.input[start:l.pos]
	if l.current == quote {
		l.advance()
	}
	return Token{Type: TokenValue, Value: value}
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

// Parser parses query tokens into a Query structure.
type Parser struct {
	lexer   *Lexer
	current Token
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

// Parse parses the query string into a Query structure.
func (p *Parser) Parse() (*Query, error) {
	query := &Query{
		Limit:     100,
		OrderBy:   "timestamp",
		OrderDesc: true,
	}

	pendingParens := 0 // tracks open parens before next condition

	for p.current.Type != TokenEOF {
		switch p.current.Type {
		case TokenField:
			cond, err := p.parseCondition()
			if err != nil {
				return nil, err
			}
			cond.OpenParens = pendingParens
			pendingParens = 0
			query.Conditions = append(query.Conditions, cond)

		case TokenAnd:
			if len(query.Conditions) > 0 {
				query.Logic = append(query.Logic, "AND")
			}
			p.advance()

		case TokenOr:
			if len(query.Conditions) > 0 {
				query.Logic = append(query.Logic, "OR")
			}
			p.advance()

		case TokenLParen:
			pendingParens++
			p.advance()

		case TokenRParen:
			// Attach close paren to the last condition
			if len(query.Conditions) > 0 {
				query.Conditions[len(query.Conditions)-1].CloseParens++
			}
			p.advance()

		case TokenNot:
			p.advance()
			if p.current.Type == TokenField {
				cond, err := p.parseCondition()
				if err != nil {
					return nil, err
				}
				// Negate the condition
				switch cond.Operator {
				case OpEquals:
					cond.Operator = OpNotEquals
				case OpContains:
					cond.Operator = OpNotContains
				case OpExists:
					cond.Operator = OpNotExists
				}
				cond.OpenParens = pendingParens
				pendingParens = 0
				query.Conditions = append(query.Conditions, cond)
			}

		default:
			p.advance()
		}
	}

	return query, nil
}

func (p *Parser) parseCondition() (Condition, error) {
	cond := Condition{
		Field:    p.current.Value,
		Operator: OpEquals,
	}

	// Detect metadata fields (metadata.key or meta.key)
	fieldLower := strings.ToLower(cond.Field)
	if strings.HasPrefix(fieldLower, "metadata.") {
		cond.IsMetadata = true
		cond.MetadataKey = cond.Field[len("metadata."):]
	} else if strings.HasPrefix(fieldLower, "meta.") {
		cond.IsMetadata = true
		cond.MetadataKey = cond.Field[len("meta."):]
	}

	p.advance()

	// Parse operator
	if p.current.Type == TokenOperator {
		cond.Operator = Operator(p.current.Value)
		p.advance()
	}

	// Parse value
	if p.current.Type == TokenValue || p.current.Type == TokenField {
		value := p.current.Value

		// Detect phrase search: value came from a quoted string and contains spaces
		if strings.Contains(value, " ") {
			cond.IsPhrase = true
		}

		// Check for wildcard
		if strings.Contains(value, "*") && !cond.IsPhrase {
			cond.IsRegex = true
			// Convert wildcard to regex
			value = "^" + regexp.QuoteMeta(value)
			value = strings.ReplaceAll(value, "\\*", ".*")
			value += "$"
		}

		// Try to parse as number (skip for phrases)
		if !cond.IsPhrase && !cond.IsRegex {
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
		} else {
			cond.Value = value
		}

		p.advance()
	}

	return cond, nil
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

	if s[0] == '-' {
		s = s[1:]
	} else if s[0] == '+' {
		s = s[1:]
	} else {
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

// FieldMapping maps query field names to database columns.
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
	// Source fields
	"source.product":  "source_product",
	"source.vendor":   "source_vendor",
	"source.version":  "source_version",
	"source.hostname": "source_hostname",
	"source.ip":       "source_ip",
	"product":         "source_product",
	"vendor":          "source_vendor",
	// Actor fields
	"actor.name":       "actor_name",
	"actor.id":         "actor_id",
	"actor.type":       "actor_type",
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
