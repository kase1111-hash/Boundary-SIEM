// Package api provides GraphQL execution engine for the SIEM.
package api

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Token types for GraphQL lexer
type TokenType int

const (
	TokenEOF TokenType = iota
	TokenName
	TokenInt
	TokenFloat
	TokenString
	TokenPunctuation
	TokenSpread
)

// Token represents a lexical token
type Token struct {
	Type  TokenType
	Value string
	Line  int
	Col   int
}

// Lexer tokenizes GraphQL queries
type Lexer struct {
	input string
	pos   int
	line  int
	col   int
}

// NewLexer creates a new lexer
func NewLexer(input string) *Lexer {
	return &Lexer{input: input, line: 1, col: 1}
}

// NextToken returns the next token
func (l *Lexer) NextToken() Token {
	l.skipWhitespace()
	l.skipComments()

	if l.pos >= len(l.input) {
		return Token{Type: TokenEOF}
	}

	ch := l.input[l.pos]

	// Punctuation
	if strings.ContainsRune("{}()[]!:=@$", rune(ch)) {
		l.pos++
		l.col++
		return Token{Type: TokenPunctuation, Value: string(ch), Line: l.line, Col: l.col - 1}
	}

	// Spread operator
	if l.pos+2 < len(l.input) && l.input[l.pos:l.pos+3] == "..." {
		l.pos += 3
		l.col += 3
		return Token{Type: TokenSpread, Value: "...", Line: l.line, Col: l.col - 3}
	}

	// String
	if ch == '"' {
		return l.readString()
	}

	// Number
	if ch == '-' || (ch >= '0' && ch <= '9') {
		return l.readNumber()
	}

	// Name
	if isNameStart(ch) {
		return l.readName()
	}

	l.pos++
	l.col++
	return Token{Type: TokenPunctuation, Value: string(ch), Line: l.line, Col: l.col - 1}
}

func (l *Lexer) skipWhitespace() {
	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if ch == ' ' || ch == '\t' || ch == ',' {
			l.pos++
			l.col++
		} else if ch == '\n' || ch == '\r' {
			l.pos++
			l.line++
			l.col = 1
		} else {
			break
		}
	}
}

func (l *Lexer) skipComments() {
	if l.pos < len(l.input) && l.input[l.pos] == '#' {
		for l.pos < len(l.input) && l.input[l.pos] != '\n' {
			l.pos++
		}
		l.skipWhitespace()
		l.skipComments()
	}
}

func (l *Lexer) readString() Token {
	startCol := l.col
	l.pos++ // skip opening quote
	l.col++

	var value strings.Builder
	for l.pos < len(l.input) && l.input[l.pos] != '"' {
		if l.input[l.pos] == '\\' && l.pos+1 < len(l.input) {
			l.pos++
			l.col++
			switch l.input[l.pos] {
			case 'n':
				value.WriteByte('\n')
			case 'r':
				value.WriteByte('\r')
			case 't':
				value.WriteByte('\t')
			case '"':
				value.WriteByte('"')
			case '\\':
				value.WriteByte('\\')
			default:
				value.WriteByte(l.input[l.pos])
			}
		} else {
			value.WriteByte(l.input[l.pos])
		}
		l.pos++
		l.col++
	}
	l.pos++ // skip closing quote
	l.col++

	return Token{Type: TokenString, Value: value.String(), Line: l.line, Col: startCol}
}

func (l *Lexer) readNumber() Token {
	start := l.pos
	startCol := l.col
	isFloat := false

	if l.input[l.pos] == '-' {
		l.pos++
		l.col++
	}

	for l.pos < len(l.input) && l.input[l.pos] >= '0' && l.input[l.pos] <= '9' {
		l.pos++
		l.col++
	}

	if l.pos < len(l.input) && l.input[l.pos] == '.' {
		isFloat = true
		l.pos++
		l.col++
		for l.pos < len(l.input) && l.input[l.pos] >= '0' && l.input[l.pos] <= '9' {
			l.pos++
			l.col++
		}
	}

	tokenType := TokenInt
	if isFloat {
		tokenType = TokenFloat
	}

	return Token{Type: tokenType, Value: l.input[start:l.pos], Line: l.line, Col: startCol}
}

func (l *Lexer) readName() Token {
	start := l.pos
	startCol := l.col

	for l.pos < len(l.input) && isNameContinue(l.input[l.pos]) {
		l.pos++
		l.col++
	}

	return Token{Type: TokenName, Value: l.input[start:l.pos], Line: l.line, Col: startCol}
}

func isNameStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'
}

func isNameContinue(ch byte) bool {
	return isNameStart(ch) || (ch >= '0' && ch <= '9')
}

// Parser parses GraphQL queries
type Parser struct {
	lexer   *Lexer
	current Token
}

// NewParser creates a new parser
func NewParser(query string) *Parser {
	lexer := NewLexer(query)
	return &Parser{
		lexer:   lexer,
		current: lexer.NextToken(),
	}
}

func (p *Parser) advance() {
	p.current = p.lexer.NextToken()
}

func (p *Parser) expect(value string) error {
	if p.current.Value != value {
		return fmt.Errorf("expected '%s', got '%s' at line %d, col %d",
			value, p.current.Value, p.current.Line, p.current.Col)
	}
	p.advance()
	return nil
}

// Document represents a parsed GraphQL document
type Document struct {
	Operations []*Operation
	Fragments  map[string]*Fragment
}

// Operation represents a GraphQL operation (query, mutation, subscription)
type Operation struct {
	Type         string // query, mutation, subscription
	Name         string
	Variables    []*VariableDefinition
	Directives   []*Directive
	SelectionSet *SelectionSet
}

// VariableDefinition represents a variable definition
type VariableDefinition struct {
	Name         string
	Type         string
	DefaultValue interface{}
}

// Directive represents a directive
type Directive struct {
	Name      string
	Arguments map[string]interface{}
}

// SelectionSet represents a selection set
type SelectionSet struct {
	Selections []Selection
}

// Selection is an interface for selections
type Selection interface {
	isSelection()
}

// Field represents a field selection
type Field struct {
	Alias        string
	Name         string
	Arguments    map[string]interface{}
	Directives   []*Directive
	SelectionSet *SelectionSet
}

func (*Field) isSelection() {}

// FragmentSpread represents a fragment spread
type FragmentSpread struct {
	Name       string
	Directives []*Directive
}

func (*FragmentSpread) isSelection() {}

// InlineFragment represents an inline fragment
type InlineFragment struct {
	TypeCondition string
	Directives    []*Directive
	SelectionSet  *SelectionSet
}

func (*InlineFragment) isSelection() {}

// Fragment represents a fragment definition
type Fragment struct {
	Name          string
	TypeCondition string
	Directives    []*Directive
	SelectionSet  *SelectionSet
}

// Parse parses the GraphQL document
func (p *Parser) Parse() (*Document, error) {
	doc := &Document{
		Operations: make([]*Operation, 0),
		Fragments:  make(map[string]*Fragment),
	}

	for p.current.Type != TokenEOF {
		if p.current.Type == TokenName {
			switch p.current.Value {
			case "query", "mutation", "subscription":
				op, err := p.parseOperation()
				if err != nil {
					return nil, err
				}
				doc.Operations = append(doc.Operations, op)
			case "fragment":
				frag, err := p.parseFragmentDefinition()
				if err != nil {
					return nil, err
				}
				doc.Fragments[frag.Name] = frag
			default:
				return nil, fmt.Errorf("unexpected token '%s' at line %d", p.current.Value, p.current.Line)
			}
		} else if p.current.Value == "{" {
			// Anonymous query
			op, err := p.parseOperation()
			if err != nil {
				return nil, err
			}
			op.Type = "query"
			doc.Operations = append(doc.Operations, op)
		} else {
			p.advance()
		}
	}

	return doc, nil
}

func (p *Parser) parseOperation() (*Operation, error) {
	op := &Operation{
		Type:      "query",
		Variables: make([]*VariableDefinition, 0),
	}

	if p.current.Type == TokenName && (p.current.Value == "query" || p.current.Value == "mutation" || p.current.Value == "subscription") {
		op.Type = p.current.Value
		p.advance()

		// Optional operation name
		if p.current.Type == TokenName {
			op.Name = p.current.Value
			p.advance()
		}

		// Optional variable definitions
		if p.current.Value == "(" {
			vars, err := p.parseVariableDefinitions()
			if err != nil {
				return nil, err
			}
			op.Variables = vars
		}

		// Optional directives
		op.Directives = p.parseDirectives()
	}

	// Selection set
	selSet, err := p.parseSelectionSet()
	if err != nil {
		return nil, err
	}
	op.SelectionSet = selSet

	return op, nil
}

func (p *Parser) parseVariableDefinitions() ([]*VariableDefinition, error) {
	vars := make([]*VariableDefinition, 0)

	if err := p.expect("("); err != nil {
		return nil, err
	}

	for p.current.Value != ")" && p.current.Type != TokenEOF {
		v, err := p.parseVariableDefinition()
		if err != nil {
			return nil, err
		}
		vars = append(vars, v)
	}

	if err := p.expect(")"); err != nil {
		return nil, err
	}

	return vars, nil
}

func (p *Parser) parseVariableDefinition() (*VariableDefinition, error) {
	if err := p.expect("$"); err != nil {
		return nil, err
	}

	v := &VariableDefinition{}

	if p.current.Type != TokenName {
		return nil, fmt.Errorf("expected variable name at line %d", p.current.Line)
	}
	v.Name = p.current.Value
	p.advance()

	if err := p.expect(":"); err != nil {
		return nil, err
	}

	v.Type = p.parseType()

	// Optional default value
	if p.current.Value == "=" {
		p.advance()
		v.DefaultValue = p.parseValue()
	}

	return v, nil
}

func (p *Parser) parseType() string {
	var typeStr strings.Builder

	if p.current.Value == "[" {
		typeStr.WriteString("[")
		p.advance()
		typeStr.WriteString(p.parseType())
		if p.current.Value == "]" {
			typeStr.WriteString("]")
			p.advance()
		}
	} else if p.current.Type == TokenName {
		typeStr.WriteString(p.current.Value)
		p.advance()
	}

	if p.current.Value == "!" {
		typeStr.WriteString("!")
		p.advance()
	}

	return typeStr.String()
}

func (p *Parser) parseDirectives() []*Directive {
	directives := make([]*Directive, 0)

	for p.current.Value == "@" {
		p.advance()
		d := &Directive{
			Arguments: make(map[string]interface{}),
		}

		if p.current.Type == TokenName {
			d.Name = p.current.Value
			p.advance()
		}

		if p.current.Value == "(" {
			d.Arguments = p.parseArguments()
		}

		directives = append(directives, d)
	}

	return directives
}

func (p *Parser) parseSelectionSet() (*SelectionSet, error) {
	if err := p.expect("{"); err != nil {
		return nil, err
	}

	ss := &SelectionSet{
		Selections: make([]Selection, 0),
	}

	for p.current.Value != "}" && p.current.Type != TokenEOF {
		sel, err := p.parseSelection()
		if err != nil {
			return nil, err
		}
		ss.Selections = append(ss.Selections, sel)
	}

	if err := p.expect("}"); err != nil {
		return nil, err
	}

	return ss, nil
}

func (p *Parser) parseSelection() (Selection, error) {
	if p.current.Type == TokenSpread {
		return p.parseFragmentOrInline()
	}
	return p.parseField()
}

func (p *Parser) parseField() (*Field, error) {
	field := &Field{
		Arguments: make(map[string]interface{}),
	}

	if p.current.Type != TokenName {
		return nil, fmt.Errorf("expected field name at line %d", p.current.Line)
	}

	name := p.current.Value
	p.advance()

	// Check for alias
	if p.current.Value == ":" {
		p.advance()
		field.Alias = name
		if p.current.Type != TokenName {
			return nil, fmt.Errorf("expected field name after alias at line %d", p.current.Line)
		}
		field.Name = p.current.Value
		p.advance()
	} else {
		field.Name = name
	}

	// Arguments
	if p.current.Value == "(" {
		field.Arguments = p.parseArguments()
	}

	// Directives
	field.Directives = p.parseDirectives()

	// Selection set
	if p.current.Value == "{" {
		ss, err := p.parseSelectionSet()
		if err != nil {
			return nil, err
		}
		field.SelectionSet = ss
	}

	return field, nil
}

func (p *Parser) parseArguments() map[string]interface{} {
	args := make(map[string]interface{})

	p.advance() // skip (

	for p.current.Value != ")" && p.current.Type != TokenEOF {
		if p.current.Type == TokenName {
			name := p.current.Value
			p.advance()

			if p.current.Value == ":" {
				p.advance()
				args[name] = p.parseValue()
			}
		} else {
			p.advance()
		}
	}

	if p.current.Value == ")" {
		p.advance()
	}

	return args
}

func (p *Parser) parseValue() interface{} {
	switch p.current.Type {
	case TokenInt:
		val, _ := strconv.ParseInt(p.current.Value, 10, 64)
		p.advance()
		return val
	case TokenFloat:
		val, _ := strconv.ParseFloat(p.current.Value, 64)
		p.advance()
		return val
	case TokenString:
		val := p.current.Value
		p.advance()
		return val
	case TokenName:
		val := p.current.Value
		p.advance()
		// Handle boolean and null
		switch val {
		case "true":
			return true
		case "false":
			return false
		case "null":
			return nil
		default:
			return val // Enum value
		}
	case TokenPunctuation:
		if p.current.Value == "$" {
			p.advance()
			varName := p.current.Value
			p.advance()
			return &VariableRef{Name: varName}
		}
		if p.current.Value == "[" {
			return p.parseListValue()
		}
		if p.current.Value == "{" {
			return p.parseObjectValue()
		}
	}

	p.advance()
	return nil
}

// VariableRef represents a variable reference
type VariableRef struct {
	Name string
}

func (p *Parser) parseListValue() []interface{} {
	list := make([]interface{}, 0)
	p.advance() // skip [

	for p.current.Value != "]" && p.current.Type != TokenEOF {
		list = append(list, p.parseValue())
	}

	if p.current.Value == "]" {
		p.advance()
	}

	return list
}

func (p *Parser) parseObjectValue() map[string]interface{} {
	obj := make(map[string]interface{})
	p.advance() // skip {

	for p.current.Value != "}" && p.current.Type != TokenEOF {
		if p.current.Type == TokenName {
			name := p.current.Value
			p.advance()
			if p.current.Value == ":" {
				p.advance()
				obj[name] = p.parseValue()
			}
		} else {
			p.advance()
		}
	}

	if p.current.Value == "}" {
		p.advance()
	}

	return obj
}

func (p *Parser) parseFragmentOrInline() (Selection, error) {
	p.advance() // skip ...

	if p.current.Value == "on" {
		// Inline fragment
		p.advance()
		inline := &InlineFragment{}

		if p.current.Type == TokenName {
			inline.TypeCondition = p.current.Value
			p.advance()
		}

		inline.Directives = p.parseDirectives()

		ss, err := p.parseSelectionSet()
		if err != nil {
			return nil, err
		}
		inline.SelectionSet = ss

		return inline, nil
	}

	// Fragment spread
	spread := &FragmentSpread{}
	if p.current.Type == TokenName {
		spread.Name = p.current.Value
		p.advance()
	}
	spread.Directives = p.parseDirectives()

	return spread, nil
}

func (p *Parser) parseFragmentDefinition() (*Fragment, error) {
	p.advance() // skip "fragment"

	frag := &Fragment{}

	if p.current.Type == TokenName {
		frag.Name = p.current.Value
		p.advance()
	}

	if p.current.Value == "on" {
		p.advance()
		if p.current.Type == TokenName {
			frag.TypeCondition = p.current.Value
			p.advance()
		}
	}

	frag.Directives = p.parseDirectives()

	ss, err := p.parseSelectionSet()
	if err != nil {
		return nil, err
	}
	frag.SelectionSet = ss

	return frag, nil
}

// Executor executes GraphQL operations
type Executor struct {
	schema    *GraphQLSchema
	resolvers *ResolverMap
}

// ResolverMap holds field resolvers
type ResolverMap struct {
	mu        sync.RWMutex
	resolvers map[string]map[string]GraphQLResolver
}

// NewResolverMap creates a new resolver map
func NewResolverMap() *ResolverMap {
	return &ResolverMap{
		resolvers: make(map[string]map[string]GraphQLResolver),
	}
}

// Set sets a resolver for a type and field
func (rm *ResolverMap) Set(typeName, fieldName string, resolver GraphQLResolver) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.resolvers[typeName] == nil {
		rm.resolvers[typeName] = make(map[string]GraphQLResolver)
	}
	rm.resolvers[typeName][fieldName] = resolver
}

// Get gets a resolver for a type and field
func (rm *ResolverMap) Get(typeName, fieldName string) (GraphQLResolver, bool) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if typeResolvers, ok := rm.resolvers[typeName]; ok {
		if resolver, ok := typeResolvers[fieldName]; ok {
			return resolver, true
		}
	}
	return nil, false
}

// NewExecutor creates a new executor
func NewExecutor(schema *GraphQLSchema) *Executor {
	exec := &Executor{
		schema:    schema,
		resolvers: NewResolverMap(),
	}
	exec.registerDefaultResolvers()
	return exec
}

// RegisterResolver registers a resolver for a field
func (e *Executor) RegisterResolver(typeName, fieldName string, resolver GraphQLResolver) {
	e.resolvers.Set(typeName, fieldName, resolver)
}

// Execute executes a GraphQL request
func (e *Executor) Execute(ctx context.Context, req GraphQLRequest) *GraphQLResponse {
	// Parse the query
	parser := NewParser(req.Query)
	doc, err := parser.Parse()
	if err != nil {
		return &GraphQLResponse{
			Errors: []GraphQLError{{Message: err.Error()}},
		}
	}

	// Find the operation to execute
	var operation *Operation
	for _, op := range doc.Operations {
		if req.OperationName == "" || op.Name == req.OperationName {
			operation = op
			break
		}
	}

	if operation == nil {
		if req.OperationName != "" {
			return &GraphQLResponse{
				Errors: []GraphQLError{{Message: fmt.Sprintf("operation '%s' not found", req.OperationName)}},
			}
		}
		if len(doc.Operations) == 0 {
			return &GraphQLResponse{
				Errors: []GraphQLError{{Message: "no operation found"}},
			}
		}
		operation = doc.Operations[0]
	}

	// Substitute variables
	variables := req.Variables
	if variables == nil {
		variables = make(map[string]interface{})
	}

	// Apply default values from variable definitions
	for _, varDef := range operation.Variables {
		if _, exists := variables[varDef.Name]; !exists && varDef.DefaultValue != nil {
			variables[varDef.Name] = varDef.DefaultValue
		}
	}

	// Execute the operation
	execCtx := &ExecutionContext{
		ctx:       ctx,
		doc:       doc,
		variables: variables,
		errors:    make([]GraphQLError, 0),
	}

	var data interface{}
	switch operation.Type {
	case "query":
		data = e.executeSelectionSet(execCtx, "Query", operation.SelectionSet, nil)
	case "mutation":
		data = e.executeSelectionSet(execCtx, "Mutation", operation.SelectionSet, nil)
	case "subscription":
		return &GraphQLResponse{
			Errors: []GraphQLError{{Message: "subscriptions are not supported in this context"}},
		}
	}

	resp := &GraphQLResponse{
		Data: data,
	}
	if len(execCtx.errors) > 0 {
		resp.Errors = execCtx.errors
	}

	return resp
}

// ExecutionContext holds execution state
type ExecutionContext struct {
	ctx       context.Context
	doc       *Document
	variables map[string]interface{}
	errors    []GraphQLError
	path      []interface{}
}

func (e *Executor) executeSelectionSet(execCtx *ExecutionContext, typeName string, selSet *SelectionSet, source interface{}) map[string]interface{} {
	if selSet == nil {
		return nil
	}

	result := make(map[string]interface{})

	for _, sel := range selSet.Selections {
		switch s := sel.(type) {
		case *Field:
			fieldName := s.Name
			alias := s.Alias
			if alias == "" {
				alias = fieldName
			}

			// Resolve arguments with variable substitution
			args := e.resolveArguments(execCtx, s.Arguments)

			// Get the field resolver
			value, err := e.resolveField(execCtx, typeName, fieldName, args, source)
			if err != nil {
				execCtx.errors = append(execCtx.errors, GraphQLError{
					Message: err.Error(),
					Path:    append(append([]interface{}{}, execCtx.path...), alias),
				})
				result[alias] = nil
				continue
			}

			// If field has nested selection set, execute it
			if s.SelectionSet != nil && value != nil {
				// Handle arrays
				if arr, ok := value.([]interface{}); ok {
					resultArr := make([]interface{}, len(arr))
					for i, item := range arr {
						if itemMap, ok := item.(map[string]interface{}); ok {
							execCtx.path = append(execCtx.path, i)
							resultArr[i] = e.executeNestedSelectionSet(execCtx, s.SelectionSet, itemMap)
							execCtx.path = execCtx.path[:len(execCtx.path)-1]
						} else {
							resultArr[i] = item
						}
					}
					value = resultArr
				} else if valueMap, ok := value.(map[string]interface{}); ok {
					value = e.executeNestedSelectionSet(execCtx, s.SelectionSet, valueMap)
				}
			}

			result[alias] = value

		case *FragmentSpread:
			if frag, ok := execCtx.doc.Fragments[s.Name]; ok {
				fragResult := e.executeSelectionSet(execCtx, frag.TypeCondition, frag.SelectionSet, source)
				for k, v := range fragResult {
					result[k] = v
				}
			}

		case *InlineFragment:
			fragResult := e.executeSelectionSet(execCtx, s.TypeCondition, s.SelectionSet, source)
			for k, v := range fragResult {
				result[k] = v
			}
		}
	}

	return result
}

func (e *Executor) executeNestedSelectionSet(execCtx *ExecutionContext, selSet *SelectionSet, source map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	for _, sel := range selSet.Selections {
		if field, ok := sel.(*Field); ok {
			alias := field.Alias
			if alias == "" {
				alias = field.Name
			}

			// Get value from source
			if value, exists := source[field.Name]; exists {
				// Handle nested selection sets
				if field.SelectionSet != nil && value != nil {
					if arr, ok := value.([]interface{}); ok {
						resultArr := make([]interface{}, len(arr))
						for i, item := range arr {
							if itemMap, ok := item.(map[string]interface{}); ok {
								resultArr[i] = e.executeNestedSelectionSet(execCtx, field.SelectionSet, itemMap)
							} else {
								resultArr[i] = item
							}
						}
						value = resultArr
					} else if valueMap, ok := value.(map[string]interface{}); ok {
						value = e.executeNestedSelectionSet(execCtx, field.SelectionSet, valueMap)
					}
				}
				result[alias] = value
			}
		}
	}

	return result
}

func (e *Executor) resolveArguments(execCtx *ExecutionContext, args map[string]interface{}) map[string]interface{} {
	resolved := make(map[string]interface{})

	for name, value := range args {
		resolved[name] = e.resolveValue(execCtx, value)
	}

	return resolved
}

func (e *Executor) resolveValue(execCtx *ExecutionContext, value interface{}) interface{} {
	switch v := value.(type) {
	case *VariableRef:
		if val, ok := execCtx.variables[v.Name]; ok {
			return val
		}
		return nil
	case []interface{}:
		resolved := make([]interface{}, len(v))
		for i, item := range v {
			resolved[i] = e.resolveValue(execCtx, item)
		}
		return resolved
	case map[string]interface{}:
		resolved := make(map[string]interface{})
		for k, item := range v {
			resolved[k] = e.resolveValue(execCtx, item)
		}
		return resolved
	default:
		return value
	}
}

func (e *Executor) resolveField(execCtx *ExecutionContext, typeName, fieldName string, args map[string]interface{}, source interface{}) (interface{}, error) {
	// Check for custom resolver
	if resolver, ok := e.resolvers.Get(typeName, fieldName); ok {
		return resolver(execCtx.ctx, args)
	}

	// Check schema for field definition
	if typeName == "Query" && e.schema.Query != nil {
		if _, ok := e.schema.Query.Fields[fieldName]; ok {
			// Return placeholder if no resolver registered
			return nil, nil
		}
	}
	if typeName == "Mutation" && e.schema.Mutation != nil {
		if _, ok := e.schema.Mutation.Fields[fieldName]; ok {
			return nil, nil
		}
	}

	// For object fields, try to get from source
	if source != nil {
		if sourceMap, ok := source.(map[string]interface{}); ok {
			if val, exists := sourceMap[fieldName]; exists {
				return val, nil
			}
		}
	}

	return nil, nil
}

// registerDefaultResolvers registers default resolvers for the SIEM schema
func (e *Executor) registerDefaultResolvers() {
	// Query resolvers
	e.RegisterResolver("Query", "events", e.resolveEvents)
	e.RegisterResolver("Query", "alerts", e.resolveAlerts)
	e.RegisterResolver("Query", "validators", e.resolveValidators)
	e.RegisterResolver("Query", "incidents", e.resolveIncidents)
	e.RegisterResolver("Query", "complianceScore", e.resolveComplianceScore)
	e.RegisterResolver("Query", "threatLevel", e.resolveThreatLevel)

	// Mutation resolvers
	e.RegisterResolver("Mutation", "acknowledgeAlert", e.resolveAcknowledgeAlert)
	e.RegisterResolver("Mutation", "createIncident", e.resolveCreateIncident)
	e.RegisterResolver("Mutation", "updateRule", e.resolveUpdateRule)
}

func (e *Executor) resolveEvents(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	limit := 100
	if first, ok := args["first"].(int64); ok {
		limit = int(first)
	}

	// Return sample events (in production, query from ClickHouse)
	events := make([]interface{}, 0, limit)
	for i := 0; i < limit && i < 10; i++ {
		events = append(events, map[string]interface{}{
			"id":        fmt.Sprintf("event-%d", i+1),
			"timestamp": time.Now().Add(-time.Duration(i) * time.Minute).Format(time.RFC3339),
			"action":    "transaction",
			"outcome":   "success",
			"severity":  3,
			"source": map[string]interface{}{
				"host": "node-1.ethereum.local",
				"ip":   "10.0.0.1",
				"type": "blockchain",
			},
			"target": "0x742d35Cc6634C0532925a3b844Bc9e7595f8E2c2",
			"metadata": map[string]interface{}{
				"chain":    "ethereum",
				"block":    12345678 + i,
				"gas_used": 21000,
				"tx_type":  "transfer",
			},
		})
	}

	return events, nil
}

func (e *Executor) resolveAlerts(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	limit := 50
	if first, ok := args["first"].(int64); ok {
		limit = int(first)
	}

	severityFilter := ""
	if sev, ok := args["severity"].(string); ok {
		severityFilter = sev
	}

	statusFilter := ""
	if status, ok := args["status"].(string); ok {
		statusFilter = status
	}

	// Return sample alerts
	alerts := make([]interface{}, 0, limit)
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	statuses := []string{"OPEN", "ACKNOWLEDGED", "INVESTIGATING"}

	for i := 0; i < limit && i < 5; i++ {
		sev := severities[i%len(severities)]
		status := statuses[i%len(statuses)]

		if severityFilter != "" && sev != severityFilter {
			continue
		}
		if statusFilter != "" && status != statusFilter {
			continue
		}

		alerts = append(alerts, map[string]interface{}{
			"id":        fmt.Sprintf("alert-%d", i+1),
			"ruleId":    fmt.Sprintf("rule-%d", i+1),
			"ruleName":  fmt.Sprintf("Detection Rule %d", i+1),
			"severity":  sev,
			"status":    status,
			"createdAt": time.Now().Add(-time.Duration(i) * time.Hour).Format(time.RFC3339),
			"events": []interface{}{
				map[string]interface{}{
					"id":        fmt.Sprintf("event-%d-1", i+1),
					"timestamp": time.Now().Add(-time.Duration(i) * time.Hour).Format(time.RFC3339),
					"action":    "suspicious_activity",
					"outcome":   "unknown",
					"severity":  4,
					"source": map[string]interface{}{
						"host": "blockchain-node-1",
						"ip":   "10.0.0.1",
						"type": "ethereum",
					},
				},
			},
		})
	}

	return alerts, nil
}

func (e *Executor) resolveValidators(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	statusFilter := ""
	if status, ok := args["status"].(string); ok {
		statusFilter = status
	}

	validators := make([]interface{}, 0)
	for i := 0; i < 5; i++ {
		status := "ACTIVE"
		if i == 2 {
			status = "INACTIVE"
		}

		if statusFilter != "" && status != statusFilter {
			continue
		}

		validators = append(validators, map[string]interface{}{
			"id":          fmt.Sprintf("validator-%d", i+1),
			"address":     fmt.Sprintf("0x%040x", i+1),
			"status":      status,
			"stake":       "32000000000000000000",
			"performance": 99.5 - float64(i)*0.5,
			"lastSeen":    time.Now().Add(-time.Duration(i) * time.Minute).Format(time.RFC3339),
		})
	}

	return validators, nil
}

func (e *Executor) resolveIncidents(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	limit := 20
	if first, ok := args["first"].(int64); ok {
		limit = int(first)
	}

	incidents := make([]interface{}, 0, limit)
	for i := 0; i < limit && i < 3; i++ {
		incidents = append(incidents, map[string]interface{}{
			"id":          fmt.Sprintf("incident-%d", i+1),
			"title":       fmt.Sprintf("Security Incident %d", i+1),
			"description": "Detected suspicious activity pattern",
			"status":      "INVESTIGATING",
			"severity":    "HIGH",
			"createdAt":   time.Now().Add(-time.Duration(i) * 24 * time.Hour).Format(time.RFC3339),
			"alertCount":  5 + i*2,
			"assignee":    fmt.Sprintf("analyst-%d", i+1),
		})
	}

	return incidents, nil
}

func (e *Executor) resolveComplianceScore(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"overall": 85.5,
		"categories": map[string]interface{}{
			"access_control":    90.0,
			"data_security":     88.5,
			"monitoring":        82.0,
			"incident_response": 81.0,
		},
		"lastUpdated": time.Now().Format(time.RFC3339),
		"trend":       "improving",
	}, nil
}

func (e *Executor) resolveThreatLevel(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"level":         "MODERATE",
		"score":         45,
		"activeThreats": 3,
		"indicators": []interface{}{
			map[string]interface{}{
				"type":  "malicious_address",
				"count": 5,
				"trend": "stable",
			},
			map[string]interface{}{
				"type":  "suspicious_pattern",
				"count": 12,
				"trend": "increasing",
			},
		},
		"lastUpdated": time.Now().Format(time.RFC3339),
	}, nil
}

func (e *Executor) resolveAcknowledgeAlert(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	id, ok := args["id"].(string)
	if !ok || id == "" {
		return nil, fmt.Errorf("id is required and must be a string")
	}

	// comment is optional, so we don't return an error if missing
	comment, _ := args["comment"].(string)

	return map[string]interface{}{
		"id":      id,
		"status":  "ACKNOWLEDGED",
		"ackedAt": time.Now().Format(time.RFC3339),
		"ackedBy": "current-user",
		"comment": comment,
	}, nil
}

func (e *Executor) resolveCreateIncident(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	input, ok := args["input"].(map[string]interface{})
	if !ok || input == nil {
		return nil, fmt.Errorf("input is required and must be an object")
	}

	title, ok := input["title"].(string)
	if !ok || title == "" {
		return nil, fmt.Errorf("title is required and must be a string")
	}

	// description is optional
	description, _ := input["description"].(string)

	// severity is optional with default
	severity, _ := input["severity"].(string)
	if severity == "" {
		severity = "MEDIUM"
	}

	return map[string]interface{}{
		"id":          fmt.Sprintf("incident-%d", time.Now().UnixNano()),
		"title":       title,
		"description": description,
		"severity":    severity,
		"status":      "OPEN",
		"createdAt":   time.Now().Format(time.RFC3339),
	}, nil
}

func (e *Executor) resolveUpdateRule(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	id, ok := args["id"].(string)
	if !ok || id == "" {
		return nil, fmt.Errorf("id is required and must be a string")
	}

	input, ok := args["input"].(map[string]interface{})
	if !ok || input == nil {
		return nil, fmt.Errorf("input is required and must be an object")
	}

	rule := map[string]interface{}{
		"id":        id,
		"updatedAt": time.Now().Format(time.RFC3339),
	}

	// Merge input into rule
	for k, v := range input {
		rule[k] = v
	}

	return rule, nil
}

// ValidateQuery validates a GraphQL query against the schema
func (e *Executor) ValidateQuery(query string) []GraphQLError {
	errors := make([]GraphQLError, 0)

	parser := NewParser(query)
	doc, err := parser.Parse()
	if err != nil {
		errors = append(errors, GraphQLError{Message: err.Error()})
		return errors
	}

	for _, op := range doc.Operations {
		errors = append(errors, e.validateOperation(op)...)
	}

	return errors
}

func (e *Executor) validateOperation(op *Operation) []GraphQLError {
	errors := make([]GraphQLError, 0)

	var rootType *GraphQLObject
	switch op.Type {
	case "query":
		rootType = e.schema.Query
	case "mutation":
		rootType = e.schema.Mutation
	case "subscription":
		rootType = e.schema.Subscription
	}

	if rootType == nil {
		errors = append(errors, GraphQLError{
			Message: fmt.Sprintf("%s operations are not supported", op.Type),
		})
		return errors
	}

	errors = append(errors, e.validateSelectionSet(op.SelectionSet, rootType.Name)...)

	return errors
}

func (e *Executor) validateSelectionSet(ss *SelectionSet, typeName string) []GraphQLError {
	errors := make([]GraphQLError, 0)

	if ss == nil {
		return errors
	}

	for _, sel := range ss.Selections {
		if field, ok := sel.(*Field); ok {
			// Check if field exists in schema
			if typeName == "Query" && e.schema.Query != nil {
				if _, exists := e.schema.Query.Fields[field.Name]; !exists {
					// Allow introspection fields
					if !isIntrospectionField(field.Name) {
						errors = append(errors, GraphQLError{
							Message: fmt.Sprintf("field '%s' not found on type '%s'", field.Name, typeName),
						})
					}
				}
			}
			if typeName == "Mutation" && e.schema.Mutation != nil {
				if _, exists := e.schema.Mutation.Fields[field.Name]; !exists {
					errors = append(errors, GraphQLError{
						Message: fmt.Sprintf("field '%s' not found on type '%s'", field.Name, typeName),
					})
				}
			}
		}
	}

	return errors
}

func isIntrospectionField(name string) bool {
	return name == "__schema" || name == "__type" || name == "__typename"
}

// Introspection support

// IntrospectionQuery handles introspection queries
func (e *Executor) HandleIntrospection(fieldName string) interface{} {
	switch fieldName {
	case "__schema":
		return e.introspectSchema()
	case "__type":
		return nil // Would need type name argument
	case "__typename":
		return "Query"
	}
	return nil
}

func (e *Executor) introspectSchema() map[string]interface{} {
	types := make([]interface{}, 0)

	// Add query type
	if e.schema.Query != nil {
		types = append(types, e.introspectType(e.schema.Query))
	}

	// Add mutation type
	if e.schema.Mutation != nil {
		types = append(types, e.introspectType(e.schema.Mutation))
	}

	// Add defined types
	for _, t := range e.schema.Types {
		types = append(types, map[string]interface{}{
			"kind":        t.Kind,
			"name":        t.Name,
			"description": t.Description,
		})
	}

	result := map[string]interface{}{
		"types": types,
	}

	if e.schema.Query != nil {
		result["queryType"] = map[string]interface{}{"name": e.schema.Query.Name}
	}
	if e.schema.Mutation != nil {
		result["mutationType"] = map[string]interface{}{"name": e.schema.Mutation.Name}
	}
	if e.schema.Subscription != nil {
		result["subscriptionType"] = map[string]interface{}{"name": e.schema.Subscription.Name}
	}

	return result
}

func (e *Executor) introspectType(obj *GraphQLObject) map[string]interface{} {
	fields := make([]interface{}, 0)

	for name, field := range obj.Fields {
		args := make([]interface{}, 0)
		for argName, arg := range field.Args {
			args = append(args, map[string]interface{}{
				"name":         argName,
				"description":  arg.Description,
				"type":         map[string]interface{}{"name": arg.Type},
				"defaultValue": arg.DefaultValue,
			})
		}

		fields = append(fields, map[string]interface{}{
			"name":        name,
			"description": field.Description,
			"args":        args,
			"type":        map[string]interface{}{"name": field.Type},
		})
	}

	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        obj.Name,
		"description": obj.Description,
		"fields":      fields,
	}
}

// GraphQL complexity analysis

// ComplexityConfig configures query complexity limits
type ComplexityConfig struct {
	MaxDepth      int
	MaxComplexity int
	MaxFields     int
}

// DefaultComplexityConfig returns default complexity limits
func DefaultComplexityConfig() *ComplexityConfig {
	return &ComplexityConfig{
		MaxDepth:      10,
		MaxComplexity: 1000,
		MaxFields:     100,
	}
}

// AnalyzeComplexity analyzes query complexity
func (e *Executor) AnalyzeComplexity(query string, config *ComplexityConfig) (int, []GraphQLError) {
	parser := NewParser(query)
	doc, err := parser.Parse()
	if err != nil {
		return 0, []GraphQLError{{Message: err.Error()}}
	}

	errors := make([]GraphQLError, 0)
	totalComplexity := 0
	totalFields := 0

	for _, op := range doc.Operations {
		complexity, depth, fields := e.calculateComplexity(op.SelectionSet, 0)
		totalComplexity += complexity
		totalFields += fields

		if depth > config.MaxDepth {
			errors = append(errors, GraphQLError{
				Message: fmt.Sprintf("query depth %d exceeds maximum %d", depth, config.MaxDepth),
			})
		}
	}

	if totalComplexity > config.MaxComplexity {
		errors = append(errors, GraphQLError{
			Message: fmt.Sprintf("query complexity %d exceeds maximum %d", totalComplexity, config.MaxComplexity),
		})
	}

	if totalFields > config.MaxFields {
		errors = append(errors, GraphQLError{
			Message: fmt.Sprintf("query field count %d exceeds maximum %d", totalFields, config.MaxFields),
		})
	}

	return totalComplexity, errors
}

func (e *Executor) calculateComplexity(ss *SelectionSet, depth int) (complexity, maxDepth, fieldCount int) {
	if ss == nil {
		return 0, depth, 0
	}

	currentDepth := depth
	for _, sel := range ss.Selections {
		if field, ok := sel.(*Field); ok {
			fieldCount++
			fieldComplexity := 1

			// List fields add multiplier
			if field.SelectionSet != nil {
				// Check for list argument (first, limit, etc.)
				if first, ok := field.Arguments["first"]; ok {
					if n, ok := first.(int64); ok {
						fieldComplexity *= int(n)
					}
				}

				childComplexity, childDepth, childFields := e.calculateComplexity(field.SelectionSet, depth+1)
				complexity += fieldComplexity * childComplexity
				fieldCount += childFields
				if childDepth > maxDepth {
					maxDepth = childDepth
				}
			} else {
				complexity += fieldComplexity
				if depth+1 > maxDepth {
					maxDepth = depth + 1
				}
			}
		}
	}

	if currentDepth > maxDepth {
		maxDepth = currentDepth
	}

	return complexity, maxDepth, fieldCount
}

// Query sanitization
var unsafePatterns = []*regexp.Regexp{
	regexp.MustCompile(`__`), // Introspection in some cases
}

// SanitizeQuery removes potentially dangerous patterns
func SanitizeQuery(query string) string {
	// Remove comments
	lines := strings.Split(query, "\n")
	var sanitized []string
	for _, line := range lines {
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		sanitized = append(sanitized, line)
	}
	return strings.Join(sanitized, "\n")
}
