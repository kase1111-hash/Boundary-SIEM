package search

import (
	"reflect"
	"testing"
)

// whereFor parses q and returns its WHERE clause without tenant or time
// filters, so the clause is exactly the user's expression.
func whereFor(t *testing.T, q string) (string, []interface{}) {
	t.Helper()
	parsed, err := ParseQuery(q)
	if err != nil {
		t.Fatalf("ParseQuery(%q) error = %v", q, err)
	}
	if len(parsed.Conditions) > 0 && len(parsed.Logic) != len(parsed.Conditions)-1 {
		t.Errorf("ParseQuery(%q): %d conditions but %d connectives %v", q, len(parsed.Conditions), len(parsed.Logic), parsed.Logic)
	}
	clause, args, err := newTestExecutor().buildWhereClause(parsed)
	if err != nil {
		t.Fatalf("buildWhereClause(%q) error = %v", q, err)
	}
	return clause, args
}

// Regression (H26): NOT was dropped before a parenthesized group and before
// >, >=, <, <=, != and !~, so analysts got the opposite result set.
func TestParseQuery_NotNegatesConditionsAndGroups(t *testing.T) {
	tests := []struct {
		query string
		want  string
	}{
		{"NOT action:login", "WHERE action != ?"},
		{"NOT (action=auth.login)", "WHERE action != ?"},
		{"NOT severity>5", "WHERE severity <= ?"},
		{"NOT severity>=5", "WHERE severity < ?"},
		{"NOT severity<5", "WHERE severity >= ?"},
		{"NOT severity<=5", "WHERE severity > ?"},
		{"NOT action!=auth.login", "WHERE action = ?"},
		{"NOT raw~error", "WHERE position(raw, ?) = 0"},
		{"NOT raw!~error", "WHERE position(raw, ?) > 0"},
		{"NOT NOT action:login", "WHERE action = ?"},
		{"!action:login", "WHERE action != ?"},
		{"NOT action:auth.*", "WHERE NOT match(action, ?)"},
		{`NOT raw:"login failed"`, "WHERE position(raw, ?) = 0"},
		{"NOT metadata.chain_id:1", "WHERE JSONExtractString(metadata, ?) != ?"},
		{"NOT metadata.gas>100", "WHERE JSONExtractFloat(metadata, ?) <= ?"},
		{"NOT meta.note~x", "WHERE position(JSONExtractString(metadata, ?), ?) = 0"},
		{"NOT meta.name:ab*", "WHERE NOT match(JSONExtractString(metadata, ?), ?)"},
		// De Morgan over groups.
		{"NOT (action:a OR action:b)", "WHERE action != ? AND action != ?"},
		{"NOT (action:a AND outcome:failure)", "WHERE action != ? OR outcome != ?"},
		{"severity>1 AND NOT (action:a OR action:b)", "WHERE severity > ? AND action != ? AND action != ?"},
		{"severity>1 AND NOT (action:a AND action:b)", "WHERE severity > ? AND (action != ? OR action != ?)"},
		{"NOT (action:a AND (outcome:x OR outcome:y))", "WHERE action != ? OR outcome != ? AND outcome != ?"},
		{"NOT (NOT (severity>5))", "WHERE severity > ?"},
		// "NOT ()" matched every event; it is rejected now (see
		// TestParseQuery_NotWithoutOperandIsRejected).
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			if got, _ := whereFor(t, tt.query); got != tt.want {
				t.Errorf("WHERE = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseQuery_NotWithoutOperandIsRejected(t *testing.T) {
	for _, q := range []string{
		"NOT", "action:a AND NOT", "(NOT)", "NOT AND action:a", "action:a NOT OR action:b", "NOT NOT",
		"NOT ()", "NOT *", "NOT (*)", // matched every event (E2E round 2)
	} {
		if _, err := ParseQuery(q); err == nil {
			t.Errorf("ParseQuery(%q) succeeded, want error", q)
		}
	}
}

// Regression (H27): adjacent conditions are implicitly ANDed, but no
// connective was recorded for them, so later OR/AND connectives were applied
// to the wrong pair ("a b OR c" became "a OR b AND c").
func TestParseQuery_ImplicitAndKeepsLogicAligned(t *testing.T) {
	tests := []struct {
		query     string
		want      string
		wantLogic []string
	}{
		{"action=a outcome=failure OR severity=9", "WHERE action = ? AND outcome = ? OR severity = ?", []string{"AND", "OR"}},
		{"action=a outcome=failure", "WHERE action = ? AND outcome = ?", []string{"AND"}},
		{"action:a OR action:b outcome:c", "WHERE action = ? OR action = ? AND outcome = ?", []string{"OR", "AND"}},
		{"action=a (outcome=x OR outcome=y)", "WHERE action = ? AND (outcome = ? OR outcome = ?)", []string{"AND", "OR"}},
		{"(action=a OR action=b) severity>3", "WHERE (action = ? OR action = ?) AND severity > ?", []string{"OR", "AND"}},
		{"action=a NOT outcome=x severity>3", "WHERE action = ? AND outcome != ? AND severity > ?", []string{"AND", "AND"}},
		{"(action:a OR action:b) AND (outcome:x OR outcome:y)", "WHERE (action = ? OR action = ?) AND (outcome = ? OR outcome = ?)", []string{"OR", "AND", "OR"}},
		{"((action:a OR action:b)) severity>1", "WHERE (action = ? OR action = ?) AND severity > ?", []string{"OR", "AND"}},
		{"* AND action:a", "WHERE action = ?", nil},
		{"action:a OR (*)", "", nil}, // OR with a term matching every event matches every event
		{"(action:a OR *) severity>3", "WHERE severity > ?", nil},
		// Dangling connectives ("AND action:a", "action:a OR",
		// "action:a AND OR action:b") and "() action:login" were ignored
		// rather than misaligning Logic; they are rejected now (see
		// TestParseQuery_RejectsMalformedQueries).
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			got, _ := whereFor(t, tt.query)
			if got != tt.want {
				t.Errorf("WHERE = %q, want %q", got, tt.want)
			}
			q, _ := ParseQuery(tt.query)
			if !reflect.DeepEqual(q.Logic, tt.wantLogic) {
				t.Errorf("Logic = %v, want %v", q.Logic, tt.wantLogic)
			}
		})
	}
}

// Regression (H28): escaped quotes kept their backslashes, and quoted values
// were still turned into numbers, relative times and wildcards.
func TestParseQuery_ValueTyping(t *testing.T) {
	tests := []struct {
		query      string
		want       interface{}
		wantRegex  bool
		wantPhrase bool
	}{
		{query: `raw:"say \"hi\" now"`, want: `say "hi" now`, wantPhrase: true},
		{query: `raw:'it\'s'`, want: `it's`},
		{query: `raw:"back\\slash"`, want: `back\slash`},
		{query: `raw:"keep \d as is"`, want: `keep \d as is`, wantPhrase: true},
		{query: `actor.id:"000123"`, want: "000123"},
		{query: `actor.id:000123`, want: "000123"}, // string column
		{query: `action:"now-1h"`, want: "now-1h"},
		{query: `action:"auth.*"`, want: "auth.*"}, // quoted: literal, not a wildcard
		{query: `action:auth.*`, want: `^auth\..*$`, wantRegex: true},
		{query: `target:42`, want: "42"},
		{query: `severity:5`, want: int64(5)},
		{query: `severity:"5"`, want: "5"},
		{query: `metadata.chain_id:1`, want: "1"},       // JSONExtractString comparison
		{query: `metadata.gas>100`, want: int64(100)},   // JSONExtractFloat comparison
		{query: `score>3.14`, want: float64(3.14)},      // unknown field keeps number parsing
		{query: `vendor:Acme`, want: "Acme"},            // metadata alias
		{query: `source.ip:10.1.2.3`, want: "10.1.2.3"}, // string column, not a float
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			q, err := ParseQuery(tt.query)
			if err != nil {
				t.Fatalf("ParseQuery error = %v", err)
			}
			if len(q.Conditions) != 1 {
				t.Fatalf("conditions = %+v, want 1", q.Conditions)
			}
			c := q.Conditions[0]
			if c.Value != tt.want {
				t.Errorf("value = %#v (%T), want %#v (%T)", c.Value, c.Value, tt.want, tt.want)
			}
			if c.IsRegex != tt.wantRegex || c.IsPhrase != tt.wantPhrase {
				t.Errorf("IsRegex=%v IsPhrase=%v, want %v %v", c.IsRegex, c.IsPhrase, tt.wantRegex, tt.wantPhrase)
			}
		})
	}
}

func TestParseQuery_MetadataAliases(t *testing.T) {
	for _, q := range []string{"vendor:Acme", "source.vendor:Acme"} {
		clause, args := whereFor(t, q)
		if clause != "WHERE JSONExtractString(metadata, ?) = ?" || len(args) != 2 || args[0] != "device_vendor" || args[1] != "Acme" {
			t.Errorf("%s: WHERE = %q args %v", q, clause, args)
		}
	}
	// A Query built without the parser resolves the alias too.
	clause, args, err := newTestExecutor().buildWhereClause(&Query{
		Conditions: []Condition{{Field: "vendor", Operator: OpEquals, Value: "Acme"}},
	})
	if err != nil || clause != "WHERE JSONExtractString(metadata, ?) = ?" || args[0] != "device_vendor" {
		t.Errorf("direct Query: WHERE = %q args %v err %v", clause, args, err)
	}
}

// Regression (H29): the lexer read bytes as runes, so the second byte of 'à'
// (0xA0, read as U+00A0 NO-BREAK SPACE) ended the value, leaving invalid
// UTF-8 "voil\xc3".
func TestLexer_DecodesUTF8(t *testing.T) {
	tests := []struct {
		query string
		want  []string
	}{
		{"user=voilà", []string{"voilà"}},
		{"user=Åsa", []string{"Åsa"}}, // Å is C3 85; 0x85 read as a rune is NEXT LINE
		{"user=名前 AND action:x", []string{"名前", "x"}},
		{`actor.name:"café au lait"`, []string{"café au lait"}},
		{"action:a outcome:b", []string{"a", "b"}}, // a real NBSP still separates terms
		// The value ends at the delimiter right after a multi-byte rune. (This
		// was "target:naïve~", whose dangling "~" is rejected now.)
		{"(target:naïve)", []string{"naïve"}},
		{"target:naïve AND action:x", []string{"naïve", "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			q, err := ParseQuery(tt.query)
			if err != nil {
				t.Fatalf("ParseQuery error = %v", err)
			}
			var got []string
			for _, c := range q.Conditions {
				s, _ := c.Value.(string)
				got = append(got, s)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("values = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLexer_UnicodeTokens(t *testing.T) {
	lexer := NewLexer("é:\"ü\"")
	if tok := lexer.NextToken(); tok.Type != TokenField || tok.Value != "é" {
		t.Errorf("first token = %+v", tok)
	}
	lexer.NextToken() // operator
	if tok := lexer.NextToken(); tok.Type != TokenValue || tok.Value != "ü" || !tok.Quoted {
		t.Errorf("value token = %+v", tok)
	}
}

func TestParseQuery_NestingDepthIsBounded(t *testing.T) {
	deep := ""
	for i := 0; i < 100; i++ {
		deep += "("
	}
	deep += "action:a"
	for i := 0; i < 100; i++ {
		deep += ")"
	}
	if _, err := ParseQuery(deep); err == nil {
		t.Error("ParseQuery accepted 100 nested groups, want a depth error")
	}
	if _, err := ParseQuery("((((action:a))))"); err != nil {
		t.Errorf("ParseQuery rejected modest nesting: %v", err)
	}
}
