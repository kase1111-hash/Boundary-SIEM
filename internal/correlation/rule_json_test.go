package correlation

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		{5 * time.Minute, "5m"},
		{time.Hour, "1h"},
		{24 * time.Hour, "24h"},
		{90 * time.Minute, "1h30m"},
		{30 * time.Second, "30s"},
		{90 * time.Second, "1m30s"},
		{300 * time.Millisecond, "300ms"},
		{0, "0s"},
	}
	for _, tt := range tests {
		got := formatDuration(tt.in)
		if got != tt.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.in, got, tt.want)
		}
		if back, err := time.ParseDuration(got); err != nil || back != tt.in {
			t.Errorf("formatDuration(%v) = %q does not parse back (%v, %v)", tt.in, got, back, err)
		}
	}
}

// Nested configs follow api.ts too: windows and spans are duration strings,
// the aggregate threshold is "threshold", absence has expected_event.
func TestRuleJSON_NestedShapes(t *testing.T) {
	tests := []struct {
		name string
		rule *Rule
		want map[string]any // path "a.b" -> value
	}{
		{
			name: "threshold",
			rule: &Rule{Type: RuleTypeThreshold, Window: time.Hour, Threshold: &ThresholdConfig{Count: 3, Window: 300, Operator: "gte"}},
			want: map[string]any{"window": "1h", "threshold.count": float64(3), "threshold.window": "5m"},
		},
		{
			name: "sequence",
			rule: &Rule{Type: RuleTypeSequence, Window: time.Hour, Sequence: &SequenceConfig{Ordered: true, MaxSpan: 30 * time.Minute, Steps: []SequenceStep{{Name: "a"}}}},
			want: map[string]any{"sequence.max_span": "30m", "sequence.ordered": true},
		},
		{
			name: "aggregate value reported as threshold",
			rule: &Rule{Type: RuleTypeAggregate, Window: time.Hour, Aggregate: &AggregateConfig{Function: "sum", Field: "metadata.amount", Value: 100}},
			want: map[string]any{"aggregate.threshold": float64(100), "aggregate.function": "sum", "aggregate.field": "metadata.amount"},
		},
		{
			name: "absence",
			rule: &Rule{Type: RuleTypeAbsence, Window: time.Hour, Absence: &AbsenceConfig{
				ExpectedConditions: []Condition{{Field: "action", Operator: "eq", Value: "system.heartbeat"}},
				Window:             600,
			}},
			want: map[string]any{"absence.window": "10m", "absence.expected_event.action": "system.heartbeat"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.rule)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			for path, want := range tt.want {
				var v any = got
				for _, key := range strings.Split(path, ".") {
					m, _ := v.(map[string]any)
					v = m[key]
				}
				if !reflect.DeepEqual(v, want) {
					t.Errorf("%s = %#v, want %#v (json %s)", path, v, want, data)
				}
			}
			if agg, _ := got["aggregate"].(map[string]any); agg["value"] != nil {
				t.Errorf("aggregate JSON reports both value and threshold: %s", data)
			}

			var back Rule
			if err := json.Unmarshal(data, &back); err != nil {
				t.Fatalf("decode own output: %v", err)
			}
			again, _ := json.Marshal(&back)
			if string(again) != string(data) {
				t.Errorf("JSON round trip changed the rule:\n got %s\nwant %s", again, data)
			}
		})
	}
}

func TestRuleJSON_Input(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		check   func(t *testing.T, r *Rule)
		wantErr string
	}{
		{
			name: "window as duration string",
			json: `{"window": "15m"}`,
			check: func(t *testing.T, r *Rule) {
				if r.Window != 15*time.Minute {
					t.Errorf("window = %v", r.Window)
				}
			},
		},
		{name: "window as number is ambiguous", json: `{"window": 300}`, wantErr: "window"},
		{name: "bad window string", json: `{"window": "5 minutes"}`, wantErr: "window"},
		{
			name: "threshold window as seconds or string",
			json: `{"threshold": {"count": 2, "window": "2m"}, "sequence": {"window": 60, "max_span": "1h", "steps": []}}`,
			check: func(t *testing.T, r *Rule) {
				if r.Threshold.Window != 120 || r.Sequence.Window != 60 || r.Sequence.MaxSpan != time.Hour {
					t.Errorf("threshold=%+v sequence=%+v", r.Threshold, r.Sequence)
				}
			},
		},
		{
			name: "aggregate threshold key",
			json: `{"aggregate": {"function": "count_distinct", "field": "target", "threshold": 20}}`,
			check: func(t *testing.T, r *Rule) {
				if r.Aggregate.threshold() != 20 {
					t.Errorf("aggregate threshold = %v", r.Aggregate.threshold())
				}
			},
		},
		{
			name: "absence expected_event shorthand",
			json: `{"absence": {"expected_event": {"action": "system.heartbeat", "source.host": "db1"}, "window": "5m"}}`,
			check: func(t *testing.T, r *Rule) {
				want := []Condition{
					{Field: "action", Operator: "eq", Value: "system.heartbeat"},
					{Field: "source.host", Operator: "eq", Value: "db1"},
				}
				if !reflect.DeepEqual(r.Absence.ExpectedConditions, want) || r.Absence.Window != 300 {
					t.Errorf("absence = %+v", r.Absence)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r Rule
			err := json.Unmarshal([]byte(tt.json), &r)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Unmarshal error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, &r)
		})
	}
}

// Alerts stored before MITREMapping had JSON tags used Go field names.
func TestMITREMapping_DecodesLegacyFieldNames(t *testing.T) {
	var m MITREMapping
	legacy := `{"TacticID":"TA0006","TacticName":"Credential Access","TechniqueID":"T1110","Techniques":["T1110.001"]}`
	if err := json.Unmarshal([]byte(legacy), &m); err != nil {
		t.Fatal(err)
	}
	want := MITREMapping{TacticID: "TA0006", TacticName: "Credential Access", TechniqueID: "T1110", Techniques: []string{"T1110.001"}}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("decoded %+v, want %+v", m, want)
	}

	data, _ := json.Marshal(&want)
	if !strings.Contains(string(data), `"tactic_id":"TA0006"`) || !strings.Contains(string(data), `"technique_name":""`) {
		t.Errorf("MITREMapping JSON = %s, want api.ts field names", data)
	}
}
