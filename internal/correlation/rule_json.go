package correlation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// JSON wire format of rules.
//
// The dashboard (web/src/types/api.ts) expects snake_case keys and every
// window or span as a duration string such as "5m". Rule.Window,
// SequenceConfig.MaxSpan and AbsenceConfig.Timeout are time.Duration values
// and the Window fields of the type configs are whole seconds, so the types
// below convert them on the way in and out. On input, a duration field must be
// a duration string; a seconds field also accepts a plain number of seconds.

// formatDuration renders d the way rule authors write it: "5m" rather than
// "5m0s", "1h30m" rather than "1h30m0s".
func formatDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// isJSONNull reports whether raw is absent or the JSON literal null.
func isJSONNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

// parseJSONDuration decodes a duration string ("5m", "1h30m"). Plain numbers
// are rejected: their unit would be ambiguous.
func parseJSONDuration(raw json.RawMessage) (time.Duration, error) {
	if isJSONNull(raw) {
		return 0, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, fmt.Errorf("must be a duration string such as \"5m\", got %s", raw)
	}
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, fmt.Errorf("must not be negative, got %s", s)
	}
	return d, nil
}

// secondsString renders a whole number of seconds as a duration string, or ""
// for zero.
func secondsString(secs int) string {
	if secs == 0 {
		return ""
	}
	return formatDuration(time.Duration(secs) * time.Second)
}

// parseJSONSeconds decodes a whole number of seconds given either as a JSON
// number or as a duration string.
func parseJSONSeconds(raw json.RawMessage) (int, error) {
	if isJSONNull(raw) {
		return 0, nil
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		if n < 0 {
			return 0, fmt.Errorf("must not be negative, got %d", n)
		}
		return n, nil
	}
	d, err := parseJSONDuration(raw)
	if err != nil {
		return 0, err
	}
	if d%time.Second != 0 {
		return 0, fmt.Errorf("must be a whole number of seconds, got %s", d)
	}
	return int(d / time.Second), nil
}

// ruleFields has Rule's fields without its JSON methods.
type ruleFields Rule

// ruleWire is the JSON representation of a Rule.
type ruleWire struct {
	ruleFields
	Window string `json:"window"`
}

func (r *Rule) wire() ruleWire {
	return ruleWire{ruleFields: ruleFields(*r), Window: formatDuration(r.Window)}
}

// MarshalJSON encodes the rule in the dashboard's wire format.
func (r Rule) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.wire())
}

// UnmarshalJSON decodes a rule in the dashboard's wire format.
func (r *Rule) UnmarshalJSON(data []byte) error {
	aux := struct {
		*ruleFields
		Window json.RawMessage `json:"window"`
	}{ruleFields: (*ruleFields)(r)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	window, err := parseJSONDuration(aux.Window)
	if err != nil {
		return fmt.Errorf("window: %w", err)
	}
	r.Window = window
	return nil
}

// sourcedRule is a rule as the rules API returns it: the rule plus whether it
// is built in or a custom (file or API managed) rule.
type sourcedRule struct {
	ruleWire
	Source string `json:"source"`
}

func withSource(r *Rule, source string) sourcedRule {
	return sourcedRule{ruleWire: r.wire(), Source: source}
}

// MarshalJSON encodes Window as a duration string.
func (t ThresholdConfig) MarshalJSON() ([]byte, error) {
	type fields ThresholdConfig
	return json.Marshal(struct {
		fields
		Window string `json:"window,omitempty"`
	}{fields(t), secondsString(t.Window)})
}

// UnmarshalJSON accepts Window as a duration string or seconds.
func (t *ThresholdConfig) UnmarshalJSON(data []byte) error {
	type fields ThresholdConfig
	aux := struct {
		*fields
		Window json.RawMessage `json:"window"`
	}{fields: (*fields)(t)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	secs, err := parseJSONSeconds(aux.Window)
	if err != nil {
		return fmt.Errorf("threshold.window: %w", err)
	}
	t.Window = secs
	return nil
}

// MarshalJSON encodes MaxSpan and Window as duration strings.
func (s SequenceConfig) MarshalJSON() ([]byte, error) {
	type fields SequenceConfig
	maxSpan := ""
	if s.MaxSpan != 0 {
		maxSpan = formatDuration(s.MaxSpan)
	}
	return json.Marshal(struct {
		fields
		MaxSpan string `json:"max_span,omitempty"`
		Window  string `json:"window,omitempty"`
	}{fields(s), maxSpan, secondsString(s.Window)})
}

// UnmarshalJSON accepts MaxSpan as a duration string and Window as a
// duration string or seconds.
func (s *SequenceConfig) UnmarshalJSON(data []byte) error {
	type fields SequenceConfig
	aux := struct {
		*fields
		MaxSpan json.RawMessage `json:"max_span"`
		Window  json.RawMessage `json:"window"`
	}{fields: (*fields)(s)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	maxSpan, err := parseJSONDuration(aux.MaxSpan)
	if err != nil {
		return fmt.Errorf("sequence.max_span: %w", err)
	}
	secs, err := parseJSONSeconds(aux.Window)
	if err != nil {
		return fmt.Errorf("sequence.window: %w", err)
	}
	s.MaxSpan, s.Window = maxSpan, secs
	return nil
}

// MarshalJSON reports the comparison value once, as "threshold" (the name in
// api.ts), and Window as a duration string.
func (a AggregateConfig) MarshalJSON() ([]byte, error) {
	type fields AggregateConfig
	return json.Marshal(struct {
		fields
		Value     json.RawMessage `json:"value,omitempty"` // folded into threshold
		Threshold float64         `json:"threshold"`
		Window    string          `json:"window,omitempty"`
	}{fields: fields(a), Threshold: a.threshold(), Window: secondsString(a.Window)})
}

// UnmarshalJSON accepts the comparison value as "threshold" or "value" and
// Window as a duration string or seconds.
func (a *AggregateConfig) UnmarshalJSON(data []byte) error {
	type fields AggregateConfig
	aux := struct {
		*fields
		Window json.RawMessage `json:"window"`
	}{fields: (*fields)(a)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	secs, err := parseJSONSeconds(aux.Window)
	if err != nil {
		return fmt.Errorf("aggregate.window: %w", err)
	}
	a.Window = secs
	return nil
}

// expectedEvent summarises the expected conditions as the field -> value map
// api.ts calls expected_event. Only top-level eq conditions can be expressed
// that way; expected_conditions stays the complete definition.
func (a *AbsenceConfig) expectedEvent() map[string]any {
	event := make(map[string]any)
	for _, c := range a.ExpectedConditions {
		if c.Field != "" && c.Operator == "eq" {
			event[c.Field] = c.Value
		}
	}
	return event
}

// MarshalJSON adds the expected_event summary and encodes Timeout and Window
// as duration strings.
func (a AbsenceConfig) MarshalJSON() ([]byte, error) {
	type fields AbsenceConfig
	timeout := ""
	if a.Timeout != 0 {
		timeout = formatDuration(a.Timeout)
	}
	window := secondsString(a.Window)
	if window == "" {
		window = "0s"
	}
	return json.Marshal(struct {
		fields
		ExpectedEvent map[string]any `json:"expected_event"`
		Timeout       string         `json:"timeout,omitempty"`
		Window        string         `json:"window"`
	}{fields(a), a.expectedEvent(), timeout, window})
}

// UnmarshalJSON accepts Timeout as a duration string and Window as a duration
// string or seconds. When expected_conditions is absent, the expected_event
// map is taken as field = value conditions.
func (a *AbsenceConfig) UnmarshalJSON(data []byte) error {
	type fields AbsenceConfig
	aux := struct {
		*fields
		ExpectedEvent map[string]any  `json:"expected_event"`
		Timeout       json.RawMessage `json:"timeout"`
		Window        json.RawMessage `json:"window"`
	}{fields: (*fields)(a)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	timeout, err := parseJSONDuration(aux.Timeout)
	if err != nil {
		return fmt.Errorf("absence.timeout: %w", err)
	}
	secs, err := parseJSONSeconds(aux.Window)
	if err != nil {
		return fmt.Errorf("absence.window: %w", err)
	}
	a.Timeout, a.Window = timeout, secs
	if len(a.ExpectedConditions) == 0 && len(aux.ExpectedEvent) > 0 {
		keys := make([]string, 0, len(aux.ExpectedEvent))
		for k := range aux.ExpectedEvent {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			a.ExpectedConditions = append(a.ExpectedConditions,
				Condition{Field: k, Operator: "eq", Value: aux.ExpectedEvent[k]})
		}
	}
	return nil
}

// UnmarshalJSON also accepts the Go field names ("TacticID", ...) that were
// written before MITREMapping had JSON tags, so older stored alerts decode.
func (m *MITREMapping) UnmarshalJSON(data []byte) error {
	type fields MITREMapping
	aux := struct {
		*fields
		LegacyTacticID    *string  `json:"TacticID"`
		LegacyTacticName  *string  `json:"TacticName"`
		LegacyTechniqueID *string  `json:"TechniqueID"`
		LegacyTechniques  []string `json:"Techniques"`
	}{fields: (*fields)(m)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if m.TacticID == "" && aux.LegacyTacticID != nil {
		m.TacticID = *aux.LegacyTacticID
	}
	if m.TacticName == "" && aux.LegacyTacticName != nil {
		m.TacticName = *aux.LegacyTacticName
	}
	if m.TechniqueID == "" && aux.LegacyTechniqueID != nil {
		m.TechniqueID = *aux.LegacyTechniqueID
	}
	if len(m.Techniques) == 0 {
		m.Techniques = aux.LegacyTechniques
	}
	return nil
}
