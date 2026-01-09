package correlation

import (
	"context"
	"sync"
	"testing"
	"time"

	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

func TestCondition_Match(t *testing.T) {
	tests := []struct {
		name      string
		condition Condition
		value     any
		expected  bool
	}{
		{
			name:      "eq string match",
			condition: Condition{Field: "action", Operator: "eq", Value: "auth.failure"},
			value:     "auth.failure",
			expected:  true,
		},
		{
			name:      "eq string no match",
			condition: Condition{Field: "action", Operator: "eq", Value: "auth.failure"},
			value:     "auth.success",
			expected:  false,
		},
		{
			name:      "ne string match",
			condition: Condition{Field: "action", Operator: "ne", Value: "auth.success"},
			value:     "auth.failure",
			expected:  true,
		},
		{
			name:      "gt numeric",
			condition: Condition{Field: "severity", Operator: "gt", Value: 5},
			value:     7,
			expected:  true,
		},
		{
			name:      "gte numeric",
			condition: Condition{Field: "severity", Operator: "gte", Value: 7},
			value:     7,
			expected:  true,
		},
		{
			name:      "lt numeric",
			condition: Condition{Field: "severity", Operator: "lt", Value: 5},
			value:     3,
			expected:  true,
		},
		{
			name:      "contains match",
			condition: Condition{Field: "action", Operator: "contains", Value: "auth"},
			value:     "auth.failure",
			expected:  true,
		},
		{
			name:      "regex match",
			condition: Condition{Field: "action", Operator: "regex", Value: "^auth\\..*"},
			value:     "auth.failure",
			expected:  true,
		},
		{
			name:      "in list match",
			condition: Condition{Field: "action", Operator: "in", Values: []string{"auth.success", "auth.failure"}},
			value:     "auth.failure",
			expected:  true,
		},
		{
			name:      "in list no match",
			condition: Condition{Field: "action", Operator: "in", Values: []string{"auth.success"}},
			value:     "auth.failure",
			expected:  false,
		},
		{
			name:      "exists match",
			condition: Condition{Field: "action", Operator: "exists"},
			value:     "something",
			expected:  true,
		},
		{
			name:      "exists no match",
			condition: Condition{Field: "action", Operator: "exists"},
			value:     "",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.condition.Match(tt.value)
			if result != tt.expected {
				t.Errorf("Match() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestRule_Validate(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		{
			name: "valid threshold rule",
			rule: Rule{
				ID:       "test-1",
				Name:     "Test Rule",
				Type:     RuleTypeThreshold,
				Enabled:  true,
				Severity: 7,
				Conditions: Conditions{
					Match: []MatchCondition{
						{Field: "action", Operator: "eq", Value: "auth.failure"},
					},
				},
				Threshold: &ThresholdConfig{Count: 10, Operator: "gte"},
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			rule: Rule{
				Name:      "Test Rule",
				Type:      RuleTypeThreshold,
				Threshold: &ThresholdConfig{Count: 10},
			},
			wantErr: true,
		},
		{
			name: "threshold rule without config",
			rule: Rule{
				ID:   "test-1",
				Name: "Test Rule",
				Type: RuleTypeThreshold,
			},
			wantErr: true,
		},
		{
			name: "sequence rule with insufficient steps",
			rule: Rule{
				ID:   "test-1",
				Name: "Test Rule",
				Type: RuleTypeSequence,
				Sequence: &SequenceConfig{
					Steps: []SequenceStep{
						{Name: "step1"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid custom rule",
			rule: Rule{
				ID:       "test-custom",
				Name:     "Custom Rule",
				Type:     RuleTypeCustom,
				Enabled:  true,
				Severity: 5,
				Conditions: Conditions{
					Match: []MatchCondition{
						{Field: "action", Operator: "eq", Value: "test"},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEngine_ThresholdRule(t *testing.T) {
	engine := NewEngine(DefaultEngineConfig())

	var alertReceived *Alert
	var mu sync.Mutex

	engine.AddHandler(func(ctx context.Context, alert *Alert) error {
		mu.Lock()
		alertReceived = alert
		mu.Unlock()
		return nil
	})

	rule := &Rule{
		ID:       "test-brute-force",
		Name:     "Brute Force Detection",
		Type:     RuleTypeThreshold,
		Enabled:  true,
		Severity: 7,
		Window:   1 * time.Minute,
		Conditions: Conditions{
			Match: []MatchCondition{
				{Field: "action", Operator: "eq", Value: "auth.failure"},
			},
		},
		GroupBy: []string{"actor.ip"},
		Threshold: &ThresholdConfig{
			Count:    3,
			Operator: "gte",
		},
	}

	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("failed to add rule: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx)
	defer engine.Stop()

	// Send events
	for i := 0; i < 5; i++ {
		event := &schema.Event{
			EventID:   uuid.New(),
			Timestamp: time.Now(),
			Action:    "auth.failure",
			Actor:     &schema.Actor{IPAddress: "192.168.1.100"},
		}
		engine.ProcessEvent(event)
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if alertReceived == nil {
		t.Error("expected alert to be generated")
	} else {
		if alertReceived.RuleID != rule.ID {
			t.Errorf("alert rule ID = %s, want %s", alertReceived.RuleID, rule.ID)
		}
		if alertReceived.Severity != 7 {
			t.Errorf("alert severity = %d, want 7", alertReceived.Severity)
		}
	}
}

func TestEngine_NoAlertBelowThreshold(t *testing.T) {
	engine := NewEngine(DefaultEngineConfig())

	var alertReceived bool
	var mu sync.Mutex

	engine.AddHandler(func(ctx context.Context, alert *Alert) error {
		mu.Lock()
		alertReceived = true
		mu.Unlock()
		return nil
	})

	rule := &Rule{
		ID:       "test-threshold",
		Name:     "Test Threshold",
		Type:     RuleTypeThreshold,
		Enabled:  true,
		Severity: 5,
		Conditions: Conditions{
			Match: []MatchCondition{
				{Field: "action", Operator: "eq", Value: "auth.failure"},
			},
		},
		Threshold: &ThresholdConfig{
			Count:    10,
			Operator: "gte",
		},
	}

	engine.AddRule(rule)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx)
	defer engine.Stop()

	// Send fewer events than threshold
	for i := 0; i < 3; i++ {
		event := &schema.Event{
			EventID:   uuid.New(),
			Timestamp: time.Now(),
			Action:    "auth.failure",
		}
		engine.ProcessEvent(event)
	}

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if alertReceived {
		t.Error("alert should not be generated below threshold")
	}
}

func TestEngine_GroupBy(t *testing.T) {
	engine := NewEngine(DefaultEngineConfig())

	alerts := make([]*Alert, 0)
	var mu sync.Mutex

	engine.AddHandler(func(ctx context.Context, alert *Alert) error {
		mu.Lock()
		alerts = append(alerts, alert)
		mu.Unlock()
		return nil
	})

	rule := &Rule{
		ID:       "test-grouped",
		Name:     "Grouped Threshold",
		Type:     RuleTypeThreshold,
		Enabled:  true,
		Severity: 5,
		Window:   1 * time.Minute,
		Conditions: Conditions{
			Match: []MatchCondition{
				{Field: "action", Operator: "eq", Value: "auth.failure"},
			},
		},
		GroupBy: []string{"actor.ip"},
		Threshold: &ThresholdConfig{
			Count:    2,
			Operator: "gte",
		},
	}

	engine.AddRule(rule)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx)
	defer engine.Stop()

	// Send events from two different IPs
	ips := []string{"192.168.1.1", "192.168.1.2"}
	for _, ip := range ips {
		for i := 0; i < 3; i++ {
			event := &schema.Event{
				EventID:   uuid.New(),
				Timestamp: time.Now(),
				Action:    "auth.failure",
				Actor:     &schema.Actor{IPAddress: ip},
			}
			engine.ProcessEvent(event)
			time.Sleep(5 * time.Millisecond)
		}
	}

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	// Should get alerts for both groups
	if len(alerts) < 2 {
		t.Errorf("expected at least 2 alerts (one per IP), got %d", len(alerts))
	}
}

func TestBuiltinRules(t *testing.T) {
	rules := BuiltinRules()

	if len(rules) == 0 {
		t.Error("expected builtin rules")
	}

	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			t.Errorf("builtin rule %s failed validation: %v", rule.ID, err)
		}
	}
}

func TestEngine_Stats(t *testing.T) {
	engine := NewEngine(DefaultEngineConfig())

	rule := &Rule{
		ID:       "test-stats",
		Name:     "Stats Test",
		Type:     RuleTypeThreshold,
		Enabled:  true,
		Severity: 5,
		Conditions: Conditions{
			Match: []MatchCondition{
				{Field: "action", Operator: "eq", Value: "test"},
			},
		},
		Threshold: &ThresholdConfig{Count: 5, Operator: "gte"},
	}

	engine.AddRule(rule)

	stats := engine.Stats()
	if stats["rules_count"].(int) != 1 {
		t.Errorf("expected 1 rule, got %v", stats["rules_count"])
	}
}

func BenchmarkEngine_ProcessEvent(b *testing.B) {
	engine := NewEngine(DefaultEngineConfig())

	rule := BruteForceRule()
	engine.AddRule(rule)

	ctx := context.Background()
	engine.Start(ctx)
	defer engine.Stop()

	event := &schema.Event{
		EventID:   uuid.New(),
		Timestamp: time.Now(),
		Action:    "auth.failure",
		Actor:     &schema.Actor{IPAddress: "192.168.1.100"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.ProcessEvent(event)
	}
}
