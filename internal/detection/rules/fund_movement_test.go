package rules

import (
	"context"
	"sync"
	"testing"
	"time"

	"boundary-siem/internal/correlation"
	"boundary-siem/internal/schema"
)

// E2E round 2: one transfer of 1500 ETH raised two alerts with conflicting
// severities, "Large ETH Transfer" (tx-001, medium) and "EVM High-Value
// Token Transfer" (community-evm-high-value-transfer, high), for the same
// sender. Each large transfer raises one high alert now.
func TestOneAlertPerLargeTransfer(t *testing.T) {
	transferRules := map[string]bool{"tx-001": true, "community-evm-high-value-transfer": true}

	var mu sync.Mutex
	byGroup := make(map[string][]*correlation.Alert)
	e := wireLikeSiemIngest(t, func(a *correlation.Alert) {
		if !transferRules[a.RuleID] {
			return
		}
		mu.Lock()
		byGroup[a.GroupKey] = append(byGroup[a.GroupKey], a)
		mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Start(ctx)
	defer e.Stop()

	transfers := []struct {
		from     string
		valueETH float64
		wantRule string // "" = no alert
	}{
		{"0xsmall", 300, ""},
		{"0xmid", 700, "community-evm-high-value-transfer"},
		{"0xedge", 1000, "tx-001"},
		{"0xlarge", 1500, "tx-001"},
	}
	for _, tr := range transfers {
		e.ProcessEvent(event("evm.transaction", schema.OutcomeSuccess, map[string]any{"value_eth": tr.valueETH, "from": tr.from}))
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(byGroup)
		mu.Unlock()
		if n >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // a duplicate would arrive with the first

	mu.Lock()
	defer mu.Unlock()
	for _, tr := range transfers {
		got := byGroup["[metadata.from="+tr.from+"]"]
		if tr.wantRule == "" {
			if len(got) != 0 {
				t.Errorf("%v ETH raised %d alert(s), want none", tr.valueETH, len(got))
			}
			continue
		}
		if len(got) != 1 {
			ids := make([]string, len(got))
			for i, a := range got {
				ids[i] = a.RuleID
			}
			t.Errorf("%v ETH raised alerts %v, want only %s", tr.valueETH, ids, tr.wantRule)
			continue
		}
		if got[0].RuleID != tr.wantRule {
			t.Errorf("%v ETH raised %s, want %s", tr.valueETH, got[0].RuleID, tr.wantRule)
		}
		if sev := correlation.IntToSeverity(got[0].Severity); sev != correlation.SeverityHigh {
			t.Errorf("%v ETH alert severity = %s, want high", tr.valueETH, sev)
		}
	}
}
