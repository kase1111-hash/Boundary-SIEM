package correlation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func contractTestRule() *Rule {
	return &Rule{
		ID:          "det-001",
		Name:        "Key Export Attempt",
		Description: "Attempt to export cryptographic key",
		Type:        RuleTypeThreshold,
		Enabled:     true,
		Severity:    10,
		Category:    "Key Management",
		Tags:        []string{"key", "export"},
		MITRE:       &MITREMapping{TacticID: "TA0006", TacticName: "Credential Access", TechniqueID: "T1552"},
		EventConditions: []Condition{
			{Field: "action", Operator: "eq", Value: "key.export"},
		},
		GroupBy:   []string{"target"},
		Window:    5 * time.Minute,
		Threshold: &ThresholdConfig{Count: 1, Operator: "gte"},
	}
}

func serveRules(h *RuleHandler, method, path, body string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// Regression (R09): the rules API serialised Rule with Go field names
// ("ID", "Window" in nanoseconds), so the dashboard rendered blank rows.
// The JSON must follow web/src/types/api.ts (Rule).
func TestHandleListRules_MatchesDashboardContract(t *testing.T) {
	engine := NewEngine(DefaultEngineConfig())
	mustAddRule(t, engine, contractTestRule())
	h := NewRuleHandler(engine, t.TempDir())

	w := serveRules(h, http.MethodGet, "/v1/rules", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /v1/rules = %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Rules []map[string]any `json:"rules"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 1 || len(resp.Rules) != 1 {
		t.Fatalf("total=%d rules=%d, want 1", resp.Total, len(resp.Rules))
	}
	got := resp.Rules[0]

	checks := []struct {
		key  string
		want any
	}{
		{"id", "det-001"},
		{"name", "Key Export Attempt"},
		{"description", "Attempt to export cryptographic key"},
		{"type", "threshold"},
		{"enabled", true},
		{"severity", float64(10)},
		{"category", "Key Management"},
		{"window", "5m"},
		{"source", "builtin"},
	}
	for _, c := range checks {
		if got[c.key] != c.want {
			t.Errorf("rule[%q] = %#v, want %#v", c.key, got[c.key], c.want)
		}
	}
	for _, goName := range []string{"ID", "Name", "Type", "Enabled", "Window", "Severity"} {
		if _, ok := got[goName]; ok {
			t.Errorf("rule JSON contains Go field name %q", goName)
		}
	}
	threshold, _ := got["threshold"].(map[string]any)
	if threshold["count"] != float64(1) {
		t.Errorf("threshold = %#v, want count 1", got["threshold"])
	}
	mitre, _ := got["mitre"].(map[string]any)
	if mitre["tactic_id"] != "TA0006" || mitre["technique_id"] != "T1552" {
		t.Errorf("mitre = %#v, want snake_case tactic_id/technique_id", got["mitre"])
	}
	if _, ok := mitre["technique_name"]; !ok {
		t.Errorf("mitre = %#v, want technique_name key (MITREMapping in api.ts)", got["mitre"])
	}
}

// The dashboard editor sends the api.ts shape (window as a duration string)
// on POST, and sends back what GET returned on PUT.
func TestRuleAPI_RoundTripDashboardShape(t *testing.T) {
	engine := NewEngine(DefaultEngineConfig())
	h := NewRuleHandler(engine, t.TempDir())

	create := `{
		"id": "custom-001",
		"name": "Custom",
		"description": "made in the dashboard",
		"type": "threshold",
		"enabled": true,
		"severity": 5,
		"category": "Custom",
		"conditions": {"match": [{"field": "action", "operator": "eq", "value": "auth.failure"}]},
		"window": "5m",
		"threshold": {"count": 10}
	}`
	w := serveRules(h, http.MethodPost, "/v1/rules", create)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST = %d: %s", w.Code, w.Body.String())
	}
	if r, ok := engine.GetRule("custom-001"); !ok || r.Window != 5*time.Minute {
		t.Fatalf("created rule window = %v, want 5m", r)
	}

	w = serveRules(h, http.MethodGet, "/v1/rules/custom-001", "")
	var got struct {
		Rule   json.RawMessage `json:"rule"`
		Source string          `json:"source"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if got.Source != "custom" {
		t.Errorf("source = %q, want custom", got.Source)
	}

	// PUT back exactly what GET returned.
	w = serveRules(h, http.MethodPut, "/v1/rules/custom-001", string(got.Rule))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT of GET body = %d: %s", w.Code, w.Body.String())
	}
	r, _ := engine.GetRule("custom-001")
	if r.Window != 5*time.Minute || r.Threshold == nil || r.Threshold.Count != 10 ||
		len(r.Conditions.Match) != 1 || r.Category != "Custom" {
		t.Errorf("rule changed by GET/PUT round trip: %+v", r)
	}
}

// Regression: the dashboard toggles rules with PUT {"enabled": false}, which
// failed with 400 for custom rules because the body was parsed as a full rule.
func TestRuleAPI_ToggleCustomRule(t *testing.T) {
	dir := t.TempDir()
	engine := NewEngine(DefaultEngineConfig())
	h := NewRuleHandler(engine, dir)

	body := `{"id":"toggle-001","name":"Toggle","type":"threshold","enabled":true,"severity":5,
		"conditions":{"match":[{"field":"action","operator":"eq","value":"x.y"}]},
		"window":"1m","threshold":{"count":1}}`
	if w := serveRules(h, http.MethodPost, "/v1/rules", body); w.Code != http.StatusCreated {
		t.Fatalf("POST = %d: %s", w.Code, w.Body.String())
	}

	w := serveRules(h, http.MethodPut, "/v1/rules/toggle-001", `{"enabled": false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT {enabled:false} = %d: %s", w.Code, w.Body.String())
	}
	if r, _ := engine.GetRule("toggle-001"); r.Enabled {
		t.Error("custom rule still enabled after toggle")
	}

	// The toggle is persisted.
	engine2 := NewEngine(DefaultEngineConfig())
	if err := NewRuleHandler(engine2, dir).LoadCustomRules(); err != nil {
		t.Fatal(err)
	}
	if r, ok := engine2.GetRule("toggle-001"); !ok || r.Enabled {
		t.Errorf("after reload rule = %+v, want disabled", r)
	}
}

// Regression (H36): toggling a builtin rule wrote rule.Enabled on the shared
// *Rule without a lock while workers read it (go test -race), and the toggle
// was lost on restart.
func TestRuleAPI_ToggleBuiltinRuleNoRaceAndPersists(t *testing.T) {
	dir := t.TempDir()
	engine := NewEngine(DefaultEngineConfig())
	mustAddRule(t, engine, contractTestRule())
	h := NewRuleHandler(engine, dir)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			engine.processEvent(ctx, testEvent("key.export"))
			drainAlerts(engine)
			for _, r := range engine.GetRules() {
				_ = r.Enabled
			}
		}
	}()
	for i := 0; i < 50; i++ {
		enabled := i%2 == 1
		w := serveRules(h, http.MethodPut, "/v1/rules/det-001", `{"enabled": `+map[bool]string{true: "true", false: "false"}[enabled]+`}`)
		if w.Code != http.StatusOK {
			t.Fatalf("toggle = %d: %s", w.Code, w.Body.String())
		}
	}
	cancel()
	wg.Wait()

	if w := serveRules(h, http.MethodPut, "/v1/rules/det-001", `{"enabled": false}`); w.Code != http.StatusOK {
		t.Fatalf("toggle = %d: %s", w.Code, w.Body.String())
	}
	if r, _ := engine.GetRule("det-001"); r.Enabled {
		t.Fatal("builtin rule still enabled after toggle")
	}

	// Restart: builtin rules are registered again, then custom state is loaded.
	engine2 := NewEngine(DefaultEngineConfig())
	mustAddRule(t, engine2, contractTestRule())
	if err := NewRuleHandler(engine2, dir).LoadCustomRules(); err != nil {
		t.Fatal(err)
	}
	if r, _ := engine2.GetRule("det-001"); r.Enabled {
		t.Error("builtin rule toggle was not persisted across restart")
	}
}

const fileLoadedRule = `id: community-evm-contract-deploy-surge
name: "Rapid Contract Deployment Surge"
type: threshold
enabled: true
severity: 7
conditions:
  match:
    - field: action
      operator: eq
      value: "evm.contract.created"
threshold:
  count: 10
  operator: gte
window: 15m
group_by:
  - actor.id
`

// Regression (R17): deleting a rule loaded from a file whose name differs from
// the rule ID reported success but left the file, so the rule came back.
func TestRuleAPI_DeleteFileLoadedRuleRemovesItsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evm_contract_deploy_surge.yaml")
	if err := os.WriteFile(path, []byte(fileLoadedRule), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(DefaultEngineConfig())
	h := NewRuleHandler(engine, dir)
	if err := h.LoadCustomRules(); err != nil {
		t.Fatal(err)
	}

	w := serveRules(h, http.MethodDelete, "/v1/rules/community-evm-contract-deploy-surge", "")
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE = %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("rule file still present after delete (stat err: %v)", err)
	}

	engine2 := NewEngine(DefaultEngineConfig())
	if err := NewRuleHandler(engine2, dir).LoadCustomRules(); err != nil {
		t.Fatal(err)
	}
	if _, ok := engine2.GetRule("community-evm-contract-deploy-surge"); ok {
		t.Error("deleted rule is back after restart")
	}
}

// Updating a file-loaded rule rewrites its own file instead of adding a
// second <id>.yaml that would load the same ID twice.
func TestRuleAPI_UpdateFileLoadedRuleRewritesItsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evm_contract_deploy_surge.yaml")
	if err := os.WriteFile(path, []byte(fileLoadedRule), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(DefaultEngineConfig())
	h := NewRuleHandler(engine, dir)
	if err := h.LoadCustomRules(); err != nil {
		t.Fatal(err)
	}

	updated := strings.Replace(fileLoadedRule, "count: 10", "count: 25", 1)
	w := serveRules(h, http.MethodPut, "/v1/rules/community-evm-contract-deploy-surge", updated)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", w.Code, w.Body.String())
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	if len(names) != 1 || names[0] != "evm_contract_deploy_surge.yaml" {
		t.Errorf("rules dir = %v, want only evm_contract_deploy_surge.yaml", names)
	}

	engine2 := NewEngine(DefaultEngineConfig())
	if err := NewRuleHandler(engine2, dir).LoadCustomRules(); err != nil {
		t.Fatal(err)
	}
	if r, ok := engine2.GetRule("community-evm-contract-deploy-surge"); !ok || r.Threshold.Count != 25 {
		t.Errorf("reloaded rule = %+v, want threshold count 25", r)
	}
}

// A file holding several rules keeps the others when one is deleted.
func TestRuleAPI_DeleteOneRuleOfMultiRuleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pair.yaml")
	if err := os.WriteFile(path, []byte(twoRuleStream), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(DefaultEngineConfig())
	h := NewRuleHandler(engine, dir)
	if err := h.LoadCustomRules(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"multi-1", "multi-2"} {
		if _, ok := engine.GetRule(id); !ok {
			t.Fatalf("rule %s from a two-document file was not loaded", id)
		}
	}

	if w := serveRules(h, http.MethodDelete, "/v1/rules/multi-1", ""); w.Code != http.StatusOK {
		t.Fatalf("DELETE = %d: %s", w.Code, w.Body.String())
	}

	engine2 := NewEngine(DefaultEngineConfig())
	if err := NewRuleHandler(engine2, dir).LoadCustomRules(); err != nil {
		t.Fatal(err)
	}
	if _, ok := engine2.GetRule("multi-1"); ok {
		t.Error("deleted rule multi-1 is back after reload")
	}
	if _, ok := engine2.GetRule("multi-2"); !ok {
		t.Error("rule multi-2 was lost when multi-1 was deleted from the same file")
	}
}

func TestRuleAPI_RejectsInvalidBodies(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantCode string
	}{
		{"two YAML documents", twoRuleStream, "parse_error"},
		{"malformed JSON", `{"id": `, "parse_error"},
		{"window as bare number", `{"id":"n","name":"n","type":"threshold","severity":5,"window":300,"threshold":{"count":1},"conditions":{"match":[{"field":"action","operator":"eq","value":"x"}]}}`, "parse_error"},
		{"dashboard template without conditions", `{"id":"t","name":"t","description":"","type":"threshold","enabled":true,"severity":5,"category":"","conditions":{"match":[]},"window":"5m","threshold":{"count":10}}`, "validation_error"},
		{"unknown operator", `{"id":"o","name":"o","type":"threshold","severity":5,"window":"5m","threshold":{"count":1},"conditions":{"match":[{"field":"action","operator":"equalz","value":"x"}]}}`, "validation_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewRuleHandler(NewEngine(DefaultEngineConfig()), t.TempDir())
			w := serveRules(h, http.MethodPost, "/v1/rules", tt.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("POST = %d, want 400: %s", w.Code, w.Body.String())
			}
			var resp map[string]string
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if resp["code"] != tt.wantCode {
				t.Errorf("code = %q, want %q (%s)", resp["code"], tt.wantCode, resp["error"])
			}
		})
	}
}

// Builtin rules still refuse edits other than the enabled flag.
func TestRuleAPI_BuiltinRuleIsImmutable(t *testing.T) {
	engine := NewEngine(DefaultEngineConfig())
	mustAddRule(t, engine, contractTestRule())
	h := NewRuleHandler(engine, t.TempDir())

	if w := serveRules(h, http.MethodPut, "/v1/rules/det-001", `{"severity": 1}`); w.Code != http.StatusForbidden {
		t.Errorf("PUT severity on builtin = %d, want 403", w.Code)
	}
	if w := serveRules(h, http.MethodDelete, "/v1/rules/det-001", ""); w.Code != http.StatusForbidden {
		t.Errorf("DELETE builtin = %d, want 403", w.Code)
	}
	if w := serveRules(h, http.MethodPut, "/v1/rules/nope", `{"enabled": false}`); w.Code != http.StatusNotFound {
		t.Errorf("PUT unknown rule = %d, want 404", w.Code)
	}
}
