package correlation

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestComputeContentHash(t *testing.T) {
	content := []byte(`id: test-rule
name: Test Rule
type: threshold`)

	hash1 := computeContentHash(content)
	hash2 := computeContentHash(content)

	if hash1 != hash2 {
		t.Error("identical content should produce identical hash")
	}
	if len(hash1) != 64 {
		t.Errorf("expected 64-char hex SHA256, got %d chars", len(hash1))
	}

	// Different content should produce different hash
	hash3 := computeContentHash([]byte(`id: different-rule`))
	if hash1 == hash3 {
		t.Error("different content should produce different hash")
	}
}

func TestRuleProvenanceOnCreate(t *testing.T) {
	engine := NewEngine(DefaultEngineConfig())
	dir := t.TempDir()
	handler := NewRuleHandler(engine, dir)

	body := `{
		"id": "provenance-test-001",
		"name": "Provenance Test",
		"type": "threshold",
		"enabled": true,
		"severity": 3,
		"conditions": {"match": [{"field": "action", "operator": "eq", "value": "test"}]},
		"window": "5m",
		"threshold": {"count": 5, "operator": "gte"}
	}`

	req := httptest.NewRequest("POST", "/v1/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleCreateRule(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]json.RawMessage
	json.Unmarshal(w.Body.Bytes(), &resp)

	var rule Rule
	json.Unmarshal(resp["rule"], &rule)

	if rule.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set on rule creation")
	}
	if rule.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set on rule creation")
	}
	if rule.ContentHash == "" {
		t.Error("ContentHash should be set on rule creation")
	}
	if len(rule.ContentHash) != 64 {
		t.Errorf("ContentHash should be 64-char hex, got %d chars", len(rule.ContentHash))
	}
}

func TestLoadCustomRulesHashTamperWarning(t *testing.T) {
	engine := NewEngine(DefaultEngineConfig())
	dir := t.TempDir()
	handler := NewRuleHandler(engine, dir)

	// Write a rule file to disk
	ruleContent := `id: tamper-test-001
name: Tamper Test
type: threshold
enabled: true
severity: 3
conditions:
  match:
    - field: action
      operator: eq
      value: test
window: 5m
threshold:
  count: 5
  operator: gte
`
	err := os.WriteFile(filepath.Join(dir, "tamper-test.yaml"), []byte(ruleContent), 0640)
	if err != nil {
		t.Fatalf("failed to write rule file: %v", err)
	}

	// Loading should succeed and set the content hash
	err = handler.LoadCustomRules()
	if err != nil {
		t.Fatalf("LoadCustomRules failed: %v", err)
	}

	handler.mu.RLock()
	rule, ok := handler.customRules["tamper-test-001"]
	handler.mu.RUnlock()

	if !ok {
		t.Fatal("rule tamper-test-001 not loaded")
	}
	if rule.ContentHash == "" {
		t.Error("ContentHash should be computed on load")
	}

	expectedHash := computeContentHash([]byte(ruleContent))
	if rule.ContentHash != expectedHash {
		t.Errorf("ContentHash mismatch: got %s, want %s", rule.ContentHash, expectedHash)
	}
}
