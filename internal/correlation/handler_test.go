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
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	var rule Rule
	if err := json.Unmarshal(resp["rule"], &rule); err != nil {
		t.Fatalf("failed to decode rule: %v", err)
	}

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

func TestValidateRuleFileID(t *testing.T) {
	valid := []string{"provenance-test-001", "community-brute-force-login", "T1110.004", "rule..v2"}
	for _, id := range valid {
		if err := validateRuleFileID(id); err != nil {
			t.Errorf("validateRuleFileID(%q) returned error: %v", id, err)
		}
	}

	invalid := []string{"", ".", "..", "../escape", "../../etc/cron.d/x", "a/b", "/abs", `..\escape`, "nul\x00byte"}
	for _, id := range invalid {
		if err := validateRuleFileID(id); err == nil {
			t.Errorf("validateRuleFileID(%q) = nil, want error", id)
		}
	}
}

func TestCreateRuleRejectsPathTraversalID(t *testing.T) {
	engine := NewEngine(DefaultEngineConfig())
	base := t.TempDir()
	dir := filepath.Join(base, "rules")
	handler := NewRuleHandler(engine, dir)

	body := `{
		"id": "../escaped",
		"name": "Traversal Test",
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

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if _, ok := engine.GetRule("../escaped"); ok {
		t.Error("rule with unsafe ID should not be added to the engine")
	}
	if _, err := os.Stat(filepath.Join(base, "escaped.yaml")); !os.IsNotExist(err) {
		t.Errorf("rule file must not be written outside the rules directory (stat err: %v)", err)
	}
}

func TestPersistedRuleFilePermissions(t *testing.T) {
	engine := NewEngine(DefaultEngineConfig())
	dir := t.TempDir()
	handler := NewRuleHandler(engine, dir)

	body := `{
		"id": "perm-test-001",
		"name": "Permission Test",
		"type": "threshold",
		"enabled": true,
		"severity": 3,
		"conditions": {"match": [{"field": "action", "operator": "eq", "value": "test"}]},
		"window": "5m",
		"threshold": {"count": 5, "operator": "gte"}
	}`

	req := httptest.NewRequest("POST", "/v1/rules", strings.NewReader(body))
	w := httptest.NewRecorder()
	handler.HandleCreateRule(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	info, err := os.Stat(filepath.Join(dir, "perm-test-001.yaml"))
	if err != nil {
		t.Fatalf("persisted rule file missing: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("rule file permissions = %o, want no group/other access", perm)
	}

	// Deleting the rule removes its file from disk.
	delReq := httptest.NewRequest("DELETE", "/v1/rules/perm-test-001", nil)
	delReq.SetPathValue("id", "perm-test-001")
	delW := httptest.NewRecorder()
	handler.HandleDeleteRule(delW, delReq)
	if delW.Code != http.StatusOK {
		t.Fatalf("expected 200 on delete, got %d: %s", delW.Code, delW.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "perm-test-001.yaml")); !os.IsNotExist(err) {
		t.Errorf("rule file should be removed on delete (stat err: %v)", err)
	}
}
