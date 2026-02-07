package correlation

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// RuleHandler provides HTTP handlers for rule management.
type RuleHandler struct {
	engine      *Engine
	customRules map[string]*Rule // custom rules keyed by ID
	rulesDir    string           // directory for persisted custom rules
	mu          sync.RWMutex
}

// NewRuleHandler creates a new rule handler.
func NewRuleHandler(engine *Engine, rulesDir string) *RuleHandler {
	return &RuleHandler{
		engine:      engine,
		customRules: make(map[string]*Rule),
		rulesDir:    rulesDir,
	}
}

// RegisterRoutes registers rule management routes on the given mux.
func (h *RuleHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/rules", h.HandleListRules)
	mux.HandleFunc("GET /v1/rules/{id}", h.HandleGetRule)
	mux.HandleFunc("POST /v1/rules", h.HandleCreateRule)
	mux.HandleFunc("PUT /v1/rules/{id}", h.HandleUpdateRule)
	mux.HandleFunc("DELETE /v1/rules/{id}", h.HandleDeleteRule)
	mux.HandleFunc("POST /v1/rules/{id}/test", h.HandleTestRule)
}

// LoadCustomRules loads custom rules from the rules directory.
func (h *RuleHandler) LoadCustomRules() error {
	if h.rulesDir == "" {
		return nil
	}

	entries, err := os.ReadDir(h.rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // directory doesn't exist yet
		}
		return err
	}

	loaded := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(h.rulesDir, entry.Name()))
		if err != nil {
			slog.Error("failed to read rule file", "file", entry.Name(), "error", err)
			continue
		}

		rule, err := ParseRule(data)
		if err != nil {
			slog.Error("failed to parse rule file", "file", entry.Name(), "error", err)
			continue
		}

		h.mu.Lock()
		h.customRules[rule.ID] = rule
		h.mu.Unlock()

		if err := h.engine.AddRule(rule); err != nil {
			slog.Error("failed to add custom rule", "rule_id", rule.ID, "error", err)
			continue
		}
		loaded++
	}

	slog.Info("loaded custom rules", "count", loaded, "dir", h.rulesDir)
	return nil
}

// HandleListRules handles GET /v1/rules requests.
func (h *RuleHandler) HandleListRules(w http.ResponseWriter, r *http.Request) {
	rules := h.engine.GetRules()

	q := r.URL.Query()
	filterType := q.Get("type")
	filterEnabled := q.Get("enabled")
	filterCategory := q.Get("category")

	h.mu.RLock()
	customIDs := make(map[string]bool, len(h.customRules))
	for id := range h.customRules {
		customIDs[id] = true
	}
	h.mu.RUnlock()

	type ruleResponse struct {
		*Rule
		Source string `json:"source"` // "builtin" or "custom"
	}

	var filtered []ruleResponse
	for _, rule := range rules {
		if filterType != "" && string(rule.Type) != filterType {
			continue
		}
		if filterEnabled == "true" && !rule.Enabled {
			continue
		}
		if filterEnabled == "false" && rule.Enabled {
			continue
		}
		if filterCategory != "" && rule.Category != filterCategory {
			continue
		}

		source := "builtin"
		if customIDs[rule.ID] {
			source = "custom"
		}
		filtered = append(filtered, ruleResponse{Rule: rule, Source: source})
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"rules": filtered,
		"total": len(filtered),
	})
}

// HandleGetRule handles GET /v1/rules/{id} requests.
func (h *RuleHandler) HandleGetRule(w http.ResponseWriter, r *http.Request) {
	ruleID := r.PathValue("id")

	rule, ok := h.engine.GetRule(ruleID)
	if !ok {
		h.writeError(w, http.StatusNotFound, "not_found", "rule not found")
		return
	}

	h.mu.RLock()
	_, isCustom := h.customRules[ruleID]
	h.mu.RUnlock()

	source := "builtin"
	if isCustom {
		source = "custom"
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"rule":   rule,
		"source": source,
	})
}

// HandleCreateRule handles POST /v1/rules requests.
func (h *RuleHandler) HandleCreateRule(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "read_error", "failed to read request body")
		return
	}

	// Try YAML first, then JSON
	rule, err := ParseRule(body)
	if err != nil {
		// Try as JSON
		var jsonRule Rule
		if jsonErr := json.Unmarshal(body, &jsonRule); jsonErr != nil {
			h.writeError(w, http.StatusBadRequest, "parse_error", err.Error())
			return
		}
		if valErr := jsonRule.Validate(); valErr != nil {
			h.writeError(w, http.StatusBadRequest, "validation_error", valErr.Error())
			return
		}
		rule = &jsonRule
	}

	// Check for ID collision with existing rules
	if _, exists := h.engine.GetRule(rule.ID); exists {
		h.writeError(w, http.StatusConflict, "duplicate_id", "a rule with this ID already exists")
		return
	}

	// Add to engine
	if err := h.engine.AddRule(rule); err != nil {
		h.writeError(w, http.StatusBadRequest, "add_error", err.Error())
		return
	}

	// Track as custom rule
	h.mu.Lock()
	h.customRules[rule.ID] = rule
	h.mu.Unlock()

	// Persist to disk
	h.persistRule(rule)

	h.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"rule":   rule,
		"source": "custom",
	})
}

// HandleUpdateRule handles PUT /v1/rules/{id} requests.
func (h *RuleHandler) HandleUpdateRule(w http.ResponseWriter, r *http.Request) {
	ruleID := r.PathValue("id")

	// Only custom rules can be updated
	h.mu.RLock()
	_, isCustom := h.customRules[ruleID]
	h.mu.RUnlock()

	if !isCustom {
		// Check if it's a builtin rule — allow toggling enabled state
		existingRule, exists := h.engine.GetRule(ruleID)
		if !exists {
			h.writeError(w, http.StatusNotFound, "not_found", "rule not found")
			return
		}

		var patch map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			h.writeError(w, http.StatusBadRequest, "parse_error", "failed to parse request body")
			return
		}

		// For builtin rules, only allow toggling 'enabled'
		if enabled, ok := patch["enabled"].(bool); ok {
			existingRule.Enabled = enabled
			h.writeJSON(w, http.StatusOK, map[string]interface{}{
				"rule":   existingRule,
				"source": "builtin",
			})
			return
		}

		h.writeError(w, http.StatusForbidden, "immutable", "builtin rules can only toggle enabled state")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "read_error", "failed to read request body")
		return
	}

	rule, err := ParseRule(body)
	if err != nil {
		var jsonRule Rule
		if jsonErr := json.Unmarshal(body, &jsonRule); jsonErr != nil {
			h.writeError(w, http.StatusBadRequest, "parse_error", err.Error())
			return
		}
		if valErr := jsonRule.Validate(); valErr != nil {
			h.writeError(w, http.StatusBadRequest, "validation_error", valErr.Error())
			return
		}
		rule = &jsonRule
	}

	// Force the ID to match the URL
	rule.ID = ruleID

	// Remove old rule and add updated one
	h.engine.RemoveRule(ruleID)
	if err := h.engine.AddRule(rule); err != nil {
		h.writeError(w, http.StatusBadRequest, "add_error", err.Error())
		return
	}

	h.mu.Lock()
	h.customRules[ruleID] = rule
	h.mu.Unlock()

	h.persistRule(rule)

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"rule":   rule,
		"source": "custom",
	})
}

// HandleDeleteRule handles DELETE /v1/rules/{id} requests.
func (h *RuleHandler) HandleDeleteRule(w http.ResponseWriter, r *http.Request) {
	ruleID := r.PathValue("id")

	h.mu.Lock()
	_, isCustom := h.customRules[ruleID]
	if !isCustom {
		h.mu.Unlock()
		h.writeError(w, http.StatusForbidden, "immutable", "builtin rules cannot be deleted")
		return
	}
	delete(h.customRules, ruleID)
	h.mu.Unlock()

	h.engine.RemoveRule(ruleID)

	// Remove from disk
	if h.rulesDir != "" {
		path := filepath.Join(h.rulesDir, ruleID+".yaml")
		os.Remove(path)
	}

	h.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// HandleTestRule handles POST /v1/rules/{id}/test requests.
// Returns info about whether the rule is valid and its current match state.
func (h *RuleHandler) HandleTestRule(w http.ResponseWriter, r *http.Request) {
	ruleID := r.PathValue("id")

	rule, ok := h.engine.GetRule(ruleID)
	if !ok {
		h.writeError(w, http.StatusNotFound, "not_found", "rule not found")
		return
	}

	result := map[string]interface{}{
		"rule_id":  rule.ID,
		"name":     rule.Name,
		"type":     rule.Type,
		"enabled":  rule.Enabled,
		"valid":    true,
		"severity": rule.Severity,
	}

	if err := rule.Validate(); err != nil {
		result["valid"] = false
		result["validation_error"] = err.Error()
	}

	h.writeJSON(w, http.StatusOK, result)
}

func (h *RuleHandler) persistRule(rule *Rule) {
	if h.rulesDir == "" {
		return
	}

	if err := os.MkdirAll(h.rulesDir, 0750); err != nil {
		slog.Error("failed to create rules directory", "error", err)
		return
	}

	data, err := yaml.Marshal(rule)
	if err != nil {
		slog.Error("failed to marshal rule", "rule_id", rule.ID, "error", err)
		return
	}

	path := filepath.Join(h.rulesDir, rule.ID+".yaml")
	if err := os.WriteFile(path, data, 0640); err != nil {
		slog.Error("failed to write rule file", "path", path, "error", err)
	}
}

func (h *RuleHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to write response", "error", err)
	}
}

func (h *RuleHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, map[string]string{
		"error": message,
		"code":  code,
	})
}
