package correlation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// computeContentHash returns a hex-encoded SHA256 hash of the rule content.
func computeContentHash(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}

// errUnsafeRuleID is returned when a rule ID cannot be used as a file name
// inside the rules directory.
var errUnsafeRuleID = errors.New("rule ID must be a single path element without path separators or '..'")

// validateRuleFileID checks that a custom rule ID can be used as a file name
// inside the rules directory. Custom rule IDs come from API request bodies and
// URLs, so they must not be able to escape the directory via path separators
// or dot segments, nor name a hidden file (which LoadCustomRules skips).
func validateRuleFileID(id string) error {
	if id == "" || strings.HasPrefix(id, ".") ||
		strings.ContainsAny(id, "/\\\x00") || filepath.Base(id) != id {
		return errUnsafeRuleID
	}
	return nil
}

// overridesFileName is the file in the rules directory that records the
// enabled state set through the API for rules not stored in that directory
// (the built-in rules). It is a hidden file so LoadCustomRules never parses
// it as a rule.
const overridesFileName = ".rule-overrides.json"

// RuleHandler provides HTTP handlers for rule management.
//
// Custom rules live in rulesDir: every rule loaded from a file there, or
// created through the API, is custom and can be edited and deleted; changes
// are written back to the file the rule came from. Other rules (built in)
// can only be enabled or disabled; that choice is kept in overridesFileName.
type RuleHandler struct {
	engine      *Engine
	customRules map[string]*Rule  // custom rules keyed by ID
	ruleFiles   map[string]string // custom rule ID -> name of the file in rulesDir holding it
	overrides   map[string]bool   // built-in rule ID -> enabled state set via the API
	rulesDir    string            // directory for persisted custom rules
	mu          sync.RWMutex
}

// NewRuleHandler creates a new rule handler.
func NewRuleHandler(engine *Engine, rulesDir string) *RuleHandler {
	return &RuleHandler{
		engine:      engine,
		customRules: make(map[string]*Rule),
		ruleFiles:   make(map[string]string),
		overrides:   make(map[string]bool),
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

// LoadCustomRules loads custom rules from the rules directory and applies the
// enabled state recorded for built-in rules. Call it after the built-in rules
// are registered with the engine.
//
// A .yaml/.yml file may hold several rules (a list or a multi-document
// stream); a .json file holds one rule object or an array of them. Hidden
// files are skipped.
func (h *RuleHandler) LoadCustomRules() error {
	if h.rulesDir == "" {
		return nil
	}

	root, err := os.OpenRoot(h.rulesDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // directory doesn't exist yet
		}
		return err
	}
	defer func() { _ = root.Close() }()

	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return err
	}

	loaded := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		ext := filepath.Ext(name)
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			continue
		}

		data, err := root.ReadFile(name)
		if err != nil {
			slog.Error("failed to read rule file", "file", name, "error", err)
			continue
		}

		rules, err := parseRuleFile(name, data)
		if err != nil {
			slog.Error("failed to parse rule file", "file", name, "error", err)
			continue
		}

		// Compute and verify content hash for tamper detection
		currentHash := computeContentHash(data)
		for _, rule := range rules {
			if rule.ContentHash != "" && rule.ContentHash != currentHash {
				slog.Warn("rule file content hash mismatch — possible tampering",
					"rule_id", rule.ID,
					"file", name,
					"expected_hash", rule.ContentHash,
					"actual_hash", currentHash,
				)
			}
			rule.ContentHash = currentHash

			if err := h.engine.AddRule(rule); err != nil {
				slog.Error("failed to add custom rule", "rule_id", rule.ID, "file", name, "error", err)
				continue
			}

			h.mu.Lock()
			if prev, dup := h.ruleFiles[rule.ID]; dup {
				slog.Warn("rule ID defined in more than one file; the later file wins",
					"rule_id", rule.ID, "file", name, "previous_file", prev)
			}
			h.customRules[rule.ID] = rule
			h.ruleFiles[rule.ID] = name
			h.mu.Unlock()
			loaded++
		}
	}

	h.applyOverrides(root)

	slog.Info("loaded custom rules", "count", loaded, "dir", h.rulesDir)
	return nil
}

// applyOverrides loads the recorded enabled state of built-in rules and
// applies it to the engine.
func (h *RuleHandler) applyOverrides(root *os.Root) {
	data, err := root.ReadFile(overridesFileName)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Error("failed to read rule overrides", "error", err)
		}
		return
	}
	var overrides map[string]bool
	if err := json.Unmarshal(data, &overrides); err != nil {
		slog.Error("failed to parse rule overrides", "file", overridesFileName, "error", err)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	for id, enabled := range overrides {
		h.overrides[id] = enabled
		if _, custom := h.customRules[id]; custom {
			continue // a custom rule's file records its own state
		}
		if _, ok := h.engine.SetRuleEnabled(id, enabled); ok {
			slog.Info("applied rule enabled override", "rule_id", id, "enabled", enabled)
		}
	}
}

// parseRuleFile parses the rules of a file in the rules directory.
func parseRuleFile(name string, data []byte) ([]*Rule, error) {
	if filepath.Ext(name) != ".json" {
		return ParseRules(data)
	}
	var rules []*Rule
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &rules); err != nil {
			return nil, err
		}
	} else {
		var rule Rule
		if err := json.Unmarshal(trimmed, &rule); err != nil {
			return nil, err
		}
		rules = []*Rule{&rule}
	}
	for i, rule := range rules {
		if rule == nil {
			return nil, fmt.Errorf("rule %d: empty rule", i)
		}
		if err := rule.Validate(); err != nil {
			return nil, fmt.Errorf("rule %d (%s): %w", i, rule.ID, err)
		}
	}
	return rules, nil
}

// ruleBodyError is a request body that could not be turned into a valid rule.
type ruleBodyError struct {
	code string // parse_error or validation_error
	err  error
}

func (e *ruleBodyError) Error() string { return e.err.Error() }

// decodeRuleBody parses a rule from an API request body: a JSON object in
// the dashboard's wire format, or a YAML rule document. If id is not empty it
// replaces the rule's ID. The rule is validated.
func decodeRuleBody(body []byte, id string) (*Rule, error) {
	var rule Rule
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		if err := json.Unmarshal(trimmed, &rule); err != nil {
			return nil, &ruleBodyError{code: "parse_error", err: err}
		}
	} else {
		docs, err := yamlDocuments(body)
		if err != nil {
			return nil, &ruleBodyError{code: "parse_error", err: err}
		}
		if len(docs) != 1 || docs[0].Kind != yaml.MappingNode {
			return nil, &ruleBodyError{code: "parse_error", err: errors.New("request body must hold exactly one rule")}
		}
		if err := docs[0].Decode(&rule); err != nil {
			return nil, &ruleBodyError{code: "parse_error", err: err}
		}
	}
	if id != "" {
		rule.ID = id
	}
	// Provenance is recorded by the server. The JSON wire format carries
	// these fields (GET returns them and the dashboard sends them back), but
	// a client must not be able to set them.
	rule.CreatedBy, rule.UpdatedBy = "", ""
	rule.CreatedAt, rule.UpdatedAt = time.Time{}, time.Time{}
	rule.ContentHash = ""
	if err := rule.Validate(); err != nil {
		return nil, &ruleBodyError{code: "validation_error", err: err}
	}
	return &rule, nil
}

func (h *RuleHandler) writeBodyError(w http.ResponseWriter, err error) {
	var bodyErr *ruleBodyError
	if errors.As(err, &bodyErr) {
		h.writeError(w, http.StatusBadRequest, bodyErr.code, bodyErr.Error())
		return
	}
	h.writeError(w, http.StatusBadRequest, "parse_error", err.Error())
}

// enabledPatch reports whether body is a JSON object carrying a boolean
// "enabled", and whether that is the only key (a pure toggle).
func enabledPatch(body []byte) (enabled, present, only bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(body), &fields); err != nil {
		return false, false, false
	}
	raw, ok := fields["enabled"]
	if !ok || json.Unmarshal(raw, &enabled) != nil {
		return false, false, false
	}
	return enabled, true, len(fields) == 1
}

func (h *RuleHandler) ruleSource(id string) string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if _, ok := h.customRules[id]; ok {
		return "custom"
	}
	return "builtin"
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

	filtered := make([]sourcedRule, 0, len(rules))
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
		filtered = append(filtered, withSource(rule, source))
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

	source := h.ruleSource(ruleID)
	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"rule":   withSource(rule, source),
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

	rule, err := decodeRuleBody(body, "")
	if err != nil {
		h.writeBodyError(w, err)
		return
	}

	// Custom rules are persisted as <id>.yaml, so the ID must be a safe file name.
	if err := validateRuleFileID(rule.ID); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}

	// Check for ID collision with existing rules
	if _, exists := h.engine.GetRule(rule.ID); exists {
		h.writeError(w, http.StatusConflict, "duplicate_id", "a rule with this ID already exists")
		return
	}

	// Set provenance metadata
	now := time.Now()
	rule.CreatedAt = now
	rule.UpdatedAt = now
	rule.ContentHash = computeContentHash(body)

	// Add to engine
	if err := h.engine.AddRule(rule); err != nil {
		h.writeError(w, http.StatusBadRequest, "add_error", err.Error())
		return
	}

	// Track as custom rule and persist to disk
	h.mu.Lock()
	h.customRules[rule.ID] = rule
	h.ruleFiles[rule.ID] = rule.ID + ".yaml"
	h.writeRuleFileLocked(h.ruleFiles[rule.ID])
	h.mu.Unlock()

	h.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"rule":   withSource(rule, "custom"),
		"source": "custom",
	})
}

// HandleUpdateRule handles PUT /v1/rules/{id} requests.
//
// A body of just {"enabled": true|false} enables or disables any rule. Other
// bodies replace a custom rule (JSON wire format or YAML); built-in rules
// only accept the enabled flag.
func (h *RuleHandler) HandleUpdateRule(w http.ResponseWriter, r *http.Request) {
	ruleID := r.PathValue("id")

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "read_error", "failed to read request body")
		return
	}
	enabled, hasEnabled, onlyEnabled := enabledPatch(body)

	h.mu.RLock()
	oldRule, isCustom := h.customRules[ruleID]
	h.mu.RUnlock()

	if !isCustom {
		if _, exists := h.engine.GetRule(ruleID); !exists {
			h.writeError(w, http.StatusNotFound, "not_found", "rule not found")
			return
		}
		// For builtin rules, only allow toggling 'enabled'
		if !hasEnabled {
			h.writeError(w, http.StatusForbidden, "immutable", "builtin rules can only toggle enabled state")
			return
		}
		updated, ok := h.engine.SetRuleEnabled(ruleID, enabled)
		if !ok {
			h.writeError(w, http.StatusNotFound, "not_found", "rule not found")
			return
		}
		h.mu.Lock()
		h.overrides[ruleID] = enabled
		h.saveOverridesLocked()
		h.mu.Unlock()
		h.writeJSON(w, http.StatusOK, map[string]interface{}{
			"rule":   withSource(updated, "builtin"),
			"source": "builtin",
		})
		return
	}

	var rule *Rule
	if onlyEnabled {
		updated, ok := h.engine.SetRuleEnabled(ruleID, enabled)
		if !ok {
			h.writeError(w, http.StatusNotFound, "not_found", "rule not found")
			return
		}
		rule = updated
	} else {
		// Force the ID to match the URL
		rule, err = decodeRuleBody(body, ruleID)
		if err != nil {
			h.writeBodyError(w, err)
			return
		}

		// Preserve original creation provenance, update modification metadata
		rule.CreatedBy = oldRule.CreatedBy
		rule.CreatedAt = oldRule.CreatedAt
		rule.UpdatedAt = time.Now()
		rule.ContentHash = computeContentHash(body)

		// Replace the rule (AddRule replaces a rule with the same ID)
		if err := h.engine.AddRule(rule); err != nil {
			h.writeError(w, http.StatusBadRequest, "add_error", err.Error())
			return
		}
	}

	h.mu.Lock()
	h.customRules[ruleID] = rule
	file, ok := h.ruleFiles[ruleID]
	if !ok {
		file = ruleID + ".yaml"
		h.ruleFiles[ruleID] = file
	}
	h.writeRuleFileLocked(file)
	h.mu.Unlock()

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"rule":   withSource(rule, "custom"),
		"source": "custom",
	})
}

// HandleDeleteRule handles DELETE /v1/rules/{id} requests.
func (h *RuleHandler) HandleDeleteRule(w http.ResponseWriter, r *http.Request) {
	ruleID := r.PathValue("id")

	h.mu.Lock()
	defer h.mu.Unlock()

	if _, isCustom := h.customRules[ruleID]; !isCustom {
		h.writeError(w, http.StatusForbidden, "immutable", "builtin rules cannot be deleted")
		return
	}
	file, ok := h.ruleFiles[ruleID]
	if !ok {
		file = ruleID + ".yaml"
	}
	delete(h.customRules, ruleID)
	delete(h.ruleFiles, ruleID)

	h.engine.RemoveRule(ruleID)

	// Remove the rule from the file it came from (and the file, once empty)
	h.writeRuleFileLocked(file)

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

// openRulesDir opens the rules directory, creating it first if needed. File
// access goes through the returned os.Root, so no file name can reach
// outside the directory.
func (h *RuleHandler) openRulesDir() (*os.Root, error) {
	if err := os.MkdirAll(h.rulesDir, 0750); err != nil {
		return nil, err
	}
	return os.OpenRoot(h.rulesDir)
}

// writeRuleFileLocked rewrites the file in rulesDir holding the custom rules
// mapped to it, or removes the file when none are left. The caller holds
// h.mu for writing.
func (h *RuleHandler) writeRuleFileLocked(file string) {
	if h.rulesDir == "" {
		return
	}
	// Names come from the directory listing or from IDs checked by
	// validateRuleFileID; hidden names are reserved (overridesFileName).
	if filepath.Base(file) != file || strings.HasPrefix(file, ".") {
		slog.Error("refusing to write rule file with unsafe name", "file", file)
		return
	}

	var rules []*Rule
	for id, f := range h.ruleFiles {
		if f == file {
			rules = append(rules, h.customRules[id])
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	var data []byte
	if len(rules) > 0 {
		var err error
		if data, err = encodeRuleFile(file, rules); err != nil {
			slog.Error("failed to marshal rules", "file", file, "error", err)
			return
		}
	}

	root, err := h.openRulesDir()
	if err != nil {
		slog.Error("failed to open rules directory", "dir", h.rulesDir, "error", err)
		return
	}
	defer func() { _ = root.Close() }()

	if len(rules) == 0 {
		if err := root.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Error("failed to remove rule file", "file", file, "error", err)
		}
		return
	}
	if err := root.WriteFile(file, data, 0600); err != nil {
		slog.Error("failed to write rule file", "file", file, "error", err)
	}
}

// encodeRuleFile renders rules in the format of the file they belong to:
// JSON for .json files, otherwise YAML (one document per rule).
func encodeRuleFile(name string, rules []*Rule) ([]byte, error) {
	if filepath.Ext(name) == ".json" {
		// ContentHash is the hash of what the rule was loaded from. Written
		// into the file it could never match the file's own hash, and
		// LoadCustomRules would report every rewritten file as tampered
		// with. (YAML files never carry it.)
		stored := make([]*Rule, len(rules))
		for i, rule := range rules {
			c := *rule
			c.ContentHash = ""
			stored[i] = &c
		}
		if len(stored) == 1 {
			return json.MarshalIndent(stored[0], "", "  ")
		}
		return json.MarshalIndent(stored, "", "  ")
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	for _, rule := range rules {
		if err := enc.Encode(rule); err != nil {
			return nil, err
		}
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// saveOverridesLocked persists the built-in rule enabled overrides. The
// caller holds h.mu for writing.
func (h *RuleHandler) saveOverridesLocked() {
	if h.rulesDir == "" {
		return
	}
	data, err := json.MarshalIndent(h.overrides, "", "  ")
	if err != nil {
		slog.Error("failed to marshal rule overrides", "error", err)
		return
	}
	root, err := h.openRulesDir()
	if err != nil {
		slog.Error("failed to open rules directory", "dir", h.rulesDir, "error", err)
		return
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile(overridesFileName, data, 0600); err != nil {
		slog.Error("failed to write rule overrides", "file", overridesFileName, "error", err)
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
