package advanced

import (
	"context"
	"testing"
	"time"

	"boundary-siem/internal/advanced/forensics"
	"boundary-siem/internal/advanced/hunting"
	"boundary-siem/internal/advanced/soar"
)

// ============================================================================
// Threat Hunting Workbench Tests
// ============================================================================

func TestHuntingWorkbenchCreation(t *testing.T) {
	cfg := hunting.Config{
		MaxConcurrentQueries: 5,
		QueryTimeout:         30 * time.Second,
		ResultsLimit:         1000,
		EnableCaching:        true,
	}

	wb := hunting.NewWorkbench(cfg, nil)
	if wb == nil {
		t.Fatal("expected workbench to be created")
	}

	// Check built-in templates loaded
	templateCount := wb.GetTemplateCount()
	if templateCount != 10 {
		t.Errorf("expected 10 built-in templates, got %d", templateCount)
	}
}

func TestHuntingTemplates(t *testing.T) {
	wb := hunting.NewWorkbench(hunting.Config{}, nil)
	ctx := context.Background()

	templates := wb.ListTemplates(ctx, "")
	if len(templates) == 0 {
		t.Fatal("expected templates to be loaded")
	}

	// Check template categories
	categories := make(map[string]int)
	for _, tmpl := range templates {
		categories[tmpl.Category]++
	}

	expectedCategories := []string{
		"DeFi Security",
		"Validator Security",
		"Wallet Analysis",
		"Smart Contract Security",
		"Bridge Security",
		"Transaction Analysis",
		"MEV Analysis",
		"Governance Security",
		"NFT Security",
	}

	for _, cat := range expectedCategories {
		if categories[cat] == 0 {
			t.Errorf("expected category %s to have templates", cat)
		}
	}
}

func TestHuntCreation(t *testing.T) {
	wb := hunting.NewWorkbench(hunting.Config{}, nil)
	ctx := context.Background()

	hunt := &hunting.Hunt{
		Name:        "Test Hunt",
		Description: "Testing hunt creation",
		Type:        hunting.HuntTypeTransaction,
		Hypothesis:  "Test hypothesis",
		CreatedBy:   "analyst@test.com",
	}

	err := wb.CreateHunt(ctx, hunt)
	if err != nil {
		t.Fatalf("failed to create hunt: %v", err)
	}

	if hunt.ID == "" {
		t.Error("expected hunt ID to be set")
	}

	if hunt.Status != hunting.HuntStatusDraft {
		t.Errorf("expected status draft, got %s", hunt.Status)
	}

	// Retrieve hunt
	retrieved, err := wb.GetHunt(ctx, hunt.ID)
	if err != nil {
		t.Fatalf("failed to get hunt: %v", err)
	}

	if retrieved.Name != hunt.Name {
		t.Errorf("expected name %s, got %s", hunt.Name, retrieved.Name)
	}
}

func TestHuntFromTemplate(t *testing.T) {
	wb := hunting.NewWorkbench(hunting.Config{}, nil)
	ctx := context.Background()

	// Create hunt from template
	hunt, err := wb.CreateHuntFromTemplate(ctx, "tmpl-001", "Flash Loan Investigation", "analyst@test.com")
	if err != nil {
		t.Fatalf("failed to create hunt from template: %v", err)
	}

	if len(hunt.Queries) == 0 {
		t.Error("expected queries to be copied from template")
	}

	if hunt.Hypothesis == "" {
		t.Error("expected hypothesis to be copied from template")
	}
}

func TestHuntLifecycle(t *testing.T) {
	wb := hunting.NewWorkbench(hunting.Config{}, nil)
	ctx := context.Background()

	hunt := &hunting.Hunt{
		Name:       "Lifecycle Test Hunt",
		Type:       hunting.HuntTypeWallet,
		Hypothesis: "Test lifecycle",
		CreatedBy:  "analyst@test.com",
	}

	_ = wb.CreateHunt(ctx, hunt)

	// Start hunt
	err := wb.StartHunt(ctx, hunt.ID)
	if err != nil {
		t.Fatalf("failed to start hunt: %v", err)
	}

	retrieved, _ := wb.GetHunt(ctx, hunt.ID)
	if retrieved.Status != hunting.HuntStatusActive {
		t.Errorf("expected status active, got %s", retrieved.Status)
	}

	if retrieved.StartedAt == nil {
		t.Error("expected started_at to be set")
	}

	// Add finding
	finding := &hunting.Finding{
		Title:       "Suspicious Wallet",
		Description: "Found suspicious wallet activity",
		Severity:    "high",
		Confidence:  0.85,
	}

	err = wb.AddFinding(ctx, hunt.ID, finding)
	if err != nil {
		t.Fatalf("failed to add finding: %v", err)
	}

	// Complete hunt
	err = wb.CompleteHunt(ctx, hunt.ID)
	if err != nil {
		t.Fatalf("failed to complete hunt: %v", err)
	}

	retrieved, _ = wb.GetHunt(ctx, hunt.ID)
	if retrieved.Status != hunting.HuntStatusCompleted {
		t.Errorf("expected status completed, got %s", retrieved.Status)
	}

	if len(retrieved.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(retrieved.Findings))
	}
}

func TestHuntTypes(t *testing.T) {
	types := []hunting.HuntType{
		hunting.HuntTypeHypothesis,
		hunting.HuntTypeIOC,
		hunting.HuntTypeAnomaly,
		hunting.HuntTypeBehavioral,
		hunting.HuntTypeTransaction,
		hunting.HuntTypeWallet,
		hunting.HuntTypeSmartContract,
	}

	if len(types) != 7 {
		t.Errorf("expected 7 hunt types, got %d", len(types))
	}
}

func TestQueryTypes(t *testing.T) {
	types := []hunting.QueryType{
		hunting.QueryTypeSQL,
		hunting.QueryTypeKQL,
		hunting.QueryTypeLucene,
		hunting.QueryTypeYARA,
		hunting.QueryTypeSigma,
		hunting.QueryTypeCustom,
	}

	if len(types) != 6 {
		t.Errorf("expected 6 query types, got %d", len(types))
	}
}

func TestHuntExport(t *testing.T) {
	wb := hunting.NewWorkbench(hunting.Config{}, nil)
	ctx := context.Background()

	hunt := &hunting.Hunt{
		Name:       "Export Test",
		Type:       hunting.HuntTypeIOC,
		Hypothesis: "Test export",
		CreatedBy:  "analyst@test.com",
	}

	_ = wb.CreateHunt(ctx, hunt)

	data, err := wb.ExportHunt(ctx, hunt.ID)
	if err != nil {
		t.Fatalf("failed to export hunt: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected export data")
	}
}

// ============================================================================
// Forensics Toolkit Tests
// ============================================================================

func TestForensicsToolkitCreation(t *testing.T) {
	cfg := forensics.Config{
		MaxConcurrentAnalyses: 3,
		TraceDepth:           10,
		ClusterMinConfidence: 0.7,
	}

	toolkit := forensics.NewToolkit(cfg, nil)
	if toolkit == nil {
		t.Fatal("expected toolkit to be created")
	}
}

func TestCaseCreation(t *testing.T) {
	toolkit := forensics.NewToolkit(forensics.Config{}, nil)
	ctx := context.Background()

	c := &forensics.Case{
		Title:       "Flash Loan Exploit Investigation",
		Description: "Investigation of flash loan attack",
		Priority:    forensics.CasePriorityCritical,
		AssignedTo:  "analyst@test.com",
		CreatedBy:   "manager@test.com",
		Tags:        []string{"flash-loan", "defi"},
	}

	err := toolkit.CreateCase(ctx, c)
	if err != nil {
		t.Fatalf("failed to create case: %v", err)
	}

	if c.ID == "" {
		t.Error("expected case ID to be set")
	}

	if c.Status != forensics.CaseStatusOpen {
		t.Errorf("expected status open, got %s", c.Status)
	}
}

func TestCaseLifecycle(t *testing.T) {
	toolkit := forensics.NewToolkit(forensics.Config{}, nil)
	ctx := context.Background()

	c := &forensics.Case{
		Title:    "Lifecycle Test Case",
		Priority: forensics.CasePriorityHigh,
	}

	_ = toolkit.CreateCase(ctx, c)

	// Update status
	err := toolkit.UpdateCaseStatus(ctx, c.ID, forensics.CaseStatusInProgress)
	if err != nil {
		t.Fatalf("failed to update status: %v", err)
	}

	retrieved, _ := toolkit.GetCase(ctx, c.ID)
	if retrieved.Status != forensics.CaseStatusInProgress {
		t.Errorf("expected status in_progress, got %s", retrieved.Status)
	}

	// Close case
	err = toolkit.UpdateCaseStatus(ctx, c.ID, forensics.CaseStatusClosed)
	if err != nil {
		t.Fatalf("failed to close case: %v", err)
	}

	retrieved, _ = toolkit.GetCase(ctx, c.ID)
	if retrieved.ClosedAt == nil {
		t.Error("expected closed_at to be set")
	}
}

func TestArtifactCollection(t *testing.T) {
	toolkit := forensics.NewToolkit(forensics.Config{}, nil)
	ctx := context.Background()

	c := &forensics.Case{
		Title: "Artifact Test Case",
	}
	_ = toolkit.CreateCase(ctx, c)

	// Add artifact
	artifact := &forensics.Artifact{
		Type:        forensics.ArtifactTypeTransaction,
		Name:        "Suspicious Transaction",
		Description: "Transaction from attack",
		ChainID:     "ethereum",
		CollectedBy: "analyst@test.com",
		Data: map[string]interface{}{
			"hash": "0x123...",
		},
	}

	err := toolkit.AddArtifact(ctx, c.ID, artifact)
	if err != nil {
		t.Fatalf("failed to add artifact: %v", err)
	}

	if artifact.ID == "" {
		t.Error("expected artifact ID to be set")
	}

	if artifact.Hash == "" {
		t.Error("expected artifact hash to be computed")
	}

	// Retrieve case and check artifact
	retrieved, _ := toolkit.GetCase(ctx, c.ID)
	if len(retrieved.Artifacts) != 1 {
		t.Errorf("expected 1 artifact, got %d", len(retrieved.Artifacts))
	}
}

func TestTimelineEntry(t *testing.T) {
	toolkit := forensics.NewToolkit(forensics.Config{}, nil)
	ctx := context.Background()

	c := &forensics.Case{
		Title: "Timeline Test Case",
	}
	_ = toolkit.CreateCase(ctx, c)

	entry := &forensics.TimelineEntry{
		Timestamp:   time.Now().Add(-1 * time.Hour),
		EventType:   "transaction",
		Description: "Attacker initiated flash loan",
		ChainID:     "ethereum",
		TxHash:      "0xabc...",
		BlockNumber: 12345678,
	}

	err := toolkit.AddTimelineEntry(ctx, c.ID, entry)
	if err != nil {
		t.Fatalf("failed to add timeline entry: %v", err)
	}

	retrieved, _ := toolkit.GetCase(ctx, c.ID)
	if len(retrieved.Timeline) != 1 {
		t.Errorf("expected 1 timeline entry, got %d", len(retrieved.Timeline))
	}
}

func TestCaseNotes(t *testing.T) {
	toolkit := forensics.NewToolkit(forensics.Config{}, nil)
	ctx := context.Background()

	c := &forensics.Case{
		Title: "Notes Test Case",
	}
	_ = toolkit.CreateCase(ctx, c)

	note, err := toolkit.AddNote(ctx, c.ID, "Initial analysis shows the attack vector was a reentrancy exploit", "analyst@test.com")
	if err != nil {
		t.Fatalf("failed to add note: %v", err)
	}

	if note.ID == "" {
		t.Error("expected note ID to be set")
	}

	retrieved, _ := toolkit.GetCase(ctx, c.ID)
	if len(retrieved.Notes) != 1 {
		t.Errorf("expected 1 note, got %d", len(retrieved.Notes))
	}
}

func TestArtifactTypes(t *testing.T) {
	toolkit := forensics.NewToolkit(forensics.Config{}, nil)
	types := toolkit.GetArtifactTypes()

	if len(types) != 12 {
		t.Errorf("expected 12 artifact types, got %d", len(types))
	}
}

func TestCasePriorities(t *testing.T) {
	priorities := []forensics.CasePriority{
		forensics.CasePriorityCritical,
		forensics.CasePriorityHigh,
		forensics.CasePriorityMedium,
		forensics.CasePriorityLow,
	}

	if len(priorities) != 4 {
		t.Errorf("expected 4 priorities, got %d", len(priorities))
	}
}

func TestCaseExport(t *testing.T) {
	toolkit := forensics.NewToolkit(forensics.Config{}, nil)
	ctx := context.Background()

	c := &forensics.Case{
		Title: "Export Test Case",
	}
	_ = toolkit.CreateCase(ctx, c)

	data, err := toolkit.ExportCase(ctx, c.ID)
	if err != nil {
		t.Fatalf("failed to export case: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected export data")
	}
}

func TestListCases(t *testing.T) {
	toolkit := forensics.NewToolkit(forensics.Config{}, nil)
	ctx := context.Background()

	// Create cases with different priorities
	_ = toolkit.CreateCase(ctx, &forensics.Case{Title: "Case 1", Priority: forensics.CasePriorityCritical})
	_ = toolkit.CreateCase(ctx, &forensics.Case{Title: "Case 2", Priority: forensics.CasePriorityHigh})
	_ = toolkit.CreateCase(ctx, &forensics.Case{Title: "Case 3", Priority: forensics.CasePriorityCritical})

	// List all
	all := toolkit.ListCases(ctx, nil, nil)
	if len(all) != 3 {
		t.Errorf("expected 3 cases, got %d", len(all))
	}

	// Filter by priority
	critical := forensics.CasePriorityCritical
	filtered := toolkit.ListCases(ctx, nil, &critical)
	if len(filtered) != 2 {
		t.Errorf("expected 2 critical cases, got %d", len(filtered))
	}
}

// ============================================================================
// SOAR Engine Tests
// ============================================================================

func TestSOAREngineCreation(t *testing.T) {
	cfg := soar.Config{
		MaxConcurrentExecutions: 10,
		DefaultTimeout:          5 * time.Minute,
		MaxRetries:              3,
		EnableAuditLogging:      true,
	}

	engine := soar.NewEngine(cfg, nil)
	if engine == nil {
		t.Fatal("expected engine to be created")
	}

	// Check built-in workflows loaded
	workflowCount := engine.GetWorkflowCount()
	if workflowCount != 8 {
		t.Errorf("expected 8 built-in workflows, got %d", workflowCount)
	}

	// Check integrations loaded
	integrationCount := engine.GetIntegrationCount()
	if integrationCount != 8 {
		t.Errorf("expected 8 built-in integrations, got %d", integrationCount)
	}
}

func TestSOARWorkflows(t *testing.T) {
	engine := soar.NewEngine(soar.Config{}, nil)
	ctx := context.Background()

	workflows := engine.ListWorkflows(ctx, nil)
	if len(workflows) == 0 {
		t.Fatal("expected workflows to be loaded")
	}

	// Check workflow names
	names := make(map[string]bool)
	for _, wf := range workflows {
		names[wf.Name] = true
	}

	expectedWorkflows := []string{
		"Suspicious Transaction Response",
		"Flash Loan Attack Response",
		"Validator Anomaly Response",
		"OFAC Address Detection Response",
		"Bridge Exploit Response",
		"Smart Contract Vulnerability Alert",
		"Wallet Drainer Detection Response",
		"Scheduled Threat Intel Update",
	}

	for _, name := range expectedWorkflows {
		if !names[name] {
			t.Errorf("expected workflow %s to exist", name)
		}
	}
}

func TestWorkflowCreation(t *testing.T) {
	engine := soar.NewEngine(soar.Config{}, nil)
	ctx := context.Background()

	wf := &soar.Workflow{
		Name:        "Custom Response Workflow",
		Description: "Custom workflow for testing",
		Trigger: soar.Trigger{
			Type: soar.TriggerTypeManual,
		},
		Steps: []soar.Step{
			{
				ID:   "step-1",
				Name: "Notification",
				Type: soar.StepTypeNotification,
			},
		},
		Owner: "admin@test.com",
	}

	err := engine.CreateWorkflow(ctx, wf)
	if err != nil {
		t.Fatalf("failed to create workflow: %v", err)
	}

	if wf.ID == "" {
		t.Error("expected workflow ID to be set")
	}

	if wf.Status != soar.WorkflowStatusDraft {
		t.Errorf("expected status draft, got %s", wf.Status)
	}
}

func TestWorkflowActivation(t *testing.T) {
	engine := soar.NewEngine(soar.Config{}, nil)
	ctx := context.Background()

	wf := &soar.Workflow{
		Name:  "Activation Test",
		Owner: "admin@test.com",
	}

	_ = engine.CreateWorkflow(ctx, wf)

	err := engine.ActivateWorkflow(ctx, wf.ID)
	if err != nil {
		t.Fatalf("failed to activate workflow: %v", err)
	}

	retrieved, _ := engine.GetWorkflow(ctx, wf.ID)
	if retrieved.Status != soar.WorkflowStatusActive {
		t.Errorf("expected status active, got %s", retrieved.Status)
	}
}

func TestWorkflowTrigger(t *testing.T) {
	engine := soar.NewEngine(soar.Config{}, nil)
	ctx := context.Background()

	// Use a built-in active workflow
	wf, _ := engine.GetWorkflow(ctx, "wf-001")
	if wf == nil {
		t.Fatal("expected workflow wf-001 to exist")
	}

	triggerData := map[string]interface{}{
		"alert_id":     "alert-123",
		"tx_hash":      "0xabc...",
		"risk_score":   85.5,
	}

	exec, err := engine.TriggerWorkflow(ctx, "wf-001", triggerData)
	if err != nil {
		t.Fatalf("failed to trigger workflow: %v", err)
	}

	if exec.ID == "" {
		t.Error("expected execution ID to be set")
	}

	if exec.WorkflowID != "wf-001" {
		t.Errorf("expected workflow ID wf-001, got %s", exec.WorkflowID)
	}

	if exec.Status != soar.ExecutionStatusPending {
		t.Errorf("expected status pending, got %s", exec.Status)
	}
}

func TestIntegrations(t *testing.T) {
	engine := soar.NewEngine(soar.Config{}, nil)
	ctx := context.Background()

	integrations := engine.ListIntegrations(ctx)

	types := make(map[string]int)
	for _, integ := range integrations {
		types[integ.Type]++
	}

	expectedTypes := map[string]int{
		"notification":  1, // Slack
		"alerting":      1, // PagerDuty
		"ticketing":     1, // Jira
		"threat_intel":  2, // Chainalysis, Elliptic
		"storage":       1, // S3
		"blockchain":    2, // TheGraph, Tenderly
	}

	for typ, count := range expectedTypes {
		if types[typ] != count {
			t.Errorf("expected %d %s integrations, got %d", count, typ, types[typ])
		}
	}
}

func TestStepTypes(t *testing.T) {
	types := []soar.StepType{
		soar.StepTypeAction,
		soar.StepTypeCondition,
		soar.StepTypeParallel,
		soar.StepTypeLoop,
		soar.StepTypeDelay,
		soar.StepTypeApproval,
		soar.StepTypeNotification,
		soar.StepTypeIntegration,
		soar.StepTypeScript,
	}

	if len(types) != 9 {
		t.Errorf("expected 9 step types, got %d", len(types))
	}
}

func TestTriggerTypes(t *testing.T) {
	types := []soar.TriggerType{
		soar.TriggerTypeAlert,
		soar.TriggerTypeEvent,
		soar.TriggerTypeSchedule,
		soar.TriggerTypeManual,
		soar.TriggerTypeWebhook,
		soar.TriggerTypeAPI,
	}

	if len(types) != 6 {
		t.Errorf("expected 6 trigger types, got %d", len(types))
	}
}

func TestExecutionStatus(t *testing.T) {
	statuses := []soar.ExecutionStatus{
		soar.ExecutionStatusPending,
		soar.ExecutionStatusRunning,
		soar.ExecutionStatusCompleted,
		soar.ExecutionStatusFailed,
		soar.ExecutionStatusCancelled,
		soar.ExecutionStatusWaiting,
	}

	if len(statuses) != 6 {
		t.Errorf("expected 6 execution statuses, got %d", len(statuses))
	}
}

func TestWorkflowExport(t *testing.T) {
	engine := soar.NewEngine(soar.Config{}, nil)
	ctx := context.Background()

	data, err := engine.ExportWorkflow(ctx, "wf-001")
	if err != nil {
		t.Fatalf("failed to export workflow: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected export data")
	}
}

func TestListExecutions(t *testing.T) {
	engine := soar.NewEngine(soar.Config{}, nil)
	ctx := context.Background()

	// Trigger multiple executions
	_, _ = engine.TriggerWorkflow(ctx, "wf-001", map[string]interface{}{"test": 1})
	_, _ = engine.TriggerWorkflow(ctx, "wf-001", map[string]interface{}{"test": 2})
	_, _ = engine.TriggerWorkflow(ctx, "wf-002", map[string]interface{}{"test": 3})

	// List all executions
	all := engine.ListExecutions(ctx, "", nil)
	if len(all) != 3 {
		t.Errorf("expected 3 executions, got %d", len(all))
	}

	// Filter by workflow
	wf001 := engine.ListExecutions(ctx, "wf-001", nil)
	if len(wf001) != 2 {
		t.Errorf("expected 2 executions for wf-001, got %d", len(wf001))
	}
}

// ============================================================================
// Summary Test
// ============================================================================

func TestAdvancedFeaturesCount(t *testing.T) {
	// Verify feature counts
	wb := hunting.NewWorkbench(hunting.Config{}, nil)
	toolkit := forensics.NewToolkit(forensics.Config{}, nil)
	engine := soar.NewEngine(soar.Config{}, nil)

	t.Logf("Hunt Templates: %d", wb.GetTemplateCount())
	t.Logf("Artifact Types: %d", len(toolkit.GetArtifactTypes()))
	t.Logf("SOAR Workflows: %d", engine.GetWorkflowCount())
	t.Logf("SOAR Integrations: %d", engine.GetIntegrationCount())

	// Summary verification
	if wb.GetTemplateCount() < 10 {
		t.Error("expected at least 10 hunt templates")
	}
	if len(toolkit.GetArtifactTypes()) < 12 {
		t.Error("expected at least 12 artifact types")
	}
	if engine.GetWorkflowCount() < 8 {
		t.Error("expected at least 8 SOAR workflows")
	}
	if engine.GetIntegrationCount() < 8 {
		t.Error("expected at least 8 integrations")
	}
}
