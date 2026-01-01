// Package forensics provides blockchain forensics toolkit for SIEM
package forensics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// CaseStatus represents the status of a forensics case
type CaseStatus string

const (
	CaseStatusOpen       CaseStatus = "open"
	CaseStatusInProgress CaseStatus = "in_progress"
	CaseStatusPending    CaseStatus = "pending_review"
	CaseStatusClosed     CaseStatus = "closed"
	CaseStatusArchived   CaseStatus = "archived"
)

// CasePriority represents case priority
type CasePriority string

const (
	CasePriorityCritical CasePriority = "critical"
	CasePriorityHigh     CasePriority = "high"
	CasePriorityMedium   CasePriority = "medium"
	CasePriorityLow      CasePriority = "low"
)

// Case represents a forensics investigation case
type Case struct {
	ID           string                 `json:"id"`
	Title        string                 `json:"title"`
	Description  string                 `json:"description"`
	Status       CaseStatus             `json:"status"`
	Priority     CasePriority           `json:"priority"`
	AssignedTo   string                 `json:"assigned_to"`
	CreatedBy    string                 `json:"created_by"`
	Incidents    []string               `json:"incident_ids"`
	Artifacts    []Artifact             `json:"artifacts"`
	Timeline     []TimelineEntry        `json:"timeline"`
	Notes        []Note                 `json:"notes"`
	Chains       []ChainAnalysis        `json:"chain_analyses"`
	Tags         []string               `json:"tags"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	ClosedAt     *time.Time             `json:"closed_at,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// Artifact represents a piece of evidence
type Artifact struct {
	ID          string                 `json:"id"`
	Type        ArtifactType           `json:"type"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Hash        string                 `json:"hash"`
	Size        int64                  `json:"size"`
	MimeType    string                 `json:"mime_type"`
	Source      string                 `json:"source"`
	ChainID     string                 `json:"chain_id,omitempty"`
	Data        interface{}            `json:"data"`
	Tags        []string               `json:"tags"`
	CollectedBy string                 `json:"collected_by"`
	CollectedAt time.Time              `json:"collected_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ArtifactType represents the type of artifact
type ArtifactType string

const (
	ArtifactTypeTransaction     ArtifactType = "transaction"
	ArtifactTypeBlock           ArtifactType = "block"
	ArtifactTypeContract        ArtifactType = "contract"
	ArtifactTypeBytecode        ArtifactType = "bytecode"
	ArtifactTypeLog             ArtifactType = "log"
	ArtifactTypeTrace           ArtifactType = "trace"
	ArtifactTypeWallet          ArtifactType = "wallet"
	ArtifactTypeMempool         ArtifactType = "mempool"
	ArtifactTypeSignature       ArtifactType = "signature"
	ArtifactTypeStateSnapshot   ArtifactType = "state_snapshot"
	ArtifactTypeScreenshot      ArtifactType = "screenshot"
	ArtifactTypeDocument        ArtifactType = "document"
)

// TimelineEntry represents an entry in the case timeline
type TimelineEntry struct {
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	Description string                 `json:"description"`
	Actor       string                 `json:"actor"`
	ChainID     string                 `json:"chain_id,omitempty"`
	TxHash      string                 `json:"tx_hash,omitempty"`
	BlockNumber uint64                 `json:"block_number,omitempty"`
	Evidence    []string               `json:"evidence_ids"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Note represents a case note
type Note struct {
	ID        string    `json:"id"`
	Content   string    `json:"content"`
	Author    string    `json:"author"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ChainAnalysis represents blockchain-specific analysis
type ChainAnalysis struct {
	ID             string            `json:"id"`
	ChainID        string            `json:"chain_id"`
	ChainName      string            `json:"chain_name"`
	AnalysisType   string            `json:"analysis_type"`
	RootAddress    string            `json:"root_address"`
	FlowAnalysis   *FlowAnalysis     `json:"flow_analysis,omitempty"`
	ClusterResult  *ClusterResult    `json:"cluster_result,omitempty"`
	RiskAssessment *RiskAssessment   `json:"risk_assessment,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
}

// FlowAnalysis represents fund flow analysis
type FlowAnalysis struct {
	TotalInflow    string         `json:"total_inflow"`
	TotalOutflow   string         `json:"total_outflow"`
	UniqueInbound  int            `json:"unique_inbound"`
	UniqueOutbound int            `json:"unique_outbound"`
	TopSources     []FlowNode     `json:"top_sources"`
	TopDestinations []FlowNode    `json:"top_destinations"`
	Paths          []FlowPath     `json:"paths"`
}

// FlowNode represents a node in flow analysis
type FlowNode struct {
	Address    string  `json:"address"`
	Label      string  `json:"label,omitempty"`
	Amount     string  `json:"amount"`
	Percentage float64 `json:"percentage"`
	Risk       string  `json:"risk_level"`
}

// FlowPath represents a path in fund flow
type FlowPath struct {
	Nodes      []string `json:"nodes"`
	TotalValue string   `json:"total_value"`
	Hops       int      `json:"hops"`
}

// ClusterResult represents wallet clustering results
type ClusterResult struct {
	ClusterID       string   `json:"cluster_id"`
	TotalAddresses  int      `json:"total_addresses"`
	Addresses       []string `json:"addresses"`
	CommonFunding   []string `json:"common_funding"`
	SharedBehavior  []string `json:"shared_behavior"`
	ConfidenceScore float64  `json:"confidence_score"`
}

// RiskAssessment represents risk scoring
type RiskAssessment struct {
	OverallRisk    float64           `json:"overall_risk"`
	RiskLevel      string            `json:"risk_level"`
	RiskFactors    []RiskFactor      `json:"risk_factors"`
	Sanctions      []SanctionMatch   `json:"sanctions"`
	Mixers         []MixerExposure   `json:"mixer_exposure"`
	KnownBad       []KnownBadActor   `json:"known_bad_actors"`
}

// RiskFactor represents a factor contributing to risk
type RiskFactor struct {
	Factor      string  `json:"factor"`
	Score       float64 `json:"score"`
	Weight      float64 `json:"weight"`
	Description string  `json:"description"`
}

// SanctionMatch represents a sanctions list match
type SanctionMatch struct {
	ListName   string  `json:"list_name"`
	EntityName string  `json:"entity_name"`
	Address    string  `json:"address"`
	Confidence float64 `json:"confidence"`
}

// MixerExposure represents exposure to mixing services
type MixerExposure struct {
	MixerName  string  `json:"mixer_name"`
	Amount     string  `json:"amount"`
	Percentage float64 `json:"percentage"`
	Direction  string  `json:"direction"`
}

// KnownBadActor represents a known malicious actor
type KnownBadActor struct {
	Address     string   `json:"address"`
	Labels      []string `json:"labels"`
	Incidents   []string `json:"incidents"`
	FirstSeen   string   `json:"first_seen"`
}

// Toolkit provides forensics investigation capabilities
type Toolkit struct {
	mu       sync.RWMutex
	cases    map[string]*Case
	analyzer ChainAnalyzer
}

// ChainAnalyzer performs blockchain analysis
type ChainAnalyzer interface {
	AnalyzeFlow(ctx context.Context, chainID, address string, depth int) (*FlowAnalysis, error)
	ClusterWallets(ctx context.Context, chainID string, addresses []string) (*ClusterResult, error)
	AssessRisk(ctx context.Context, chainID, address string) (*RiskAssessment, error)
	TraceTransaction(ctx context.Context, chainID, txHash string) (*TransactionTrace, error)
}

// TransactionTrace represents a detailed transaction trace
type TransactionTrace struct {
	TxHash       string       `json:"tx_hash"`
	BlockNumber  uint64       `json:"block_number"`
	From         string       `json:"from"`
	To           string       `json:"to"`
	Value        string       `json:"value"`
	GasUsed      uint64       `json:"gas_used"`
	Status       bool         `json:"status"`
	InternalTxs  []InternalTx `json:"internal_txs"`
	Logs         []Log        `json:"logs"`
	StateChanges []StateChange `json:"state_changes"`
}

// InternalTx represents an internal transaction
type InternalTx struct {
	Type    string `json:"type"`
	From    string `json:"from"`
	To      string `json:"to"`
	Value   string `json:"value"`
	Input   string `json:"input"`
	Output  string `json:"output"`
	GasUsed uint64 `json:"gas_used"`
}

// Log represents an event log
type Log struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `json:"data"`
	Index   uint     `json:"index"`
}

// StateChange represents a state change
type StateChange struct {
	Address  string `json:"address"`
	Key      string `json:"key"`
	OldValue string `json:"old_value"`
	NewValue string `json:"new_value"`
}

// Config holds toolkit configuration
type Config struct {
	MaxConcurrentAnalyses int
	TraceDepth           int
	ClusterMinConfidence float64
}

// NewToolkit creates a new forensics toolkit
func NewToolkit(cfg Config, analyzer ChainAnalyzer) *Toolkit {
	return &Toolkit{
		cases:    make(map[string]*Case),
		analyzer: analyzer,
	}
}

// CreateCase creates a new forensics case
func (t *Toolkit) CreateCase(ctx context.Context, c *Case) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if c.ID == "" {
		c.ID = fmt.Sprintf("case-%d", time.Now().UnixNano())
	}
	c.Status = CaseStatusOpen
	c.CreatedAt = time.Now()
	c.UpdatedAt = time.Now()
	c.Artifacts = []Artifact{}
	c.Timeline = []TimelineEntry{}
	c.Notes = []Note{}
	c.Chains = []ChainAnalysis{}

	t.cases[c.ID] = c
	return nil
}

// GetCase retrieves a case by ID
func (t *Toolkit) GetCase(ctx context.Context, caseID string) (*Case, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	c, exists := t.cases[caseID]
	if !exists {
		return nil, fmt.Errorf("case not found: %s", caseID)
	}
	return c, nil
}

// UpdateCaseStatus updates the status of a case
func (t *Toolkit) UpdateCaseStatus(ctx context.Context, caseID string, status CaseStatus) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	c, exists := t.cases[caseID]
	if !exists {
		return fmt.Errorf("case not found: %s", caseID)
	}

	c.Status = status
	c.UpdatedAt = time.Now()

	if status == CaseStatusClosed {
		now := time.Now()
		c.ClosedAt = &now
	}

	return nil
}

// AddArtifact adds an artifact to a case
func (t *Toolkit) AddArtifact(ctx context.Context, caseID string, artifact *Artifact) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	c, exists := t.cases[caseID]
	if !exists {
		return fmt.Errorf("case not found: %s", caseID)
	}

	if artifact.ID == "" {
		artifact.ID = fmt.Sprintf("artifact-%d", time.Now().UnixNano())
	}
	artifact.CollectedAt = time.Now()

	// Compute hash if not provided
	if artifact.Hash == "" && artifact.Data != nil {
		data, _ := json.Marshal(artifact.Data)
		hash := sha256.Sum256(data)
		artifact.Hash = hex.EncodeToString(hash[:])
	}

	c.Artifacts = append(c.Artifacts, *artifact)
	c.UpdatedAt = time.Now()

	return nil
}

// CollectTransaction collects a transaction as evidence
func (t *Toolkit) CollectTransaction(ctx context.Context, caseID, chainID, txHash string, collector string) (*Artifact, error) {
	artifact := &Artifact{
		Type:        ArtifactTypeTransaction,
		Name:        fmt.Sprintf("Transaction %s", txHash[:16]),
		Description: fmt.Sprintf("Transaction collected from chain %s", chainID),
		ChainID:     chainID,
		CollectedBy: collector,
		Tags:        []string{"transaction", chainID},
		Metadata: map[string]interface{}{
			"tx_hash":  txHash,
			"chain_id": chainID,
		},
	}

	// If analyzer is available, get full trace
	if t.analyzer != nil {
		trace, err := t.analyzer.TraceTransaction(ctx, chainID, txHash)
		if err == nil {
			artifact.Data = trace
		}
	}

	if err := t.AddArtifact(ctx, caseID, artifact); err != nil {
		return nil, err
	}

	return artifact, nil
}

// AddTimelineEntry adds an entry to the case timeline
func (t *Toolkit) AddTimelineEntry(ctx context.Context, caseID string, entry *TimelineEntry) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	c, exists := t.cases[caseID]
	if !exists {
		return fmt.Errorf("case not found: %s", caseID)
	}

	c.Timeline = append(c.Timeline, *entry)
	c.UpdatedAt = time.Now()

	return nil
}

// AddNote adds a note to a case
func (t *Toolkit) AddNote(ctx context.Context, caseID string, content, author string) (*Note, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	c, exists := t.cases[caseID]
	if !exists {
		return nil, fmt.Errorf("case not found: %s", caseID)
	}

	note := Note{
		ID:        fmt.Sprintf("note-%d", time.Now().UnixNano()),
		Content:   content,
		Author:    author,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	c.Notes = append(c.Notes, note)
	c.UpdatedAt = time.Now()

	return &note, nil
}

// AnalyzeFundFlow performs fund flow analysis for a case
func (t *Toolkit) AnalyzeFundFlow(ctx context.Context, caseID, chainID, address string, depth int) (*ChainAnalysis, error) {
	t.mu.RLock()
	c, exists := t.cases[caseID]
	t.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("case not found: %s", caseID)
	}

	if t.analyzer == nil {
		return nil, fmt.Errorf("chain analyzer not configured")
	}

	flowAnalysis, err := t.analyzer.AnalyzeFlow(ctx, chainID, address, depth)
	if err != nil {
		return nil, fmt.Errorf("flow analysis failed: %w", err)
	}

	analysis := &ChainAnalysis{
		ID:           fmt.Sprintf("analysis-%d", time.Now().UnixNano()),
		ChainID:      chainID,
		AnalysisType: "fund_flow",
		RootAddress:  address,
		FlowAnalysis: flowAnalysis,
		CreatedAt:    time.Now(),
	}

	t.mu.Lock()
	c.Chains = append(c.Chains, *analysis)
	c.UpdatedAt = time.Now()
	t.mu.Unlock()

	return analysis, nil
}

// PerformRiskAssessment performs risk assessment on an address
func (t *Toolkit) PerformRiskAssessment(ctx context.Context, caseID, chainID, address string) (*ChainAnalysis, error) {
	t.mu.RLock()
	c, exists := t.cases[caseID]
	t.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("case not found: %s", caseID)
	}

	if t.analyzer == nil {
		return nil, fmt.Errorf("chain analyzer not configured")
	}

	riskAssessment, err := t.analyzer.AssessRisk(ctx, chainID, address)
	if err != nil {
		return nil, fmt.Errorf("risk assessment failed: %w", err)
	}

	analysis := &ChainAnalysis{
		ID:             fmt.Sprintf("analysis-%d", time.Now().UnixNano()),
		ChainID:        chainID,
		AnalysisType:   "risk_assessment",
		RootAddress:    address,
		RiskAssessment: riskAssessment,
		CreatedAt:      time.Now(),
	}

	t.mu.Lock()
	c.Chains = append(c.Chains, *analysis)
	c.UpdatedAt = time.Now()
	t.mu.Unlock()

	return analysis, nil
}

// ClusterAddresses performs wallet clustering analysis
func (t *Toolkit) ClusterAddresses(ctx context.Context, caseID, chainID string, addresses []string) (*ChainAnalysis, error) {
	t.mu.RLock()
	c, exists := t.cases[caseID]
	t.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("case not found: %s", caseID)
	}

	if t.analyzer == nil {
		return nil, fmt.Errorf("chain analyzer not configured")
	}

	clusterResult, err := t.analyzer.ClusterWallets(ctx, chainID, addresses)
	if err != nil {
		return nil, fmt.Errorf("clustering failed: %w", err)
	}

	analysis := &ChainAnalysis{
		ID:            fmt.Sprintf("analysis-%d", time.Now().UnixNano()),
		ChainID:       chainID,
		AnalysisType:  "wallet_clustering",
		ClusterResult: clusterResult,
		CreatedAt:     time.Now(),
	}

	t.mu.Lock()
	c.Chains = append(c.Chains, *analysis)
	c.UpdatedAt = time.Now()
	t.mu.Unlock()

	return analysis, nil
}

// ListCases lists all cases with optional filtering
func (t *Toolkit) ListCases(ctx context.Context, status *CaseStatus, priority *CasePriority) []*Case {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var result []*Case
	for _, c := range t.cases {
		if status != nil && c.Status != *status {
			continue
		}
		if priority != nil && c.Priority != *priority {
			continue
		}
		result = append(result, c)
	}

	return result
}

// ExportCase exports a case to JSON
func (t *Toolkit) ExportCase(ctx context.Context, caseID string) ([]byte, error) {
	t.mu.RLock()
	c, exists := t.cases[caseID]
	t.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("case not found: %s", caseID)
	}

	return json.MarshalIndent(c, "", "  ")
}

// GetCaseCount returns the number of cases
func (t *Toolkit) GetCaseCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.cases)
}

// GetArtifactTypes returns all supported artifact types
func (t *Toolkit) GetArtifactTypes() []ArtifactType {
	return []ArtifactType{
		ArtifactTypeTransaction,
		ArtifactTypeBlock,
		ArtifactTypeContract,
		ArtifactTypeBytecode,
		ArtifactTypeLog,
		ArtifactTypeTrace,
		ArtifactTypeWallet,
		ArtifactTypeMempool,
		ArtifactTypeSignature,
		ArtifactTypeStateSnapshot,
		ArtifactTypeScreenshot,
		ArtifactTypeDocument,
	}
}
