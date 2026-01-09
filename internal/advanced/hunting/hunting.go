// Package hunting provides a threat hunting workbench for blockchain SIEM
package hunting

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// HuntType represents the type of threat hunt
type HuntType string

const (
	HuntTypeHypothesis    HuntType = "hypothesis"
	HuntTypeIOC           HuntType = "ioc"
	HuntTypeAnomaly       HuntType = "anomaly"
	HuntTypeBehavioral    HuntType = "behavioral"
	HuntTypeTransaction   HuntType = "transaction"
	HuntTypeWallet        HuntType = "wallet"
	HuntTypeSmartContract HuntType = "smart_contract"
)

// HuntStatus represents the status of a hunt
type HuntStatus string

const (
	HuntStatusDraft     HuntStatus = "draft"
	HuntStatusActive    HuntStatus = "active"
	HuntStatusPaused    HuntStatus = "paused"
	HuntStatusCompleted HuntStatus = "completed"
	HuntStatusArchived  HuntStatus = "archived"
)

// Hunt represents a threat hunting investigation
type Hunt struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        HuntType               `json:"type"`
	Status      HuntStatus             `json:"status"`
	Hypothesis  string                 `json:"hypothesis"`
	Queries     []HuntQuery            `json:"queries"`
	Findings    []Finding              `json:"findings"`
	Techniques  []string               `json:"mitre_techniques"`
	Tags        []string               `json:"tags"`
	CreatedBy   string                 `json:"created_by"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// HuntQuery represents a query used in hunting
type HuntQuery struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	QueryType   QueryType              `json:"query_type"`
	Query       string                 `json:"query"`
	DataSource  string                 `json:"data_source"`
	TimeRange   TimeRange              `json:"time_range"`
	Parameters  map[string]interface{} `json:"parameters"`
	Results     *QueryResults          `json:"results,omitempty"`
	ExecutedAt  *time.Time             `json:"executed_at,omitempty"`
}

// QueryType represents the type of hunt query
type QueryType string

const (
	QueryTypeSQL    QueryType = "sql"
	QueryTypeKQL    QueryType = "kql"
	QueryTypeLucene QueryType = "lucene"
	QueryTypeYARA   QueryType = "yara"
	QueryTypeSigma  QueryType = "sigma"
	QueryTypeCustom QueryType = "custom"
)

// TimeRange represents a time range for queries
type TimeRange struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Relative string    `json:"relative,omitempty"` // e.g., "24h", "7d"
}

// QueryResults represents results from a hunt query
type QueryResults struct {
	TotalHits    int64                    `json:"total_hits"`
	Records      []map[string]interface{} `json:"records"`
	Aggregations map[string]interface{}   `json:"aggregations,omitempty"`
	ExecutionMs  int64                    `json:"execution_ms"`
}

// Finding represents a finding from a hunt
type Finding struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Confidence  float64                `json:"confidence"`
	Evidence    []Evidence             `json:"evidence"`
	Indicators  []Indicator            `json:"indicators"`
	Entities    []Entity               `json:"entities"`
	Timeline    []TimelineEvent        `json:"timeline"`
	Techniques  []string               `json:"mitre_techniques"`
	CreatedAt   time.Time              `json:"created_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Evidence represents evidence supporting a finding
type Evidence struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Source     string                 `json:"source"`
	Data       interface{}            `json:"data"`
	Hash       string                 `json:"hash"`
	CapturedAt time.Time              `json:"captured_at"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// Indicator represents an indicator of compromise
type Indicator struct {
	Type       string    `json:"type"`
	Value      string    `json:"value"`
	Confidence float64   `json:"confidence"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Context    string    `json:"context"`
}

// Entity represents an entity involved in findings
type Entity struct {
	Type       string                 `json:"type"`
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Attributes map[string]interface{} `json:"attributes"`
	Risk       float64                `json:"risk_score"`
}

// TimelineEvent represents an event in the finding timeline
type TimelineEvent struct {
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Data        map[string]interface{} `json:"data"`
}

// HuntTemplate represents a reusable hunt template
type HuntTemplate struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Category    string      `json:"category"`
	Type        HuntType    `json:"type"`
	Hypothesis  string      `json:"hypothesis"`
	Queries     []HuntQuery `json:"queries"`
	Techniques  []string    `json:"mitre_techniques"`
	Tags        []string    `json:"tags"`
	Difficulty  string      `json:"difficulty"`
	Author      string      `json:"author"`
}

// Workbench provides threat hunting capabilities
type Workbench struct {
	mu        sync.RWMutex
	hunts     map[string]*Hunt
	templates map[string]*HuntTemplate
	executor  QueryExecutor
}

// QueryExecutor executes hunt queries
type QueryExecutor interface {
	Execute(ctx context.Context, query HuntQuery) (*QueryResults, error)
	ValidateQuery(query HuntQuery) error
}

// Config holds workbench configuration
type Config struct {
	MaxConcurrentQueries int
	QueryTimeout         time.Duration
	ResultsLimit         int
	EnableCaching        bool
}

// NewWorkbench creates a new threat hunting workbench
func NewWorkbench(cfg Config, executor QueryExecutor) *Workbench {
	wb := &Workbench{
		hunts:     make(map[string]*Hunt),
		templates: make(map[string]*HuntTemplate),
		executor:  executor,
	}
	wb.loadBuiltInTemplates()
	return wb
}

// loadBuiltInTemplates loads built-in hunt templates
func (w *Workbench) loadBuiltInTemplates() {
	templates := []HuntTemplate{
		{
			ID:          "tmpl-001",
			Name:        "Suspicious Token Approval Patterns",
			Description: "Hunt for unusual token approval patterns that may indicate wallet drainer activity",
			Category:    "DeFi Security",
			Type:        HuntTypeTransaction,
			Hypothesis:  "Attackers are using phishing to obtain unlimited token approvals",
			Queries: []HuntQuery{
				{
					ID:        "q1",
					Name:      "Unlimited Approvals",
					QueryType: QueryTypeSQL,
					Query:     "SELECT * FROM transactions WHERE method = 'approve' AND amount = 'unlimited' ORDER BY timestamp DESC",
				},
				{
					ID:        "q2",
					Name:      "Approval to New Contracts",
					QueryType: QueryTypeSQL,
					Query:     "SELECT * FROM transactions WHERE method = 'approve' AND spender_age_days < 7",
				},
			},
			Techniques: []string{"T1566", "T1204"},
			Tags:       []string{"defi", "phishing", "token-approval"},
			Difficulty: "medium",
			Author:     "Boundary SIEM",
		},
		{
			ID:          "tmpl-002",
			Name:        "Flash Loan Attack Detection",
			Description: "Identify potential flash loan attacks by analyzing transaction patterns",
			Category:    "DeFi Security",
			Type:        HuntTypeTransaction,
			Hypothesis:  "Flash loans are being used to manipulate protocol prices",
			Queries: []HuntQuery{
				{
					ID:        "q1",
					Name:      "Flash Loan Transactions",
					QueryType: QueryTypeSQL,
					Query:     "SELECT * FROM transactions WHERE has_flash_loan = true AND profit_usd > 10000",
				},
				{
					ID:        "q2",
					Name:      "Price Oracle Manipulation",
					QueryType: QueryTypeSQL,
					Query:     "SELECT * FROM oracle_updates WHERE price_change_pct > 10 AND time_window_seconds < 60",
				},
			},
			Techniques: []string{"T1565.001"},
			Tags:       []string{"defi", "flash-loan", "price-manipulation"},
			Difficulty: "hard",
			Author:     "Boundary SIEM",
		},
		{
			ID:          "tmpl-003",
			Name:        "Validator Slashing Investigation",
			Description: "Investigate validator slashing events for potential attacks",
			Category:    "Validator Security",
			Type:        HuntTypeBehavioral,
			Hypothesis:  "Validators are being targeted for slashing attacks",
			Queries: []HuntQuery{
				{
					ID:        "q1",
					Name:      "Recent Slashing Events",
					QueryType: QueryTypeSQL,
					Query:     "SELECT * FROM slashing_events WHERE timestamp > now() - interval '7 days'",
				},
				{
					ID:        "q2",
					Name:      "Double Signing Patterns",
					QueryType: QueryTypeSQL,
					Query:     "SELECT validator_id, COUNT(*) as violations FROM attestations GROUP BY validator_id HAVING COUNT(*) > 1",
				},
			},
			Techniques: []string{"T1485", "T1498"},
			Tags:       []string{"validator", "slashing", "consensus"},
			Difficulty: "hard",
			Author:     "Boundary SIEM",
		},
		{
			ID:          "tmpl-004",
			Name:        "Wallet Clustering Analysis",
			Description: "Identify related wallets through transaction pattern analysis",
			Category:    "Wallet Analysis",
			Type:        HuntTypeWallet,
			Hypothesis:  "Malicious actor is using multiple wallets to obscure activity",
			Queries: []HuntQuery{
				{
					ID:        "q1",
					Name:      "Common Funding Sources",
					QueryType: QueryTypeSQL,
					Query:     "SELECT funding_wallet, COUNT(DISTINCT wallet) as funded_count FROM wallet_funding GROUP BY funding_wallet HAVING COUNT(*) > 5",
				},
				{
					ID:        "q2",
					Name:      "Temporal Transaction Patterns",
					QueryType: QueryTypeSQL,
					Query:     "SELECT * FROM transactions WHERE wallet IN (SELECT wallet FROM suspect_cluster)",
				},
			},
			Techniques: []string{"T1070", "T1036"},
			Tags:       []string{"wallet", "clustering", "obfuscation"},
			Difficulty: "medium",
			Author:     "Boundary SIEM",
		},
		{
			ID:          "tmpl-005",
			Name:        "Smart Contract Vulnerability Hunt",
			Description: "Proactively hunt for exploitable smart contract patterns",
			Category:    "Smart Contract Security",
			Type:        HuntTypeSmartContract,
			Hypothesis:  "Deployed contracts contain known vulnerability patterns",
			Queries: []HuntQuery{
				{
					ID:        "q1",
					Name:      "Reentrancy Patterns",
					QueryType: QueryTypeCustom,
					Query:     "ANALYZE_BYTECODE(pattern='reentrancy', depth=3)",
				},
				{
					ID:        "q2",
					Name:      "Unprotected Functions",
					QueryType: QueryTypeCustom,
					Query:     "ANALYZE_ABI(check='missing_access_control')",
				},
			},
			Techniques: []string{"T1190", "T1059"},
			Tags:       []string{"smart-contract", "vulnerability", "code-analysis"},
			Difficulty: "expert",
			Author:     "Boundary SIEM",
		},
		{
			ID:          "tmpl-006",
			Name:        "Bridge Exploit Investigation",
			Description: "Hunt for cross-chain bridge exploitation attempts",
			Category:    "Bridge Security",
			Type:        HuntTypeTransaction,
			Hypothesis:  "Attackers are attempting to exploit bridge validation logic",
			Queries: []HuntQuery{
				{
					ID:        "q1",
					Name:      "Unmatched Bridge Transactions",
					QueryType: QueryTypeSQL,
					Query:     "SELECT * FROM bridge_deposits WHERE NOT EXISTS (SELECT 1 FROM bridge_withdrawals WHERE deposit_hash = hash)",
				},
				{
					ID:        "q2",
					Name:      "Unusual Bridge Volumes",
					QueryType: QueryTypeSQL,
					Query:     "SELECT bridge, SUM(amount_usd) as volume FROM bridge_txs WHERE volume > avg_volume * 10 GROUP BY bridge",
				},
			},
			Techniques: []string{"T1565", "T1495"},
			Tags:       []string{"bridge", "cross-chain", "exploit"},
			Difficulty: "expert",
			Author:     "Boundary SIEM",
		},
		{
			ID:          "tmpl-007",
			Name:        "Mixer and Tumbler Detection",
			Description: "Identify transactions involving mixing services",
			Category:    "Transaction Analysis",
			Type:        HuntTypeTransaction,
			Hypothesis:  "Stolen funds are being laundered through mixing services",
			Queries: []HuntQuery{
				{
					ID:        "q1",
					Name:      "Known Mixer Interactions",
					QueryType: QueryTypeSQL,
					Query:     "SELECT * FROM transactions WHERE to_address IN (SELECT address FROM known_mixers)",
				},
				{
					ID:        "q2",
					Name:      "Mixer-like Patterns",
					QueryType: QueryTypeSQL,
					Query:     "SELECT * FROM transactions WHERE equal_value_outputs > 3 AND time_delayed_outputs = true",
				},
			},
			Techniques: []string{"T1070.004", "T1027"},
			Tags:       []string{"mixer", "laundering", "privacy"},
			Difficulty: "medium",
			Author:     "Boundary SIEM",
		},
		{
			ID:          "tmpl-008",
			Name:        "MEV Bot Activity Analysis",
			Description: "Analyze MEV bot behavior for malicious patterns",
			Category:    "MEV Analysis",
			Type:        HuntTypeBehavioral,
			Hypothesis:  "MEV bots are conducting sandwich attacks on users",
			Queries: []HuntQuery{
				{
					ID:        "q1",
					Name:      "Sandwich Attack Patterns",
					QueryType: QueryTypeSQL,
					Query:     "SELECT * FROM mempool_txs WHERE is_sandwiched = true ORDER BY victim_loss_usd DESC",
				},
				{
					ID:        "q2",
					Name:      "Frontrunning Detection",
					QueryType: QueryTypeSQL,
					Query:     "SELECT * FROM transactions WHERE gas_price > next_tx_gas_price * 1.5 AND same_target = true",
				},
			},
			Techniques: []string{"T1557", "T1040"},
			Tags:       []string{"mev", "sandwich", "frontrunning"},
			Difficulty: "hard",
			Author:     "Boundary SIEM",
		},
		{
			ID:          "tmpl-009",
			Name:        "Governance Attack Detection",
			Description: "Hunt for governance manipulation attempts",
			Category:    "Governance Security",
			Type:        HuntTypeBehavioral,
			Hypothesis:  "Attackers are attempting to manipulate DAO governance",
			Queries: []HuntQuery{
				{
					ID:        "q1",
					Name:      "Flash Loan Governance",
					QueryType: QueryTypeSQL,
					Query:     "SELECT * FROM governance_votes WHERE voter_token_age < 1 AND vote_weight > threshold * 0.4",
				},
				{
					ID:        "q2",
					Name:      "Whale Vote Coordination",
					QueryType: QueryTypeSQL,
					Query:     "SELECT proposal_id, COUNT(*) as aligned_whales FROM whale_votes WHERE vote_direction = 'yes' GROUP BY proposal_id",
				},
			},
			Techniques: []string{"T1078", "T1098"},
			Tags:       []string{"governance", "dao", "voting"},
			Difficulty: "medium",
			Author:     "Boundary SIEM",
		},
		{
			ID:          "tmpl-010",
			Name:        "NFT Wash Trading Detection",
			Description: "Identify NFT wash trading and market manipulation",
			Category:    "NFT Security",
			Type:        HuntTypeTransaction,
			Hypothesis:  "NFT prices are being artificially inflated through wash trading",
			Queries: []HuntQuery{
				{
					ID:        "q1",
					Name:      "Self-Trading Patterns",
					QueryType: QueryTypeSQL,
					Query:     "SELECT * FROM nft_sales WHERE seller_cluster = buyer_cluster",
				},
				{
					ID:        "q2",
					Name:      "Rapid Price Escalation",
					QueryType: QueryTypeSQL,
					Query:     "SELECT token_id, price_increase_pct FROM nft_sales WHERE trades_24h > 5 AND price_increase_pct > 500",
				},
			},
			Techniques: []string{"T1565.001", "T1036"},
			Tags:       []string{"nft", "wash-trading", "manipulation"},
			Difficulty: "medium",
			Author:     "Boundary SIEM",
		},
	}

	for i := range templates {
		w.templates[templates[i].ID] = &templates[i]
	}
}

// CreateHunt creates a new hunt
func (w *Workbench) CreateHunt(ctx context.Context, hunt *Hunt) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if hunt.ID == "" {
		hunt.ID = fmt.Sprintf("hunt-%d", time.Now().UnixNano())
	}
	hunt.Status = HuntStatusDraft
	hunt.CreatedAt = time.Now()
	hunt.UpdatedAt = time.Now()

	w.hunts[hunt.ID] = hunt
	return nil
}

// CreateHuntFromTemplate creates a hunt from a template
func (w *Workbench) CreateHuntFromTemplate(ctx context.Context, templateID string, name string, createdBy string) (*Hunt, error) {
	w.mu.RLock()
	tmpl, exists := w.templates[templateID]
	w.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("template not found: %s", templateID)
	}

	hunt := &Hunt{
		ID:          fmt.Sprintf("hunt-%d", time.Now().UnixNano()),
		Name:        name,
		Description: tmpl.Description,
		Type:        tmpl.Type,
		Status:      HuntStatusDraft,
		Hypothesis:  tmpl.Hypothesis,
		Queries:     make([]HuntQuery, len(tmpl.Queries)),
		Findings:    []Finding{},
		Techniques:  tmpl.Techniques,
		Tags:        tmpl.Tags,
		CreatedBy:   createdBy,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Metadata:    map[string]interface{}{"template_id": templateID},
	}

	copy(hunt.Queries, tmpl.Queries)

	w.mu.Lock()
	w.hunts[hunt.ID] = hunt
	w.mu.Unlock()

	return hunt, nil
}

// StartHunt starts a hunt
func (w *Workbench) StartHunt(ctx context.Context, huntID string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	hunt, exists := w.hunts[huntID]
	if !exists {
		return fmt.Errorf("hunt not found: %s", huntID)
	}

	now := time.Now()
	hunt.Status = HuntStatusActive
	hunt.StartedAt = &now
	hunt.UpdatedAt = now

	return nil
}

// ExecuteQuery executes a hunt query
func (w *Workbench) ExecuteQuery(ctx context.Context, huntID string, queryID string) (*QueryResults, error) {
	w.mu.RLock()
	hunt, exists := w.hunts[huntID]
	w.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("hunt not found: %s", huntID)
	}

	var query *HuntQuery
	for i := range hunt.Queries {
		if hunt.Queries[i].ID == queryID {
			query = &hunt.Queries[i]
			break
		}
	}

	if query == nil {
		return nil, fmt.Errorf("query not found: %s", queryID)
	}

	if w.executor == nil {
		return nil, fmt.Errorf("query executor not configured")
	}

	results, err := w.executor.Execute(ctx, *query)
	if err != nil {
		return nil, fmt.Errorf("query execution failed: %w", err)
	}

	w.mu.Lock()
	now := time.Now()
	query.Results = results
	query.ExecutedAt = &now
	hunt.UpdatedAt = now
	w.mu.Unlock()

	return results, nil
}

// AddFinding adds a finding to a hunt
func (w *Workbench) AddFinding(ctx context.Context, huntID string, finding *Finding) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	hunt, exists := w.hunts[huntID]
	if !exists {
		return fmt.Errorf("hunt not found: %s", huntID)
	}

	if finding.ID == "" {
		finding.ID = fmt.Sprintf("finding-%d", time.Now().UnixNano())
	}
	finding.CreatedAt = time.Now()

	hunt.Findings = append(hunt.Findings, *finding)
	hunt.UpdatedAt = time.Now()

	return nil
}

// CompleteHunt marks a hunt as completed
func (w *Workbench) CompleteHunt(ctx context.Context, huntID string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	hunt, exists := w.hunts[huntID]
	if !exists {
		return fmt.Errorf("hunt not found: %s", huntID)
	}

	now := time.Now()
	hunt.Status = HuntStatusCompleted
	hunt.CompletedAt = &now
	hunt.UpdatedAt = now

	return nil
}

// GetHunt retrieves a hunt by ID
func (w *Workbench) GetHunt(ctx context.Context, huntID string) (*Hunt, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	hunt, exists := w.hunts[huntID]
	if !exists {
		return nil, fmt.Errorf("hunt not found: %s", huntID)
	}

	return hunt, nil
}

// ListHunts lists all hunts with optional filtering
func (w *Workbench) ListHunts(ctx context.Context, status *HuntStatus, huntType *HuntType) []*Hunt {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var result []*Hunt
	for _, hunt := range w.hunts {
		if status != nil && hunt.Status != *status {
			continue
		}
		if huntType != nil && hunt.Type != *huntType {
			continue
		}
		result = append(result, hunt)
	}

	return result
}

// ListTemplates lists all available hunt templates
func (w *Workbench) ListTemplates(ctx context.Context, category string) []*HuntTemplate {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var result []*HuntTemplate
	for _, tmpl := range w.templates {
		if category != "" && tmpl.Category != category {
			continue
		}
		result = append(result, tmpl)
	}

	return result
}

// ExportHunt exports a hunt to JSON
func (w *Workbench) ExportHunt(ctx context.Context, huntID string) ([]byte, error) {
	w.mu.RLock()
	hunt, exists := w.hunts[huntID]
	w.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("hunt not found: %s", huntID)
	}

	return json.MarshalIndent(hunt, "", "  ")
}

// GetTemplateCount returns the number of built-in templates
func (w *Workbench) GetTemplateCount() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.templates)
}

// GetHuntCount returns the number of hunts
func (w *Workbench) GetHuntCount() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.hunts)
}
