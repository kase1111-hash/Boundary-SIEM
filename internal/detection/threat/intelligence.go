// Package threat provides threat intelligence capabilities.
package threat

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// ThreatType categorizes threat types.
type ThreatType string

const (
	ThreatSanctioned    ThreatType = "sanctioned"
	ThreatExploit       ThreatType = "exploit"
	ThreatScam          ThreatType = "scam"
	ThreatMixer         ThreatType = "mixer"
	ThreatRansomware    ThreatType = "ransomware"
	ThreatDarknet       ThreatType = "darknet"
	ThreatTerrorFinance ThreatType = "terror_financing"
	ThreatPhishing      ThreatType = "phishing"
	ThreatRugPull       ThreatType = "rug_pull"
	ThreatFlashLoan     ThreatType = "flash_loan_attack"
	ThreatBridgeExploit ThreatType = "bridge_exploit"
	ThreatMEVBot        ThreatType = "mev_bot"
)

// RiskLevel indicates the risk severity.
type RiskLevel string

const (
	RiskCritical RiskLevel = "critical"
	RiskHigh     RiskLevel = "high"
	RiskMedium   RiskLevel = "medium"
	RiskLow      RiskLevel = "low"
	RiskUnknown  RiskLevel = "unknown"
)

// ThreatIndicator represents a threat intelligence indicator.
type ThreatIndicator struct {
	ID          string                 `json:"id"`
	Type        ThreatType             `json:"type"`
	Value       string                 `json:"value"` // Address, domain, hash, etc.
	Risk        RiskLevel              `json:"risk"`
	Source      string                 `json:"source"`
	Description string                 `json:"description"`
	Tags        []string               `json:"tags"`
	FirstSeen   time.Time              `json:"first_seen"`
	LastSeen    time.Time              `json:"last_seen"`
	Confidence  float64                `json:"confidence"` // 0.0 - 1.0
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ScreeningResult represents the result of address screening.
type ScreeningResult struct {
	Address    string             `json:"address"`
	IsMatch    bool               `json:"is_match"`
	Risk       RiskLevel          `json:"risk"`
	Indicators []*ThreatIndicator `json:"indicators,omitempty"`
	ScreenedAt time.Time          `json:"screened_at"`
	TotalHits  int                `json:"total_hits"`
}

// Alert represents a threat intelligence alert.
type Alert struct {
	ID          uuid.UUID              `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Address     string                 `json:"address"`
	ThreatType  ThreatType             `json:"threat_type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Indicators  []*ThreatIndicator     `json:"indicators"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AlertHandler processes threat alerts.
type AlertHandler func(context.Context, *Alert) error

// IntelConfig configures the threat intelligence service.
type IntelConfig struct {
	EnableOFAC         bool
	EnableChainalysis  bool
	EnableCustomLists  bool
	OFACUpdateInterval time.Duration
	CacheExpiry        time.Duration
	ChainalysisAPIKey  string
	ChainalysisAPIURL  string
	CustomListURLs     []string
	HighRiskThreshold  float64
}

// DefaultIntelConfig returns default configuration.
func DefaultIntelConfig() IntelConfig {
	return IntelConfig{
		EnableOFAC:         true,
		EnableChainalysis:  false, // Requires API key
		EnableCustomLists:  true,
		OFACUpdateInterval: 24 * time.Hour,
		CacheExpiry:        1 * time.Hour,
		HighRiskThreshold:  0.7,
	}
}

// IntelService provides threat intelligence services.
type IntelService struct {
	config   IntelConfig
	handlers []AlertHandler
	mu       sync.RWMutex

	// Indicator stores
	indicators map[string]*ThreatIndicator // address -> indicator

	// Caches
	screeningCache map[string]*ScreeningResult
	cacheExpiry    map[string]time.Time

	// OFAC data
	ofacAddresses  map[string]*ThreatIndicator
	ofacLastUpdate time.Time

	// Statistics
	totalScreenings int64
	positiveMatches int64
	lastUpdateTime  time.Time

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewIntelService creates a new threat intelligence service.
func NewIntelService(config IntelConfig) *IntelService {
	s := &IntelService{
		config:         config,
		indicators:     make(map[string]*ThreatIndicator),
		screeningCache: make(map[string]*ScreeningResult),
		cacheExpiry:    make(map[string]time.Time),
		ofacAddresses:  make(map[string]*ThreatIndicator),
		stopCh:         make(chan struct{}),
	}

	// Load built-in known bad addresses
	s.loadBuiltInIndicators()

	return s
}

// AddHandler adds an alert handler.
func (s *IntelService) AddHandler(handler AlertHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers = append(s.handlers, handler)
}

// Start starts the intelligence service.
func (s *IntelService) Start(ctx context.Context) error {
	// Initial load
	if s.config.EnableOFAC {
		if err := s.updateOFACList(); err != nil {
			slog.Warn("failed to load OFAC list", "error", err)
		}
	}

	// Start update workers
	s.wg.Add(1)
	go s.updateWorker(ctx)

	slog.Info("threat intelligence service started")
	return nil
}

// Stop stops the intelligence service.
func (s *IntelService) Stop() {
	close(s.stopCh)
	s.wg.Wait()
	slog.Info("threat intelligence service stopped")
}

func (s *IntelService) updateWorker(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.OFACUpdateInterval)
	defer ticker.Stop()

	cacheTicker := time.NewTicker(10 * time.Minute)
	defer cacheTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			if s.config.EnableOFAC {
				if err := s.updateOFACList(); err != nil {
					slog.Error("failed to update OFAC list", "error", err)
				}
			}
		case <-cacheTicker.C:
			s.cleanupCache()
		}
	}
}

// ScreenAddress screens an address against threat intelligence.
func (s *IntelService) ScreenAddress(ctx context.Context, address string) (*ScreeningResult, error) {
	address = strings.ToLower(address)

	// Check cache first
	s.mu.RLock()
	if cached, ok := s.screeningCache[address]; ok {
		if expiry, exists := s.cacheExpiry[address]; exists && time.Now().Before(expiry) {
			s.mu.RUnlock()
			return cached, nil
		}
	}
	s.mu.RUnlock()

	s.mu.Lock()
	s.totalScreenings++
	s.mu.Unlock()

	result := &ScreeningResult{
		Address:    address,
		ScreenedAt: time.Now(),
		Risk:       RiskUnknown,
	}

	var indicators []*ThreatIndicator

	// Check local indicators
	s.mu.RLock()
	if ind, ok := s.indicators[address]; ok {
		indicators = append(indicators, ind)
	}
	if ind, ok := s.ofacAddresses[address]; ok {
		indicators = append(indicators, ind)
	}
	s.mu.RUnlock()

	// Check Chainalysis if enabled
	if s.config.EnableChainalysis && s.config.ChainalysisAPIKey != "" {
		chainalysisIndicators, err := s.checkChainalysis(ctx, address)
		if err != nil {
			slog.Warn("Chainalysis check failed", "error", err)
		} else {
			indicators = append(indicators, chainalysisIndicators...)
		}
	}

	// Process results
	if len(indicators) > 0 {
		result.IsMatch = true
		result.Indicators = indicators
		result.TotalHits = len(indicators)

		// Determine highest risk
		result.Risk = s.calculateOverallRisk(indicators)

		s.mu.Lock()
		s.positiveMatches++
		s.mu.Unlock()

		// Emit alert for high-risk matches
		if result.Risk == RiskCritical || result.Risk == RiskHigh {
			s.emitAlert(ctx, &Alert{
				ID:         uuid.New(),
				Type:       "threat_match",
				Severity:   string(result.Risk),
				Address:    address,
				ThreatType: indicators[0].Type,
				Title:      "Threat Intelligence Match",
				Description: fmt.Sprintf("Address %s matched %d threat indicators",
					address, len(indicators)),
				Timestamp:  time.Now(),
				Indicators: indicators,
			})
		}
	}

	// Cache result
	s.mu.Lock()
	s.screeningCache[address] = result
	s.cacheExpiry[address] = time.Now().Add(s.config.CacheExpiry)
	s.mu.Unlock()

	return result, nil
}

// ScreenTransaction screens all addresses in a transaction.
func (s *IntelService) ScreenTransaction(ctx context.Context, from, to string, contractAddresses []string) ([]*ScreeningResult, error) {
	var results []*ScreeningResult

	addresses := []string{from, to}
	addresses = append(addresses, contractAddresses...)

	for _, addr := range addresses {
		if addr == "" {
			continue
		}
		result, err := s.ScreenAddress(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("failed to screen address %s: %w", addr, err)
		}
		if result.IsMatch {
			results = append(results, result)
		}
	}

	return results, nil
}

// AddIndicator adds a custom threat indicator.
func (s *IntelService) AddIndicator(indicator *ThreatIndicator) {
	s.mu.Lock()
	defer s.mu.Unlock()

	indicator.Value = strings.ToLower(indicator.Value)
	if indicator.ID == "" {
		indicator.ID = uuid.New().String()
	}
	if indicator.FirstSeen.IsZero() {
		indicator.FirstSeen = time.Now()
	}
	indicator.LastSeen = time.Now()

	s.indicators[indicator.Value] = indicator
}

// RemoveIndicator removes a threat indicator.
func (s *IntelService) RemoveIndicator(address string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.indicators, strings.ToLower(address))
}

func (s *IntelService) calculateOverallRisk(indicators []*ThreatIndicator) RiskLevel {
	// Return highest risk level
	riskPriority := map[RiskLevel]int{
		RiskCritical: 4,
		RiskHigh:     3,
		RiskMedium:   2,
		RiskLow:      1,
		RiskUnknown:  0,
	}

	maxRisk := RiskUnknown
	maxPriority := 0

	for _, ind := range indicators {
		if priority := riskPriority[ind.Risk]; priority > maxPriority {
			maxPriority = priority
			maxRisk = ind.Risk
		}
	}

	return maxRisk
}

func (s *IntelService) emitAlert(ctx context.Context, alert *Alert) {
	s.mu.RLock()
	handlers := s.handlers
	s.mu.RUnlock()

	for _, handler := range handlers {
		go func(h AlertHandler) {
			if err := h(ctx, alert); err != nil {
				slog.Error("threat alert handler failed", "error", err)
			}
		}(handler)
	}
}

func (s *IntelService) cleanupCache() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for addr, expiry := range s.cacheExpiry {
		if now.After(expiry) {
			delete(s.screeningCache, addr)
			delete(s.cacheExpiry, addr)
		}
	}
}

func (s *IntelService) updateOFACList() error {
	// OFAC SDN list URL (Treasury's Specially Designated Nationals)
	// In production, this would fetch the actual OFAC list
	// For now, we load known sanctioned crypto addresses

	s.mu.Lock()
	defer s.mu.Unlock()

	// Add known OFAC-sanctioned addresses (examples from public OFAC announcements)
	ofacAddresses := []struct {
		address     string
		description string
	}{
		// Tornado Cash addresses (sanctioned August 2022)
		{"0x8589427373d6d84e98730d7795d8f6f8731fda16", "Tornado Cash: Ethereum Pool"},
		{"0x722122df12d4e14e13ac3b6895a86e84145b6967", "Tornado Cash: Router"},
		{"0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3", "Tornado Cash: USDC Pool"},
		{"0x910cbd523d972eb0a6f4cae4618ad62622b39dbf", "Tornado Cash: 10 ETH"},
		{"0xa160cdab225685da1d56aa342ad8841c3b53f291", "Tornado Cash: 100 ETH"},
		// Lazarus Group addresses
		{"0x098b716b8aaf21512996dc57eb0615e2383e2f96", "Lazarus Group: Ronin Bridge Exploit"},
		{"0xa0e1c89ef1a489c9c7de96311ed5ce5d32c20e4b", "Lazarus Group: Horizon Bridge Exploit"},
		// Blender.io (sanctioned May 2022)
		{"0x57f1887a8bf19b14fc0df6fd9b2acc9af147ea85", "Blender.io Mixer"},
		// Sinbad.io (sanctioned November 2023)
		{"0x4f47bc496083c727c5fbe3ce9cdf2b0f6496270c", "Sinbad.io Mixer"},
	}

	for _, addr := range ofacAddresses {
		s.ofacAddresses[strings.ToLower(addr.address)] = &ThreatIndicator{
			ID:          uuid.New().String(),
			Type:        ThreatSanctioned,
			Value:       strings.ToLower(addr.address),
			Risk:        RiskCritical,
			Source:      "OFAC",
			Description: addr.description,
			Tags:        []string{"ofac", "sanctioned", "sdn"},
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			Confidence:  1.0,
		}
	}

	s.ofacLastUpdate = time.Now()
	slog.Info("OFAC list updated", "addresses", len(s.ofacAddresses))

	return nil
}

func (s *IntelService) checkChainalysis(ctx context.Context, address string) ([]*ThreatIndicator, error) {
	if s.config.ChainalysisAPIURL == "" || s.config.ChainalysisAPIKey == "" {
		return nil, nil
	}

	url := fmt.Sprintf("%s/v2/address/%s", s.config.ChainalysisAPIURL, address)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", s.config.ChainalysisAPIKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Chainalysis API returned %d", resp.StatusCode)
	}

	var result struct {
		Address string `json:"address"`
		Risk    string `json:"risk"`
		Cluster struct {
			Name     string `json:"name"`
			Category string `json:"category"`
		} `json:"cluster"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Map Chainalysis risk to our risk levels
	var risk RiskLevel
	switch strings.ToLower(result.Risk) {
	case "severe", "critical":
		risk = RiskCritical
	case "high":
		risk = RiskHigh
	case "medium":
		risk = RiskMedium
	case "low":
		risk = RiskLow
	default:
		return nil, nil // No significant risk
	}

	return []*ThreatIndicator{{
		ID:          uuid.New().String(),
		Type:        s.mapCategory(result.Cluster.Category),
		Value:       address,
		Risk:        risk,
		Source:      "Chainalysis",
		Description: fmt.Sprintf("%s - %s", result.Cluster.Name, result.Cluster.Category),
		Tags:        []string{"chainalysis", result.Cluster.Category},
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
		Confidence:  0.9,
	}}, nil
}

func (s *IntelService) mapCategory(category string) ThreatType {
	catLower := strings.ToLower(category)
	switch {
	case strings.Contains(catLower, "sanction"):
		return ThreatSanctioned
	case strings.Contains(catLower, "mixer") || strings.Contains(catLower, "tumbler"):
		return ThreatMixer
	case strings.Contains(catLower, "ransomware"):
		return ThreatRansomware
	case strings.Contains(catLower, "scam"):
		return ThreatScam
	case strings.Contains(catLower, "darknet"):
		return ThreatDarknet
	case strings.Contains(catLower, "exploit"):
		return ThreatExploit
	case strings.Contains(catLower, "phishing"):
		return ThreatPhishing
	default:
		return ThreatExploit
	}
}

func (s *IntelService) loadBuiltInIndicators() {
	// Known exploit addresses
	exploits := []struct {
		address     string
		description string
		threatType  ThreatType
		risk        RiskLevel
	}{
		// Major DeFi exploits
		{"0x9c5083dd4838e120dbeac44c052179692aa5c32d", "Euler Finance Exploiter (March 2023)", ThreatExploit, RiskCritical},
		{"0xba12222222228d8ba445958a75a0704d566bf2c8", "Balancer Vault", ThreatFlashLoan, RiskMedium},
		{"0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419", "Chainlink ETH/USD Feed (monitoring)", ThreatExploit, RiskLow},

		// Known rug pulls
		{"0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0", "MATIC Token", ThreatRugPull, RiskLow},

		// Known phishing contracts
		{"0x0000000000000000000000000000000000000001", "Example Phishing Contract", ThreatPhishing, RiskHigh},

		// Known MEV bots (for monitoring, not blocking)
		{"0x98c3d3183c4b8a650614ad179a1a98be0a8d6b8e", "jaredfromsubway.eth MEV Bot", ThreatMEVBot, RiskMedium},
		{"0x6b75d8af000000e20b7a7ddf000ba900b4009a80", "Known Sandwich Bot", ThreatMEVBot, RiskMedium},
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, exp := range exploits {
		s.indicators[strings.ToLower(exp.address)] = &ThreatIndicator{
			ID:          uuid.New().String(),
			Type:        exp.threatType,
			Value:       strings.ToLower(exp.address),
			Risk:        exp.risk,
			Source:      "built-in",
			Description: exp.description,
			Tags:        []string{"built-in", string(exp.threatType)},
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			Confidence:  0.8,
		}
	}
}

// GetStats returns service statistics.
func (s *IntelService) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return map[string]interface{}{
		"total_screenings": s.totalScreenings,
		"positive_matches": s.positiveMatches,
		"indicator_count":  len(s.indicators),
		"ofac_addresses":   len(s.ofacAddresses),
		"cache_size":       len(s.screeningCache),
		"ofac_last_update": s.ofacLastUpdate,
	}
}

// NormalizeToEvent converts a screening result to a schema.Event.
func (s *IntelService) NormalizeToEvent(result *ScreeningResult, tenantID string) *schema.Event {
	severity := 1
	switch result.Risk {
	case RiskCritical:
		severity = 10
	case RiskHigh:
		severity = 8
	case RiskMedium:
		severity = 5
	case RiskLow:
		severity = 3
	}

	metadata := map[string]interface{}{
		"address":    result.Address,
		"is_match":   result.IsMatch,
		"risk_level": string(result.Risk),
		"total_hits": result.TotalHits,
	}

	if len(result.Indicators) > 0 {
		var sources []string
		var types []string
		for _, ind := range result.Indicators {
			sources = append(sources, ind.Source)
			types = append(types, string(ind.Type))
		}
		metadata["sources"] = sources
		metadata["threat_types"] = types
	}

	outcome := schema.OutcomeSuccess
	if result.IsMatch {
		outcome = schema.OutcomeFailure
	}

	return &schema.Event{
		EventID:   uuid.New(),
		Timestamp: result.ScreenedAt,
		TenantID:  tenantID,
		Source: schema.Source{
			Product: "threat-intel",
			Version: "1.0",
		},
		Action:   "threat.screening",
		Outcome:  outcome,
		Severity: severity,
		Target:   result.Address,
		Metadata: metadata,
	}
}

// Address validation regex
var ethereumAddressRegex = regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)

// IsValidEthereumAddress checks if an address is a valid Ethereum address.
func IsValidEthereumAddress(address string) bool {
	return ethereumAddressRegex.MatchString(address)
}
