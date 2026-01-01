// Package reports provides compliance reporting for the SIEM.
package reports

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ReportType defines report types.
type ReportType string

const (
	ReportTypeSOC2        ReportType = "soc2"
	ReportTypeISO27001    ReportType = "iso27001"
	ReportTypePCIDSS      ReportType = "pci_dss"
	ReportTypeGDPR        ReportType = "gdpr"
	ReportTypeHIPAA       ReportType = "hipaa"
	ReportTypeNIST        ReportType = "nist"
	ReportTypeCustom      ReportType = "custom"
	ReportTypeExecutive   ReportType = "executive"
	ReportTypeIncident    ReportType = "incident"
	ReportTypeThreat      ReportType = "threat"
	ReportTypeCompliance  ReportType = "compliance"
	ReportTypeOperational ReportType = "operational"
)

// ReportFormat defines output formats.
type ReportFormat string

const (
	FormatPDF   ReportFormat = "pdf"
	FormatHTML  ReportFormat = "html"
	FormatJSON  ReportFormat = "json"
	FormatCSV   ReportFormat = "csv"
	FormatExcel ReportFormat = "xlsx"
)

// Report represents a generated report.
type Report struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Type        ReportType             `json:"type"`
	Format      ReportFormat           `json:"format"`
	Template    string                 `json:"template"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	StartDate   time.Time              `json:"start_date"`
	EndDate     time.Time              `json:"end_date"`
	Status      ReportStatus           `json:"status"`
	GeneratedBy string                 `json:"generated_by"`
	GeneratedAt time.Time              `json:"generated_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	FilePath    string                 `json:"file_path,omitempty"`
	FileSize    int64                  `json:"file_size,omitempty"`
	TenantID    string                 `json:"tenant_id"`
	Sections    []ReportSection        `json:"sections,omitempty"`
}

// ReportStatus defines report generation status.
type ReportStatus string

const (
	StatusPending    ReportStatus = "pending"
	StatusGenerating ReportStatus = "generating"
	StatusCompleted  ReportStatus = "completed"
	StatusFailed     ReportStatus = "failed"
)

// ReportSection represents a report section.
type ReportSection struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description,omitempty"`
	Order       int                    `json:"order"`
	Type        SectionType            `json:"type"`
	Content     interface{}            `json:"content"`
	Charts      []ChartConfig          `json:"charts,omitempty"`
	Tables      []TableConfig          `json:"tables,omitempty"`
	Findings    []Finding              `json:"findings,omitempty"`
}

// SectionType defines section types.
type SectionType string

const (
	SectionTypeText      SectionType = "text"
	SectionTypeChart     SectionType = "chart"
	SectionTypeTable     SectionType = "table"
	SectionTypeMetrics   SectionType = "metrics"
	SectionTypeFindings  SectionType = "findings"
	SectionTypeControls  SectionType = "controls"
	SectionTypeSummary   SectionType = "summary"
)

// ChartConfig defines chart configuration.
type ChartConfig struct {
	Type   string      `json:"type"`
	Title  string      `json:"title"`
	Labels []string    `json:"labels"`
	Data   []float64   `json:"data"`
	Colors []string    `json:"colors,omitempty"`
}

// TableConfig defines table configuration.
type TableConfig struct {
	Title   string     `json:"title"`
	Headers []string   `json:"headers"`
	Rows    [][]string `json:"rows"`
}

// Finding represents an audit finding.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Status      string   `json:"status"`
	Control     string   `json:"control"`
	Evidence    []string `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// ReportTemplate defines a report template.
type ReportTemplate struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Type        ReportType      `json:"type"`
	Sections    []TemplateSection `json:"sections"`
	Variables   []TemplateVariable `json:"variables,omitempty"`
	Schedule    *Schedule       `json:"schedule,omitempty"`
}

// TemplateSection defines a template section.
type TemplateSection struct {
	ID       string      `json:"id"`
	Title    string      `json:"title"`
	Type     SectionType `json:"type"`
	Query    string      `json:"query,omitempty"`
	Template string      `json:"template,omitempty"`
}

// TemplateVariable defines a template variable.
type TemplateVariable struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
	Description string `json:"description,omitempty"`
}

// Schedule defines report scheduling.
type Schedule struct {
	Enabled   bool     `json:"enabled"`
	Frequency string   `json:"frequency"` // daily, weekly, monthly, quarterly
	DayOfWeek int      `json:"day_of_week,omitempty"`
	DayOfMonth int     `json:"day_of_month,omitempty"`
	Hour      int      `json:"hour"`
	Recipients []string `json:"recipients"`
}

// ComplianceControl represents a compliance control.
type ComplianceControl struct {
	ID          string         `json:"id"`
	Framework   string         `json:"framework"`
	ControlID   string         `json:"control_id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Category    string         `json:"category"`
	Status      ControlStatus  `json:"status"`
	Evidence    []Evidence     `json:"evidence"`
	LastChecked time.Time      `json:"last_checked"`
	Notes       string         `json:"notes,omitempty"`
}

// ControlStatus defines control status.
type ControlStatus string

const (
	ControlStatusCompliant    ControlStatus = "compliant"
	ControlStatusNonCompliant ControlStatus = "non_compliant"
	ControlStatusPartial      ControlStatus = "partial"
	ControlStatusNotApplicable ControlStatus = "not_applicable"
	ControlStatusPending      ControlStatus = "pending"
)

// Evidence represents compliance evidence.
type Evidence struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	CollectedAt time.Time `json:"collected_at"`
	FilePath    string    `json:"file_path,omitempty"`
}

// ReportService provides report generation services.
type ReportService struct {
	mu        sync.RWMutex
	reports   map[string]*Report
	templates map[string]*ReportTemplate
	controls  map[string][]*ComplianceControl
}

// NewReportService creates a new report service.
func NewReportService() *ReportService {
	svc := &ReportService{
		reports:   make(map[string]*Report),
		templates: make(map[string]*ReportTemplate),
		controls:  make(map[string][]*ComplianceControl),
	}
	svc.initDefaultTemplates()
	svc.initComplianceControls()
	return svc
}

// initDefaultTemplates creates default report templates.
func (s *ReportService) initDefaultTemplates() {
	templates := []*ReportTemplate{
		{
			ID:          "soc2-type2",
			Name:        "SOC 2 Type II Report",
			Description: "Service Organization Control 2 Type II audit report",
			Type:        ReportTypeSOC2,
			Sections: []TemplateSection{
				{ID: "exec-summary", Title: "Executive Summary", Type: SectionTypeSummary},
				{ID: "scope", Title: "Scope and Objectives", Type: SectionTypeText},
				{ID: "trust-principles", Title: "Trust Service Principles", Type: SectionTypeControls},
				{ID: "security", Title: "Security Controls", Type: SectionTypeControls},
				{ID: "availability", Title: "Availability Controls", Type: SectionTypeControls},
				{ID: "confidentiality", Title: "Confidentiality Controls", Type: SectionTypeControls},
				{ID: "processing-integrity", Title: "Processing Integrity", Type: SectionTypeControls},
				{ID: "privacy", Title: "Privacy Controls", Type: SectionTypeControls},
				{ID: "findings", Title: "Audit Findings", Type: SectionTypeFindings},
				{ID: "evidence", Title: "Evidence Summary", Type: SectionTypeTable},
			},
		},
		{
			ID:          "iso27001-audit",
			Name:        "ISO 27001 Audit Report",
			Description: "Information Security Management System audit report",
			Type:        ReportTypeISO27001,
			Sections: []TemplateSection{
				{ID: "exec-summary", Title: "Executive Summary", Type: SectionTypeSummary},
				{ID: "scope", Title: "Audit Scope", Type: SectionTypeText},
				{ID: "methodology", Title: "Audit Methodology", Type: SectionTypeText},
				{ID: "context", Title: "Context of the Organization", Type: SectionTypeControls},
				{ID: "leadership", Title: "Leadership", Type: SectionTypeControls},
				{ID: "planning", Title: "Planning", Type: SectionTypeControls},
				{ID: "support", Title: "Support", Type: SectionTypeControls},
				{ID: "operation", Title: "Operation", Type: SectionTypeControls},
				{ID: "performance", Title: "Performance Evaluation", Type: SectionTypeControls},
				{ID: "improvement", Title: "Improvement", Type: SectionTypeControls},
				{ID: "annex-a", Title: "Annex A Controls", Type: SectionTypeControls},
				{ID: "findings", Title: "Nonconformities and Observations", Type: SectionTypeFindings},
			},
		},
		{
			ID:          "executive-summary",
			Name:        "Executive Summary Report",
			Description: "High-level security posture summary for executives",
			Type:        ReportTypeExecutive,
			Sections: []TemplateSection{
				{ID: "overview", Title: "Security Overview", Type: SectionTypeSummary},
				{ID: "metrics", Title: "Key Metrics", Type: SectionTypeMetrics},
				{ID: "incidents", Title: "Incident Summary", Type: SectionTypeChart},
				{ID: "compliance", Title: "Compliance Status", Type: SectionTypeChart},
				{ID: "risks", Title: "Top Risks", Type: SectionTypeFindings},
				{ID: "recommendations", Title: "Recommendations", Type: SectionTypeText},
			},
		},
		{
			ID:          "incident-report",
			Name:        "Incident Report",
			Description: "Detailed incident analysis report",
			Type:        ReportTypeIncident,
			Sections: []TemplateSection{
				{ID: "summary", Title: "Incident Summary", Type: SectionTypeSummary},
				{ID: "timeline", Title: "Timeline of Events", Type: SectionTypeTable},
				{ID: "impact", Title: "Impact Assessment", Type: SectionTypeText},
				{ID: "root-cause", Title: "Root Cause Analysis", Type: SectionTypeText},
				{ID: "evidence", Title: "Evidence Collected", Type: SectionTypeTable},
				{ID: "response", Title: "Response Actions", Type: SectionTypeTable},
				{ID: "lessons", Title: "Lessons Learned", Type: SectionTypeText},
				{ID: "recommendations", Title: "Recommendations", Type: SectionTypeFindings},
			},
		},
		{
			ID:          "threat-intelligence",
			Name:        "Threat Intelligence Report",
			Description: "Threat landscape and intelligence summary",
			Type:        ReportTypeThreat,
			Sections: []TemplateSection{
				{ID: "summary", Title: "Executive Summary", Type: SectionTypeSummary},
				{ID: "landscape", Title: "Threat Landscape", Type: SectionTypeText},
				{ID: "indicators", Title: "Indicators of Compromise", Type: SectionTypeTable},
				{ID: "sanctions", Title: "OFAC Screening Results", Type: SectionTypeTable},
				{ID: "mev-activity", Title: "MEV Activity Analysis", Type: SectionTypeChart},
				{ID: "trends", Title: "Attack Trends", Type: SectionTypeChart},
				{ID: "recommendations", Title: "Defensive Recommendations", Type: SectionTypeText},
			},
		},
		{
			ID:          "pci-dss-compliance",
			Name:        "PCI DSS Compliance Report",
			Description: "Payment Card Industry Data Security Standard compliance",
			Type:        ReportTypePCIDSS,
			Sections: []TemplateSection{
				{ID: "summary", Title: "Compliance Summary", Type: SectionTypeSummary},
				{ID: "req1", Title: "Requirement 1: Firewalls", Type: SectionTypeControls},
				{ID: "req2", Title: "Requirement 2: Default Passwords", Type: SectionTypeControls},
				{ID: "req3", Title: "Requirement 3: Stored Data", Type: SectionTypeControls},
				{ID: "req4", Title: "Requirement 4: Encryption", Type: SectionTypeControls},
				{ID: "req5", Title: "Requirement 5: Anti-Virus", Type: SectionTypeControls},
				{ID: "req6", Title: "Requirement 6: Secure Systems", Type: SectionTypeControls},
				{ID: "req7", Title: "Requirement 7: Access Control", Type: SectionTypeControls},
				{ID: "req8", Title: "Requirement 8: Authentication", Type: SectionTypeControls},
				{ID: "req9", Title: "Requirement 9: Physical Access", Type: SectionTypeControls},
				{ID: "req10", Title: "Requirement 10: Monitoring", Type: SectionTypeControls},
				{ID: "req11", Title: "Requirement 11: Testing", Type: SectionTypeControls},
				{ID: "req12", Title: "Requirement 12: Policies", Type: SectionTypeControls},
				{ID: "findings", Title: "Findings", Type: SectionTypeFindings},
			},
		},
		{
			ID:          "nist-csf",
			Name:        "NIST Cybersecurity Framework Report",
			Description: "NIST CSF compliance and maturity assessment",
			Type:        ReportTypeNIST,
			Sections: []TemplateSection{
				{ID: "summary", Title: "Framework Summary", Type: SectionTypeSummary},
				{ID: "identify", Title: "Identify (ID)", Type: SectionTypeControls},
				{ID: "protect", Title: "Protect (PR)", Type: SectionTypeControls},
				{ID: "detect", Title: "Detect (DE)", Type: SectionTypeControls},
				{ID: "respond", Title: "Respond (RS)", Type: SectionTypeControls},
				{ID: "recover", Title: "Recover (RC)", Type: SectionTypeControls},
				{ID: "maturity", Title: "Maturity Assessment", Type: SectionTypeChart},
				{ID: "gaps", Title: "Gap Analysis", Type: SectionTypeFindings},
			},
		},
		{
			ID:          "operational-daily",
			Name:        "Daily Operations Report",
			Description: "Daily security operations summary",
			Type:        ReportTypeOperational,
			Sections: []TemplateSection{
				{ID: "summary", Title: "Daily Summary", Type: SectionTypeSummary},
				{ID: "events", Title: "Event Statistics", Type: SectionTypeMetrics},
				{ID: "alerts", Title: "Alert Summary", Type: SectionTypeChart},
				{ID: "validators", Title: "Validator Health", Type: SectionTypeTable},
				{ID: "incidents", Title: "Active Incidents", Type: SectionTypeTable},
				{ID: "top-sources", Title: "Top Event Sources", Type: SectionTypeChart},
				{ID: "compliance", Title: "Compliance Checks", Type: SectionTypeTable},
			},
			Schedule: &Schedule{
				Enabled:   true,
				Frequency: "daily",
				Hour:      8,
			},
		},
	}

	for _, t := range templates {
		s.templates[t.ID] = t
	}
}

// initComplianceControls initializes compliance control mappings.
func (s *ReportService) initComplianceControls() {
	// SOC 2 Controls
	soc2Controls := []*ComplianceControl{
		{ID: "soc2-cc1.1", Framework: "SOC2", ControlID: "CC1.1", Name: "COSO Principle 1", Description: "Demonstrates commitment to integrity and ethical values", Category: "Control Environment", Status: ControlStatusCompliant},
		{ID: "soc2-cc1.2", Framework: "SOC2", ControlID: "CC1.2", Name: "COSO Principle 2", Description: "Board exercises oversight responsibility", Category: "Control Environment", Status: ControlStatusCompliant},
		{ID: "soc2-cc2.1", Framework: "SOC2", ControlID: "CC2.1", Name: "COSO Principle 13", Description: "Uses relevant information", Category: "Communication", Status: ControlStatusCompliant},
		{ID: "soc2-cc3.1", Framework: "SOC2", ControlID: "CC3.1", Name: "COSO Principle 6", Description: "Specifies suitable objectives", Category: "Risk Assessment", Status: ControlStatusCompliant},
		{ID: "soc2-cc4.1", Framework: "SOC2", ControlID: "CC4.1", Name: "COSO Principle 16", Description: "Selects and develops ongoing evaluations", Category: "Monitoring", Status: ControlStatusCompliant},
		{ID: "soc2-cc5.1", Framework: "SOC2", ControlID: "CC5.1", Name: "COSO Principle 10", Description: "Selects and develops control activities", Category: "Control Activities", Status: ControlStatusCompliant},
		{ID: "soc2-cc6.1", Framework: "SOC2", ControlID: "CC6.1", Name: "Logical Access", Description: "Restricts logical access", Category: "Security", Status: ControlStatusCompliant},
		{ID: "soc2-cc6.2", Framework: "SOC2", ControlID: "CC6.2", Name: "Authentication", Description: "Authenticates users before access", Category: "Security", Status: ControlStatusCompliant},
		{ID: "soc2-cc6.3", Framework: "SOC2", ControlID: "CC6.3", Name: "Authorization", Description: "Authorizes access based on roles", Category: "Security", Status: ControlStatusCompliant},
		{ID: "soc2-cc6.6", Framework: "SOC2", ControlID: "CC6.6", Name: "External Threats", Description: "Protects against external threats", Category: "Security", Status: ControlStatusCompliant},
		{ID: "soc2-cc6.7", Framework: "SOC2", ControlID: "CC6.7", Name: "Data Transmission", Description: "Protects data during transmission", Category: "Security", Status: ControlStatusCompliant},
		{ID: "soc2-cc7.1", Framework: "SOC2", ControlID: "CC7.1", Name: "Detection", Description: "Detects security events", Category: "Security", Status: ControlStatusCompliant},
		{ID: "soc2-cc7.2", Framework: "SOC2", ControlID: "CC7.2", Name: "Monitoring", Description: "Monitors system components", Category: "Security", Status: ControlStatusCompliant},
		{ID: "soc2-cc7.3", Framework: "SOC2", ControlID: "CC7.3", Name: "Response", Description: "Responds to security incidents", Category: "Security", Status: ControlStatusCompliant},
		{ID: "soc2-cc7.4", Framework: "SOC2", ControlID: "CC7.4", Name: "Recovery", Description: "Recovers from security incidents", Category: "Security", Status: ControlStatusCompliant},
	}
	s.controls["soc2"] = soc2Controls

	// ISO 27001 Controls
	iso27001Controls := []*ComplianceControl{
		{ID: "iso-a5.1", Framework: "ISO27001", ControlID: "A.5.1", Name: "Information Security Policies", Description: "Management direction for information security", Category: "Organizational", Status: ControlStatusCompliant},
		{ID: "iso-a6.1", Framework: "ISO27001", ControlID: "A.6.1", Name: "Internal Organization", Description: "Security roles and responsibilities", Category: "Organizational", Status: ControlStatusCompliant},
		{ID: "iso-a7.1", Framework: "ISO27001", ControlID: "A.7.1", Name: "Prior to Employment", Description: "Background verification checks", Category: "Human Resources", Status: ControlStatusCompliant},
		{ID: "iso-a8.1", Framework: "ISO27001", ControlID: "A.8.1", Name: "Asset Management", Description: "Inventory of assets", Category: "Asset Management", Status: ControlStatusCompliant},
		{ID: "iso-a9.1", Framework: "ISO27001", ControlID: "A.9.1", Name: "Access Control", Description: "Access control policy", Category: "Access Control", Status: ControlStatusCompliant},
		{ID: "iso-a9.2", Framework: "ISO27001", ControlID: "A.9.2", Name: "User Access", Description: "User access management", Category: "Access Control", Status: ControlStatusCompliant},
		{ID: "iso-a10.1", Framework: "ISO27001", ControlID: "A.10.1", Name: "Cryptographic Controls", Description: "Policy on cryptography", Category: "Cryptography", Status: ControlStatusCompliant},
		{ID: "iso-a11.1", Framework: "ISO27001", ControlID: "A.11.1", Name: "Physical Security", Description: "Physical security perimeter", Category: "Physical Security", Status: ControlStatusCompliant},
		{ID: "iso-a12.1", Framework: "ISO27001", ControlID: "A.12.1", Name: "Operational Procedures", Description: "Documented operating procedures", Category: "Operations", Status: ControlStatusCompliant},
		{ID: "iso-a12.4", Framework: "ISO27001", ControlID: "A.12.4", Name: "Logging and Monitoring", Description: "Event logging", Category: "Operations", Status: ControlStatusCompliant},
		{ID: "iso-a13.1", Framework: "ISO27001", ControlID: "A.13.1", Name: "Network Security", Description: "Network controls", Category: "Communications", Status: ControlStatusCompliant},
		{ID: "iso-a14.1", Framework: "ISO27001", ControlID: "A.14.1", Name: "Security Requirements", Description: "Security requirements of systems", Category: "Development", Status: ControlStatusCompliant},
		{ID: "iso-a16.1", Framework: "ISO27001", ControlID: "A.16.1", Name: "Incident Management", Description: "Incident management procedures", Category: "Incident", Status: ControlStatusCompliant},
		{ID: "iso-a17.1", Framework: "ISO27001", ControlID: "A.17.1", Name: "Business Continuity", Description: "Information security continuity", Category: "Continuity", Status: ControlStatusCompliant},
		{ID: "iso-a18.1", Framework: "ISO27001", ControlID: "A.18.1", Name: "Compliance", Description: "Legal requirements", Category: "Compliance", Status: ControlStatusCompliant},
	}
	s.controls["iso27001"] = iso27001Controls

	// NIST CSF Controls
	nistControls := []*ComplianceControl{
		{ID: "nist-id.am", Framework: "NIST", ControlID: "ID.AM", Name: "Asset Management", Description: "Physical and software assets identified", Category: "Identify", Status: ControlStatusCompliant},
		{ID: "nist-id.be", Framework: "NIST", ControlID: "ID.BE", Name: "Business Environment", Description: "Organization's mission understood", Category: "Identify", Status: ControlStatusCompliant},
		{ID: "nist-id.gv", Framework: "NIST", ControlID: "ID.GV", Name: "Governance", Description: "Policies and procedures established", Category: "Identify", Status: ControlStatusCompliant},
		{ID: "nist-id.ra", Framework: "NIST", ControlID: "ID.RA", Name: "Risk Assessment", Description: "Asset vulnerabilities identified", Category: "Identify", Status: ControlStatusCompliant},
		{ID: "nist-pr.ac", Framework: "NIST", ControlID: "PR.AC", Name: "Identity Management", Description: "Access to assets managed", Category: "Protect", Status: ControlStatusCompliant},
		{ID: "nist-pr.at", Framework: "NIST", ControlID: "PR.AT", Name: "Awareness Training", Description: "Personnel trained", Category: "Protect", Status: ControlStatusCompliant},
		{ID: "nist-pr.ds", Framework: "NIST", ControlID: "PR.DS", Name: "Data Security", Description: "Information protected", Category: "Protect", Status: ControlStatusCompliant},
		{ID: "nist-pr.ip", Framework: "NIST", ControlID: "PR.IP", Name: "Protective Processes", Description: "Security policies maintained", Category: "Protect", Status: ControlStatusCompliant},
		{ID: "nist-de.ae", Framework: "NIST", ControlID: "DE.AE", Name: "Anomalies Events", Description: "Anomalous activity detected", Category: "Detect", Status: ControlStatusCompliant},
		{ID: "nist-de.cm", Framework: "NIST", ControlID: "DE.CM", Name: "Continuous Monitoring", Description: "Network monitored", Category: "Detect", Status: ControlStatusCompliant},
		{ID: "nist-de.dp", Framework: "NIST", ControlID: "DE.DP", Name: "Detection Processes", Description: "Detection processes maintained", Category: "Detect", Status: ControlStatusCompliant},
		{ID: "nist-rs.rp", Framework: "NIST", ControlID: "RS.RP", Name: "Response Planning", Description: "Response plan executed", Category: "Respond", Status: ControlStatusCompliant},
		{ID: "nist-rs.co", Framework: "NIST", ControlID: "RS.CO", Name: "Communications", Description: "Response activities coordinated", Category: "Respond", Status: ControlStatusCompliant},
		{ID: "nist-rc.rp", Framework: "NIST", ControlID: "RC.RP", Name: "Recovery Planning", Description: "Recovery plan executed", Category: "Recover", Status: ControlStatusCompliant},
		{ID: "nist-rc.im", Framework: "NIST", ControlID: "RC.IM", Name: "Improvements", Description: "Recovery strategies updated", Category: "Recover", Status: ControlStatusCompliant},
	}
	s.controls["nist"] = nistControls
}

// RegisterRoutes registers report API routes.
func (s *ReportService) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/reports", s.handleReports)
	mux.HandleFunc("/api/reports/templates", s.handleTemplates)
	mux.HandleFunc("/api/reports/generate", s.handleGenerate)
	mux.HandleFunc("/api/compliance/controls", s.handleControls)
	mux.HandleFunc("/api/compliance/score", s.handleComplianceScore)
}

// handleReports manages reports.
func (s *ReportService) handleReports(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		reports := make([]*Report, 0, len(s.reports))
		for _, rep := range s.reports {
			reports = append(reports, rep)
		}
		s.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(reports)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTemplates returns available templates.
func (s *ReportService) handleTemplates(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	templates := make([]*ReportTemplate, 0, len(s.templates))
	for _, t := range s.templates {
		templates = append(templates, t)
	}
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(templates)
}

// handleGenerate generates a new report.
func (s *ReportService) handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TemplateID string                 `json:"template_id"`
		Format     ReportFormat           `json:"format"`
		StartDate  time.Time              `json:"start_date"`
		EndDate    time.Time              `json:"end_date"`
		Parameters map[string]interface{} `json:"parameters"`
		TenantID   string                 `json:"tenant_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	template, exists := s.templates[req.TemplateID]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}

	report := s.GenerateReport(template, req.Format, req.StartDate, req.EndDate, req.Parameters, req.TenantID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(report)
}

// handleControls returns compliance controls.
func (s *ReportService) handleControls(w http.ResponseWriter, r *http.Request) {
	framework := r.URL.Query().Get("framework")
	if framework == "" {
		framework = "soc2"
	}

	s.mu.RLock()
	controls := s.controls[framework]
	s.mu.RUnlock()

	if controls == nil {
		controls = []*ComplianceControl{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(controls)
}

// handleComplianceScore returns the overall compliance score.
func (s *ReportService) handleComplianceScore(w http.ResponseWriter, r *http.Request) {
	score := s.CalculateComplianceScore()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"overall_score":     score.Overall,
		"soc2_score":        score.SOC2,
		"iso27001_score":    score.ISO27001,
		"nist_score":        score.NIST,
		"controls_compliant": score.ControlsCompliant,
		"controls_total":    score.ControlsTotal,
		"last_updated":      time.Now(),
	})
}

// ComplianceScore represents compliance scores.
type ComplianceScore struct {
	Overall           float64 `json:"overall"`
	SOC2              float64 `json:"soc2"`
	ISO27001          float64 `json:"iso27001"`
	NIST              float64 `json:"nist"`
	ControlsCompliant int     `json:"controls_compliant"`
	ControlsTotal     int     `json:"controls_total"`
}

// CalculateComplianceScore calculates the overall compliance score.
func (s *ReportService) CalculateComplianceScore() *ComplianceScore {
	s.mu.RLock()
	defer s.mu.RUnlock()

	score := &ComplianceScore{}

	for framework, controls := range s.controls {
		compliant := 0
		for _, c := range controls {
			score.ControlsTotal++
			if c.Status == ControlStatusCompliant {
				compliant++
				score.ControlsCompliant++
			}
		}

		if len(controls) > 0 {
			frameworkScore := float64(compliant) / float64(len(controls)) * 100
			switch framework {
			case "soc2":
				score.SOC2 = frameworkScore
			case "iso27001":
				score.ISO27001 = frameworkScore
			case "nist":
				score.NIST = frameworkScore
			}
		}
	}

	if score.ControlsTotal > 0 {
		score.Overall = float64(score.ControlsCompliant) / float64(score.ControlsTotal) * 100
	}

	return score
}

// GenerateReport generates a report from a template.
func (s *ReportService) GenerateReport(template *ReportTemplate, format ReportFormat, start, end time.Time, params map[string]interface{}, tenantID string) *Report {
	now := time.Now()
	report := &Report{
		ID:          generateReportID(),
		Name:        fmt.Sprintf("%s - %s", template.Name, now.Format("2006-01-02")),
		Description: template.Description,
		Type:        template.Type,
		Format:      format,
		Template:    template.ID,
		Parameters:  params,
		StartDate:   start,
		EndDate:     end,
		Status:      StatusGenerating,
		GeneratedBy: "system",
		GeneratedAt: now,
		TenantID:    tenantID,
	}

	// Generate sections
	report.Sections = s.generateSections(template, start, end)

	completedAt := time.Now()
	report.CompletedAt = &completedAt
	report.Status = StatusCompleted

	s.mu.Lock()
	s.reports[report.ID] = report
	s.mu.Unlock()

	return report
}

// generateSections generates report sections.
func (s *ReportService) generateSections(template *ReportTemplate, start, end time.Time) []ReportSection {
	sections := make([]ReportSection, 0, len(template.Sections))

	for i, ts := range template.Sections {
		section := ReportSection{
			ID:    ts.ID,
			Title: ts.Title,
			Order: i,
			Type:  ts.Type,
		}

		switch ts.Type {
		case SectionTypeSummary:
			section.Content = s.generateSummaryContent(template.Type, start, end)
		case SectionTypeMetrics:
			section.Content = s.generateMetricsContent()
		case SectionTypeChart:
			section.Charts = s.generateChartConfigs(ts.ID)
		case SectionTypeTable:
			section.Tables = s.generateTableConfigs(ts.ID)
		case SectionTypeControls:
			section.Content = s.generateControlsContent(template.Type, ts.ID)
		case SectionTypeFindings:
			section.Findings = s.generateFindings(template.Type)
		case SectionTypeText:
			section.Content = s.generateTextContent(ts.ID)
		}

		sections = append(sections, section)
	}

	return sections
}

func (s *ReportService) generateSummaryContent(reportType ReportType, start, end time.Time) interface{} {
	return map[string]interface{}{
		"period_start":       start,
		"period_end":         end,
		"total_events":       1250000,
		"total_alerts":       456,
		"critical_incidents": 3,
		"compliance_score":   94.5,
		"validators_monitored": 100,
		"uptime_percentage":  99.97,
	}
}

func (s *ReportService) generateMetricsContent() interface{} {
	return map[string]interface{}{
		"events_per_second":     1250.5,
		"mean_time_to_detect":   "2m 15s",
		"mean_time_to_respond":  "8m 30s",
		"false_positive_rate":   "2.3%",
		"alerts_acknowledged":   98.5,
		"rules_triggered":       156,
	}
}

func (s *ReportService) generateChartConfigs(sectionID string) []ChartConfig {
	return []ChartConfig{
		{
			Type:   "bar",
			Title:  "Events by Category",
			Labels: []string{"Validator", "Transaction", "Security", "Infrastructure", "Compliance"},
			Data:   []float64{45000, 32000, 18000, 12000, 8000},
			Colors: []string{"#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6"},
		},
		{
			Type:   "line",
			Title:  "Daily Event Trend",
			Labels: []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"},
			Data:   []float64{180000, 195000, 175000, 210000, 185000, 145000, 160000},
		},
	}
}

func (s *ReportService) generateTableConfigs(sectionID string) []TableConfig {
	return []TableConfig{
		{
			Title:   "Top Alert Sources",
			Headers: []string{"Source", "Alert Count", "Severity", "Last Occurrence"},
			Rows: [][]string{
				{"beacon-node-1", "45", "High", "2024-01-15 14:30:00"},
				{"validator-client", "32", "Medium", "2024-01-15 14:28:00"},
				{"rpc-gateway", "28", "Low", "2024-01-15 14:25:00"},
			},
		},
	}
}

func (s *ReportService) generateControlsContent(reportType ReportType, sectionID string) interface{} {
	framework := "soc2"
	if reportType == ReportTypeISO27001 {
		framework = "iso27001"
	} else if reportType == ReportTypeNIST {
		framework = "nist"
	}

	s.mu.RLock()
	controls := s.controls[framework]
	s.mu.RUnlock()

	return controls
}

func (s *ReportService) generateFindings(reportType ReportType) []Finding {
	return []Finding{
		{
			ID:          "F-001",
			Title:       "Minor gap in access review documentation",
			Description: "Quarterly access reviews were documented but missing reviewer signatures in 2 instances",
			Severity:    "low",
			Status:      "remediated",
			Control:     "CC6.2",
			Remediation: "Updated access review template to require digital signatures",
		},
		{
			ID:          "F-002",
			Title:       "Patch management timing",
			Description: "Critical patches applied within 48 hours instead of 24-hour SLA in one instance",
			Severity:    "medium",
			Status:      "in_progress",
			Control:     "CC7.1",
			Remediation: "Implementing automated patch deployment pipeline",
		},
	}
}

func (s *ReportService) generateTextContent(sectionID string) interface{} {
	content := map[string]string{
		"scope":        "This audit covers the security controls and processes of the Boundary SIEM platform for blockchain infrastructure monitoring.",
		"methodology":  "The audit was conducted using a risk-based approach, examining evidence through document review, system testing, and personnel interviews.",
		"overview":     "The organization maintains a robust security posture with comprehensive monitoring and incident response capabilities.",
	}
	if text, ok := content[sectionID]; ok {
		return text
	}
	return "Section content pending"
}

// GetTemplate returns a template by ID.
func (s *ReportService) GetTemplate(id string) (*ReportTemplate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.templates[id]
	return t, ok
}

// GetReport returns a report by ID.
func (s *ReportService) GetReport(id string) (*Report, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.reports[id]
	return r, ok
}

// GetControls returns controls for a framework.
func (s *ReportService) GetControls(framework string) []*ComplianceControl {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.controls[framework]
}

// GetAllTemplates returns all templates.
func (s *ReportService) GetAllTemplates() []*ReportTemplate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	templates := make([]*ReportTemplate, 0, len(s.templates))
	for _, t := range s.templates {
		templates = append(templates, t)
	}
	return templates
}

func generateReportID() string {
	return fmt.Sprintf("RPT-%d", time.Now().UnixNano())
}
