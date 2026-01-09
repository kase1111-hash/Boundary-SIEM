// Package cloud provides cloud provider log parsing capabilities.
package cloud

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"boundary-siem/internal/correlation"
	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// Provider represents a cloud provider.
type Provider string

const (
	ProviderAWS   Provider = "aws"
	ProviderGCP   Provider = "gcp"
	ProviderAzure Provider = "azure"
)

// LogType categorizes cloud log types.
type LogType string

const (
	LogTypeAudit    LogType = "audit"
	LogTypeFlow     LogType = "flow"
	LogTypeAccess   LogType = "access"
	LogTypeActivity LogType = "activity"
	LogTypeMetric   LogType = "metric"
	LogTypeSecurity LogType = "security"
)

// CloudLog represents a parsed cloud log entry.
type CloudLog struct {
	Provider  Provider               `json:"provider"`
	LogType   LogType                `json:"log_type"`
	Timestamp time.Time              `json:"timestamp"`
	EventID   string                 `json:"event_id"`
	EventName string                 `json:"event_name"`
	Region    string                 `json:"region"`
	AccountID string                 `json:"account_id"`
	UserID    string                 `json:"user_id,omitempty"`
	SourceIP  string                 `json:"source_ip,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	Resource  string                 `json:"resource,omitempty"`
	Action    string                 `json:"action,omitempty"`
	Result    string                 `json:"result,omitempty"`
	ErrorCode string                 `json:"error_code,omitempty"`
	Severity  int                    `json:"severity"`
	Raw       string                 `json:"raw,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Parser parses cloud provider logs.
type Parser struct {
	provider Provider
}

// NewParser creates a new cloud log parser.
func NewParser(provider Provider) *Parser {
	return &Parser{provider: provider}
}

// Parse parses a log line based on provider.
func (p *Parser) Parse(line string) (*CloudLog, error) {
	switch p.provider {
	case ProviderAWS:
		return p.parseAWS(line)
	case ProviderGCP:
		return p.parseGCP(line)
	case ProviderAzure:
		return p.parseAzure(line)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", p.provider)
	}
}

// parseAWS parses AWS CloudTrail logs.
func (p *Parser) parseAWS(line string) (*CloudLog, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil, fmt.Errorf("invalid AWS CloudTrail JSON: %w", err)
	}

	log := &CloudLog{
		Provider: ProviderAWS,
		LogType:  LogTypeAudit,
		Raw:      line,
		Metadata: make(map[string]interface{}),
	}

	// Parse CloudTrail fields
	if eventTime, ok := raw["eventTime"].(string); ok {
		t, _ := time.Parse(time.RFC3339, eventTime)
		log.Timestamp = t
	} else {
		log.Timestamp = time.Now()
	}

	if eventID, ok := raw["eventID"].(string); ok {
		log.EventID = eventID
	}
	if eventName, ok := raw["eventName"].(string); ok {
		log.EventName = eventName
	}
	if region, ok := raw["awsRegion"].(string); ok {
		log.Region = region
	}
	if accountID, ok := raw["recipientAccountId"].(string); ok {
		log.AccountID = accountID
	}

	// User identity
	if userIdentity, ok := raw["userIdentity"].(map[string]interface{}); ok {
		if arn, ok := userIdentity["arn"].(string); ok {
			log.UserID = arn
		}
		if userName, ok := userIdentity["userName"].(string); ok {
			log.Metadata["user_name"] = userName
		}
		if userType, ok := userIdentity["type"].(string); ok {
			log.Metadata["user_type"] = userType
		}
	}

	// Source IP
	if sourceIP, ok := raw["sourceIPAddress"].(string); ok {
		log.SourceIP = sourceIP
	}
	if userAgent, ok := raw["userAgent"].(string); ok {
		log.UserAgent = userAgent
	}

	// Error handling
	if errorCode, ok := raw["errorCode"].(string); ok {
		log.ErrorCode = errorCode
		log.Result = "failure"
	} else {
		log.Result = "success"
	}

	// Classify severity
	log.Severity = p.classifyAWSSeverity(log.EventName, log.ErrorCode)
	log.Action = p.classifyAWSAction(log.EventName)

	// Add request parameters
	if requestParams, ok := raw["requestParameters"].(map[string]interface{}); ok {
		log.Metadata["request_parameters"] = requestParams
	}

	return log, nil
}

func (p *Parser) classifyAWSSeverity(eventName, errorCode string) int {
	// High severity events
	highSeverityEvents := []string{
		"CreateUser", "DeleteUser", "AttachUserPolicy", "AttachRolePolicy",
		"CreateAccessKey", "DeleteAccessKey", "CreateLoginProfile",
		"UpdateAssumeRolePolicy", "PutBucketPolicy", "DeleteBucketPolicy",
		"StopLogging", "DeleteTrail", "UpdateTrail",
		"CreateSecurityGroup", "AuthorizeSecurityGroupIngress",
		"ModifyInstanceAttribute", "RunInstances",
	}

	// Critical severity events
	criticalEvents := []string{
		"ConsoleLogin", "AssumeRole", "GetSessionToken",
		"DeleteBucket", "DeleteDBInstance", "TerminateInstances",
		"ModifyDBCluster", "CreateNetworkAclEntry",
	}

	eventLower := strings.ToLower(eventName)

	for _, e := range criticalEvents {
		if strings.EqualFold(eventName, e) {
			if errorCode != "" {
				return 6 // Failed critical action
			}
			return 8
		}
	}

	for _, e := range highSeverityEvents {
		if strings.EqualFold(eventName, e) {
			return 6
		}
	}

	// Error conditions
	if errorCode != "" {
		if strings.Contains(errorCode, "Unauthorized") || strings.Contains(errorCode, "AccessDenied") {
			return 5
		}
		return 4
	}

	// Read operations
	if strings.HasPrefix(eventLower, "get") || strings.HasPrefix(eventLower, "list") ||
		strings.HasPrefix(eventLower, "describe") {
		return 2
	}

	return 3
}

func (p *Parser) classifyAWSAction(eventName string) string {
	eventLower := strings.ToLower(eventName)

	if strings.HasPrefix(eventLower, "create") {
		return "resource.create"
	}
	if strings.HasPrefix(eventLower, "delete") {
		return "resource.delete"
	}
	if strings.HasPrefix(eventLower, "update") || strings.HasPrefix(eventLower, "modify") {
		return "resource.modify"
	}
	if strings.HasPrefix(eventLower, "attach") || strings.HasPrefix(eventLower, "put") {
		return "policy.attach"
	}
	if strings.HasPrefix(eventLower, "detach") || strings.HasPrefix(eventLower, "remove") {
		return "policy.detach"
	}
	if eventLower == "consolelogin" {
		return "auth.login"
	}
	if eventLower == "assumerole" || eventLower == "getsessiontoken" {
		return "auth.assume_role"
	}

	return fmt.Sprintf("aws.%s", eventLower)
}

// parseGCP parses GCP Cloud Audit logs.
func (p *Parser) parseGCP(line string) (*CloudLog, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil, fmt.Errorf("invalid GCP log JSON: %w", err)
	}

	log := &CloudLog{
		Provider: ProviderGCP,
		LogType:  LogTypeAudit,
		Raw:      line,
		Metadata: make(map[string]interface{}),
	}

	// Parse GCP fields
	if ts, ok := raw["timestamp"].(string); ok {
		t, _ := time.Parse(time.RFC3339Nano, ts)
		log.Timestamp = t
	} else {
		log.Timestamp = time.Now()
	}

	if insertId, ok := raw["insertId"].(string); ok {
		log.EventID = insertId
	}

	// Proto payload (audit log)
	if protoPayload, ok := raw["protoPayload"].(map[string]interface{}); ok {
		if methodName, ok := protoPayload["methodName"].(string); ok {
			log.EventName = methodName
		}
		if serviceName, ok := protoPayload["serviceName"].(string); ok {
			log.Metadata["service_name"] = serviceName
		}

		// Authentication info
		if authInfo, ok := protoPayload["authenticationInfo"].(map[string]interface{}); ok {
			if principal, ok := authInfo["principalEmail"].(string); ok {
				log.UserID = principal
			}
		}

		// Request metadata
		if requestMetadata, ok := protoPayload["requestMetadata"].(map[string]interface{}); ok {
			if callerIP, ok := requestMetadata["callerIp"].(string); ok {
				log.SourceIP = callerIP
			}
			if callerAgent, ok := requestMetadata["callerSuppliedUserAgent"].(string); ok {
				log.UserAgent = callerAgent
			}
		}

		// Status
		if status, ok := protoPayload["status"].(map[string]interface{}); ok {
			if code, ok := status["code"].(float64); ok {
				if code != 0 {
					log.Result = "failure"
					log.ErrorCode = fmt.Sprintf("%v", code)
				} else {
					log.Result = "success"
				}
			}
		} else {
			log.Result = "success"
		}
	}

	// Resource
	if resource, ok := raw["resource"].(map[string]interface{}); ok {
		if resType, ok := resource["type"].(string); ok {
			log.Resource = resType
		}
		if labels, ok := resource["labels"].(map[string]interface{}); ok {
			if projectId, ok := labels["project_id"].(string); ok {
				log.AccountID = projectId
			}
			if zone, ok := labels["zone"].(string); ok {
				log.Region = zone
			}
		}
	}

	log.Severity = p.classifyGCPSeverity(log.EventName)
	log.Action = p.classifyGCPAction(log.EventName)

	return log, nil
}

func (p *Parser) classifyGCPSeverity(methodName string) int {
	methodLower := strings.ToLower(methodName)

	// Critical operations
	if strings.Contains(methodLower, "delete") && (strings.Contains(methodLower, "bucket") ||
		strings.Contains(methodLower, "instance") || strings.Contains(methodLower, "project")) {
		return 8
	}

	// High severity
	if strings.Contains(methodLower, "setiampolicy") || strings.Contains(methodLower, "setiam") {
		return 7
	}
	if strings.Contains(methodLower, "create") && strings.Contains(methodLower, "serviceaccount") {
		return 6
	}

	// Medium
	if strings.Contains(methodLower, "insert") || strings.Contains(methodLower, "update") {
		return 4
	}

	// Low for read operations
	if strings.Contains(methodLower, "get") || strings.Contains(methodLower, "list") {
		return 2
	}

	return 3
}

func (p *Parser) classifyGCPAction(methodName string) string {
	parts := strings.Split(methodName, ".")
	if len(parts) > 0 {
		action := parts[len(parts)-1]
		return fmt.Sprintf("gcp.%s", strings.ToLower(action))
	}
	return "gcp.unknown"
}

// parseAzure parses Azure Activity logs.
func (p *Parser) parseAzure(line string) (*CloudLog, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil, fmt.Errorf("invalid Azure log JSON: %w", err)
	}

	log := &CloudLog{
		Provider: ProviderAzure,
		LogType:  LogTypeActivity,
		Raw:      line,
		Metadata: make(map[string]interface{}),
	}

	// Parse Azure fields
	if ts, ok := raw["time"].(string); ok {
		t, _ := time.Parse(time.RFC3339, ts)
		log.Timestamp = t
	} else {
		log.Timestamp = time.Now()
	}

	if operationName, ok := raw["operationName"].(string); ok {
		log.EventName = operationName
	}
	if correlationId, ok := raw["correlationId"].(string); ok {
		log.EventID = correlationId
	}

	// Caller identity
	if caller, ok := raw["caller"].(string); ok {
		log.UserID = caller
	}
	if callerIpAddress, ok := raw["callerIpAddress"].(string); ok {
		log.SourceIP = callerIpAddress
	}

	// Resource
	if resourceId, ok := raw["resourceId"].(string); ok {
		log.Resource = resourceId
		// Extract subscription ID from resource ID
		if strings.Contains(resourceId, "/subscriptions/") {
			parts := strings.Split(resourceId, "/")
			for i, part := range parts {
				if part == "subscriptions" && i+1 < len(parts) {
					log.AccountID = parts[i+1]
					break
				}
			}
		}
	}

	// Result
	if resultType, ok := raw["resultType"].(string); ok {
		if resultType == "Success" {
			log.Result = "success"
		} else {
			log.Result = "failure"
		}
	}
	if resultSignature, ok := raw["resultSignature"].(string); ok {
		log.ErrorCode = resultSignature
	}

	// Properties
	if properties, ok := raw["properties"].(map[string]interface{}); ok {
		log.Metadata["properties"] = properties
	}

	log.Severity = p.classifyAzureSeverity(log.EventName)
	log.Action = p.classifyAzureAction(log.EventName)

	return log, nil
}

func (p *Parser) classifyAzureSeverity(operationName string) int {
	opLower := strings.ToLower(operationName)

	// Critical
	if strings.Contains(opLower, "delete") && (strings.Contains(opLower, "resourcegroup") ||
		strings.Contains(opLower, "virtualmachines") || strings.Contains(opLower, "storage")) {
		return 8
	}

	// High
	if strings.Contains(opLower, "roleassignments") || strings.Contains(opLower, "policies") {
		return 6
	}

	// Medium
	if strings.Contains(opLower, "write") || strings.Contains(opLower, "action") {
		return 4
	}

	// Low
	if strings.Contains(opLower, "read") {
		return 2
	}

	return 3
}

func (p *Parser) classifyAzureAction(operationName string) string {
	parts := strings.Split(operationName, "/")
	if len(parts) > 0 {
		action := parts[len(parts)-1]
		return fmt.Sprintf("azure.%s", strings.ToLower(action))
	}
	return "azure.unknown"
}

// Normalize converts a CloudLog to a schema.Event.
func (p *Parser) Normalize(log *CloudLog, tenantID string) (*schema.Event, error) {
	outcome := schema.OutcomeSuccess
	if log.Result == "failure" {
		outcome = schema.OutcomeFailure
	}

	metadata := map[string]interface{}{
		"provider":   string(log.Provider),
		"log_type":   string(log.LogType),
		"event_name": log.EventName,
		"region":     log.Region,
		"account_id": log.AccountID,
	}

	if log.ErrorCode != "" {
		metadata["error_code"] = log.ErrorCode
	}
	if log.Resource != "" {
		metadata["resource"] = log.Resource
	}
	if log.UserAgent != "" {
		metadata["user_agent"] = log.UserAgent
	}
	for k, v := range log.Metadata {
		metadata[k] = v
	}

	var actor *schema.Actor
	if log.UserID != "" {
		actor = &schema.Actor{
			ID:        log.UserID,
			Type:      schema.ActorUser,
			IPAddress: log.SourceIP,
		}
	}

	return &schema.Event{
		EventID:   uuid.New(),
		Timestamp: log.Timestamp,
		TenantID:  tenantID,
		Source: schema.Source{
			Product: fmt.Sprintf("%s-logs", log.Provider),
			Host:    log.Region,
			Version: "1.0",
		},
		Action:   log.Action,
		Outcome:  outcome,
		Severity: log.Severity,
		Target:   log.Resource,
		Actor:    actor,
		Metadata: metadata,
		Raw:      log.Raw,
	}, nil
}

// CreateCorrelationRules creates cloud security correlation rules.
func CreateCorrelationRules() []*correlation.Rule {
	return []*correlation.Rule{
		{
			ID:          "cloud-unauthorized-access",
			Name:        "Cloud Unauthorized Access Attempts",
			Description: "Multiple unauthorized access attempts to cloud resources",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"cloud", "security", "access-denied"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0001",
				TacticName:  "Initial Access",
				TechniqueID: "T1078",
			},
			EventConditions: []correlation.Condition{
				{Field: "outcome", Operator: "eq", Value: "failure"},
				{Field: "metadata.error_code", Operator: "contains", Value: "Unauthorized"},
			},
			GroupBy: []string{"actor.id"},
			Window:  10 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    5,
				Operator: "gte",
			},
		},
		{
			ID:          "cloud-iam-change",
			Name:        "Cloud IAM Policy Change",
			Description: "IAM policy or role modification detected",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"cloud", "iam", "policy"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "in", Values: []string{
					"policy.attach", "policy.detach",
					"gcp.setiampolicy", "azure.roleassignments",
				}},
			},
			GroupBy: []string{"metadata.account_id"},
			Window:  1 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "cloud-resource-deletion",
			Name:        "Critical Cloud Resource Deletion",
			Description: "Critical cloud resource was deleted",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"cloud", "deletion", "critical"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "resource.delete"},
				{Field: "outcome", Operator: "eq", Value: "success"},
			},
			GroupBy: []string{"metadata.account_id"},
			Window:  15 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "cloud-console-login-anomaly",
			Name:        "Unusual Console Login",
			Description: "Console login from unusual location or pattern",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityMedium),
			Tags:        []string{"cloud", "authentication", "login"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "auth.login"},
			},
			GroupBy: []string{"actor.id", "actor.ip"},
			Window:  24 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "cloud-logging-disabled",
			Name:        "Cloud Logging Disabled",
			Description: "Cloud audit logging was disabled or modified",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"cloud", "logging", "evasion"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0005",
				TacticName:  "Defense Evasion",
				TechniqueID: "T1562.008",
			},
			EventConditions: []correlation.Condition{
				{Field: "metadata.event_name", Operator: "in", Values: []string{
					"StopLogging", "DeleteTrail", "UpdateTrail",
					"logging.sinks.delete", "logging.logServices.delete",
				}},
			},
			GroupBy: []string{"metadata.account_id"},
			Window:  1 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
	}
}
