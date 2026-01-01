# Step 3: CEF Ingestion

**Objective:** Implement Common Event Format (CEF) ingestion over UDP and TCP, with parsing and normalization to the canonical event schema.

**Estimated Complexity:** Medium
**Dependencies:** Step 1 (Ingest Foundation), Step 2 (Storage Engine)

---

## Why This Step?

CEF (Common Event Format) is a widely-adopted log format used by security products. Adding CEF support:

1. **Enables boundary-daemon integration** via standard syslog/CEF output
2. **Supports existing security tools** (firewalls, IDS/IPS, endpoint agents)
3. **Proves multi-source capability** required for MVP SIEM status
4. **Handles high-volume UDP** for performance-critical sources

After this step, the SIEM can ingest from both JSON HTTP and CEF UDP/TCP sources.

---

## CEF Format Overview

### CEF Structure

```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

### Example CEF Messages

```
CEF:0|Boundary|boundary-daemon|1.0.0|100|Session Created|3|src=192.168.1.10 suser=admin dhost=db-prod-01 outcome=success

CEF:0|Boundary|boundary-daemon|1.0.0|401|Authentication Failed|7|src=10.0.0.50 suser=unknown dhost=api-server-01 outcome=failure reason=invalid_credentials

CEF:0|PaloAlto|Firewall|9.1|THREAT|Malware Detected|9|src=203.0.113.50 dst=192.168.1.100 spt=443 dpt=8080 act=blocked filePath=/tmp/malware.exe
```

### CEF Severity Mapping

| CEF Severity | SIEM Severity | Description |
|--------------|---------------|-------------|
| 0-3 | 1-3 | Low |
| 4-6 | 4-6 | Medium |
| 7-8 | 7-8 | High |
| 9-10 | 9-10 | Critical |

---

## Deliverables

### 1. Project Structure Additions

```
boundary-siem/
├── internal/
│   ├── ingest/
│   │   ├── cef/
│   │   │   ├── parser.go           # CEF format parser
│   │   │   ├── parser_test.go
│   │   │   ├── normalizer.go       # CEF to canonical schema
│   │   │   ├── normalizer_test.go
│   │   │   ├── extensions.go       # CEF extension field mapping
│   │   │   └── extensions_test.go
│   │   ├── udp_server.go           # UDP listener
│   │   ├── udp_server_test.go
│   │   ├── tcp_server.go           # TCP listener with framing
│   │   └── tcp_server_test.go
│   └── config/
│       └── config.go               # Updated with CEF settings
├── configs/
│   └── cef-mappings.yaml           # Custom field mappings
└── scripts/
    ├── test-cef-udp.sh
    └── test-cef-tcp.sh
```

### 2. CEF Parser

```go
// internal/ingest/cef/parser.go
package cef

import (
    "errors"
    "fmt"
    "regexp"
    "strconv"
    "strings"
)

var (
    ErrInvalidCEF      = errors.New("invalid CEF format")
    ErrMissingVersion  = errors.New("missing CEF version")
    ErrInvalidSeverity = errors.New("invalid severity value")
)

// CEFEvent represents a parsed CEF message
type CEFEvent struct {
    Version       int
    DeviceVendor  string
    DeviceProduct string
    DeviceVersion string
    SignatureID   string
    Name          string
    Severity      int
    Extensions    map[string]string
    RawMessage    string
}

// Parser handles CEF message parsing
type Parser struct {
    strictMode     bool
    maxExtensions  int
    extensionRegex *regexp.Regexp
}

func NewParser(strictMode bool, maxExtensions int) *Parser {
    return &Parser{
        strictMode:     strictMode,
        maxExtensions:  maxExtensions,
        extensionRegex: regexp.MustCompile(`(\w+)=`),
    }
}

// Parse parses a CEF message string into a CEFEvent
func (p *Parser) Parse(message string) (*CEFEvent, error) {
    message = strings.TrimSpace(message)

    // Check for CEF prefix
    if !strings.HasPrefix(message, "CEF:") {
        return nil, ErrInvalidCEF
    }

    // Remove CEF: prefix
    content := message[4:]

    // Split into header and extension parts
    // Header has 7 pipe-delimited fields, extension is everything after
    parts := p.splitHeader(content)
    if len(parts) < 7 {
        return nil, fmt.Errorf("%w: expected 7 header fields, got %d", ErrInvalidCEF, len(parts))
    }

    // Parse version
    version, err := strconv.Atoi(parts[0])
    if err != nil {
        return nil, fmt.Errorf("%w: %v", ErrMissingVersion, err)
    }

    // Parse severity
    severity, err := strconv.Atoi(parts[5])
    if err != nil || severity < 0 || severity > 10 {
        if p.strictMode {
            return nil, fmt.Errorf("%w: %s", ErrInvalidSeverity, parts[5])
        }
        severity = 5 // Default to medium if not strict
    }

    // Parse extensions
    extensions := make(map[string]string)
    if len(parts) > 6 && parts[6] != "" {
        extensions = p.parseExtensions(parts[6])
    }

    return &CEFEvent{
        Version:       version,
        DeviceVendor:  p.unescapeField(parts[1]),
        DeviceProduct: p.unescapeField(parts[2]),
        DeviceVersion: p.unescapeField(parts[3]),
        SignatureID:   p.unescapeField(parts[4]),
        Name:          p.unescapeField(parts[5]),
        Severity:      severity,
        Extensions:    extensions,
        RawMessage:    message,
    }, nil
}

// splitHeader splits the CEF header respecting escaped pipes
func (p *Parser) splitHeader(content string) []string {
    var parts []string
    var current strings.Builder
    escaped := false
    pipeCount := 0

    for i, char := range content {
        if escaped {
            current.WriteRune(char)
            escaped = false
            continue
        }

        if char == '\\' && i+1 < len(content) {
            next := content[i+1]
            if next == '|' || next == '\\' || next == '=' {
                escaped = true
                continue
            }
        }

        if char == '|' && pipeCount < 6 {
            parts = append(parts, current.String())
            current.Reset()
            pipeCount++
            continue
        }

        current.WriteRune(char)
    }

    // Add the remaining content (extensions)
    parts = append(parts, current.String())

    return parts
}

// parseExtensions parses the CEF extension key=value pairs
func (p *Parser) parseExtensions(extStr string) map[string]string {
    extensions := make(map[string]string)

    // Find all key positions
    matches := p.extensionRegex.FindAllStringIndex(extStr, -1)
    if len(matches) == 0 {
        return extensions
    }

    for i, match := range matches {
        keyStart := match[0]
        keyEnd := match[1] - 1 // Exclude the '='
        key := extStr[keyStart:keyEnd]

        // Value goes from after '=' to the start of next key (or end)
        valueStart := match[1]
        var valueEnd int
        if i+1 < len(matches) {
            // Find the last space before the next key
            valueEnd = matches[i+1][0]
            for valueEnd > valueStart && extStr[valueEnd-1] == ' ' {
                valueEnd--
            }
        } else {
            valueEnd = len(extStr)
        }

        value := strings.TrimSpace(extStr[valueStart:valueEnd])
        extensions[key] = p.unescapeValue(value)

        if len(extensions) >= p.maxExtensions {
            break
        }
    }

    return extensions
}

// unescapeField unescapes CEF header field values
func (p *Parser) unescapeField(s string) string {
    s = strings.ReplaceAll(s, `\|`, "|")
    s = strings.ReplaceAll(s, `\\`, "\\")
    return s
}

// unescapeValue unescapes CEF extension values
func (p *Parser) unescapeValue(s string) string {
    s = strings.ReplaceAll(s, `\=`, "=")
    s = strings.ReplaceAll(s, `\n`, "\n")
    s = strings.ReplaceAll(s, `\r`, "\r")
    s = strings.ReplaceAll(s, `\\`, "\\")
    return s
}
```

### 3. CEF Extension Mappings

```go
// internal/ingest/cef/extensions.go
package cef

// Standard CEF extension field mappings
// https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdocs/cef-implementation-standard/cef-implementation-standard.pdf

var StandardExtensions = map[string]ExtensionInfo{
    // Source fields
    "src":      {Category: "source", Field: "ip", Description: "Source IP address"},
    "spt":      {Category: "source", Field: "port", Description: "Source port"},
    "smac":     {Category: "source", Field: "mac", Description: "Source MAC address"},
    "shost":    {Category: "source", Field: "hostname", Description: "Source hostname"},
    "suser":    {Category: "source", Field: "user", Description: "Source user name"},
    "suid":     {Category: "source", Field: "user_id", Description: "Source user ID"},

    // Destination fields
    "dst":      {Category: "destination", Field: "ip", Description: "Destination IP address"},
    "dpt":      {Category: "destination", Field: "port", Description: "Destination port"},
    "dmac":     {Category: "destination", Field: "mac", Description: "Destination MAC address"},
    "dhost":    {Category: "destination", Field: "hostname", Description: "Destination hostname"},
    "duser":    {Category: "destination", Field: "user", Description: "Destination user name"},
    "duid":     {Category: "destination", Field: "user_id", Description: "Destination user ID"},

    // Event fields
    "act":      {Category: "event", Field: "action", Description: "Action taken"},
    "outcome":  {Category: "event", Field: "outcome", Description: "Event outcome"},
    "reason":   {Category: "event", Field: "reason", Description: "Reason for action"},
    "msg":      {Category: "event", Field: "message", Description: "Event message"},
    "cat":      {Category: "event", Field: "category", Description: "Event category"},

    // Time fields
    "rt":       {Category: "time", Field: "receipt_time", Description: "Receipt time"},
    "start":    {Category: "time", Field: "start_time", Description: "Start time"},
    "end":      {Category: "time", Field: "end_time", Description: "End time"},

    // File fields
    "fname":    {Category: "file", Field: "name", Description: "File name"},
    "filePath": {Category: "file", Field: "path", Description: "File path"},
    "fsize":    {Category: "file", Field: "size", Description: "File size"},
    "fileHash": {Category: "file", Field: "hash", Description: "File hash"},

    // Request fields
    "request":       {Category: "request", Field: "url", Description: "Request URL"},
    "requestMethod": {Category: "request", Field: "method", Description: "Request method"},
    "requestContext":{Category: "request", Field: "context", Description: "Request context"},

    // Device fields
    "dvc":      {Category: "device", Field: "ip", Description: "Device IP"},
    "dvchost":  {Category: "device", Field: "hostname", Description: "Device hostname"},

    // Custom fields (cn1-cn3, cs1-cs6)
    "cn1":      {Category: "custom", Field: "number1", Description: "Custom number 1"},
    "cn2":      {Category: "custom", Field: "number2", Description: "Custom number 2"},
    "cn3":      {Category: "custom", Field: "number3", Description: "Custom number 3"},
    "cs1":      {Category: "custom", Field: "string1", Description: "Custom string 1"},
    "cs2":      {Category: "custom", Field: "string2", Description: "Custom string 2"},
    "cs3":      {Category: "custom", Field: "string3", Description: "Custom string 3"},
    "cs4":      {Category: "custom", Field: "string4", Description: "Custom string 4"},
    "cs5":      {Category: "custom", Field: "string5", Description: "Custom string 5"},
    "cs6":      {Category: "custom", Field: "string6", Description: "Custom string 6"},
}

type ExtensionInfo struct {
    Category    string
    Field       string
    Description string
}

// GetExtensionInfo returns information about a CEF extension field
func GetExtensionInfo(key string) (ExtensionInfo, bool) {
    info, ok := StandardExtensions[key]
    return info, ok
}
```

### 4. CEF to Canonical Schema Normalizer

```go
// internal/ingest/cef/normalizer.go
package cef

import (
    "fmt"
    "strconv"
    "strings"
    "time"

    "github.com/google/uuid"
    "boundary-siem/internal/schema"
)

// ActionMappings maps CEF signature IDs to canonical action names
var ActionMappings = map[string]string{
    // Boundary-daemon mappings
    "100": "session.created",
    "101": "session.terminated",
    "200": "auth.login",
    "201": "auth.logout",
    "400": "auth.failure",
    "401": "auth.failure",

    // Generic mappings
    "TRAFFIC": "network.connection",
    "THREAT":  "threat.detected",
    "SYSTEM":  "system.event",
}

// Normalizer converts CEF events to canonical schema
type Normalizer struct {
    actionMappings  map[string]string
    defaultTenantID string
}

func NewNormalizer(defaultTenantID string) *Normalizer {
    return &Normalizer{
        actionMappings:  ActionMappings,
        defaultTenantID: defaultTenantID,
    }
}

// Normalize converts a CEFEvent to a canonical schema Event
func (n *Normalizer) Normalize(cef *CEFEvent, sourceIP string) (*schema.Event, error) {
    event := &schema.Event{
        EventID:       uuid.New(),
        Timestamp:     n.extractTimestamp(cef),
        ReceivedAt:    time.Now().UTC(),
        SchemaVersion: "1.0.0",
        TenantID:      n.defaultTenantID,

        Source: schema.Source{
            Product:    cef.DeviceProduct,
            Host:       n.extractSourceHost(cef, sourceIP),
            InstanceID: cef.SignatureID,
            Version:    cef.DeviceVersion,
        },

        Action:   n.mapAction(cef),
        Target:   n.extractTarget(cef),
        Outcome:  n.extractOutcome(cef),
        Severity: n.mapSeverity(cef.Severity),
        Raw:      cef.RawMessage,

        Metadata: n.buildMetadata(cef),
    }

    // Extract actor information
    event.Actor = n.extractActor(cef)

    return event, nil
}

// extractTimestamp extracts timestamp from CEF extensions or uses current time
func (n *Normalizer) extractTimestamp(cef *CEFEvent) time.Time {
    // Try receipt time first
    if rt, ok := cef.Extensions["rt"]; ok {
        if t, err := n.parseTimestamp(rt); err == nil {
            return t
        }
    }

    // Try start time
    if start, ok := cef.Extensions["start"]; ok {
        if t, err := n.parseTimestamp(start); err == nil {
            return t
        }
    }

    // Default to now
    return time.Now().UTC()
}

// parseTimestamp handles various CEF timestamp formats
func (n *Normalizer) parseTimestamp(s string) (time.Time, error) {
    // CEF uses milliseconds since epoch
    if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
        return time.UnixMilli(ms).UTC(), nil
    }

    // Try common formats
    formats := []string{
        time.RFC3339,
        time.RFC3339Nano,
        "Jan 02 2006 15:04:05",
        "Jan 02 15:04:05",
        "2006-01-02T15:04:05Z",
        "2006-01-02 15:04:05",
    }

    for _, format := range formats {
        if t, err := time.Parse(format, s); err == nil {
            return t.UTC(), nil
        }
    }

    return time.Time{}, fmt.Errorf("unable to parse timestamp: %s", s)
}

// extractSourceHost gets the source host from extensions or falls back to source IP
func (n *Normalizer) extractSourceHost(cef *CEFEvent, sourceIP string) string {
    if host, ok := cef.Extensions["dvchost"]; ok {
        return host
    }
    if host, ok := cef.Extensions["shost"]; ok {
        return host
    }
    if ip, ok := cef.Extensions["dvc"]; ok {
        return ip
    }
    return sourceIP
}

// mapAction maps CEF signature ID to canonical action
func (n *Normalizer) mapAction(cef *CEFEvent) string {
    // Check explicit mappings first
    if action, ok := n.actionMappings[cef.SignatureID]; ok {
        return action
    }

    // Check act extension
    if act, ok := cef.Extensions["act"]; ok {
        return n.normalizeActionString(act)
    }

    // Build action from event name
    return n.normalizeActionString(cef.Name)
}

// normalizeActionString converts a string to action format (lowercase, dots)
func (n *Normalizer) normalizeActionString(s string) string {
    s = strings.ToLower(s)
    s = strings.ReplaceAll(s, " ", "_")
    s = strings.ReplaceAll(s, "-", "_")

    // Ensure it matches action pattern
    if !strings.Contains(s, ".") {
        s = "event." + s
    }

    return s
}

// extractTarget determines the target from CEF extensions
func (n *Normalizer) extractTarget(cef *CEFEvent) string {
    // Build target from destination info
    var parts []string

    if host, ok := cef.Extensions["dhost"]; ok {
        parts = append(parts, "host:"+host)
    } else if ip, ok := cef.Extensions["dst"]; ok {
        parts = append(parts, "ip:"+ip)
    }

    if user, ok := cef.Extensions["duser"]; ok {
        parts = append(parts, "user:"+user)
    }

    if path, ok := cef.Extensions["filePath"]; ok {
        parts = append(parts, "file:"+path)
    }

    if url, ok := cef.Extensions["request"]; ok {
        parts = append(parts, "url:"+url)
    }

    if len(parts) == 0 {
        return ""
    }

    return strings.Join(parts, ",")
}

// extractOutcome determines the outcome from CEF extensions
func (n *Normalizer) extractOutcome(cef *CEFEvent) schema.Outcome {
    if outcome, ok := cef.Extensions["outcome"]; ok {
        switch strings.ToLower(outcome) {
        case "success", "succeeded", "allowed", "permit":
            return schema.OutcomeSuccess
        case "failure", "failed", "denied", "blocked", "reject":
            return schema.OutcomeFailure
        }
    }

    // Check action for hints
    if act, ok := cef.Extensions["act"]; ok {
        actLower := strings.ToLower(act)
        if strings.Contains(actLower, "block") || strings.Contains(actLower, "deny") {
            return schema.OutcomeFailure
        }
        if strings.Contains(actLower, "allow") || strings.Contains(actLower, "permit") {
            return schema.OutcomeSuccess
        }
    }

    return schema.OutcomeUnknown
}

// mapSeverity maps CEF severity (0-10) to canonical severity (1-10)
func (n *Normalizer) mapSeverity(cefSeverity int) int {
    if cefSeverity < 1 {
        return 1
    }
    if cefSeverity > 10 {
        return 10
    }
    return cefSeverity
}

// extractActor extracts actor information from CEF extensions
func (n *Normalizer) extractActor(cef *CEFEvent) *schema.Actor {
    actor := &schema.Actor{
        Type: schema.ActorUnknown,
    }

    // Source user
    if user, ok := cef.Extensions["suser"]; ok {
        actor.Type = schema.ActorUser
        actor.Name = user
    }

    if uid, ok := cef.Extensions["suid"]; ok {
        actor.ID = uid
    }

    // Source IP
    if ip, ok := cef.Extensions["src"]; ok {
        actor.IPAddress = ip
    }

    // If no actor info found, return nil
    if actor.Name == "" && actor.ID == "" && actor.IPAddress == "" {
        return nil
    }

    return actor
}

// buildMetadata builds the metadata map from CEF extensions
func (n *Normalizer) buildMetadata(cef *CEFEvent) map[string]any {
    metadata := make(map[string]any)

    // Add CEF-specific metadata
    metadata["cef_version"] = cef.Version
    metadata["device_vendor"] = cef.DeviceVendor
    metadata["signature_id"] = cef.SignatureID
    metadata["event_name"] = cef.Name

    // Add useful extensions to metadata
    interestingFields := []string{
        "msg", "reason", "cat", "filePath", "fname", "fsize",
        "request", "requestMethod", "spt", "dpt",
        "cs1", "cs2", "cs3", "cs4", "cs5", "cs6",
    }

    for _, field := range interestingFields {
        if val, ok := cef.Extensions[field]; ok {
            metadata["cef_"+field] = val
        }
    }

    return metadata
}
```

### 5. UDP Server

```go
// internal/ingest/udp_server.go
package ingest

import (
    "context"
    "log/slog"
    "net"
    "sync"
    "sync/atomic"

    "boundary-siem/internal/ingest/cef"
    "boundary-siem/internal/queue"
    "boundary-siem/internal/schema"
    "boundary-siem/internal/storage"
)

type UDPServerConfig struct {
    Address       string
    BufferSize    int
    Workers       int
    MaxMessageSize int
}

type UDPServer struct {
    config     UDPServerConfig
    conn       *net.UDPConn
    parser     *cef.Parser
    normalizer *cef.Normalizer
    validator  *schema.Validator
    queue      *queue.RingBuffer
    quarantine *storage.QuarantineWriter

    wg   sync.WaitGroup
    done chan struct{}

    // Metrics
    received   uint64
    parsed     uint64
    normalized uint64
    queued     uint64
    errors     uint64
}

func NewUDPServer(
    cfg UDPServerConfig,
    parser *cef.Parser,
    normalizer *cef.Normalizer,
    validator *schema.Validator,
    q *queue.RingBuffer,
    quarantine *storage.QuarantineWriter,
) *UDPServer {
    return &UDPServer{
        config:     cfg,
        parser:     parser,
        normalizer: normalizer,
        validator:  validator,
        queue:      q,
        quarantine: quarantine,
        done:       make(chan struct{}),
    }
}

func (s *UDPServer) Start(ctx context.Context) error {
    addr, err := net.ResolveUDPAddr("udp", s.config.Address)
    if err != nil {
        return err
    }

    conn, err := net.ListenUDP("udp", addr)
    if err != nil {
        return err
    }

    // Set read buffer size
    conn.SetReadBuffer(s.config.BufferSize)
    s.conn = conn

    slog.Info("UDP server started", "address", s.config.Address)

    // Start worker goroutines
    messages := make(chan udpMessage, s.config.Workers*100)

    for i := 0; i < s.config.Workers; i++ {
        s.wg.Add(1)
        go s.worker(ctx, messages, i)
    }

    // Start receiver
    s.wg.Add(1)
    go s.receiver(ctx, messages)

    return nil
}

type udpMessage struct {
    data     []byte
    sourceIP string
}

func (s *UDPServer) receiver(ctx context.Context, messages chan<- udpMessage) {
    defer s.wg.Done()
    defer close(messages)

    buffer := make([]byte, s.config.MaxMessageSize)

    for {
        select {
        case <-ctx.Done():
            return
        case <-s.done:
            return
        default:
        }

        n, remoteAddr, err := s.conn.ReadFromUDP(buffer)
        if err != nil {
            if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
                continue
            }
            slog.Error("UDP read error", "error", err)
            continue
        }

        atomic.AddUint64(&s.received, 1)

        // Copy data to avoid buffer reuse issues
        data := make([]byte, n)
        copy(data, buffer[:n])

        select {
        case messages <- udpMessage{data: data, sourceIP: remoteAddr.IP.String()}:
        default:
            // Channel full, drop message
            atomic.AddUint64(&s.errors, 1)
        }
    }
}

func (s *UDPServer) worker(ctx context.Context, messages <-chan udpMessage, workerID int) {
    defer s.wg.Done()

    for msg := range messages {
        s.processMessage(ctx, msg)
    }
}

func (s *UDPServer) processMessage(ctx context.Context, msg udpMessage) {
    // Parse CEF
    cefEvent, err := s.parser.Parse(string(msg.data))
    if err != nil {
        atomic.AddUint64(&s.errors, 1)
        s.quarantine.Write(ctx, &storage.QuarantineEntry{
            RawEvent:         string(msg.data),
            SourceIP:         msg.sourceIP,
            SourceFormat:     "cef",
            ValidationErrors: []string{err.Error()},
            ErrorCode:        "PARSE_ERROR",
        })
        return
    }
    atomic.AddUint64(&s.parsed, 1)

    // Normalize to canonical schema
    event, err := s.normalizer.Normalize(cefEvent, msg.sourceIP)
    if err != nil {
        atomic.AddUint64(&s.errors, 1)
        s.quarantine.Write(ctx, &storage.QuarantineEntry{
            RawEvent:         string(msg.data),
            SourceIP:         msg.sourceIP,
            SourceFormat:     "cef",
            ValidationErrors: []string{err.Error()},
            ErrorCode:        "NORMALIZE_ERROR",
        })
        return
    }
    atomic.AddUint64(&s.normalized, 1)

    // Validate
    if err := s.validator.Validate(event); err != nil {
        atomic.AddUint64(&s.errors, 1)
        s.quarantine.Write(ctx, &storage.QuarantineEntry{
            RawEvent:         string(msg.data),
            SourceIP:         msg.sourceIP,
            SourceFormat:     "cef",
            ValidationErrors: []string{err.Error()},
            ErrorCode:        "VALIDATION_ERROR",
        })
        return
    }

    // Queue for storage
    if err := s.queue.Push(event); err != nil {
        atomic.AddUint64(&s.errors, 1)
        return
    }

    atomic.AddUint64(&s.queued, 1)
}

func (s *UDPServer) Stop() {
    close(s.done)
    s.conn.Close()
    s.wg.Wait()
    slog.Info("UDP server stopped")
}

func (s *UDPServer) Metrics() (received, parsed, normalized, queued, errors uint64) {
    return atomic.LoadUint64(&s.received),
        atomic.LoadUint64(&s.parsed),
        atomic.LoadUint64(&s.normalized),
        atomic.LoadUint64(&s.queued),
        atomic.LoadUint64(&s.errors)
}
```

### 6. TCP Server

```go
// internal/ingest/tcp_server.go
package ingest

import (
    "bufio"
    "context"
    "crypto/tls"
    "io"
    "log/slog"
    "net"
    "sync"
    "sync/atomic"
    "time"

    "boundary-siem/internal/ingest/cef"
    "boundary-siem/internal/queue"
    "boundary-siem/internal/schema"
    "boundary-siem/internal/storage"
)

type TCPServerConfig struct {
    Address        string
    TLSEnabled     bool
    TLSCertFile    string
    TLSKeyFile     string
    MaxConnections int
    IdleTimeout    time.Duration
    MaxLineLength  int
}

type TCPServer struct {
    config     TCPServerConfig
    listener   net.Listener
    parser     *cef.Parser
    normalizer *cef.Normalizer
    validator  *schema.Validator
    queue      *queue.RingBuffer
    quarantine *storage.QuarantineWriter

    connCount int32
    wg        sync.WaitGroup
    done      chan struct{}

    // Metrics
    connections uint64
    received    uint64
    parsed      uint64
    errors      uint64
}

func NewTCPServer(
    cfg TCPServerConfig,
    parser *cef.Parser,
    normalizer *cef.Normalizer,
    validator *schema.Validator,
    q *queue.RingBuffer,
    quarantine *storage.QuarantineWriter,
) *TCPServer {
    return &TCPServer{
        config:     cfg,
        parser:     parser,
        normalizer: normalizer,
        validator:  validator,
        queue:      q,
        quarantine: quarantine,
        done:       make(chan struct{}),
    }
}

func (s *TCPServer) Start(ctx context.Context) error {
    var listener net.Listener
    var err error

    if s.config.TLSEnabled {
        cert, err := tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile)
        if err != nil {
            return err
        }

        tlsConfig := &tls.Config{
            Certificates: []tls.Certificate{cert},
            MinVersion:   tls.VersionTLS12,
        }

        listener, err = tls.Listen("tcp", s.config.Address, tlsConfig)
        if err != nil {
            return err
        }
    } else {
        listener, err = net.Listen("tcp", s.config.Address)
        if err != nil {
            return err
        }
    }

    s.listener = listener

    slog.Info("TCP server started",
        "address", s.config.Address,
        "tls", s.config.TLSEnabled,
    )

    s.wg.Add(1)
    go s.acceptLoop(ctx)

    return nil
}

func (s *TCPServer) acceptLoop(ctx context.Context) {
    defer s.wg.Done()

    for {
        select {
        case <-ctx.Done():
            return
        case <-s.done:
            return
        default:
        }

        conn, err := s.listener.Accept()
        if err != nil {
            if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
                continue
            }
            select {
            case <-s.done:
                return
            default:
                slog.Error("TCP accept error", "error", err)
                continue
            }
        }

        // Check connection limit
        if atomic.LoadInt32(&s.connCount) >= int32(s.config.MaxConnections) {
            slog.Warn("max connections reached, rejecting")
            conn.Close()
            continue
        }

        atomic.AddInt32(&s.connCount, 1)
        atomic.AddUint64(&s.connections, 1)

        s.wg.Add(1)
        go s.handleConnection(ctx, conn)
    }
}

func (s *TCPServer) handleConnection(ctx context.Context, conn net.Conn) {
    defer s.wg.Done()
    defer atomic.AddInt32(&s.connCount, -1)
    defer conn.Close()

    sourceIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()

    slog.Debug("new TCP connection", "remote", conn.RemoteAddr())

    reader := bufio.NewReaderSize(conn, s.config.MaxLineLength)

    for {
        select {
        case <-ctx.Done():
            return
        case <-s.done:
            return
        default:
        }

        // Set read deadline
        conn.SetReadDeadline(time.Now().Add(s.config.IdleTimeout))

        // Read line (CEF messages are newline-delimited)
        line, err := reader.ReadString('\n')
        if err != nil {
            if err == io.EOF {
                return
            }
            if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
                return // Idle timeout
            }
            slog.Debug("TCP read error", "error", err)
            return
        }

        atomic.AddUint64(&s.received, 1)

        // Process message
        s.processMessage(ctx, line, sourceIP)
    }
}

func (s *TCPServer) processMessage(ctx context.Context, message string, sourceIP string) {
    // Parse CEF
    cefEvent, err := s.parser.Parse(message)
    if err != nil {
        atomic.AddUint64(&s.errors, 1)
        s.quarantine.Write(ctx, &storage.QuarantineEntry{
            RawEvent:         message,
            SourceIP:         sourceIP,
            SourceFormat:     "cef",
            ValidationErrors: []string{err.Error()},
            ErrorCode:        "PARSE_ERROR",
        })
        return
    }
    atomic.AddUint64(&s.parsed, 1)

    // Normalize
    event, err := s.normalizer.Normalize(cefEvent, sourceIP)
    if err != nil {
        atomic.AddUint64(&s.errors, 1)
        return
    }

    // Validate
    if err := s.validator.Validate(event); err != nil {
        atomic.AddUint64(&s.errors, 1)
        return
    }

    // Queue
    s.queue.Push(event)
}

func (s *TCPServer) Stop() {
    close(s.done)
    s.listener.Close()
    s.wg.Wait()
    slog.Info("TCP server stopped")
}

func (s *TCPServer) Metrics() (connections, received, parsed, errors uint64) {
    return atomic.LoadUint64(&s.connections),
        atomic.LoadUint64(&s.received),
        atomic.LoadUint64(&s.parsed),
        atomic.LoadUint64(&s.errors)
}
```

### 7. Configuration Updates

```yaml
# configs/config.example.yaml (additions)

ingest:
  cef:
    udp:
      enabled: true
      address: ":5514"
      buffer_size: 16777216  # 16MB
      workers: 8
      max_message_size: 65535

    tcp:
      enabled: true
      address: ":5515"
      tls_enabled: false
      tls_cert_file: /etc/siem/certs/server.crt
      tls_key_file: /etc/siem/certs/server.key
      max_connections: 1000
      idle_timeout: 5m
      max_line_length: 65535

    parser:
      strict_mode: false
      max_extensions: 100

    normalizer:
      default_tenant_id: "default"
```

### 8. Custom CEF Mappings File

```yaml
# configs/cef-mappings.yaml

# Custom action mappings for specific vendors/products
action_mappings:
  # Boundary daemon
  boundary-daemon:
    "100": "session.created"
    "101": "session.terminated"
    "102": "session.expired"
    "200": "auth.login"
    "201": "auth.logout"
    "400": "auth.failure"
    "401": "auth.mfa_failure"
    "500": "access.granted"
    "501": "access.denied"

  # Palo Alto Firewall
  PaloAlto:
    "TRAFFIC": "network.connection"
    "THREAT": "threat.detected"
    "WILDFIRE": "threat.malware"
    "URL": "network.web_access"

  # Generic/fallback
  default:
    "LOGIN": "auth.login"
    "LOGOUT": "auth.logout"
    "DENY": "access.denied"
    "ALLOW": "access.granted"

# Severity overrides by signature
severity_overrides:
  "THREAT": 8
  "MALWARE": 9
  "CRITICAL": 10
```

---

## Testing Scripts

### Test CEF UDP

```bash
#!/bin/bash
# scripts/test-cef-udp.sh

SIEM_HOST="${SIEM_HOST:-localhost}"
SIEM_PORT="${SIEM_PORT:-5514}"

echo "Sending CEF events to $SIEM_HOST:$SIEM_PORT via UDP..."

# Session created
echo 'CEF:0|Boundary|boundary-daemon|1.0.0|100|Session Created|3|src=192.168.1.10 suser=admin dhost=db-prod-01 outcome=success' | nc -u -w1 $SIEM_HOST $SIEM_PORT

# Authentication failure
echo 'CEF:0|Boundary|boundary-daemon|1.0.0|400|Authentication Failed|7|src=10.0.0.50 suser=unknown dhost=api-server outcome=failure reason=invalid_password' | nc -u -w1 $SIEM_HOST $SIEM_PORT

# High severity threat
echo 'CEF:0|SecurityVendor|IDS|2.0|THREAT|Malware Detected|9|src=203.0.113.50 dst=192.168.1.100 act=blocked filePath=/tmp/evil.exe fileHash=abc123' | nc -u -w1 $SIEM_HOST $SIEM_PORT

# Batch test
for i in {1..100}; do
    echo "CEF:0|Boundary|boundary-daemon|1.0.0|100|Session $i|3|src=192.168.1.$((i % 255)) suser=user$i outcome=success" | nc -u -w0 $SIEM_HOST $SIEM_PORT
done

echo "Done! Sent 103 CEF events"
```

### Test CEF TCP

```bash
#!/bin/bash
# scripts/test-cef-tcp.sh

SIEM_HOST="${SIEM_HOST:-localhost}"
SIEM_PORT="${SIEM_PORT:-5515}"

echo "Sending CEF events to $SIEM_HOST:$SIEM_PORT via TCP..."

{
    echo 'CEF:0|Boundary|boundary-daemon|1.0.0|100|Session Created|3|src=192.168.1.10 suser=admin dhost=db-prod-01 outcome=success'
    echo 'CEF:0|Boundary|boundary-daemon|1.0.0|400|Auth Failed|7|src=10.0.0.50 suser=attacker outcome=failure'
    echo 'CEF:0|Boundary|boundary-daemon|1.0.0|200|Login Success|2|src=192.168.1.100 suser=admin outcome=success'
} | nc $SIEM_HOST $SIEM_PORT

echo "Done!"
```

---

## Testing Checklist

### Unit Tests

- [ ] `cef.Parser` correctly parses valid CEF messages
- [ ] `cef.Parser` handles escaped pipes and equals signs
- [ ] `cef.Parser` extracts all extension fields
- [ ] `cef.Parser` rejects invalid CEF formats (strict mode)
- [ ] `cef.Normalizer` maps CEF to canonical schema correctly
- [ ] `cef.Normalizer` extracts actor from suser/suid
- [ ] `cef.Normalizer` maps severity correctly
- [ ] `cef.Normalizer` handles missing optional fields
- [ ] `UDPServer` receives and processes messages
- [ ] `TCPServer` handles multiple concurrent connections
- [ ] `TCPServer` respects idle timeout

### Integration Tests

- [ ] End-to-end: UDP CEF → parse → normalize → validate → queue → storage
- [ ] End-to-end: TCP CEF → parse → normalize → validate → queue → storage
- [ ] Invalid CEF messages go to quarantine
- [ ] Mixed JSON HTTP and CEF UDP ingestion works simultaneously
- [ ] TLS TCP connections work with valid certificates

### Performance Tests

- [ ] UDP: Sustain 5,000 messages/sec for 5 minutes
- [ ] TCP: Handle 100 concurrent connections
- [ ] No memory leaks under sustained load
- [ ] Parser handles malformed messages gracefully

---

## Acceptance Criteria

This step is complete when:

1. **UDP server** listens on port 5514 and receives CEF messages
2. **TCP server** listens on port 5515 with optional TLS
3. **CEF parser** correctly parses standard CEF format with extensions
4. **Normalizer** converts CEF to canonical schema
5. **Invalid CEF** messages are quarantined with error details
6. **Metrics exposed** for received/parsed/errors per protocol
7. **Both protocols** feed into the same queue/storage pipeline
8. **Integration test** proves boundary-daemon CEF events flow through

---

## MVP Milestone Check

After completing Step 3, the SIEM meets the **Ingest Layer MVP** requirements:

| Requirement | Status |
|-------------|--------|
| CEF ingestion (UDP or TCP) | ✅ |
| JSON over HTTP (POST) | ✅ (Step 1) |
| Backpressure-safe ingestion | ✅ (Step 1) |
| Event timestamp normalization | ✅ |
| Source identity tagging | ✅ |

---

## Next Steps (Preview)

**Step 4: Search & Query API**
- Time-range search
- Field-based filtering
- Full-text search on raw
- JSON query API
- Pagination & limits
- CLI interface

**Step 5: Correlation Engine**
- Rule definition format (YAML)
- Time-window correlation
- Cross-source matching
- Alert event emission
