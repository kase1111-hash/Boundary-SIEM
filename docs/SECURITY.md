# Boundary SIEM Security Documentation

This document provides comprehensive documentation for the security features implemented in Boundary SIEM.

## Overview

Boundary SIEM implements defense-in-depth security controls across multiple layers:

1. **Audit Logging** - Tamper-evident logging with cryptographic integrity
2. **Log Protection** - Linux immutable file attributes for log files
3. **External Integration** - Secure syslog forwarding to external SIEM
4. **Container Security** - Isolation and hardening for containerized deployments
5. **Hardware Security** - TPM 2.0 integration for key storage
6. **Automated Security Scanning** - CI/CD integration with gosec and govulncheck

---

## 1. Tamper-Evident Audit Logging

### Location
`internal/security/audit/`

### Features

- **Hash Chain Integrity**: Each log entry includes the hash of the previous entry, creating an unbreakable chain
- **Cryptographic Signatures**: Optional HMAC or ECDSA signatures for each entry
- **Automatic Rotation**: Size and time-based log rotation with configurable retention
- **Structured Format**: JSON-based entries with timestamps, event types, and metadata

### Configuration

```go
import "boundary-siem/internal/security/audit"

config := &audit.Config{
    LogDir:           "/var/log/boundary-siem/audit",
    MaxFileSize:      100 * 1024 * 1024, // 100MB
    MaxAge:           90,                 // days
    RotationInterval: 24 * time.Hour,
    SigningKey:       signingKey,         // ECDSA or HMAC key
}

logger, err := audit.NewAuditLogger(config)
```

### Entry Structure

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "sequence": 12345,
  "event_type": "authentication",
  "actor": "user@example.com",
  "action": "login",
  "resource": "/api/v1/events",
  "outcome": "success",
  "metadata": {},
  "prev_hash": "sha256:abc123...",
  "signature": "..."
}
```

### Verification

```go
// Verify chain integrity
valid, brokenAt, err := logger.VerifyChain(ctx)
if !valid {
    log.Fatalf("Chain broken at sequence %d", brokenAt)
}
```

---

## 2. Immutable Log Protection

### Location
`internal/security/audit/immutable.go`

### Features

- **Append-Only Mode**: `chattr +a` prevents modification/deletion of active logs
- **Immutable Mode**: `chattr +i` fully protects rotated/archived logs
- **Capability Detection**: Automatic detection of filesystem and permission support
- **Graceful Fallback**: Continues operation if filesystem doesn't support attributes

### Requirements

- Linux kernel 2.6.x or later
- ext4, XFS, or Btrfs filesystem (not tmpfs)
- `CAP_LINUX_IMMUTABLE` capability or root privileges

### Configuration

```go
immutableConfig := &audit.ImmutableConfig{
    EnableAppendOnly: true,  // Active log files
    EnableImmutable:  true,  // Rotated log files
    StrictMode:       false, // Don't fail if unsupported
}

err := audit.WithImmutableLogs(logger, immutableConfig)
```

### Manual Operations

```bash
# View file attributes
lsattr /var/log/boundary-siem/audit/

# Remove append-only for maintenance (requires root)
sudo chattr -a /var/log/boundary-siem/audit/current.log

# Remove immutable for archival
sudo chattr -i /var/log/boundary-siem/audit/2024-01-15.log
```

---

## 3. Remote Syslog Forwarding

### Location
`internal/security/audit/syslog.go`

### Features

- **Multiple Protocols**: UDP, TCP, TLS (RFC 5425)
- **Message Formats**: RFC 3164, RFC 5424, CEF, JSON
- **Buffering**: Async buffering with configurable retry logic
- **Connection Management**: Automatic reconnection with exponential backoff

### Configuration

```go
syslogConfig := &audit.SyslogConfig{
    Servers: []audit.SyslogServer{
        {
            Address:  "siem.example.com:6514",
            Protocol: "tls",
            TLSConfig: &tls.Config{
                RootCAs:    certPool,
                MinVersion: tls.VersionTLS12,
            },
        },
        {
            Address:  "backup-siem.example.com:514",
            Protocol: "tcp",
        },
    },
    Format:     audit.FormatRFC5424,
    Facility:   audit.FacilityLocal0,
    AppName:    "boundary-siem",
    BufferSize: 10000,
    RetryCount: 3,
    RetryDelay: 5 * time.Second,
}

err := audit.WithRemoteSyslog(logger, syslogConfig)
```

### Message Formats

**RFC 5424 (recommended)**
```
<134>1 2024-01-15T10:30:00.000Z hostname boundary-siem - - [meta@12345 id="..."] Authentication success
```

**CEF**
```
CEF:0|Boundary|SIEM|1.0|AUTH|Authentication|3|src=10.0.0.1 dst=api.example.com outcome=success
```

**JSON**
```json
{"timestamp":"2024-01-15T10:30:00Z","event_type":"authentication","outcome":"success",...}
```

---

## 4. Container Security

### Location
`deploy/container/`

### Docker Isolation

#### Networks
Three isolated networks with different access levels:

| Network | Subnet | Purpose | External Access |
|---------|--------|---------|-----------------|
| siem-internal | 172.28.0.0/24 | Inter-service communication | None |
| siem-ingestion | 172.28.1.0/24 | Log ingestion | Inbound only |
| siem-management | 172.28.2.0/24 | Admin API | VPN/bastion only |

#### Seccomp Profile
Restricts available syscalls to a minimal set:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {"names": ["read", "write", "open", ...], "action": "SCMP_ACT_ALLOW"}
  ]
}
```

#### AppArmor Profile
Enforces mandatory access control:

```
profile boundary-siem flags=(attach_disconnected,mediate_deleted) {
  # Read-only access to system
  /etc/** r,
  /usr/share/** r,

  # Writable data directories
  /var/log/boundary-siem/** rw,
  /var/lib/boundary-siem/** rw,

  # Network restrictions
  network inet tcp,
  network inet udp,
}
```

### Kubernetes Security

#### Pod Security Standards
Enforces the "restricted" security profile:

```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

#### Network Policies
Default deny with explicit allow rules:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

#### OPA Gatekeeper Constraints
Policy enforcement for:
- Non-root user requirement
- Read-only root filesystem
- No privileged containers
- Capability restrictions
- Seccomp profile requirement

### Deployment

```bash
# Docker
cd deploy/container
sudo ./setup-container-isolation.sh docker
docker-compose up -d

# Kubernetes
kubectl apply -f deploy/container/pod-security-policy.yaml
kubectl apply -f deploy/container/network-policy.yaml
```

---

## 5. Hardware Key Storage (TPM 2.0)

### Location
`internal/security/hardware/`

### Features

- **TPM 2.0 Support**: Hardware-backed key generation and storage
- **PCR Binding**: Keys sealed to specific platform configuration register values
- **Software Fallback**: Encrypted file-based storage when TPM unavailable
- **Key Hierarchy**: Primary key → derived keys for specific purposes

### Requirements

- TPM 2.0 chip (Intel PTT, AMD fTPM, or discrete TPM)
- Linux with `/dev/tpm0` or `/dev/tpmrm0`
- `tpm2-tools` for debugging/verification

### Configuration

```go
import "boundary-siem/internal/security/hardware"

config := &hardware.TPMConfig{
    DevicePath:      "/dev/tpmrm0",  // Resource manager
    UsePCRPolicy:    true,
    PCRSelection:    []int{0, 1, 7}, // BIOS, config, SecureBoot
    KeyStorePath:    "/var/lib/boundary-siem/keys",
    FallbackEnabled: true,           // Software fallback
}

keyStore, err := hardware.NewTPMKeyStore(config)
```

### Key Operations

```go
// Create a new key
keyHandle, err := keyStore.CreateKey(ctx, "audit-signing", 256)

// Retrieve existing key
key, err := keyStore.GetKey(ctx, "audit-signing")

// Use for audit logging
auditKey, err := hardware.CreateAuditKey(keyStore, "/var/lib/boundary-siem/keys/audit.key")
```

### PCR Policy

Keys are sealed to Platform Configuration Register values:

| PCR | Description |
|-----|-------------|
| 0 | BIOS/UEFI firmware |
| 1 | BIOS configuration |
| 7 | Secure Boot policy |

If PCR values change (firmware update, configuration change), keys must be re-sealed.

### Software Fallback

When TPM is unavailable:
1. Keys are generated using Go's `crypto/rand`
2. Keys are encrypted with a master password (env: `SIEM_KEY_PASSWORD`)
3. Encrypted keys stored in `KeyStorePath`

---

## 6. Automated Security Scanning

### Location
`.github/workflows/security.yml` and `Makefile`

### Tools

| Tool | Purpose | Integration |
|------|---------|-------------|
| [gosec](https://github.com/securego/gosec) | Go source code security analyzer | CI + Local |
| [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | Go dependency vulnerability scanner | CI + Local |
| [golangci-lint](https://golangci-lint.run/) | Go linters aggregator | CI + Local |

### CI/CD Integration

#### GitHub Actions Workflows

**ci.yml** - Runs on every push and PR:
- Linting with `go vet` and `golangci-lint`
- Security scanning with `gosec`
- Race-condition testing with `-race` flag
- Coverage reporting

**security.yml** - Enhanced security scanning:
- Daily scheduled scans
- SARIF output for GitHub Security tab
- Dependency vulnerability checks with `govulncheck`
- Dependency review for PRs

### Local Security Scanning

```bash
# Run gosec security scanner
make security

# Generate detailed security reports (JSON + HTML)
make security-report

# Run all CI checks locally (lint, security, test)
make ci
```

### Installing Security Tools

```bash
# Install gosec
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Install govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest

# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

### Gosec Rules

Gosec checks for common security issues:

| Rule ID | Description |
|---------|-------------|
| G101 | Hardcoded credentials |
| G102 | Bind to all interfaces |
| G103 | Audit unsafe block usage |
| G104 | Audit errors not checked |
| G107 | URL provided to HTTP request as taint input |
| G201 | SQL query construction using format string |
| G202 | SQL query construction using string concatenation |
| G203 | Use of unescaped data in HTML templates |
| G301 | Poor file permissions on directory creation |
| G304 | File path provided as taint input |
| G401 | Detect use of DES, RC4, MD5, SHA1 |
| G501 | Import blocklist: net/http/cgi |

### Security Report Output

```bash
# Generate HTML report for review
make security-report

# Reports generated:
# - security-report.json (machine-readable)
# - security-report.html (human-readable)
```

---

## Security Best Practices

### Deployment Checklist

- [ ] Enable tamper-evident audit logging
- [ ] Configure immutable log attributes (if filesystem supports)
- [ ] Set up remote syslog forwarding to external SIEM
- [ ] Deploy with container isolation (seccomp + AppArmor/SELinux)
- [ ] Use TPM for key storage when available
- [ ] Enable TLS for all network communications
- [ ] Configure network policies in Kubernetes
- [ ] Set up log rotation with appropriate retention
- [ ] Regularly verify audit log chain integrity
- [ ] Monitor for privilege escalation attempts
- [ ] Run `make security` before deployments
- [ ] Configure CI/CD security scanning workflows
- [ ] Review security reports regularly

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Log tampering | Hash chain + immutable attributes |
| Key theft | TPM sealing + PCR binding |
| Container escape | Seccomp + AppArmor + non-root |
| Network lateral movement | Network policies + isolation |
| Privilege escalation | Capability restrictions + PSP |
| Data exfiltration | Egress filtering + monitoring |

### Compliance Mapping

| Feature | SOC 2 | ISO 27001 | NIST CSF | PCI DSS |
|---------|-------|-----------|----------|---------|
| Audit logging | CC7.2 | A.12.4 | DE.CM-1 | 10.2 |
| Log integrity | CC7.2 | A.12.4 | PR.DS-6 | 10.5 |
| Access control | CC6.1 | A.9.2 | PR.AC-4 | 7.1 |
| Encryption | CC6.7 | A.10.1 | PR.DS-2 | 3.4 |

---

## Troubleshooting

### Immutable Logs

```bash
# Check if filesystem supports immutable
touch /tmp/test && chattr +i /tmp/test && chattr -i /tmp/test && rm /tmp/test
# If error: filesystem doesn't support immutable attributes

# Check current attributes
lsattr /var/log/boundary-siem/audit/

# Remove for maintenance (requires root)
sudo chattr -a -i /var/log/boundary-siem/audit/*
```

### TPM Issues

```bash
# Check TPM availability
ls -la /dev/tpm*

# Check TPM status
tpm2_getcap properties-fixed

# Clear TPM (CAUTION: destroys all keys)
tpm2_clear
```

### Syslog Forwarding

```bash
# Test connectivity
nc -zv siem.example.com 514

# Test TLS
openssl s_client -connect siem.example.com:6514

# Check buffer status
curl localhost:8080/metrics | grep syslog_buffer
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01 | Initial security features |
| 1.1.0 | 2024-01 | Added TPM 2.0 support |
| 1.2.0 | 2024-01 | Container isolation improvements |
| 1.3.0 | 2026-01 | Added CI/CD security scanning (gosec, govulncheck) |
