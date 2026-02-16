# Security Vulnerability Scanning

This document describes the automated security scanning setup for Boundary-SIEM.

## Overview

Boundary-SIEM includes comprehensive security vulnerability scanning to detect:
- Go language vulnerabilities (govulncheck)
- Security issues in code (gosec)
- Vulnerable dependencies (Trivy, Nancy)
- License compliance issues
- Hardcoded secrets and credentials

## Automated Scans

### GitHub Actions Workflow

Security scans run automatically on:
- Every push to main/master/develop branches
- Every pull request
- Daily at 2 AM UTC (scheduled scan)
- Manual workflow dispatch

**Workflow**: `.github/workflows/security-scan.yml`

### Scan Tools

1. **govulncheck** - Go vulnerability database scanner
   - Checks for known vulnerabilities in Go dependencies
   - Uses official Go vulnerability database
   - Fast and accurate

2. **gosec** - Go security checker
   - Static code analysis for security issues
   - Detects common security problems
   - SARIF output for GitHub Security tab

3. **Trivy** - Comprehensive vulnerability scanner
   - Scans for vulnerabilities, misconfigurations, and secrets
   - Supports multiple severity levels
   - Container and filesystem scanning

4. **Nancy** - Dependency vulnerability checker
   - OSS Index integration
   - Checks for known vulnerable dependencies
   - Detailed vulnerability reports

5. **Dependency Review** - GitHub native dependency analysis
   - Runs on pull requests
   - Fails on moderate or higher severity issues
   - License compliance checking

## Local Scanning

Security scanning targets are defined in `Makefile.security`. You can use them
with `make -f Makefile.security <target>`, or add `include Makefile.security`
to the main `Makefile` to use them directly.

The main `Makefile` also provides a basic `make security` target that runs gosec.

### Prerequisites

Install security scanning tools:

```bash
make -f Makefile.security security-install-tools
```

### Run All Scans

```bash
make -f Makefile.security security-scan
```

### Individual Scans

```bash
# Go vulnerability check
make -f Makefile.security security-govulncheck

# Security code analysis
make -f Makefile.security security-gosec

# Check for secrets
make -f Makefile.security security-check-secrets

# Generate comprehensive report
make -f Makefile.security security-report
```

### Quick CI Check

For fast feedback in CI pipelines:

```bash
make -f Makefile.security security-quick
```

## Scan Results

### GitHub Security Tab

Security findings are automatically uploaded to GitHub's Security tab via SARIF format:
- Go to repository → Security → Code scanning alerts
- View, filter, and dismiss findings
- Track remediation progress

### Local Reports

Generated reports are saved to `reports/` directory:
- `govulncheck-YYYYMMDD-HHMMSS.json` - Vulnerability scan results
- `gosec-YYYYMMDD-HHMMSS.json` - Security issue findings
- `gosec-YYYYMMDD-HHMMSS.html` - HTML report
- `trivy-YYYYMMDD-HHMMSS.json` - Trivy scan results
- `security-report.md` - Combined security report

### Artifacts

GitHub Actions uploads scan results as artifacts:
- govulncheck results (30-day retention)
- Available under Actions → Workflow run → Artifacts

## Interpreting Results

### Severity Levels

- **CRITICAL**: Immediate action required
- **HIGH**: Fix in next release
- **MEDIUM**: Address in upcoming sprint
- **LOW**: Fix when convenient
- **INFO**: Informational only

### False Positives

If a finding is a false positive:

1. **For gosec**: Add inline comment
   ```go
   // #nosec G204 - input is validated
   cmd := exec.Command(sanitizedInput)
   ```

2. **For govulncheck**: Update dependencies or document exception

3. **For Trivy**: Add to `.trivyignore` file with justification

## Remediation Workflow

1. **Review findings** in GitHub Security tab or local reports
2. **Assess severity** and prioritize fixes
3. **Update dependencies** for vulnerability fixes:
   ```bash
   go get -u ./...
   go mod tidy
   ```
4. **Fix code issues** identified by gosec
5. **Re-run scans** to verify fixes:
   ```bash
   make security-scan
   ```
6. **Commit and push** fixes

## Security Policy

### Dependency Updates

- Security patches: Within 48 hours
- High severity: Within 1 week
- Medium severity: Within 2 weeks
- Low severity: Next release cycle

### Vulnerability Disclosure

Report security vulnerabilities to: security@boundary-siem.io

See `SECURITY.md` for full disclosure policy.

## Best Practices

1. **Run scans locally** before pushing code
2. **Address findings** before merging pull requests
3. **Keep dependencies updated** regularly
4. **Review security alerts** from GitHub
5. **Enable branch protection** requiring security scans to pass

## Configuration

### gosec Configuration

Create `.gosec.json` to customize scanning:

```json
{
  "severity": "medium",
  "confidence": "medium",
  "exclude": ["G104"],
  "exclude-dirs": ["vendor", "test"]
}
```

### Trivy Configuration

Create `.trivy.yaml` for custom rules:

```yaml
severity:
  - CRITICAL
  - HIGH
  - MEDIUM
vulnerability:
  type:
    - os
    - library
scan:
  skip-dirs:
    - vendor
```

## Continuous Improvement

Regular security practices:
- Weekly dependency updates
- Monthly security audit reviews
- Quarterly penetration testing
- Annual third-party security assessment

## Help and Support

- **GitHub Issues**: Report scan issues
- **Security Team**: security@boundary-siem.io
- **Documentation**: See `SECURITY_AUDIT_REPORT.md`

## Makefile Targets

See `Makefile.security` for all available targets:

```bash
make -f Makefile.security security-help
```
