# Contributing to Boundary-SIEM

Thank you for your interest in contributing to Boundary-SIEM! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Bugs](#reporting-bugs)
- [Requesting Features](#requesting-features)
- [Security Vulnerabilities](#security-vulnerabilities)

## Getting Started

### Prerequisites

- **Go 1.21+** - [Installation Guide](https://golang.org/doc/install)
- **Docker & Docker Compose** - For local development dependencies
- **ClickHouse 23.8+** (optional) - For persistent storage testing
- **Git** - Version control

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Boundary-SIEM.git
   cd Boundary-SIEM
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/kase1111-hash/Boundary-SIEM.git
   ```

## Development Setup

### Install Dependencies

```bash
# Download Go module dependencies
make deps

# Install development tools
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
```

### Start Local Services

```bash
# Start ClickHouse (optional, for storage testing)
docker-compose -f deployments/clickhouse/docker-compose.yaml up -d
```

### Build

```bash
# Build all binaries
make build

# Or build individually
make build-ingest  # Build SIEM server
make build-tui     # Build Terminal UI
```

### Run

```bash
# Run the SIEM server
make run

# In another terminal, run the TUI
make run-tui
```

## Code Style

### Go Standards

- Follow the [Effective Go](https://golang.org/doc/effective_go) guidelines
- Use `gofmt` for formatting (run `make fmt`)
- Follow Go naming conventions (camelCase for private, PascalCase for exported)
- Keep functions focused and small
- Document exported types and functions

### Linting

```bash
# Run all linters
make lint

# This runs go vet and golangci-lint (if installed)
```

### Project Structure

```
boundary-siem/
├── cmd/                    # Application entry points
│   ├── boundary-siem/     # TUI client
│   └── siem-ingest/       # SIEM server
├── internal/              # Private application code
│   ├── api/              # REST API handlers
│   ├── blockchain/       # Blockchain-specific modules
│   ├── correlation/      # Event correlation engine
│   ├── detection/        # Detection rules
│   ├── ingest/          # Event ingestion
│   ├── schema/          # Event schema
│   ├── search/          # Search engine
│   ├── storage/         # ClickHouse storage
│   └── tui/             # Terminal UI
├── configs/              # Configuration files
├── deploy/               # Deployment configurations
├── deployments/          # Docker Compose files
└── docs/                 # Documentation
```

### Commit Messages

Use clear, descriptive commit messages:

- Start with a verb in the imperative mood (Add, Fix, Update, Remove)
- Keep the first line under 72 characters
- Reference issue numbers when applicable

Examples:
```
Add validator monitoring detection rules

Fix CEF parser handling of malformed timestamps

Update ClickHouse storage batch writer for better performance

Remove deprecated API endpoint /v1/legacy/events
```

## Testing

### Running Tests

```bash
# Run all tests with race detection
make test

# Run tests with coverage report
make test-coverage

# Run unit tests only (faster)
make test-unit

# Run specific package tests
go test -v ./internal/correlation/...
```

### Writing Tests

- Place tests in the same package as the code being tested
- Use table-driven tests for comprehensive coverage
- Test edge cases and error conditions
- Include benchmarks for performance-critical code

Example:
```go
func TestEventValidation(t *testing.T) {
    tests := []struct {
        name    string
        event   *Event
        wantErr bool
    }{
        {
            name:    "valid event",
            event:   &Event{ID: "123", Timestamp: time.Now()},
            wantErr: false,
        },
        {
            name:    "missing timestamp",
            event:   &Event{ID: "123"},
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := tt.event.Validate()
            if (err != nil) != tt.wantErr {
                t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### Security Testing

```bash
# Run security scanners
make security

# Generate detailed security report
make security-report

# Run all CI checks (lint, security, test)
make ci
```

## Submitting Changes

### Branch Naming

Use descriptive branch names:
- `feature/add-kafka-consumer`
- `fix/cef-parser-memory-leak`
- `docs/update-api-reference`
- `refactor/storage-batch-writer`

### Pull Request Process

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and commit them

3. **Ensure all checks pass**:
   ```bash
   make ci  # Runs lint, security, and tests
   ```

4. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Open a Pull Request** on GitHub

### Pull Request Guidelines

- Fill out the PR template completely
- Link related issues
- Provide a clear description of changes
- Include screenshots for UI changes
- Ensure all CI checks pass
- Request review from maintainers

### Code Review

All changes require review before merging. Reviewers will look for:

- Code correctness and functionality
- Test coverage
- Security considerations
- Performance implications
- Documentation updates
- Adherence to code style

## Reporting Bugs

### Before Reporting

1. Check existing issues to avoid duplicates
2. Verify the bug on the latest version
3. Collect relevant information (logs, configuration, environment)

### Bug Report Contents

- **Clear title** describing the issue
- **Environment details** (OS, Go version, deployment type)
- **Steps to reproduce**
- **Expected behavior**
- **Actual behavior**
- **Logs and error messages**
- **Screenshots** (if applicable)

Use the bug report issue template for consistency.

## Requesting Features

### Feature Request Contents

- **Clear description** of the feature
- **Use case** explaining why it's needed
- **Proposed implementation** (if you have ideas)
- **Alternatives considered**
- **Additional context**

Use the feature request issue template for consistency.

## Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Please report security issues responsibly:
- Email: security@boundary-siem.io
- GitHub Security Advisories (private)

See [SECURITY.md](SECURITY.md) for our full security policy.

## Additional Resources

- [README.md](README.md) - Project overview and quick start
- [SIEM_SPECIFICATION.md](SIEM_SPECIFICATION.md) - Technical specification
- [docs/](docs/) - Additional documentation
- [CHANGELOG.md](CHANGELOG.md) - Version history

## Questions?

- Open a [Discussion](https://github.com/kase1111-hash/Boundary-SIEM/discussions) on GitHub
- Check existing issues and discussions
- Review the documentation

Thank you for contributing to Boundary-SIEM!
