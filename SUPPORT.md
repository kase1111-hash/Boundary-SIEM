# Support

This document outlines how to get help with Boundary-SIEM.

## Documentation

Before seeking support, please check our documentation:

| Resource | Description |
|----------|-------------|
| [README.md](README.md) | Project overview, quick start, and configuration |
| [SIEM_SPECIFICATION.md](SIEM_SPECIFICATION.md) | Technical specification and API reference |
| [SECURITY.md](SECURITY.md) | Security features and vulnerability reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| [CHANGELOG.md](CHANGELOG.md) | Version history and release notes |
| [docs/](docs/) | Additional documentation |

## Getting Help

### GitHub Discussions

For questions, ideas, and general discussion:

- **Q&A**: Ask questions and get help from the community
- **Ideas**: Share feature ideas and suggestions
- **Show and Tell**: Share your Boundary-SIEM deployments and integrations

[Open a Discussion](https://github.com/kase1111-hash/Boundary-SIEM/discussions)

### GitHub Issues

For bug reports and feature requests:

- **Bug Reports**: Report reproducible bugs with detailed information
- **Feature Requests**: Request new features or enhancements

[Open an Issue](https://github.com/kase1111-hash/Boundary-SIEM/issues)

**Note**: Please use the issue templates to ensure you provide all necessary information.

## Common Issues

### Build Issues

**Problem**: Build fails with dependency errors
```bash
# Solution: Update dependencies
make deps
go mod tidy
```

**Problem**: Binary not found after build
```bash
# Solution: Check the bin directory
ls -la ./bin/
# Binaries are in: ./bin/siem-ingest and ./bin/boundary-siem
```

### Runtime Issues

**Problem**: ClickHouse connection fails
```bash
# Solution: Verify ClickHouse is running
docker ps | grep clickhouse

# Start ClickHouse if needed
docker-compose -f deployments/clickhouse/docker-compose.yaml up -d
```

**Problem**: Port already in use
```bash
# Solution: Check what's using the port
lsof -i :8080

# Or change the port in configs/config.yaml
```

**Problem**: TUI fails to connect to server
```bash
# Solution: Verify server is running
curl http://localhost:8080/health

# Specify server URL when running TUI
./bin/boundary-siem --server http://localhost:8080
```

### Configuration Issues

**Problem**: Configuration file not found
```bash
# Solution: Ensure config file exists
ls configs/config.yaml

# Or set environment variable
export BOUNDARY_CONFIG_PATH=/path/to/config.yaml
```

**Problem**: Admin password not set
```bash
# Solution: Set via environment variable
export BOUNDARY_ADMIN_PASSWORD='YourSecureP@ssw0rd123!'

# Or check generated password file
cat /var/lib/boundary-siem/admin-password.txt
# or
cat ./admin-password.txt
```

## Security Issues

**DO NOT** report security vulnerabilities in public issues.

For security vulnerabilities, please:

1. Email: security@boundary-siem.io
2. Use GitHub Security Advisories (private)

See [SECURITY.md](SECURITY.md) for our complete security policy.

## Commercial Support

Commercial support options are not currently available. For enterprise inquiries, please open a GitHub Discussion.

## Community Guidelines

When seeking support:

1. **Search first**: Check existing issues and discussions
2. **Be specific**: Include version, OS, configuration, and error messages
3. **Provide context**: Explain what you're trying to accomplish
4. **Be patient**: Maintainers are volunteers with limited time
5. **Be respectful**: Treat others as you'd like to be treated

## Response Times

As an open-source project maintained by volunteers:

| Priority | Expected Response |
|----------|-------------------|
| Security vulnerabilities | 48 hours |
| Critical bugs | 1 week |
| General issues | 2 weeks |
| Feature requests | Best effort |
| Questions | Best effort |

## Contributing Back

The best way to ensure the project's long-term success is to contribute:

- Report bugs with detailed reproduction steps
- Submit pull requests for fixes and features
- Improve documentation
- Help others in discussions
- Share your experience and use cases

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## Stay Updated

- **Watch** the repository for release notifications
- **Star** the repository to show support
- Check [CHANGELOG.md](CHANGELOG.md) for release notes

---

Thank you for using Boundary-SIEM!
