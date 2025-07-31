# ASH Trivy Plugin

This plugin integrates [Aquasec's Trivy](https://trivy.dev/) CLI tool with the Automated Security Helper (ASH) to provide comprehensive repository scanning for vulnerabilities, misconfigurations, secrets, and license issues.

## Overview

The Trivy plugin enables ASH to leverage Trivy's powerful scanning capabilities for:

- **Vulnerability Detection**: Identifies known CVEs in dependencies and packages
- **Misconfiguration Scanning**: Detects security misconfigurations in IaC files
- **Secret Detection**: Finds hardcoded secrets and sensitive information
- **License Scanning**: Analyzes software licenses and compliance issues

## Prerequisites

### Install Trivy CLI

The plugin requires Trivy CLI to be installed and available in your system PATH.

**macOS (Homebrew)**:
```bash
brew install trivy
```

**Linux**:
```bash
# Download and install latest release
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

**Other platforms**: See [Trivy Installation Guide](https://aquasecurity.github.io/trivy/latest/getting-started/installation/)

### Verify Installation

```bash
trivy --version
```

## Quick Start

### Basic Configuration

Add to your `.ash/.ash.yaml`:

```yaml
scanners:
  trivy-repo:
    enabled: true
    severity_threshold: "MEDIUM"
```

### Run Trivy Scan

```bash
# Scan current directory
uv run ash --scanners trivy-repo

# Scan specific directory
uv run ash --scanners trivy-repo /path/to/project
```

## Configuration Options

### Scanner Types

Configure which types of security issues to detect:

```yaml
scanners:
  trivy-repo:
    enabled: true
    options:
      scanners: ["vuln", "secret", "misconfig", "license"]  # Default: all types
```

Available scanner types:
- `vuln`: Vulnerability detection
- `secret`: Secret detection  
- `misconfig`: Misconfiguration detection
- `license`: License scanning

### Advanced Options

```yaml
scanners:
  trivy-repo:
    enabled: true
    severity_threshold: "HIGH"
    options:
      scanners: ["vuln", "secret"]
      license_full: true          # Deep license scanning (default: true)
      ignore_unfixed: true        # Only show fixed vulnerabilities (default: true)
      disable_telemetry: true     # Disable usage analytics (default: true)
```

## Usage Examples

### Vulnerability Scanning Only

```yaml
scanners:
  trivy-repo:
    enabled: true
    options:
      scanners: ["vuln"]
      ignore_unfixed: false  # Include unfixed vulnerabilities
```

### Secret Detection Focus

```yaml
scanners:
  trivy-repo:
    enabled: true
    severity_threshold: "LOW"
    options:
      scanners: ["secret"]
```

### Infrastructure Scanning

```yaml
scanners:
  trivy-repo:
    enabled: true
    options:
      scanners: ["misconfig"]
      severity_threshold: "MEDIUM"
```

### Combined with Other Scanners

```bash
# Use Trivy alongside other ASH scanners
uv run ash --scanners trivy-repo,bandit,semgrep
```

## Output Integration

Trivy results are integrated into ASH's unified reporting system:

- **SARIF Format**: Machine-readable results for CI/CD integration
- **HTML Reports**: Visual security dashboard
- **JSON/CSV**: Structured data for analysis
- **Markdown**: Human-readable summaries

## Performance Considerations

- **First Run**: Trivy downloads vulnerability databases (may take time)
- **Subsequent Runs**: Uses cached databases for faster scanning
- **Large Repositories**: Consider using severity thresholds to focus on critical issues
- **CI/CD**: Database updates can be cached between pipeline runs

## Troubleshooting

### Common Issues

**Trivy not found**:
```bash
# Check if Trivy is in PATH
which trivy

# Install if missing (macOS)
brew install trivy
```

**Database download issues**:
```bash
# Manually update Trivy database
trivy image --download-db-only
```

**Permission errors**:
```bash
# Ensure Trivy cache directory is writable
ls -la ~/.cache/trivy/
```

### Debug Mode

Enable verbose logging to troubleshoot issues:

```bash
uv run ash --scanners trivy-repo --log-level DEBUG
```

## Integration Examples

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: ash-trivy
        name: ASH Trivy Security Scan
        entry: uv run ash --scanners trivy-repo --mode precommit
        language: system
        pass_filenames: false
```

### CI/CD Pipeline

```yaml
# GitHub Actions example
- name: Security Scan with Trivy
  run: |
    uv run ash --scanners trivy-repo --output-format sarif
    # Upload SARIF to GitHub Security tab
    gh api repos/${{ github.repository }}/code-scanning/sarifs \
      --method POST --field sarif=@.ash/ash_output/reports/results.sarif
```

## Documentation

For comprehensive documentation and advanced configuration options, see:
- [ASH Community Plugins Documentation](../../../docs/content/docs/plugins/community/trivy-plugin.md)
- [Trivy Official Documentation](https://aquasecurity.github.io/trivy/)

## Support

- **ASH Issues**: [GitHub Issues](https://github.com/awslabs/automated-security-helper/issues)
- **Trivy Issues**: [Trivy GitHub](https://github.com/aquasecurity/trivy/issues)
- **Community**: [ASH Discussions](https://github.com/awslabs/automated-security-helper/discussions)