# Built-in Plugins

ASH ships with a comprehensive set of built-in plugins that provide core security scanning, reporting, and file processing capabilities. These plugins are automatically available and can be configured to meet your specific security requirements.

## Overview

Built-in plugins are organized into four main categories:

| Category                                  | Purpose                                                      | Count | Location           |
|-------------------------------------------|--------------------------------------------------------------|-------|--------------------|
| **[Scanners](scanners.md)**               | Analyze code and infrastructure for security vulnerabilities | 10    | `scanners/`        |
| **[Reporters](reporters.md)**             | Generate scan results in various output formats              | 13    | `reporters/`       |
| **[Converters](converters.md)**           | Process and prepare files for scanning                       | 2     | `converters/`      |
| **[Event Handlers](event-handlers.md)** | Handle scan lifecycle events and notifications               | 1     | `event_handlers/` |

## Quick Start

All built-in plugins are enabled by default and require no additional configuration to get started:

```bash
# Run with default built-in scanners
ash scan /path/to/code

# Use specific built-in scanners only
ash scan /path/to/code --scanners bandit,semgrep

# Generate reports in multiple formats
ash scan /path/to/code --reporters sarif,html,csv
```

## Configuration

Built-in plugins can be customized through configuration files:

```yaml
# ash-config.yml
scanners:
  bandit:
    enabled: true
    severity_threshold: "MEDIUM"
    options:
      confidence_level: "HIGH"

  semgrep:
    enabled: true
    options:
      rules: "auto"
      timeout: 300

reporters:
  html:
    enabled: true
    options:
      include_suppressed: false

  sarif:
    enabled: true
    options:
      include_rule_metadata: true
```

## Plugin Categories

### Security Scanners

Built-in scanners cover a wide range of security analysis:

- **Static Analysis**: Bandit, Semgrep, OpenGrep
- **Infrastructure Security**: CDK-Nag, CFN-Nag, Checkov
- **Dependency Scanning**: NPM Audit, Grype
- **Secret Detection**: Detect-Secrets
- **SBOM Generation**: Syft

### Output Formats

Multiple output formats support different use cases:

- **CI/CD Integration**: SARIF, JUnit XML, GitLab SAST
- **Human Readable**: HTML, Markdown, Text
- **Data Processing**: CSV, JSON, YAML
- **Compliance**: SPDX, CycloneDX, OCSF

### File Processing

Converters handle various file types:

- **Archives**: Automatic extraction of zip, tar, and other compressed formats
- **Notebooks**: Jupyter notebook processing for Python code analysis

## Dependencies

Built-in plugins may require external tools to be installed:

```bash
# Check plugin dependencies
ash dependencies --check

# Install missing dependencies (where possible)
ash dependencies --install
```

## Advanced Usage

### Plugin-Specific Configuration

Each plugin supports specific configuration options:

```yaml
scanners:
  checkov:
    options:
      framework: ["terraform", "cloudformation"]
      check: ["CKV_AWS_*"]
      skip_check: ["CKV_AWS_123"]
      external_checks_dir: "/path/to/custom/checks"
```

### Selective Plugin Execution

Control which plugins run:

```bash
# Run only infrastructure scanners
ash scan --scanners cdk-nag,cfn-nag,checkov

# Exclude specific scanners
ash scan --exclude-scanners grype,syft

# Generate only compliance reports
ash scan --reporters spdx,cyclonedx
```

### Integration with External Tools

Built-in plugins integrate with popular security tools:

- **Semgrep**: Uses Semgrep Registry rules
- **Bandit**: Leverages Python AST analysis
- **Checkov**: Supports custom policy frameworks
- **Grype**: Integrates with vulnerability databases

## Troubleshooting

Common issues and solutions:

### Scanner Not Found
```bash
# Check if scanner dependencies are installed
ash dependencies --check --scanner bandit

# Install missing dependencies
pip install bandit
```

### Configuration Issues
```bash
# Validate configuration
ash config --validate

# Show effective configuration
ash config --show
```

### Performance Optimization
```bash
# Run scanners in parallel (default)
ash scan --parallel

# Limit concurrent scanners
ash scan --max-workers 2

# Skip time-intensive scanners for quick feedback
ash scan --exclude-scanners grype,syft
```

## Next Steps

- **[Scanner Details](scanners.md)**: Detailed information about each security scanner
- **[Reporter Details](reporters.md)**: Complete guide to output formats
- **[Configuration Guide](../../configuration-guide.md)**: Advanced configuration options
- **[Plugin Development](../development-guide.md)**: Create custom plugins
