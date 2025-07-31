# ASH Snyk Code Plugin

This plugin integrates [Snyk Code](https://snyk.io/product/snyk-code/) CLI tool with the Automated Security Helper (ASH) to provide comprehensive static application security testing (SAST) for source code vulnerabilities.

## Overview

The Snyk Code plugin enables ASH to leverage Snyk's powerful static analysis capabilities for:

- **Static Application Security Testing (SAST)**: Identifies security vulnerabilities in source code
- **Real-time Analysis**: Fast scanning with minimal false positives
- **Multi-language Support**: Supports JavaScript, TypeScript, Python, Java, C#, PHP, Go, Ruby, Scala, Swift, and mor. See a full list [here](https://docs.snyk.io/supported-languages-package-managers-and-frameworks#supported-languages)
- **Developer-friendly Results**: Provides actionable remediation guidance with code examples

## Prerequisites

### Install Snyk CLI

The plugin requires Snyk CLI to be installed and available in your system PATH.

**npm (Recommended)**:
```bash
npm install -g snyk
```

**Homebrew (macOS)**:
```bash
brew install snyk/tap/snyk
```

**Manual Installation**:
```bash
# Download and install latest release
curl -Lo snyk https://github.com/snyk/cli/releases/latest/download/snyk-linux
chmod +x snyk
sudo mv snyk /usr/local/bin/
```

**Other platforms**: See [Snyk CLI Installation Guide](https://docs.snyk.io/cli-ide-and-ci-cd-integrations/snyk-cli/getting-started-with-the-snyk-cli)

### Authentication

Snyk Code requires authentication to access the scanning service:

**Option 1: Environment Variable**
```bash
export SNYK_TOKEN=your-snyk-token
```

**Option 2: CLI Authentication**
```bash
snyk auth
```

**Option 3: Configuration File**
The plugin will automatically check for credentials at `~/.config/configstore/snyk.json`

### Verify Installation

```bash
snyk --version
snyk code test --help
```

## Quick Start

### Basic Configuration

Snyk code plugin is not included by default with ASH since it requires authentication.
Include Snyk plugin module in your `.ash/.ash.yaml` configuration file

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_snyk_plugins
```

Add to your `.ash/.ash.yaml`:

```yaml
scanners:
  snyk-code:
    enabled: true
    severity_threshold: "MEDIUM"
```

### Run Snyk Code Scan

```bash
# Scan current directory
uv run ash --scanners snyk-code

# Scan specific directory
uv run ash --scanners snyk-code /path/to/project
```

### Run Snyk Code Scan without an ASH configuration file

If you want to run Snyk code scan without saving a configuration file for ASH, use the following
command to enable the plugin

```bash
# Scan current directory only with snyk-code
uv run ash --scanners snyk-code --config-overrides "ash_plugin_modules+=[\"automated_security_helper.plugin_modules.ash_snyk_plugins\"]"

# SCan current directory with all available scanners (including snyk-code)
uv run ash  --config-overrides "ash_plugin_modules+=[\"automated_security_helper.plugin_modules.ash_snyk_plugins\"]"

```

## Configuration Options

### Severity Filtering

Configure the minimum severity level for reported vulnerabilities:

```yaml
scanners:
  snyk-code:
    enabled: true
    severity_threshold: "HIGH"  # Options: LOW, MEDIUM, HIGH, CRITICAL
```

### Advanced Options

```yaml
scanners:
  snyk-code:
    enabled: true
    severity_threshold: "MEDIUM"
    options:
      # Additional scanner-specific options can be added here
```

## Usage Examples

### High Severity Issues Only

```yaml
scanners:
  snyk-code:
    enabled: true
    severity_threshold: "HIGH"
```

### All Severity Levels

```yaml
scanners:
  snyk-code:
    enabled: true
    severity_threshold: "LOW"
```

### Combined with Other Scanners

```bash
# Use Snyk Code alongside other ASH scanners
uv run ash --scanners snyk-code,bandit,semgrep
```

### CI/CD Integration

```bash
# Run in container mode for CI/CD
uv run ash --mode container --scanners snyk-code
```

## Output Integration

Snyk Code results are integrated into ASH's unified reporting system:

- **SARIF Format**: Machine-readable results for CI/CD integration
- **HTML Reports**: Visual security dashboard with remediation guidance
- **JSON/CSV**: Structured data for analysis and tracking
- **Markdown**: Human-readable summaries for pull requests

## Performance Considerations

- **First Run**: May require initial authentication and setup
- **Network Dependency**: Requires internet connection for cloud-based analysis
- **Large Codebases**: Scanning time scales with codebase size
- **Rate Limits**: Snyk may apply rate limits based on your subscription tier

## Troubleshooting

### Common Issues

**Snyk CLI not found**:
```bash
# Check if Snyk is in PATH
which snyk

# Install if missing
npm install -g snyk
```

**Authentication errors**:
```bash
# Check authentication status
snyk auth

# Set token via environment variable
export SNYK_TOKEN=your-token-here
```

**Network connectivity issues**:
```bash
# Test connectivity to Snyk services
snyk test --dry-run
```

**Empty directory warnings**:
The plugin will skip scanning if the target directory is empty or doesn't exist, logging an appropriate warning message.

### Debug Mode

Enable verbose logging to troubleshoot issues:

```bash
uv run ash --scanners snyk-code --log-level DEBUG
```

### Offline Mode

**Note**: Snyk Code requires internet connectivity and will be automatically disabled in offline mode:

```bash
# Snyk Code will be skipped in offline mode
uv run ash --offline --scanners snyk-code
```

## Integration Examples

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: ash-snyk-code
        name: ASH Snyk Code Security Scan
        entry: uv run ash --scanners snyk-code --mode precommit
        language: system
        pass_filenames: false
```

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Snyk CLI
        run: npm install -g snyk
      - name: Run ASH with Snyk Code
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        run: |
          uv run ash --scanners snyk-code --output-format sarif
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: .ash/ash_output/reports/ash.sarif
```

### GitLab CI

```yaml
# .gitlab-ci.yml
snyk-security-scan:
  stage: test
  image: node:18
  before_script:
    - npm install -g snyk
  script:
    - uv run ash --scanners snyk-code
  variables:
    SNYK_TOKEN: $SNYK_TOKEN
  artifacts:
    reports:
      sast: .ash/ash_output/reports/ash.sarif
```

## Supported Languages

Snyk Code supports static analysis for:

- **JavaScript/TypeScript**: Node.js, React, Angular, Vue.js
- **Python**: Django, Flask, FastAPI
- **Java**: Spring, Maven, Gradle projects
- **C#/.NET**: .NET Framework, .NET Core
- **PHP**: Laravel, Symfony, WordPress
- **Go**: Standard library and popular frameworks
- **Ruby**: Rails, Sinatra
- **Scala**: Play Framework, Akka
- **Swift**: iOS/macOS applications

Full list of supported languages is available at the [Snyk Website](https://docs.snyk.io/supported-languages-package-managers-and-frameworks#supported-languages)

## Documentation

For comprehensive documentation and advanced configuration options, see:
- [ASH Community Plugins Documentation](../../../docs/content/docs/plugins/community/snyk-plugin.md)
- [Snyk CLI Documentation](https://docs.snyk.io/cli-ide-and-ci-cd-integrations/snyk-cli)
- [Snyk Code Documentation](https://docs.snyk.io/products/snyk-code)

## Support

- **ASH Issues**: [GitHub Issues](https://github.com/awslabs/automated-security-helper/issues)
- **Snyk Issues**: [Snyk Support](https://support.snyk.io/)
- **Community**: [ASH Discussions](https://github.com/awslabs/automated-security-helper/discussions)