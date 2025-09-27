# Quick Start

This guide will help you get started with ASH v3 quickly. For more detailed information, refer to the other documentation pages.

## Overview

ASH v3 has been entirely rewritten in Python with significant improvements:

1. **Python-based CLI**: New Python entrypoint with backward compatibility for shell scripts
2. **Multiple Execution Modes**: Run in `local`, `container`, or `precommit` mode
3. **New Output Structure**: Results stored in `.ash/ash_output/` with multiple report formats
4. **Enhanced Configuration**: YAML-based configuration with CLI overrides

## Installation

Choose one of these methods to install ASH:

### Option 1: Using uvx (recommended)

Prerequisites: Python 3.10+, [uv](https://docs.astral.sh/uv/getting-started/installation/)

#### Linux/macOS
```bash
# Install uv if you don't have it
curl -sSf https://astral.sh/uv/install.sh | sh

# Create an alias for ASH
alias ash="uvx git+https://github.com/awslabs/automated-security-helper.git@v3.0.1"
```

#### Windows PowerShell
```powershell
# Install uv if you don't have it
irm https://astral.sh/uv/install.ps1 | iex

# Create a function for ASH
function ash { uvx git+https://github.com/awslabs/automated-security-helper.git@v3.0.1 $args }
```

### Option 2: Using pipx

Prerequisites: Python 3.10+, [pipx](https://pipx.pypa.io/stable/installation/)

```bash
pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.0.1
```

### Option 3: Using pip

Prerequisites: Python 3.10+

```bash
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.0.1
```

## Basic Usage

### Running Your First Scan

Navigate to your project directory and run:

```bash
# Run a scan in local mode (Python-based scanners only)
ash --mode local

# Run a scan in container mode (all scanners)
ash --mode container

# Run a scan in precommit mode (fast subset of scanners)
ash --mode precommit
```

The `precommit` mode runs a subset of fast scanners:
- bandit
- detect-secrets
- checkov
- cdk-nag
- npm-audit (if available)

### Specifying Source and Output Directories

```bash
ash --source-dir /path/to/code --output-dir /path/to/output
```

### Viewing Results

After running a scan, check the output directory (default: `.ash/ash_output/`):

```bash
# View the summary report
cat .ash/ash_output/reports/ash.summary.txt

# Open the HTML report in your browser
open .ash/ash_output/reports/ash.html  # On macOS
xdg-open .ash/ash_output/reports/ash.html  # On Linux
start .ash/ash_output/reports/ash.html  # On Windows
```

Available report formats:
- `ash.summary.txt`: Human-readable text summary
- `ash.summary.md`: Markdown summary for GitHub PRs and other platforms
- `ash.html`: Interactive HTML report
- `ash.csv`: CSV report for filtering and sorting findings
- `ash_aggregated_results.json`: Complete machine-readable results

## Configuration

ASH uses a YAML configuration file. Create a basic configuration:

```bash
# Initialize a new configuration file
ash config init
```

This creates `.ash/.ash.yaml` with default settings. Edit this file to customize your scan:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json
project_name: my-project
global_settings:
  severity_threshold: MEDIUM
  ignore_paths:
    - path: 'tests/test_data'
      reason: 'Test data only'
  suppressions:
    - rule_id: 'RULE-123'
      file_path: 'src/example.py'
      line_start: 10
      line_end: 15
      reason: 'False positive due to test mock'
      expiration: '2025-12-31'
    - rule_id: 'RULE-456'
      file_path: 'src/*.js'
      reason: 'Known issue, planned for fix in v2.0'
scanners:
  bandit:
    enabled: true
  semgrep:
    enabled: true
reporters:
  markdown:
    enabled: true
  html:
    enabled: true
```

## Common Tasks

### Overriding Configuration Options

```bash
# Enable a specific scanner
ash --config-overrides 'scanners.bandit.enabled=true'

# Change severity threshold
ash --config-overrides 'global_settings.severity_threshold=LOW'

# Ignore a path
ash --config-overrides 'global_settings.ignore_paths+=[{"path": "build/", "reason": "Generated files"}]'
```

### Running Specific Scanners

```bash
# Run only specific scanners
ash --scanners bandit,semgrep

# Exclude specific scanners
ash --exclude-scanners cfn-nag,cdk-nag
```

### Generating Specific Reports

```bash
# Generate specific report formats
ash --output-formats markdown,html,json

# Generate a report from existing results
ash report --format html --output-dir ./my-scan-results
```

## Using ASH with pre-commit

Add this to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/awslabs/automated-security-helper
    rev: v3.0.0
    hooks:
      - id: ash-simple-scan
```

Run with:

```bash
pre-commit run ash-simple-scan --all-files
```

## Next Steps

- [Configure ASH](configuration-guide.md) for your project
- Learn about [ASH's CLI options](cli-reference.md)
- Set up [ASH in CI/CD pipelines](../tutorials/running-ash-in-ci.md)
- Explore [advanced features](advanced-usage.md)