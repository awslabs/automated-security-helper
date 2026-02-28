# ASH - Automated Security Helper

[![ASH - Core Pipeline](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-build-and-scan.yml/badge.svg)](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-build-and-scan.yml)
[![ASH - Matrix Unit Tests](https://github.com/awslabs/automated-security-helper/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/awslabs/automated-security-helper/actions/workflows/unit-tests.yml)

## Table of Contents
- [Table of Contents](#table-of-contents)
- [Overview](#overview)
- [Key Features in ASH v3](#key-features-in-ash-v3)
- [Built-In Scanners](#built-in-scanners)
- [Prerequisites](#prerequisites)
  - [Runtime Requirements](#runtime-requirements)
- [Installation Options](#installation-options)
  - [Quick Install (Recommended)](#quick-install-recommended)
  - [Other Installation Methods](#other-installation-methods)
    - [Using `uvx`](#using-uvx)
    - [Using `pip`](#using-pip)
    - [Clone the Repository](#clone-the-repository)
- [Basic Usage](#basic-usage)
  - [Sample Output](#sample-output)
- [AI Integration with MCP](#ai-integration-with-mcp)
  - [MCP Server Features](#mcp-server-features)
  - [Installation and Setup](#installation-and-setup)
    - [Prerequisites](#prerequisites-1)
    - [Client Configuration](#client-configuration)
  - [Available MCP Tools](#available-mcp-tools)
  - [Usage Examples](#usage-examples)
  - [Configuration Support](#configuration-support)
- [Configuration](#configuration)
- [Using ASH with pre-commit](#using-ash-with-pre-commit)
- [Output Files](#output-files)
- [FAQ](#faq)
- [Documentation](#documentation)
- [Feedback and Contributing](#feedback-and-contributing)
- [Security](#security)
- [License](#license)
- [Star History](#star-history)

## Overview

ASH (Automated Security Helper) is a security scanning tool designed to help you identify potential security issues in your code, infrastructure, and IAM configurations as early as possible in your development process.

- ASH is not a replacement for human review or team/customer security standards
- It leverages lightweight, open-source tools for flexibility and portability
- ASH v3 has been completely rewritten in Python with significant improvements to usability and functionality

## Key Features in ASH v3

- **Python-based CLI**: ASH now has a Python-based CLI entrypoint while maintaining backward compatibility with the shell script entrypoint
- **Multiple Execution Modes**: Run ASH in `local`, `container`, or `precommit` mode depending on your needs
- **Enhanced Configuration**: Support for YAML/JSON configuration files with overrides via CLI parameters
- **Improved Reporting**: Multiple report formats including JSON, Markdown, HTML, and CSV
- **Scanner Validation System**: Comprehensive validation ensures all expected scanners are registered, enabled, queued, executed, and included in results
- **Pluggable Architecture**: Extend ASH with custom plugins, scanners, and reporters
- **Unified Output Format**: Standardized output format that can be exported to multiple formats (SARIF, JSON, HTML, Markdown, CSV)
- **UV Package Management**: ASH now uses UV for faster dependency resolution and tool isolation
- **Comprehensive Testing**: Extensive integration test suite validates UV migration functionality across platforms

## Built-In Scanners

ASH v3 integrates multiple open-source security tools as scanners. Tools like Bandit, Checkov, and Semgrep are managed via UV's tool isolation system, which automatically installs and runs them in isolated environments without affecting your project dependencies:

| Scanner                                                       | Type      | Languages/Frameworks                                                                         | Installation (Local Mode)                                               |
|---------------------------------------------------------------|-----------|----------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| [Bandit](https://github.com/PyCQA/bandit)                     | SAST      | Python                                                                                       | Managed via UV tool isolation (auto-installed: `bandit>=1.7.0`)        |
| [Semgrep](https://github.com/semgrep/semgrep)                 | SAST      | Python, JavaScript, TypeScript, Java, Go, C#, Ruby, PHP, Kotlin, Swift, Bash, and more       | Managed via UV tool isolation (auto-installed: `semgrep>=1.125.0`)     |
| [detect-secrets](https://github.com/Yelp/detect-secrets)      | Secrets   | All text files                                                                               | Included with ASH                                                       |
| [Checkov](https://github.com/bridgecrewio/checkov)            | IaC, SAST | Terraform, CloudFormation, Kubernetes, Dockerfile, ARM Templates, Serverless, Helm, and more | Managed via UV tool isolation (auto-installed: `checkov>=3.2.0,<4.0.0`) |
| [cfn_nag](https://github.com/stelligent/cfn_nag)              | IaC       | CloudFormation                                                                               | `gem install cfn-nag`                                                   |
| [cdk-nag](https://github.com/cdklabs/cdk-nag)                 | IaC       | CloudFormation                                                                               | Included with ASH                                                       |
| [npm-audit](https://docs.npmjs.com/cli/v8/commands/npm-audit) | SCA       | JavaScript/Node.js                                                                           | Install Node.js/npm                                                     |
| [Grype](https://github.com/anchore/grype)                     | SCA       | Python, JavaScript/Node.js, Java, Go, Ruby, and more                                         | See [Grype Installation](https://github.com/anchore/grype#installation) |
| [Syft](https://github.com/anchore/syft)                       | SBOM      | Python, JavaScript/Node.js, Java, Go, Ruby, and more                                         | See [Syft Installation](https://github.com/anchore/syft#installation)   |

## Prerequisites

### Runtime Requirements

| Mode      | Requirements                                                                                                                                                         | Notes                                                    |
|-----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------|
| Local     | Python 3.10+, UV package manager                                                                                                                                     | Some scanners require additional tools (see table above) |
| Container | Any OCI-compatible container runtime ([Finch](https://github.com/runfinch/finch), [Docker](https://docs.docker.com/get-docker/), [Podman](https://podman.io/), etc.) | On Windows: WSL2 is typically required                   |
| Precommit | Python 3.10+, UV package manager                                                                                                                                     | Subset of scanners, optimized for speed                  |

## Installation Options

### Quick Install (Recommended)

```bash
# Install uv on Linux/macOS if it isn't installed already
curl -sSfL https://astral.sh/uv/install.sh | sh

# Create an alias for ASH
alias ash="uvx git+https://github.com/awslabs/automated-security-helper.git@v3.2.2"
```

```powershell
# Install uv on Windows with PowerShell if it isn't installed already
irm https://astral.sh/uv/install.ps1 | iex

# Create a function for ASH
function ash { uvx git+https://github.com/awslabs/automated-security-helper.git@v3.2.2 $args }
```

### Other Installation Methods

<details>
<summary>Click to expand other installation options</summary>

#### Using `pipx`

```bash
# Install with pipx (isolated environment)
pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.0,1

# Use as normal
ash --help
```

#### Using `pip`

```bash
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.2.2
```

#### Clone the Repository

```bash
git clone https://github.com/awslabs/automated-security-helper.git --branch v3.2.2
cd automated-security-helper
pip install .
```
</details>

## Basic Usage

```bash
# Run a scan in local mode (Python only)
ash --mode local

# Run a scan in container mode (all tools)
ash --mode container

# Run a scan in precommit mode (fast subset of tools)
ash --mode precommit

# Download the GenAI Integration Guide for AI assistants
ash get-genai-guide -o ash-genai-guide.md
```

### Sample Output

```
                                                 ASH Scan Results Summary
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━┳━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ Scanner        ┃ Suppressed ┃ Critical ┃ High ┃ Medium ┃ Low ┃ Info ┃ Duration ┃ Actionable ┃ Result ┃ Threshold       ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━╇━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ bandit         │ 7          │ 0        │ 1    │ 0      │ 56  │ 0    │ 19.9s    │ 1          │ FAILED │ MEDIUM (global) │
│ cdk-nag        │ 0          │ 0        │ 30   │ 0      │ 0   │ 5    │ 48.7s    │ 30         │ FAILED │ MEDIUM (global) │
│ cfn-nag        │ 0          │ 0        │ 0    │ 15     │ 0   │ 0    │ 45.1s    │ 15         │ FAILED │ MEDIUM (global) │
│ checkov        │ 10         │ 0        │ 25   │ 0      │ 0   │ 0    │ 38.9s    │ 25         │ FAILED │ MEDIUM (global) │
│ detect-secrets │ 0          │ 0        │ 48   │ 0      │ 0   │ 0    │ 18.9s    │ 48         │ FAILED │ MEDIUM (global) │
│ grype          │ 0          │ 0        │ 2    │ 1      │ 0   │ 0    │ 40.3s    │ 3          │ FAILED │ MEDIUM (global) │
└────────────────┴────────────┴──────────┴──────┴────────┴─────┴──────┴──────────┴────────────┴────────┴─────────────────┘
                                                     source-dir: '.'
                                              output-dir: '.ash/ash_output'

=== ASH Scan Completed in 1m 6s: Next Steps ===
View detailed findings...
  - SARIF: '.ash/ash_output/reports/ash.sarif'
  - JUnit: '.ash/ash_output/reports/ash.junit.xml'
  - ASH aggregated results JSON available at: '.ash/ash_output/ash_aggregated_results.json'

=== Actionable findings detected! ===
To investigate...
  1. Open one of the summary reports for a user-friendly table of the findings:
    - HTML report of all findings: '.ash/ash_output/reports/ash.html'
    - Markdown summary: '.ash/ash_output/reports/ash.summary.md'
    - Text summary: '.ash/ash_output/reports/ash.summary.txt'
  2. Use ash report to view a short text summary of the scan in your terminal
  3. Use ash inspect findings to explore the findings interactively
  4. Review scanner-specific reports and outputs in the '.ash/ash_output/scanners' directory

=== ASH Exit Codes ===
  0: Success - No actionable findings or not configured to fail on findings
  1: Error during execution
  2: Actionable findings detected when configured with `fail_on_findings: true`. Default is True. Current value: True
ERROR (2) Exiting due to 122 actionable findings found in ASH scan
```

## AI Integration with MCP

ASH includes a Model Context Protocol (MCP) server that enables AI assistants to perform security scans and analyze results through a standardized interface. This allows you to integrate ASH with AI development tools like Amazon Q CLI, Claude Desktop, and Cline (VS Code).

### GenAI Integration Guide

ASH provides a comprehensive guide for AI assistants and LLMs on how to properly interact with scan results. This guide helps GenAI tools:

- Use the correct output formats (JSON, not HTML)
- Handle severity discrepancies between report formats
- Create suppressions properly with correct syntax
- Analyze dependencies using CycloneDX SBOM
- Avoid common pitfalls and known issues

**Download the guide**:
```bash
ash get-genai-guide -o ash-genai-guide.md
```

The guide can be provided to any AI assistant as context to ensure they process ASH results correctly and efficiently.

### MCP Server Features

The ASH MCP server provides:

- **Real-time Progress Tracking**: Monitor scan progress with streaming updates
- **Background Scanning**: Start scans and continue other work while they run
- **Multiple Scan Management**: Handle concurrent scans with unique identifiers
- **Comprehensive Error Handling**: Detailed error messages and recovery suggestions
- **Configuration Support**: Full support for ASH configuration files and environment variables

### Installation and Setup

#### Prerequisites

1. **Install UV**: Install `uv` from [Astral](https://docs.astral.sh/uv/getting-started/installation/) or the [GitHub README](https://github.com/astral-sh/uv#installation)
2. **Install Python 3.10+**: Use `uv python install 3.10` (or a more recent version)

#### Client Configuration

**Amazon Q Developer CLI** - Add to `~/.aws/amazonq/mcp.json`:
```json
{
  "mcpServers": {
    "ash": {
      "command": "uvx",
      "args": [
        "--from=git+https://github.com/awslabs/automated-security-helper@v3.0.0",
        "ash",
        "mcp"
      ],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

**Claude Desktop** - Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "ash-security": {
      "command": "uvx",
      "args": [
        "--from=git+https://github.com/awslabs/automated-security-helper@v3.0.0",
        "ash",
        "mcp"
      ]
    }
  }
}
```

**Cline (VS Code)**:
```json
{
  "mcpServers": {
    "ash": {
      "command": "uvx",
      "args": [
        "--from=git+https://github.com/awslabs/automated-security-helper@v3.0.0",
        "ash",
        "mcp"
      ],
      "disabled": false,
      "autoApprove": [
        "get_scan_progress",
        "list_active_scans",
        "get_scan_results"
      ]
    }
  }
}
```

### Available MCP Tools

The ASH MCP server provides these tools:

| Tool | Description | Use Case |
|------|-------------|----------|
| `scan_directory` | Perform a complete security scan | One-time scans with full results |
| `scan_directory_with_progress` | Start a scan with real-time progress tracking | Long-running scans with progress monitoring |
| `get_scan_progress` | Get current progress of a running scan | Monitor scan status and partial results |
| `get_scan_results` | Get final results of a completed scan | Retrieve complete scan results |
| `list_active_scans` | List all active and recent scans | Manage multiple concurrent scans |
| `cancel_scan` | Cancel a running scan | Stop unnecessary or problematic scans |
| `check_installation` | Verify ASH installation and dependencies | Troubleshoot setup issues |

### Usage Examples

Once configured, you can interact with ASH through natural language. Each of the
sentences below represent prompts which can be used in the various coding CLIs
(Q CLI, Cline, etc.) in order to inform the CLI to identify the ASH MCP tool and use it
based on the instructions provided in the prompt.


**Basic Security Scanning:**
```
"Can you scan this project directory for security vulnerabilities?"
"Please run ASH on the ./src folder and analyze the results"
"Check this code for security issues with HIGH severity threshold"
```

**Progress Monitoring:**
```
"Start a security scan on this directory and show me the progress"
"Monitor the current scan and let me know when it's done"
"What's the status of my running security scans?"
```

**Analysis & Reporting:**
```
"Perform a comprehensive security audit and create a prioritized action plan"
"Scan this code and help me fix any critical security issues"
"Generate a security report with remediation recommendations"
```

### Configuration Support

The MCP server supports all ASH configuration methods:

- **Configuration files**: `.ash/ash.yaml` or custom config paths
- **Environment variables**: `ASH_DEFAULT_SEVERITY_LEVEL`, `ASH_OFFLINE`, etc.
- **CLI parameters**: Severity thresholds, custom output directories

For detailed information about streaming capabilities and advanced usage, see the [MCP Streaming Guide](docs/content/tutorials/mcp-streaming-guide.md).


## Configuration

ASH v3 uses a YAML configuration file (`.ash/ash.yaml`) with support for JSON Schema validation:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json
project_name: my-project
global_settings:
  severity_threshold: MEDIUM
  ignore_paths:
    - path: 'tests/test_data'
      reason: 'Test data only'
scanners:
  bandit:
    enabled: true
    options:
      confidence_level: high
reporters:
  markdown:
    enabled: true
    options:
      include_detailed_findings: true
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

## Output Files

ASH v3 produces several output files in the `.ash/ash_output/` directory:

- `ash_aggregated_results.json`: Complete machine-readable results including validation checkpoints
- `reports/ash.summary.txt`: Human-readable text summary
- `reports/ash.summary.md`: Markdown summary for GitHub PRs and other platforms
- `reports/ash.html`: Interactive HTML report
- `reports/ash.csv`: CSV report for filtering and sorting findings

The `ash_aggregated_results.json` file includes comprehensive validation information that tracks scanner registration, enablement, execution, and result inclusion throughout the scan process. The Scanner Validation System can also generate detailed validation reports that provide comprehensive analysis of scanner states, validation checkpoints, dependency issues, and actionable recommendations for troubleshooting scan issues.

## FAQ

<details>
<summary>How do I run ASH on Windows?</summary>

ASH v3 can run directly on Windows in local mode with Python 3.10+. Simply install ASH using pip, pipx, or uvx and run with `--mode local`. For container mode, you'll need WSL2 and a container runtime like Docker Desktop, Rancher Desktop, or Podman Desktop.
</details>

<details>
<summary>How do I run ASH in CI/CD pipelines?</summary>

ASH can be run in container mode in any CI/CD environment that supports containers. See the [tutorials](docs/content/tutorials/running-ash-in-ci.md) for examples.
</details>

<details>
<summary>How do I exclude files from scanning?</summary>

ASH respects `.gitignore` files. You can also configure ignore paths in your `.ash/ash.yaml` configuration file.
</details>

<details>
<summary>How do I run ASH in an offline/air-gapped environment?</summary>

Build an offline image with `ash --mode container --offline --offline-semgrep-rulesets p/ci --no-run`, push to your private registry, then use `ash --mode container --offline --no-build` in your air-gapped environment.
</details>

<details>
<summary>I am trying to scan a CDK application, but ASH does not show CDK Nag scan results -- why is that?</summary>

ASH uses CDK Nag underneath to apply NagPack rules to *CloudFormation templates* via the `CfnInclude` CDK construct. This is purely a mechanism to ingest a bare CloudFormation template and apply CDK NagPacks to it; doing this against a template emitted by another CDK application causes a collision in the `CfnInclude` construct due to the presence of the `BootstrapVersion` parameter on the template added by CDK. For CDK applications, we recommend integrating CDK Nag directly in your CDK code. ASH will still apply other CloudFormation scanners (cfn-nag, checkov) against templates synthesized via CDK, but the CDK Nag scanner will not scan those templates.
</details>

<details>
<summary>Why is ASH trying to install tools automatically? Can I use my own tool installations?</summary>

ASH v3 uses UV's tool isolation system to automatically manage scanner dependencies like Bandit, Checkov, and Semgrep. This ensures consistent tool versions and avoids dependency conflicts. If you prefer to use your own tool installations:

1. **Pre-install tools**: Install tools manually using `uv tool install <tool>` or your preferred method
2. **Offline mode**: Set `ASH_OFFLINE=true` to skip automatic installations and use system-installed tools
3. **Fallback behavior**: ASH automatically falls back to system-installed tools if UV tool installation fails

The automatic installation uses sensible default version constraints to ensure compatibility:
- **Bandit**: `>=1.7.0` (enhanced SARIF support and security fixes)
- **Checkov**: `>=3.2.0,<4.0.0` (improved stability, avoiding potential breaking changes in 4.x)
- **Semgrep**: `>=1.125.0` (comprehensive rule support and performance improvements)

These constraints can be overridden through scanner configuration when needed.
</details>

<details>
<summary>ASH is failing with UV tool installation errors. How do I fix this?</summary>

If you're experiencing UV tool installation issues:

1. **Check UV installation**: Ensure UV is installed and available: `uv --version`
2. **Network connectivity**: UV tool installation requires internet access
3. **Use offline mode**: Set `ASH_OFFLINE=true` to skip downloads and use pre-installed tools
4. **Manual installation**: Pre-install tools manually:
   ```bash
   uv tool install bandit>=1.7.0
   uv tool install checkov>=3.2.0,<4.0.0
   uv tool install semgrep>=1.125.0
   ```
5. **Check logs**: Run ASH with `--verbose` to see detailed error messages including:
   - UV availability status
   - Tool installation attempts and retry logic
   - Version detection information
   - Fallback mechanism activation
6. **Fallback to system tools**: ASH will automatically try to use system-installed tools if UV installation fails
7. **Installation timeout**: Increase timeout in scanner configuration if needed:
   ```yaml
   scanners:
     checkov:
       options:
         install_timeout: 600  # 10 minutes
   ```
</details>

## Documentation

For complete documentation, visit the [ASH Documentation](https://awslabs.github.io/automated-security-helper/).

## Feedback and Contributing

- Create an issue [here](https://github.com/awslabs/automated-security-helper/issues)
- See [CONTRIBUTING](CONTRIBUTING.md) for contribution guidelines

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for security issue reporting information.

## License

This library is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=awslabs/automated-security-helper&type=Date)](https://www.star-history.com/#awslabs/automated-security-helper&Date)
