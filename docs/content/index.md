# Home

[![ASH - Core Pipeline](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-build-and-scan.yml/badge.svg)](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-build-and-scan.yml)
[![ASH - Matrix Unit Tests](https://github.com/awslabs/automated-security-helper/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/awslabs/automated-security-helper/actions/workflows/unit-tests.yml)

## Overview

ASH (Automated Security Helper) is a security scanning tool designed to help you identify potential security issues in your code, infrastructure, and IAM configurations as early as possible in your development process.

- ASH is not a replacement for human review or team/customer security standards
- It leverages lightweight, open-source tools for flexibility and portability
- ASH v3 has been completely rewritten in Python with significant improvements to usability and functionality

[![Star History Chart](https://api.star-history.com/svg?repos=awslabs/automated-security-helper&type=Date)](https://www.star-history.com/#awslabs/automated-security-helper&Date)

## Key Features in ASH v3

- **Python-based CLI**: ASH now has a Python-based CLI entrypoint while maintaining backward compatibility with the shell script entrypoint
- **Multiple Execution Modes**: Run ASH in `local`, `container`, or `precommit` mode depending on your needs
- **Enhanced Configuration**: Support for YAML/JSON configuration files with overrides via CLI parameters
- **Improved Reporting**: Multiple report formats including JSON, Markdown, HTML, and CSV
- **Pluggable Architecture**: Extend ASH with custom plugins, scanners, and reporters
- **Unified Output Format**: Standardized output format that can be exported to multiple formats (SARIF, JSON, HTML, Markdown, CSV)

## Built-In Scanners

ASH v3 integrates multiple open-source security tools as scanners:

| Scanner                                                       | Type      | Languages/Frameworks                                                                         | Installation (Local Mode)                                               |
|---------------------------------------------------------------|-----------|----------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| [Bandit](https://github.com/PyCQA/bandit)                     | SAST      | Python                                                                                       | Included with ASH                                                       |
| [Semgrep](https://github.com/semgrep/semgrep)                 | SAST      | Python, JavaScript, TypeScript, Java, Go, C#, Ruby, PHP, Kotlin, Swift, Bash, and more       | Included with ASH                                                       |
| [detect-secrets](https://github.com/Yelp/detect-secrets)      | Secrets   | All text files                                                                               | Included with ASH                                                       |
| [Checkov](https://github.com/bridgecrewio/checkov)            | IaC, SAST | Terraform, CloudFormation, Kubernetes, Dockerfile, ARM Templates, Serverless, Helm, and more | Included with ASH                                                       |
| [cfn_nag](https://github.com/stelligent/cfn_nag)              | IaC       | CloudFormation                                                                               | `gem install cfn-nag`                                                   |
| [cdk-nag](https://github.com/cdklabs/cdk-nag)                 | IaC       | CloudFormation                                                                               | Included with ASH                                                       |
| [npm-audit](https://docs.npmjs.com/cli/v8/commands/npm-audit) | SCA       | JavaScript/Node.js                                                                           | Install Node.js/npm                                                     |
| [Grype](https://github.com/anchore/grype)                     | SCA       | Python, JavaScript/Node.js, Java, Go, Ruby, and more                                         | See [Grype Installation](https://github.com/anchore/grype#installation) |
| [Syft](https://github.com/anchore/syft)                       | SBOM      | Python, JavaScript/Node.js, Java, Go, Ruby, and more                                         | See [Syft Installation](https://github.com/anchore/syft#installation)   |

## Prerequisites

### Runtime Requirements

| Mode      | Requirements                                                                                                                                                         | Notes                                                    |
|-----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------|
| Local     | Python 3.10+                                                                                                                                                         | Some scanners require additional tools (see table above) |
| Container | Any OCI-compatible container runtime ([Finch](https://github.com/runfinch/finch), [Docker](https://docs.docker.com/get-docker/), [Podman](https://podman.io/), etc.) | On Windows: WSL2 is typically required                   |
| Precommit | Python 3.10+                                                                                                                                                         | Subset of scanners, optimized for speed                  |

## Installation Options

### Quick Install (Recommended)

```bash
# Install with pipx (isolated environment)
pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.0.0-beta

# Use as normal
ash --help
```

### Other Installation Methods

<details>
<summary>Click to expand other installation options</summary>

#### Using `uvx`

```bash
# Linux/macOS
curl -sSf https://astral.sh/uv/install.sh | sh
alias ash="uvx git+https://github.com/awslabs/automated-security-helper.git@v3.0.0-beta"

# Windows PowerShell
irm https://astral.sh/uv/install.ps1 | iex
function ash { uvx git+https://github.com/awslabs/automated-security-helper.git@v3.0.0-beta $args }
```

#### Using `pip`

```bash
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.0.0-beta
```

#### Clone the Repository

```bash
git clone https://github.com/awslabs/automated-security-helper.git --branch v3.0.0-beta
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

## Configuration

ASH v3 uses a YAML configuration file (`.ash/ash.yaml`) with support for JSON Schema validation:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/beta/automated_security_helper/schemas/AshConfig.json
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
    rev: v3.0.0-beta
    hooks:
      - id: ash-simple-scan
```

Run with:

```bash
pre-commit run ash-simple-scan --all-files
```

## Output Files

ASH v3 produces several output files in the `.ash/ash_output/` directory:

- `ash_aggregated_results.json`: Complete machine-readable results
- `reports/ash.summary.txt`: Human-readable text summary
- `reports/ash.summary.md`: Markdown summary for GitHub PRs and other platforms
- `reports/ash.html`: Interactive HTML report
- `reports/ash.csv`: CSV report for filtering and sorting findings

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

## Documentation

For complete documentation, visit the [ASH Documentation](https://awslabs.github.io/automated-security-helper/).

## Feedback and Contributing

- Create an issue [here](https://github.com/awslabs/automated-security-helper/issues)
- See [CONTRIBUTING](contributing.md) for contribution guidelines

## Security

See [CONTRIBUTING](contributing.md#security-issue-notifications) for security issue reporting information.

## License

This library is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file.
