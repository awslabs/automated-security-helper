# Home

[![ASH - Core Pipeline](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-repo-scan.yml/badge.svg)](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-repo-scan.yml)
[![ASH - Unified CI](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-unified-ci.yml/badge.svg)](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-unified-ci.yml)
[![ASH - Install Methods](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-install-methods.yml/badge.svg)](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-install-methods.yml)

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
- **UV Package Management**: ASH now uses UV for faster dependency resolution and tool isolation

## Built-In Scanners

ASH v3 integrates multiple open-source security tools as scanners. Tools like Bandit, Checkov, and Semgrep are managed via UV's tool isolation system, which automatically installs and runs them in isolated environments without affecting your project dependencies:

| Scanner                                                       | Type      | Languages/Frameworks                                                                         | Installation (Local Mode)                                               |
|---------------------------------------------------------------|-----------|----------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| [Bandit](https://github.com/PyCQA/bandit)                     | SAST      | Python                                                                                       | Managed via UV tool isolation (auto-installed: `bandit>=1.7.0,<2.0.0`)        |
| [Semgrep](https://github.com/semgrep/semgrep)                 | SAST      | Python, JavaScript, TypeScript, Java, Go, C#, Ruby, PHP, Kotlin, Swift, Bash, and more       | Managed via UV tool isolation (auto-installed: `semgrep>=1.125.0,<2.0.0`)     |
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
# Install with pipx (isolated environment)
pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0

# Use as normal
ash --help
```

> **Floating tag `v3`**: We also maintain a `v3` floating tag that always points to the latest stable v3.x release. You can use `@v3` instead of `@v3.7.0` to stay up to date automatically. Pin a specific version when you need reproducible builds.

### Other Installation Methods

<details>
<summary>Click to expand other installation options</summary>

#### Using `uvx`

```bash
# Linux/macOS
curl -sSf https://astral.sh/uv/install.sh | sh
alias ash="uvx git+https://github.com/awslabs/automated-security-helper.git@v3.7.0"

# Windows PowerShell
irm https://astral.sh/uv/install.ps1 | iex
function ash { uvx git+https://github.com/awslabs/automated-security-helper.git@v3.7.0 $args }
```

#### Using `pip`

```bash
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
```

#### Clone the Repository

```bash
git clone https://github.com/awslabs/automated-security-helper.git --branch v3.7.0
cd automated-security-helper
pip install .
```
</details>

## Basic Usage

```bash
# Run a scan in local mode (the scanner tools installed on this machine)
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
  0: success
  1: scan errors / scanner failures
  2: actionable findings at or above threshold (fail_on_findings is true; default true)
  3: invalid config or refused input
  4: workspace definition or policy error
  5: usage error
ERROR (2) Exiting due to 122 actionable findings found in ASH scan
```

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
    rev: v3.7.0
    hooks:
      - id: ash
```

Run with:

```bash
pre-commit run ash --all-files
```

The `ash` hook runs bandit, detect-secrets, checkov, cdk-nag and npm-audit. It needs pre-commit running on Python 3.10 to 3.14, and Node.js and npm on `PATH` for cdk-nag and npm-audit. `ash-simple-scan` is the same hook under its earlier id. See [Using ASH with pre-commit](tutorials/using-ash-with-pre-commit.md) for running without Node.js and for the container hook, `ash-full-scan`.

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

ASH leaves out of its scan set every file a `.gitignore` or `.ignore` file in the scanned tree matches. You can also configure ignore paths in your `.ash/.ash.yaml` configuration file. The summaries record how many files the ignore files excluded, and `--no-honor-ignore-files` (or `honor_ignore_files: false` in a config file outside the scanned tree) scans those files too. See [Ignore files and the scan set](docs/configuration-guide.md#ignore-files-and-the-scan-set).
</details>

<details>
<summary>Does ASH scan its own output, or the templates in cdk.out?</summary>

ASH leaves its own output out of the scan, whether or not `.gitignore` lists it: the output directory of the current scan, and `.ash/ash_output` under the scanned directory and under the directory ASH runs from. In a git checkout, regular files committed to one of those directories are still scanned (a committed link is not), and ASH warns that its output directory holds committed files. Outside a git checkout, or when git cannot list the repository, only the current scan's output directory is left out: an earlier run's `.ash/ash_output` is scanned like the rest of the tree, and ASH warns once per scan while the scan set still holds files in it, naming it and saying how to leave it out: delete it, or list it in an ignore file such as `.gitignore`. Adding it to `global_settings.ignore_paths` leaves its findings out, but the scan still reads it, so the warning repeats until the directory is deleted or an ignore file lists it. The output directory is recognized when it or the scanned directory is given through a link above the tree, as `/var` is on macOS. A scan does not delete or overwrite a committed file: when git tracks one where a scan writes its output (`ash_aggregated_results.json`, `ash-ignore-report.txt`, `ash-scan-set-files-list.txt`, `ash-scan-set-run.json`, `ash.log`, `ash.log.jsonl`, `.ash_previous_results_restored`, or anything under `analysis/`, `reports/`, `scanners/`, `converted/`, `.ash_previous_results/` or `.ash_previous_results.partial/`), the scan exits 3 before it deletes or writes anything, in every mode and from the MCP server. When git cannot list the repository the output directory is in (git is not installed, or it fails on the repository), any file at one of those paths stops the scan the same way, and the message names git's error and says to let git read the repository or remove the old results. A report over existing results (`--use-existing`) is stopped only where it writes: the results file, the logs, `reports/`, and `analysis/` with `--inspect` or `converted/` with `--cleanup`. A `.ash/ash_output` that is a link, or that a link inside the scanned directory leads to, is not taken as ASH's output, however the path to it is spelled, and a scan into an output directory git tracks as a link exits 3. The trivy-repo plugin still reads those directories, and ASH drops the findings it reports there, except in committed files. Any other directory is scanned, even one holding an earlier run's or another shard's results; ASH warns when a directory holds `ash_aggregated_results.json`, or both `ash-ignore-report.txt` and `ash-scan-set-files-list.txt`. Write shard output outside the scanned directory, or list it in `.gitignore`. CloudFormation templates that `cdk synth` writes (`*.template.json`) are scanned even when `.gitignore` excludes `cdk.out`, so cdk-nag and cfn-nag check them; the rest of the `cdk.out` directory stays excluded.
</details>

<details>
<summary>How do I run ASH in an offline/air-gapped environment?</summary>

Build an offline image with `ash --mode container --offline --offline-semgrep-rulesets p/ci --no-run`, push to your private registry, then use `ash --mode container --offline --no-build` in your air-gapped environment.
</details>

<details>
<summary>I am trying to scan a CDK application, but ASH does not show CDK Nag scan results -- why is that?</summary>

ASH uses CDK Nag underneath to apply NagPack rules to *CloudFormation templates* via the `CfnInclude` CDK construct. This is purely a mechanism to ingest a bare CloudFormation template and apply CDK NagPacks to it; doing this against a template emitted by another CDK application causes a collision in the `CfnInclude` construct due to the presence of the `BootstrapVersion` parameter on the template added by CDK. For CDK applications, we recommend integrating CDK Nag directly in your CDK code. ASH will still apply other CloudFormation scanners (cfn-nag, checkov) against templates synthesized via CDK, but the CDK Nag scanner will not scan those templates.
</details>

## Feedback and Contributing

- Create an issue [in the GitHub repository](https://github.com/awslabs/automated-security-helper/issues)
- See [CONTRIBUTING](contributing.md) for contribution guidelines

## Security

See [CONTRIBUTING](contributing.md#security-issue-notifications) for security issue reporting information.

## License

This library is licensed under the Apache 2.0 License. See the [LICENSE](https://github.com/awslabs/automated-security-helper/blob/main/LICENSE) file.
