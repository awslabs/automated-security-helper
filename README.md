# ASH - Automated Security Helper

[![ASH - Core Pipeline](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-build-and-scan.yml/badge.svg)](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-build-and-scan.yml)
[![ASH - Matrix Unit Tests](https://github.com/awslabs/automated-security-helper/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/awslabs/automated-security-helper/actions/workflows/unit-tests.yml)

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
- **Customizable**: Extend ASH with custom plugins, scanners, and reporters

## Integrated Security Tools

ASH v3 integrates multiple open-source security tools to provide comprehensive scanning capabilities:

| Tool                                                          | Type      | Supported Languages/Frameworks                                                               |
|---------------------------------------------------------------|-----------|----------------------------------------------------------------------------------------------|
| [Bandit](https://github.com/PyCQA/bandit)                     | SAST      | Python                                                                                       |
| [Semgrep](https://github.com/semgrep/semgrep)                 | SAST      | Python, JavaScript, TypeScript, Java, Go, C#, Ruby, PHP, Kotlin, Swift, Bash, and more       |
| [detect-secrets](https://github.com/Yelp/detect-secrets)      | Secrets   | All text files                                                                               |
| [Checkov](https://github.com/bridgecrewio/checkov)            | IaC, SAST | Terraform, CloudFormation, Kubernetes, Dockerfile, ARM Templates, Serverless, Helm, and more |
| [cfn_nag](https://github.com/stelligent/cfn_nag)              | IaC       | CloudFormation                                                                               |
| [cdk-nag](https://github.com/cdklabs/cdk-nag)                 | IaC       | CloudFormation                                                                               |
| [npm-audit](https://docs.npmjs.com/cli/v8/commands/npm-audit) | SCA       | JavaScript/Node.js                                                                           |
| [Grype](https://github.com/anchore/grype)                     | SCA       | Python, JavaScript/Node.js, Java, Go, Ruby, and more                                         |
| [Syft](https://github.com/anchore/syft)                       | SBOM      | Python, JavaScript/Node.js, Java, Go, Ruby, and more                                         |
| [nbconvert](https://nbconvert.readthedocs.io/en/latest/)      | Converter | Jupyter Notebooks (converts to Python for scanning)                                          |

### Key Improvements in ASH v3

- **Expanded Checkov Coverage**: Now scans all supported frameworks, not just Terraform, CloudFormation, and Dockerfile's
- **Enhanced Semgrep Integration**: Utilizes Semgrep's full language support beyond the previously limited set
- **Improved Secret Detection**: Added detect-secrets in place of git-secrets for more comprehensive secret scanning
- **Better SCA and SBOM Generation**: Full integration of Grype and Syft for dependency scanning and SBOM creation
- **Unified Scanning Approach**: Tools are now applied to all relevant files in the codebase, not just specific file types

## Prerequisites

### For Local Mode
- Python 3.10 or later

For full scanner coverage in local mode, the following non-Python tools are recommended:
- Ruby with cfn-nag (`gem install cfn-nag`)
- Node.js/npm (for npm audit support)
- Grype and Syft (for SBOM and vulnerability scanning)

### For Container Mode
- Any OCI-compatible container runtime (Docker, Podman, Finch, etc.)
- On Windows: WSL2 is typically required for running Linux containers due to the requirements of the container runtime. ASH itself just requires the ability to run Linux containers for container mode, it doesn't typically care what the engine running underneath it is or whether you are interacting with it from PowerShell in Windows or Bash in WSL, as long as `docker`/`finch`/`nerdctl`/`podman` is in `PATH`.

## Installation Options

### 1. Using `uvx` (Recommended)

#### Linux/macOS
```bash
# Install uv if you don't have it
curl -sSf https://astral.sh/uv/install.sh | sh

# Create an alias for ASH
alias ash="uvx git+https://github.com/awslabs/automated-security-helper.git@v3.0.0-beta"

# Use as normal
ash --help
```

#### Windows
```powershell
# Install uv if you don't have it
irm https://astral.sh/uv/install.ps1 | iex

# Create a function for ASH
function ash { uvx git+https://github.com/awslabs/automated-security-helper.git@v3.0.0-beta $args }

# Use as normal
ash --help
```

### 2. Using `pipx`

```bash
# Works on Windows, macOS, and Linux
pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.0.0-beta

# Use as normal
ash --help
```

### 3. Using `pip`

```bash
# Works on Windows, macOS, and Linux
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.0.0-beta

# Use as normal
ash --help
```

### 4. Clone the Repository

```bash
# Works on Windows, macOS, and Linux
git clone https://github.com/awslabs/automated-security-helper.git --branch v3.0.0-beta
cd automated-security-helper
pip install .

# Use as normal
ash --help
```

## Basic Usage

```bash
# Run a scan in local mode (Python only)
ash --mode local

# Run a scan in container mode (all tools)
ash --mode container

# Run a scan in precommit mode (fast subset of tools)
ash --mode precommit

# Specify source and output directories
ash --source-dir /path/to/code --output-dir /path/to/output

# Override configuration options
ash --config-overrides 'scanners.bandit.enabled=true' --config-overrides 'global_settings.severity_threshold=LOW'
```

### Windows-Specific Usage

ASH v3 provides the same experience on Windows as on other platforms:

```powershell
# Run in local mode (works natively on Windows)
ash --mode local

# Run in container mode (requires WSL2 and a container runtime)
ash --mode container
```

## Configuration

ASH v3 uses a YAML configuration file (`.ash/.ash.yaml`) with support for JSON Schema validation:

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

- **Q: How do I run ASH on Windows?**

  A: ASH v3 can run directly on Windows in local mode with Python 3.10+. Simply install ASH using pip, pipx, or uvx and run with `--mode local`. For container mode, you'll need WSL2 and a container runtime like Docker Desktop, Rancher Desktop, or Podman Desktop.

- **Q: How do I run ASH in CI/CD pipelines?**

  A: ASH can be run in container mode in any CI/CD environment that supports containers. See the [tutorials](docs/content/tutorials/running-ash-in-ci.md) for examples.

- **Q: How do I exclude files from scanning?**

  A: ASH respects `.gitignore` files. You can also configure ignore paths in your `.ash/.ash.yaml` configuration file.

- **Q: How do I run ASH in an offline/air-gapped environment?**

  A: Build an offline image with `ash --mode container --offline --offline-semgrep-rulesets p/ci --no-run`, push to your private registry, then use `ash --mode container --offline --no-build` in your air-gapped environment.

- **Q: I am trying to scan a CDK application, but ASH does not show CDK Nag scan results -- why is that?**

  A: ASH uses CDK Nag underneath to apply NagPack rules to *CloudFormation templates* via the `CfnInclude` CDK construct. This is purely a mechanism to ingest a bare CloudFormation template and apply CDK NagPacks to it; doing this against a template emitted by another CDK application causes a collision in the `CfnInclude` construct due to the presence of the `BootstrapVersion` parameter on the template added by CDK. For CDK applications, we recommend integrating CDK Nag directly in your CDK code. ASH will still apply other CloudFormation scanners (cfn-nag, checkov) against templates synthesized via CDK, but the CDK Nag scanner will not scan those templates.

## Documentation

For complete documentation, visit the [ASH Documentation](https://awslabs.github.io/automated-security-helper/).

## Feedback and Contributing

- Create an issue [here](https://github.com/awslabs/automated-security-helper/issues)
- See [CONTRIBUTING](CONTRIBUTING.md) for contribution guidelines

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for security issue reporting information.

## License

This library is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file.