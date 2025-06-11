# Frequently Asked Questions

## General Questions

### What is ASH?
ASH (Automated Security Helper) is a security scanning tool designed to help you identify potential security issues in your code, infrastructure, and IAM configurations as early as possible in your development process.

### What's new in ASH v3?
ASH v3 has been completely rewritten in Python with significant improvements:
- Python-based CLI with multiple execution modes
- Enhanced configuration system
- Improved reporting formats
- Customizable plugin system
- Better Windows support
- Programmatic API for integration

### Is ASH a replacement for human security reviews?
No. ASH is designed to help identify common security issues early in the development process, but it's not a replacement for human security reviews or team/customer security standards.

## Installation and Setup

### How do I install ASH v3?
You have several options:
```bash
# Using uvx (recommended)
alias ash="uvx git+https://github.com/awslabs/automated-security-helper.git@v3.0.0-beta"

# Using pipx
pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.0.0-beta

# Using pip
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.0.0-beta
```

### What are the prerequisites for ASH v3?
- For local mode: Python 3.10 or later
- For container mode: Any OCI-compatible container runtime (Docker, Podman, Finch, etc.)
- On Windows with container mode: WSL2 is typically required

### How do I run ASH on Windows?
ASH v3 can run directly on Windows in local mode with Python 3.10+. Simply install ASH using pip, pipx, or uvx and run with `--mode local`. For container mode, you'll need WSL2 and a container runtime like Docker Desktop, Rancher Desktop, or Podman Desktop.

## Usage

### What are the different execution modes in ASH v3?
ASH v3 supports three execution modes:
- **Local Mode**: Runs entirely in the local Python process
- **Container Mode**: Runs non-Python scanners in a container
- **Precommit Mode**: Runs a subset of fast scanners optimized for pre-commit hooks

### How do I run a basic scan?
```bash
# Run in local mode (Python-based scanners only)
ash --mode local

# Run in container mode (all scanners)
ash --mode container

# Run in precommit mode (fast subset of scanners)
ash --mode precommit
```

### How do I specify which files to scan?
```bash
# Scan a specific directory
ash --source-dir /path/to/code

# Configure ignore paths in .ash/.ash.yaml
global_settings:
  ignore_paths:
    - path: 'tests/test_data'
      reason: 'Test data only'
```

### How do I exclude files from scanning?
ASH respects `.gitignore` files. You can also configure ignore paths in your `.ash/.ash.yaml` configuration file.

### How do I run specific scanners?
```bash
# Run only specific scanners
ash --scanners bandit,semgrep

# Exclude specific scanners
ash --exclude-scanners cfn-nag,cdk-nag
```

### How do I generate specific report formats?
```bash
# Generate specific report formats
ash --output-formats markdown,html,json

# Generate a report from existing results
ash report --format html --output-dir ./my-scan-results
```

## Configuration

### Where is the ASH configuration file located?
By default, ASH looks for a configuration file in the following locations (in order):
1. `.ash/.ash.yaml`
2. `.ash/.ash.yml`
3. `.ash.yaml`
4. `.ash.yml`

### How do I create a configuration file?
```bash
# Initialize a new configuration file
ash config init
```

### How do I override configuration values at runtime?
```bash
# Enable a specific scanner
ash --config-overrides 'scanners.bandit.enabled=true'

# Change severity threshold
ash --config-overrides 'global_settings.severity_threshold=LOW'
```

## Scanners and Tools

### What security scanners are included in ASH v3?
ASH v3 integrates multiple open-source security tools:
- Bandit (Python SAST)
- Semgrep (Multi-language SAST)
- detect-secrets (Secret detection)
- Checkov (IaC scanning)
- cfn_nag (CloudFormation scanning)
- cdk-nag (CloudFormation scanning)
- npm-audit (JavaScript/Node.js SCA)
- Grype (Multi-language SCA)
- Syft (SBOM generation)

### I am trying to scan a CDK application, but ASH does not show CDK Nag scan results -- why is that?
ASH uses CDK Nag underneath to apply NagPack rules to *CloudFormation templates* via the `CfnInclude` CDK construct. This is purely a mechanism to ingest a bare CloudFormation template and apply CDK NagPacks to it; doing this against a template emitted by another CDK application causes a collision in the `CfnInclude` construct due to the presence of the `BootstrapVersion` parameter on the template added by CDK. For CDK applications, we recommend integrating CDK Nag directly in your CDK code. ASH will still apply other CloudFormation scanners (cfn-nag, checkov) against templates synthesized via CDK, but the CDK Nag scanner will not scan those templates.

### How do I add custom scanners?
You can create custom scanners by implementing the scanner plugin interface and adding your plugin module to the ASH configuration:

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - my_ash_plugins
```

## CI/CD Integration

### How do I run ASH in CI/CD pipelines?
ASH can be run in container mode in any CI/CD environment that supports containers. See the [tutorials](tutorials/running-ash-in-ci.md) for examples.

### How do I use ASH with pre-commit?
Add this to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/awslabs/automated-security-helper
    rev: v3.0.0-beta
    hooks:
      - id: ash-simple-scan
```

### How do I fail CI builds on security findings?
```bash
# Exit with non-zero code if findings are found
ash --mode local --fail-on-findings
```

## Advanced Usage

### How do I run ASH in an offline/air-gapped environment?
Build an offline image with `ash --mode container --offline --offline-semgrep-rulesets p/ci --no-run`, push to your private registry, then use `ash --mode container --offline --no-build` in your air-gapped environment.

### Can I use ASH programmatically?
Yes, ASH v3 can be used programmatically in Python:

```python
from automated_security_helper.interactions.run_ash_scan import run_ash_scan
from automated_security_helper.core.enums import RunMode

results = run_ash_scan(
    source_dir="/path/to/code",
    output_dir="/path/to/output",
    mode=RunMode.local
)
```

### How do I customize the container image?
```bash
# Specify a custom container image
export ASH_IMAGE_NAME="my-registry/ash:custom"
ash --mode container

# Build a custom image
ash build-image --build-target ci --custom-containerfile ./my-dockerfile
```

## Troubleshooting

### ASH is not finding any files to scan
Ensure you're running ASH inside the folder you intend to scan or using the `--source-dir` parameter. If the folder where the files reside is part of a git repository, ensure the files are added (committed) before running ASH.

### I'm getting "command not found" errors for scanners in local mode
Some scanners require external dependencies. Either install the required dependencies locally or use container mode (`--mode container`).

### ASH is running slowly
Try these options:
- Use `--mode precommit` for faster scans
- Use `--scanners` to run only specific scanners
- Use `--strategy parallel` (default) to run scanners in parallel

### How do I debug ASH?
```bash
# Enable debug logging
ash --debug

# Enable verbose logging
ash --verbose
```

## Getting Help

### Where can I find more documentation?
Visit the [ASH Documentation](https://awslabs.github.io/automated-security-helper/).

### How do I report issues or request features?
Create an issue on [GitHub](https://github.com/awslabs/automated-security-helper/issues).

### How do I contribute to ASH?
See the [CONTRIBUTING](contributing.md) guide for contribution guidelines.