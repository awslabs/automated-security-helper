# Migration Guide: ASH v2 to v3

This guide helps users migrate from ASH v2 to ASH v3.

## Migration Steps

1. **Install ASH v3** using one of the installation methods from the [Installation Guide](./installation-guide.md)
2. **Initialize Configuration**:
   ```bash
   ash config init
   ```
3. **Update Scripts**:

   - Add `--mode container` to your ASH commands if you need to run ASH in a container still
    - **NOTE:** This is only required if you are using the ASH CLI to manage the lifecycle of the container. If you are already running inside a container, such as running inside a CI pipeline using a pre-built ASH image, then you do not have to adjust your scripts.
   - Update output directory handling:
    - If you are explicitly passing the `--output-dir` to ASH, then ASH will continue to output to the same directory.
    - If you are not explicitly passing the `--output-dir` to ASH, then you will need to update output directory references to `.ash/ash_output` OR start including `--output-dir ash_output` in your scripts to retain the existing output directory.
   - Replace any collection and/or parsing of `aggregated_results.txt` with collecting/parsing the reports found in the new `reports` directory of the `output-dir` OR with JSON parsing of the new `ash_aggregated_results.json` (public JSON schema in GitHub)
   - **Recommendation**: Add `ash report` to your script after `ash` has completed to pretty-print the summary report in the terminal or job stdout.

4. **Update Pre-commit Configuration**:

   - Change hook ID from `ash` to `ash-simple-scan`
   - Update the revision to `v3.0.0` or later
   
5. **Test Your Migration**:
   ```bash
   ash --mode local
   ```

## Key Changes in ASH v3

1. **Python-based CLI**: ASH now has a Python-based CLI entrypoint while maintaining backward compatibility with the shell script entrypoint
2. **Multiple Execution Modes**: Run ASH in `local`, `container`, or `precommit` mode depending on your needs
3. **Enhanced Configuration**: Support for YAML/JSON configuration files with overrides via CLI parameters
4. **Improved Reporting**: Multiple report formats including JSON, Markdown, HTML, and CSV
5. **UV Tool Management**: Automatic installation and isolation of scanner tools (Bandit, Checkov, Semgrep) via UV
6. **Customizable**: Extend ASH with custom plugins, scanners, and reporters

## Installation Changes

### ASH v2

```bash
# Clone the repository
git clone https://github.com/awslabs/automated-security-helper.git
export PATH="${PATH}:/path/to/automated-security-helper"
```

### ASH v3

```bash
# Option 1: Using uvx (recommended) -- add to shell profile
alias ash="uvx git+https://github.com/awslabs/automated-security-helper.git@v3.0.0"

# Option 2: Using pipx
pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.0.0

# Option 3: Using pip
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.0.0
```

## Tool Management Changes

### ASH v2
- Required manual installation of all scanner tools
- Tools needed to be available in system PATH
- Version compatibility issues could occur

### ASH v3
- **Automatic Tool Management**: Tools like Bandit, Checkov, and Semgrep are automatically installed via UV tool isolation
- **Flexible Version Constraints**: ASH uses sensible default version constraints (e.g., Bandit >=1.7.0 for enhanced SARIF support) with the ability to override through configuration
- **Isolated Environments**: Tools run in isolated environments without affecting your project dependencies
- **Fallback Support**: If UV tool installation fails, ASH falls back to system-installed tools when available

### Migration Impact
- **No Action Required**: Most users don't need to change anything - tools are installed automatically
- **Offline Environments**: Set `ASH_OFFLINE=true` to skip automatic installations and use pre-installed tools
- **Custom Tool Versions**: Pre-install specific versions using `uv tool install <tool>==<version>` if needed

## Command Line Changes

### Basic Usage

#### ASH v2

```bash
# Only runs in a container
ash --source-dir /path/to/code --output-dir /path/to/output
```

#### ASH v3

```bash
# Runs in Local mode by default with scanners found locally in $PATH
ash --source-dir /path/to/code --output-dir /path/to/output

# Explicitly run in container mode (ensures all default scanners are available)
ash --mode container --source-dir /path/to/code --output-dir /path/to/output
```

### Common Parameters

| ASH v2 Parameter   | ASH v3 Parameter        | Notes                                |
|--------------------|-------------------------|--------------------------------------|
| `--source-dir`     | `--source-dir`          | Same behavior                        |
| `--output-dir`     | `--output-dir`          | Default changed to `.ash/ash_output` |
| `--ext`            | Not directly supported  | Use configuration file instead       |
| `--force`          | `--force`               | Same behavior                        |
| `--no-cleanup`     | `--cleanup false`       | Inverted logic                       |
| `--debug`          | `--debug`               | Same behavior                        |
| `--quiet`          | `--quiet`               | Same behavior                        |
| `--no-color`       | `--color false`         | Inverted logic                       |
| `--single-process` | `--strategy sequential` | Renamed                              |
| `--oci-runner`     | `--oci-runner`          | Same behavior                        |

## Output Directory Changes

### ASH v2

```
output_dir/
├── aggregated_results.txt
└── ash_cf2cdk_output/
```

### ASH v3

```
.ash/ash_output/
├── ash_aggregated_results.json
├── ash-ignore-report.txt
├── ash-scan-set-files-list.txt
├── converted
│   └── jupyter
├── reports
│   ├── ash.cdx.json
│   ├── ash.csv
│   ├── ash.flat.json
│   ├── ash.gl-sast-report.json
│   ├── ash.html
│   ├── ash.junit.xml
│   ├── ash.ocsf.json
│   ├── ash.sarif
│   ├── ash.summary.md
│   └── ash.summary.txt
└── scanners
    ├── bandit
    │   └── source
    │       ├── bandit.sarif
    │       ├── BanditScanner.stderr.log
    │       └── BanditScanner.stdout.log
    ├── cdk-nag
    │   └── source
    │       ├── ash-cdk-nag.sarif
    │       ├── tests--test_data--scanners--cdk--insecure-s3-template--yaml
    │       │   ├── ASHCDKNagScanner.assets.json
    │       │   ├── ASHCDKNagScanner.template.json
    │       │   ├── AwsSolutions-ASHCDKNagScanner-NagReport.json
    │       │   ├── cdk.out
    │       │   ├── HIPAA.Security-ASHCDKNagScanner-NagReport.json
    │       │   ├── manifest.json
    │       │   ├── NIST.800.53.R4-ASHCDKNagScanner-NagReport.json
    │       │   ├── NIST.800.53.R5-ASHCDKNagScanner-NagReport.json
    │       │   ├── PCI.DSS.321-ASHCDKNagScanner-NagReport.json
    │       │   └── tree.json
    ├── cfn-nag
    │   └── source
    │       ├── _ash__ash_output_precommit__scanners__cdk-nag__source__tests-test_data-scanners-cdk-insecure-s3-template-yaml__ASHCDKNagScanner__template__json
    │       │   └── CfnNagScanner.stdout.log
    │       ├── _ash__ash_output_precommit_local__scanners__cdk-nag__source__tests-test_data-scanners-cdk-insecure-s3-template-yaml__ASHCDKNagScanner__template__json
    │       │   └── CfnNagScanner.stdout.log
    │       └── cfn_nag.sarif
    ├── checkov
    │   └── source
    │       ├── CheckovScanner.stderr.log
    │       ├── CheckovScanner.stdout.log
    │       └── results_sarif.sarif
    ├── detect-secrets
    │   └── source
    │       └── results_sarif.sarif
    ├── grype
    │   └── source
    │       ├── GrypeScanner.stderr.log
    │       └── results_sarif.sarif
    ├── opengrep
    │   └── source
    │       ├── OpengrepScanner.stderr.log
    │       ├── OpengrepScanner.stdout.log
    │       └── results_sarif.sarif
    ├── semgrep
    │   └── source
    │       ├── results_sarif.sarif
    │       ├── SemgrepScanner.stderr.log
    │       └── SemgrepScanner.stdout.log
    └── syft
        └── source
            ├── syft.cdx.json
            ├── syft.cdx.json.syft-table.txt
            └── SyftScanner.stderr.log
```

## Configuration Changes

### ASH v2
No formal configuration file. Settings controlled via command line parameters.

### ASH v3
YAML configuration file (`.ash/.ash.yaml`):

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
      confidence_level: HIGH
reporters:
  markdown:
    enabled: true
    options:
      include_detailed_findings: true
```

## Pre-commit Integration Changes

### ASH v2

> V2 pre-commit hook runs in a container

```yaml
repos:
  - repo: https://github.com/awslabs/automated-security-helper
    rev: v1.3.3
    hooks:
      - id: ash
```

### ASH v3

> V3 pre-commit hook runs 100% locally, no container involved

```yaml
repos:
  - repo: https://github.com/awslabs/automated-security-helper
    rev: v3.0.0
    hooks:
      - id: ash-simple-scan
```

## Scanner Changes

### Added Scanners

- **detect-secrets**: Replaced git-secrets for more comprehensive secret scanning
- **Expanded Checkov Coverage**: Now scans all supported frameworks

### Improved Scanners

- **Enhanced Semgrep Integration**: Utilizes Semgrep's full language support
- **Better SCA and SBOM Generation**: Full integration of Grype and Syft

## Windows Support Changes

### ASH v2

- Required a container runtime for all operations, which required WSL2.

### ASH v3

- **Local Mode**: Runs natively on Windows with Python 3.10+
- **Container Mode**: Still requires WSL2 and a container runtime

## Programmatic Usage (New in v3)

ASH v3 can be used programmatically in Python:

```python
from automated_security_helper.interactions.run_ash_scan import run_ash_scan
from automated_security_helper.core.enums import RunMode, Strategy

# Run a scan
results = run_ash_scan(
    source_dir="/path/to/code",
    output_dir="/path/to/output",
    mode=RunMode.local,
    strategy=Strategy.parallel,
    scanners=["bandit", "semgrep"]
)
```

## Troubleshooting Common Migration Issues

### Issue: ASH command not found
**Solution**: Ensure you've installed ASH v3 using one of the installation methods and that it's in your PATH.

### Issue: Missing scanners in local mode
**Solution**: Use `--mode container` to access all scanners or install the required dependencies locally.

### Issue: Configuration file not found
**Solution**: Run `ash config init` to create a default configuration file.

### Issue: Different findings compared to v2
**Solution**: ASH v3 uses updated versions of scanners and may have different detection capabilities. Review the findings and adjust your configuration as needed.

### Issue: Scripts parsing aggregated_results.txt no longer work
**Solution**: Update your scripts to parse the new JSON output format in `ash_aggregated_results.json`.

## Getting Help

If you encounter issues during migration:

1. Check the [ASH Documentation](https://awslabs.github.io/automated-security-helper/)
2. Create an issue on [GitHub](https://github.com/awslabs/automated-security-helper/issues)
3. Run `ash --help` for command-line help