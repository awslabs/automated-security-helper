# ASH Ferret Scan Plugin

This plugin integrates [Ferret Scan](https://github.com/awslabs/ferret-scan) with the Automated Security Helper (ASH) to provide comprehensive sensitive data detection for source code and documents.

## Overview

The Ferret Scan plugin enables ASH to leverage Ferret's powerful sensitive data detection capabilities for:

- **Credit Card Detection**: 15+ card brands with mathematical validation (Luhn algorithm)
- **Passport Numbers**: Multi-country formats including US, UK, Canada, EU, and MRZ
- **Social Security Numbers**: Domain-aware validation with HR/Tax/Healthcare context
- **API Keys & Secrets**: 40+ patterns including AWS, GitHub, Google Cloud, Stripe, and more
- **Email Addresses**: RFC-compliant with domain validation
- **Phone Numbers**: International and domestic formats
- **IP Addresses**: IPv4 and IPv6 with network context
- **Social Media Profiles**: LinkedIn, Twitter/X, Facebook, GitHub, Instagram, TikTok
- **Intellectual Property**: Patents, trademarks, copyrights, trade secrets
- **Document Metadata**: EXIF and document metadata extraction

## ASH Convention Compliance

This plugin follows ASH conventions for consistent behavior across all scanners:

### Hardcoded by Plugin (Do NOT configure at plugin level)

| Feature | ASH Convention | Notes |
|---------|---------------|-------|
| **Output Format** | Always SARIF | Required by ASH for result aggregation |
| **Color Output** | Always `--no-color` | ASH handles formatting |

### Ferret-Scan Log Controls

| Option | Description |
|--------|-------------|
| `ferret_debug: true` | Enables ferret-scan's own debug output (preprocessing/validation flow) |
| `ferret_verbose: true` | Enables ferret-scan's own verbose output (detailed finding info) |

Note: Bare `debug` and `verbose` are blocked to avoid confusion with ASH's `--debug`/`--verbose` flags.

### Managed by ASH Framework

| Feature | ASH Convention | Notes |
|---------|---------------|-------|
| **Output Directory** | `.ash/ash_output/scanners/ferret-scan/` | Follows ASH conventions |
| **Offline Mode** | `ASH_OFFLINE=true` | Respects ASH offline mode |
| **Suppressions** | `.ash/suppressions.yaml` | Managed centrally by ASH |

### Unsupported Options

The following ferret-scan CLI options are **NOT supported** and will raise an error:

| Option | Reason |
|--------|--------|
| `format`, `output_format` | ASH requires SARIF format |
| `debug`, `verbose` | Use `ferret_debug`/`ferret_verbose` instead (avoids confusion with ASH flags) |
| `web`, `port` | Web server mode not applicable |
| `enable_redaction`, `redaction_*`, `memory_scrub` | Post-processing, not scanning |
| `generate_suppressions`, `show_suppressed`, `suppressions_file` | ASH manages suppressions |
| `extract_text` | Utility mode, not scanning |

## Prerequisites

### Version Compatibility

This plugin is tested and compatible with specific ferret-scan versions. Using versions outside the supported range may result in unexpected behavior.

**Supported Versions:** 0.1.0 to 2.0.0 (exclusive)

| Plugin Version | ferret-scan Version | Notes |
|---------------|---------------------|-------|
| Current | 0.1.0 - 2.0.0 (exclusive) | Initial release with full feature support |

### Install Ferret Scan

The plugin requires Ferret Scan to be installed and available in your system PATH.

**pip (Recommended)**:
```bash
pip install ferret-scan
```

**Build from Source**:
```bash
git clone https://github.com/awslabs/ferret-scan.git
cd ferret-scan
make build
```

### Verify Installation

```bash
ferret-scan --version
ferret-scan --help
```

## Quick Start

### Enable the Plugin

The ferret-scan plugin is a community plugin that must be explicitly enabled. There are two ways to do this:

#### Option 1: Add to ASH Configuration File (Recommended)

Include the plugin module in your `.ash/.ash.yaml` configuration file:

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_ferret_plugins

scanners:
  ferret-scan:
    enabled: true
```

#### Option 2: Command Line Flag

Use the `--ash-plugin-modules` flag when running ASH:

```bash
uv run ash scan --source-dir /path/to/code \
    --ash-plugin-modules automated_security_helper.plugin_modules.ash_ferret_plugins
```

### Verify Plugin is Loaded

```bash
# With config file
uv run ash plugin list | grep -i ferret

# Or with command line flag
uv run ash plugin list --ash-plugin-modules automated_security_helper.plugin_modules.ash_ferret_plugins | grep -i ferret
```

You should see `ferret-scan` in the list of scanners.

### Basic Configuration

Add scanner configuration to your `.ash/.ash.yaml`:

```yaml
scanners:
  ferret-scan:
    enabled: true
```

### Run Ferret Scan

```bash
# Scan current directory
uv run ash --scanners ferret-scan

# Scan specific directory
uv run ash --source-dir /path/to/project --scanners ferret-scan

# Run with ferret-scan's own debug output
uv run ash --scanners ferret-scan -o ferret_debug=true

# Run with ferret-scan's own verbose output
uv run ash --scanners ferret-scan -o ferret_verbose=true
```

### Run Without Configuration File

If you want to run Ferret Scan without saving a configuration file:

```bash
# Scan current directory only with ferret-scan
uv run ash --scanners ferret-scan \
  --ash-plugin-modules automated_security_helper.plugin_modules.ash_ferret_plugins

# Scan with all available scanners (including ferret-scan)
uv run ash --ash-plugin-modules automated_security_helper.plugin_modules.ash_ferret_plugins
```

## Configuration Options

### Basic Options

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      confidence_levels: "all"    # high, medium, low, or combinations
      checks: "all"               # Specific checks to run
      recursive: true             # Recursively scan directories
```

### Configuration Options Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `confidence_levels` | string | `"all"` | Confidence levels: `high`, `medium`, `low`, or combinations like `high,medium` |
| `checks` | string | `"all"` | Specific checks to run (comma-separated) |
| `recursive` | bool | `true` | Recursively scan directories |
| `config_file` | string | `null` | Path to custom Ferret YAML config file |
| `use_default_config` | bool | `true` | Use the default config bundled with this plugin |
| `profile` | string | `null` | Profile name from config file |
| `exclude_patterns` | list | `[]` | Glob patterns to exclude |
| `show_match` | bool | `false` | ⚠️ Display matched text in findings (see security warning below) |
| `enable_preprocessors` | bool | `true` | Enable text extraction from documents (PDF, Office) |
| `ferret_debug` | bool | `false` | Enable ferret-scan's own debug logging (preprocessing/validation flow) |
| `ferret_verbose` | bool | `false` | Enable ferret-scan's own verbose output (detailed finding info) |
| `tool_version` | string | `null` | Version constraint for ferret-scan (e.g., `>=1.0.0,<2.0.0`, `==1.2.0`) |
| `skip_version_check` | bool | `false` | Skip version compatibility check (use with caution) |

### Options NOT Supported (Will Raise Error)

The following options are **not supported** because they conflict with ASH conventions:

| Option | Error Message |
|--------|--------------|
| `format`, `output_format` | "ASH requires SARIF format for result aggregation" |
| `debug` | "Use 'ferret_debug: true' instead. Bare 'debug' is blocked to avoid confusion with ASH's --debug flag." |
| `verbose` | "Use 'ferret_verbose: true' instead. Bare 'verbose' is blocked to avoid confusion with ASH's --verbose flag." |
| `web`, `port` | "Web server mode is not supported in ASH integration" |
| `enable_redaction`, `redaction_output_dir`, `redaction_strategy`, `redaction_audit_log`, `memory_scrub` | "Redaction is not supported in ASH integration" |
| `generate_suppressions`, `show_suppressed`, `suppressions_file` | "ASH manages suppressions centrally" |
| `extract_text` | "Text extraction mode is not supported" |

### Security Warning: show_match Option

⚠️ **Data Exfiltration Risk**: The `show_match` option causes ferret-scan to include the actual matched sensitive data (credit card numbers, SSNs, API keys, etc.) in the scan output. This creates significant security risks:

- **Log file exposure**: Matched sensitive data will appear in SARIF reports, CI/CD logs, and ASH output files
- **Accidental data leakage**: Reports shared with team members or uploaded to security dashboards may contain real sensitive data
- **Compliance violations**: Logging actual PII/PCI data may violate data protection regulations (GDPR, PCI-DSS, HIPAA)

**Recommendation**: Keep `show_match: false` (the default) in production environments. Only enable it temporarily for debugging in isolated, secure environments where log files are properly protected and purged.

### Available Checks

- `CREDIT_CARD` - Credit card numbers (Visa, MasterCard, Amex, etc.)
- `EMAIL` - Email addresses
- `INTELLECTUAL_PROPERTY` - Patents, trademarks, copyrights
- `IP_ADDRESS` - IPv4 and IPv6 addresses
- `METADATA` - Document and image metadata
- `PASSPORT` - Passport numbers (multi-country)
- `PERSON_NAME` - Person names
- `PHONE` - Phone numbers
- `SECRETS` - API keys, tokens, passwords
- `SOCIAL_MEDIA` - Social media profiles
- `SSN` - Social Security Numbers

### Advanced Configuration

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      confidence_levels: "high,medium"
      checks: "CREDIT_CARD,SECRETS,SSN,PASSPORT"
      recursive: true
      profile: "security-audit"
      config_file: "my-ferret-config.yaml"
      # show_match: false  # Keep disabled to avoid logging sensitive data
      enable_preprocessors: true  # Extract text from PDFs, Office docs
      exclude_patterns:
        - "*.log"
        - "node_modules/**"
        - "vendor/**"
        - ".git/**"
```

Note: Do NOT configure bare `debug`, `verbose`, `format`, or suppression options at the plugin level. Use `ferret_debug`/`ferret_verbose` for ferret-scan's own log output. Other options are managed by ASH globally.

### Version Pinning

Pin to a specific ferret-scan version for reproducible builds:

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      tool_version: "==1.2.0"  # Exact version
```

Or use a version range:

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      tool_version: ">=1.0.0,<1.5.0"  # Compatible range
```

To bypass version checks (not recommended for production):

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      skip_version_check: true  # Use with caution
```

## Default Configuration

This plugin includes a bundled `ferret-config.yaml` that is automatically used when no custom config is specified. The default config includes:

- Comprehensive validator patterns for intellectual property detection
- Social media platform detection patterns (LinkedIn, Twitter, Facebook, etc.)
- Pre-configured profiles for common use cases
- AWS/Amazon internal URL patterns for IP detection

### Available Profiles

The default configuration includes these pre-defined profiles:

| Profile | Description |
|---------|-------------|
| `quick` | Fast security check (high confidence only) |
| `thorough` | All confidence levels with text extraction |
| `ci` | CI/CD integration (JUnit XML output) |
| `security-audit` | Security team scanning (JSON output) |
| `comprehensive` | Complete analysis (YAML output) |
| `credit-card` | PCI compliance focused |
| `passport` | Identity verification focused |
| `intellectual-property` | IP detection focused |
| `json-api` | Structured JSON for APIs |
| `csv-export` | CSV for spreadsheet analysis |
| `silent` | Minimal output for automation |

### Using Profiles

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      profile: "security-audit"
```

## Overriding Default Configuration

### Option 1: Custom Config File Path

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      config_file: "/path/to/your/custom-ferret.yaml"
```

### Option 2: Config File in Source Directory

The plugin searches for config files in this order:
1. Explicitly specified `config_file` path
2. `ferret.yaml` or `.ferret.yaml` in the source directory
3. `.ash/ferret.yaml` or `.ash/ferret-scan.yaml` in the source directory
4. Default config bundled with this plugin

Simply create a `ferret.yaml` or `.ferret.yaml` in your project root to override the defaults.

### Option 3: Disable Default Config

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      use_default_config: false  # Use ferret-scan's built-in defaults only
```

### Creating a Custom Config File

Copy the default config from the plugin:

```bash
cp $(python -c "import automated_security_helper.plugin_modules.ash_ferret_plugins as p; print(p.__path__[0])")/ferret-config.yaml ./my-ferret-config.yaml
```

Or create a minimal config that only overrides what you need:

```yaml
# my-ferret-config.yaml
defaults:
  confidence_levels: high,medium
  checks: SECRETS,CREDIT_CARD,SSN

validators:
  intellectual_property:
    internal_urls:
      - "http[s]?:\\/\\/.*\\.mycompany\\.com"
      - "http[s]?:\\/\\/internal\\..*"
```

## Usage Examples

### High Confidence Findings Only

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      confidence_levels: "high"
```

### PCI Compliance Scan

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      checks: "CREDIT_CARD"
      confidence_levels: "all"
      profile: "credit-card"
```

### Secrets Detection Only

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      checks: "SECRETS"
      confidence_levels: "high,medium"
```

### Combined with Other Scanners

```bash
# Use Ferret Scan alongside other ASH scanners
uv run ash --scanners ferret-scan,bandit,detect-secrets
```

### CI/CD Integration

```bash
# Run in container mode for CI/CD
uv run ash --mode container --scanners ferret-scan
```

## Output Integration

Ferret Scan results are integrated into ASH's unified reporting system:

- **SARIF Format**: Machine-readable results for CI/CD integration
- **HTML Reports**: Visual security dashboard with remediation guidance
- **JSON/CSV**: Structured data for analysis and tracking
- **Markdown**: Human-readable summaries for pull requests

Results are written to:
```
.ash/ash_output/
├── scanners/
│   └── ferret-scan/
│       └── source/
│           └── ferret-scan.sarif
└── reports/
    └── ash.sarif  # Aggregated results
```

## Troubleshooting

### Common Issues

**Ferret Scan not found**:
```bash
# Check if ferret-scan is in PATH
which ferret-scan

# Install if missing
pip install ferret-scan
```

**Unsupported option error**:
If you see an error like:
```
ValueError: Unsupported option 'debug' in ferret-scan plugin configuration. 
Use 'ferret_debug: true' instead. Bare 'debug' is blocked to avoid confusion with ASH's --debug flag.
```

This means you used a bare option name that's blocked. Use the `ferret_` prefixed version instead:
```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      ferret_debug: true    # Correct
      ferret_verbose: true  # Correct
```

**Empty directory warnings**:
The plugin will skip scanning if the target directory is empty or doesn't exist, logging an appropriate warning message.

**No findings in output**:
```bash
# Check if ferret-scan works directly
ferret-scan --format sarif --file /path/to/test/file
```

### Debug Mode

Enable ferret-scan's own debug/verbose output to troubleshoot issues:

```bash
# Enable ferret-scan's debug output (shows preprocessing and validation flow)
uv run ash --scanners ferret-scan -o ferret_debug=true

# Enable ferret-scan's verbose output (shows detailed finding info)
uv run ash --scanners ferret-scan -o ferret_verbose=true
```

## Integration Examples

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: ash-ferret-scan
        name: ASH Ferret Scan Sensitive Data Detection
        entry: uv run ash --scanners ferret-scan --mode precommit
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
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          pip install ferret-scan
          pip install uv
      - name: Run ASH with Ferret Scan
        run: |
          uv run ash --scanners ferret-scan --output-format sarif \
            --config-overrides "ash_plugin_modules+=[\"automated_security_helper.plugin_modules.ash_ferret_plugins\"]"
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: .ash/ash_output/reports/ash.sarif
```

### GitLab CI

```yaml
# .gitlab-ci.yml
ferret-security-scan:
  stage: test
  image: python:3.11
  before_script:
    - pip install ferret-scan uv
  script:
    - uv run ash --scanners ferret-scan \
        --config-overrides "ash_plugin_modules+=[\"automated_security_helper.plugin_modules.ash_ferret_plugins\"]"
  artifacts:
    reports:
      sast: .ash/ash_output/reports/ash.sarif
```

## Comparison with detect-secrets

| Feature | Ferret Scan | detect-secrets |
|---------|-------------|----------------|
| Credit Cards | ✅ 15+ brands with Luhn | ❌ |
| Passports | ✅ Multi-country + MRZ | ❌ |
| SSN | ✅ Domain-aware | ❌ |
| API Keys | ✅ 40+ patterns | ✅ Multiple patterns |
| High Entropy | ❌ | ✅ |
| Social Media | ✅ | ❌ |
| IP Detection | ✅ | ❌ |
| Document Metadata | ✅ EXIF extraction | ❌ |

Consider using both scanners together for comprehensive coverage:
```bash
uv run ash --scanners ferret-scan,detect-secrets
```

## Documentation

For comprehensive documentation and advanced configuration options, see:
- [Ferret Scan GitHub Repository](https://github.com/awslabs/ferret-scan)
- [ASH Plugin Development Guide](../index.md)
- [ASH Scanner Plugins](../scanner-plugins.md)

## Support

- **ASH Issues**: [GitHub Issues](https://github.com/awslabs/automated-security-helper/issues)
- **Ferret Scan Issues**: [GitHub Issues](https://github.com/awslabs/ferret-scan/issues)
- **Community**: [ASH Discussions](https://github.com/awslabs/automated-security-helper/discussions)
