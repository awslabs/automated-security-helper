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
| **Suppressions** | `global_settings.suppressions` in the ASH config file | Managed centrally by ASH |

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
| `preprocess_only`, `pre_commit_mode`, `list_profiles` | Utility/pre-commit modes — produce no SARIF scan results |

## Prerequisites

### Version Compatibility

This plugin is tested and compatible with specific ferret-scan versions. Using versions outside the supported range may result in unexpected behavior.

**Supported Versions:** 2.4.5 to 2.6.0 (exclusive)

| Plugin Version | ferret-scan Version | Notes |
|---------------|---------------------|-------|
| Current | 2.4.5 - 2.6.0 (exclusive) | 2.4.5 and 2.5.2 verified end to end; 2.5.2 is the recommended version |

### Install Ferret Scan

The plugin runs the `ferret-scan` command. ASH finds it on `PATH`, or beside the
Python interpreter that runs ASH, which is where `ash dependencies install` puts it.

**ASH (Recommended)** — installs the version the plugin is tested against into
the Python environment that runs ASH, with pip or uv, whichever owns that
environment (a uv tool, uvx or `uv venv` install has no pip):
<!-- doctest: illustrative reason="reads .ash/.ash_community_plugins.yaml, a file of the ASH repository that a project does not have until it adds one, and installs ferret-scan over the network" -->
```bash
ash dependencies install --config .ash/.ash_community_plugins.yaml
```

**pip**: pass the supported range. A bare `pip install ferret-scan` resolves to
the newest release, which may sit outside the range in the table above — that is
how a release published partway through a CI run once failed every open pull
request without a source change.
<!-- doctest: illustrative reason="installs a tool over the network" -->
```bash
pip install 'ferret-scan>=2.4.5,<2.6.0'
```

**Build from Source**:
<!-- doctest: illustrative reason="installs a tool over the network" -->
```bash
git clone https://github.com/awslabs/ferret-scan.git
cd ferret-scan
make build
```

### Verify Installation

<!-- doctest: illustrative reason="needs ferret-scan installed on the host" -->
```bash
ferret-scan --version
ferret-scan --help
```

## Quick Start

### Enable the Plugin

The ferret-scan plugin is a community plugin that must be explicitly enabled. There are two ways to do this:

#### Option 1: Add to ASH Configuration File (Recommended)

Include the plugin module in your ASH config file (`.ashrc.yaml` in a new project):

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_ferret_plugins

scanners:
  ferret-scan:
    enabled: true
```

#### Option 2: Command Line Flag

Use the `--ash-plugin-modules` flag when running ASH:

<!-- doctest: illustrative reason="runs a scan that needs ferret-scan installed on the host" -->
```bash
uv run ash scan --source-dir /path/to/code \
    --ash-plugin-modules automated_security_helper.plugin_modules.ash_ferret_plugins
```

### Verify Plugin is Loaded

<!-- doctest: illustrative reason="runs a scan that needs ferret-scan installed on the host" -->
```bash
# With config file
uv run ash plugin list | grep -i ferret

# Or with command line flag
uv run ash plugin list --ash-plugin-modules automated_security_helper.plugin_modules.ash_ferret_plugins | grep -i ferret
```

You should see `ferret-scan` in the list of scanners.

### Basic Configuration

Add scanner configuration to your ASH config file (`.ashrc.yaml` in a new project):

```yaml
scanners:
  ferret-scan:
    enabled: true
```

### Run Ferret Scan

<!-- doctest: illustrative reason="runs a scan that needs ferret-scan installed on the host" -->
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

<!-- doctest: illustrative reason="runs a scan that needs ferret-scan installed on the host" -->
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

<!-- doctest: options of=scanners.ferret-scan -->
| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `confidence_levels` | string | `"all"` | Confidence levels: `high`, `medium`, `low`, or combinations like `high,medium` |
| `checks` | string | `"all"` | Specific checks to run (comma-separated) |
| `recursive` | bool | `true` | Recursively scan directories |
| `config_file` | string | `null` | Path to custom Ferret YAML config file |
| `use_default_config` | bool | `true` | Use the default config bundled with this plugin. Set by the operator only; see [Using profiles](#using-profiles) |
| `profile` | string | `null` | Profile name from config file. Set by the operator only; see [Using profiles](#using-profiles) |
| `exclude_patterns` | list | `[]` | Glob patterns to exclude. ASH also excludes its own output directories inside the scanned directory, except one whose path holds a comma, which ferret-scan's comma-separated `ferret-scan --exclude` cannot hold; ferret-scan then reads it, ASH logs a warning naming it, and the findings ferret-scan reports there are dropped. The files `global_settings.ignore_paths` ignores are excluded too, each by its full path, as ASH matches the ignore paths: an ignore path ASH matches to no file, such as a bare `api` (write `api/` for the directory), excludes nothing. |
| `show_match` | bool | `false` | Display matched text in ferret-scan's own output (see [show_match](#show_match) below) |
| `enable_preprocessors` | bool | `true` | Enable text extraction from documents (PDF, Office) |
| `finding_limit` | int | `0` | Max findings ferret-scan emits (`ferret-scan --limit`). `0` = unlimited. ASH defaults to `0` because ferret-scan's own default of `200` silently truncates large scans. |
| `fail_on_incomplete` | bool | `false` | Pass `ferret-scan --fail-on-incomplete` so ferret-scan exits 3 when a file could not be fully scanned; ASH still reports the partial findings, counts the target as failed, and records the scanner `ERROR`, so the completeness gate fails the scan. |
| `respect_gitignore` | bool | `false` | Pass `ferret-scan --respect-gitignore` to honor `.gitignore`. Off by default, because `.gitignore` often hides high-value files (`.env`, `*.pem`) a sensitive-data scan should see. |
| `disable_ip_types` | string | `null` | Comma-separated `INTELLECTUAL_PROPERTY` sub-types to skip (`ferret-scan --disable-ip-types`): `copyright,patent,trademark,trade_secret,internal_url`. |
| `explain` | bool | `false` | Pass `ferret-scan --explain` for an offline per-finding rationale + verdict + drafted suppression reason. No data leaves the host. |
| `validator_budget` | string | `null` | Per-validator time budget (`ferret-scan --validator-budget`), e.g. `SSN=500ms,all=2m`. Over-budget validators stop and mark the scan incomplete. |
| `max_live_bytes` | string | `null` | Cap on extracted content held in memory (`ferret-scan --max-live-bytes`), e.g. `256MB`/`1GB`. Bounds peak memory on constrained hosts. |
| `ferret_debug` | bool | `false` | Enable ferret-scan's own debug logging (preprocessing/validation flow) |
| `ferret_verbose` | bool | `false` | Enable ferret-scan's own verbose output (detailed finding info) |
| `tool_version` | string | `null` | Version constraint for ferret-scan (e.g., `>=2.4.5,<2.6.0`, `==2.5.2`) |
| `skip_version_check` | bool | `false` | Skip version compatibility check (use with caution) |

### Options NOT Supported (Will Raise Error)

The following options are **not supported** because they conflict with ASH conventions.
Setting one stops the scan with exit code 3 when ASH loads the plugins, before
anything is converted or scanned. The error names the option's location and gives the
message in the table, for example:

```text
Configuration validation failed: scanners.ferret-scan.options (scanner 'ferret-scan'): Value error, Unsupported option 'debug' in ferret-scan plugin configuration. Use 'ferret_debug: true' instead. Bare 'debug' is blocked to avoid confusion with ASH's --debug flag.
```

Any other option the plugin does not declare is refused the same way, as `Unknown
key '<option>'` with the accepted options listed. `ash config validate` and `ash
config lint` do not import the plugin, so they do not catch either kind; both say
its section is not checked there, and a scan checks it.

| Option | Error Message |
|--------|--------------|
| `format`, `output_format` | "ASH requires SARIF format for result aggregation" |
| `debug` | "Use 'ferret_debug: true' instead. Bare 'debug' is blocked to avoid confusion with ASH's --debug flag." |
| `verbose` | "Use 'ferret_verbose: true' instead. Bare 'verbose' is blocked to avoid confusion with ASH's --verbose flag." |
| `web`, `port` | "Web server mode is not supported in ASH integration" |
| `enable_redaction`, `redaction_output_dir`, `redaction_strategy`, `redaction_audit_log`, `memory_scrub` | "Redaction is not supported in ASH integration" |
| `generate_suppressions`, `show_suppressed`, `suppressions_file` | "ASH manages suppressions centrally" |
| `extract_text` | "Text extraction mode is not supported" |
| `preprocess_only` | "Outputs extracted text and exits — produces no SARIF results" |
| `pre_commit_mode` | "ASH manages output formatting and exit codes; use ASH's own pre-commit hook" |
| `list_profiles` | "Only prints available profiles and exits — produces no scan results" |

### show_match

With `show_match` on, ferret-scan writes each matched value (card numbers, national
IDs, keys) into its own output: the result message (`Matched text: '...'`) and the
SARIF snippets. ASH masks those values before it writes `ash_aggregated_results.json`
or any report, so they do not reach ASH's reports, the Bedrock summary or MCP
responses (see "Secret values in reports" in the output formats page). They do stay
in ferret-scan's own results file under `scanners/ferret-scan/`, and in its log
output.

`show_match` is off by default, and every profile in the bundled
`ferret-config.yaml` sets it to `false`, including `debug`, `comprehensive`,
`json-api`, `person-name`, `enhanced-metadata` and `social-media`, which turned it
on before. Turn it on only where the scanner's own output directory is protected.

### Available Checks

The authoritative list for your installed version is `ferret-scan --help checks` — do not
hardcode it, as ferret-scan adds detectors between releases. As of v2.4.5 through v2.5.2:

- `BANK_ACCOUNT` - Bank account / IBAN / routing numbers
- `CLOUD_RESOURCES` - Cloud resource identifiers (AWS ARNs, Azure/GCP/OCI/IBM/Alibaba IDs)
- `CREDIT_CARD` - Credit card numbers (Visa, MasterCard, Amex, etc.)
- `DATE_OF_BIRTH` - Dates of birth
- `DRIVERS_LICENSE` - Driver's license numbers (state formats)
- `EMAIL` - Email addresses
- `INTELLECTUAL_PROPERTY` - Patents, trademarks, copyrights (internal-URL detection requires config)
- `IP_ADDRESS` - IPv4 and IPv6 addresses
- `MEDICAL_ID` - Medical / health identifiers (PHI)
- `METADATA` - Document, image, audio, and video metadata
- `OTP` - One-time-passcode / two-factor secrets
- `PASSPORT` - Passport numbers (multi-country)
- `PERSON_NAME` - Person names
- `PHONE` - Phone numbers
- `PHYSICAL_ADDRESS` - Physical / postal addresses
- `SECRETS` - API keys, tokens, passwords
- `SOCIAL_MEDIA` - Social media profiles
- `SSN` - Social Security Numbers
- `VIN` - Vehicle Identification Numbers

#### Note: `API_KEY_OR_SECRET` false positives (SECRETS check)

The `SECRETS` check includes a generic `API_KEY_OR_SECRET` detector that matches on the
*name* of an assignment when the name is a secret keyword (`session`, `token`, `secret`,
`password`, `api_key`, …) — **regardless of the value**. So typed code and config such as a
`session` field on a generated model, a `session` local, or a Terraform local named
`manage_auth_secret` can be flagged at HIGH confidence even though no credential is present.

This detector **cannot be disabled in ferret-scan's config** (the tool honors
`disabled_types` only for the `INTELLECTUAL_PROPERTY` check, not `SECRETS`). The plugin
keeps it enabled so real secrets are still found, and expects you to manage false positives
with ASH's own controls — a path-scoped suppression:

```yaml
global_settings:
  suppressions:
    - path: path/to/generated_or_test_file.py
      rule_id: API_KEY_OR_SECRET
      reason: "False positive — variable/field name matches the secret-keyword heuristic, not a credential"
```

or the plugin's `exclude_patterns`, or scoping the `checks` option to omit `SECRETS`.

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
      config_file: "/etc/ash/ferret-config.yaml"  # outside the scanned tree
      # show_match: false  # Keep disabled to avoid logging sensitive data
      enable_preprocessors: true  # Extract text from PDFs, Office docs
      exclude_patterns:
        - "*.log"
        - "node_modules/**"
        - "vendor/**"
        - ".git/**"
```

`profile`, `use_default_config` and `config_file` take effect only from the
operator: `profile` and `use_default_config` from `--config-overrides` or a config
file outside the scanned tree, and `config_file` only when the file it names is
outside the tree.

Note: Do NOT configure bare `debug`, `verbose`, `format`, or suppression options at the plugin level. Use `ferret_debug`/`ferret_verbose` for ferret-scan's own log output. Other options are managed by ASH globally.

### Version Pinning

Pin to a specific ferret-scan version for reproducible builds:

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      tool_version: "==2.5.2"  # Exact version
```

Or use a version range:

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      tool_version: ">=2.4.5,<2.6.0"  # Compatible range
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

A profile changes what is reported: it can run fewer checks and report only
higher-confidence findings. On ASH's ferret-scan test files, with ferret-scan
2.5.3, the bundled config reported 111 findings with no profile, 30 with `quick`,
and none with six of its profiles. The bundled `redaction` and `secure-redaction`
profiles also have ferret-scan write redacted copies of the files it scans.
`use_default_config: false` changes what is reported too, since the empty config
it gives ferret-scan has none of the bundled validators' patterns.

So `profile` and `use_default_config` are the operator's choice. A config file
inside the scanned tree, or one an MCP client delivered, does not set them, and
the scan's warnings name the value that was ignored (see
[How a file's tier is decided](../../../concepts/trust-model.md#how-the-tier-is-decided)).
Set them with `--config-overrides`:

<!-- doctest: illustrative reason="runs a scan that needs ferret-scan installed on the host" -->
```bash
ash --config-overrides 'scanners.ferret-scan.options.profile=security-audit'
```

or in a config file outside the scanned tree, named with `--config`:

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

A config file inside the scanned tree is not passed to ferret-scan, whether
`config_file` names it or the plugin finds it by name (`ferret.yaml`,
`ferret.yml`, `.ferret.yaml`, `.ferret.yml`, `.ash/ferret.yaml` or
`.ash/ferret-scan.yaml` in the source directory). The bundled config is used
instead, and the scan's warnings name the file. Put the file outside the scanned
tree and name it with `config_file`.

### Option 3: Disable Default Config

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      use_default_config: false  # Use ferret-scan's built-in defaults only
```

Like `profile`, this is honored only from the operator: `--config-overrides` or a
config file outside the scanned tree.

### Creating a Custom Config File

Copy the default config from the plugin:

<!-- doctest: illustrative reason="a shell outline that needs the plugin's tool and a project to scan" -->
```bash
cp $(python -c "import automated_security_helper.plugin_modules.ash_ferret_plugins as p; print(p.__path__[0])")/ferret-config.yaml ./my-ferret-config.yaml
```

Or create a minimal config that only overrides what you need:

<!-- doctest: config kind=other reason="a ferret-scan configuration file, which ferret-scan reads, not ASH" -->
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

<!-- doctest: illustrative reason="runs a scan that needs ferret-scan installed on the host" -->
```bash
# Use Ferret Scan alongside other ASH scanners
uv run ash --scanners ferret-scan,bandit,detect-secrets
```

### CI/CD Integration

<!-- doctest: illustrative reason="needs a container runtime" -->
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
```text
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
<!-- doctest: illustrative reason="installs a tool over the network" -->
```bash
# Check if ferret-scan is in PATH
which ferret-scan

# Install if missing
pip install ferret-scan
```

**Unsupported option error**:
If the scan exits 3 with an error like:
```text
Configuration validation failed: scanners.ferret-scan.options (scanner 'ferret-scan'): Value error, Unsupported option 'debug' in ferret-scan plugin configuration. Use 'ferret_debug: true' instead. Bare 'debug' is blocked to avoid confusion with ASH's --debug flag.
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
<!-- doctest: illustrative reason="needs ferret-scan installed on the host" -->
```bash
# Check if ferret-scan works directly
ferret-scan --format sarif --file /path/to/test/file
```

### Debug Mode

Enable ferret-scan's own debug/verbose output to troubleshoot issues:

<!-- doctest: illustrative reason="runs a scan that needs ferret-scan installed on the host" -->
```bash
# Enable ferret-scan's debug output (shows preprocessing and validation flow)
uv run ash --scanners ferret-scan -o ferret_debug=true

# Enable ferret-scan's verbose output (shows detailed finding info)
uv run ash --scanners ferret-scan -o ferret_verbose=true
```

## Integration Examples

### Pre-commit Hook

<!-- doctest: config kind=pre-commit -->
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

<!-- doctest: config kind=github-actions runner=none reason="a workflow for the reader's own repository, which installs ferret-scan from the network" -->
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
        # Also when ASH exits non-zero on findings: without a status function
        # GitHub skips this step after any failed step.
        if: ${{ !cancelled() }}
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: .ash/ash_output/reports/ash.sarif
```

### GitLab CI

<!-- doctest: config kind=gitlab-ci runner=none reason="a pipeline for the reader's own project, which installs ferret-scan from the network" -->
```yaml
# .gitlab-ci.yml
ferret-security-scan:
  stage: test
  image: python:3.11
  before_script:
    - pip install ferret-scan uv
  script:
    - |
      uv run ash --scanners ferret-scan \
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
<!-- doctest: illustrative reason="runs a scan that needs ferret-scan installed on the host" -->
```bash
uv run ash --scanners ferret-scan,detect-secrets
```

## Documentation

For comprehensive documentation and advanced configuration options, see:
- [Ferret Scan GitHub Repository](https://github.com/awslabs/ferret-scan)
- [Plugins](../../../plugins/index.md)
- [Write a scanner plugin](../../../plugins/write-a-scanner.md)

## Support

- **ASH Issues**: [GitHub Issues](https://github.com/awslabs/automated-security-helper/issues)
- **Ferret Scan Issues**: [GitHub Issues](https://github.com/awslabs/ferret-scan/issues)
- **Community**: [ASH Discussions](https://github.com/awslabs/automated-security-helper/discussions)
