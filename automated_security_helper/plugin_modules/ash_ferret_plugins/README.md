# ASH Ferret Scan Plugin

This plugin integrates [Ferret Scan](https://github.com/awslabs/ferret-scan) into the Automated Security Helper (ASH) for sensitive data detection.

## Overview

Ferret Scan is a sensitive data detection tool that scans files for potential sensitive information including:

- **Credit Card Numbers** - 15+ card brands with mathematical validation
- **Passport Numbers** - Multi-country formats (US, UK, Canada, EU, MRZ)
- **Social Security Numbers** - Domain-aware validation with HR/Tax/Healthcare context
- **Email Addresses** - RFC-compliant with domain validation
- **Phone Numbers** - International and domestic formats
- **API Keys & Secrets** - 40+ patterns (AWS, GitHub, Google Cloud, Stripe, etc.)
- **IP Addresses** - IPv4 and IPv6 with network context
- **Social Media Profiles** - LinkedIn, Twitter/X, Facebook, GitHub, etc.
- **Intellectual Property** - Patents, trademarks, copyrights, trade secrets
- **Document Metadata** - EXIF and document metadata extraction

## Installation

### Prerequisites

Install Ferret Scan:

```bash
# Recommended: let ASH install the version this plugin is tested against
ash dependencies install --config .ash/.ash_community_plugins.yaml

# Or install by hand. Use the constraint, not a bare `pip install ferret-scan`:
# the latter resolves to whatever is newest, which is how a release published
# mid-CI-run once turned every open pull request red.
pip install 'ferret-scan>=2.4.5,<2.6.0'

# Or build from source
git clone https://github.com/awslabs/ferret-scan.git
cd ferret-scan
make build
```

The supported range is declared in `ferret_scanner.py` (`DEFAULT_VERSION_CONSTRAINT`)
and is what `ash dependencies install` applies. If the two ever disagree, the
constant is correct.

### Enable the Plugin

The ferret-scan plugin is a community plugin that must be explicitly enabled. There are two ways to do this:

#### Option 1: Add to ASH Configuration File (Recommended)

Add the plugin module to your `.ash/.ash.yaml` configuration file:

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_ferret_plugins

scanners:
  ferret-scan:
    enabled: true
    options:
      confidence_levels: "high"
      checks: "CREDIT_CARD,SECRETS,SSN,PASSPORT"
```

#### Option 2: Command Line Flag

Use the `--ash-plugin-modules` flag when running ASH:

```bash
uv run ash scan --source-dir /path/to/code \
    --ash-plugin-modules automated_security_helper.plugin_modules.ash_ferret_plugins
```

### Verify Plugin is Loaded

To verify the plugin is properly loaded:

```bash
# With config file
uv run ash plugin list | grep -i ferret

# Or with command line flag
uv run ash plugin list --ash-plugin-modules automated_security_helper.plugin_modules.ash_ferret_plugins | grep -i ferret
```

You should see `ferret-scan` in the list of scanners.

## ASH Convention Compliance

This plugin follows ASH conventions for consistent behavior across all scanners:

### Inherited from ASH (Do NOT configure at plugin level)

| Feature | ASH Convention | Notes |
|---------|---------------|-------|
| **Debug Mode** | `ferret_debug: true` | Controls ferret-scan's own debug output (independent of ASH's `--debug`) |
| **Verbose Mode** | `ferret_verbose: true` | Controls ferret-scan's own verbose output (independent of ASH's `--verbose`) |
| **Output Format** | Always SARIF | Required by ASH for result aggregation |
| **Output Directory** | `.ash/ash_output/scanners/ferret-scan/` | Follows ASH conventions |
| **Offline Mode** | `ASH_OFFLINE=true` | Respects ASH offline mode environment variable |
| **Suppressions** | `.ash/suppressions.yaml` | Managed centrally by ASH |

### Unsupported Options

The following ferret-scan CLI options are **NOT supported** in the ASH plugin and will raise an error if used:

| Option | Reason |
|--------|--------|
| `format`, `output_format` | ASH requires SARIF format. Use ASH reporter plugins for other formats. |
| `debug` | Use `ferret_debug: true` instead. Bare `debug` is blocked to avoid confusion with ASH's `--debug`. |
| `verbose` | Use `ferret_verbose: true` instead. Bare `verbose` is blocked to avoid confusion with ASH's `--verbose`. |
| `web`, `port` | Web server mode is not applicable for ASH integration. |
| `enable_redaction`, `redaction_*`, `memory_scrub` | Redaction is post-processing, not scanning. |
| `generate_suppressions`, `show_suppressed`, `suppressions_file` | ASH manages suppressions centrally. |
| `extract_text` | Text extraction mode is a utility, not scanning. |
| `preprocess_only` | Outputs extracted text and exits — produces no SARIF results. |
| `pre_commit_mode` | ASH manages output formatting and exit codes centrally; use ASH's own pre-commit hook. |
| `list_profiles` | Only prints available profiles and exits — produces no scan results. |

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

### Note: `API_KEY_OR_SECRET` false positives (SECRETS check)

ferret-scan's `SECRETS` check includes a generic `API_KEY_OR_SECRET` detector that
matches on the *name* of an assignment when the name is a secret keyword (`session`,
`token`, `secret`, `password`, `api_key`, …) — **regardless of the value**. So typed
code and config such as a `session` field on a generated model, a `session` local, or a
Terraform local named `manage_auth_secret` can be flagged at HIGH confidence even though
no credential is present.

This detector **cannot be turned off in ferret-scan's config** — the tool only supports
`disabled_types` for the `INTELLECTUAL_PROPERTY` check, not `SECRETS`. The plugin
therefore keeps the detector enabled (so real secrets are still found) and expects you to
manage false positives with ASH's own controls:

- **Suppress** the false positives with a path-scoped ASH suppression:
  ```yaml
  global_settings:
    suppressions:
      - path: path/to/generated_or_test_file.py
        rule_id: API_KEY_OR_SECRET
        reason: "False positive — variable/field name matches the secret-keyword heuristic, not a credential"
  ```
- Or **exclude** whole noise directories via the plugin's `exclude_patterns`.
- Or scope the `checks` option to omit `SECRETS` if you do not need secret detection.

See `DEVELOPMENT.md` → "Design decision: API_KEY_OR_SECRET stays ENABLED" for the full
rationale.

## Configuration

### Basic Configuration

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      confidence_levels: "high"       # high, medium, low, or combinations
      checks: "CREDIT_CARD,SECRETS,SSN,PASSPORT"  # or "all" for everything
      recursive: true
      use_default_config: false       # disable bundled config to let CLI args take effect
      exclude_patterns:
        - ".venv"
        - ".git"
        - "node_modules"
```

> **Note on `use_default_config`**: The bundled `ferret-config.yaml` is a comprehensive
> reference config. `use_default_config` controls whether its validator/profile settings
> (IP `internal_urls`, social-media patterns, named profiles) are loaded — it does **not**
> affect excludes: ferret-scan's CLI flags take precedence over the config file's defaults,
> so ASH's `exclude_patterns` and `--recursive` are honoured either way (verified against
> v2.4.5). Set `false` to rely only on ferret-scan's built-in defaults plus your explicit
> ASH options; keep it `true` (or use `profile`) to pick up the bundled validator patterns.

> **`use_default_config` and `profile` are the operator's**: both change what is
> reported (with ferret-scan 2.5.3 on ASH's test files, the bundled config reported 111
> findings with no profile, 30 with `quick` and none with six of its profiles), so a
> config file inside the scanned tree, or one an MCP client delivered, does not set
> them. Set them with `--config-overrides` or in a config file outside the tree. See
> "Settings a repository's config cannot choose" in the configuration guide.

> **Note on `exclude_patterns`**: Ferret-scan's `--exclude` matches each pattern with
> Go's `filepath.Match` glob (`*`, `?`, `[abc]` — `**` globstar is **not** supported)
> **and** as a plain substring of the full path. So `.venv` excludes any path containing
> "`.venv`", and `*.log` matches log files; use `.venv` rather than `.venv/**`. Because of
> the substring branch, a short bare token (e.g. `test`) can over-exclude any path
> containing it. Patterns are passed as a single comma-separated `--exclude` value.

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `confidence_levels` | string | `"all"` | Confidence levels: `high`, `medium`, `low`, or combinations |
| `checks` | string | `"all"` | Specific checks to run (comma-separated) |
| `recursive` | bool | `true` | Recursively scan directories |
| `config_file` | string | `null` | Path to custom Ferret YAML config file |
| `use_default_config` | bool | `true` | Use the default config bundled with this plugin. Set by the operator only (see above) |
| `profile` | string | `null` | Profile name from config file. Set by the operator only (see above) |
| `exclude_patterns` | list | `[]` | Patterns to exclude from scanning (directory names or file patterns, e.g., `.venv`, `*.log`) |
| `show_match` | bool | `false` | Display matched text in ferret-scan's own output (see [show_match](#show_match) above) |
| `enable_preprocessors` | bool | `true` | Enable text extraction from documents |
| `finding_limit` | int | `0` | Max findings ferret-scan emits (`--limit`). `0` = unlimited. ASH defaults to `0` because ferret-scan's own default of `200` silently truncates large scans. |
| `fail_on_incomplete` | bool | `false` | Pass `--fail-on-incomplete` so ferret-scan exits 3 when a file could not be fully scanned (findings may be missing). ASH still returns the partial SARIF and records the invocation as unsuccessful/incomplete. |
| `respect_gitignore` | bool | `false` | Pass `--respect-gitignore` to honor `.gitignore`. Off by default — `.gitignore` often hides high-value files (`.env`, `*.pem`) a sensitive-data scan should see. |
| `disable_ip_types` | string | `null` | Comma-separated `INTELLECTUAL_PROPERTY` sub-types to skip (`--disable-ip-types`): `copyright,patent,trademark,trade_secret,internal_url`. |
| `explain` | bool | `false` | Pass `--explain` for an offline per-finding rationale + verdict + drafted suppression reason. No data leaves the host. |
| `validator_budget` | string | `null` | Per-validator time budget (`--validator-budget`), e.g. `SSN=500ms,all=2m`. Over-budget validators stop and mark the scan incomplete. |
| `max_live_bytes` | string | `null` | Cap on extracted content held in memory (`--max-live-bytes`), e.g. `256MB`/`1GB`. Bounds peak memory on constrained hosts. |
| `tool_version` | string | `null` | Version constraint for ferret-scan (e.g., `>=1.0.0,<2.0.0`) |
| `skip_version_check` | bool | `false` | Skip version compatibility check (use with caution) |

### Default Configuration

This plugin includes a default `ferret-config.yaml` that is automatically used when no custom config is specified. The default config includes:

- Comprehensive validator patterns for intellectual property detection
- Social media platform detection patterns
- Pre-configured profiles for common use cases (quick, thorough, ci, security-audit, etc.)
- AWS/Amazon internal URL patterns for IP detection

### Overriding the Default Config

You can override the default configuration in several ways:

#### Option 1: Provide a custom config file path

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      config_file: "/path/to/your/custom-ferret.yaml"
```

#### Option 2: A config file in your source directory is not used

A config file inside the scanned tree is not passed to ferret-scan, whether
`config_file` names it or the plugin finds it by name (`ferret.yaml`,
`ferret.yml`, `.ferret.yaml`, `.ferret.yml`, `.ash/ferret.yaml` or
`.ash/ferret-scan.yaml` in the source directory). The bundled config is used
instead, and the scan's warnings name the file. Put the file outside the scanned
tree and name it with `config_file`.

#### Option 3: Disable the default config entirely

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      use_default_config: false  # Use ferret-scan's built-in defaults only
```

### Advanced Configuration

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      confidence_levels: "high,medium"
      checks: "CREDIT_CARD,SECRETS,SSN,PASSPORT"
      recursive: true
      profile: "security-audit"  # Use predefined profile from config
      config_file: "/etc/ash/ferret-config.yaml"  # Custom config file, outside the scanned tree
      # show_match: false  # Keep disabled to avoid logging sensitive data
      enable_preprocessors: true  # Extract text from PDFs, Office docs
      exclude_patterns:
        - "*.log"
        - "node_modules"
        - "vendor"
```

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

### Available Checks

The authoritative list for your installed version is `ferret-scan --help checks` — do not
hardcode it, as ferret-scan adds detectors between releases. As of v2.4.5 through v2.5.2 the checks are:

- `BANK_ACCOUNT` - Bank account / IBAN / routing numbers
- `CLOUD_RESOURCES` - Cloud resource identifiers (AWS ARNs, Azure/GCP/OCI/IBM/Alibaba IDs)
- `CREDIT_CARD` - Credit card numbers
- `DATE_OF_BIRTH` - Dates of birth
- `DRIVERS_LICENSE` - Driver's license numbers (state formats)
- `EMAIL` - Email addresses
- `INTELLECTUAL_PROPERTY` - Patents, trademarks, copyrights (internal-URL detection requires config)
- `IP_ADDRESS` - IPv4 and IPv6 addresses
- `MEDICAL_ID` - Medical / health identifiers (PHI)
- `METADATA` - Document, image, audio, and video metadata
- `OTP` - One-time-passcode / two-factor secrets
- `PASSPORT` - Passport numbers
- `PERSON_NAME` - Person names
- `PHONE` - Phone numbers
- `PHYSICAL_ADDRESS` - Physical / postal addresses
- `SECRETS` - API keys, tokens, passwords
- `SOCIAL_MEDIA` - Social media profiles
- `SSN` - Social Security Numbers
- `VIN` - Vehicle Identification Numbers

### Available Profiles (in default config)

- `quick` - Fast security check (high confidence only, no preprocessors)
- `thorough` - All confidence levels with text extraction
- `ci` - CI/CD pipeline profile (high+medium confidence, recursive)
- `precommit` - Pre-commit hook optimized (critical data types, concise output)
- `security-audit` - Security team scanning (secrets, PCI, identity focused)
- `comprehensive` - Complete analysis with all features enabled
- `credit-card` - PCI compliance focused
- `passport` - Identity verification focused
- `person-name` - Person name detection focused
- `social-media` - Social media profile and handle detection
- `intellectual-property` - IP detection focused
- `silent` - Minimal output for automation

## Creating a Custom Config File

To create your own config file, you can:

1. Copy the default config from the plugin:
   ```bash
   cp $(python -c "import automated_security_helper.plugin_modules.ash_ferret_plugins as p; print(p.__path__[0])")/ferret-config.yaml ./my-ferret-config.yaml
   ```

2. Or create a minimal config that only overrides what you need:
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

## Output

The plugin outputs results in SARIF format, which is automatically aggregated with other ASH scanner results.

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

## Example Usage

```bash
# Run ASH with Ferret Scan enabled
uv run ash --source-dir /path/to/code

# Run only Ferret Scan
uv run ash --source-dir /path/to/code --scanners ferret-scan

# Run with ferret-scan's own debug output
uv run ash --source-dir /path/to/code --scanners ferret-scan -o ferret_debug=true

# Run with ferret-scan's own verbose output
uv run ash --source-dir /path/to/code --scanners ferret-scan -o ferret_verbose=true

# Run with a custom config file
uv run ash --source-dir /path/to/code \
    --scanners ferret-scan \
    --config-overrides "scanners.ferret-scan.options.config_file=/path/to/custom.yaml"
```

## Error Handling

### Unsupported Option Errors

If you try to use bare `debug` instead of `ferret_debug`, you'll see a clear error:

```
ValueError: Unsupported option 'debug' in ferret-scan plugin configuration. 
Use 'ferret_debug: true' instead. Bare 'debug' is blocked to avoid confusion with ASH's --debug flag.
```

### Common Issues

**ferret-scan binary not found:**
```bash
# Install ferret-scan
pip install ferret-scan

# Verify installation
ferret-scan --version
```

**Empty directory warnings:**
The plugin will skip scanning if the target directory is empty or doesn't exist, logging an appropriate warning message.

## License

Apache-2.0
