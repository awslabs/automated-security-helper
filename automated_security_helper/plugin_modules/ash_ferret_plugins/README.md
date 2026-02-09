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
# Via pip (recommended)
pip install ferret-scan

# Or build from source
git clone https://github.com/awslabs/ferret-scan.git
cd ferret-scan
make build
```

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
      confidence_levels: "all"
      checks: "all"
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
| **Debug Mode** | `ash --debug` | Not passed to ferret-scan; ASH manages its own logging |
| **Verbose Mode** | `ash --verbose` | Not passed to ferret-scan; ASH manages its own logging |
| **Output Format** | Always SARIF | Required by ASH for result aggregation |
| **Output Directory** | `.ash/ash_output/scanners/ferret-scan/` | Follows ASH conventions |
| **Offline Mode** | `ASH_OFFLINE=true` | Respects ASH offline mode environment variable |
| **Suppressions** | `.ash/suppressions.yaml` | Managed centrally by ASH |

### Unsupported Options

The following ferret-scan CLI options are **NOT supported** in the ASH plugin and will raise an error if used:

| Option | Reason |
|--------|--------|
| `format`, `output_format` | ASH requires SARIF format. Use ASH reporter plugins for other formats. |
| `debug` | Not applicable; ASH manages its own logging independently. |
| `verbose` | Not applicable; ASH manages its own logging independently. |
| `web`, `port` | Web server mode is not applicable for ASH integration. |
| `enable_redaction`, `redaction_*`, `memory_scrub` | Redaction is post-processing, not scanning. |
| `generate_suppressions`, `show_suppressed`, `suppressions_file` | ASH manages suppressions centrally. |
| `extract_text` | Text extraction mode is a utility, not scanning. |

### Security Warning: show_match Option

⚠️ **Data Exfiltration Risk**: The `show_match` option causes ferret-scan to include the actual matched sensitive data (credit card numbers, SSNs, API keys, etc.) in the scan output. This creates significant security risks:

- **Log file exposure**: Matched sensitive data will appear in SARIF reports, CI/CD logs, and ASH output files
- **Accidental data leakage**: Reports shared with team members or uploaded to security dashboards may contain real sensitive data
- **Compliance violations**: Logging actual PII/PCI data may violate data protection regulations (GDPR, PCI-DSS, HIPAA)

**Recommendation**: Keep `show_match: false` (the default) in production environments. Only enable it temporarily for debugging in isolated, secure environments where log files are properly protected and purged.

## Configuration

### Basic Configuration

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      confidence_levels: "all"  # high, medium, low, or combinations
      checks: "all"             # or specific: CREDIT_CARD,EMAIL,SECRETS
      recursive: true
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `confidence_levels` | string | `"all"` | Confidence levels: `high`, `medium`, `low`, or combinations |
| `checks` | string | `"all"` | Specific checks to run (comma-separated) |
| `recursive` | bool | `true` | Recursively scan directories |
| `config_file` | string | `null` | Path to custom Ferret YAML config file |
| `use_default_config` | bool | `true` | Use the default config bundled with this plugin |
| `profile` | string | `null` | Profile name from config file |
| `exclude_patterns` | list | `[]` | Glob patterns to exclude |
| `show_match` | bool | `false` | ⚠️ Display matched text in findings (see security warning above) |
| `enable_preprocessors` | bool | `true` | Enable text extraction from documents |
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

#### Option 2: Place a config file in your source directory

The plugin searches for config files in this order:
1. Explicitly specified `config_file` path
2. `ferret.yaml` or `.ferret.yaml` in the source directory
3. `.ash/ferret.yaml` or `.ash/ferret-scan.yaml` in the source directory
4. Default config bundled with this plugin

Simply create a `ferret.yaml` or `.ferret.yaml` in your project root to override the defaults.

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
      config_file: "my-ferret-config.yaml"  # Custom config file
      # show_match: false  # Keep disabled to avoid logging sensitive data
      enable_preprocessors: true  # Extract text from PDFs, Office docs
      exclude_patterns:
        - "*.log"
        - "node_modules/**"
        - "vendor/**"
```

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

### Available Checks

- `CREDIT_CARD` - Credit card numbers
- `EMAIL` - Email addresses
- `INTELLECTUAL_PROPERTY` - Patents, trademarks, copyrights
- `IP_ADDRESS` - IPv4 and IPv6 addresses
- `METADATA` - Document and image metadata
- `PASSPORT` - Passport numbers
- `PERSON_NAME` - Person names
- `PHONE` - Phone numbers
- `SECRETS` - API keys, tokens, passwords
- `SOCIAL_MEDIA` - Social media profiles
- `SSN` - Social Security Numbers

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

# Run with debug mode (ASH-level logging only; not passed to ferret-scan)
uv run ash --source-dir /path/to/code --scanners ferret-scan --debug

# Run with verbose mode (ASH-level logging only; not passed to ferret-scan)
uv run ash --source-dir /path/to/code --scanners ferret-scan --verbose

# Run with a custom config file
uv run ash --source-dir /path/to/code \
    --scanners ferret-scan \
    --config-overrides "scanners.ferret-scan.options.config_file=/path/to/custom.yaml"
```

## Error Handling

### Unsupported Option Errors

If you try to use an unsupported option, you'll see a clear error message:

```
ValueError: Unsupported option 'debug' in ferret-scan plugin configuration. 
Debug mode is not applicable in ASH integration. ASH manages its own logging.
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
