# Configuration Guide

ASH v3 uses a YAML configuration file to control its behavior. This guide explains how to configure ASH for your project.

## Configuration File Location

By default, ASH looks for a configuration file in the following locations (in order):

1. `.ash/.ash.yaml`
2. `.ash/.ash.yml`
3. `.ash.yaml`
4. `.ash.yml`

You can also specify a custom configuration file path using the `--config` option:

```bash
ash --config /path/to/my-config.yaml
```

## Creating a Configuration File

The easiest way to create a configuration file is to use the `config init` command:

```bash
ash config init
```

This creates a default configuration file at `.ash/.ash.yaml` with recommended settings.

## Configuration Structure

The ASH configuration file has the following main sections:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json
project_name: my-project
global_settings:
  severity_threshold: MEDIUM
  ignore_paths: []
converters:
  # Converter plugins configuration
scanners:
  # Scanner plugins configuration
reporters:
  # Reporter plugins configuration
ash_plugin_modules: []
```

### Global Settings

The `global_settings` section controls general behavior:

```yaml
global_settings:
  # Minimum severity level to consider findings actionable
  # Options: CRITICAL, HIGH, MEDIUM, LOW, INFO
  severity_threshold: MEDIUM

  # Paths to ignore during scanning
  ignore_paths:
    - path: 'tests/test_data'
      reason: 'Test data only'
    - path: 'node_modules/'
      reason: 'Third-party dependencies'

  # Findings to suppress based on rule ID, file path, and line numbers
  suppressions:
    - rule_id: 'RULE-123'  # Scanner-specific rule ID
      path: 'src/example.py'  # File path (supports glob patterns)
      line_start: 10  # Optional starting line number
      line_end: 15  # Optional ending line number
      reason: 'False positive due to test mock'  # Reason for suppression
      expiration: '2025-12-31'  # Optional expiration date (YYYY-MM-DD)
```

Omitting `line_end` does **not** suppress only `line_start`. A suppression with
`line_start` and no `line_end` matches every finding from that line to the end of
the file, including findings introduced later. To suppress a single line, set
`line_end` to the same value as `line_start`:

```yaml
    - rule_id: 'RULE-123'
      path: 'src/example.py'
      line_start: 10
      line_end: 10  # Without this, lines 10 onwards are all suppressed
      reason: 'False positive due to test mock'
    - rule_id: 'RULE-456'
      path: 'src/*.js'  # Glob pattern matching all JS files in src/
      reason: 'Known issue, planned for fix in v2.0'

  # Whether to fail with non-zero exit code if actionable findings are found
  fail_on_findings: true
```

### Converters Configuration

The `converters` section configures file converters that transform files before scanning:

```yaml
converters:
  jupyter:
    enabled: true
    options:
      tool_version: null      # Version constraint for the conversion tool
      install_timeout: 300    # Seconds allowed for tool installation
  archive:
    enabled: true             # The archive converter exposes no options
```

### Scanners Configuration

The `scanners` section configures security scanners:

```yaml
scanners:
  bandit:
    enabled: true
    options:
      confidence_level: high     # all | low | medium | high (lowercase)
      severity_threshold: MEDIUM # ALL | LOW | MEDIUM | HIGH | CRITICAL (uppercase)

  semgrep:
    enabled: true
    options:
      config: 'p/ci'        # Ruleset, directory, or URL passed to --config
      exclude_rule: []      # Rule IDs to skip
      tool_version: null    # Version constraint (e.g., '>=1.125.0')
      install_timeout: 300  # Timeout in seconds for tool installation

  detect-secrets:
    enabled: true
    options:
      baseline_file: null   # Path to a detect-secrets baseline, relative to the source directory

  checkov:
    enabled: true
    options:
      frameworks: ['all']   # Note the plural; 'framework' is not a field
      skip_path: []         # Paths to skip, matched as regular expressions
      tool_version: null    # Version constraint (e.g., '>=3.2.0,<4.0.0')
      install_timeout: 300  # Timeout in seconds for tool installation

  cfn-nag:
    enabled: true
    options:
      severity_threshold: MEDIUM

  cdk-nag:
    enabled: true
    options:
      nag_packs:            # An object of per-pack booleans, not a list
        AwsSolutionsChecks: true
        HIPAASecurityChecks: false

  npm-audit:
    enabled: true
    options:
      severity_threshold: MEDIUM

  grype:
    enabled: true
    options:
      severity_threshold: MEDIUM

  syft:
    enabled: true
    options:
      exclude: []           # Paths to skip, matched as regular expressions
```

Two conventions differ between fields, and both are enforced: `severity_threshold`
accepts only uppercase (`ALL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), while bandit's
`confidence_level` accepts only lowercase (`all`, `low`, `medium`, `high`). The wrong
case is rejected with a validation error rather than coerced.

#### An unrecognized option is accepted and ignored

Scanner option models allow extra keys, so a misspelled or invented option does not
raise an error -- it is stored and never read. `severity_level: medium` on bandit
validates cleanly and changes nothing, because bandit reads `severity_threshold`.
When a setting appears to have no effect, check the option name against
[the built-in scanner reference](plugins/builtin/scanners.md) before assuming the
scanner ignored the value.

#### Bounding how long a scanner may run

Every scanner accepts `scan_timeout`, the number of seconds its tool invocation may
run before it is killed. The default is `1800` (30 minutes). Set it to `null` to leave
a scanner unbounded:

```yaml
scanners:
  semgrep:
    options:
      scan_timeout: 3600  # An hour for a large repository
  syft:
    options:
      scan_timeout: null  # No limit
```

A scanner killed by its timeout produces no results file, so the scan fails with an
error naming the scanner rather than silently reporting zero findings for it.
`scan_timeout` bounds the scan itself; `install_timeout` separately bounds tool
installation and defaults to `300`.

### Reporters Configuration

The `reporters` section configures output report formats:

```yaml
reporters:
  markdown:
    enabled: true
    options:
      include_detailed_findings: true

  html:
    enabled: true             # The HTML reporter exposes no options

  flat-json:                  # Note the hyphen; there is no 'json' reporter
    enabled: true
    options:
      include_metadata: true
      include_scanner_metrics: true

  csv:
    enabled: true             # The CSV reporter exposes no options

  sarif:
    enabled: true             # The SARIF reporter exposes no options

  github-ghas:
    enabled: true
    options:
      exclude_suppressed: true  # Exclude ASH-suppressed findings (default)
```

### Custom Plugin Modules

The `ash_plugin_modules` section allows you to specify custom Python modules containing ASH plugins:

```yaml
ash_plugin_modules:
  - my_custom_ash_plugins
  - another_plugin_module
```

## Validating Configuration

To validate your configuration file:

```bash
ash config validate
```

## Viewing Current Configuration

To view the current configuration:

```bash
ash config get
```

## Updating Configuration

To update configuration values:

```bash
ash config update --set 'scanners.bandit.enabled=true'
ash config update --set 'global_settings.severity_threshold=LOW'
```

## Configuration Overrides

You can override configuration values at runtime using the `--config-overrides` option:

```bash
# Enable a specific scanner
ash --config-overrides 'scanners.bandit.enabled=true'

# Change severity threshold
ash --config-overrides 'global_settings.severity_threshold=LOW'

# Append to a list
ash --config-overrides 'ash_plugin_modules+=["my_custom_plugin"]'

# Add a complex value
ash --config-overrides 'global_settings.ignore_paths+=[{"path": "build/", "reason": "Generated files"}]'
```

## Scanner-Specific Configuration

Each scanner has its own configuration options. Here are some examples:

### Bandit

```yaml
scanners:
  bandit:
    enabled: true
    options:
      confidence_level: high      # all | low | medium | high -- lowercase only
      severity_threshold: MEDIUM  # ALL | LOW | MEDIUM | HIGH | CRITICAL -- uppercase only
      ignore_nosec: false         # true scans lines carrying a '# nosec' comment anyway
      excluded_paths: []          # Paths to exclude, each with a reason
      config_file: null           # Explicit .bandit file, relative to the source directory
      scan_timeout: 1800          # Seconds before the bandit invocation is killed
      # Bandit is installed via UV tool management with the constraint
      # '>=1.7.0,<2.0.0' for SARIF support.
```

Selecting individual bandit tests is done in a bandit configuration file rather than
through ASH options: point `config_file` at one, or rely on the discovery described
below.

If you have been using Bandit separately and have an existing configuration file you would like to use with ASH, ASH can automatically discover and use it. ASH will automatically search your current directory and the ```.ash``` directory for a file named ```.bandit```, ```.bandit.toml```, or ```.bandit.yaml```, and will use the settings found in the file if it is detected. For more details on using a Bandit configuration file, refer to the Bandit [documentation](https://bandit.readthedocs.io/en/latest/config.html).

### Semgrep

```yaml
scanners:
  semgrep:
    enabled: true
    options:
      config: 'p/ci'        # Ruleset, directory of YAML rules, or URL, passed to --config
      exclude: ['*-converted.py', '*_report_result.txt']  # Paths to skip
      exclude_rule: []      # Rule IDs to skip (singular; 'exclude_rules' is not a field)
      severity: []          # Report only findings from rules of these severities
      metrics: 'auto'       # How usage metrics are sent to the Semgrep server
      offline: false        # Use locally cached rules only
      scan_timeout: 1800    # Seconds before the semgrep invocation is killed
      tool_version: null    # Version constraint (e.g., '>=1.125.0')
      install_timeout: 300  # Timeout in seconds for tool installation
```

### Detect-Secrets

```yaml
scanners:
  detect-secrets:
    enabled: true
    options:
      baseline_file: null   # Explicit .secrets.baseline path, relative to the source directory
      scan_timeout: 1800    # Seconds before the detect-secrets invocation is killed
```

Which plugins and filters run, and which findings are already accepted, live in the
detect-secrets baseline rather than in ASH options. Point `baseline_file` at one, or
rely on the discovery described below. The `scan_settings` option takes the same
structure as a baseline's own settings block if you would rather inline it.

If you have been using detect-secrets separately and have an existing baseline file you would like to use with ASH, ASH can automatically use it. ASH automatically searches your current directory and the ```.ash``` directory for a ```.secrets.baseline``` file. For more details on baseline files, refer to the detect-secrets [documentation](https://github.com/Yelp/detect-secrets/tree/master).

### Checkov

```yaml
scanners:
  checkov:
    enabled: true
    options:
      frameworks: ['all']  # Frameworks to scan (plural; 'framework' is not a field)
      skip_frameworks: []  # Frameworks to exclude
      skip_path: []  # Paths to skip, matched as regular expressions
      offline: false  # Run in offline mode
      additional_formats: ['cyclonedx_json']  # Additional output formats
      tool_version: null  # Version constraint (e.g., '>=3.2.0,<4.0.0')
      install_timeout: 300  # Timeout in seconds for tool installation
      # Note: Checkov is automatically downloaded and run via UV tool management
      # with version constraint >=3.2.0,<4.0.0 for enhanced stability
```

If you have been using Checkov separately and have an existing configuration file you would like to use with ASH, ASH can automatically discover and use it. ASH will automatically search your current directory and the ```.ash``` directory for a file named ```.checkov.yml``` or ```.checkov.yaml```, and will use the settings found in the file if it is detected. For more details on using a bandit configuration file, refer to the Checkov [documentation](https://github.com/bridgecrewio/checkov?tab=readme-ov-file#configuration-using-a-config-file).

### Grype

```yaml
scanners:
  grype:
    enabled: true
    options:
      config_file: .grype.yaml # Specific path to grype configuration file
      severity_threshold: MEDIUM # Options: ALL, LOW, MEDIUM, HIGH, CRITICAL
      offline: false # Run in offline mode
```

If you have been using Grype separately and have an existing configuration file you would like to use with ASH, ASH can automatically discover and use it. ASH will automatically search your current directory, the ```.ash``` directory, and the ```.grype``` directory for a file named ```.grype.yaml```. The current directory will also be searched for a ```grype.yaml``` file. If any of these files are found, ASH will use the settings found in the file. For more details on using a Grype configuration file, refer to the Grype [documentation](https://github.com/anchore/grype?tab=readme-ov-file#configuration).

### Syft

```yaml
scanners:
  syft:
    enabled: true
    options:
      config_file: .syft.yaml # Specific path to the Syft configuration file
      exclude:                # Each entry needs a path and a reason
        - path: 'tests'
          reason: 'Test fixtures are not shipped'
      additional_outputs: ["syft-json"] # List of additional output formats for Syft. Options:
      # "cyclonedx-json", "cyclonedx-xml","github-json", "spdx-json",
      # "spdx-tag-value", "syft-json", "syft-table", "syft-text"
```

If you have been using Syft separately and have an existing configuration file you would like to use with ASH, ASH can automatically discover and use it. ASH will automatically search your current directory for a file named ```.syft.yaml``` or ```.syft.yml```. If either of these files are found, ASH will use the settings found in the file. For more details on using a Syft configuration file, refer to the Syft [documentation](https://github.com/anchore/syft/wiki/Configuration).

## UV Tool Management

ASH v3 uses UV's tool isolation system to automatically manage scanner dependencies. This provides several benefits:

- **Automatic Installation**: Tools like Bandit, Checkov, and Semgrep are automatically installed when needed
- **Version Constraints**: ASH ensures compatible tool versions with sensible defaults:
  - **Bandit**: `>=1.7.0` (enhanced SARIF support and security fixes)
  - **Checkov**: `>=3.2.0,<4.0.0` (improved stability, avoiding potential breaking changes)
  - **Semgrep**: `>=1.125.0` (comprehensive rule support and performance improvements)
- **Isolation**: Tools run in isolated environments without affecting your project dependencies
- **Retry Logic**: Automatic retry with exponential backoff for network issues
- **Comprehensive Logging**: Detailed installation and execution logging for troubleshooting
- **Fallback Support**: If UV tool installation fails, ASH falls back to system-installed tools when available

### UV Tool Configuration Options

Each UV-managed scanner supports these configuration options:

```yaml
scanners:
  checkov:  # or bandit, semgrep
    enabled: true
    options:
      tool_version: ">=3.2.0,<4.0.0"  # Override default version constraint
      install_timeout: 300             # Installation timeout in seconds (default: 300)
```

### Environment Variables

Control UV tool behavior globally:

```bash
# Disable automatic tool installation (use pre-installed tools)
export ASH_OFFLINE=true

# Custom UV executable path (if needed)
export UV_EXECUTABLE=/custom/path/to/uv
```

### Troubleshooting UV Tool Issues

If you encounter UV tool installation issues:

1. **Check UV availability**: `uv --version`
2. **Enable verbose logging**: `ash --verbose` for detailed installation logs
3. **Use offline mode**: `ASH_OFFLINE=true` to skip installations
4. **Pre-install tools manually**:
   ```bash
   uv tool install bandit>=1.7.0
   uv tool install checkov>=3.2.0,<4.0.0
   uv tool install semgrep>=1.125.0
   ```
5. **Increase timeout** for slow networks:
   ```yaml
   scanners:
     checkov:
       options:
         install_timeout: 600  # 10 minutes
   ```

For more detailed information about UV tool management, see the [UV Tool Management Developer Guide](../developer-guide/uv-tool-management.md).
- **Flexible Version Management**: Scanners can optionally specify version constraints, with sensible defaults provided

### UV Tool Behavior

- **Bandit**: Automatically installed via `uv tool install bandit>=1.7.0` (default version constraint)
- **Checkov**: Automatically installed via `uv tool install checkov>=3.2.0,<4.0.0` (default version constraint) with fallback to `uv tool run`
- **Semgrep**: Automatically installed via `uv tool install semgrep>=1.125.0` (default version constraint) with fallback to `uv tool run`

### Version Constraint Configuration

Each UV-managed scanner can specify version constraints in two ways:

1. **Default Constraints**: Built-in version constraints ensure compatibility and stability
2. **Custom Constraints**: Override defaults via configuration options (where supported)

For scanners that support custom version constraints (like Semgrep and Checkov), you can specify them in your configuration:

```yaml
scanners:
  semgrep:
    options:
      tool_version: ">=1.130.0,<2.0.0"  # Custom version constraint
  checkov:
    options:
      tool_version: ">=3.3.0"  # Custom version constraint
```

### Troubleshooting UV Tool Issues

If you encounter issues with UV tool management:

1. **Check UV Installation**: Ensure UV is installed and available in your PATH
2. **Network Connectivity**: UV tool installation requires internet access
3. **Offline Mode**: Use `ASH_OFFLINE=true` to skip tool downloads and rely on pre-installed tools
4. **Manual Installation**: You can pre-install tools manually if needed:
   ```bash
   uv tool install bandit>=1.7.0
   uv tool install checkov>=3.2.0,<4.0.0
   uv tool install semgrep>=1.125.0
   ```

## Advanced Configuration

For advanced configuration options, refer to the [JSON Schema](https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json) that defines all available configuration options.

You can add this schema reference to your configuration file for editor autocompletion:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json
```
