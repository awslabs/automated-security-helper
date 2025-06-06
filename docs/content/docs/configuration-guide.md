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
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/beta/automated_security_helper/schemas/AshConfig.json
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
      file_path: 'src/example.py'  # File path (supports glob patterns)
      line_start: 10  # Optional starting line number
      line_end: 15  # Optional ending line number
      reason: 'False positive due to test mock'  # Reason for suppression
      expiration: '2025-12-31'  # Optional expiration date (YYYY-MM-DD)
    - rule_id: 'RULE-456'
      file_path: 'src/*.js'  # Glob pattern matching all JS files in src/
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
      # Converter-specific options
  archive:
    enabled: true
    options:
      # Converter-specific options
```

### Scanners Configuration

The `scanners` section configures security scanners:

```yaml
scanners:
  bandit:
    enabled: true
    options:
      confidence_level: high
      severity_level: medium

  semgrep:
    enabled: true
    options:
      rules: ['p/ci']

  detect-secrets:
    enabled: true
    options:
      exclude_lines: []

  checkov:
    enabled: true
    options:
      framework: ['all']

  cfn-nag:
    enabled: true
    options:
      profile_path: null

  cdk-nag:
    enabled: true
    options:
      nag_packs: ['AWS_SOLUTIONS']

  npm-audit:
    enabled: true
    options:
      audit_level: moderate

  grype:
    enabled: true
    options:
      severity: medium

  syft:
    enabled: true
    options:
      scope: squashed
```

### Reporters Configuration

The `reporters` section configures output report formats:

```yaml
reporters:
  markdown:
    enabled: true
    options:
      include_detailed_findings: true

  html:
    enabled: true
    options:
      include_detailed_findings: true

  json:
    enabled: true
    options:
      pretty_print: true

  csv:
    enabled: true
    options:
      include_all_fields: false

  sarif:
    enabled: true
    options:
      include_help_uri: true
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
      confidence_level: HIGH  # Options: LOW, MEDIUM, HIGH
      severity_level: medium  # Options: low, medium, high
      skip_tests: []  # List of test IDs to skip
      include_tests: []  # List of test IDs to include
```

### Semgrep

```yaml
scanners:
  semgrep:
    enabled: true
    options:
      rules: ['p/ci']  # Rulesets to use
      timeout: 300  # Timeout in seconds
      max_memory: 0  # Max memory in MB (0 = no limit)
      exclude_rules: []  # Rules to exclude
```

### Detect-Secrets

```yaml
scanners:
  detect-secrets:
    enabled: true
    options:
      exclude_lines: []  # Lines to exclude
      exclude_files: []  # Files to exclude
      custom_plugins: []  # Custom plugins to use
```

## Advanced Configuration

For advanced configuration options, refer to the [JSON Schema](https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/beta/automated_security_helper/schemas/AshConfig.json) that defines all available configuration options.

You can add this schema reference to your configuration file for editor autocompletion:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/beta/automated_security_helper/schemas/AshConfig.json
```