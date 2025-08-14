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
      tool_version: null  # Version constraint (e.g., '>=1.125.0')
      install_timeout: 300  # Timeout in seconds for tool installation

  detect-secrets:
    enabled: true
    options:
      exclude_lines: []

  checkov:
    enabled: true
    options:
      framework: ['all']
      tool_version: null  # Version constraint (e.g., '>=3.2.0,<4.0.0')
      install_timeout: 300  # Timeout in seconds for tool installation

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
      # Note: Bandit is automatically installed via UV tool management
      # with version constraint >=1.7.0 for enhanced SARIF support
```

If you have been using Bandit separately and have an existing configuration file you would like to use with ASH, ASH can automatically discover and use it. ASH will automatically search your current directory and the ```.ash``` directory for a file named ```.bandit```, ```.bandit.toml```, or ```.bandit.yaml```, and will use the settings found in the file if it is detected. For more details on using a Bandit configuration file, refer to the Bandit [documentation](https://bandit.readthedocs.io/en/latest/config.html).

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
      tool_version: null  # Version constraint (e.g., '>=1.125.0')
      install_timeout: 300  # Timeout in seconds for tool installation
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

If you have been using detect-secrets separately and have an existing baseline file you would like to use with ASH, ASH can automatically use it. ASH automatically searches your current directory and the ```.ash``` directory for a ```.secrets.baseline``` file. For more details on baseline files, refer to the detect-secrets [documentation](https://github.com/Yelp/detect-secrets/tree/master).

### Checkov

```yaml
scanners:
  checkov:
    enabled: true
    options:
      framework: ['all']  # Frameworks to scan
      skip_frameworks: []  # Frameworks to exclude
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
      config_file: .grype.yaml # Specific path to grype configuration file
      exclude: ['tests'] # List of files and directories to exclude from scans
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