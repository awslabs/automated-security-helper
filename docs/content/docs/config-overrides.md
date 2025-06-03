# Configuration Overrides

ASH supports runtime configuration overrides through the `--config-overrides` CLI parameter. This allows you to modify configuration values without editing the configuration file.

## Basic Usage

```bash
ash scan --config-overrides 'reporters.markdown.options.include_detailed_findings=true'
```

You can specify multiple overrides by using the parameter multiple times:

```bash
ash scan \
  --config-overrides 'reporters.cloudwatch-logs.options.aws_region=us-west-2' \
  --config-overrides 'global_settings.severity_threshold=LOW'
```

## Supported Value Types

The configuration override system automatically converts values to appropriate types:

- **Strings**: `'key=value'`
- **Numbers**: `'key=123'` or `'key=3.14'`
- **Booleans**: `'key=true'` or `'key=false'`
- **Null**: `'key=null'` or `'key=none'`
- **Lists**: `'key=[item1, item2, item3]'` or `'key=["item1", "item2", "item3"]'`
- **Dictionaries**: `'key={"subkey1": "value1", "subkey2": "value2"}'`

## Advanced Features

### List Append Mode

You can append to existing lists by adding a `+` at the end of the key path:

```bash
# Add a new plugin module without replacing existing ones
ash scan --config-overrides 'ash_plugin_modules+=["my_custom_plugin_module"]'
```

### Complex Structures

For complex structures, you can use JSON syntax:

```bash
# Add a new ignore path
ash scan --config-overrides 'global_settings.ignore_paths+=[{"path": "build/", "reason": "Generated files"}]'
```

### Examples

1. Change severity threshold:
   ```bash
   ash scan --config-overrides 'global_settings.severity_threshold=LOW'
   ```

2. Enable a specific scanner:
   ```bash
   ash scan --config-overrides 'scanners.bandit.enabled=true'
   ```

3. Configure AWS region for CloudWatch Logs reporter:
   ```bash
   ash scan --config-overrides 'reporters.cloudwatch-logs.options.aws_region=us-west-2'
   ```

4. Replace the list of plugin modules:
   ```bash
   ash scan --config-overrides 'ash_plugin_modules=["automated_security_helper.plugin_modules.ash_aws_plugins"]'
   ```

5. Add a plugin module to the existing list:
   ```bash
   ash scan --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.custom_plugin"]'
   ```

6. Configure multiple scanner options:
   ```bash
   ash scan \
     --config-overrides 'scanners.bandit.options.confidence_level=high' \
     --config-overrides 'scanners.bandit.options.ignore_nosec=true'
   ```

## Configuration Management

ASH provides several ways to manage your configuration:

### Configuration File

ASH uses YAML configuration files by default. The standard location is `.ash/.ash.yaml` in your project directory. You can also use JSON format with `.ash/.ash.json`.

A basic configuration file looks like this:

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

### JSON Schema Support

ASH provides a JSON schema for configuration files, which enables validation and auto-completion in compatible editors. Add this line at the top of your YAML file:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/beta/automated_security_helper/schemas/AshConfig.json
```

### Configuration Commands

ASH provides several commands to manage your configuration:

#### Initialize a Configuration

Create a new configuration file:

```bash
ash config init
```

This creates a default configuration file at `.ash/.ash.yaml`.

#### View Current Configuration

View the current configuration:

```bash
ash config get
```

You can also apply overrides when viewing the configuration:

```bash
ash config get --config-overrides 'scanners.bandit.enabled=false'
```

#### Update Configuration

Update an existing configuration file:

```bash
ash config update --set 'scanners.bandit.enabled=false' --set 'global_settings.severity_threshold=LOW'
```

You can use the same syntax as `--config-overrides`, including list operations:

```bash
# Add a new ignore path
ash config update --set 'global_settings.ignore_paths+=[{"path": "build/", "reason": "Generated files"}]'

# Preview changes without writing to file
ash config update --set 'scanners.semgrep.enabled=false' --dry-run
```

#### Validate Configuration

Validate your configuration file:

```bash
ash config validate
```

You can also validate with overrides:

```bash
ash config validate --config-overrides 'scanners.bandit.options.confidence_level=high'
```

### Custom Plugins

You can add custom plugins to ASH by specifying them in the `ash_plugin_modules` list:

```yaml
ash_plugin_modules:
  - my_custom_plugin_module
```

Or using the override:

```bash
ash scan --config-overrides 'ash_plugin_modules+=["my_custom_plugin_module"]'
```

## Notes

- Configuration overrides are applied after loading the configuration file
- Overrides work with both default and explicit configurations
- If validation fails after applying overrides, the original configuration will be used
- For complex values, use valid JSON syntax
- Environment variables can be referenced in YAML configuration files using `!ENV ${VAR_NAME:default_value}` syntax
