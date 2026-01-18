# CLI Reference

This page provides detailed information about the ASH command-line interface.

## Common Parameters

These parameters are available across multiple ASH commands:

| Parameter              | Description                                                | Default           | Environment Variable | Commands                             |
|------------------------|------------------------------------------------------------|-------------------|----------------------|--------------------------------------|
| `--source-dir`         | Path to the directory containing code to scan              | Current directory | `ASH_SOURCE_DIR`     | `scan`                               |
| `--output-dir`         | Path to store scan results                                 | `.ash/ash_output` | `ASH_OUTPUT_DIR`     | `scan`, `report`                     |
| `--config`, `-c`       | Path to ASH configuration file                             | `.ash/.ash.yaml`  | `ASH_CONFIG`         | `scan`, `config`, `plugin`           |
| `--config-overrides`   | Override configuration values (can be used multiple times) |                   |                      | `scan`, `config`, `plugin`, `report` |
| `--ash-plugin-modules` | List of Python modules to import containing ASH plugins    |                   | `ASH_PLUGIN_MODULES` | `scan`, `plugin`                     |
| `--mode`               | Execution mode: `local`, `container`, or `precommit`       | `local`           | `ASH_MODE`           | `scan`                               |
| `--debug`, `-d`        | Enable debug logging                                       | `False`           | `ASH_DEBUG`          | All commands                         |
| `--verbose`, `-v`      | Enable verbose logging                                     | `False`           | `ASH_VERBOSE`        | All commands                         |
| `--quiet`              | Suppress non-essential output                              | `False`           | `ASH_QUIET`          | All commands                         |
| `--no-color`           | Disable colored output                                     | `False`           | `ASH_NO_COLOR`       | All commands                         |
| `--oci-runner`, `-o`   | OCI runner to use                                          | `docker`          | `ASH_OCI_RUNNER`     | `scan` (container mode)              |

### Config Overrides Syntax

The `--config-overrides` parameter allows you to modify configuration values without editing the configuration file:

```bash
# Basic usage
ash --config-overrides 'scanners.bandit.enabled=true'

# Multiple overrides
ash \
  --config-overrides 'scanners.bandit.enabled=true' \
  --config-overrides 'global_settings.severity_threshold=MEDIUM'

# Append to lists
ash --config-overrides 'ash_plugin_modules+=["my_custom_plugin"]'

# Complex values using JSON syntax
ash --config-overrides 'global_settings.ignore_paths+=[{"path": "build/", "reason": "Generated files"}]'
```

## Core Commands

ASH v3 provides several core commands:

```
ash [command] [options]
```

### Available Commands

| Command        | Description                                         |
|----------------|-----------------------------------------------------|
| `scan`         | Run security scans on source code (default command) |
| `config`       | Manage ASH configuration                            |
| `plugin`       | Manage ASH plugins                                  |
| `report`       | Generate reports from scan results                  |
| `dependencies` | Install dependencies for ASH plugins                |
| `inspect`      | Inspect and analyze ASH outputs and reports         |
| `build-image`  | Build the ASH container image                       |

## Scan Command

The `scan` command is the primary command for running security scans. If no command is specified, ASH defaults to the `scan` command.

```bash
ash [options]
```

### Scan Options

| Option                        | Description                                             | Default               | Environment Variable    |
|-------------------------------|---------------------------------------------------------|-----------------------|-------------------------|
| `--source-dir`                | Path to the directory containing code to scan           | Current directory     | `ASH_SOURCE_DIR`        |
| `--output-dir`                | Path to store scan results                              | `.ash/ash_output`     | `ASH_OUTPUT_DIR`        |
| `--mode`                      | Execution mode: `local`, `container`, or `precommit`    | `local`               | `ASH_MODE`              |
| `--config`, `-c`              | Path to ASH configuration file                          | `.ash/.ash.yaml`      | `ASH_CONFIG`            |
| `--config-overrides`          | Override configuration values                           |                       |                         |
| `--ash-plugin-modules`        | List of Python modules to import containing ASH plugins |                       | `ASH_PLUGIN_MODULES`    |
| `--scanners`                  | Specific scanner names to run                           | All enabled scanners  | `ASH_SCANNERS`          |
| `--exclude-scanners`          | Specific scanner names to exclude                       | None                  | `ASH_EXCLUDED_SCANNERS` |
| `--output-formats`, `-f`      | Output formats (comma-separated). Available: text, flat-json, yaml, csv, html, dict, junitxml, markdown, sarif, asff, ocsf, cyclonedx, spdx, custom | Default formats       |                         |
| `--strategy`                  | Whether to run scanners in parallel or sequential       | `parallel`            |                         |
| `--log-level`                 | Set the log level                                       | `INFO`                |                         |
| `--fail-on-findings`          | Exit with non-zero code if findings are found           | From config           |                         |
| `--ignore-suppressions`       | Ignore all suppression rules and report all findings    | `False`               |                         |
| `--offline`                   | Run in offline mode (container mode only)               | `False`               |                         |
| `--offline-semgrep-rulesets`  | Semgrep rulesets for offline mode                       | `p/ci`                |                         |
| `--build/--no-build`, `-b/-B` | Whether to build the ASH container image                | `True`                |                         |
| `--run/--no-run`, `-r/-R`     | Whether to run the ASH container image                  | `True`                |                         |
| `--build-target`              | Container build target: `non-root` or `ci`              | `non-root`            |                         |
| `--oci-runner`, `-o`          | OCI runner to use                                       | `docker`              | `ASH_OCI_RUNNER`        |
| `--python-only/--full`        | Use only Python-based plugins                           | `False`               |                         |
| `--cleanup`                   | Clean up temporary files after scan                     | `False`               |                         |
| `--use-existing`              | Use existing results file                               | `False`               |                         |
| `--phases`                    | Phases to run: `convert`, `scan`, `report`, `inspect`   | `convert,scan,report` |                         |
| `--inspect`                   | Enable inspection of SARIF fields                       | `False`               |                         |

### Examples

```bash
# Basic scan in local mode (default)
ash

# Scan with container mode
ash --mode container

# Scan with specific source and output directories
ash --source-dir ./my-project --output-dir ./scan-results

# Scan with configuration overrides
ash --config-overrides 'scanners.bandit.enabled=true' --config-overrides 'global_settings.severity_threshold=MEDIUM'

# Scan with specific output formats
ash --output-formats flat-json,sarif,html,markdown

# Scan in precommit mode (faster)
ash --mode precommit

# Scan with custom plugins
ash --ash-plugin-modules my_custom_plugin_module
```

## Config Command

The `config` command allows you to manage ASH configuration.

```bash
ash config [subcommand] [options]
```

### Config Subcommands

| Subcommand | Description                         |
|------------|-------------------------------------|
| `init`     | Initialize a new configuration file |
| `get`      | Display current configuration       |
| `update`   | Update configuration values         |
| `validate` | Validate configuration file         |

### Config Options

| Option               | Description                                     | Default          | Environment Variable |
|----------------------|-------------------------------------------------|------------------|----------------------|
| `--config`, `-c`     | Path to configuration file                      | `.ash/.ash.yaml` | `ASH_CONFIG`         |
| `--config-overrides` | Override configuration values                   |                  |                      |
| `--set`              | Set configuration values (with `update`)        |                  |                      |
| `--dry-run`          | Preview changes without writing (with `update`) | `False`          |                      |
| `--force`            | Overwrite existing config file (with `init`)    | `False`          |                      |
| `--debug`, `-d`      | Enable debug logging                            | `False`          | `ASH_DEBUG`          |
| `--verbose`, `-v`    | Enable verbose logging                          | `False`          | `ASH_VERBOSE`        |
| `--no-color`         | Disable colored output                          | `False`          | `ASH_NO_COLOR`       |

### Examples

```bash
# Initialize a new configuration file
ash config init

# Display current configuration
ash config get

# Update configuration
ash config update --set 'scanners.bandit.enabled=true'

# Validate configuration
ash config validate
```

## Plugin Command

The `plugin` command allows you to manage ASH plugins.

```bash
ash plugin [subcommand] [options]
```

### Plugin Subcommands

| Subcommand | Description            |
|------------|------------------------|
| `list`     | List available plugins |

### Plugin Options

| Option                    | Description                            | Default          | Environment Variable |
|---------------------------|----------------------------------------|------------------|----------------------|
| `--include-plugin-config` | Include plugin configuration in output | `False`          |                      |
| `--ash-plugin-modules`    | Additional plugin modules to load      |                  | `ASH_PLUGIN_MODULES` |
| `--config`, `-c`          | Path to configuration file             | `.ash/.ash.yaml` | `ASH_CONFIG`         |
| `--config-overrides`      | Override configuration values          |                  |                      |
| `--debug`, `-d`           | Enable debug logging                   | `False`          | `ASH_DEBUG`          |
| `--verbose`, `-v`         | Enable verbose logging                 | `False`          | `ASH_VERBOSE`        |
| `--no-color`              | Disable colored output                 | `False`          | `ASH_NO_COLOR`       |

### Examples

```bash
# List all available plugins
ash plugin list

# List plugins with their configuration
ash plugin list --include-plugin-config

# List plugins including custom modules
ash plugin list --ash-plugin-modules my_custom_plugin_module
```

## Report Command

The `report` command generates reports from scan results.

```bash
ash report [options]
```

### Report Options

| Option               | Description                       | Default           | Environment Variable |
|----------------------|-----------------------------------|-------------------|----------------------|
| `--format`           | Report format to generate         | `markdown`        |                      |
| `--output-dir`       | Directory containing scan results | `.ash/ash_output` | `ASH_OUTPUT_DIR`     |
| `--config`, `-c`     | Path to configuration file        | `.ash/.ash.yaml`  | `ASH_CONFIG`         |
| `--config-overrides` | Override configuration values     |                   |                      |
| `--log-level`        | Set the log level                 | `INFO`            |                      |
| `--debug`, `-d`      | Enable debug logging              | `False`           | `ASH_DEBUG`          |
| `--verbose`, `-v`    | Enable verbose logging            | `False`           | `ASH_VERBOSE`        |
| `--no-color`         | Disable colored output            | `False`           | `ASH_NO_COLOR`       |

### Examples

```bash
# Generate a markdown report
ash report --format markdown

# Generate a JSON report
ash report --format json

# Generate a report from specific results
ash report --output-dir ./my-scan-results --format html
```

## Dependencies Command

The `dependencies` command installs dependencies for ASH plugins.

```bash
ash dependencies install [options]
```

### Dependencies Options

| Option                | Description                              | Default                      | Environment Variable |
|-----------------------|------------------------------------------|------------------------------|----------------------|
| `--bin-path`, `-b`    | Path to install binaries                 | `~/.ash/bin`                 | `ASH_BIN_PATH`       |
| `--plugin-type`, `-t` | Plugin types to install dependencies for | `converter,scanner,reporter` |                      |
| `--config`, `-c`      | Path to configuration file               | `.ash/.ash.yaml`             | `ASH_CONFIG`         |
| `--config-overrides`  | Override configuration values            |                              |                      |
| `--debug`, `-d`       | Enable debug logging                     | `False`                      | `ASH_DEBUG`          |
| `--verbose`, `-v`     | Enable verbose logging                   | `False`                      | `ASH_VERBOSE`        |
| `--no-color`          | Disable colored output                   | `False`                      | `ASH_NO_COLOR`       |

### Examples

```bash
# Install dependencies for all plugin types
ash dependencies install

# Install dependencies for scanners only
ash dependencies install --plugin-type scanner

# Install dependencies to a custom directory
ash dependencies install --bin-path ~/tools/ash-bin
```

## Inspect Command

The `inspect` command allows you to analyze ASH outputs and reports.

```bash
ash inspect [subcommand] [options]
```

### Inspect Subcommands

| Subcommand     | Description                                    |
|----------------|------------------------------------------------|
| `sarif-fields` | Analyze SARIF fields across different scanners |
| `findings`     | Interactive TUI to explore findings            |

### Inspect Options

| Option            | Description                       | Default           | Environment Variable |
|-------------------|-----------------------------------|-------------------|----------------------|
| `--output-dir`    | Directory containing scan results | `.ash/ash_output` | `ASH_OUTPUT_DIR`     |
| `--config`, `-c`  | Path to configuration file        | `.ash/.ash.yaml`  | `ASH_CONFIG`         |
| `--debug`, `-d`   | Enable debug logging              | `False`           | `ASH_DEBUG`          |
| `--verbose`, `-v` | Enable verbose logging            | `False`           | `ASH_VERBOSE`        |
| `--no-color`      | Disable colored output            | `False`           | `ASH_NO_COLOR`       |

### Examples

```bash
# Analyze SARIF fields
ash inspect sarif-fields

# Explore findings interactively
ash inspect findings
```

## Build-Image Command

The `build-image` command builds the ASH container image.

```bash
ash build-image [options]
```

### Build-Image Options

| Option                       | Description                                | Default    | Environment Variable |
|------------------------------|--------------------------------------------|------------|----------------------|
| `--build-target`             | Container build target: `non-root` or `ci` | `non-root` |                      |
| `--offline`                  | Build for offline use                      | `False`    |                      |
| `--offline-semgrep-rulesets` | Semgrep rulesets for offline mode          | `p/ci`     |                      |
| `--oci-runner`, `-o`         | OCI runner to use                          | `docker`   | `ASH_OCI_RUNNER`     |
| `--debug`, `-d`              | Enable debug logging                       | `False`    | `ASH_DEBUG`          |
| `--verbose`, `-v`            | Enable verbose logging                     | `False`    | `ASH_VERBOSE`        |
| `--no-color`                 | Disable colored output                     | `False`    | `ASH_NO_COLOR`       |

### Examples

```bash
# Build the default image
ash build-image

# Build for CI environments
ash build-image --build-target ci

# Build for offline use
ash build-image --offline --offline-semgrep-rulesets p/ci

# Build using a specific OCI runner
ash build-image --oci-runner podman
```

## Additional Environment Variables

ASH supports additional environment variables that don't directly map to command-line parameters:

| Variable                   | Description                            | Default                            |
|----------------------------|----------------------------------------|------------------------------------|
| `ASH_IMAGE_NAME`           | Name of ASH container image            | `automated-security-helper:latest` |
| `ASH_CONTAINER_WORK_DIR`   | Working directory inside the container | `/work`                            |
| `ASH_CONTAINER_SOURCE_DIR` | Source directory inside the container  | `/src`                             |
| `ASH_CONTAINER_OUTPUT_DIR` | Output directory inside the container  | `/out`                             |

## Exit Codes

ASH returns the following exit codes:

| Code | Description                                      |
|------|--------------------------------------------------|
| 0    | Success - No issues found                        |
| 1    | Scan execution error                             |
| 2    | Issues found with severity at or above threshold |
