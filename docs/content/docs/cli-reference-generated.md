# CLI Reference (Auto-Generated)

This document is auto-generated from the ASH CLI source code using introspection.
Do not edit manually. Regenerate with: `uv run python scripts/generate_cli_docs.py`

## Commands

### `ash scan`

Runs an ASH scan against the source-dir, outputting results to the output-dir.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--source-dir` | str |  | ASH_SOURCE_DIR | The source directory to scan |
| `--output-dir` | str |  | ASH_OUTPUT_DIR | The directory to output results to |
| `--scanners` | List[str] |  | ASH_SCANNERS | Specific scanner names to run. Defaults to all scanners. |
| `--exclude-scanners` | List[str] |  | ASH_EXCLUDED_SCANNERS | Specific scanner names to exclude from running. Takes precedence over scanners parameter. |
| `--ash-plugin-modules` | List[str] |  | ASH_PLUGIN_MODULES | List of Python modules to import containing ASH plugins and/or event subscribers. These are loaded in addition to the default modules. |
| `--config-overrides` | List[str] |  |  | Configuration overrides specified as key-value pairs (e.g., 'reporters.cloudwatch-logs.options.aws_region=us-west-2'). Supports lists with [item1,item2], append mode with key+=[value], and JSON syntax. See docs/config-overrides.md |
| `--offline` | bool | False |  | Run scan in offline/airgapped mode (skips NPM/PNPM/Yarn Audit checks). IMPORTANT: Online access is needed when building ASH to prepare it for usage during a scan! If selecting Offline while performing a build, the ASH container image will be built in offline mode and any typically online-only dependencies like downloadable tool vulnerability databases will be cached in the image itself before publishing for scan usage. |
| `--offline-semgrep-rulesets` | str | `p/ci` |  | Specify Semgrep rulesets for use in ASH offline mode |
| `--strategy` | enum(sequential, parallel) | `parallel` |  | Whether to run scanners in parallel or sequential |
| `-p/-P` | bool | True |  | Show progress of each job live in the console. Defaults to True. |
| `--output-format`, `--formats`, `--format`, `-f` | List[str] |  |  | The output formats to use (comma-separated). Available formats: aggregated, text, flat-json, yaml, csv, html, dict, junitxml, markdown, sarif, asff, ocsf, cyclonedx, spdx, custom |
| `--cleanup` | bool | False |  | Clean up 'converted' directory and other temporary files after scan completes. Defaults to False. Note: Scans will always clean up existing files in the output directory before a new scan starts. This parameter only affects the cleanup of the temporary work directory after a scan has completed, typically for inspection of temporary artifacts. |
| `--phases` | List[enum(convert, scan, report, inspect)] |  |  | The phases to run. Defaults to all phases except inspect. |
| `--inspect` | bool | False |  | Enable inspection of SARIF fields after running. This adds the inspect phase to the execution. |
| `--use-existing` | bool | False |  | Use an existing ash_aggregated_results.json file in the output-dir. If True, the scan phase will be skipped and reports will be generated from this file. |
| `--version` | bool | False |  | Prints version number |
| `--mode` | enum(precommit, container, local) | `RunMode.local` | ASH_MODE | Execution mode preset. 'precommit' enables python-based plugins only and simplified output. 'container' runs non-Python plugins in a container. 'local' (default) runs everything in the local Python process. |
| `--python-based-scanners-only/--all-enabled-scanners`, `--python-based-plugins-only/--all-enabled-plugins` | bool | False |  | Exclude execution of any plugins or tools that have depencies external to Python. |
| `--show-summary` | bool | True |  | Show metrics table and results summary |
| `--quiet` | bool | False |  | Hide all log output |
| `--log-level` | enum(QUIET, SIMPLE, ERROR, INFO, ...) | `AshLogLevel.INFO` |  | Set the log level. |
| `-c` | str |  | ASH_CONFIG | The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: ['.ash.yml', '.ash.yaml', '.ash.json', 'ash.yml', 'ash.yaml', 'ash.json']. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH. |
| `-v` | bool | False |  | Enable verbose logging |
| `-d` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |
| `--fail-on-findings` | bool |  |  | Enable/disable throwing non-successful exit codes if any actionable findings are found. Defaults to unset, which prefers the configuration value. If this is set directly, it takes precedence over the configuration value. |
| `--simple` | bool | False |  | Simplified output mode with minimal logging |
| `--ignore-suppressions` | bool | False |  | Ignore all suppression rules and report all findings regardless of suppression status. |
| `--min-severity` | str | `low` |  | Minimum severity to trigger non-zero exit code (critical, high, medium, low, none). 'critical' and 'high' are equivalent because SARIF does not distinguish them. Findings below this threshold are still reported but don't affect the exit code. |
| `--compact-report` | bool | False |  | Produce a shorter markdown report suitable for PR comments. Omits the severity legend, scan metadata, footer, and rows for scanners that were skipped or had zero findings. |
| `--changed-files-only` | bool | False | ASH_CHANGED_FILES_ONLY | Limit the scan to files changed between the base branch and HEAD. Useful in CI to scan only PR changes. Falls back to a full scan when git is unavailable. |
| `--base-ref` | str | `origin/main` | ASH_BASE_REF | Git ref to diff against when --changed-files-only is set. |
| `-b/-B` | bool | True |  | Whether to build the ASH container image |
| `-r/-R` | bool | True |  | Whether to run the ASH container image |
| `--force` | bool | False |  | Force rebuild of the ASH container image |
| `--oci`, `--runner`, `-o` | str |  | OCI_RUNNER | Use the specified OCI runner instead of docker to run the containerized tools |
| `--build-target` | enum(non-root, ci) |  |  | Specify the target stage of the ASH image to build |
| `-u` | str |  |  | UID to use for the container user |
| `-g` | str |  |  | GID to use for the container user |
| `--ash-revision-to-install` | str |  |  | ASH branch or tag to install in the container image for usage during containerized scans |
| `--custom-containerfile` | str |  |  | Path to a custom container definition (e.g. Dockerfile) that you would like to build *after* the ASH container image builds. This is typically used when building a custom container image for ASH and including custom tooling that ASH does not come with by default. The fully qualified image name for the ASH image is passed in as the `ASH_BASE_IMAGE` build-arg so you can use it as a base. IMPORTANT: When a custom_containerfile path is provided, the build-target is set to `ci` so the container run-as configuration is not shifted to the non-root user. If you are using this parameter, you are responsible for securing your final container as appropriate. |
| `--custom-build-arg` | List[str] |  |  | Custom build arguments to pass to the container build |

### `ash build-image`

Builds the ASH container image then runs a scan with it.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `-f` | bool | False |  | Force rebuild of the ASH container image |
| `--oci`, `--runner`, `-r` | str |  | OCI_RUNNER | Use the specified OCI runner instead of docker to run the containerized tools |
| `--build-target` | enum(non-root, ci) | `BuildTarget.NON_ROOT` |  | Specify the target stage of the ASH image to build |
| `--offline-semgrep-rulesets` | str | `p/ci` |  | Specify Semgrep rulesets for use in ASH offline mode |
| `-u` | str |  |  | UID to use for the container user |
| `-g` | str |  |  | GID to use for the container user |
| `--ash-revision-to-install` | str |  |  | ASH branch or tag to install in the container image for usage during containerized scans |
| `--custom-containerfile` | str |  |  | Path to a custom container definition (e.g. Dockerfile) that you would like to build *after* the ASH container image builds. This is typically used when building a custom container image for ASH and including custom tooling that ASH does not come with by default. The fully qualified image name for the ASH image is passed in as the `ASH_BASE_IMAGE` build-arg so you can use it as a base. IMPORTANT: When a custom_containerfile path is provided, the build-target is set to `ci` so the container run-as configuration is not shifted to the non-root user. If you are using this parameter, you are responsible for securing your final container as appropriate. |
| `--custom-build-arg` | List[str] |  |  | Custom build arguments to pass to the container build |
| `--config-overrides` | List[str] |  |  | Configuration overrides specified as key-value pairs (e.g., 'reporters.cloudwatch-logs.options.aws_region=us-west-2') |
| `--offline` | bool | False |  | Run scan in offline/airgapped mode (skips NPM/PNPM/Yarn Audit checks). IMPORTANT: Online access is needed when building ASH to prepare it for usage during a scan! If selecting Offline while performing a build, the ASH container image will be built in offline mode and any typically online-only dependencies like downloadable tool vulnerability databases will be cached in the image itself before publishing for scan usage. |
| `--quiet` | bool | False |  | Hide all log output |
| `--log-level` | enum(QUIET, SIMPLE, ERROR, INFO, ...) | `AshLogLevel.INFO` |  | Set the log level. |
| `-c` | str |  | ASH_CONFIG | The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: ['.ash.yml', '.ash.yaml', '.ash.json', 'ash.yml', 'ash.yaml', 'ash.json']. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH. |
| `-v` | bool | False |  | Enable verbose logging |
| `-d` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |

### `ash report`

Generate a report from ASH scan results using the specified reporter plugin.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--report-format` | str | `markdown` |  | Report format to generate (reporter plugin name). Defaults to 'markdown'. Examples values: aggregated, text, flat-json, yaml, csv, html, dict, junitxml, markdown, sarif, asff, ocsf, cyclonedx, spdx, custom |
| `--output-dir` | str |  | ASH_OUTPUT_DIR | The directory to output results to |
| `--log-level` | enum(QUIET, SIMPLE, ERROR, INFO, ...) | `AshLogLevel.INFO` |  | Set the log level. |
| `-c` | str |  | ASH_CONFIG | The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: ['.ash.yml', '.ash.yaml', '.ash.json', 'ash.yml', 'ash.yaml', 'ash.json']. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH. |
| `--config-overrides` | List[str] |  |  | Configuration overrides specified as key-value pairs (e.g., 'reporters.cloudwatch-logs.options.aws_region=us-west-2') |
| `-v` | bool | False |  | Enable verbose logging |
| `-d` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |

### `ash mcp`

Start the ASH MCP server (Model Context Protocol).

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--log-level` | str | `INFO` |  | Log level |
| `--verbose` | bool | False |  | Verbose output |
| `--debug` | bool | False |  | Debug output |
| `--color` | bool | True |  | Enable color output |
| `--quiet` | bool | False |  | Quiet output |

### `ash get-genai-guide`

Download the ASH GenAI Integration Guide for use with AI assistants and LLMs.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--output`, `-o` | str | `ash-genai-guide.md` |  | Output path for the GenAI integration guide |
| `--from-github` | bool | False |  | Fetch from GitHub instead of local installation |
| `--branch`, `-b` | str | `main` |  | GitHub branch to fetch from when using --from-github (default: main) |

## Config Subcommands

### `ash config init`

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `-c` | str | `.ash/.ash.yaml` | ASH_CONFIG | The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: ['.ash.yml', '.ash.yaml', '.ash.json', 'ash.yml', 'ash.yaml', 'ash.json']. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH. |
| `-v` | bool | False |  | Enable verbose logging |
| `-d` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |
| `--force` | bool | False |  | Overwrite the config file if it already exists at the target path. |

### `ash config get`

**Arguments:**

| Argument | Type | Default | Env Var | Description |
|----------|------|---------|---------|-------------|
| `CONFIG_PATH` | str |  |  | The name of the config file to get. By default, ASH looks for the following config file names in the source directory of a scan: ['.ash.yml', '.ash.yaml', '.ash.json', 'ash.yml', 'ash.yaml', 'ash.json']. If  a different filename is specified, it must be provided when running ASH via the `--config` option or by setting the `ASH_CONFIG` environment variable. |

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--config-overrides` | List[str] | [] |  | Configuration overrides specified as key-value pairs (e.g., 'global_settings.severity_threshold=LOW') |
| `--verbose` | bool | False |  | Enable verbose logging |
| `--debug` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |

### `ash config update`

Update an existing configuration file with the specified modifications.

**Arguments:**

| Argument | Type | Default | Env Var | Description |
|----------|------|---------|---------|-------------|
| `CONFIG_PATH` | str |  |  | The path to the configuration file to update. By default, ASH looks for the following config file names in the source directory of a scan: ['.ash.yml', '.ash.yaml', '.ash.json', 'ash.yml', 'ash.yaml', 'ash.json']. |

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--modifications` | List[str] | [] |  | Configuration modifications specified as key-value pairs (e.g., 'global_settings.severity_threshold=LOW'). Supports lists with [item1,item2], append mode with key+=[value], and JSON syntax. |
| `--verbose` | bool | False |  | Enable verbose logging |
| `--debug` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |
| `--dry-run` | bool | False |  | Show changes without writing to file |

### `ash config validate-plugin-dependencies`

**Arguments:**

| Argument | Type | Default | Env Var | Description |
|----------|------|---------|---------|-------------|
| `CONFIG_PATH` | str |  |  | The name of the config file to create. By default, ASH looks for the following config file names in the source directory of a scan: ['.ash.yml', '.ash.yaml', '.ash.json', 'ash.yml', 'ash.yaml', 'ash.json']. If  a different filename is specified, it must be provided when running ASH via the `--config` option or by setting the `ASH_CONFIG` environment variable. |

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--config-overrides` | List[str] | [] |  | Configuration overrides specified as key-value pairs (e.g., 'global_settings.severity_threshold=LOW') |
| `--verbose` | bool | False |  | Enable verbose logging |
| `--debug` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |

### `ash config lint`

Lint an ASH configuration file for issues and optionally auto-fix them.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `-c` | str | `.ash/.ash.yaml` | ASH_CONFIG | The path to the configuration file to lint. By default, ASH looks for config files in .ash/.ash.yaml |
| `-o` | str |  |  | Path to the ASH output directory (for unused suppressions report). Defaults to .ash/ash_output |
| `--fix` | bool | False |  | Auto-fix fixable issues (internal fields, missing line_end, expired suppressions) |
| `--fix-unused` | bool | False |  | Comment out unused suppressions based on the last scan's unused suppressions report |
| `--yes`, `-y` | bool | False |  | Accept all changes without prompting. Useful for pre-commit hooks and CI/CD |
| `-v` | bool | False |  | Enable verbose logging |
| `-d` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |

### `ash config wizard`

Interactive configuration wizard.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `-c` | str | `.ash/.ash.yaml` | ASH_CONFIG | Path to read/write the configuration file. |
| `-v` | bool | False |  | Enable verbose logging |
| `-d` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |

### `ash config validate`

Validate an ASH configuration file for common issues.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `-c` | str | `.ash/.ash.yaml` | ASH_CONFIG | The path to the configuration file to validate. By default, ASH looks for config files in .ash/.ash.yaml |
| `-v` | bool | False |  | Enable verbose logging |
| `-d` | bool | False |  | Enable debug logging |

## Inspect Subcommands

### `ash inspect findings`

Interactively explore security findings.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--output-dir` | Path |  |  | Path to the output directory containing an ASH Aggregated Results JSON report file to analyze. |
| `--report-file` | str | `ash_aggregated_results.json` |  | Name of the report file to analyze. Defaults to 'ash_aggregated_results.json'. |

### `ash inspect sarif-fields`

Analyze SARIF fields across different scanners to understand their schema.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--sarif-dir` | str |  |  | Directory containing SARIF files to analyze |
| `--output-dir` | str |  |  | Directory to write output files |

## MCP Tools

The ASH MCP server exposes the following tools for integration with AI assistants via the Model Context Protocol.

### `cancel_scan`

Cancel a running scan and clean up its resources.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_id` | str | *required* | The scan ID to cancel |

### `check_installation`

Check if ASH is properly installed and ready to use.

### `get_scan_progress`

Get current progress and partial results for a running scan.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_id` | str | *required* | The scan ID returned from run_ash_scan |

### `get_scan_result_paths`

Get file paths for all scan result files by type.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `output_dir` | str | `.ash/ash_output` | Path to the scan output directory (absolute path recommended) |

### `get_scan_results`

Get final results for a completed scan with optional filtering.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `output_dir` | str | `.ash/ash_output` | Path to the scan output directory (absolute path recommended) |
| `filter_level` | str | `full` | Filter level for response data. Options: |
| `scanners` | str |  | Comma-separated list of scanner names to include (e.g., "bandit,semgrep"). |
| `severities` | str |  | Comma-separated list of severity levels to include (e.g., "critical,high,medium"). |
| `actionable_only` | bool | False | If True, exclude suppressed findings from results. This filters out findings |

### `get_scan_summary`

Get a lightweight summary of scan results without detailed findings.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `output_dir` | str | `.ash/ash_output` | Path to the scan output directory (absolute path recommended) |

### `list_active_scans`

List all active and recent scans with their current status.

### `run_ash_scan`

Start a security scan and return immediately.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `source_dir` | str |  | Path to the directory to scan. This should be the absolute path! |
| `severity_threshold` | str | `MEDIUM` | Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL) |
| `config_path` | str |  | Optional path to ASH configuration file |
| `clean_output` | bool | True | Whether to clean up existing output files before starting the scan |
