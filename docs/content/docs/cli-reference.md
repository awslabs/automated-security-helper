# CLI Reference

This page provides detailed information about the ASH command-line interface.

## Common Parameters

These parameters are available across multiple ASH commands:

| Parameter              | Description                                                | Default           | Environment Variable | Commands                             |
|------------------------|------------------------------------------------------------|-------------------|----------------------|--------------------------------------|
| `--source-dir`         | Path to the directory containing code to scan              | Current directory | `ASH_SOURCE_DIR`     | `scan`                               |
| `--version`            | Print the installed ASH version and exit                   |                   |                      | `scan`                               |
| `--ash-revision-to-install` | ASH branch or tag to install in the container image for usage during containerized scans | |  | `scan` |
| `--base-ref` | Git ref to diff against when --changed-files-only is set. | | `ASH_BASE_REF` | `scan` |
| `--changed-files-only` | Limit the scan to files changed between the base branch and HEAD. | | `ASH_CHANGED_FILES_ONLY` | `scan` |
| `--color` | Enable/disable colorized output | |  | `scan` |
| `--compact-report` | Produce a shorter markdown report suitable for PR comments. | |  | `scan` |
| `--container-gid` | GID to use for the container user | |  | `scan` |
| `--container-uid` | UID to use for the container user | |  | `scan` |
| `--custom-build-arg` | Custom build arguments to pass to the container build | |  | `scan` |
| `--custom-containerfile` | Path to a custom container definition (e.g. | |  | `scan` |
| `--formats` | The output formats to use (comma-separated). | |  | `scan` |
| `--min-severity` | Minimum severity to trigger non-zero exit code (critical, high, medium, low, none). | |  | `scan` |
| `--progress` | Show progress of each job live in the console. Defaults to True. | |  | `scan` |
| `--python-based-plugins-only` | Exclude execution of any plugins or tools that have depencies external to Python. | |  | `scan` |
| `--runner` | Use the specified OCI runner instead of docker to run the containerized tools | | `OCI_RUNNER` | `scan` |
| `--show-summary` | Show metrics table and results summary | |  | `scan` |
| `--simple` | Simplified output mode with minimal logging | |  | `scan` |
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

| Command           | Description                                                |
|-------------------|------------------------------------------------------------|
| `scan`            | Run security scans on source code (default command)        |
| `config`          | Manage ASH configuration                                   |
| `plugin`          | Manage ASH plugins                                         |
| `report`          | Generate reports from scan results                         |
| `dependencies`    | Install dependencies for ASH plugins                       |
| `inspect`         | Inspect and analyze ASH outputs and reports                |
| `build-image`     | Build the ASH container image                              |
| `get-genai-guide` | Download the GenAI Integration Guide for AI assistants     |
| `mcp`             | Start the Model Context Protocol (MCP) server for AI tools |

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
| `--workspace`                 | Path to a `.code-workspace` file, or `auto` to find the one in the current directory. Mutually exclusive with `--source-dir` | None | `ASH_WORKSPACE` |
| `--workspace-config`          | Path to the workspace policy file. Defaults to `ash-workspace.{yaml,yml,json}` in the workspace root or its `.ash` directory | None | `ASH_WORKSPACE_CONFIG` |
| `--allow-missing-projects`    | Skip workspace projects that are absent or unreadable   | `False`               |                         |
| `--dry-run`                   | Print the resolved workspace plan and exit without scanning | `False`           |                         |

### Workspace Mode

A [VS Code workspace file](https://code.visualstudio.com/docs/editor/workspaces) lists several project folders. Passing it to `--workspace` tells ASH to treat each folder as its own project, with its own configuration, rather than as one directory tree:

```json
{
  "folders": [
    { "path": "services/api" },
    { "path": "shared-infra" }
  ]
}
```

Folder paths are relative to the directory holding the workspace file, which becomes the workspace root. Each project gets a key derived from its path below that root — `services/api` becomes `services-api` — and that key is what output paths and per-project attribution use. ASH reads only the `folders` array; the `settings` block is ignored, because ASH configuration belongs in ASH's own config file.

`--workspace` and `--source-dir` cannot be combined. Note that `ASH_SOURCE_DIR` counts as setting `--source-dir`.

`--dry-run` resolves and validates the workspace, prints the resulting plan, and exits 0 without scanning anything. Without it, the same plan is what gets scanned — resolved once, so what you inspect is what runs.

#### Workspace policy

Each project is judged against its own configuration, so there is nowhere in a project's config to say something about the workspace as a whole. That goes in a workspace policy file, which ASH looks for at `ash-workspace.yaml` (or `.yml`/`.json`) in the workspace root or its `.ash` directory. Having none is not an error.

```yaml
workspace:
  # The LOOSEST threshold any project may use. A stricter project keeps its own.
  max_severity_threshold: MEDIUM
  # Paths are workspace-relative and are rewritten per project.
  suppressions:
    - path: services/api/src/legacy.py
      rule_id: B101
      reason: tracked in TICKET-1
  ignore_paths:
    - path: '**/vendor'
      reason: third-party code
  # Additive: a project cannot be made to run fewer scanners than it enables.
  additional_scanners:
    - bandit
  # Whether findings from scanners added above affect a project's exit code.
  policy_scanners_gate: false
```

The policy file must be a **different file** from any project's ASH config. When the workspace root is itself a project, `.ash/ash.yaml` there is that project's config and keeps meaning exactly that; policy goes in `.ash/ash-workspace.yaml`, or in any file named with `--workspace-config`. Pointing `--workspace-config` at a project's config exits 4 and names the file, because workspace policy governs every project and reading one project's config as policy would apply its settings to its siblings.

`max_severity_threshold` is a ceiling on permissiveness, not on severity. The strictness order is `ALL` (strictest) through `CRITICAL` (loosest), so *raising* this value loosens it. A project's effective threshold is whichever of its own setting and this ceiling is stricter: a project at `CRITICAL` under a `MEDIUM` ceiling is judged at `MEDIUM`, while a project already at `LOW` is left alone. `--dry-run` prints both values for any project the ceiling moved, so you can see what it changed before running a scan.

One limitation is worth knowing before relying on the ceiling. It tightens findings that carry a severity. A finding that carries only a SARIF `error` level is treated as critical and stays actionable at every threshold, so no ceiling excludes it — this is not specific to workspace mode, and `severity_threshold` behaves the same way in a single-project scan. In practice it means the ceiling cannot quieten checkov, which reports no per-finding severity.

Rather than leave that as a caveat to remember, ASH measures it. When the ceiling tightens a project and some of that project's findings were beyond the tightening's reach, the project's entry in `ash_aggregated_results.json` carries `ceiling_unreachable_findings` — a count per scanner:

```json
"ceiling_unreachable_findings": { "checkov": 7 }
```

Read it as a statement about those findings, not about the scanner: seven findings in this project carry no severity, so the ceiling did not change their verdict. It is recomputed on every scan from the findings actually present, so it disappears if a scanner starts reporting severity, and it is absent entirely when the ceiling either did not tighten the project or reached everything it needed to.

Suppressions and ignore paths are written workspace-relative and pushed down into each project's own coordinates. A pattern that cannot match inside a project is not applied there, so `services/api/src/legacy.py` silences nothing in `shared-infra`. A pattern with no exact per-project equivalent is refused with exit 4 rather than approximated, because a suppression that matches more than intended hides findings and leaves nothing in the output to show what went missing. `**/vendor` works; `**/vendor/**` is refused, and the error names the pattern and the project.

Scanners in `additional_scanners` that a project already enables run under that project's own configuration and their findings are the project's. Scanners only the policy adds run with default configuration, are reported separately as `origin: workspace-policy`, and do not affect the project's exit code unless `policy_scanners_gate: true`.

#### What each project gets

Each project is scanned in its own scope: its own directory as the scan root, its own configuration, its own suppressions, and its own severity threshold. A project's findings and its pass/fail verdict are the same as `ash --source-dir <that project>` would produce. A suppression written in one project's config does not apply to another, even for the same rule at the same relative path.

Output is laid out per project, with a workspace-level roll-up beside it:

```
.ash/ash_output/
  ash_aggregated_results.json      # unified, with per-project attribution
  reports/
    workspace-reports.json         # what every reporter did, and where
    ash.<ext>                       # workspace-level reports (see below)
  projects/<project-key>/
    ash_aggregated_results.json    # this project alone
    reports/ash.<ext>              # this project's own reports
    scanners/<scanner>/<target>/   # raw scanner output
```

The unified `ash_aggregated_results.json` carries a `workspace` block: one entry per project with its threshold, finding counts, verdict and `sarif_run_index`, plus the `skipped_projects` payload.

Its SARIF holds one `run` per project. Each run declares its own project root under `originalUriBaseIds`, and result paths inside a run stay relative to that root — so a consumer that ingests SARIF against a single repository root, such as GitHub code scanning, still resolves every path correctly. Selecting one run gives you a valid single-root SARIF document for one project. Each result also carries `properties.workspace_project` and `properties.workspace_uri`, the workspace-relative path, for consumers that want one flat coordinate space.

#### Which reports are written where

Not every format can be merged across projects, so each reporter declares what it does with a multi-project scan. Three answers:

| Behaviour | Reporters | What you get |
| --- | --- | --- |
| Merged | `sarif`, `html`, `markdown`, `text`, `csv`, `flat-json`, `yaml`, `junitxml`, `ocsf` | One workspace-level artefact under `reports/`, carrying the project on every finding |
| Per project | `github-ghas`, `gitlab-sast`, `cyclonedx`, `gitlab-cyclonedx`, `spdx`, and the AWS reporters | No workspace-level artefact. The files under `projects/<key>/reports/` are the answer |
| Workspace-scoped | `unused-suppressions` | A workspace-level artefact covering workspace-level state only, not a merge of the projects |

Where the project appears depends on the format: a `workspace_project` column in `csv`, a field of the same name in `flat-json`, a per-project section in `html`, `markdown` and `text`, a `<project>/<scanner>` testsuite name in `junitxml`, and a `workspace_project:<key>` entry in `metadata.labels` for `ocsf`. Single-directory output is unchanged in every case.

A reporter is per project when merging would be wrong rather than merely unimplemented. `github-ghas` and `gitlab-sast` produce documents their consumers resolve against a single repository root, so a merged one would mis-locate findings. The three SBOM formats describe one deliverable each, and a workspace of independently versioned projects is N SBOMs. The AWS reporters publish side effects, which a second invocation would duplicate.

`reports/workspace-reports.json` accounts for all of them, including the ones that deliberately produced nothing: what each reporter's behaviour is, the path of its workspace-level artefact or `null`, the per-project paths that replace it, which of those are missing, and why a reporter was not considered at all — `disabled`, `not-in-requested-output-formats`, or unsatisfied dependencies. A missing report is never silent.

Reporter enablement at the workspace level comes from ASH's default configuration plus `--output-format`, not from any single project's config, because there is no workspace-level configuration yet. So a project that disables `html` still contributes to the workspace-level `html` report; its own `projects/<key>/reports/` respects its config as usual.

If a reporter declares that it cannot produce a correct workspace-level artefact at all, the scan is refused before anything is scanned, with exit code `4` naming the reporter. No reporter shipped with ASH is in that state. Disable it or narrow `--output-format` to proceed.

#### Changed files and precommit

`--mode precommit` and `--changed-files-only` are evaluated per project, against that project's own git repository, because projects in a workspace are versioned independently. A project with no changed files is skipped and recorded with `skipped_reason: no-changes`, which does not affect the exit code. Under `--mode precommit`, a project that is not a git repository is an error, because precommit selects files from a diff; pass `--allow-missing-projects` to scan it in full instead.

#### Concurrency

Set these in the ASH config resolved for the workspace **root** — how many projects run at once is not a project's decision:

```yaml
workspace:
  max_parallel_projects: 4   # default: min(4, cpu_count)
  project_timeout: 600       # seconds; default: no limit
```

`max_parallel_projects` bounds how many projects run concurrently. It is an outer bound over each project's own scanner thread pool, not a replacement for it, so the worst-case thread count is the product of the two. Wall clock is roughly `ceil(projects / max_parallel_projects)` times one project's: five projects at the default bound of 4 take two waves. Raise the bound to the project count to get one wave, and accept the larger thread product.

`project_timeout` records a project that overruns as failed and continues with the others; the workspace then exits non-zero. The abandoned worker cannot be interrupted, so it runs to completion in the background and the process will not exit until it does.

#### Container mode

Container mode has one bind mount, so the workspace **root** is mounted at `/src` and each project is `/src/<relative-path>`. This is why every project must sit below the workspace root. `--changed-files-only` is not supported in container mode, as in single-directory mode.

#### Fail-closed validation

Workspace resolution refuses the whole workspace rather than scanning part of it, because a partial scan exits 0 and the projects that did run supply a passing result for code nothing examined. A workspace is refused when:

- a folder does not exist, or exists but is not readable
- a folder resolves outside the workspace root, or a path contains `..`
- a folder entry is a symlink
- two entries resolve to the same directory, or one is nested inside another
- two entries reduce to the same project key
- two projects pin incompatible `tool_version` constraints for the same scanner
- the `folders` list is empty, or the file is not valid JSON

`--allow-missing-projects` opts out of the first item only. Projects skipped that way are recorded in the plan's `skipped_projects` payload with a reason, not just logged. Nothing opts out of the others: they are problems with the definition rather than with the machine, so they are wrong everywhere.

Workspace mode does not introduce a separate exit-code vocabulary; it uses the codes in [Exit Codes](#exit-codes). Every refusal listed above is code `4` — the workspace definition could not be used, so nothing was scanned. That is deliberately distinct from code `2`, which means a scan ran and found issues above the threshold.

When several projects end differently, the code is chosen by how specific the diagnosis is rather than by severity: `3` (a named misconfigured project) outranks `1` (a project that reached no verdict at all, whether from an internal error or a per-project timeout), which outranks `2` (a project with a verdict that failed). The results payload also records `workspace.status` — `completed` or `refused` — and `workspace.refusal_detail`, for consumers reading the file rather than the exit status.

Comments are not supported in the workspace file. VS Code tolerates them; ASH reads strict JSON and reports a commented file as malformed.

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

# Inspect the plan for a workspace, without scanning
ash --workspace ./dev.code-workspace --dry-run

# Use the single .code-workspace file in the current directory
ash --workspace auto --dry-run

# Tolerate project folders that have not been cloned on this machine
ash --workspace ./dev.code-workspace --allow-missing-projects --dry-run
```

## Config Command

The `config` command allows you to manage ASH configuration.

```bash
ash config [subcommand] [options]
```

### Config Subcommands

| Subcommand | Description                                                      |
|------------|------------------------------------------------------------------|
| `init`     | Initialize a new configuration file                              |
| `get`      | Display current configuration                                    |
| `update`   | Update configuration values                                      |
| `validate` | Validate configuration file against JSON schema and check syntax |
| `lint`     | Lint configuration for issues and optionally auto-fix them       |

### Config Options

| Option               | Description                                     | Default          | Environment Variable |
|----------------------|-------------------------------------------------|------------------|----------------------|
| `--config`, `-c`     | Path to configuration file                      | `.ash/.ash.yaml` | `ASH_CONFIG`         |
| `--config-overrides` | Override configuration values                   |                  |                      |
| `--set`              | Set configuration values (with `update`)        |                  |                      |
| `--dry-run`          | Preview changes without writing (with `update`) | `False`          |                      |
| `--force`            | Overwrite existing config file (with `init`)    | `False`          |                      |
| `--fix`              | Auto-fix common issues (with `lint`)            | `False`          |                      |
| `--fix-unused`       | Comment out unused suppressions (with `lint`)   | `False`          |                      |
| `--non-interactive`  | Skip confirmation prompts (with `lint`)         | `False`          |                      |
| `--output-dir`, `-o` | Path to ASH output directory (with `lint`)      | `.ash/ash_output`|                      |
| `--debug`, `-d`      | Enable debug logging                            | `False`          | `ASH_DEBUG`          |
| `--verbose`, `-v`    | Enable verbose logging                          | `False`          | `ASH_VERBOSE`        |
| `--no-color`         | Disable colored output                          | `False`          | `ASH_NO_COLOR`       |

### Examples

```bash
# Initialize a new configuration file
ash config init

# Initialize with force (overwrite existing)
ash config init --force

# Display current configuration
ash config get

# Display configuration from a specific file
ash config get --config /path/to/config.yaml

# Update configuration
ash config update --set 'scanners.bandit.enabled=true'

# Preview configuration update without writing
ash config update --set 'scanners.bandit.enabled=true' --dry-run

# Validate configuration file
ash config validate

# Validate a specific configuration file
ash config validate --config /path/to/config.yaml

# Validate with verbose output showing all checks
ash config validate --verbose

# Lint configuration for issues
ash config lint

# Lint and auto-fix common issues
ash config lint --fix

# Lint, fix, and comment out unused suppressions
ash config lint --fix --fix-unused

# Non-interactive mode (for pre-commit hooks and CI/CD)
ash config lint --fix --fix-unused --non-interactive

# Lint a specific config file
ash config lint --config path/to/config.yaml
```

### Config Validate Details

The `ash config validate` command performs comprehensive validation of your ASH configuration file:

**Validation Checks:**
- **Schema Validation**: Verifies the configuration matches the JSON schema
- **YAML Syntax**: Checks for valid YAML syntax and structure
- **Required Fields**: Ensures all required fields are present
- **Type Checking**: Validates data types for all fields
- **Enum Values**: Verifies enum fields contain valid values
- **Path Validation**: Checks that file paths in suppressions and ignore rules are valid
- **Suppression Rules**: Validates suppression syntax and required fields
- **Scanner Configuration**: Checks scanner-specific options

**Exit Codes:**
- `0`: Configuration is valid
- `1`: Configuration has validation errors

**Example Output:**

```bash
$ ash config validate
✓ Configuration file loaded successfully
✓ YAML syntax is valid
✓ Schema validation passed
✓ All required fields present
✓ Suppression rules validated (3 rules)
✓ Scanner configurations validated (10 scanners)

Configuration is valid!

$ ash config validate --config .ash/.ash_bad_config.yaml
✗ Configuration validation failed

Errors found:
  - Line 15: 'scanners.bandit.options' must be an object, got list
  - Line 23: Unknown field 'global_settings.invalid_field'
  - Line 30: 'suppressions[0].reason' is required but missing

Please fix these errors and try again.
```

**Use Cases:**
- Validate configuration before committing to version control
- Debug configuration issues when scans fail
- Verify configuration after manual edits
- CI/CD pipeline checks to ensure valid configuration
- Pre-deployment validation in automated workflows

### Config Lint Details

The `ash config lint` command performs all validation checks plus additional lint checks that can identify and auto-fix common configuration issues:

**Lint Checks:**
- **All validation checks**: Same checks as `ash config validate`
- **Internal fields**: Detects internal-only fields leaked from older `ash config init` versions (e.g., `name`, `extension`, `tool_version` in scanner configs)
- **Invalid sections**: Detects internal top-level sections like `build` that shouldn't be in user configs
- **Missing line_end**: Detects suppressions with `line_start` but no `line_end`
- **Expired suppressions**: Detects suppressions past their expiration date
- **Unused suppressions**: Detects suppressions not matching any findings (requires `--fix-unused`)

**Auto-fix Behavior (`--fix`):**
- Removes internal-only fields from scanner/reporter/converter configs
- Removes invalid top-level sections (e.g., `build`)
- Sets `line_end` equal to `line_start` when missing
- Removes expired suppressions

**Unused Suppression Handling (`--fix-unused`):**
- Comments out unused suppressions instead of removing them
- Adds a dated note explaining why they were commented out
- Preserves suppressions for easy re-activation if needed
- This is intentionally conservative: a suppression unused locally may still be needed in CI/CD where different scanners are available

**Non-interactive Mode (`--non-interactive` / `--yes` / `-y`):**
- Skips all confirmation prompts
- Useful for pre-commit hooks and CI/CD pipelines
- Warns (but proceeds) when the unused suppressions report is older than 1 hour

**Exit Codes:**
- `0`: No errors found (warnings and info are acceptable)
- `1`: Configuration has errors that need attention

**Example Output:**

```bash
$ ash config lint
Linting configuration file: .ash/.ash.yaml

Found 3 issue(s):
  ❌ Scanner 'bandit' contains internal-only field 'name' [auto-fixable]
  ⚠️  Suppression has 'line_start' (42) but missing 'line_end' [auto-fixable]
  ⚠️  Suppression has expired (expiration: 2024-01-01) [auto-fixable]

  Errors: 1
  Warnings: 2

💡 3 issue(s) can be auto-fixed. Run with --fix to apply fixes.

$ ash config lint --fix --non-interactive
Linting configuration file: .ash/.ash.yaml

🔧 Fixing 3 issue(s):
  • Remove internal field 'name' from scanner 'bandit'
  • Set line_end = 42 (same as line_start)
  • Remove expired suppression

✅ Fixed 3 issue(s) in .ash/.ash.yaml
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

## Get-GenAI-Guide Command

The `get-genai-guide` command downloads the ASH GenAI Integration Guide, a comprehensive document designed to help AI assistants and LLMs properly interact with ASH scan results.

```bash
ash get-genai-guide [options]
```

### Purpose

This guide provides AI assistants with:
- Instructions on using correct output formats (JSON vs HTML)
- How to handle severity discrepancies between report formats
- Proper suppression creation with correct YAML syntax
- Working with CycloneDX SBOM for dependency analysis
- Configuration file schema and structure
- Common pitfalls and known issues
- Integration patterns and examples
- Pre-tested jq queries for efficient result querying

### Get-GenAI-Guide Options

| Option            | Description                                | Default              |
|-------------------|--------------------------------------------|----------------------|
| `--output`, `-o`  | Output path for the GenAI integration guide | `ash-genai-guide.md` |

### Examples

```bash
# Download to default location (ash-genai-guide.md)
ash get-genai-guide

# Download to custom location
ash get-genai-guide -o /path/to/guide.md

# Download to current directory with custom name
ash get-genai-guide --output genai-integration.md
```

### Installation for AI Coding Tools

**For Kiro (Global - Recommended)**:
```bash
# Install globally for all Kiro workspaces
mkdir -p ~/.kiro/steering
ash get-genai-guide -o ~/.kiro/steering/ash-integration.md

# Kiro will automatically load this as steering context
```

**For Kiro (Project-Specific)**:
```bash
# Install for current project only
mkdir -p .kiro/steering
ash get-genai-guide -o .kiro/steering/ash-integration.md
```

**For Cline (VS Code)**:
```bash
# Add to project root for Cline to reference
ash get-genai-guide -o .cline/ash-guide.md

# Or add to VS Code workspace settings
mkdir -p .vscode
ash get-genai-guide -o .vscode/ash-integration-guide.md
```

**For Claude Desktop / MCP Clients**:
```bash
# Save to a dedicated documentation folder
mkdir -p ~/Documents/ai-guides
ash get-genai-guide -o ~/Documents/ai-guides/ash-integration.md

# Then reference in your prompts:
# "Please read the ASH integration guide at ~/Documents/ai-guides/ash-integration.md"
```

**For Amazon Q CLI**:
```bash
# Add to project documentation
mkdir -p docs/ai-guides
ash get-genai-guide -o docs/ai-guides/ash-integration.md

# Reference in .q/config if supported
```

**For Cursor**:
```bash
# Add to .cursorrules or project docs
ash get-genai-guide -o .cursor/ash-guide.md

# Or add to project root
ash get-genai-guide -o ASH_INTEGRATION_GUIDE.md
```

### Use Cases

**For Users:**
- Download and provide to AI assistants as context
- Share with team members using AI coding tools
- Include in documentation for AI-assisted workflows

**For AI Assistants:**
- Learn correct ASH result processing patterns
- Avoid common mistakes (parsing HTML, incorrect suppressions)
- Use efficient queries and proper data formats
- Understand ASH configuration and suppression syntax

### Guide Contents

The guide includes:
- Quick reference for key files and locations
- Critical rules for GenAI tools
- File structure and output directory layout
- Working with `ash_aggregated_results.json`
- Working with CycloneDX SBOM
- Configuration file schema
- Creating suppressions properly
- Common pitfalls and solutions
- Integration patterns (CI/CD, analysis, reporting)
- MCP server integration guidelines
- Scanner-specific notes
- Performance optimization tips
- Troubleshooting guide

For more information, see the [GenAI Integration Guide](genai-steering-guide.md) documentation.

## MCP Command

The `mcp` command starts the Model Context Protocol (MCP) server, which enables AI assistants to interact with ASH programmatically.

```bash
ash mcp
```

### Purpose

The MCP server provides a standardized interface for AI assistants to:
- Run security scans programmatically
- Retrieve scan results with filtering options
- Monitor scan progress in real-time
- Manage multiple concurrent scans
- Access scan result files and paths

### MCP Server Features

- **Real-time Progress Tracking**: Monitor scan progress with streaming updates
- **Background Scanning**: Start scans and continue other work while they run
- **Multiple Scan Management**: Handle concurrent scans with unique identifiers
- **Comprehensive Error Handling**: Detailed error messages and recovery suggestions
- **Configuration Support**: Full support for ASH configuration files and environment variables
- **Result Filtering**: Filter results by severity, scanner, or response size

### Usage

The MCP server is typically configured in AI assistant clients (Amazon Q CLI, Claude Desktop, Cline) rather than run directly. See the [MCP Server Guide](mcp-server-guide.md) for detailed setup instructions.

### Configuration Example

For Amazon Q CLI (`~/.aws/amazonq/mcp.json`):
```json
{
  "mcpServers": {
    "ash": {
      "command": "uvx",
      "args": [
        "--from=git+https://github.com/awslabs/automated-security-helper@v3.4.1",
        "ash",
        "mcp"
      ],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

For more information, see:
- [MCP Server Guide](mcp-server-guide.md)
- [MCP Tools Reference](MCP-TOOLS-REFERENCE.md)
- [MCP Filtering Guide](MCP-FILTERING-GUIDE.md)
- [Using ASH with MCP Tutorial](../tutorials/using-ash-with-mcp.md)

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
| 3    | Invalid configuration                            |
| 4    | Workspace definition or policy error - nothing was scanned |

Code 4 is distinct from code 2 on purpose. Code 2 means a scan ran and found
issues; code 4 means the workspace definition could not be used and no project
was scanned at all.
