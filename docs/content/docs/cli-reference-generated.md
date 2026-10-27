# CLI Reference (Auto-Generated)

This document is auto-generated from the ASH CLI source code using introspection.
Do not edit manually. Regenerate with: `uv run python scripts/generate_cli_docs.py`

**Which CLI reference is authoritative.** Two pages describe the CLI: this one and the hand-written [CLI Reference](cli-reference.md). They are not interchangeable, and the split is deliberate rather than accidental:

* For **flag names and aliases, parameter types, defaults, and environment variables**, this page wins. Every row here is introspected from the Typer command definitions, and `tests/unit/test_generated_docs_freshness.py` fails the build if this file and the code disagree. The hand-written page has no such gate and has drifted.
* For **worked examples, exit codes, configuration-override syntax, and narrative guidance**, the hand-written page wins. None of that can be introspected, so it is not reproduced here.

The intended end state is a single page: this one, with the hand-written page's narrative content folded in. Until that migration lands, treat a disagreement about a flag between the two pages as a defect in the hand-written page.

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
| `--config-overrides` | List[str] |  |  | Configuration overrides specified as key-value pairs (e.g., 'reporters.cloudwatch-logs.options.aws_region=us-west-2'). Supports lists with [item1,item2], append mode with key+=[value], and JSON syntax. See https://awslabs.github.io/automated-security-helper/latest/how-to/configure/ |
| `--offline` | bool | False |  | Run scan in offline/airgapped mode. npm-audit does not run offline, because npm, yarn and pnpm audit by asking the registry: a project with a lockfile reports it MISSING, and one without reports it SKIPPED. IMPORTANT: Online access is needed when building ASH to prepare it for usage during a scan! If selecting Offline while performing a build, the ASH container image will be built in offline mode and any typically online-only dependencies like downloadable tool vulnerability databases will be cached in the image itself before publishing for scan usage. |
| `--sandbox` | enum(off, auto, bwrap, firejail, landlock, sandbox-exec) |  |  | Run every scanner subprocess in an OS-level sandbox: read-only source, writable results directory only, private home and temporary directory, no network unless the scanner needs one (never under --offline). 'auto' picks the best available (Linux: bwrap, firejail, landlock; macOS: sandbox-exec). A scanner that cannot be sandboxed as requested is reported MISSING. Overrides the config file's sandbox.mode; default off. Refused with --mode container (exit 5), which runs the scanners unsandboxed inside the container. See docs/content/docs/scanner-sandbox.md |
| `--offline-semgrep-rulesets` | str | `p/ci` |  | Specify Semgrep rulesets for use in ASH offline mode |
| `--strategy` | enum(sequential, parallel) | `parallel` |  | Whether to run scanners in parallel or sequential |
| `--progress/--no-progress`, `-p/-P` | bool | True |  | Show progress of each job live in the console. Defaults to True. |
| `--output-formats`, `--output-format`, `--formats`, `--format`, `-f` | List[str] |  |  | The output formats to use (comma-separated). Available formats: text, flat-json, yaml, csv, html, junitxml, markdown, sarif, ocsf, cyclonedx, spdx, github-ghas, gitlab-sast, gitlab-cyclonedx, unused-suppressions. With the AWS plugin module (ash_aws_plugins) in ash_plugin_modules, also, once enabled: aws-security-hub, bedrock-summary-reporter, cloudwatch-logs, s3. Also accepted, though no reporter writes them: aggregated, dict, asff, custom. |
| `--cleanup` | bool | False |  | Clean up 'converted' directory and other temporary files after scan completes. Defaults to False. Note: Scans will always clean up existing files in the output directory before a new scan starts. This parameter only affects the cleanup of the temporary work directory after a scan has completed, typically for inspection of temporary artifacts. |
| `--phases` | List[enum(convert, scan, report, inspect)] |  |  | The phases to run. Defaults to all phases except inspect. |
| `--inspect` | bool | False |  | Enable inspection of SARIF fields after running. This adds the inspect phase to the execution. |
| `--use-existing` | bool | False |  | Use an existing ash_aggregated_results.json file in the output-dir. If True, the scan phase will be skipped and reports will be generated from this file. |
| `--version` | bool | False |  | Prints version number |
| `--mode` | enum(precommit, container, local, nix) | `local` | ASH_MODE | Execution mode preset. 'local' (default) runs the scan in this process with the scanner tools installed on this machine. 'precommit' is a local scan that runs only bandit, detect-secrets, checkov, cdk-nag, npm-audit, plus any --scanners, with simplified output and no progress display; in workspace mode it changes only the output. 'container' builds the ASH container image and runs the scan inside it. 'nix' runs the scan inside `nix develop`, whose shell supplies pinned scanner versions, and always offline. |
| `--python-only/--full`, `--python-based-scanners-only/--all-enabled-scanners`, `--python-based-plugins-only/--all-enabled-plugins` | bool | False |  | Exclude execution of any plugins or tools that have depencies external to Python. |
| `--show-summary` | bool | True |  | Show metrics table and results summary |
| `--quiet` | bool | False |  | Hide all log output |
| `--log-level` | enum(QUIET, SIMPLE, ERROR, INFO, ...) | `INFO` |  | Set the log level. |
| `--config`, `-c` | str |  | ASH_CONFIG | The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: ['.ash.yml', '.ash.yaml', '.ash.json', 'ash.yml', 'ash.yaml', 'ash.json'] (each at the root, then in .ash/), then ['.ashrc.toml', '.ashrc.yaml', '.ashrc.yml', '.ashrc.json', 'ashrc.toml', 'ashrc.yaml', 'ashrc.yml', 'ashrc.json'] at the root, then the tool.ash table of pyproject.toml at the root; the first found is used. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH. |
| `--verbose`, `-v` | bool | False | ASH_VERBOSE | Enable verbose logging. Any log flag on the command line overrides ASH_VERBOSE. |
| `--debug`, `-d` | bool | False | ASH_DEBUG | Enable debug logging. Any log flag on the command line overrides ASH_DEBUG. |
| `--color` | bool | True |  | Enable/disable colorized output |
| `--fail-on-findings` | bool |  |  | Enable/disable throwing non-successful exit codes if any actionable findings are found. Defaults to unset, which prefers the configuration value. If this is set directly, it takes precedence over the configuration value. |
| `--fail-on-incomplete-scanners` | bool |  |  | Exit 1 when a selected scanner did not complete -- ERROR (ran and failed) or MISSING (dependencies unavailable, so it never ran). Without this, a run where nothing ran exits 0, the same code as a clean scan, because no scanner produced any finding. A SKIPPED scanner, one you did not select or one with nothing of its kind to scan, does not trip it by itself, so --scanners and --exclude-scanners both narrow what is gated; but a run in which every scanner is SKIPPED, such as one where no selected scanner had a file to scan, exits 1. Independent of --fail-on-findings, and takes precedence over it when both would fail: a partial scan's findings are real but its clean bill of health is not. Defaults to unset, which prefers the configuration value and then on. Pass --no-fail-on-incomplete-scanners to accept a partial scan's exit code, or --exclude-scanners for a tool you do not have, which records it SKIPPED and says so in the report. |
| `--allow-stale-content-db` | bool |  |  | Let the scan pass when a scanner's content database (grype's or trivy's vulnerability database, the offline semgrep/opengrep rulesets) is older than its declared bound -- for grype, 120h after the database was built. Without it such a scan exits 1, except for trivy's database in an image built with OFFLINE=YES, which warns by default. With it the scan proceeds and the warning is recorded in the log and in the reports. --no-allow-stale-content-db forces the failure, for that database too. Defaults to unset, which prefers the `content_db_staleness` config value and then 'fail'; either form of the flag takes precedence over the config. |
| `--simple` | bool | False |  | Simplified output mode with minimal logging |
| `--ignore-suppressions` | bool | False |  | Ignore all suppression rules and report all findings regardless of suppression status. |
| `--honor-ignore-files` | bool |  |  | Whether the .gitignore and .ignore files in the scanned tree decide which files are left out of ASH's scan set (the files detect-secrets, cfn-nag, cdk-nag, cfn-lint, cfn-guard, actionlint, zizmor, npm-audit and the converters read). --no-honor-ignore-files scans the files they match too; ASH's own exclusions such as .git still apply. Defaults to unset, which prefers the operator's `honor_ignore_files` config value and then honoring them. Either form takes precedence over the config. A config file inside the scanned tree cannot set it. The results and summaries record whether the ignore files were honored and how many files they excluded. |
| `--min-severity` | enum(critical, high, medium, low, none) | `low` |  | Minimum severity to trigger non-zero exit code (critical, high, medium, low, none). 'critical' and 'high' are equivalent because SARIF does not distinguish them. Findings below this threshold are still reported but don't affect the exit code. |
| `--compact-report` | bool | False |  | Produce a shorter markdown report suitable for PR comments. Omits the severity legend, scan metadata, footer, and rows for scanners that were skipped or had zero findings. |
| `--changed-files-only` | bool | False | ASH_CHANGED_FILES_ONLY | Report only findings in files changed between --base-ref and HEAD, for example on a pull request. Scanners still scan every file; findings located in other files are dropped from every report, the summary counts and the exit code. Findings with no file location are kept. When git cannot list the changes, everything is reported; when nothing changed inside --source-dir, nothing is. Not supported with --mode container, which refuses it (exit 5). |
| `--base-ref` | str | `origin/main` | ASH_BASE_REF | Git ref to diff against when --changed-files-only is set. |
| `--allow-in-tree-tools` | bool | False |  | Let ASH start scanners and other tools found inside the scanned directory, such as an activated in-repo .venv/bin or node_modules/.bin. Off by default: a tool inside the scanned directory is treated as missing. Only this flag (also the allow_in_tree_tools key of --cli-json-input) and the ASH_ALLOW_IN_TREE_TOOLS environment variable (1, true, yes or on) turn it on, never a config file, and `ash mcp` never does. |
| `--shard-index` | int |  | ASH_SHARD_INDEX | Zero-based index of this shard when one scan is split across several executors. Requires --shard-count. A 3-way split uses indices 0, 1 and 2. Each shard runs a disjoint subset of the scanners and records which ones in its results; recombine them with 'ash merge'. |
| `--shard-count` | int |  | ASH_SHARD_COUNT | Total number of shards this scan is split across. Requires --shard-index. Balance is by scanner count rather than scanner cost, so counts above about four buy little: wall clock is bounded by the slowest single scanner. |
| `--config-from-scanned-repository` | bool | False |  | Apply the limits ASH puts on a repository-written config file to the --config file and every file it extends, wherever they are. Container mode passes this to the scan inside the container when the config is a file the scanned repository wrote (judged by its resolved path and by the name that reached it) but outside --source-dir, where that scan cannot see it. In a workspace scan it marks the --config file that is layered over every project's own config and used alone by a project without one, from planning on. |
| `--config-file-from-scanned-repository` | List[str] |  |  | Apply the limits ASH puts on a repository-written config file to this one file of the extends chain of the --config file or of the file ASH_CONFIG names. Container mode passes it, once per file, for each file of those chains the scanned repository wrote; the bases of a --config whose whole chain carries --config-from-scanned-repository are passed individually as well, so a mounted base judged on its own is still a marked file. Refused for a file that is in neither chain. |
| `--config-file-from-another-checkout` | List[str] |  |  | Apply the limits ASH puts on a config file inside a git checkout other than the scanned one to this one file of the extends chain of the --config file or of the file ASH_CONFIG names. The file cannot grant, and still sets what only restricts, as it does on the host: a lowered archive extraction limit, a scanner option that sends no usage data, and a network_scanners list as a limit. Container mode passes it, once per file, for each file of those chains that is in such a checkout, by its path inside the container, where the scan inside cannot see the checkout. Refused for a file that is in neither chain. |
| `--ash-config-from-host` | str |  |  | Read this file as the file ASH_CONFIG names, for the whole command. Container mode passes it to the scan inside the container, with the path there of the file the host's ASH_CONFIG names, which a local scan reads as its base whatever names the config. Not --config, whose environment variable ASH_CONFIG is. |
| `--workspace` | str |  | ASH_WORKSPACE | Path to a '.code-workspace' file whose folders are scanned as separate, independently-scoped projects. Pass 'auto' to use the single '*.code-workspace' file in the current directory. Mutually exclusive with --source-dir. |
| `--workspace-config` | str |  | ASH_WORKSPACE_CONFIG | Path to the workspace policy file (severity ceiling, workspace-wide suppressions and ignore paths, additional scanners). Without this, ASH looks for 'ash-workspace.{yaml,yml,json}' in the workspace root or its '.ash' directory; finding none is not an error. Must not be any project's own ASH config: workspace policy governs every project, so reading one project's config as policy would apply its settings to its siblings. |
| `--allow-missing-projects` | bool | False |  | In workspace mode, skip project folders that are absent or unreadable instead of failing. Skipped projects are recorded in the plan. Without this, a missing project fails the whole workspace, so a typo or an un-cloned repository cannot pass as a clean scan. |
| `--dry-run` | bool | False |  | In workspace mode, print the resolved execution plan and exit without scanning anything. |
| `--build/--no-build`, `-b/-B` | bool | True |  | Whether to build the ASH container image |
| `--run/--no-run`, `-r/-R` | bool | True |  | Whether to run the ASH container image |
| `--force` | bool | False |  | Force rebuild of the ASH container image |
| `--oci-runner`, `--oci`, `--runner`, `-o` | str |  | OCI_RUNNER | Use the specified OCI runner instead of docker to run the containerized tools |
| `--build-target` | enum(non-root, ci) |  |  | The ASH image stage to build and run: 'non-root' (an unprivileged user, the default) or 'ci' (root, the default on Windows). CI environment variables do not change it; --custom-containerfile builds on 'ci'. |
| `--container-uid`, `-u` | str |  |  | UID to use for the container user |
| `--container-gid`, `-g` | str |  |  | GID to use for the container user |
| `--ash-revision-to-install` | str |  |  | ASH branch, tag or full commit id to install in the container image for usage during containerized scans |
| `--custom-containerfile` | str |  |  | Path to a custom container definition (e.g. Dockerfile) that you would like to build *after* the ASH container image builds. This is typically used when building a custom container image for ASH and including custom tooling that ASH does not come with by default. The fully qualified image name for the ASH image is passed in as the `ASH_BASE_IMAGE` build-arg so you can use it as a base. IMPORTANT: When a custom_containerfile path is provided, the build-target is set to `ci` so the container run-as configuration is not shifted to the non-root user. If you are using this parameter, you are responsible for securing your final container as appropriate. |
| `--custom-build-arg` | List[str] |  |  | Custom build arguments to pass to the container build |
| `--cli-json-input` | str |  |  | Read parameter values from a JSON object: a path, a file:// URI, or '-' for stdin. Keys are parameter names (output_dir) or long flag spellings (--output-dir). Flags given on the command line override the file; the file overrides environment variables. Run with --generate-cli-skeleton for a template. |
| `--generate-cli-skeleton` | bool |  |  | Print a JSON template for --cli-json-input, listing every parameter of this command with its default, and exit. |

### `ash build-image`

Builds the ASH container image, then scans the current directory with it unless --no-run is given.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--no-build` | bool | False |  | Skip building the ASH container image; reuse an existing image if present |
| `--no-run` | bool | False |  | Build the ASH container image but do not run a scan |
| `--force`, `-f` | bool | False |  | Force rebuild of the ASH container image |
| `--oci-runner`, `--oci`, `--runner`, `-r` | str |  | OCI_RUNNER | Use the specified OCI runner instead of docker to run the containerized tools. To prefix every OCI command with a wrapper (e.g. sudo), set the OCI_RUNNER_WRAPPER environment variable instead of using this option (e.g. OCI_RUNNER_WRAPPER=sudo ash ...). |
| `--container-network` | str | `bridge` |  | Docker network mode for the container run (e.g. 'bridge', 'none', 'host'). Pass 'none' to force offline/airgapped network isolation independently of --offline. |
| `--build-target` | enum(non-root, ci) |  |  | The ASH image stage to build: 'non-root' (an unprivileged user, the default) or 'ci' (root, the default on Windows). CI environment variables do not change it. |
| `--offline-semgrep-rulesets` | str | `p/ci` |  | Specify Semgrep rulesets for use in ASH offline mode |
| `--container-uid`, `-u` | str |  |  | UID to use for the container user |
| `--container-gid`, `-g` | str |  |  | GID to use for the container user |
| `--ash-revision-to-install` | str |  |  | ASH branch, tag or full commit id to install in the container image for usage during containerized scans |
| `--custom-containerfile` | str |  |  | Path to a custom container definition (e.g. Dockerfile) that you would like to build *after* the ASH container image builds. This is typically used when building a custom container image for ASH and including custom tooling that ASH does not come with by default. The fully qualified image name for the ASH image is passed in as the `ASH_BASE_IMAGE` build-arg so you can use it as a base. IMPORTANT: When a custom_containerfile path is provided, the build-target is set to `ci` so the container run-as configuration is not shifted to the non-root user. If you are using this parameter, you are responsible for securing your final container as appropriate. |
| `--custom-build-arg` | List[str] |  |  | Custom build arguments to pass to the container build |
| `--config-overrides` | List[str] |  |  | Configuration overrides specified as key-value pairs (e.g., 'reporters.cloudwatch-logs.options.aws_region=us-west-2') |
| `--offline` | bool | False |  | Run scan in offline/airgapped mode. npm-audit does not run offline, because npm, yarn and pnpm audit by asking the registry: a project with a lockfile reports it MISSING, and one without reports it SKIPPED. IMPORTANT: Online access is needed when building ASH to prepare it for usage during a scan! If selecting Offline while performing a build, the ASH container image will be built in offline mode and any typically online-only dependencies like downloadable tool vulnerability databases will be cached in the image itself before publishing for scan usage. |
| `--quiet` | bool | False |  | Hide all log output |
| `--log-level` | enum(QUIET, SIMPLE, ERROR, INFO, ...) | `INFO` |  | Set the log level. |
| `--config`, `-c` | str |  | ASH_CONFIG | The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: ['.ash.yml', '.ash.yaml', '.ash.json', 'ash.yml', 'ash.yaml', 'ash.json'] (each at the root, then in .ash/), then ['.ashrc.toml', '.ashrc.yaml', '.ashrc.yml', '.ashrc.json', 'ashrc.toml', 'ashrc.yaml', 'ashrc.yml', 'ashrc.json'] at the root, then the tool.ash table of pyproject.toml at the root; the first found is used. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH. |
| `--verbose`, `-v` | bool | False |  | Enable verbose logging |
| `--debug`, `-d` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |
| `--cli-json-input` | str |  |  | Read parameter values from a JSON object: a path, a file:// URI, or '-' for stdin. Keys are parameter names (output_dir) or long flag spellings (--output-dir). Flags given on the command line override the file; the file overrides environment variables. Run with --generate-cli-skeleton for a template. |
| `--generate-cli-skeleton` | bool |  |  | Print a JSON template for --cli-json-input, listing every parameter of this command with its default, and exit. |

### `ash report`

Generate a report from ASH scan results using the specified reporter plugin.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--format` | str | `markdown` |  | Report format to generate: a reporter's name. Defaults to 'markdown'. Values: text, flat-json, yaml, csv, html, junitxml, markdown, sarif, ocsf, cyclonedx, spdx, github-ghas, gitlab-sast, gitlab-cyclonedx, unused-suppressions. With the AWS plugin module (ash_aws_plugins) in ash_plugin_modules, also, once enabled: aws-security-hub, bedrock-summary-reporter, cloudwatch-logs, s3. A reporter another module there adds is named the same way. |
| `--output-dir` | str |  | ASH_OUTPUT_DIR | The directory to output results to |
| `--log-level` | enum(QUIET, SIMPLE, ERROR, INFO, ...) | `INFO` |  | Set the log level. |
| `--config`, `-c` | str |  | ASH_CONFIG | The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: ['.ash.yml', '.ash.yaml', '.ash.json', 'ash.yml', 'ash.yaml', 'ash.json'] (each at the root, then in .ash/), then ['.ashrc.toml', '.ashrc.yaml', '.ashrc.yml', '.ashrc.json', 'ashrc.toml', 'ashrc.yaml', 'ashrc.yml', 'ashrc.json'] at the root, then the tool.ash table of pyproject.toml at the root; the first found is used. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH. |
| `--config-overrides` | List[str] |  |  | Configuration overrides specified as key-value pairs (e.g., 'reporters.cloudwatch-logs.options.aws_region=us-west-2') |
| `--verbose`, `-v` | bool | False |  | Enable verbose logging |
| `--debug`, `-d` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |
| `--cli-json-input` | str |  |  | Read parameter values from a JSON object: a path, a file:// URI, or '-' for stdin. Keys are parameter names (output_dir) or long flag spellings (--output-dir). Flags given on the command line override the file; the file overrides environment variables. Run with --generate-cli-skeleton for a template. |
| `--generate-cli-skeleton` | bool |  |  | Print a JSON template for --cli-json-input, listing every parameter of this command with its default, and exit. |

### `ash merge`

Merges the results of a sharded scan into one unified report.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--results` | List[str] | *required* |  | A shard's ash_aggregated_results.json, or a directory containing one. Repeat once per shard. |
| `--output-dir` | str | *required* | ASH_OUTPUT_DIR | Directory to write the merged results and reports to. |
| `--output-formats` | List[str] |  |  | Comma-separated report formats to generate. Defaults to the formats the scan's own configuration asks for. |
| `--config`, `-c` | str |  | ASH_CONFIG | The operator's config file. Its values replace the shards' for the settings a shard's recorded config cannot choose, such as where reporters send findings and which off-host reporters run. Its ash_plugin_modules are the plugin modules the merge loads, with any --config-overrides adds; a module only the shards recorded is not loaded. It adds no reporter section the shards did not record; use --config-overrides for that. |
| `--config-overrides` | List[str] |  |  | Configuration overrides as key-value pairs (e.g., 'reporters.s3.enabled=true'), applied over the shards' recorded config. |
| `--min-severity` | enum(critical, high, medium, low, none) | `low` |  | Minimum severity that counts as actionable for the exit code. |
| `--ignore-suppressions` | bool | False |  | Ignore all suppression rules and report every finding regardless of suppression status. Mirrors 'ash scan --ignore-suppressions', so the same tree gives the same verdict sharded or not. |
| `--fail-on-findings/--no-fail-on-findings` | bool |  |  | Exit non-zero when the merged report has actionable findings. Defaults to the scan configuration's value, then to true. |
| `--fail-on-incomplete-scanners/--no-fail-on-incomplete-scanners` | bool |  |  | Refuse the merge when a shard completed none of the scanners it owned, and exit 1 when any scanner in the union is ERROR or MISSING, or when every one is SKIPPED, such as when no selected scanner had a file to scan. Without it, a shard whose scanners never ran contributes no findings and the merged report reads as a complete, clean scan. Defaults to the scan configuration's value, then to true; pass --no-fail-on-incomplete-scanners to merge a partial union anyway. |
| `--log-level` | enum(QUIET, SIMPLE, ERROR, INFO, ...) | `INFO` |  | Set the log level. |
| `--verbose`, `-v` | bool | False |  | Enable verbose logging |
| `--debug`, `-d` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |
| `--cli-json-input` | str |  |  | Read parameter values from a JSON object: a path, a file:// URI, or '-' for stdin. Keys are parameter names (output_dir) or long flag spellings (--output-dir). Flags given on the command line override the file; the file overrides environment variables. Run with --generate-cli-skeleton for a template. |
| `--generate-cli-skeleton` | bool |  |  | Print a JSON template for --cli-json-input, listing every parameter of this command with its default, and exit. |

### `ash mcp`

Start the ASH MCP server (Model Context Protocol).

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--log-level` | enum(QUIET, SIMPLE, ERROR, INFO, ...) | `INFO` |  | Set the log level. |
| `--verbose/--no-verbose`, `-v` | bool | False |  | Enable verbose logging |
| `--debug/--no-debug`, `-d` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |
| `--quiet` | bool | False |  | Hide all log output |
| `--transport` | str | `stdio` |  | Transport: 'stdio' (default), 'streamable-http', or 'sse'. |
| `--host` | str | `127.0.0.1` |  | Host to bind for HTTP transports. |
| `--port` | int | 8000 |  | Port to bind for HTTP transports. |
| `--mount-path` | str | `/mcp` |  | HTTP path the transport listens on (default: /mcp for streamable-http, /sse for sse). |
| `--auth-header-name` | str |  |  | Required HTTP header name for single-tenant auth (HTTP transports only). |
| `--auth-header-value` | str |  |  | Expected value of --auth-header-name. Visible to other local users on the command line; prefer --auth-header-value-file or --auth-header-value-fd. |
| `--auth-header-value-file` | Path |  |  | Read the expected value of --auth-header-name from this file, once at startup: a regular file, not a symlink, readable by its owner only. One trailing newline is dropped. |
| `--auth-header-value-fd` | int |  |  | Read the expected value of --auth-header-name from this inherited file descriptor (3 or above), once at startup, then close it. |
| `--stateless-http/--no-stateless-http` | bool | False |  | Handle each streamable-HTTP request independently instead of binding it to a server-held session. Required behind a load balancer that may route consecutive requests to different replicas, and by managed runtimes that inject their own Mcp-Session-Id. Only valid with --transport streamable-http. |
| `--trust-upstream-session-id` | bool | False |  | Stateless streamable-HTTP only. Declare that a platform in front of ASH issues and authenticates the Mcp-Session-Id header, so it can name the caller's session. Without it a stateless server identifies no session, and tools that need one (source delivery, profiles, the scan registry) refuse. |
| `--allowed-host` | List[str] |  |  | Host header value to accept, repeatable. Keeps DNS-rebinding protection enabled while allowing a known proxy or load balancer hostname. Required with a non-loopback --host unless --trust-upstream-host-check is given. |
| `--session-workspace-ttl` | int |  |  | HTTP transports only. Seconds a session workspace (delivered source, uploads, bound profile) may go unused before it is removed. Covers sessions whose end the server cannot see, such as every stateless one. Default: 86400 (24 hours). |
| `--trust-upstream-host-check` | bool | False |  | HTTP transports only. Declare that a proxy or platform in front of ASH checks the Host and Origin headers, so ASH serves any. Without it, a non-loopback --host needs --allowed-host or the server refuses to start. Cannot be combined with --allowed-host. |
| `--profile` | List[str] |  |  | Register a named config profile as NAME=path/to/ash.yaml, repeatable. Clients list them with the list_profiles tool and bind one to their session with select_profile; a bound profile supplies the config for every later call in that session that names none. Each file is loaded and schema-validated now, so a typo fails startup rather than a scan. |

### `ash get-genai-guide`

Write the ASH GenAI Integration Guide for AI assistants and LLMs to a file.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--output`, `-o` | str | `ash-genai-guide.md` |  | Output path for the GenAI integration guide |
| `--from-github` | bool | False |  | Fetch from GitHub instead of local installation |
| `--branch`, `-b` | str | `main` |  | GitHub branch to fetch from when using --from-github (default: main) |

## Config Subcommands

### `ash config init`

Create a configuration file with every setting at its default.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--config`, `-c` | str |  | ASH_CONFIG | Where to write the new config file. By default .ashrc.yaml in the current directory, a name a scan of that directory reads. Discovery reads these names: ['.ash.yml', '.ash.yaml', '.ash.json', 'ash.yml', 'ash.yaml', 'ash.json'] (each at the root, then in .ash/), then ['.ashrc.toml', '.ashrc.yaml', '.ashrc.yml', '.ashrc.json', 'ashrc.toml', 'ashrc.yaml', 'ashrc.yml', 'ashrc.json'] at the root, then the tool.ash table of pyproject.toml at the root; the first found is used. Can also be set with the ASH_CONFIG environment variable. |
| `--verbose`, `-v` | bool | False |  | Enable verbose logging |
| `--debug`, `-d` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |
| `--force` | bool | False |  | Overwrite the config file if it already exists at the target path. |

### `ash config get`

Print the resolved configuration: the file's settings over the defaults.

**Arguments:**

| Argument | Type | Default | Env Var | Description |
|----------|------|---------|---------|-------------|
| `CONFIG_PATH` | str |  |  | The configuration file, as a positional argument. Same as --config, which is preferred; when both are given they must name the same file. |

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--config`, `-c` | str |  | ASH_CONFIG | The path to the configuration file. By default, the config a scan of the current directory would use: ['.ash.yml', '.ash.yaml', '.ash.json', 'ash.yml', 'ash.yaml', 'ash.json'] (each at the root, then in .ash/), then ['.ashrc.toml', '.ashrc.yaml', '.ashrc.yml', '.ashrc.json', 'ashrc.toml', 'ashrc.yaml', 'ashrc.yml', 'ashrc.json'] at the root, then the tool.ash table of pyproject.toml at the root; the first found is used. |
| `--config-overrides` | List[str] | [] |  | Configuration overrides specified as key-value pairs (e.g., 'global_settings.severity_threshold=LOW') |
| `--source-dir` | str |  | ASH_SOURCE_DIR | The directory a scan would scan, as `ash scan --source-dir`: the config is discovered there unless --config names one, and a config inside it may only extend files inside it. Defaults to the current directory. |
| `--verbose/--no-verbose`, `-v` | bool | False |  | Enable verbose logging |
| `--debug/--no-debug`, `-d` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |

### `ash config update`

Update an existing configuration file with the specified modifications.

**Arguments:**

| Argument | Type | Default | Env Var | Description |
|----------|------|---------|---------|-------------|
| `CONFIG_PATH` | str |  |  | The configuration file, as a positional argument. Same as --config, which is preferred; when both are given they must name the same file. |

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--config`, `-c` | str |  | ASH_CONFIG | The path to the configuration file. By default, the config a scan of the current directory would use: ['.ash.yml', '.ash.yaml', '.ash.json', 'ash.yml', 'ash.yaml', 'ash.json'] (each at the root, then in .ash/), then ['.ashrc.toml', '.ashrc.yaml', '.ashrc.yml', '.ashrc.json', 'ashrc.toml', 'ashrc.yaml', 'ashrc.yml', 'ashrc.json'] at the root, then the tool.ash table of pyproject.toml at the root; the first found is used. |
| `--set` | List[str] | [] |  | Configuration modifications specified as key-value pairs (e.g., 'global_settings.severity_threshold=LOW'). Supports lists with [item1,item2], append mode with key+=[value], and JSON syntax. |
| `--verbose/--no-verbose`, `-v` | bool | False |  | Enable verbose logging |
| `--debug/--no-debug`, `-d` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |
| `--dry-run` | bool | False |  | Show changes without writing to file |

### `ash config validate-plugin-dependencies`

Check that the configuration resolves and names a project.

**Arguments:**

| Argument | Type | Default | Env Var | Description |
|----------|------|---------|---------|-------------|
| `CONFIG_PATH` | str |  |  | The configuration file, as a positional argument. Same as --config, which is preferred; when both are given they must name the same file. |

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--config`, `-c` | str |  | ASH_CONFIG | The path to the configuration file. By default, the config a scan of the current directory would use: ['.ash.yml', '.ash.yaml', '.ash.json', 'ash.yml', 'ash.yaml', 'ash.json'] (each at the root, then in .ash/), then ['.ashrc.toml', '.ashrc.yaml', '.ashrc.yml', '.ashrc.json', 'ashrc.toml', 'ashrc.yaml', 'ashrc.yml', 'ashrc.json'] at the root, then the tool.ash table of pyproject.toml at the root; the first found is used. |
| `--config-overrides` | List[str] | [] |  | Configuration overrides specified as key-value pairs (e.g., 'global_settings.severity_threshold=LOW') |
| `--source-dir` | str |  | ASH_SOURCE_DIR | The directory a scan would scan, as `ash scan --source-dir`: the config is discovered there unless --config names one, and a config inside it may only extend files inside it. Defaults to the current directory. |
| `--verbose/--no-verbose`, `-v` | bool | False |  | Enable verbose logging |
| `--debug/--no-debug`, `-d` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |

### `ash config lint`

Lint an ASH configuration file for issues and optionally auto-fix them.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--config`, `-c` | str |  | ASH_CONFIG | The path to the configuration file. By default, the config a scan of the current directory would use: ['.ash.yml', '.ash.yaml', '.ash.json', 'ash.yml', 'ash.yaml', 'ash.json'] (each at the root, then in .ash/), then ['.ashrc.toml', '.ashrc.yaml', '.ashrc.yml', '.ashrc.json', 'ashrc.toml', 'ashrc.yaml', 'ashrc.yml', 'ashrc.json'] at the root, then the tool.ash table of pyproject.toml at the root; the first found is used. |
| `--output-dir`, `-o` | str |  |  | Path to the ASH output directory (for unused suppressions report). Defaults to .ash/ash_output |
| `--fix` | bool | False |  | Auto-fix fixable issues (internal fields, missing line_end, expired suppressions, multi-line suppression reasons). A TOML file, and a file that reads the environment (${VAR} or !ENV), are not rewritten: fix those by hand |
| `--fix-unused` | bool | False |  | Comment out unused suppressions based on the last scan's unused suppressions report. A TOML file, and a JSON file (which holds no comments), are not rewritten: remove those by hand |
| `--non-interactive`, `--yes`, `-y` | bool | False |  | Accept all changes without prompting. Useful for pre-commit hooks and CI/CD |
| `--source-dir` | str |  | ASH_SOURCE_DIR | The directory a scan would scan, as `ash scan --source-dir`: the config is discovered there unless --config names one, and a config inside it may only extend files inside it. Defaults to the current directory. |
| `--verbose`, `-v` | bool | False |  | Enable verbose logging |
| `--debug`, `-d` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |

### `ash config wizard`

Interactive configuration wizard.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--config`, `-c` | str |  | ASH_CONFIG | Path to read/write the configuration file. By default, the config a scan of the current directory would use, or a new .ashrc.yaml when there is none. |
| `--verbose`, `-v` | bool | False |  | Enable verbose logging |
| `--debug`, `-d` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |

### `ash config validate`

Validate an ASH configuration file the way a scan loads it.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--config`, `-c` | str |  | ASH_CONFIG | The path to the configuration file. By default, the config a scan of the current directory would use: ['.ash.yml', '.ash.yaml', '.ash.json', 'ash.yml', 'ash.yaml', 'ash.json'] (each at the root, then in .ash/), then ['.ashrc.toml', '.ashrc.yaml', '.ashrc.yml', '.ashrc.json', 'ashrc.toml', 'ashrc.yaml', 'ashrc.yml', 'ashrc.json'] at the root, then the tool.ash table of pyproject.toml at the root; the first found is used. |
| `--config-overrides` | List[str] | [] |  | Configuration overrides specified as key-value pairs (e.g., 'global_settings.severity_threshold=LOW'), checked as a scan given the same --config-overrides would apply them. |
| `--source-dir` | str |  | ASH_SOURCE_DIR | The directory a scan would scan, as `ash scan --source-dir`: the config is discovered there unless --config names one, and a config inside it may only extend files inside it. Defaults to the current directory. |
| `--verbose`, `-v` | bool | False |  | Enable verbose logging |
| `--debug`, `-d` | bool | False |  | Enable debug logging |
| `--color` | bool | True |  | Enable/disable colorized output |

## Inspect Subcommands

### `ash inspect findings`

Interactively explore security findings.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--output-dir` | Path |  |  | Path to the output directory containing an ASH Aggregated Results JSON report file to analyze. |
| `--report-file` | str | `ash_aggregated_results.json` |  | Name of the report file to analyze. Defaults to 'ash_aggregated_results.json'. |
| `--config`, `-c` | Path |  | ASH_CONFIG | Path to the configuration file where suppressions should be saved. By default, ASH searches for ['.ash.yml', '.ash.yaml', '.ash.json', 'ash.yml', 'ash.yaml', 'ash.json'] (each at the root, then in .ash/), then ['.ashrc.toml', '.ashrc.yaml', '.ashrc.yml', '.ashrc.json', 'ashrc.toml', 'ashrc.yaml', 'ashrc.yml', 'ashrc.json'] at the root, then the tool.ash table of pyproject.toml at the root; the first found is used. With none found, suppressions go to a new .ashrc.yaml in the current directory. |

### `ash inspect sarif-fields`

Analyze SARIF fields across different scanners to understand their schema.

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--sarif-dir` | str |  |  | Directory containing SARIF files to analyze |
| `--output-dir` | str |  |  | Directory to write output files |

## MCP Tools

The ASH MCP server exposes the following tools for integration with AI assistants via the Model Context Protocol.

### `cancel_scan`

Cancel a running scan and stop it.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_id` | str | *required* | The scan ID to cancel |

### `check_installation`

Report whether ASH can scan, from each built-in scanner's dependency check.

### `clear_source`

Delete this session's delivered source tree and workspace.

### `diff_scan_results`

Compare two ash_aggregated_results.json files and return a structured diff.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `before_path` | str | *required* | Path to the baseline ash_aggregated_results.json file. |
| `after_path` | str | *required* | Path to the comparison ash_aggregated_results.json file. |

### `explain_finding`

Return structured details for a single finding by ID.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `finding_id` | str | *required* | The FlatVulnerability ID to look up (e.g. "bandit-B601-880359fd90e1"). |
| `results_path` | str |  | Optional path to the output directory containing |

### `get_config`

Get the resolved ASH config (defaults + user overrides merged).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config_path` | str |  | Optional explicit path to config file. If None, auto-discovers. |
| `raw` | bool | False | If True, returns the file's contents as written, without merging |
| `search_dir` | str |  | The directory the caller's scan will target |

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
| `actionable_only` | bool | False | If True, keep only the findings that make the scan exit 2. |

### `get_scan_summary`

Get a lightweight summary of scan results without detailed findings.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `output_dir` | str | `.ash/ash_output` | Path to the scan output directory (absolute path recommended) |

### `list_active_scans`

List this session's active and recent scans with their current status.

### `list_profiles`

List the config profiles the operator registered at server startup.

### `list_scanners`

List all registered ASH scanners with their metadata.

### `resolve_ash_workspace`

Resolve a VS Code workspace file into a scan plan without scanning anything.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `workspace_file` | str | *required* | Absolute path to the .code-workspace file. |
| `workspace_config` | str |  | Optional path to a workspace policy file. Must exist if |
| `allow_missing_projects` | bool | False | Mark project directories that are absent or |
| `config_overrides` | list |  | Optional list of `key=value` config overrides, applied to |
| `profile` | str |  | Name of a registered config profile to resolve under for this one |

### `run_ash_scan`

Start a security scan and return immediately.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `source_dir` | str |  | Path to the directory to scan. This should be the absolute path! |
| `severity_threshold` | str |  | The least severe finding that still counts as actionable: |
| `config_path` | str |  | Optional path to ASH configuration file |
| `clean_output` | bool | True | Hide the previous scan's results when this call starts the scan. |

### `run_ash_workspace_scan`

Scan every project in a VS Code workspace and return the per-project verdict.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `workspace_file` | str | *required* | Absolute path to the .code-workspace file. |
| `workspace_config` | str |  | Optional path to a workspace policy file. |
| `allow_missing_projects` | bool | False | Skip absent or unreadable project directories |
| `config_overrides` | list |  | Optional list of `key=value` config overrides. |
| `output_dir` | str |  | Where to write the workspace output tree. Defaults to |
| `scanners` | list |  | Restrict every project to these scanner names. |
| `excluded_scanners` | list |  | Exclude these scanners from every project. Takes |
| `offline` | bool | False | Run without network access. |
| `clean_output` | bool | True | Hide each project's previous results once the scan has its |
| `profile` | str |  | Name of a registered config profile to scan under for this one |

### `select_profile`

Bind one of the operator's registered config profiles to this session.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `profile_name` | str | *required* | Name the operator registered the profile under. |
| `patch_ops` | list |  | JSON-Patch operations to apply to the profile's config. |
| `override_yaml` | str |  | Complete ASH config YAML replacing the profile's. |

### `set_source_git`

Clone a repository into this session's workspace and make it the scan target.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | str | *required* | Remote URL to clone: https://, ssh:// or user@host:path. Refused if |
| `ref` | str |  | Optional branch, tag, or commit. Defaults to the remote's default |
| `ssh_key_id` | str |  | Must be omitted. The server registers no ssh keys, so any id |
| `depth` | int | 1 | Shallow-clone depth, a whole number from 1 to 1000. Defaults to 1. |

### `set_source_zip_chunk`

Upload one base64 chunk of a zipped source tree.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `upload_id` | str | *required* | Identifier you choose, scoping this one upload. |
| `sequence` | int | *required* | Zero-based ordinal of this chunk. |
| `data_b64` | str | *required* | Base64-encoded chunk payload. |
| `last` | bool | *required* | True on the final chunk. |

### `set_source_zip_finalize`

Verify an uploaded zip and extract it as this session's scan target.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `upload_id` | str | *required* | The identifier used for the preceding chunk calls. |
| `expected_sha256` | str | *required* | Hex sha256 of the complete zip. |

### `suggest_suppression`

Build a paste-ready AshSuppression entry for a specific finding.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `finding_id` | str | *required* | Stable hash ID of the finding (from get_scan_results or explain_finding). |
| `results_path` | str |  | Path to ash_aggregated_results.json. Defaults to |
| `expiration` | str |  | Expiration date in YYYY-MM-DD format. Defaults to 90 days from today. |
| `justification` | str |  | Human-readable reason for the suppression. |

### `validate_config`

Validate an ASH configuration file or content string.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config_content` | str |  | YAML/JSON string to validate. |
| `config_path` | str |  | Path to the config file to validate. |
