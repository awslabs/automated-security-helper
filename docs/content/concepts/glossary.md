# Glossary

Terms used across these docs, in alphabetical order. Each entry links to the page that explains it.

## Actionable finding

An unsuppressed finding at or above the severity threshold that applies to its scanner. Actionable findings are what `fail_on_findings` counts: any actionable finding makes the scan exit 2. See [Set the gate](../how-to/set-the-gate.md).

## Age bound

The age past which ASH treats a content database as too old to trust: 120 hours for grype's database, 24 hours for trivy's, and 30 days for the offline rulesets. See [Content databases](content-databases.md).

## Aggregated results

`ash_aggregated_results.json`, the file ASH writes at the root of the output directory. It holds the resolved configuration, with each value read from the environment recorded as its reference, a status row per scanner and converter, and the aggregated SARIF, and every reporter renders it. See [How ASH works](how-ash-works.md#the-results-model).

## Aggregated SARIF

The single SARIF run that every scanner's results are merged into, written as `reports/ash.sarif`. Findings are appended, not deduplicated. See [How ASH works](how-ash-works.md#findings-are-merged-not-deduplicated).

## AWS plugins

The `ash_aws_plugins` package, which ships with ASH and holds reporters that send results to AWS services. It loads only when the operator names it in a plugin module list; a repository config cannot. See [AWS reporters](../plugins/aws.md).

## Client-supplied

The mark ASH puts on a suppression or ignore path set by a config file an MCP client delivered, rather than by the operator. A client-supplied ignore path keeps the finding in the results as a suppressed finding instead of dropping it. See [Configuration trust model](trust-model.md#client-supplied).

## Community plugin

A plugin package that ships with ASH but is not built in, such as the trivy-repo, snyk-code, and ferret-scan scanners. `ash scan` loads it only when a plugin module list names it; for the MCP server, see [What a plugin can do](../plugins/index.md#what-a-plugin-can-do). See [Community plugins](../docs/plugins/community/index.md).

## Content database

Data a scanner downloads and matches code against: grype's and trivy's vulnerability databases, and the rulesets semgrep and opengrep use offline. Each has an age bound, and by default a scan fails when one is older than its bound. See [Content databases](content-databases.md).

## Converter

A plugin that runs in the convert phase and turns files scanners cannot read, such as archives and Jupyter notebooks, into files they can. Its output is scanned as the `converted` target. See [How ASH works](how-ash-works.md#phases) and the [converter reference](../reference/converters.md).

## Delivered tree

Source code an MCP client sent to an ASH MCP server, as a git URL or a zip upload. The server keeps it under the MCP workspace root, and its config files belong to the MCP-client tier. See [Run the MCP server](../how-to/mcp-server.md).

## Event subscriber

A plugin that runs code when a scan event happens, such as a phase starting or a scanner finishing. See [Subscribe to scan events](../plugins/event-subscribers.md).

## Exit code

The number `ash scan` returns: 0 for success, 1 for an incomplete or failed scan, 2 for actionable findings, 3 for a configuration it cannot use or an input it refuses before scanning, such as a linked output directory, 4 for a workspace error, and 5 for a usage error, such as an unknown option. See [Exit codes](../reference/exit-codes.md).

## Finding

One result a scanner reported, which is one result in the SARIF. Two scanners reporting the same problem produce two findings.

## Gate

The rules that turn a scan's results into its exit code: `fail_on_incomplete_scanners`, `content_db_staleness`, `fail_on_findings`, and the severity thresholds. See [Set the gate](../how-to/set-the-gate.md).

## Ignore path

An entry in `global_settings.ignore_paths`. Findings located in matching files are dropped from the results. When it has an expiration date, it stops applying on that date, as a suppression does. See [Suppressions, ignore paths, and scanner exclusions](suppressions.md).

## In-tree tool

A program found inside the scanned directory, for example in an in-repo `.venv/bin` or `node_modules/.bin`. ASH does not run in-tree tools unless the operator passes `--allow-in-tree-tools`, sets `ASH_ALLOW_IN_TREE_TOOLS`, or sets `allow_in_tree_tools` in the `--cli-json-input` document. `ash mcp` never runs them. See [Manage scanner tools](../docs/advanced-usage.md#tools-inside-the-scanned-directory).

## Incomplete scan

A scan in which a selected scanner is MISSING or ERROR, no scanner ran, or a converter could not convert all of its inputs. With the default `fail_on_incomplete_scanners`, an incomplete scan exits 1 whatever it found. See [Set the gate](../how-to/set-the-gate.md).

## Inline suppression

A comment in the source that suppresses a finding on its line: ASH's `ash-ignore` and `ash-ignore-next-line`, or a scanner's own syntax such as bandit's `# nosec`. See [Suppressions, ignore paths, and scanner exclusions](suppressions.md).

## MCP client

A program that uses the ASH MCP server, such as an AI coding agent or an IDE. Files it delivers to the server form the MCP-client trust tier. See [Run the MCP server](../how-to/mcp-server.md) and [Configuration trust model](trust-model.md).

## MCP workspace root

The directory where the ASH MCP server keeps each session's delivered source and config: `ASH_MCP_WORKSPACE_ROOT`, else `$XDG_CACHE_HOME/ash-mcp`, else `~/.cache/ash-mcp`. See [Configuration trust model](trust-model.md#tiers).

## MISSING

The status of a scanner that was selected but did not run, because its tool was not found or was found only inside the scanned directory, or because it cannot run offline, as npm-audit cannot. The reason is in the scanner's `missing_reason`. A MISSING scanner makes the scan incomplete. See [Troubleshoot](../how-to/troubleshoot.md).

## Offline mode

A scan with `--offline` or `ASH_OFFLINE` set: every scanner runs in its offline mode, except npm-audit, which does not run offline, and ASH downloads and installs nothing. Content databases must already be in the cache. See [Run ASH offline](../how-to/run-offline.md).

## Operator

The person or pipeline running ASH. The operator owns the command line, the environment, and config files outside every git checkout and the scanned directory, and is the only tier that may grant sandbox access or choose where ASH's AWS reporters send results. See [Configuration trust model](trust-model.md).

## Output directory

The directory ASH writes its results, reports, and logs to: `--output-dir`, else `.ash/ash_output` inside the scanned directory. ASH leaves it out of every scan, apart from the files git tracks in it. See [Output files](../reference/output-files.md) and [How ASH works](how-ash-works.md#how-scanners-run).

## Phase

One stage of a scan: convert, scan, or report, run in that order, plus the optional inspect phase. See [How ASH works](how-ash-works.md#phases).

## Plugin module

A Python module that ASH imports to register plugins, named in `ash_plugin_modules`, `--config-overrides`, `--ash-plugin-modules`, `ASH_PLUGIN_MODULES`, or the Python API's `ash_plugin_modules` argument. It runs inside ASH's own process, outside the scanner sandbox. See [Plugins](../plugins/index.md).

## Reporter

A plugin that renders the aggregated results in one format and writes it to the `reports/` directory. See the [reporter reference](../reference/reporters.md).

## Repository config

An ASH config file inside a git checkout or inside the scanned directory, such as the `.ash/.ash.yaml` ASH discovers in the repository, or a config kept in an ops repository of its own. It cannot grant sandbox access, load ASH's off-host plugin packages, or choose where ASH's AWS reporters send results. See [Configuration trust model](trust-model.md).

## Run mode

Where a scan runs: `local` (the default), `container`, `nix`, or `precommit`, chosen with `--mode`. See [How ASH works](how-ash-works.md#phases).

## Sandbox grant

A setting that gives sandboxed scanners more than the default policy: `sandbox.network_scanners`, `sandbox.extra_read_paths`, `sandbox.read_path_scanners`, `sandbox.env_scanners`, or `sandbox.environment`. Only the operator may grant. See [Scanner sandbox](sandbox.md#grants).

## Scanned directory

The directory a scan runs over: `--source-dir`, the working directory, or a workspace's root. A config file inside it is a [repository config](#repository-config), and for the tool files you name ASH also looks at the [scanned tree](#scanned-tree) around it.

## Scanned tree

The outermost git checkout at or above the scanned directory, or the scanned directory itself when it is not in a checkout. ASH treats every file inside it as written by the repository being scanned, so a tool file you name there is refused for the scanners that do not allow one. For every restricted setting a config file makes, a config file inside any git checkout, the scanned one or a separate one such as an ops repository, is a [repository config](#repository-config). See [Configuration trust model](trust-model.md#scanned-tree).

## Scanner

A plugin that runs a security tool against a target and returns its results as SARIF. See the [scanner reference](../reference/scanners.md).

## Scanner exclusion

A scanner's own option that keeps files away from it, such as bandit's `excluded_paths` or checkov's `skip_path`. The scanner never sees the files, so nothing about them reaches the results. See [Suppressions, ignore paths, and scanner exclusions](suppressions.md).

## Scanner sandbox

An operating-system confinement around the processes a scanner starts through ASH, with limited reads and writes, a filtered environment, and no network unless the scanner needs one; how strict it is depends on the backend. Off by default. See [Scanner sandbox](sandbox.md).

## Scanner status

The result ASH records for each scanner and target. PASSED: it ran and found nothing actionable. FAILED: it ran and found actionable findings. ERROR: ASH tried to run it and it failed, or its tool could not start as asked. MISSING: it was selected but could not run. SKIPPED: it was not selected or was excluded, `--python-only` left it out, it does not support this platform, or it had nothing to scan. See [How ASH works](how-ash-works.md#the-results-model).

## Severity threshold

The least severe level that counts as actionable: `global_settings.severity_threshold`, `MEDIUM` by default, or a scanner's own `severity_threshold` option, which replaces it for that scanner. See [Set the gate](../how-to/set-the-gate.md).

## Shard

One of several scans of the same repository that each run a share of the scanners, combined afterward with `ash merge`. See [Scale to large repositories](../how-to/scale-large-repos.md).

## Suppression

An entry in `global_settings.suppressions`, or an `ash-ignore` comment, that keeps a finding in the results but marks it suppressed, with a reason. Suppressed findings do not count toward the gate. See [Suppressions, ignore paths, and scanner exclusions](suppressions.md).

## Target

What a scanner scans: `source`, the scanned directory, or `converted`, the files the converters produced. See [How ASH works](how-ash-works.md#phases).

## Trust tier

The owner ASH assigns to a piece of configuration: operator, repository, or MCP client. The tier decides which settings the configuration may make. See [Configuration trust model](trust-model.md#tiers).

## Workspace

A set of projects scanned together in one run, defined by a VS Code `.code-workspace` file, from the CLI or over MCP. See [Scale to large repositories](../how-to/scale-large-repos.md).
