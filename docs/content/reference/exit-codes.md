# Exit codes

The exit code of every `ash` command, with the conditions that produce it. For how to change the scan verdict, see [Set the gate](../how-to/set-the-gate.md).

On every command, a command-line usage error exits 2: an unknown option or subcommand, an invalid value for an option that takes a fixed set of values (such as `--mode`) or a number, or a missing required option. That is the same code `ash scan` uses for findings. Two exceptions: `ash scan` and `ash build-image` do not reject an option they do not define (`ash scan` ignores it), while `ash` with no subcommand rejects it with 2; and `--min-severity` does not check its value, so an unrecognized value acts like `low`.

## `ash scan` {#scan}

`ash` with no subcommand runs a scan and exits the same way.

| Code | Condition |
|---|---|
| 0 | No actionable findings; or findings, with `fail_on_findings` off. Also `--version`, and `--workspace` with `--dry-run`. |
| 1 | The scan is incomplete: a selected scanner ended ERROR or MISSING or lost some of its targets, no scanner ran, or a converter failed (with `fail_on_incomplete_scanners` on, the default) |
| 1 | A rule could not be evaluated |
| 1 | A content database is past its age bound, with `content_db_staleness: fail` (the default) |
| 1 | Refused before scanning: the source directory does not exist; `--use-existing` finds no results; the shard options are invalid or combined with `--workspace`; the output directory, a directory on the way to it, or a directory or file ASH writes in it is a link ([Output files](output-files.md#links)); no name in `--scanners` matches a scanner; every scanner `--scanners` names is also excluded |
| 1 | Any other error during the scan |
| 2 | Actionable findings: an unsuppressed finding at or above its scanner's severity threshold, with `fail_on_findings` on and `--min-severity` met |
| 2 | A usage error, including an invalid `--output-formats` value |
| 3 | The configuration is invalid: it does not validate, an override does not validate, or a config file an MCP client delivered sets a field the server's policy denies |
| 4 | A workspace error (see [Workspace mode](#workspace)), or `--dry-run`, `--allow-missing-projects`, or `--workspace-config` given without `--workspace` |
| 130 | Interrupted with Ctrl-C |

A config file that is named but missing, or a YAML or JSON config file that does not parse, is not exit 3: ASH logs a warning and scans with the default configuration. A TOML config file that does not parse, or an `extends` base that is missing or does not parse, is exit 3.

### Precedence {#scan-precedence}

ASH stops at the first of these that applies:

1. A usage error: 2.
2. A check before scanning: the shard and workspace options, workspace resolution, the source directory, `--use-existing`, the output directory, the config, then the scanner selection. Each exits as the table above says (1, 3, or 4).
3. With `fail_on_incomplete_scanners` on: a selected scanner ERROR, MISSING, or with lost targets; then no scanner ran; then a failed converter: 1.
4. A rule could not be evaluated: 1.
5. A stale content database under `content_db_staleness: fail`: 1.
6. `fail_on_findings` off: 0.
7. Actionable findings, counted against each scanner's own threshold, and at least one unsuppressed finding at or above `--min-severity`: 2.
8. Otherwise: 0.

`fail_on_findings` and `fail_on_incomplete_scanners` each come from the command-line flag, then the config, then their default (on). `--allow-stale-content-db` and `--no-allow-stale-content-db` replace the config's `content_db_staleness`.

### Container and Nix mode {#container}

In `--mode container` (and `ash build-image`) and `--mode nix`, ASH reads the results back on the host and computes the code by the rules above, applying `--min-severity` there. `--ignore-suppressions` has no effect in container mode: suppressions still apply.

| Code | Condition |
|---|---|
| 0, 1, 2 | The verdict, from the results |
| 1, or the container runtime's code | Refused before a container started: no container runtime found, a non-numeric UID or GID, an invalid revision, no Dockerfile, or a failed image build |
| 1 | The results file is missing or does not parse |
| 0, or the build's code | `--no-run` |
| any other | The container exited with a code other than 0, 1, or 2 (for example 3, 4, 125, 126, 127, or 137); ASH exits with the same code |
| 1 | Nix mode: `nix` is not installed |

### Sharded scans {#shards}

Each shard computes the verdict for its own scanners, so a shard with findings exits 2 and a shard with a MISSING scanner exits 1. The one difference is that a shard that ran no scanner does not fail for that reason. Gate the pipeline on [`ash merge`](#merge), not on the shards.

### Workspace mode {#workspace}

With `--workspace`, ASH scans each project and combines their verdicts. The highest of these wins: 3 (a project's config is invalid), then 2 (a project has actionable findings), then 1 (a project is incomplete or has a stale database), then 0.

| Code | Condition |
|---|---|
| 3 | A project's config is invalid. ASH detects this before it scans anything, also with `--dry-run`. |
| 4 | The workspace file is missing or ambiguous (`--workspace auto` finds more than one); `--source-dir` is also given; a project directory is missing and `--allow-missing-projects` is not set; or no project could be scanned |
| 0 | `--dry-run`; or nothing was scanned because every project was skipped as unchanged |

Because the combination puts 2 above 1, a project with findings and a MISSING scanner makes the workspace exit 2, where the same project scanned alone exits 1. Workspace mode does not check for rules that could not be evaluated.

## `ash merge` {#merge}

| Code | Condition |
|---|---|
| 0, 1, 2 | The verdict over all shards, by the same rules as `ash scan`, including incompleteness, stale databases, and `--min-severity` |
| 1 | Refused: no shard index; results from a scan that was not sharded; a `--results` path that does not exist; a duplicated or mismatched shard; a results file that does not parse; a shard that completed none of its scanners; a link at or in the output directory ([Output files](output-files.md#links)) |
| 2 | A usage error, including a missing `--results` and an invalid `--output-formats` value |

## `ash report` {#report}

`ash report` never fails on findings.

| Code | Condition |
|---|---|
| 0 | The report was printed |
| 1 | No results to report on; an unknown `--format`; the reporter failed; a link at or in the output directory ([Output files](output-files.md#links)) |
| 3 | The `--config` file is invalid |

## `ash mcp` {#mcp}

| Code | Condition |
|---|---|
| 0 | The stdio transport's input closed, or the server was stopped with Ctrl-C. On the stdio transport, also an error while the server runs: ASH logs it and exits 0. |
| 1 | The MCP dependencies are not installed, or an HTTP server failed to start |
| 2 | A usage error, such as an unknown option or a `--port` that is not a number; a scanner error that stops an HTTP server |
| 3 | Conflicting options: `--quiet` with `--verbose`, only one of `--auth-header-name` and `--auth-header-value`, an invalid `--transport`, or `--stateless-http` without the streamable-http transport. Also when the HTTP server cannot bind its port, which the HTTP server reports with 3. |

## `ash config` {#config}

| Command | Code | Condition |
|---|---|---|
| `ash config init` | 0 | The file was written |
| | 1 | The file exists and `--force` is not given |
| `ash config get` | 0 | The resolved config was printed (the defaults, when no config file is found) |
| | 1 | The named file does not exist |
| | 3 | The config does not parse or does not validate |
| `ash config update` | 0 | The file was updated, or no `--set` was given. Also when a `--set` value has no `=`: ASH prints an error and still rewrites the file. |
| | 1 | No config file found or the file does not exist; the file is TOML or uses `extends` or `patch`; it does not load; the result does not validate; it cannot be written |
| `ash config validate` | 0 | Every structural check passed (known top-level keys, no internal-only fields, path patterns). Values are not checked, so a file that passes can still make `ash scan` exit 3; `ash config get` checks values. |
| | 1 | The file does not exist, a check failed, or an error occurred |
| `ash config lint` | 0 | No errors (warnings and notes are allowed); or `--fix` or `--fix-unused` was given, even if errors remain; or a fix prompt was declined |
| | 1 | The file is not found; errors were found and no fix was requested; `--fix` on a TOML file; it stopped with a Python error, as it does on an unquoted `expiration` date |
| `ash config validate-plugin-dependencies` | 0 | The config resolves (`project_name` has a default, so the file does not need to set it) |
| | 1 | The named file does not exist, the config does not resolve, or no config file is found (`ASH_CONFIG` is not read) |
| `ash config wizard` | 0 | The file was written |
| | 1 | The file is TOML or uses `extends` or `patch`; a prompt was aborted |

[Configure ASH](../how-to/configure.md#check) explains what `validate`, `lint`, and `get` check.

## Other commands {#other}

| Command | Code | Condition |
|---|---|---|
| `ash dependencies install` | 0 | No install command failed. A tool that is still absent afterward does not change this, unless you named it with `--tool` or ASH ran no install command at all. |
| | 1 | An install command failed; a tool named with `--tool` is still absent; ASH ran no install command while a tool it needs is absent; a plugin failed; the config or an override is invalid |
| | 2 | An unknown `--tool` name |
| `ash plugin list` | 0 | The lists were printed, also when a `--config` file is missing (ASH warns and uses the defaults) or a plugin module is skipped |
| | 1 | Any error, such as an invalid config or override |
| `ash get-genai-guide` | 0 | The guide was written |
| | 1 | The download from GitHub failed, or the output directory does not exist |
| `ash inspect findings` | 0 | Always, also when there are no results to show |
| `ash inspect sarif-fields` | 0 | The analysis was written |
| | 1 | No SARIF files were found, or a scanner's field is missing from the aggregated SARIF |
