# Exit codes

The exit code of every `ash` command, with the conditions that produce it. For how to change the scan verdict, see [Set the gate](../how-to/set-the-gate.md).

On every command, a command-line usage error exits 5: an unknown option, subcommand, or argument; a value outside the choices an option takes (such as `--mode` or `--min-severity`) or a number that is not one; a missing required option; or a `--cli-json-input` document that ASH cannot read or use. `ash scan`, `ash build-image`, and `ash` with no subcommand reject an option or argument they do not define. An option given to `ash` before a subcommand is passed to the command named right after `ash`, and is a usage error when that command does not take it: `ash --source-dir . config get` exits 5, because `ash config` has no `--source-dir`, while `ash config get --source-dir .` works. Some names and paths that ASH cannot use are usage errors too, such as a `--scanners` list that names no scanner, a `--source-dir` that does not exist, or an `--output-dir` that ASH cannot create, while `ash report`, and a scan with `--use-existing`, exit 1 when they find no results to use. The tables below list both. Two `ash dependencies install` selections exit 2 instead: a `--tool` name that it has no plugin for, or whose plugin type `--plugin-type` leaves out, and a `--plugin-type` other than `converter`, `scanner`, or `reporter`. Usage errors have a code of their own so that a CI gate does not read a mistyped flag as a scan with findings.

## `ash scan` {#scan}

`ash` with no subcommand runs a scan and exits the same way.

| Code | Condition |
|---|---|
| 0 | No actionable findings; or findings, with `fail_on_findings` off. With `fail_on_incomplete_scanners` off, also an incomplete scan, including one in which no selected scanner had a file to scan. Also `--version`, and `--workspace` with `--dry-run`. |
| 1 | The scan is incomplete: a selected scanner ended ERROR or MISSING or lost some of its targets, no scanner ran (every selected scanner was SKIPPED, also when none of them had a file to scan), or a converter failed (with `fail_on_incomplete_scanners` on, the default) |
| 1 | A rule could not be evaluated, or a scanner tool ASH could not stop (also with `fail_on_incomplete_scanners` off) |
| 1 | A content database is past its age bound, with `content_db_staleness: fail` (the default). A scanner that passed against that database is recorded ERROR, and one that failed its threshold stays FAILED. This row sets the code for both, also with `fail_on_incomplete_scanners` off. |
| 1 | A report file a reporter is about to write, such as `reports/ash.sarif`, is a link ([Output files](output-files.md#links)) |
| 1 | `--use-existing` finds no `ash_aggregated_results.json` in the output directory. The command is well formed, but what it asks to use is not on disk, so this is the code `ash report` gives for missing results and not a usage error |
| 1 | Any other error during the scan |
| 2 | Actionable findings: an unsuppressed finding at or above its scanner's severity threshold, with `fail_on_findings` on and `--min-severity` met |
| 3 | The configuration cannot be used: the config file that `--config` or `ASH_CONFIG` names, or that discovery finds, does not exist, is not a regular file, cannot be read, is not UTF-8, or does not parse; it does not validate (an unknown key in a suppression, an ignore path, or a plugin's options makes it invalid, and so does one plugin's section written under two spellings, such as `detect-secrets` and `DETECT_SECRETS`); an override does not parse or does not validate; a config file an MCP client delivered sets a field the server's policy denies; or two plugins of one type that the scan loads have the same name or names that read as one ([Package a third-party plugin](../plugins/index.md#package-a-third-party-plugin)) |
| 3 | Refused before writing: the output directory, a directory on the way to it, or a directory or fixed-name file ASH writes in it, such as `reports` or `ash.log`, is a link ([Output files](output-files.md#links)). An output directory that is a symlink, or that a symlink below the source directory leads to, is refused this way in every mode, `--mode container` (also with `--no-run`) and `--mode nix` included, and before the check that the directory can be written, so nothing is made and the link's target keeps its entries. |
| 4 | A workspace error (see [Workspace mode](#workspace)), or `--dry-run`, `--allow-missing-projects`, or `--workspace-config` given without `--workspace` |
| 5 | A usage error. For a scan that includes: the source directory (`--source-dir` or `ASH_SOURCE_DIR`) does not exist, is not a directory, cannot be entered, or is not a valid path because it holds a NUL character; the output directory is not a directory, cannot be created, cannot be entered, or cannot be written, or it is not a valid path because it holds a NUL character, which a `--cli-json-input` document can carry and a command line cannot; with `--changed-files-only`, a `--base-ref` that git would read as something other than a revision, such as one that starts with `-`; `--changed-files-only`, or `ASH_CHANGED_FILES_ONLY`, with `--mode container`, which is refused before anything is built or run; the shard options are invalid or combined with `--workspace`; an `--output-formats` value is not a format name ASH accepts; no name in `--scanners` (or `ASH_SCANNERS`) matches a scanner; every scanner `--scanners` names is also excluded; every scanner `--scanners` names is left out of a `--python-only` run. ASH checks the `--scanners` names when the scan phase starts, after the converters have run and the output directory has been written. |
| 130 | Interrupted with Ctrl-C, in every mode, container and Nix mode included. ASH prints `ASH scan interrupted before it finished: there is no verdict, and the output directory may hold partial results.` on stderr, and no results table and no line saying the scan completed, in the console or in the scan's log file. Container and Nix mode first give the runtime or the Nix shell time to stop ([Container and Nix mode](#container)). |

A source or output directory that ASH refuses stops the scan before anything is created, with one of these lines on stderr, each naming the path as it was given:

- `Source directory does not exist: <path>`
- `Source directory is not a directory: <path>`
- `Source directory cannot be entered: <path>`
- `Source directory is not a valid path: <path>`
- `Output directory is not a directory: <path>`
- `Output directory is not a valid path: <path>`
- `Output directory cannot be created: <path> (<reason>)`
- `Output directory cannot be entered: <path>`
- `Output directory cannot be written: <path> (<reason>)`

The reason is the system's text for the error, such as `Not a directory` when a file is on the way to the output directory, or `Permission denied`. A NUL character in the path is shown as `\x00`, as in `Output directory is not a valid path: out\x00dir`. An output directory that does not exist is created. `--mode container` refuses the same directories, also with `--no-run`. So does `./ash`, which prints the same line after `ERROR: ` and exits 5, and so does `Invoke-ASH`, which sets `$LASTEXITCODE` to 5 and stops with the same line after `ERROR: `.

Only a scan with no config file at all uses the default configuration. A config file that is named or found and cannot be used, in any format, is exit 3, and so is an `extends` base that is missing or does not parse.

### Examples {#scan-examples}

In a repository where detect-secrets reports one finding, `SECRET-SECRET-KEYWORD` in `app.py`, a scan with only that scanner fails on it, with 2:

<!-- doctest: run expect-exit=2 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress
```

With `fail_on_findings` off, the same scan exits 0:

<!-- doctest: run expect-exit=0 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress --no-fail-on-findings
```

`--use-existing` with an output directory that holds no results exits 1, the same answer `ash report` gives for missing results. The command is well formed; what it asks to use is not on disk yet, so it is not a usage error:

<!-- doctest: run expect-exit=1 -->
```bash
ash --source-dir . --use-existing --output-dir no-scan-here
```

A `--source-dir` that does not exist is a usage error, 5:

<!-- doctest: run expect-exit=5 -->
```bash
ash --source-dir no-such-dir --scanners detect-secrets --offline --no-progress
```

<!-- doctest: output -->
```text
Source directory does not exist: no-such-dir
```

A threshold in lowercase does not validate, so the config is invalid, 3:

<!-- doctest: run expect-exit=3 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress \
  --config-overrides global_settings.severity_threshold=high
```

A `--config` that names no file exits 3 too:

<!-- doctest: run expect-exit=3 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress --config no-such-config.yaml
```

`--dry-run` without `--workspace` exits 4:

<!-- doctest: run expect-exit=4 -->
```bash
ash --source-dir . --dry-run
```

A mistyped `--min-severity` value is a usage error, 5, and nothing is scanned:

<!-- doctest: run expect-exit=5 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress --min-severity hihg
```

### Precedence {#scan-precedence}

ASH stops at the first of these that applies:

1. A usage error in the command line itself, such as an unknown option, an invalid value, or a missing required option: 5.
2. A check before scanning: the shard and workspace options, workspace resolution, the source directory, an output directory that is a link or is reached through one, then an output directory that is not a directory, cannot be entered or written, or has a file on the way to it, `--use-existing`, `--output-formats`, an output directory that cannot be created for another reason, such as a parent directory that cannot be written, the config, then the scanner selection, which ASH checks when the scan phase starts. Each exits as the table above says: 3, 4 or 5, except `--use-existing` with no results to use, which exits 1 as the table says, and which is checked before `--output-formats` and the config, so a command that also carries one of those mistakes reports the missing results first.
3. With `fail_on_incomplete_scanners` on: a selected scanner ERROR, MISSING, or with lost targets; then no scanner ran; then a failed converter: 1.
4. A rule could not be evaluated, or a scanner tool ASH could not stop: 1.
5. A stale content database under `content_db_staleness: fail`: 1.
6. `fail_on_findings` off: 0.
7. Actionable findings, counted against each scanner's own threshold, and at least one unsuppressed finding at or above `--min-severity`: 2.
8. Otherwise: 0.

`fail_on_findings` and `fail_on_incomplete_scanners` each come from the command-line flag, then the config, then their default (on). `--allow-stale-content-db` and `--no-allow-stale-content-db` replace the config's `content_db_staleness`.

### Container and Nix mode {#container}

In `--mode container` (and `ash build-image`) and `--mode nix`, ASH reads the results back on the host and computes the code by the rules above, applying `--min-severity` there. `--ignore-suppressions` reaches the scan inside the container and works there as in a local scan.

| Code | Condition |
|---|---|
| 0, 1, 2 | The verdict, from the results |
| 1, or the container runtime's code | Refused before a container started: no container runtime found, a non-numeric UID or GID, an invalid revision, no Dockerfile, or a failed image build |
| 3 | Refused before a container started: a path ASH would mount is not UTF-8 ([Mounts and network](../how-to/run-in-a-container.md#mounts)); a config file cannot be used, or would be mounted from a place the scanned repository chooses ([The config file](../how-to/run-in-a-container.md#config)); a config file reads a variable a container scan does not pass in; or, through `OCI_RUNNER_WRAPPER`, the variables a config reads cannot be passed in an env file; or the output directory is a symlink, or a symlink below the source directory leads to it (such as a committed `.ash` link, for the default `.ash/ash_output`), as in every mode ([`ash scan`](#scan)). Nothing is created or mounted, also with `--no-run`. `./ash` and `Invoke-ASH` refuse the same output directory with exit 3 |
| 1 | The results file is missing or does not parse |
| 0, or the build's code | `--no-run` |
| 130 | Interrupted with Ctrl-C. Outside Windows, ASH passes the interrupt to the container runtime or the Nix shell, unless the terminal already delivered it there, waits up to 5 seconds for it to stop, and then kills it; a second Ctrl-C during the wait kills it at once. On Windows, a Ctrl-C typed in the console reaches the container runtime as well, and ASH waits up to 5 seconds for it to stop, as above; without a console, ASH ends the runtime at once. A scan prints the interrupted-scan message above. `ash build-image` prints `ASH build-image interrupted before it finished.`, and, without `--no-run`, adds `: there is no verdict, and the output directory may hold partial results` before the period. |
| any other | The container exited with a code other than 0, 1, or 2 (for example 3, 4, 5, 125, 126, 127, or 137); ASH exits with the same code |
| 1 | Nix mode: `nix` is not installed |
| 3, 4, or 5 | Nix mode: the Nix shell wrote no results and exited with 3, 4, or 5, which means the ASH inside it refused the run before scanning; ASH exits with the same code. Any other code without results exits 1. |

### Sharded scans {#shards}

Each shard computes the verdict for its own scanners, so a shard with findings exits 2 and a shard with a MISSING scanner exits 1. The one difference is that a shard that ran no scanner does not fail for that reason. Gate the pipeline on [`ash merge`](#merge), not on the shards.

### Workspace mode {#workspace}

With `--workspace`, ASH scans each project and combines their verdicts. The first of these that applies wins: 3 (a project's config is invalid), then 1 (a project failed, is incomplete, or has a stale database), then 2 (a project has actionable findings at or above its threshold), then 0. Codes 4 and 5 are not part of that ranking: ASH gives them when it refuses the workspace before any project runs.

| Code | Condition |
|---|---|
| 3 | A project's config, or the `--config` file, cannot be used or is invalid, as for a scan; or two plugins of one type that the scan loads have the same name or names that read as one, as for a scan. ASH detects this before it scans anything, also with `--dry-run`. |
| 4 | The workspace file is missing or ambiguous (`--workspace auto` finds more than one); `--source-dir` is also given; the workspace policy file is not valid, including an unknown key in one of its suppressions or ignore paths; a project directory is missing and `--allow-missing-projects` is not set; or no project could be scanned |
| 5 | A usage error, including a `--scanners` selection that matches no scanner or that `--exclude-scanners` cancels. ASH refuses it once, before it scans any project. |
| 0 | `--dry-run`; or nothing was scanned because every project was skipped as unchanged, counting a missing project that `--allow-missing-projects` tolerated as neither scanned nor failed (it is listed in the results, not in the exit code) |

A project that is incomplete exits 1 even when it also has findings, as the same project scanned alone does. Workspace mode checks the same unconditional causes as a single scan: a rule a scanner could not evaluate, a scanner tool ASH could not stop, and a stale content database under a `fail` policy each fail the project whatever `fail_on_incomplete_scanners` says. One exception, and only in workspace mode: a stale database of a scanner that the workspace policy alone added (`additional_scanners`) with `policy_scanners_gate` off is listed in the project's `stale_content_databases` and does not fail it, as that scanner's missing tool and findings decide nothing either. The other two unconditional causes have no such exception: a rule that such a scanner could not evaluate, or its tool that ASH could not stop, still fails the project, whichever config asked for the scanner, because a rule that raised says nothing about compliance with it and a tool still running may write into the project's output after the verdict read it.

## `ash merge` {#merge}

| Code | Condition |
|---|---|
| 0, 1, 2 | The verdict over all shards, by the same rules as `ash scan`, including incompleteness, stale databases, and `--min-severity` |
| 1 | Refused: no shard index; results from a scan that was not sharded; a `--results` directory with no `ash_aggregated_results.json` at its top, in `ash_output/`, or in `.ash/ash_output/`, and none or more than one below it; a duplicated or mismatched shard; a results file that does not parse; a shard that completed none of its scanners; a report file it is about to write, such as `reports/ash.sarif`, is a link ([Output files](output-files.md#links)) |
| 3 | The output directory, a directory on the way to it, or a directory ASH writes in it, such as `reports`, is a link ([Output files](output-files.md#links)) |
| 3 | The configuration recorded in the shards reads a field that takes a fixed choice, a boolean, or a number from the environment, and neither `--config-overrides` nor the file `--config` names supplies the field ([Read values from the environment](../how-to/configure.md#environment)) |
| 3 | Two reporters that the merge loads have the same name or names that read as one, as for a scan |
| 5 | A usage error, including a missing `--results` or `--output-dir`, a `--results` path that does not exist or is neither a file nor a directory, and an invalid `--output-formats` or `--min-severity` value |
| 5 | An output directory it cannot use, refused as a scan refuses it ([`ash scan`](#scan)): it is not a directory, it cannot be created, entered, or written, or it is not a valid path because it holds a NUL character, which a `--cli-json-input` document can carry. The merge prints the scan's `Output directory` line for it, with the path as given, on standard output, where it prints its log, and creates nothing. An output directory that does not exist is created |

A shard whose scanner is ERROR only because its content database is stale counts as having completed that scanner: `ash merge` merges the shard and then exits 1 for the stale database.

A `--results` path that does not exist is a usage error:

<!-- doctest: run expect-exit=5 -->
```bash
ash merge --results no-such-shard --output-dir merged
```

## `ash report` {#report}

`ash report` never fails on findings.

| Code | Condition |
|---|---|
| 0 | The report was printed |
| 1 | No results to report on (no `ash_aggregated_results.json` in any of the places an output directory is searched; nothing is created, and the same code `--use-existing` gives a scan for the same reason); results that cannot be read; the reporter failed; an AWS reporter's pre-flight check refused, for a missing setting or for credentials it cannot find ([AWS reporters](../plugins/aws.md#ash-report)) |
| 3 | The output directory, a directory on the way to it, or `reports` in it is a link ([Output files](output-files.md#links)) |
| 3 | The `--config` file cannot be used or is invalid, as for a scan, including an option that a plugin loaded from `ash_plugin_modules` does not accept; an override is invalid; or the configuration recorded in the results reads a field that takes a fixed choice, a boolean, or a number from the environment, and neither `--config-overrides` nor `--config` supplies the field; or two reporters that the command loads have the same name or names that read as one, as for a scan |
| 5 | A results file in more than one of the places an output directory is searched (nothing is created, and an output directory under a directory ASH cannot search counts as one with no results); an output directory that is a file (`Output directory is not a directory:`), or a path the system cannot look up, such as one holding a NUL character (`Output directory is not a valid path:`), each with the path as given; an unknown `--format`, also when there are no results; an output directory that exists but cannot be entered (`Output directory cannot be entered:` and the path as given); any other usage error |

ASH checks the config first, then `--format`, then the results:

<!-- doctest: run expect-exit=5 -->
```bash
ash report --output-dir no-scan-here --format bogus
```

## `ash mcp` {#mcp}

| Code | Condition |
|---|---|
| 0 | The stdio transport's input closed, also while the server was writing to it; or the server was stopped with SIGTERM or SIGHUP: a stdio server on Linux and macOS, or an HTTP server with SIGHUP |
| 1 | The MCP dependencies are not installed, or an error stopped the server while it started or ran, on any transport, other than an HTTP server that fails to start (3). The error is printed on stderr, also with `--quiet`. |
| 3 | A `--profile` that cannot be registered: no `=`, a file that does not exist or does not load, an unknown top-level key, a name given twice, or a file kept where a client can write it: inside the MCP workspace root, other than a config the server wrote there itself, or inside a git checkout under a scan root `ASH_MCP_ALLOWED_ROOTS` grants. An `ASH_CONFIG` that names a path that is not a file, a file the server cannot read, or a config that does not load or validate, on every transport; an empty `ASH_CONFIG` counts as unset. Also when an HTTP server fails to start, for example because it cannot bind its port: the HTTP server exits 3 for that. |
| 5 | A usage error, such as an unknown option, a `--port` that is not a number, an invalid `--transport` or `ASH_MCP_TRANSPORT`, `--quiet` with `--verbose` or `--debug`, only one of `--auth-header-name` and `--auth-header-value`, or `--stateless-http` without the streamable-http transport. Also these refusals at startup: `--trust-upstream-session-id` anywhere other than `--transport streamable-http --stateless-http`; `--trust-upstream-host-check` on stdio, with a loopback `--host`, or with `--allowed-host`; a non-loopback `--host` with neither `--allowed-host` nor `--trust-upstream-host-check`; and a `--session-workspace-ttl` that is not a positive number of seconds, or is given on stdio |
| 130 | The server was stopped with Ctrl-C, on any transport |
| 143 | An HTTP server was stopped with SIGTERM: the HTTP server ends the process with the signal, which a shell reports as 128 + 15 |

A scan's own errors end that scan as failed, not the server. On Windows a stdio server has no SIGTERM handling: the process that ends it sets its exit code. Ctrl-C there ends a stdio server with 130 only once the client has closed the connection.

<!-- doctest: run expect-exit=5 -->
```bash
ash mcp --transport bogus
```

## `ash config` {#config}

| Command | Code | Condition |
|---|---|---|
| `ash config init` | 0 | The file was written |
| | 1 | The file exists and `--force` is not given. When neither `--config` nor `ASH_CONFIG` names the file, also when the directory already has another config source, which `--force` does not override. |
| `ash config get` | 0 | The resolved config was printed (the defaults, when no config file is found) |
| | 3 | The named config path does not exist, is a directory, or cannot be read; the config does not parse or does not validate; or an override does not validate |
| `ash config update` | 0 | The file was updated, no `--set` was given, or `--dry-run` was given with `--set` values it can apply |
| | 1 | No config file is found; the file is TOML, uses `extends` or `patch`, or reads values from the environment; it cannot be written |
| | 3 | The named config path does not exist, is a directory, or cannot be read; the file is not UTF-8, does not load, or does not validate; a `--set` value does not parse (no `=`, or nothing before it), starts with a top-level key the configuration does not have, or leaves a config a scan would refuse. `update` prints `Not updating <file>: ...` and leaves the file unchanged, also with `--dry-run`, and applies no other `--set` given with it. |
| `ash config validate` | 0 | A scan accepts the config, apart from the options of plugins loaded from `ash_plugin_modules`, which only a scan checks. Warnings may be printed, for example for a missing `project_name`, which a scan does not need, or for an ignore or suppression path that names an existing directory and matches no file in it ([Check a config](../how-to/configure.md#check)). |
| | 1 | No config file is found in the source directory and none is named: `validate` says so, and that a scan of that directory uses the default configuration. Also when an error occurred. |
| | 3 | The named config path does not exist, is a directory, or cannot be read. A scan refuses the config: it does not parse, it or an override does not validate (one plugin's section written under two spellings included), its `extends` chain does not resolve, or `ash_plugin_modules` names a module a scan refuses. `validate` imports no plugin module, so two plugins whose names read as one pass it. |
| | 5 | The source directory (`--source-dir` or `ASH_SOURCE_DIR`) does not exist, is not a directory, or cannot be entered, refused with the line a scan prints |
| `ash config lint` | 0 | A scan accepts the config (warnings and notes are allowed), apart from the options of plugins loaded from `ash_plugin_modules`. Also when a fix prompt was declined, if a scan accepts the file. |
| | 1 | No config file is found; `--fix` or `--fix-unused` refused to rewrite the file (a TOML file, `--fix-unused` on a JSON file, or `--fix` with something to fix on a file that reads values from the environment); an error that a scan accepts remains |
| | 3 | As for `validate`, also after a declined fix prompt. With `--fix`, the code describes the file after the fixes. |
| `ash config validate-plugin-dependencies` | 0 | The config resolves (`project_name` has a default, so the file does not need to set it) |
| | 1 | No config file is found |
| | 3 | The named config path does not exist, is a directory, or cannot be read, or the config does not resolve |
| `ash config wizard` | 0 | The file was written |
| | 1 | The file is TOML, uses `extends` or `patch`, or reads values from the environment; a prompt was aborted |
| | 3 | The file cannot be loaded |

The named config path is the one `--config`, `ASH_CONFIG`, or the path argument of `get`, `update`, and `validate-plugin-dependencies` gives. An `ASH_CONFIG` that names a file that does not exist exits 3 from `get`, `validate`, `lint`, and `validate-plugin-dependencies` even when `--config` or the path argument names a file that loads, since a scan refuses that pair too. [Configure ASH](../how-to/configure.md#check) explains what `validate`, `lint`, and `get` check.

`ash config init` refuses to add a second config source:

<!-- doctest: run expect-exit=1 -->
```bash
mkdir -p .ash && printf 'project_name: payments-api\n' > .ash/.ash.yaml
ash config init
```

A named config path that does not exist or is a directory exits 3 from every `ash config` command that reads a config:

<!-- doctest: run expect-exit=3 -->
```bash
ash config get --config no-such-config.yaml
```

<!-- doctest: run expect-exit=3 -->
```bash
ash config validate --config .ash
```

<!-- doctest: run expect-exit=3 -->
```bash
ash config lint --config no-such-config.yaml
```

<!-- doctest: run expect-exit=3 -->
```bash
ash config validate-plugin-dependencies --config no-such-config.yaml
```

So does an `ASH_CONFIG` that names one, beside a `--config` file that loads:

<!-- doctest: run expect-exit=3 -->
```bash
printf 'project_name: payments-api\n' > named.yaml
ASH_CONFIG=no-such-config.yaml ash config lint --config named.yaml
```

`ash config update` refuses a file that is not UTF-8 the same way, and leaves it unchanged:

<!-- doctest: run expect-exit=3 -->
```bash
printf '\377\376' > not-utf8.yaml
ash config update --config not-utf8.yaml --set fail_on_findings=false
```

A config without `project_name` is valid, with a warning:

<!-- doctest: run expect-exit=0 -->
```bash
printf 'global_settings:\n  severity_threshold: HIGH\n' > no-name.yaml
ash config validate --config no-name.yaml
```

A `--set` without `=` leaves the file unchanged and exits 3:

<!-- doctest: run expect-exit=3 -->
```bash
ash config update --set fail_on_findings
```

So does a `--set` whose top-level key the configuration does not have, such as the misspelled `fail_on_finding`. A top-level key may be written with `-` for `_`, as in a config file, so `--set fail-on-findings=false` sets `fail_on_findings`:

<!-- doctest: run expect-exit=3 -->
```bash
ash config update --set fail_on_finding=false
```

A config that a scan refuses exits 3 from `ash config validate`, here for the misspelled `rule_id`:

<!-- doctest: run expect-exit=3 -->
```bash
cat > misspelled.yaml <<'EOF'
project_name: payments-api
global_settings:
  suppressions:
    - path: app.py
      ruleId: SECRET-SECRET-KEYWORD
      reason: Fixture value, not a real password
EOF
ash config validate --config misspelled.yaml
```

## Other commands {#other}

| Command | Code | Condition |
|---|---|---|
| `ash dependencies install` | 0 | Without `--tool`: every tool that a scan with the same configuration on this platform would run is present after the install. With `--tool`: every named plugin's tool is present; the other plugins are not installed and do not count. |
| | 1 | For a plugin that counts (one such a scan would run, or with `--tool` one it names): an install command failed, the plugin raised an error, or its tool is still absent. Without `--tool`, a plugin the scan skips (disabled in the config, or not available on this platform) does not count. |
| | 2 | A `--tool` name matches no plugin, or names a plugin of a type that `--plugin-type` leaves out; or a `--plugin-type` is not `converter`, `scanner`, or `reporter`. ASH names the tool or the type, installs nothing, and starts no program. |
| | 3 | The config cannot be used or is invalid, as for a scan, or an override does not validate; or there is no usable home directory, so nowhere to keep install receipts, whatever `--bin-path` says: `HOME` is empty or relative, or unset with no absolute home in the passwd entry. Nothing is installed. The same code for a `--bin-path` (or `ASH_BIN_PATH`) directory that cannot be made, because a file is in the way or a directory it needs cannot be written to; an existing bin directory is accepted whether or not you can write to it. A `--tool` name that matches no plugin is refused first, with code 2 |
| `ash plugin list` | 0 | The lists were printed, also when a plugin module is skipped |
| | 1 | Any other error |
| | 3 | The config cannot be used or is invalid, as for a scan, or an override does not validate |
| `ash get-genai-guide` | 0 | The guide was written |
| | 1 | The installation has no readable copy of the guide; with `--from-github`, the download failed; or the output directory does not exist |
| `ash inspect findings` | 0 | Always, also when there are no results to show |
| `ash inspect sarif-fields` | 0 | The analysis was written |
| | 1 | No SARIF files were found, or a scanner's field is missing from the aggregated SARIF |

<!-- doctest: run expect-exit=2 -->
```bash
tool=not-a-tool
ash dependencies install --tool "${tool}"
```
