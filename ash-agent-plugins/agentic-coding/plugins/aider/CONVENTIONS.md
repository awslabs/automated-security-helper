# ASH Security Scanner

Run ASH (Automated Security Helper) security scans via MCP — Bandit, Semgrep, detect-secrets, Checkov, Grype, Syft, and more across Python, JS, IaC, and dependencies.

---

# ASH MCP security scanning workflow

ASH (Automated Security Helper) runs a set of security scanners over a project and combines their results. Its MCP server runs a scan in the background: you start it, poll it until it ends, then read the results. This skill assumes the server is connected; the plugin that ships this skill configures it.

The server scans on the machine it runs on, always in local mode, with the scanner tools installed there. The project's ASH config, such as `.ash/.ash.yaml`, chooses the scanners and thresholds. No tool argument does.

## Run a scan

1. Call `run_ash_scan` with `source_dir` set to the absolute path of the project. It returns at once with a `scan_id` and `status` `running`. Keep the `scan_id`.
2. Call `get_scan_progress` with that `scan_id` about every 5 seconds until `status` is `completed`, `incomplete`, `failed` or `cancelled`. Decide on `status`, not on `is_complete`: `is_complete` stays false for a failed or cancelled scan that left no results, so a loop that waits for it may never end.
3. Read the results from `output_directory`, the absolute path in the progress response. It is `.ash/ash_output` inside `source_dir`.

```text
run_ash_scan(source_dir="/absolute/path/to/project")
get_scan_progress(scan_id="<scan_id from run_ash_scan>")
```

| Final status | Meaning | What to do |
|--------------|---------|------------|
| `completed` | Every selected scanner ran. | Read the results. |
| `incomplete` | The scan finished and its results are readable, but a selected scanner did not run or did not finish. | Read the results, name each scanner in `incomplete_scanners` and its `reason`, and say the coverage is partial. |
| `failed` | The scan crashed or left no readable results. | Report `error_message`. |
| `cancelled` | The scan was cancelled. | Do not treat any results as final. |

Never report a project as clean unless the status is `completed` and there are no actionable findings. In the final progress response, `scanner_statuses` and `skipped_scanners` tell a scanner that ran and found nothing from one that never ran.

While the scan runs, tell the user its status. `completed_scanners` and `total_scanners` are not a percentage: `total_scanners` is 0 until the scanners start, and `completed_scanners` counts only scanners that passed.

## Read the results

Pass `output_directory` as `output_dir` to these tools:

- `get_scan_summary` returns the counts: `findings_summary` has the findings by severity, with `actionable` and `suppressed` totals, and `scanner_summary` has each scanner's status and counts.
- `get_scan_result_paths` returns the absolute path of every report under `files`. Read the findings from the `flat_json` one, `reports/ash.flat.json`: its `findings` list has one record per finding, with `id`, `severity`, `scanner`, `rule_id`, `file_path`, `line_start` and `is_suppressed`. `reports/ash.summary.md` is a summary to show the user.
- `get_scan_results` returns counts and per-scanner summaries, not findings. With `actionable_only` set, its `findings` list is always empty, whatever the scan found, so never take that list as a sign that the project is clean.

A finding that a scanner reports with no severity of its own, as detect-secrets does, counts as CRITICAL in the counts and shows as HIGH in `ash.flat.json`. Describe a finding with the severity in `ash.flat.json`, and decide whether the scan passes from the counts.

## Limits

- `run_ash_scan` takes no scanner list. To skip a scanner, the project's ASH config sets `scanners.<name>.enabled` to `false`. Its `severity_threshold` argument does not change what the scan reports; the config's thresholds decide which findings are actionable.
- `cancel_scan` marks a scan cancelled, but the scan keeps running and can still write to the output directory.
- The server keeps its list of scans in memory. After it restarts, `get_scan_progress` fails with `scan_not_found` for older scan ids; read their results from the output directory.
- `check_installation` reports that ASH runs. It does not check the scanner tools. A scanner whose tool is missing ends as MISSING, listed in `incomplete_scanners`.
- For a container scan, the user runs the ASH command line, `ash scan --mode container`, instead of the MCP server.

## Explain, suppress and compare

- `explain_finding` takes a finding's `id` from `ash.flat.json` and `results_path` set to the output directory. It returns the scanner's description, why the finding is or is not actionable, and the matched code. Two findings with the same rule and message share an `id`, so check that the location it returns is the one you meant.
- `suggest_suppression` takes the `id`, `results_path` set to the `ash_aggregated_results.json` file in the output directory, and the user's reason as `justification`. It writes nothing and returns an entry for `global_settings.suppressions` in the project's ASH config. Leave out its `client_supplied` key. Fix a finding before you suppress it, and suppress only with a reason the user agrees with.
- `diff_scan_results` compares two `ash_aggregated_results.json` files, `before_path` and `after_path`. Unless `run_ash_scan` gets `clean_output` false, a scan deletes the previous file in its output directory before it starts, so copy the file first.

The [tool reference](#ash-mcp-tool-reference) lists every tool and its parameters. [Troubleshooting](#ash-troubleshooting) covers the common failures.


---

## Reference

# ASH MCP Tool Reference

<!-- Generated by scripts/generate_mcp_tool_reference.py from the MCP server's
     registered tools and resources. Do not edit this file directly; edit the
     generator (prose and caveats live in its TOOL_NOTES table) and re-run it,
     then `agentic-plugins build` to propagate to every plugin backend. -->

The ASH MCP server exposes twenty-two tools and five resources.

## run_ash_scan

Starts a scan in the server process and returns a `scan_id` at once. The scan stops if the server process exits; over stdio, that is when the client disconnects.

<!-- doctest: options of=mcp.run_ash_scan -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `source_dir` | string \| null | not set | Absolute path to scan. When not set: the source delivered to this session with `set_source_git` or `set_source_zip_finalize`, or, for a client with no session, the server's working directory |
| `severity_threshold` | string | `"MEDIUM"` | Recorded with the scan and returned by `get_scan_progress`; it does not change which findings the scan reports |
| `config_path` | string \| null | not set | Custom config path. When not set: the config this session bound with `select_profile`, or else ASH's own discovery in the source directory |
| `clean_output` | boolean | `true` | Wipe stale reports before starting |

Output reports are written to `<source_dir>/.ash/ash_output/` — there is no parameter to override this. Scanner selection, mode, and other tuning live in `.ash/.ash.yaml`, not in tool arguments.

Returns:

<!-- doctest: config kind=other reason="example MCP tool response" -->
```json
{
  "success": true,
  "status": "running",
  "scan_id": "<uuid>",
  "progress": 0.0,
  "message": "Scan started, initializing scanners. Use get_scan_progress to track progress.",
  "directory_path": "<absolute path scanned>",
  "important": {
    "connection_management": "<server's polling guidance>",
    "next_steps": ["..."]
  }
}
```

The `directory_path` field tells you the resolved absolute path the server is scanning — derive `output_dir` for `get_scan_results` from this value (`<directory_path>/.ash/ash_output`) rather than constructing it independently.

**Heads-up:** the server's own docstring and the `important.next_steps` array suggest polling `progress['is_complete']`. Decide on `status` instead: `is_complete` can stay `False` for a cancelled or failed scan that writes no results file. (See `get_scan_progress` below.)

## get_scan_progress

Poll progress every 5 seconds until `status` is `completed`, `incomplete`, `failed`, or `cancelled`.

<!-- doctest: options of=mcp.get_scan_progress -->
| Param | Type | Notes |
|-------|------|-------|
| `scan_id` | string | From `run_ash_scan` |

Returns:

```text
{
  "scan_id": "...",
  "directory_path": "/path/to/scanned/project",
  "output_directory": "/path/to/.ash/ash_output",
  "start_time": "<iso8601>",
  "end_time": "<iso8601 | null>",
  "status": "pending | running | completed | incomplete | failed | cancelled",
  "severity_threshold": "MEDIUM",
  "config_path": "<path | null>",
  "warnings": [...],
  "error_message": "<str | null>",
  "is_complete": bool,
  "coverage_complete": "bool | null",
  "incomplete_scanners": [
    { "scanner": "grype", "status": "MISSING", "reason": "missing_dependencies", "detail": "MISSING" }
  ],
  "no_scanner_ran": bool,
  "incomplete_converters": [{ "converter": "...", "reason": "..." }],
  "unevaluated_rules": ["..."],
  "stale_content_databases": [{ "name": "grype-db", "scanner": "grype", "built": "<iso8601 | null>", "age": "...", "max_age": "...", "refresh": "..." }],
  "completed_scanners": int,
  "total_scanners": int,
  "total_findings": int,
  "severity_counts": { "critical": int, "high": int, "medium": int, "low": int, "info": int, "suppressed": int },
  "scanners": {
    "<scanner_name>": {
      "<target_type>": { ... per-scanner-target progress ... }
    }
  }
}
```

There is no overall percentage field. To compute progress, use `completed_scanners / total_scanners` — but **guard against `total_scanners == 0`** during the pre-flight phase (before any scanner has registered). Show "initializing" or 0% when `total_scanners` is zero.

There is no top-level `duration` field — derive elapsed time from `start_time` and `end_time` (or from current time while running).

**Decide on `status`, not `is_complete`.** `is_complete` is `True` for `completed` and `incomplete`, and for `failed` or `cancelled` once a results file exists in the output directory, which an earlier scan of the same directory may have left. Stop polling when `status` is `completed`, `incomplete`, `failed`, or `cancelled`. Polling on `is_complete` alone never ends for a cancelled or failed scan that writes no results file.

**`incomplete` is terminal, with partial coverage.** The run finished and its results are readable, but a selected scanner was `MISSING` or `ERROR` (or lost targets), no scanner reached a verdict, a converter did not run, a rule could not be evaluated, or a content database was past its declared age bound. `incomplete_scanners` names each scanner and why, and `stale_content_databases` each stale database. The findings are real but partial, so read them, and do not report the target as clean. `failed` means the run crashed or left no readable results. `coverage_complete` is `null` while running and for `failed` or `cancelled`; with `fail_on_incomplete_scanners: false` a scan is `completed` with `coverage_complete: false` when scanners did not run.

**Status enum:** the documented values are `pending | running | completed | incomplete | failed | cancelled`. The registry uses `pending` briefly while a scan is queued, transitions to `running` once execution begins, and may also expose the legacy `in_progress` string from older `ScanProgress` instances. Treat `pending`, `running`, and `in_progress` as equivalent "not done yet" states.

## get_scan_results

Fetch finalized results with filtering. Run only after `get_scan_progress` reports complete.

<!-- doctest: options of=mcp.get_scan_results -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `output_dir` | string | `".ash/ash_output"` | Absolute path strongly recommended; the server resolves relative paths against its own cwd, which usually isn't your project root |
| `filter_level` | string | `"full"` | `full`, `summary`, `minimal` |
| `scanners` | string | not set | Comma-separated subset; not set means every scanner |
| `severities` | string | not set | Comma-separated subset of `critical,high,medium,low,info,suppressed`; not set means every severity |
| `actionable_only` | boolean | `false` | Sets the suppressed counts to zero. The `findings` list it adds is always empty, because the response does not carry the SARIF it is built from |

With `filter_level` `full`, `raw_results` is the aggregated results document without its `sarif`, `cyclonedx` and `ash_config` sections; `summary` returns the metadata and the counts by severity and by scanner, and `minimal` the status. Individual findings are in the report files: `get_scan_result_paths` lists them, and the `flat-json` reporter, which is enabled by default, writes `reports/ash.flat.json` under `output_dir`.

`status` is `completed` or `incomplete`, decided by the same rule as the scan's exit code, with `coverage_complete` and `incomplete_scanners` as in `get_scan_progress`. An `incomplete` scan's findings are returned in full.

## get_scan_summary

Metadata and counts only — no individual findings. Cheap for quick health checks.

<!-- doctest: options of=mcp.get_scan_summary -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `output_dir` | string | `".ash/ash_output"` | Absolute path |

Returns total count, severity breakdown, scanner statuses.

## get_scan_result_paths

Returns file paths to all generated reports. Useful when you want to read HTML, SARIF, CSV, or markdown directly with file tools instead of pulling JSON over MCP.

<!-- doctest: options of=mcp.get_scan_result_paths -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `output_dir` | string | `".ash/ash_output"` | Absolute path |

Returns a dict mapping format names to absolute paths.

## list_active_scans

All scans the server tracks (active + recently completed).

No parameters. Returns a list of scan summaries.

## cancel_scan

Marks a running scan `cancelled`. It does not stop the scan: the scan keeps running in the server process and can still write its results, while its `status` stays `cancelled`.

<!-- doctest: options of=mcp.cancel_scan -->
| Param | Type | Notes |
|-------|------|-------|
| `scan_id` | string | The scan to mark cancelled |

Returns `success`, `status`, and `message`. A scan that has already finished is not changed, and the response has `success: false` and the scan's status.

## check_installation

Reports the version of the ASH package the MCP server runs. It does not run a scan or check that any scanner's tool is installed.

No parameters. Returns `version`, with `installed` and `ash_command_available` both `true` when the version could be read.

## clear_source

Delete this session's delivered source tree and workspace.

No parameters. Deletes this session's delivered source tree and workspace.

## diff_scan_results

Compare two ash_aggregated_results.json files and return a structured diff.

<!-- doctest: options of=mcp.diff_scan_results -->
| Param | Type | Notes |
|-------|------|-------|
| `before_path` | string | Path to the baseline ash_aggregated_results.json file. |
| `after_path` | string | Path to the comparison ash_aggregated_results.json file. |

## explain_finding

Return structured details for a single finding by ID.

<!-- doctest: options of=mcp.explain_finding -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `finding_id` | string | *required* | The FlatVulnerability ID to look up (e.g. "bandit-B601-deadbeef"). |
| `results_path` | string \| null | not set | Optional path to the output directory containing ash_aggregated_results.json. Defaults to <cwd>/.ash/ash_output. |

## get_config

Get the resolved ASH config (defaults + user overrides merged).

<!-- doctest: options of=mcp.get_config -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `config_path` | string \| null | not set | Optional explicit path to config file. If None, auto-discovers. |
| `raw` | boolean | `false` | If True, returns the user file contents without merging defaults. |

## list_profiles

List the config profiles the operator registered at server startup.

No parameters. Returns the config profiles the operator registered at server startup.

## list_scanners

List all registered ASH scanners with their metadata.

No parameters. Returns one entry per registered scanner with its config name, detected version, and whether it is enabled.

## resolve_ash_workspace

Resolve a VS Code workspace file into a scan plan without scanning anything.

<!-- doctest: options of=mcp.resolve_ash_workspace -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `workspace_file` | string | *required* | Absolute path to the .code-workspace file. |
| `workspace_config` | string \| null | not set | Optional path to a workspace policy file. Must exist if given; ASH will not fall back to searching for one. |
| `allow_missing_projects` | boolean | `false` | Mark project directories that are absent or unreadable as skipped instead of refusing the workspace. |
| `config_overrides` | array \| null | not set | Optional list of `key=value` config overrides, applied to each project's config so the reported threshold is the enforced one. |
| `profile` | string \| null | not set | Name of a registered config profile to resolve under for this one call, instead of whatever select_profile bound to this session. Call list_profiles to see what the operator registered. |

## run_ash_workspace_scan

Scan every project in a VS Code workspace and return the per-project verdict.

<!-- doctest: options of=mcp.run_ash_workspace_scan -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `workspace_file` | string | *required* | Absolute path to the .code-workspace file. |
| `workspace_config` | string \| null | not set | Optional path to a workspace policy file. |
| `allow_missing_projects` | boolean | `false` | Skip absent or unreadable project directories rather than refusing the workspace. |
| `config_overrides` | array \| null | not set | Optional list of `key=value` config overrides. |
| `output_dir` | string \| null | not set | Where to write the workspace output tree. Defaults to `<workspace root>/.ash/ash_output`. |
| `scanners` | array \| null | not set | Restrict every project to these scanner names. |
| `excluded_scanners` | array \| null | not set | Exclude these scanners from every project. Takes precedence over `scanners`. |
| `offline` | boolean | `false` | Run without network access. |
| `clean_output` | boolean | `true` | Remove each project's previous aggregated-results file first. |
| `profile` | string \| null | not set | Name of a registered config profile to scan under for this one call, instead of whatever select_profile bound to this session. An unknown name refuses the whole scan; running N repository scans under the default config because a profile name was misspelled, and reporting success, is exactly what the confinement refusal above exists to prevent. |

## select_profile

Bind one of the operator's registered config profiles to this session.

<!-- doctest: options of=mcp.select_profile -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `profile_name` | string | *required* | Name the operator registered the profile under. |
| `patch_ops` | array \| null | not set | JSON-Patch operations to apply to the profile's config. |
| `override_yaml` | string \| null | not set | Complete ASH config YAML replacing the profile's. |

## set_source_git

Clone a repository into this session's workspace and make it the scan target.

<!-- doctest: options of=mcp.set_source_git -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `url` | string | *required* | Repository URL |
| `ref` | string \| null | not set | Branch, tag, or commit; not set means the remote's default branch |
| `ssh_key_id` | string \| null | not set | Operator-registered key id for private repos; not set means no key |
| `depth` | integer | `1` | Clone depth; `0` for a full clone |

## set_source_zip_chunk

Upload one base64 chunk of a zipped source tree.

<!-- doctest: options of=mcp.set_source_zip_chunk -->
| Param | Type | Notes |
|-------|------|-------|
| `upload_id` | string | Caller-chosen id tying the chunks of one upload together |
| `sequence` | integer | Zero-based chunk index; chunks must arrive in order |
| `data_b64` | string | Base64 of this chunk's bytes |
| `last` | boolean | `true` on the final chunk |

Pair with `set_source_zip_finalize`, which verifies the reassembled archive against `expected_sha256` before extracting it. A chunked upload that is never finalized is not a scan target.

## set_source_zip_finalize

Verify an uploaded zip and extract it as this session's scan target.

<!-- doctest: options of=mcp.set_source_zip_finalize -->
| Param | Type | Notes |
|-------|------|-------|
| `upload_id` | string | The identifier used for the preceding chunk calls. |
| `expected_sha256` | string | Hex sha256 of the complete zip. |

## suggest_suppression

Build a paste-ready AshSuppression entry for a specific finding.

<!-- doctest: options of=mcp.suggest_suppression -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `finding_id` | string | *required* | Stable hash ID of the finding (from get_scan_results or explain_finding). |
| `results_path` | string \| null | not set | Path to ash_aggregated_results.json. Defaults to .ash/ash_output/ash_aggregated_results.json in cwd. |
| `expiration` | string \| null | not set | Expiration date in YYYY-MM-DD format. Defaults to 90 days from today. |
| `justification` | string \| null | not set | Human-readable reason for the suppression. |

## validate_config

Validate an ASH configuration file or content string.

<!-- doctest: options of=mcp.validate_config -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `config_content` | string \| null | not set | YAML/JSON string to validate. |
| `config_path` | string \| null | not set | Path to the config file to validate. |

## Resources

- `ash://exit-codes` — Return the meaning of each ASH exit code as JSON
- `ash://help` — Get help information about ASH usage
- `ash://schema/config` — Return the AshConfig JSON schema
- `ash://schema/suppression` — Return the AshSuppression JSON schema
- `ash://status` — Get the current status of ASH installation

Read these via the standard MCP resource read mechanism for context-free help.

## Severity levels

`CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO` > `SUPPRESSED`

`actionable_only=True` on `get_scan_results` sets the `SUPPRESSED` counts (false positives, accepted risks) to zero; the `findings` list it adds is always empty.


# ASH troubleshooting

## The agent has no ASH tools

The MCP server did not start. The plugin starts it with `uvx`, which needs uv on the PATH the agent sees, and network access to GitHub the first time it runs. To see the error, the user can run the same command in a terminal:

<!-- doctest: illustrative reason="installs ASH from GitHub, then starts the MCP server, which waits for a client on stdin" -->
```bash
uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.7.0 ash mcp
```

When the server starts, it waits for a client; Ctrl+C stops it. If ASH is already installed, the server command can be `ash` with the argument `mcp` instead. Desktop apps often see a shorter PATH than a shell, so an absolute path to `uvx` or `ash` can fix a server that starts in a terminal and not in the agent.

## Scanners are MISSING

`check_installation` checks ASH, not the scanner tools. A scanner whose tool is not installed ends as MISSING, and the scan ends `incomplete`. With the user's agreement, `ash dependencies install` installs the tools for the user that runs the server; then scan again. A tool installed only inside the scanned project does not count.

## The scan does not reach a final status

Poll `get_scan_progress` until `status` is `completed`, `incomplete`, `failed` or `cancelled`. `incomplete` is final. A loop that waits for `is_complete` alone does not end for a failed or cancelled scan that left no results.

ASH stops a scanner's tool after its `scan_timeout` option, 1800 seconds unless the project's ASH config sets `scanners.<name>.options.scan_timeout`. For a large project, scan a subdirectory, or disable the scanners you do not need in the config. `cancel_scan` does not stop a running scan; restarting the MCP server does, and the server then forgets its scans.

## No findings, but the project has problems

- `get_scan_results` does not list findings, and with `actionable_only` set its `findings` list is always empty. Read `reports/ash.flat.json` in the output directory.
- A scanner that did not run reports nothing. Check `incomplete_scanners` and `skipped_scanners` in the final progress response.
- Check which config the scan read. Without `config_path`, `run_ash_scan` uses the ASH config it finds in the project.

## `scan_target_not_permitted`

The server refuses to scan that directory. It always refuses system directories such as `/etc` and `/root`, and when `ASH_MCP_ALLOWED_ROOTS` is set in the server's environment it refuses everything outside the directories that variable names. Ask the user to scan another directory or to change the server's environment.

## `output_dir_not_permitted`

`.ash` or `.ash/ash_output` in the project is a symbolic link, and ASH does not write through one. Ask the user to replace it with a directory.

## A suppression does not apply

Suppressions go under `global_settings.suppressions` in the project's ASH config, and each entry needs `path` and `reason`. `path` is relative to the scanned directory, and a `path` that starts with `./` matches nothing. From its `expiration` date on, an entry no longer applies. `ash config get .ash/.ash.yaml` checks the config and exits with code 3, naming the field, when it is invalid. After the next scan, `reports/ash.unused-suppressions.json` lists the suppressions that matched no finding.


---

## Note

Aider does not support MCP servers. To run ASH security scans, invoke
the ASH CLI directly (`ash scan`) or use one of the MCP-supporting agents
(Claude Code, Codex, Cursor, Continue, Cline, etc.) for tool integration.
