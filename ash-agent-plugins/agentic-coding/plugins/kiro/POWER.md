---
name: "ash-security-scanner"
displayName: "ASH Security Scanner"
description: "Run ASH (Automated Security Helper) security scans via MCP — Bandit, Semgrep, detect-secrets, Checkov, Grype, Syft, and more across Python, JS, IaC, and dependencies."
keywords: ["security-scan", "vulnerability-scan", "ash", "sast", "sca", "checkov", "bandit", "semgrep", "grype"]
author: "AWS Labs"
---

# ASH MCP security scanning workflow

ASH (Automated Security Helper) combines code, infrastructure, secrets, and dependency scanners behind one MCP interface. Its MCP server runs a scan in the background: you start it, poll it until it ends, then read the results. This skill assumes the server is connected; the plugin that ships this skill configures it.

The server scans on the machine it runs on, always in local mode, with the scanner tools installed there. The project's ASH config, or the config profile the session selected, chooses the scanners and the severity thresholds. Use `list_scanners` to inspect the installed scanner catalog. No tool argument chooses scanners, and `run_ash_scan`'s `severity_threshold` can only make the config's threshold stricter.

## Run a scan

1. Call `run_ash_scan` with `source_dir` set to the absolute path of the project. It returns at once with a `scan_id` and `status` `running`. Keep the `scan_id`.
2. Call `get_scan_progress` with that `scan_id` about every 5 seconds until `is_complete` is true. It is true for every way a scan ends: `status` is then `completed`, `incomplete`, `failed`, or `cancelled`.
3. When `results_available` is true, read the results from `output_directory`, the absolute path in the progress response. It is `.ash/ash_output` inside `source_dir`.

### Step 1 — Start the scan

Call `run_ash_scan` with the absolute path to the project. The call returns immediately with a `scan_id`.

<!-- doctest: illustrative reason="calls the MCP tools, which need a client connected to ash mcp" -->
```python
run_ash_scan(
    source_dir="/absolute/path/to/project",
    config_path=None,  # Optional path to .ash.yaml
    clean_output=True,
)
```

Leave `severity_threshold` unset: the scan then uses the config's `global_settings.severity_threshold`. The argument (`ALL | LOW | MEDIUM | HIGH | CRITICAL`) can only tighten that threshold for one scan, never loosen it — pass it (e.g. `"HIGH"`) only when the user asks for a stricter level. For a looser level, lower the setting in `.ash/.ash.yaml` and re-scan.

Returns a dict with `scan_id`, `status: "running"`, `directory_path` (the resolved absolute scan root), and an `important.next_steps` block. **Always store the `scan_id`** — every subsequent call needs it.

After `failed` or `cancelled`, `results_available` is false: do not report results for that scan. Once ASH has put the previous scan's results back in the output directory, `output_holds_previous_results` is true.

Poll until `progress['is_complete']` is `true`, as the server's `important.next_steps` block says, and then read `status`; see Step 2.

The MCP server always runs scans in local mode: on the server's own machine, with the scanner tools installed there, and never in a container. For container or precommit modes, use the ASH CLI directly. Scanner selection lives in `.ash/.ash.yaml`, not in tool parameters.

## Read the results

Pass `output_directory` as `output_dir` to these tools:

- `get_scan_summary` returns the counts: `findings_summary` has the findings by severity, with `actionable` and `suppressed` totals, and `scanner_summary` has each scanner's status and counts.
- `get_scan_result_paths` returns the absolute path of every report under `files`. Read the findings from the `flat_json` one, `reports/ash.flat.json`: its `findings` list has one record per finding, with `id`, `severity`, `scanner`, `rule_id`, `file_path`, `line_start`, and `is_suppressed`. `reports/ash.summary.md` is a summary to show the user.
- `get_scan_results` returns counts and per-scanner summaries. With `actionable_only` set, a response at the default `filter_level`, `full`, also has a `findings` list of the actionable findings, the unsuppressed ones at or above the threshold their scanner was judged by, each with `rule_id`, `severity`, `scanner`, `file_path`, and its lines, but no `id`. Take the `id` that `explain_finding` and `suggest_suppression` need from `ash.flat.json`.

Stop polling when `is_complete` is `true`. It is `true` for every ending: `status` is then one of `completed | incomplete | failed | cancelled`, and `results_available` says whether `get_scan_results` can read the results (`completed` and `incomplete`). Typical scans take 30-120 seconds.

For progress display, use `finished_scanners / total_scanners` (`completed_scanners` counts only scanners that PASSED) — but check `total_scanners > 0` first (it's zero during pre-flight before any scanner registers; show "initializing" in that case). The response also includes `severity_counts` and per-scanner breakdown to surface in user-facing updates.

- `run_ash_scan` takes no scanner list. To skip a scanner, the project's ASH config sets `scanners.<name>.enabled` to `false`. Its `severity_threshold` argument makes the config's `global_settings.severity_threshold` stricter for that scan, never looser: `LOW` over a configured `MEDIUM` makes LOW findings actionable, and `CRITICAL` changes nothing. It tightens a scanner's own `severity_threshold` option the same way. Every finding is reported either way.
- A scan runs inside the server process and stops if the server exits. Over stdio, the server exits when the agent disconnects from it.
- `cancel_scan` stops a running scan: no further scanner, phase, or reporter starts, so a scan canceled before its report phase writes no reports, and `ash_aggregated_results.json` is not written after the cancel. Previous results that the output directory held are put back in place of the results it wrote, and its log, `ash.log`, stays, while an `ash.log.jsonl` already there is left as it was. With none to put back, what it wrote before it stopped stays, but a cancel during the report phase removes that phase's reports, all but `reports/ash.unused-suppressions.md`. The status is `cancelled` at once. Until the scan has stopped, up to about 10 seconds, or until the scan it waits for ends if it was queued behind another scan of the session, a new scan of the same directory is refused as still stopping.
- The server keeps its list of scans in memory. After it restarts, `get_scan_progress` fails with `scan_not_found` for older scan ids; read their results from the output directory.
- `check_installation` reports the ASH version and whether each built-in scanner's tool is installed: `ready` is false when a scanner that ASH enables by default cannot run and no scan will install its tool, and `missing_dependencies` names those scanners. It does not read the project's config, so a scanner the project turns off can be listed. It installs and downloads nothing. When the tool of a scanner that ASH installs with uv is missing, the first scan installs it if the server is online and has uv; such a scanner is listed in `installs_on_first_scan` and counts toward `ready`, and otherwise it is in `missing_dependencies`. Offline, semgrep is also missing when it has no rules cache. A scanner that has files to scan and whose tool is missing ends as MISSING, listed in `incomplete_scanners`.
- The server's operator limits how many scans it holds at once, running or waiting (`max_concurrent_scans`, 3 by default), and how long one may run (`scan_timeout_seconds`, 1800 by default). A scan over the first limit is refused with an `error` that names it; start it again when a scan has finished. A scan over the second is stopped and ends `failed`.
- For a container scan, the user runs the ASH command line, `ash scan --mode container`, instead of the MCP server.

## Explain, suppress, and compare

- `explain_finding` takes a finding's `id` from `ash.flat.json` and `results_path` set to the output directory. It returns the scanner's description, why the finding is or is not actionable, and the matched code.
- `suggest_suppression` takes the `id`, `results_path` set to the `ash_aggregated_results.json` file in the output directory, and the user's reason as `justification`. It writes nothing and returns an entry for `global_settings.suppressions` in the project's ASH config. Leave out its `client_supplied` key. Fix a finding before you suppress it, and suppress only with a reason the user agrees with.
- `diff_scan_results` compares two `ash_aggregated_results.json` files, `before_path` and `after_path`. A scan replaces the previous file in its output directory once it has results of its own, so copy the file first.

| User goal | Filter combination |
|-----------|-------------------|
| "How bad is it?" | `filter_level="summary"` + `actionable_only=True` |
| "Show me the critical issues" | `filter_level="full"` + `severities="critical,high"` |
| "Audit Bandit only" | `scanners="bandit"` + `filter_level="full"` |
| "Generate exec summary" | Use `get_scan_result_paths`, then read `ash.summary.md` |

<!-- doctest: illustrative reason="calls the MCP tools, which need a client connected to ash mcp" -->
```python
get_scan_results(
    output_dir="/absolute/path/to/project/.ash/ash_output",
    filter_level="summary",
    severities="critical,high",
    actionable_only=True,
)
```

For HTML/SARIF/CSV reports, prefer `get_scan_result_paths` and read the files directly with native file tools — it avoids piping large payloads through MCP.

## Tool inventory

For full parameter details, see [tool-reference.md](#ash-mcp-tool-reference).

- `run_ash_scan` — Start a scan asynchronously
- `get_scan_progress` — Poll progress (call every 5s)
- `get_scan_results` — Fetch filtered results
- `get_scan_summary` — Counts only, no findings
- `get_scan_result_paths` — File paths to all reports
- `list_active_scans` — All current/recent scans
- `cancel_scan` — Stop a running scan
- `check_installation` — Verify ASH can scan, and which scanner tools are missing

## Choosing scanners

ASH runs all nine scanners by default. To run only a subset, edit `.ash/.ash.yaml` at the project root before scanning — `run_ash_scan` does not accept a scanners argument. To filter results post-scan, use the `scanners` parameter on `get_scan_results`.

For result-time filtering by scanner:

- **Python issues** → `scanners="bandit,semgrep"`
- **Secrets only** → `scanners="detect-secrets"`
- **IaC review** → `scanners="checkov,cfn_nag,cdk-nag"`
- **Dependencies** → `scanners="grype,npm-audit"`
- **SBOM generation** → `scanners="syft"`

## When something goes wrong

See [troubleshooting.md](#ash-troubleshooting) for the common failures: connection timeouts, empty results, stuck scans, container/Docker issues, suppression rules not applying.

The fast checks: scan never starts → run `check_installation` first. Scan returns no findings → ask for `filter_level="full"` with `actionable_only=True`, which is the only response with a `findings` list, and widen `severities`. The list holds the actionable findings only, those at or above the scan's severity threshold and not suppressed; the files `get_scan_result_paths` names have the rest. Stale progress visibility → you weren't polling every 5 seconds.

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
| `source_dir` | string \| null | not set | Absolute path to scan. When not set: the tree this session delivered with `set_source_git` or `set_source_zip_finalize`. With none delivered, a call with no session id (stdio) scans the server's working directory, and a call with a session id is refused |
| `severity_threshold` | string \| null | not set | Least severe finding that counts as actionable, any case; it can make the config's `global_settings.severity_threshold` stricter for this scan, never looser |
| `config_path` | string \| null | not set | Custom config path. When not set: the profile this session bound with `select_profile`, else the config ASH discovers in the source directory, else the file `ASH_CONFIG` names in the server's environment, else the built-in defaults |
| `clean_output` | boolean | `true` | Set the previous scan's results in the output directory aside as soon as the scan is registered; with `false`, the scan's own set-up does it a moment later. Either way they are deleted once the scan has results of its own, and put back if it fails or is canceled. A refused call leaves the previous results as they were |

Output reports are written to `<source_dir>/.ash/ash_output/` — there is no parameter to override this. Scanner selection, mode, and other tuning live in the project's ASH config, not in tool arguments.

Returns:

<!-- doctest: config kind=mcp-response of=mcp.run_ash_scan -->
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

Poll `get_scan_progress` until `is_complete` is `true`, then read `status`. `is_complete` is `true` for every ending, including `failed` and `cancelled`. (See `get_scan_progress` below.)

**A refused config keeps its own `error_type`.** The scan does not start, and the response is `success: false` with one of these `error_type` values and the reason in `error`:

- `config_input_not_permitted`: `config_path`, or a base its `extends` chain names, is outside the directories this session may read a config from.
- `config_check_failed`: the check of the config sources in the scan target could not finish (an unreadable entry, a link loop), so the scan was not started. The config was not found to be outside the permitted roots -- that case is `config_input_not_permitted` -- so check the config files in the target for unreadable entries and link loops.
- `config_field_denied`: a config file an MCP client delivered or named sets a field the session's runtime-override policy denies. `error` names each field and why.
- `config_policy_unreadable`: that policy cannot be established, for example because the profile the session bound is no longer registered. `error` starts with `A config an MCP client delivered cannot be checked:`.
- `config_env_not_resolved`: a file of the config uses an `!ENV` tag, or a plain value that starts with a `${VAR}` or `${VAR:default}` reference, where none is resolved. For a remote caller that is any file the operator did not set aside (outside the directories `ASH_MCP_ALLOWED_CONFIG_ROOTS` names, other than the profile files the server writes in the calling session's `config/` directory), the scan target's own config included, and every base such a file extends; for a stdio caller, a file a client delivered. The server's own config, the file `ASH_CONFIG` names outside the MCP workspace root and each registered profile, is not refused. `error` names the file and the line or key.

The target and source checks have their own `error_type` values too (`scan_target_not_permitted`, `output_dir_not_permitted`, `no_source_delivered`, `session_source_mismatch`, `delivered_source_missing`, `invalid_session_id`). A directory that already has a scan is refused with `error_type: MCPResourceError` and `error_category: resource_exhausted`; `error` says the directory `already has an active scan`, or, for a scan that was cancelled or stopped at its timeout and has not finished stopping, `has a scan that is still stopping`. That `error_type` is the exception's class name, and an unexpected error while the scan is being started arrives as `MCPResourceError` too, with `error_category: unexpected_error`, so `MCPResourceError` alone does not prove a deliberate refusal: branch on `error_category`. The server's `max_concurrent_scans` limit is refused the same way (`resource_exhausted`); its `context` holds `max_concurrent_scans`: wait for a running scan to finish, then retry. The busy-directory refusal's `context` names the running scan's `scan_id` only when the scan is this session's: poll `get_scan_progress` with it, or `cancel_scan` it if it is no longer needed (`list_active_scans` lists this session's scans). Without a `scan_id`, another session's scan holds the directory and the server does not name it: wait and retry, or scan another directory. After a `cancel_scan` of that directory the refusal repeats until the scan has stopped (see `cancel_scan`): retry after a few seconds. Four more refusals carry their own `error_type`: `committed_output_files` (a file git tracks in `.ash/ash_output` where the scan writes, or that check could not finish), `session_identity_required` (the caller has no session the server issued, so a scan it could neither follow nor stop is not started), `session_scan_limit` (this session is already running `max_concurrent_scans_per_session` scans: retry once one has finished, or `cancel_scan` one) and `source_delivery_busy` (the session's delivered source is being changed: retry after the change finishes). Any other reason the scan could not be started returns `error_type: scan_start_failure`, and an unexpected error returns the exception's class name. Branch on `error_type` and `error_category`, never on the text of `error`.

On failure, `error_type` is one of `bound_profile_unavailable`, `committed_output_files`, `config_env_not_resolved`, `config_field_denied`, `config_input_not_permitted`, `config_policy_unreadable`, `delivered_source_missing`, `invalid_session_id`, `no_source_delivered`, `output_dir_not_permitted`, `output_dir_not_usable`, `scan_start_failure`, `scan_target_not_permitted`, `session_identity_required`, `session_scan_limit`, `session_source_mismatch`, `session_workspace_busy`, `source_delivery_busy` and `source_dir_not_usable`, or the class name of an exception.

## get_scan_progress

Poll progress every 5 seconds until `is_complete` is `true`, then read `status`: `completed`, `incomplete`, `failed`, or `cancelled`. The scan continues server-side independently of polling.

<!-- doctest: options of=mcp.get_scan_progress -->
| Param | Type | Notes |
|-------|------|-------|
| `scan_id` | string | From `run_ash_scan` |

Returns:

<!-- doctest: config kind=mcp-response of=mcp.get_scan_progress -->
```text
{
  "success": true,
  "scan_id": "...",
  "directory_path": "/path/to/scanned/project",
  "output_directory": "/path/to/.ash/ash_output",
  "start_time": "<iso8601>",
  "end_time": "<iso8601 | null>",
  "status": "pending | running | completed | incomplete | failed | cancelled",
  "severity_threshold": "<the threshold the scan was judged by; null until it finishes when none was named>",
  "requested_severity_threshold": "<the threshold the request named | null>",
  "config_path": "<path | null>",
  "warnings": [...],
  "error_message": "<str | null>",
  "exit_code": "<int | null>",
  "exit_code_meaning": "<str | null>",
  "is_complete": bool,
  "results_available": bool,
  "output_holds_previous_results": bool,
  "output_superseded": bool,
  "superseded_by": ["<scan_id>"],
  "coverage_complete": "bool | null",
  "incomplete_scanners": [
    { "scanner": "grype", "status": "MISSING", "reason": "missing_dependencies", "detail": "MISSING" }
  ],
  "no_scanner_ran": bool,
  "incomplete_converters": [{ "converter": "...", "reason": "...", "failed_input_kinds": ["..."] }],
  "unevaluated_rules": ["..."],
  "stale_content_databases": [{ "name": "grype-db", "scanner": "grype", "built": "<iso8601 | null>", "age": "...", "max_age": "...", "refresh": "..." }],
  "could_not_stop": [{ "scanner": "...", "reason": "..." }],
  "completed_scanners": int,
  "finished_scanners": int,
  "total_scanners": int,
  "scanner_status_counts": { "passed": int, "failed": int, "skipped": int, "running": int, "pending": int },
  "scanner_statuses": { "<scanner_name>": { "status": "PASSED | FAILED | ERROR | MISSING | SKIPPED", "excluded": bool, "dependencies_satisfied": bool } },
  "skipped_scanners": [{ "scanner": "grype", "status": "MISSING", "reason": "missing_dependencies | excluded_by_configuration | skipped" }],
  "total_findings": int,
  "severity_counts": { "critical": int, "high": int, "medium": int, "low": int, "info": int, "suppressed": int, "unknown": int },
  "scanners": {
    "<scanner_name>": {
      "<target_type>": { ... per-scanner-target progress ... }
    }
  },
  "timestamp": "<iso8601>",
  "operation": "get_scan_progress"
}
```

There is no overall percentage field. To compute progress, use `finished_scanners / total_scanners`: `finished_scanners` counts every scanner that has ended, whatever its status, and `completed_scanners` only the ones that PASSED. `scanner_status_counts` splits them into `passed`, `failed` (FAILED or ERROR), `skipped` (MISSING or SKIPPED), `running`, and `pending`. **Guard against `total_scanners == 0`** during the pre-flight phase (before any scanner has registered). Show "initializing" or 0% when `total_scanners` is zero.

There is no top-level `duration` field; derive elapsed time from `start_time` and `end_time` (or from current time while running).

**`is_complete` is `true` once the scan has ended**, whatever the ending: `completed`, `incomplete`, `failed` or `cancelled`. It is decided by the scan's state alone, never by a results file on disk, which can be a previous scan's. `results_available` is `true` for `completed` and `incomplete`, the scans whose results `get_scan_results` can read, and `false` for one of them whose results file cannot be read (the scan ended without writing its final results, or the file is not valid JSON): `error_message` then names the file and `coverage_complete` is `null`.

**A later scan can take the output tree over.** `output_superseded` is `true` once a later scan of the same directory has written `output_directory`; `superseded_by` lists those scans' ids, oldest first, and is empty otherwise. Nothing below is read from the files then: this scan's results are gone, and `get_scan_results` on that directory reads the newest scan's. `exit_code` and `exit_code_meaning` are the ASH exit code of a run that ended with one and its documented meaning, `null` for every other ending and while the scan runs.

**A failed or cancelled scan leaves the previous scan's results in place.** ASH puts them back in `output_directory`, and `output_holds_previous_results` is then `true` and the scanner fields are empty, because those files are not this scan's. `get_scan_results` on that directory reads the previous scan's results.

**`incomplete` is terminal, with partial coverage.** The run finished and its results are readable, but a selected scanner was `MISSING` or `ERROR` (or lost targets), no scanner reached a verdict, a converter did not run or could not convert some of its inputs, a rule could not be evaluated, or a content database was past its declared age bound. `incomplete_scanners` names each scanner and why, and `stale_content_databases` each stale database. The findings are real but partial, so read them, and do not report the target as clean. `failed` means the run crashed, left no readable results, or ran past the server's `scan_timeout_seconds`. `coverage_complete` is `null` while running and for `failed` or `cancelled`; with `fail_on_incomplete_scanners: false` a scan is `completed` with `coverage_complete: false` when scanners did not run.

**Status enum:** the documented values are `pending | running | completed | incomplete | failed | cancelled`, the registry entry's own state and nothing else. The registry uses `pending` briefly while a scan is queued and `running` once execution begins; treat both as "not done yet", and read `is_complete` rather than comparing the string.

On failure, `error_type` is one of `invalid_session_id`, `scan_not_found` and `session_identity_required`, or the class name of an exception.

## get_scan_results

Fetch finalized results with filtering. Run only after `get_scan_progress` reports complete.

<!-- doctest: options of=mcp.get_scan_results -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `output_dir` | string | `".ash/ash_output"` | Absolute path strongly recommended; the server resolves relative paths against its own cwd, which usually isn't your project root |
| `filter_level` | string | `"full"` | `full`, `summary`, `minimal` |
| `scanners` | string \| null | not set | Comma-separated subset; not set means every scanner |
| `severities` | string \| null | not set | Comma-separated subset of `critical,high,medium,low,info,suppressed`; not set means every severity |
| `actionable_only` | boolean | `false` | Keep only the actionable findings, the ones behind exit code 2: unsuppressed and at or above the severity threshold the scan was judged by (a scanner's own where its config sets one). Drop the rest and add `findings`, a flat list of them that honors `scanners` and `severities` (`full` level only) |

With `filter_level` `full`, `raw_results` is the aggregated results document without its `sarif`, `cyclonedx`, and `ash_config` sections; `summary` returns the metadata and the counts by severity and by scanner, and `minimal` the status. Individual findings are in the report files: `get_scan_result_paths` lists them, and the `flat-json` reporter, which is enabled by default, writes `reports/ash.flat.json` under `output_dir`.

`status` is `completed` or `incomplete`, decided by the same rule as the scan's exit code, with `coverage_complete` and `incomplete_scanners` as in `get_scan_progress`. An `incomplete` scan's findings are returned in full.

On failure, `error_type` is `invalid_session_id`, or the class name of an exception.

## get_scan_summary

Metadata and counts only — no individual findings. Cheap for quick health checks.

<!-- doctest: options of=mcp.get_scan_summary -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `output_dir` | string | `".ash/ash_output"` | Absolute path |

Returns total count, severity breakdown, scanner statuses.

On failure, `error_type` is `invalid_session_id`, or the class name of an exception.

## get_scan_result_paths

Returns file paths to all generated reports. Useful when you want to read HTML, SARIF, CSV, or markdown directly with file tools instead of pulling JSON over MCP.

<!-- doctest: options of=mcp.get_scan_result_paths -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `output_dir` | string | `".ash/ash_output"` | Absolute path |

Returns `output_dir`, `reports_dir` and `files`, a dict keyed by format name (`sarif`, `flat_json`, `html`, `csv`, `markdown`, `text`, `ocsf`, `cyclonedx`, `junit_xml`, `gitlab_sast`, `aggregated_results`) whose values are objects with the absolute `path`, whether the file `exists`, and its `size_bytes`; a report the scan did not write is listed with `exists: false`. When the output directory holds a `scanners/` tree, `scanners_dir` and `scanner_results` (per scanner, per target) are added.

On failure, `error_type` is one of `DirectoryNotFound`, `invalid_session_id` and `scan_target_not_permitted`, or the class name of an exception.

## list_active_scans

This session's scans, active and recently completed. Only scans this session started are listed; another session's scans are not visible, and the statistics count only this session's.

No parameters. Returns a list of scan summaries.

On failure, `error_type` is one of `invalid_session_id` and `session_identity_required`, or the class name of an exception.

## cancel_scan

Stops a running scan. The scanner tool running at the time is stopped with every process it started (SIGTERM, then SIGKILL after 10 seconds). The scan halts at its next cancel check, and no further scanner, phase, or reporter starts, so a scan canceled before its report phase writes no reports. Work that is not waiting on a child process, such as a scanner parsing its tool's output, can still finish and write under `scanners/` or `converted/`, but `ash_aggregated_results.json` is not written after the cancel. When the output directory held a previous scan's results, they are put back in place of every result the canceled scan wrote; its log, `ash.log`, stays, and an `ash.log.jsonl` already there is left as it was. With no previous results, what the scan wrote before it stopped stays, except that a cancel during the report phase removes the reports that phase wrote and every other file a reporter wrote beside them, `reports/ash.unused-suppressions.md` included.

<!-- doctest: options of=mcp.cancel_scan -->
| Param | Type | Notes |
|-------|------|-------|
| `scan_id` | string | The scan to cancel |

Returns `success`, `status`, and `message`. The status is `cancelled` at once. A running scan stops within about 10 seconds; one still waiting for another scan of its session stops when that scan ends. Until it has stopped, `run_ash_scan` refuses another scan of the same directory as still stopping, and the scan counts against `max_concurrent_scans`. A scan that has already ended is not changed, and the response has `success: false` and the scan's status. For a `run_ash_workspace_scan`, `cancel_scan` takes one project's scan id and stops that project, which ends `failed`; the other projects carry on.

On failure, `error_type` is one of `invalid_session_id` and `session_identity_required`, or the class name of an exception.

## check_installation

Reports whether ASH can scan: its version and, for each built-in scanner, whether its tool can run. Enabled means enabled in ASH's defaults: the call reads no project's config and checks no plugin scanner. It runs each scanner's dependency check, which can start the tool, so it takes several seconds, and it installs and downloads nothing. The tool of a scanner that ASH installs with uv is installed when `uv tool list` lists it, or when its executable is on `PATH` or in a directory ASH also searches, such as `~/.ash/bin`. A scanner whose tool is not, when the server is online and has uv, is listed in `installs_on_first_scan`, because the first scan installs it with uv, which needs network access. Offline, or without uv, it is listed in `missing_dependencies`. Offline, semgrep is also missing when it has no rules cache.

No parameters. Returns `installed` (at least one enabled scanner can run, or will once the first scan installs its tool), `ready` (every enabled scanner can run or will), `version`, `scanners` (each scanner's `name`, `enabled`, `dependencies_satisfied`, `installs_on_first_scan`, and `version`), `installs_on_first_scan`, `missing_dependencies` and `undetermined_dependencies` (the enabled scanners whose tool is missing and that a scan cannot install, or whose check could not run), and `ash_command_available` (whether an `ash` executable is on `PATH`, which the server does not need).

On failure, `error_type` is `invalid_session_id`, or the class name of an exception.

## clear_source

Delete this session's delivered source tree and workspace.

No parameters. Deletes this session's delivered source tree and workspace.

Refused while a scan of this session is running: `success: false`, `error_type: source_delivery_busy`. Clear again once the scan ends. Entries the server cannot delete (files another account owns) stay on disk; the session's delivered source is forgotten either way.

On failure, `error_type` is one of `invalid_session_id`, `session_identity_required` and `source_delivery_busy`, or the class name of an exception.

## diff_scan_results

Compare two ash_aggregated_results.json files and return a structured diff.

<!-- doctest: options of=mcp.diff_scan_results -->
| Param | Type | Notes |
|-------|------|-------|
| `before_path` | string | Path to the baseline ash_aggregated_results.json file. |
| `after_path` | string | Path to the comparison ash_aggregated_results.json file. |

On failure, `error_type` is `invalid_session_id`, or the class name of an exception.

## explain_finding

Return structured details for a single finding by ID.

<!-- doctest: options of=mcp.explain_finding -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `finding_id` | string | *required* | The FlatVulnerability ID to look up (e.g. "bandit-B601-880359fd90e1"). |
| `results_path` | string \| null | not set | Optional path to the output directory containing ash_aggregated_results.json. Defaults to <cwd>/.ash/ash_output. |

On failure, `error_type` is `invalid_session_id`, or the class name of an exception.

## get_config

Get the resolved ASH config (defaults + user overrides merged).

<!-- doctest: options of=mcp.get_config -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `config_path` | string \| null | not set | Optional explicit path to config file. If None, auto-discovers. |
| `raw` | boolean | `false` | If True, returns the file's contents as written, without merging defaults or reading the environment. A value the config's loader would read from the environment (an `!ENV` value, or an unquoted `${VAR:default}`) comes back as `!ENV ` and the reference, never as its value; a quoted string that only looks like a reference comes back as written. |
| `search_dir` | string \| null | not set | The directory the caller's scan will target (scan_directory's directory_path). With config_path None it is where the config is discovered; with a named config_path it is the target the file is judged for, so the answer refuses exactly what a scan of that target refuses -- an entry such a scan drops with a warning never refuses the answer. Without it, a named file is judged for this session's delivered source, or else the server's working directory. |

A config this session may not read, or one a client delivered that the server refuses, returns `success: false` with `error_type` `config_input_not_permitted`, `config_field_denied`, `config_policy_unreadable` or `config_env_not_resolved`, as `run_ash_scan` does for the same file.

On failure, `error_type` is one of `bound_profile_unavailable`, `config_env_not_resolved`, `config_field_denied`, `config_input_not_permitted`, `config_policy_unreadable`, `invalid_session_id`, `plugin_module_refused`, `scan_target_not_permitted`, `session_workspace_busy` and `source_dir_not_usable`, or the class name of an exception.

## list_profiles

List the config profiles the operator registered at server startup.

No parameters. Returns the config profiles the operator registered at server startup, each with `ash mcp --profile NAME=path/to/ash.yaml` (repeatable). A client cannot register one; an empty list means the operator registered none.

On failure, `error_type` is the class name of an exception.

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
| `profile` | string \| null | not set | Name of a registered config profile to resolve under for this one call, instead of whatever select_profile bound to this session. Call list_profiles to see what the operator registered. The fields the profile sets are final for every project, and a project's own config fills the rest. |

A workspace policy file, named or found in the workspace file's directory or its `.ash` directory, is used only when it is in a directory `ASH_MCP_ALLOWED_CONFIG_ROOTS` names; any other refuses the workspace with exit code 4, or with exit code 3 when a client delivered it and it sets a field the server's policy denies.

On failure, `error_type` is one of `config_env_not_resolved`, `config_input_not_permitted`, `environment_value_in_longer_string`, `invalid_session_id`, `output_dir_not_usable` and `session_identity_required`, or the class name of an exception.

## run_ash_workspace_scan

Scan every project in a VS Code workspace and return the per-project verdict.

<!-- doctest: options of=mcp.run_ash_workspace_scan -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `workspace_file` | string | *required* | Absolute path to the .code-workspace file. |
| `workspace_config` | string \| null | not set | Optional path to a workspace policy file. |
| `allow_missing_projects` | boolean | `false` | Skip absent or unreadable project directories rather than refusing the workspace. |
| `config_overrides` | array \| null | not set | Optional list of `key=value` config overrides. |
| `output_dir` | string \| null | not set | Where to write the workspace output tree. Defaults to `<workspace root>/.ash/ash_output`. Refused when it, a directory or file ASH writes in it, or a project's `projects/<key>` is a symlink. |
| `scanners` | array \| null | not set | Restrict every project to these scanner names. |
| `excluded_scanners` | array \| null | not set | Exclude these scanners from every project. Takes precedence over `scanners`. |
| `offline` | boolean | `false` | Run without network access. |
| `clean_output` | boolean | `true` | Hide each project's previous results once the scan has its directory. Either way they are put back for a project whose scan does not finish. A scan refused because a project already has a scan touches nothing in any project's output. |
| `profile` | string \| null | not set | Name of a registered config profile to scan under for this one call, instead of whatever select_profile bound to this session. An unknown name refuses the whole scan; running N repository scans under the default config because a profile name was misspelled, and reporting success, is the outcome a whole-workspace refusal exists to prevent, as one project outside the permitted roots refuses the whole workspace. The fields the profile sets are final for every project, and a project's own config fills the rest. Needs a session: refused (error_type session_identity_required) for a caller with no session the server issued, because the profile is materialized into the caller's session workspace. |

A workspace policy file, named or found in the workspace file's directory or its `.ash` directory, is used only when it is in a directory `ASH_MCP_ALLOWED_CONFIG_ROOTS` names; any other refuses the workspace with exit code 4, or with exit code 3 when a client delivered it and it sets a field the server's policy denies.

On failure, `error_type` is one of `config_env_not_resolved`, `config_input_not_permitted`, `environment_value_in_longer_string`, `invalid_session_id`, `output_dir_not_usable`, `session_identity_required`, `session_scan_limit` and `source_delivery_busy`, or the class name of an exception.

## select_profile

Bind one of the operator's registered config profiles to this session.

<!-- doctest: options of=mcp.select_profile -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `profile_name` | string | *required* | Name the operator registered the profile under. |
| `patch_ops` | array \| null | not set | JSON-Patch operations to apply to the profile's config. |
| `override_yaml` | string \| null | not set | Complete ASH config YAML replacing the profile's. |

On failure, `error_type` is one of `environment_value_in_longer_string`, `invalid_session_id`, `session_identity_required` and `session_workspace_busy`, or the class name of an exception.

## set_source_git

Clone a repository into this session's workspace and make it the scan target.

<!-- doctest: options of=mcp.set_source_git -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `url` | string | *required* | Repository URL |
| `ref` | string \| null | not set | Branch, tag, or commit; not set means the remote's default branch |
| `ssh_key_id` | string \| null | not set | Leave it out: the server registers no SSH keys, so any value is refused |
| `depth` | integer | `1` | Clone depth, a whole number of commits from 1 to 1000 |

Refused while a scan of this session is running, because the clone would replace the tree and config files that scan is reading. The response is `success: false`, `error_type: source_delivery_busy`, and `error` set to `a scan of this session is running; change the delivered source after it finishes`. Deliver the source again once `get_scan_progress` reports a terminal status.

A refusal or a git failure returns `success: false` with an `error_type`: `clone_url_not_permitted` (a url beginning with `-` or using the `ext::` transport, a url holding a control character or a lone surrogate, or a url whose host cannot be read), `clone_ref_not_permitted` (a ref beginning with `-` or holding a control character or a lone surrogate), `invalid_clone_depth` (below 1 or above 1000; the limit is on how much history is fetched), `invalid_session_id`, `local_clone_source_refused` (a local path or `file://` url, which would read the server's own filesystem), `clone_host_not_permitted` (the host is not in `ASH_MCP_GIT_ALLOWED_HOSTS`), `ssh_key_not_registered` (an `ssh_key_id` was named), `clone_timed_out` (git ran past its time limit and was stopped), `git_clone_failed` or `git_checkout_failed` (git's own message is in `error`; `git_clone_failed` also covers a git that is not on `PATH` or cannot be started), or `session_workspace_unavailable` (the session's workspace could not take the clone: a directory of it could not be created, the previously delivered source could not be moved aside for it, or the clone could not be moved into place; each move is tried a few times before it fails). The clone is made beside the delivered source and replaces it only once it has worked, so a delivery that fails for any of these reasons, or is refused, leaves the previously delivered source in place, and `run_ash_scan` with no `source_dir` scans it. A partial clone that cannot be fully deleted stays beside the source, logged, for the next delivery to delete, and the error returned is still git's own. The one exception is a clone that could not be moved into place after the previous source had been moved aside and could not be put back: the recorded source then names a path that is gone, and `run_ash_scan` with no `source_dir` answers `delivered_source_missing` until a source is delivered again; that next delivery puts the previous source back first. A `session_workspace_unavailable` that names a refused rename can be retried with the same call: the refusal is usually a program holding a handle inside a tree (a virus scanner, a file indexer), and it passes.

A re-delivery needs room for both trees at once, because the new clone is made beside the delivered source, which is deleted only after it. When the disk is short, call `clear_source` first to free the delivered one. A clone, fetch or checkout that fails for want of space returns `git_clone_failed` or `git_checkout_failed` with git's own message, and that advice added when the session has a delivered source to free.

On failure, `error_type` is one of `clone_host_not_permitted`, `clone_ref_not_permitted`, `clone_timed_out`, `clone_too_large`, `clone_tree_unreadable`, `clone_url_not_permitted`, `git_checkout_failed`, `git_clone_failed`, `invalid_clone_depth`, `invalid_session_id`, `local_clone_source_refused`, `session_identity_required`, `session_workspace_unavailable`, `source_delivery_busy` and `ssh_key_not_registered`, or the class name of an exception.

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

When the session's workspace directory cannot be created, both upload tools return `success: false` with `error_type` `session_workspace_unavailable`.

While the server removes the session's workspace for being unused longer than its time to live, `set_source_zip_chunk` returns `success: false` with `error_type` `session_workspace_busy`. Send the upload again from its first chunk.

On failure, `error_type` is one of `invalid_session_id`, `session_identity_required`, `session_workspace_busy` and `session_workspace_unavailable`, or the class name of an exception.

## set_source_zip_finalize

Verify an uploaded zip and extract it as this session's scan target.

<!-- doctest: options of=mcp.set_source_zip_finalize -->
| Param | Type | Notes |
|-------|------|-------|
| `upload_id` | string | The identifier used for the preceding chunk calls. |
| `expected_sha256` | string | Hex sha256 of the complete zip. |

Refused while a scan of this session is running, for the same reason as `set_source_git`: `success: false`, `error_type: source_delivery_busy`, and `error` set to `a scan of this session is running; change the delivered source after it finishes`. `set_source_zip_chunk` is not refused, so the chunks can be sent while the scan runs and the upload finalized after it ends.

A finalize that cannot deliver returns `success: false` with an `error`. Its `error_type` is `session_workspace_unavailable` when the session's workspace could not take the tree: a directory of it could not be created, the previous tree could not be renamed aside (nothing is deleted where it stands), or the extracted one could not be moved into place, whatever the operating system error was. The previous tree stays delivered and the uploaded zip is kept, so the same call can be sent again; when the previous tree could not be put back either, `run_ash_scan` with no `source_dir` answers `delivered_source_missing`. A checksum mismatch, an upload that never received its last chunk, or an archive the limits refuse returns `error` with no `error_type`. An archive that is not a zip returns `error_type` `BadZipFile`, and a failure on disk while the archive is read or extracted (no space, no permission, a file that vanished) returns the class name of the exception, `OSError` or one of its subclasses; both carry an `error` that starts `Error finalizing source upload:`.

On failure, `error_type` is one of `invalid_session_id`, `session_identity_required`, `session_workspace_unavailable` and `source_delivery_busy`, or the class name of an exception.

## suggest_suppression

Build a paste-ready AshSuppression entry for a specific finding.

<!-- doctest: options of=mcp.suggest_suppression -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `finding_id` | string | *required* | Stable hash ID of the finding (from get_scan_results or explain_finding). |
| `results_path` | string \| null | not set | Path to ash_aggregated_results.json. Defaults to .ash/ash_output/ash_aggregated_results.json in cwd. |
| `expiration` | string \| null | not set | Expiration date in YYYY-MM-DD format. Defaults to 90 days from today. |
| `justification` | string \| null | not set | Human-readable reason for the suppression. |

On failure, `error_type` is one of `invalid_expiration`, `invalid_session_id`, `path_not_expressible` and `suppression_not_specific`, or the class name of an exception.

## validate_config

Validate an ASH configuration file or content string.

<!-- doctest: options of=mcp.validate_config -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `config_content` | string \| null | not set | YAML/JSON string to validate. |
| `config_path` | string \| null | not set | Path to the config file to validate. |

`config_content` counts as the client's config, and so does a `config_path` that a client delivered or that is outside the directories `ASH_MCP_ALLOWED_CONFIG_ROOTS` names and its session's `config/` directory. Each field such a config may not set under the server's runtime-override policy is an error of type `denied_by_runtime_policy`, and a policy the server cannot read is one error of type `config_policy_unreadable`; for `config_content`, both only when a remote client calls. A `${VAR}` or `${VAR:default}` reference at the start of a plain value, or an `!ENV` tag, in such a config is an error of type `config_env_not_resolved`.

Each entry of `errors` has a `type` that is one of `config_env_not_resolved`, `config_input_not_permitted`, `config_policy_unreadable`, `conflicting_input`, `denied_by_runtime_policy`, `duplicate_field`, `extends_error`, `file_not_found`, `internal_field`, `invalid_field`, `invalid_session_id`, `json_parse_error`, `missing_input`, `missing_required_field`, `toml_parse_error`, `unknown_field`, `validation_error` and `yaml_parse_error`, or the class name of an exception.

## Resources

- `ash://exit-codes` — Return the meaning of each ASH exit code as JSON
- `ash://help` — Get help information about ASH usage
- `ash://schema/config` — Return the AshConfig JSON schema
- `ash://schema/suppression` — Return the AshSuppression JSON schema
- `ash://status` — Get the current status of ASH installation

Read these via the standard MCP resource read mechanism for context-free help.

## Severity levels

`CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO` > `SUPPRESSED`

`actionable_only=True` drops `SUPPRESSED` findings (false positives, accepted risks) and findings below the scan's severity threshold, which are reported but do not fail the scan.


# ASH troubleshooting

## The agent has no ASH tools

The MCP server did not start. The plugin starts it with `uvx`, which needs uv on the PATH the agent sees, and network access to GitHub the first time it runs. To see the error, the user can run the same command in a terminal:

**Cause:** Not polling on the 5-second cadence the ASH server's docstring requests. The scan itself runs server-side regardless of polling — only the progress channel suffers.

**Fix:** Poll `get_scan_progress(scan_id=...)` every 5 seconds while a scan is active. Even on small scans, this gives reliable per-scanner status. If the connection truly drops, reconnect and re-issue `get_scan_progress` with the stored `scan_id` — the server retains scan state.

## Scan returns immediately with no findings

**Symptom:** `get_scan_results` returns an empty `findings` list, but the project clearly has issues.

**Causes & fixes:**
1. `findings` is only in a response with `actionable_only=True` and `filter_level="full"`. A `summary` or `minimal` response, or one without `actionable_only`, has counts and no `findings` list.
2. `actionable_only=True` lists the actionable findings only, the ones that make the scan exit 2: unsuppressed and at or above the severity threshold the scan was judged by. To see the suppressed ones and those below the threshold too, read the SARIF or `ash_aggregated_results.json` file that `get_scan_result_paths` names.
3. `severities` filter is too tight — try `severities=None` first.
4. `severity_threshold` decides which findings are actionable. The scan still reports the findings below it, but `findings` leaves them out, so a high threshold can empty the list. Re-scan with `severity_threshold="LOW"` to make LOW findings actionable too.
5. Scanners didn't run — check `get_scan_summary` output for scanner-level failures.

## "ASH not installed"

**Symptom:** `check_installation` returns failure or `installed: false`, or `run_ash_scan` errors with "command not found."

`installed: false` means no enabled built-in scanner has its tool available, so a scan would run nothing. `ready: false` with `installed: true` means some scanners will not run: `missing_dependencies` names them, and a scan reports them as not run. On the server's host, `ash dependencies install` installs the tools ASH can install itself.

**Fix:** The MCP server needs ASH on its PATH. The standard install via `uvx`:
<!-- doctest: illustrative reason="installs ASH from GitHub over the network and starts the MCP server, which waits for a client" -->
```bash
uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.7.1 ash mcp
```

When the server starts, it waits for a client; Ctrl+C stops it. If ASH is already installed, the server command can be `ash` with the argument `mcp` instead. Desktop apps often see a shorter PATH than a shell, so an absolute path to `uvx` or `ash` can fix a server that starts in a terminal and not in the agent.

## Scanners are MISSING

**Causes:**
1. Project too large — the server stops a scan after `scan_timeout_seconds` (default 1800 s) and reports it `failed`. The operator sets that limit in the server's `ASH_CONFIG` file; a repository's `.ash/.ash.yaml` cannot raise it. Ask the operator for a higher limit, or scan a subdirectory.
2. Stuck scanner — call `cancel_scan(scan_id)`, wait a few seconds, then retry. Until the scan has stopped, `run_ash_scan` for the same directory can be refused as busy with `error_type: MCPResourceError` and `error_category: resource_exhausted`: retry after a few seconds. To isolate which scanner is hanging, narrow the scanner set in `.ash/.ash.yaml` and re-scan.
3. Server-side dependency stalled — restart the MCP server. The previous scan's state is lost, but the next scan will start clean.

## The scan does not reach a final status

Poll `get_scan_progress` until `is_complete` is true. It is true for every final status, `incomplete` included.

ASH stops a scanner's tool after its `scan_timeout` option, 1800 seconds unless the project's ASH config sets `scanners.<name>.options.scan_timeout`. The server also stops a whole scan after its operator's `scan_timeout_seconds`, 1800 seconds by default, and reports it `failed` with an `error_message` that names the limit; a project's config cannot change that limit. For a large project, scan a subdirectory, or disable the scanners you do not need in the config. To stop a scan, call `cancel_scan`.

## `run_ash_scan` returns `scan_start_failure`

The scan did not start, and `error` says why:

- `max_concurrent_scans limit`: the server is running as many scans as its operator allows. Start the scan again when one has finished, or cancel one you no longer need.
- `already has an active scan`: a scan of that directory is running. Wait for it, or cancel it.
- `still stopping`: a canceled scan of that directory has not stopped yet. Try again in a few seconds. A canceled scan that was waiting for another scan of its session stops only when that scan ends.

**Symptom:** `get_scan_progress` shows `scanners: {}` and `finished_scanners: 0`, `total_scanners: 0` for a long time.

- `get_scan_results` lists findings only with `actionable_only` set, in a response at the default `filter_level`, `full`, and then only the actionable ones: not suppressed, and at or above the threshold their scanner was judged by. A `summary` or `minimal` response has counts and no `findings` list. `reports/ash.flat.json` in the output directory has every finding, the suppressed ones with `is_suppressed` true.
- After a failed or canceled scan, `results_available` is false. When `output_holds_previous_results` is true, the files in the output directory are the previous scan's, and the results tools refuse that directory with `error_category` `scan_incomplete`.
- A scanner that did not run reports nothing. Check `incomplete_scanners` and `skipped_scanners` in the final progress response.
- Check which config the scan read. Without `config_path`, `run_ash_scan` uses the ASH config it finds in the project.

## `scan_target_not_permitted`

The server refuses to scan that directory. It always refuses system directories such as `/etc` and `/root`, and when `ASH_MCP_ALLOWED_ROOTS` is set in the server's environment it refuses everything outside the directories that variable names. Ask the user to scan another directory or to change the server's environment.

## `output_dir_not_permitted`

`.ash` or `.ash/ash_output` in the project is a symbolic link, and ASH does not write through one. Ask the user to replace it with a directory.

**Fix:** Confirm `.ash/.ash.yaml` exists at the project root and has the right syntax. Read the SARIF or `ash_aggregated_results.json` file that `get_scan_result_paths` names to see ALL findings (including suppressed) and verify the suppression rules match; a `get_scan_results` response lists findings only with `actionable_only=True`, which leaves the suppressed ones out.
