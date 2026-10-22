# ASH Security Scanner

Run ASH (Automated Security Helper) security scans via MCP — Bandit, Semgrep, detect-secrets, Checkov, Grype, Syft, and more across Python, JS, IaC, and dependencies.

# ASH MCP — Security Scanning Workflow

ASH (Automated Security Helper) wraps nine security scanners behind a single MCP interface. The server exposes scans as async tools — start a scan, poll for progress, fetch filtered results.

This skill assumes the ASH MCP server is configured (the plugin/power that ships this skill provides it).

## The mandatory three-step workflow

Every scan follows this exact pattern. Skipping the poll step means stale progress visibility — the scan keeps running server-side, but you lose real-time updates.

### Step 1 — Start the scan

Call `run_ash_scan` with the absolute path to the project. The call returns immediately with a `scan_id`.

```
run_ash_scan(
    source_dir="/absolute/path/to/project",
    severity_threshold="MEDIUM",   # ALL | LOW | MEDIUM | HIGH | CRITICAL; tightens the config's, never loosens it; omit to use the config's
    config_path=None,              # Optional path to .ash.yaml
    clean_output=True
)
```

Returns a dict with `scan_id`, `status: "running"`, `directory_path` (the resolved absolute scan root), and an `important.next_steps` block. **Always store the `scan_id`** — every subsequent call needs it.

For the output directory, prefer reading `output_directory` from any subsequent `get_scan_progress` response (it pre-computes the path). If you need the output dir before the first poll, derive it from this response's `directory_path` as `<directory_path>/.ash/ash_output/`.

Poll until `progress['is_complete']` is `true`, as the server's `important.next_steps` block says, and then read `status`; see Step 2.

The MCP server always runs scans in local mode: on the server's own machine, with the scanner tools installed there, and never in a container. For container or precommit modes, use the ASH CLI directly. Scanner selection lives in `.ash/.ash.yaml`, not in tool parameters.

### Step 2 — Poll progress every 5 seconds

Loop on `get_scan_progress` until the scan is complete. The 5-second cadence is what the ASH MCP server's own docstring requests for reliable progress streaming over long scans.

```
get_scan_progress(scan_id="<uuid>")
```

Stop polling when `is_complete` is `true`. It is `true` for every ending: `status` is then one of `completed | incomplete | failed | cancelled`, and `results_available` says whether `get_scan_results` can read the results (`completed` and `incomplete`). Typical scans take 30-120 seconds.

For progress display, use `finished_scanners / total_scanners` (`completed_scanners` counts only scanners that PASSED) — but check `total_scanners > 0` first (it's zero during pre-flight before any scanner registers; show "initializing" in that case). The response also includes `severity_counts` and per-scanner breakdown to surface in user-facing updates.

The scan itself runs server-side regardless of polling cadence — polling is for progress visibility, not for keeping the scan alive.

### Step 3 — Fetch results with the right filter

Once the scan is complete, call `get_scan_results`. Match the filter to the user's intent.

| User goal | Filter combination |
|-----------|-------------------|
| "How bad is it?" | `filter_level="summary"` + `actionable_only=True` |
| "Show me the critical issues" | `filter_level="full"` + `severities="critical,high"` |
| "Audit Bandit only" | `scanners="bandit"` + `filter_level="full"` |
| "Generate exec summary" | Use `get_scan_result_paths`, then read `ash.summary.md` |

```
get_scan_results(
    output_dir="/absolute/path/to/project/.ash/ash_output",
    filter_level="summary",
    severities="critical,high",
    actionable_only=True
)
```

For HTML/SARIF/CSV reports, prefer `get_scan_result_paths` and read the files directly with native file tools — it avoids piping large payloads through MCP.

## Tool inventory

For full parameter details, see [tool-reference.md](references/tool-reference.md).

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

See [troubleshooting.md](references/troubleshooting.md) for the common failures: connection timeouts, empty results, stuck scans, container/Docker issues, suppression rules not applying.

The fast checks: scan never starts → run `check_installation` first. Scan returns no findings → ask for `filter_level="full"` with `actionable_only=True`, which is the only response with a `findings` list, and widen `severities`. The list holds the actionable findings only, those at or above the scan's severity threshold and not suppressed; the files `get_scan_result_paths` names have the rest. Stale progress visibility → you weren't polling every 5 seconds.


## Reference

# ASH MCP Tool Reference

<!-- Generated by scripts/generate_mcp_tool_reference.py from the MCP server's
     registered tools and resources. Do not edit this file directly; edit the
     generator (prose and caveats live in its TOOL_NOTES table) and re-run it,
     then `agentic-plugins build` to propagate to every plugin backend. -->

The ASH MCP server exposes twenty-two tools and five resources.

## run_ash_scan

Starts a scan asynchronously. Returns a `scan_id` immediately — the scan continues in the background regardless of MCP connection state.

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `source_dir` | string \| null | current dir | Absolute path to scan |
| `severity_threshold` | string \| null | the config's | Least severe finding that counts as actionable, any case; it can make the config's `global_settings.severity_threshold` stricter for this scan, never looser |
| `config_path` | string \| null | `null` | Custom config path. When not set: the profile this session bound with `select_profile`, else the config ASH discovers in the source directory, else the file `ASH_CONFIG` names in the server's environment, else the built-in defaults |
| `clean_output` | boolean | `true` | Wipe stale reports before starting |

Output reports are written to `<source_dir>/.ash/ash_output/` — there is no parameter to override this. Scanner selection, mode, and other tuning live in `.ash/.ash.yaml`, not in tool arguments.

Returns:
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

The target and source checks have their own `error_type` values too (`scan_target_not_permitted`, `output_dir_not_permitted`, `no_source_delivered`, `session_source_mismatch`, `delivered_source_missing`, `invalid_session_id`). Any other reason the scan could not be started returns `error_type: scan_start_failure`, and an unexpected error returns the exception's class name. Branch on `error_type`, not on the text of `error`.

## get_scan_progress

Poll progress every 5 seconds until complete. Keeps the MCP connection alive while the scan runs.

| Param | Type | Notes |
|-------|------|-------|
| `scan_id` | string | From `run_ash_scan` |

Returns:
```json
{
  "scan_id": "...",
  "directory_path": "/path/to/scanned/project",
  "output_directory": "/path/to/.ash/ash_output",
  "start_time": "<iso8601>",
  "end_time": "<iso8601 | null>",
  "status": "pending | running | completed | incomplete | failed | cancelled",
  "severity_threshold": "<the threshold the scan was judged by; null until it finishes when none was named>",
  "config_path": "<path | null>",
  "warnings": [...],
  "error_message": "<str | null>",
  "is_complete": bool,
  "results_available": bool,
  "output_holds_previous_results": bool,
  "coverage_complete": "bool | null",
  "incomplete_scanners": [
    { "scanner": "grype", "status": "MISSING", "reason": "missing_dependencies", "detail": "MISSING" }
  ],
  "no_scanner_ran": bool,
  "incomplete_converters": [{ "converter": "...", "reason": "...", "failed_input_kinds": ["..."] }],
  "unevaluated_rules": ["..."],
  "stale_content_databases": [{ "name": "grype-db", "scanner": "grype", "built": "<iso8601 | null>", "age": "...", "max_age": "...", "refresh": "..." }],
  "completed_scanners": int,
  "finished_scanners": int,
  "total_scanners": int,
  "scanner_status_counts": { "passed": int, "failed": int, "skipped": int, "running": int, "pending": int },
  "total_findings": int,
  "severity_counts": { "critical": int, "high": int, "medium": int, "low": int, "info": int, "suppressed": int },
  "scanners": {
    "<scanner_name>": {
      "<target_type>": { ... per-scanner-target progress ... }
    }
  }
}
```

There is no overall percentage field. To compute progress, use `finished_scanners / total_scanners`, which counts every scanner that ended; `completed_scanners` counts those that PASSED only — but **guard against `total_scanners == 0`** during the pre-flight phase (before any scanner has registered). Show "initializing" or 0% when `total_scanners` is zero.

There is no top-level `duration` field — derive elapsed time from `start_time` and `end_time` (or from current time while running).

**`is_complete` is `true` once the scan has ended**, whatever the ending: `completed`, `incomplete`, `failed` or `cancelled`. It is decided by the scan's state alone, never by a results file on disk, which can be a previous scan's. `results_available` is `true` for `completed` and `incomplete`, the scans whose results `get_scan_results` can read.

**A failed or cancelled scan leaves the previous scan's results in place.** ASH puts them back in `output_directory`, and `output_holds_previous_results` is then `true` and the scanner fields are empty, because those files are not this scan's. `get_scan_results` on that directory reads the previous scan's results.

**`incomplete` is terminal, with partial coverage.** The run finished and its results are readable, but a selected scanner was `MISSING` or `ERROR` (or lost targets), no scanner reached a verdict, a converter did not run or could not convert some of its inputs, a rule could not be evaluated, or a content database was past its declared age bound. `incomplete_scanners` names each scanner and why, and `stale_content_databases` each stale database. The findings are real but partial, so read them, and do not report the target as clean. `failed` means the run crashed or left no readable results. `coverage_complete` is `null` while running and for `failed` or `cancelled`; with `fail_on_incomplete_scanners: false` a scan is `completed` with `coverage_complete: false` when scanners did not run.

**Status enum:** the documented values are `pending | running | completed | incomplete | failed | cancelled`. The registry uses `pending` briefly while a scan is queued, transitions to `running` once execution begins, and may also expose the legacy `in_progress` string from older `ScanProgress` instances. Treat `pending`, `running`, and `in_progress` as equivalent "not done yet" states.

## get_scan_results

Fetch finalized results with filtering. Run only after `get_scan_progress` reports complete.

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `output_dir` | string | `".ash/ash_output"` | Absolute path strongly recommended; the server resolves relative paths against its own cwd, which usually isn't your project root |
| `filter_level` | string | `"full"` | `full`, `summary`, `minimal` |
| `scanners` | string | all | Comma-separated subset |
| `severities` | string | all | `critical,high,medium,low,info` |
| `actionable_only` | boolean | `false` | Keep only the actionable findings, the ones behind exit code 2: unsuppressed and at or above the severity threshold the scan was judged by (a scanner's own where its config sets one). Drop the rest and add `findings`, a flat list of them that honors `scanners` and `severities` (`full` level only) |

Returns full or filtered findings depending on `filter_level`.

`status` is `completed` or `incomplete`, decided by the same rule as the scan's exit code, with `coverage_complete` and `incomplete_scanners` as in `get_scan_progress`. An `incomplete` scan's findings are returned in full.

## get_scan_summary

Metadata and counts only — no individual findings. Cheap for quick health checks.

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `output_dir` | string | `".ash/ash_output"` | Absolute path |

Returns total count, severity breakdown, scanner statuses.

## get_scan_result_paths

Returns file paths to all generated reports. Useful when you want to read HTML, SARIF, CSV, or markdown directly with file tools instead of pulling JSON over MCP.

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `output_dir` | string | `".ash/ash_output"` | Absolute path |

Returns a dict mapping format names to absolute paths.

## list_active_scans

All scans the server tracks (active + recently completed).

No parameters. Returns a list of scan summaries.

## cancel_scan

Stop a running scan. The scanner running at the time is stopped, no further scanner starts, and no reports or results file are written after the cancel.

| Param | Type | Notes |
|-------|------|-------|
| `scan_id` | string | The scan to stop |

Returns `success: true` and `status: cancelled`. A scan that already finished cannot be cancelled: `success` is `false` and `status` is the status it finished with.

The status is `cancelled` at once, while the scan takes up to about 10 seconds to stop and put the previous results back. Until then a new `run_ash_scan` of the same directory is refused as still stopping; retry after a few seconds.

## check_installation

Report whether ASH can scan: its version, and for each built-in scanner whether its tool is available. Run before the first scan in a session if you're unsure of the install state. Each scanner's check may run its tool, so the call takes seconds.

No parameters. Returns `installed` (at least one enabled scanner can run), `ready` (all of them can), `version`, `scanners` (name, enabled, `dependencies_satisfied`, version) and the enabled scanners in `missing_dependencies` and `undetermined_dependencies`.

## clear_source

Delete this session's delivered source tree and workspace.

No parameters. Deletes this session's delivered source tree and workspace.

## diff_scan_results

Compare two ash_aggregated_results.json files and return a structured diff.

| Param | Type | Notes |
|-------|------|-------|
| `before_path` | string | Path to the baseline ash_aggregated_results.json file. |
| `after_path` | string | Path to the comparison ash_aggregated_results.json file. |

## explain_finding

Return structured details for a single finding by ID.

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `finding_id` | string | *required* | The FlatVulnerability ID to look up (e.g. "bandit-B601-880359fd90e1"). |
| `results_path` | string \| null | `null` | Optional path to the output directory containing ash_aggregated_results.json. Defaults to <cwd>/.ash/ash_output. |

## get_config

Get the resolved ASH config (defaults + user overrides merged).

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `config_path` | string \| null | `null` | Optional explicit path to config file. If None, auto-discovers. |
| `raw` | boolean | `false` | If True, returns the file's contents as written, without merging defaults or reading the environment. A value the config's loader would read from the environment (an `!ENV` value, or an unquoted `${VAR:default}`) comes back as `!ENV ` and the reference, never as its value; a quoted string that only looks like a reference comes back as written. |
| `search_dir` | string \| null | `null` | The directory the caller's scan will target (scan_directory's directory_path). With config_path None it is where the config is discovered; with a named config_path it is the target the file is judged for, so the answer refuses exactly what a scan of that target refuses -- an entry such a scan drops with a warning never refuses the answer. Without it, a named file is judged for this session's delivered source, or else the server's working directory. |

A config this session may not read, or one a client delivered that the server refuses, returns `success: false` with `error_type` `config_input_not_permitted`, `config_field_denied`, `config_policy_unreadable` or `config_env_not_resolved`, as `run_ash_scan` does for the same file.

## list_profiles

List the config profiles the operator registered at server startup.

No parameters. Returns the config profiles the operator registered at server startup, each with `ash mcp --profile NAME=path/to/ash.yaml` (repeatable). A client cannot register one; an empty list means the operator registered none.

## list_scanners

List all registered ASH scanners with their metadata.

No parameters. Returns one entry per registered scanner with its config name, detected version, and whether it is enabled.

## resolve_ash_workspace

Resolve a VS Code workspace file into a scan plan without scanning anything.

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `workspace_file` | string | *required* | Absolute path to the .code-workspace file. |
| `workspace_config` | string \| null | `null` | Optional path to a workspace policy file. Must exist if given; ASH will not fall back to searching for one. |
| `allow_missing_projects` | boolean | `false` | Mark project directories that are absent or unreadable as skipped instead of refusing the workspace. |
| `config_overrides` | array \| null | `null` | Optional list of `key=value` config overrides, applied to each project's config so the reported threshold is the enforced one. |
| `profile` | string \| null | `null` | Name of a registered config profile to resolve under for this one call, instead of whatever select_profile bound to this session. Call list_profiles to see what the operator registered. The fields the profile sets are final for every project, and a project's own config fills the rest. |

## run_ash_workspace_scan

Scan every project in a VS Code workspace and return the per-project verdict.

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `workspace_file` | string | *required* | Absolute path to the .code-workspace file. |
| `workspace_config` | string \| null | `null` | Optional path to a workspace policy file. |
| `allow_missing_projects` | boolean | `false` | Skip absent or unreadable project directories rather than refusing the workspace. |
| `config_overrides` | array \| null | `null` | Optional list of `key=value` config overrides. |
| `output_dir` | string \| null | `null` | Where to write the workspace output tree. Defaults to `<workspace root>/.ash/ash_output`. Refused when it, a directory or file ASH writes in it, or a project's `projects/<key>` is a symlink. |
| `scanners` | array \| null | `null` | Restrict every project to these scanner names. |
| `excluded_scanners` | array \| null | `null` | Exclude these scanners from every project. Takes precedence over `scanners`. |
| `offline` | boolean | `false` | Run without network access. |
| `clean_output` | boolean | `true` | Hide each project's previous results once the scan has its directory. Either way they are put back for a project whose scan does not finish. A scan refused because a project already has a scan touches nothing in any project's output. |
| `profile` | string \| null | `null` | Name of a registered config profile to scan under for this one call, instead of whatever select_profile bound to this session. An unknown name refuses the whole scan; running N repository scans under the default config because a profile name was misspelled, and reporting success, is exactly what the confinement refusal above exists to prevent. The fields the profile sets are final for every project, and a project's own config fills the rest. |

## select_profile

Bind one of the operator's registered config profiles to this session.

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `profile_name` | string | *required* | Name the operator registered the profile under. |
| `patch_ops` | array \| null | `null` | JSON-Patch operations to apply to the profile's config. |
| `override_yaml` | string \| null | `null` | Complete ASH config YAML replacing the profile's. |

## set_source_git

Clone a repository into this session's workspace and make it the scan target.

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `url` | string | *required* | Repository URL: `https://`, `ssh://` or `user@host:path`, on a host the operator listed in `ASH_MCP_GIT_ALLOWED_HOSTS` |
| `ref` | string \| null | default branch | Branch, tag, or commit |
| `ssh_key_id` | string \| null | none | Must be omitted: the server registers no ssh keys |
| `depth` | integer | `1` | Clone depth; `0` for a full clone |

Refused while a scan of this session is running, because the clone would replace the tree and config files that scan is reading. The response is `success: false`, `error_type: source_delivery_busy`, and `error` set to `a scan of this session is running; change the delivered source after it finishes`. Deliver the source again once `get_scan_progress` reports a terminal status.

A refusal or a git failure returns `success: false` with an `error_type`: `clone_url_not_permitted` (a url beginning with `-` or using the `ext::` transport), `clone_ref_not_permitted` (a ref beginning with `-`), `invalid_clone_depth`, `invalid_session_id`, `scan_target_not_permitted` (a local path or `file://` url outside the scan roots), `git_clone_failed` or `git_checkout_failed` (git's own message is in `error`), or `session_workspace_unavailable` (the session's workspace directory could not be created).

## set_source_zip_chunk

Upload one base64 chunk of a zipped source tree.

| Param | Type | Notes |
|-------|------|-------|
| `upload_id` | string | Caller-chosen id tying the chunks of one upload together |
| `sequence` | integer | Zero-based chunk index; chunks must arrive in order |
| `data_b64` | string | Base64 of this chunk's bytes |
| `last` | boolean | `true` on the final chunk |

Pair with `set_source_zip_finalize`, which verifies the reassembled archive against `expected_sha256` before extracting it. A chunked upload that is never finalized is not a scan target.

When the session's workspace directory cannot be created, both upload tools return `success: false` with `error_type` `session_workspace_unavailable`.

## set_source_zip_finalize

Verify an uploaded zip and extract it as this session's scan target.

| Param | Type | Notes |
|-------|------|-------|
| `upload_id` | string | The identifier used for the preceding chunk calls. |
| `expected_sha256` | string | Hex sha256 of the complete zip. |

Refused while a scan of this session is running, for the same reason as `set_source_git`: `success: false`, `error_type: source_delivery_busy`, and `error` set to `a scan of this session is running; change the delivered source after it finishes`. `set_source_zip_chunk` is not refused while a scan runs, so the chunks can be sent while the scan runs and the upload finalized after it ends; this call holds its upload's lock, so a chunk of the upload being finalized waits for it. A chunk is refused (`error_type: session_workspace_busy`) only while another request holds the session's workspace (its removal, `clear_source`, or the end of the session); send the same chunk again then, and start again from the first chunk only if the answer is an out-of-order chunk.

## suggest_suppression

Build a paste-ready AshSuppression entry for a specific finding.

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `finding_id` | string | *required* | Stable hash ID of the finding (from get_scan_results or explain_finding). |
| `results_path` | string \| null | `null` | Path to ash_aggregated_results.json. Defaults to .ash/ash_output/ash_aggregated_results.json in cwd. |
| `expiration` | string \| null | `null` | Expiration date in YYYY-MM-DD format. Defaults to 90 days from today. |
| `justification` | string \| null | `null` | Human-readable reason for the suppression. |

## validate_config

Validate an ASH configuration file or content string.

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `config_content` | string \| null | `null` | YAML/JSON string to validate. |
| `config_path` | string \| null | `null` | Path to the config file to validate. |

Each error is `{field, message, type}`. A remote caller's `config_content` counts as the client's config, and so does a `config_path` that a client delivered or that is outside the directories `ASH_MCP_ALLOWED_CONFIG_ROOTS` names, unless it is a profile file the server wrote in the calling session's `config/` directory. On stdio, `config_content` is the caller's own, because the caller started the server. Besides schema and parse errors, `type` can be `config_input_not_permitted` (a `config_path` this session may not read), `config_policy_unreadable` (the session's runtime-override policy cannot be established for the client's config), `denied_by_runtime_policy` (a field of the client's config that policy denies, named in `field`, with the message `<field> may not be set by a config an MCP client delivers: <reason>`), or `config_env_not_resolved`. A `${VAR}` or `${VAR:default}` reference at the start of a plain value, or an `!ENV` tag, is an error of type `config_env_not_resolved` anywhere in a remote caller's client config, and for a stdio caller only in a file a client delivered. A policy check that cannot finish on the client's config makes it invalid, with an error of type `validation_error` that starts `The config could not be checked against this session's runtime-override policy`.

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


# ASH Troubleshooting

## Stale progress visibility during scan

**Symptom:** `get_scan_progress` shows the same state for a long time, or the client appears to lose contact with the server.

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
```
uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.7.0 ash mcp
```
This always uses the pinned ASH version regardless of system installs.

## Scan never completes

**Symptom:** `get_scan_progress` shows `status: running` indefinitely.

**Causes:**
1. Project too large — the server stops a scan after `scan_timeout_seconds` (default 1800 s) and reports it `failed`. The operator sets that limit in the server's `ASH_CONFIG` file; a repository's `.ash/.ash.yaml` cannot raise it. Ask the operator for a higher limit, or scan a subdirectory.
2. Stuck scanner — call `cancel_scan(scan_id)` and retry. To isolate which scanner is hanging, narrow the scanner set in `.ash/.ash.yaml` and re-scan.
3. Server-side dependency stalled — restart the MCP server. The previous scan's state is lost, but the next scan will start clean.

Note: container-mode hangs are not possible via the MCP server — it always runs in local mode. If you suspect a Docker issue, you're not using the MCP integration; check your CLI invocation.

## "Permission denied" reading output

**Symptom:** `get_scan_result_paths` returns paths but the files can't be read.

**Cause:** This typically only happens with CLI container-mode scans, which leave files owned by root. The MCP server runs in local mode, so this should not occur via MCP.

**Fix:** If you arrived here from MCP, check filesystem permissions on the project directory. If you're mixing CLI container scans with MCP reads, `chown` the output directory.

## Empty `scanners` map in progress

**Symptom:** `get_scan_progress` shows `scanners: {}` and `finished_scanners: 0`, `total_scanners: 0` for a long time.

**Cause:** The scan is still in the pre-flight phase (cloning, dependency analysis). This is normal for the first 5-15 seconds of a scan, longer for large projects.

**Fix:** Keep polling. If it's still empty after 60 seconds, cancel and check the ASH server logs.

## SUPPRESSED findings keep appearing

**Symptom:** Findings flagged as suppressed/false-positive show up in `actionable_only=True` results.

**Cause:** Suppression rules are stored in `.ash/.ash.yaml` under `global_settings.ignore_paths` and per-scanner config blocks. If those aren't being read, suppressions don't apply.

**Fix:** Confirm `.ash/.ash.yaml` exists at the project root and has the right syntax. Read the SARIF or `ash_aggregated_results.json` file that `get_scan_result_paths` names to see ALL findings (including suppressed) and verify the suppression rules match; a `get_scan_results` response lists findings only with `actionable_only=True`, which leaves the suppressed ones out.

