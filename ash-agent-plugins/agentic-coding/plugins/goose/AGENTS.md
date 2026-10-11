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
    severity_threshold="MEDIUM",   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    config_path=None,              # Optional path to .ash.yaml
    clean_output=True
)
```

Returns a dict with `scan_id`, `status: "running"`, `directory_path` (the resolved absolute scan root), and an `important.next_steps` block. **Always store the `scan_id`** — every subsequent call needs it.

For the output directory, prefer reading `output_directory` from any subsequent `get_scan_progress` response (it pre-computes the path). If you need the output dir before the first poll, derive it from this response's `directory_path` as `<directory_path>/.ash/ash_output/`.

The server's `important.next_steps` block recommends polling `progress['is_complete']`. Ignore that — `is_complete` stays `False` for cancelled scans. Always check `status` independently, as described in Step 2.

The MCP server always runs scans in local mode (Python-only, no Docker). For container or precommit modes, use the ASH CLI directly. Scanner selection lives in `.ash/.ash.yaml`, not in tool parameters.

### Step 2 — Poll progress every 5 seconds

Loop on `get_scan_progress` until the scan is complete. The 5-second cadence is what the ASH MCP server's own docstring requests for reliable progress streaming over long scans.

```
get_scan_progress(scan_id="<uuid>")
```

Stop polling when `status` is one of `completed | failed | cancelled`. Do **not** rely on `is_complete` alone — it stays `False` for cancelled scans, so polling on `is_complete` will loop forever after a cancel. Typical scans take 30-120 seconds.

For progress display, use `completed_scanners / total_scanners` — but check `total_scanners > 0` first (it's zero during pre-flight before any scanner registers; show "initializing" in that case). The response also includes `severity_counts` and per-scanner breakdown to surface in user-facing updates.

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
- `check_installation` — Verify ASH is installed

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

The fast checks: scan never starts → run `check_installation` first. Scan returns no findings → drop `actionable_only` and widen `severities`. Stale progress visibility → you weren't polling every 5 seconds.


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


# ASH Troubleshooting

## Stale progress visibility during scan

**Symptom:** `get_scan_progress` shows the same state for a long time, or the client appears to lose contact with the server.

**Cause:** Not polling on the 5-second cadence the ASH server's docstring requests. The scan itself runs server-side regardless of polling — only the progress channel suffers.

**Fix:** Poll `get_scan_progress(scan_id=...)` every 5 seconds while a scan is active. Even on small scans, this gives reliable per-scanner status. If the connection truly drops, reconnect and re-issue `get_scan_progress` with the stored `scan_id` — the server retains scan state.

## Scan returns immediately with no findings

**Symptom:** `get_scan_results` returns an empty `findings` list, but the project clearly has issues.

**Causes & fixes:**
1. `actionable_only=True` is dropping suppressed findings — set it to `false` to see everything.
2. `severities` filter is too tight — try `severities=None` first.
3. `severity_threshold` at scan time was too high — re-scan with `severity_threshold="LOW"`.
4. Scanners didn't run — check `get_scan_summary` output for scanner-level failures.

## "ASH not installed"

**Symptom:** `check_installation` returns failure or `run_ash_scan` errors with "command not found."

**Fix:** The MCP server needs ASH on its PATH. The standard install via `uvx`:
```
uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.7.0 ash mcp
```
This always uses the pinned ASH version regardless of system installs.

## Scan never completes

**Symptom:** `get_scan_progress` shows `status: running` indefinitely.

**Causes:**
1. Project too large — default scan timeout is 2400s (40 min). For larger codebases, set `scan_timeout_seconds` higher in `.ash/.ash.yaml` or scan a subdirectory.
2. Stuck scanner — call `cancel_scan(scan_id)` and retry. To isolate which scanner is hanging, narrow the scanner set in `.ash/.ash.yaml` and re-scan.
3. Server-side dependency stalled — restart the MCP server. The previous scan's state is lost, but the next scan will start clean.

Note: container-mode hangs are not possible via the MCP server — it always runs in local mode. If you suspect a Docker issue, you're not using the MCP integration; check your CLI invocation.

## "Permission denied" reading output

**Symptom:** `get_scan_result_paths` returns paths but the files can't be read.

**Cause:** This typically only happens with CLI container-mode scans, which leave files owned by root. The MCP server runs in local mode, so this should not occur via MCP.

**Fix:** If you arrived here from MCP, check filesystem permissions on the project directory. If you're mixing CLI container scans with MCP reads, `chown` the output directory.

## Empty `scanners` map in progress

**Symptom:** `get_scan_progress` shows `scanners: {}` and `completed_scanners: 0`, `total_scanners: 0` for a long time.

**Cause:** The scan is still in the pre-flight phase (cloning, dependency analysis). This is normal for the first 5-15 seconds of a scan, longer for large projects.

**Fix:** Keep polling. If it's still empty after 60 seconds, cancel and check the ASH server logs.

## SUPPRESSED findings keep appearing

**Symptom:** Findings flagged as suppressed/false-positive show up in `actionable_only=True` results.

**Cause:** Suppression rules are stored in `.ash/.ash.yaml` under `global_settings.ignore_paths` and per-scanner config blocks. If those aren't being read, suppressions don't apply.

**Fix:** Confirm `.ash/.ash.yaml` exists at the project root and has the right syntax. Run with `actionable_only=False` to see ALL findings (including suppressed) and verify the suppression rules match.

