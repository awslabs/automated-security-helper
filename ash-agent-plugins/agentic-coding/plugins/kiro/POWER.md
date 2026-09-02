---
name: "ash-security-scanner"
displayName: "ASH Security Scanner"
description: "Run ASH (Automated Security Helper) security scans via MCP — Bandit, Semgrep, detect-secrets, Checkov, Grype, Syft, and more across Python, JS, IaC, and dependencies."
keywords: ["security-scan", "vulnerability-scan", "ash", "sast", "sca", "checkov", "bandit", "semgrep", "grype"]
author: "AWS Labs"
---

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

# ASH MCP Tool Reference

The ASH MCP server exposes eight tools and two resources.

## run_ash_scan

Starts a scan asynchronously. Returns a `scan_id` immediately — the scan continues in the background regardless of MCP connection state.

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `source_dir` | string \| null | current dir | Absolute path to scan |
| `severity_threshold` | string | `"MEDIUM"` | Findings below this are filtered out at scan time |
| `config_path` | string \| null | `<source>/.ash/.ash.yaml` | Custom config path |
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

**Heads-up:** the server's own docstring and the `important.next_steps` array suggest polling `progress['is_complete']`. This is incomplete advice — `is_complete` stays `False` for cancelled scans. Always check `status` independently. (See `get_scan_progress` below.)

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
  "status": "running | completed | failed | cancelled",
  "severity_threshold": "MEDIUM",
  "config_path": "<path | null>",
  "warnings": [...],
  "error_message": "<str | null>",
  "is_complete": bool,
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

**`is_complete` does not flip to `True` for cancelled scans** — it returns `True` only for `completed` and `failed`. Always check `status` independently: stop polling when `status` is `completed`, `failed`, or `cancelled`. Polling on `is_complete` alone will loop forever on a cancelled scan.

**Status enum:** the documented values are `pending | running | completed | failed | cancelled`. The registry uses `pending` briefly while a scan is queued, transitions to `running` once execution begins, and may also expose the legacy `in_progress` string from older `ScanProgress` instances. Treat `pending`, `running`, and `in_progress` as equivalent "not done yet" states.

## get_scan_results

Fetch finalized results with filtering. Run only after `get_scan_progress` reports complete.

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `output_dir` | string | `".ash/ash_output"` | Absolute path strongly recommended; the server resolves relative paths against its own cwd, which usually isn't your project root |
| `filter_level` | string | `"full"` | `full`, `summary`, `minimal` |
| `scanners` | string \| null | all | Comma-separated subset |
| `severities` | string \| null | all | `critical,high,medium,low,info` |
| `actionable_only` | boolean | `false` | Drop suppressed findings |

Returns full or filtered findings depending on `filter_level`.

## get_scan_summary

Metadata and counts only — no individual findings. Cheap for quick health checks.

| Param | Type | Notes |
|-------|------|-------|
| `output_dir` | string | Absolute path |

Returns total count, severity breakdown, scanner statuses.

## get_scan_result_paths

Returns file paths to all generated reports. Useful when you want to read HTML, SARIF, CSV, or markdown directly with file tools instead of pulling JSON over MCP.

| Param | Type | Notes |
|-------|------|-------|
| `output_dir` | string | Absolute path |

Returns a dict mapping format names to absolute paths.

## list_active_scans

All scans the server tracks (active + recently completed).

No parameters. Returns a list of scan summaries.

## cancel_scan

Stop a running scan and free resources.

| Param | Type | Notes |
|-------|------|-------|
| `scan_id` | string | The scan to stop |

Returns confirmation.

## check_installation

Verify ASH is installed and the MCP server can spawn it. Run before the first scan in a session if you're unsure of the install state.

No parameters. Returns version string and feature flags.

## Resources

- `ash://status` — Installation status (text)
- `ash://help` — Usage guide (text)

Read these via the standard MCP resource read mechanism for context-free help.

## Severity levels

`CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO` > `SUPPRESSED`

`actionable_only=True` drops `SUPPRESSED` findings (false positives, accepted risks).


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
uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.4.0 ash mcp
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
