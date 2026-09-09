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
