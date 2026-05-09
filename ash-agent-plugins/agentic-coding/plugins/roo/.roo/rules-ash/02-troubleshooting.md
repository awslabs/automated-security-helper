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
