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
2. Stuck scanner — call `cancel_scan(scan_id)`, wait a few seconds, then retry. Until the scan has stopped, `run_ash_scan` for the same directory can be refused as busy with `error_type: MCPResourceError` and `error_category: resource_exhausted`: retry after a few seconds. To isolate which scanner is hanging, narrow the scanner set in `.ash/.ash.yaml` and re-scan.
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
