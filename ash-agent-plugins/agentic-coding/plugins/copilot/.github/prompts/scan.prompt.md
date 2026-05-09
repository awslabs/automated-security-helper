---
description: 'Run an ASH security scan on the current directory and report findings'
name: 'scan'
agent: 'agent'
---

# Scan

Run a full ASH security scan on the current working directory and report a prioritized findings summary.

## Workflow

1. **Verify installation** — call `check_installation`. If it fails, surface the install command (`uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.4.0 ash mcp`) and stop.

2. **Determine source directory** — use `pwd` to get the absolute path. If the user provides an argument, use that instead. For monorepos, confirm with the user whether they want the full repo or a subdirectory before scanning.

3. **Start the scan** — call `run_ash_scan` with:
   - `source_dir` = absolute path
   - `severity_threshold="MEDIUM"` (configurable via user prompt)
   - `clean_output=True`

   Store the returned `scan_id`. Reports land in `<source_dir>/.ash/ash_output/`. The MCP server always runs scans in local mode; for container scans the user needs to invoke the ASH CLI directly (`ash scan --mode container`).

4. **Poll progress every 5 seconds** — loop on `get_scan_progress(scan_id=<id>)` until `status` is one of `completed`, `failed`, or `cancelled`. Don't rely on `is_complete` alone — it stays `False` for cancelled scans. Show the user a brief status update on each poll: which scanners are running, and `completed_scanners / total_scanners` as the progress fraction (treat `total_scanners == 0` as "initializing").

5. **Fetch summary results** — call `get_scan_results` with:
   - `output_dir` = `<source_dir>/.ash/ash_output`
   - `filter_level="summary"`
   - `severities="critical,high,medium"`
   - `actionable_only=True`

6. **Report to user** — render a markdown summary:
   - Total findings by severity (CRITICAL/HIGH/MEDIUM)
   - Top 3-5 most severe findings with file:line references
   - Scanner-level breakdown (which scanners ran, which fired)
   - Path to the HTML report (from `get_scan_result_paths`) so the user can open it

## Notes

- The scan runs in the background regardless of MCP connection state. If the user cancels mid-scan, call `cancel_scan` to free server resources.
- Default scan time is 30-120 seconds; longer for large monorepos.
- For deeper investigation of a specific finding, use the full ASH MCP skill workflow.
