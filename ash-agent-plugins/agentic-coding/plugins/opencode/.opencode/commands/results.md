---
description: Fetch and display results from the most recent ASH scan
---

# Results

Display findings from the most recent ASH scan in the current directory, or from a scan_id if provided.

## Workflow

1. **Locate the scan output** — default to `<cwd>/.ash/ash_output`. If the user provides a scan_id, use `list_active_scans` to find the matching output_dir.

2. **Get the summary first** — call `get_scan_summary(output_dir=...)`. This is cheap and tells you whether there are any findings worth fetching.

3. **Fetch full results if needed** — if the summary shows findings, call `get_scan_results` with `filter_level="full"` and any user-specified filters (severities, scanners).

4. **Render** — group findings by severity (CRITICAL → HIGH → MEDIUM → LOW), then by scanner. For each finding show:
   - Severity tag
   - Scanner name and rule ID
   - File path and line number
   - One-line description

5. **Offer report links** — call `get_scan_result_paths` and tell the user where the HTML, SARIF, and CSV reports live.

## Argument shortcuts

If the user passes a severity (e.g., `critical`), filter to that severity. If they pass a scanner name (e.g., `bandit`), filter to that scanner. Otherwise show everything actionable.

## When no scan exists

If there's no `.ash/ash_output` directory, tell the user no recent scan was found and suggest running a scan first. Do not silently start a new scan from this command.
