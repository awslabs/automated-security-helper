# Scan

Run an ASH security scan on the current project and report what it finds, most severe first.

## Steps

1. **Verify installation** — call `check_installation`. If it fails or `installed` is false, surface the install command (`uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.7.1 ash mcp`) and stop. If `ready` is false, tell the user which scanners in `missing_dependencies` will not run (their tools are not installed on the server's host; `ash dependencies install` installs the ones ASH can) and continue. Scanners in `installs_on_first_scan` do run: the first scan installs their tools, which needs network access and takes longer.

2. **Determine source directory** — use `pwd` to get the absolute path. If the user provides an argument, use that instead. For monorepos, confirm with the user whether they want the full repo or a subdirectory before scanning.

3. **Start the scan** — call `run_ash_scan` with:
   - `source_dir` = absolute path
   - `clean_output=True`
   - `severity_threshold` left unset, so the scan uses the config's `global_settings.severity_threshold`. The argument can only tighten that threshold for one scan, never loosen it: pass it (e.g. `severity_threshold="HIGH"`) only when the user asks for a stricter level. For a looser level, have the user lower the setting in `.ash/.ash.yaml` and re-scan.

   Store the returned `scan_id`. Reports land in `<source_dir>/.ash/ash_output/`. The MCP server always runs scans in local mode; for container scans the user needs to invoke the ASH CLI directly (`ash scan --mode container`).

4. **Poll progress every 5 seconds** — loop on `get_scan_progress(scan_id=<id>)` until `is_complete` is `true`, which it is for every ending (`completed`, `incomplete`, `failed`, `cancelled`); then read `status`. Show the user a brief status update on each poll: which scanners are running, and `finished_scanners / total_scanners` as the progress fraction (treat `total_scanners == 0` as "initializing").

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

- If there are no ASH tools, the MCP server is not running. The plugin starts it with `uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.7.1 ash mcp`, which needs uv, and network access to GitHub the first time.
- The MCP server always scans in local mode. For a container scan, the user runs `ash scan --mode container`.
- Do not repeat the value of a detected secret. Refer to its file and line.
