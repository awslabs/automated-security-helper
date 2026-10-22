---
description: Run an ASH security scan on the current directory and report findings
allowed-tools: ["mcp__plugin_ash_ash__run_ash_scan", "mcp__plugin_ash_ash__get_scan_progress", "mcp__plugin_ash_ash__get_scan_results", "mcp__plugin_ash_ash__get_scan_summary", "mcp__plugin_ash_ash__get_scan_result_paths", "mcp__plugin_ash_ash__list_active_scans", "mcp__plugin_ash_ash__cancel_scan", "mcp__plugin_ash_ash__check_installation", "Read", "Bash"]
---

# Scan

Run an ASH security scan on the current project and report what it finds, most severe first.

## Steps

1. Use the absolute path of the current working directory as the source directory, or the path the user gives. In a monorepo, ask whether to scan the whole repository or one directory.
2. Call `run_ash_scan` with `source_dir` set to that path, and keep the `scan_id` it returns.
3. Call `get_scan_progress` with the `scan_id` about every 5 seconds until `is_complete` is true, then read `status`: `completed`, `incomplete`, `failed`, or `cancelled`. Tell the user the status as it changes. For `failed`, report `error_message` and stop. For `cancelled`, say so and stop.
4. Call `get_scan_summary` with `output_dir` set to `output_directory` from the progress response, for the counts by severity and by scanner.
5. Call `get_scan_result_paths` with the same `output_dir`, and read the findings from the `flat_json` report it names. Leave out the records with `is_suppressed` true.
6. Report to the user:
   - the final status, and for `incomplete`, each scanner in `incomplete_scanners` with its `reason`, and that the coverage is partial
   - the number of actionable findings, by severity
   - the most severe findings, each with its severity, scanner, `rule_id`, and file and line
   - the paths of `ash.html` and `ash.summary.md` from `get_scan_result_paths`

## Notes

- If there are no ASH tools, the MCP server is not running. The plugin starts it with `uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.7.0 ash mcp`, which needs uv, and network access to GitHub the first time.
- The MCP server always scans in local mode. For a container scan, the user runs `ash scan --mode container`.
- Do not repeat the value of a detected secret. Refer to its file and line.
