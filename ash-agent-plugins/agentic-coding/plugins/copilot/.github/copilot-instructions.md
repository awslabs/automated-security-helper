# ASH Security Scanner

Run ASH (Automated Security Helper) security scans via MCP — Bandit, Semgrep, detect-secrets, Checkov, Grype, Syft, and more across Python, JS, IaC, and dependencies.

---

# ASH MCP security scanning workflow

ASH (Automated Security Helper) combines code, infrastructure, secrets, and dependency scanners behind one MCP interface. Its MCP server runs a scan in the background: you start it, poll it until it ends, then read the results. This skill assumes the server is connected; the plugin that ships this skill configures it.

The server scans on the machine it runs on, always in local mode, with the scanner tools installed there. The project's ASH config, or the config profile the session selected, chooses the scanners and the severity thresholds. Use `list_scanners` to inspect the installed scanner catalog. No tool argument chooses scanners, and `run_ash_scan`'s `severity_threshold` can only make the config's threshold stricter.

## Run a scan

1. Call `run_ash_scan` with `source_dir` set to the absolute path of the project. It returns at once with a `scan_id` and `status` `running`. Keep the `scan_id`.
2. Call `get_scan_progress` with that `scan_id` about every 5 seconds until `is_complete` is true. It is true for every way a scan ends: `status` is then `completed`, `incomplete`, `failed`, or `cancelled`.
3. When `results_available` is true, read the results from `output_directory`, the absolute path in the progress response. It is `.ash/ash_output` inside `source_dir`.

```text
run_ash_scan(source_dir="/absolute/path/to/project")
get_scan_progress(scan_id="<scan_id from run_ash_scan>")
```

| Final status | Meaning | What to do |
|--------------|---------|------------|
| `completed` | Every selected scanner ran. | Read the results. |
| `incomplete` | The scan finished and its results are readable, but a selected scanner did not run or did not finish. | Read the results, name each scanner in `incomplete_scanners` and its `reason`, and say the coverage is partial. |
| `failed` | The scan crashed, left no readable results, or ran past the server's time limit. | Report `error_message`. |
| `cancelled` | The scan was canceled. | Say so. |

After `failed` or `cancelled`, `results_available` is false: do not report results for that scan. Once ASH has put the previous scan's results back in the output directory, `output_holds_previous_results` is true.

Never report a project as clean unless the status is `completed` and there are no actionable findings. In the final progress response, `scanner_statuses` and `skipped_scanners` tell a scanner that ran and found nothing from one that never ran.

While the scan runs, tell the user its status. For progress, use `finished_scanners` out of `total_scanners`: `total_scanners` is 0 until the scanners start, and `completed_scanners` counts only scanners that passed.

## Read the results

Pass `output_directory` as `output_dir` to these tools:

- `get_scan_summary` returns the counts: `findings_summary` has the findings by severity, with `actionable` and `suppressed` totals, and `scanner_summary` has each scanner's status and counts.
- `get_scan_result_paths` returns the absolute path of every report under `files`. Read the findings from the `flat_json` one, `reports/ash.flat.json`: its `findings` list has one record per finding, with `id`, `severity`, `scanner`, `rule_id`, `file_path`, `line_start`, and `is_suppressed`. `reports/ash.summary.md` is a summary to show the user.
- `get_scan_results` returns counts and per-scanner summaries. With `actionable_only` set, a response at the default `filter_level`, `full`, also has a `findings` list of the actionable findings, the unsuppressed ones at or above the threshold their scanner was judged by, each with `rule_id`, `severity`, `scanner`, `file_path`, and its lines, but no `id`. Take the `id` that `explain_finding` and `suggest_suppression` need from `ash.flat.json`.

[... see prompt files for details]
