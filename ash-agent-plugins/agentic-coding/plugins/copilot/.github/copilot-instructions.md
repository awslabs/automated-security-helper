# ASH Security Scanner

Run ASH (Automated Security Helper) security scans via MCP — Bandit, Semgrep, detect-secrets, Checkov, Grype, Syft, and more across Python, JS, IaC, and dependencies.

---

# ASH MCP security scanning workflow

ASH (Automated Security Helper) runs a set of security scanners over a project and combines their results. Its MCP server runs a scan in the background: you start it, poll it until it ends, then read the results. This skill assumes the server is connected; the plugin that ships this skill configures it.

The server scans on the machine it runs on, always in local mode, with the scanner tools installed there. The project's ASH config, such as `.ash/.ash.yaml`, chooses the scanners and thresholds. No tool argument does.

## Run a scan

1. Call `run_ash_scan` with `source_dir` set to the absolute path of the project. It returns at once with a `scan_id` and `status` `running`. Keep the `scan_id`.
2. Call `get_scan_progress` with that `scan_id` about every 5 seconds until `status` is `completed`, `incomplete`, `failed` or `cancelled`. Decide on `status`, not on `is_complete`: `is_complete` stays false for a failed or cancelled scan that left no results, so a loop that waits for it may never end.
3. Read the results from `output_directory`, the absolute path in the progress response. It is `.ash/ash_output` inside `source_dir`.

```text
run_ash_scan(source_dir="/absolute/path/to/project")
get_scan_progress(scan_id="<scan_id from run_ash_scan>")
```

| Final status | Meaning | What to do |
|--------------|---------|------------|
| `completed` | Every selected scanner ran. | Read the results. |
| `incomplete` | The scan finished and its results are readable, but a selected scanner did not run or did not finish. | Read the results, name each scanner in `incomplete_scanners` and its `reason`, and say the coverage is partial. |
| `failed` | The scan crashed or left no readable results. | Report `error_message`. |
| `cancelled` | The scan was cancelled. | Do not treat any results as final. |

Never report a project as clean unless the status is `completed` and there are no actionable findings. In the final progress response, `scanner_statuses` and `skipped_scanners` tell a scanner that ran and found nothing from one that never ran.

While the scan runs, tell the user its status. `completed_scanners` and `total_scanners` are not a percentage: `total_scanners` is 0 until the scanners start, and `completed_scanners` counts only scanners that passed.

## Read the results

Pass `output_directory` as `output_dir` to these tools:

- `get_scan_summary` returns the counts: `findings_summary` has the findings by severity, with `actionable` and `suppressed` totals, and `scanner_summary` has each scanner's status and counts.
- `get_scan_result_paths` returns the absolute path of every report under `files`. Read the findings from the `flat_json` one, `reports/ash.flat.json`: its `findings` list has one record per finding, with `id`, `severity`, `scanner`, `rule_id`, `file_path`, `line_start` and `is_suppressed`. `reports/ash.summary.md` is a summary to show the user.
- `get_scan_results` returns counts and per-scanner summaries, not findings. With `actionable_only` set, its `findings` list is always empty, whatever the scan found, so never take that list as a sign that the project is clean.

A finding that a scanner reports with no severity of its own, as detect-secrets does, counts as CRITICAL in the counts and shows as HIGH in `ash.flat.json`. Describe a finding with the severity in `ash.flat.json`, and decide whether the scan passes from the counts.

[... see prompt files for details]
