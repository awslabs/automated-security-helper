---
name: ash-mcp
description: Run security scans with the ASH (Automated Security Helper) MCP server. Use this skill whenever the user asks to scan for vulnerabilities, run a security check, find CVEs, audit dependencies, check for secrets, run SAST or SCA, scan IaC (Terraform/CloudFormation/Kubernetes), check for hardcoded credentials, or mentions ASH, Bandit, Semgrep, Checkov, Grype, Syft, or detect-secrets. Also trigger when the user wants to find security issues, harden a codebase, or asks "is my code secure". Do NOT trigger for code review without security context, performance audits, or test writing.
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

## Limits

- `run_ash_scan` takes no scanner list. To skip a scanner, the project's ASH config sets `scanners.<name>.enabled` to `false`. Its `severity_threshold` argument does not change what the scan reports; the config's thresholds decide which findings are actionable.
- `cancel_scan` marks a scan cancelled, but the scan keeps running and can still write to the output directory.
- The server keeps its list of scans in memory. After it restarts, `get_scan_progress` fails with `scan_not_found` for older scan ids; read their results from the output directory.
- `check_installation` reports that ASH runs. It does not check the scanner tools. A scanner whose tool is missing ends as MISSING, listed in `incomplete_scanners`.
- For a container scan, the user runs the ASH command line, `ash scan --mode container`, instead of the MCP server.

## Explain, suppress and compare

- `explain_finding` takes a finding's `id` from `ash.flat.json` and `results_path` set to the output directory. It returns the scanner's description, why the finding is or is not actionable, and the matched code. Two findings with the same rule and message share an `id`, so check that the location it returns is the one you meant.
- `suggest_suppression` takes the `id`, `results_path` set to the `ash_aggregated_results.json` file in the output directory, and the user's reason as `justification`. It writes nothing and returns an entry for `global_settings.suppressions` in the project's ASH config. Leave out its `client_supplied` key. Fix a finding before you suppress it, and suppress only with a reason the user agrees with.
- `diff_scan_results` compares two `ash_aggregated_results.json` files, `before_path` and `after_path`. Unless `run_ash_scan` gets `clean_output` false, a scan deletes the previous file in its output directory before it starts, so copy the file first.

The [tool reference](references/tool-reference.md) lists every tool and its parameters. [Troubleshooting](references/troubleshooting.md) covers the common failures.
