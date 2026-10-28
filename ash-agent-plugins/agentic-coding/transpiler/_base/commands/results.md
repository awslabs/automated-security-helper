# Results

Show the findings of the most recent ASH scan of the current project, or of the scan whose `scan_id` the user gives.

## Steps

1. Find the output directory. By default it is `.ash/ash_output` inside the current working directory; use its absolute path. For a `scan_id`, call `list_active_scans` and take that scan's `output_directory`. The server forgets its scans when it restarts.
2. Call `get_scan_summary` with `output_dir` set to that directory. It returns the counts by severity and by scanner.
3. If there are findings, call `get_scan_result_paths` with the same `output_dir`, and read the findings from the `flat_json` report it names. Leave out the records with `is_suppressed` true unless the user asks for them.
4. Group the findings by severity, CRITICAL first, then by scanner. For each one, show its severity, scanner, `rule_id`, `file_path`, `line_start`, and title.
5. Give the paths of the HTML, SARIF, and CSV reports from `get_scan_result_paths`.

If the user names a severity, such as `critical`, or a scanner, such as `bandit`, show only those findings.

If there is no `.ash/ash_output` directory, say that no scan was found and offer to run one. Do not start a scan from this command.
