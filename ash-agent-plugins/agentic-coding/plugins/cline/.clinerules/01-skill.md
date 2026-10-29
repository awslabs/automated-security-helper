# ASH MCP security scanning workflow

ASH (Automated Security Helper) combines code, infrastructure, secrets, and dependency scanners behind one MCP interface. Its MCP server runs a scan in the background: you start it, poll it until it ends, then read the results. This skill assumes the server is connected; the plugin that ships this skill configures it.

The server scans on the machine it runs on, always in local mode, with the scanner tools installed there. The project's ASH config, or the config profile the session selected, chooses the scanners and the severity thresholds. Use `list_scanners` to inspect the installed scanner catalog. No tool argument chooses scanners, and `run_ash_scan`'s `severity_threshold` can only make the config's threshold stricter.

## Run a scan

1. Call `run_ash_scan` with `source_dir` set to the absolute path of the project. It returns at once with a `scan_id` and `status` `running`. Keep the `scan_id`.
2. Call `get_scan_progress` with that `scan_id` about every 5 seconds until `is_complete` is true. It is true for every way a scan ends: `status` is then `completed`, `incomplete`, `failed`, or `cancelled`.
3. When `results_available` is true, read the results from `output_directory`, the absolute path in the progress response. It is `.ash/ash_output` inside `source_dir`.

### Step 1 — Start the scan

Call `run_ash_scan` with the absolute path to the project. The call returns immediately with a `scan_id`.

<!-- doctest: illustrative reason="calls the MCP tools, which need a client connected to ash mcp" -->
```python
run_ash_scan(
    source_dir="/absolute/path/to/project",
    config_path=None,  # Optional path to .ash.yaml
    clean_output=True,
)
```

Leave `severity_threshold` unset: the scan then uses the config's `global_settings.severity_threshold`. The argument (`ALL | LOW | MEDIUM | HIGH | CRITICAL`) can only tighten that threshold for one scan, never loosen it — pass it (e.g. `"HIGH"`) only when the user asks for a stricter level. For a looser level, lower the setting in `.ash/.ash.yaml` and re-scan.

Returns a dict with `scan_id`, `status: "running"`, `directory_path` (the resolved absolute scan root), and an `important.next_steps` block. **Always store the `scan_id`** — every subsequent call needs it.

After `failed` or `cancelled`, `results_available` is false: do not report results for that scan. Once ASH has put the previous scan's results back in the output directory, `output_holds_previous_results` is true.

Poll until `progress['is_complete']` is `true`, as the server's `important.next_steps` block says, and then read `status`; see Step 2.

The MCP server always runs scans in local mode: on the server's own machine, with the scanner tools installed there, and never in a container. For container or precommit modes, use the ASH CLI directly. Scanner selection lives in `.ash/.ash.yaml`, not in tool parameters.

## Read the results

Pass `output_directory` as `output_dir` to these tools:

- `get_scan_summary` returns the counts: `findings_summary` has the findings by severity, with `actionable` and `suppressed` totals, and `scanner_summary` has each scanner's status and counts.
- `get_scan_result_paths` returns the absolute path of every report under `files`. Read the findings from the `flat_json` one, `reports/ash.flat.json`: its `findings` list has one record per finding, with `id`, `severity`, `scanner`, `rule_id`, `file_path`, `line_start`, and `is_suppressed`. `reports/ash.summary.md` is a summary to show the user.
- `get_scan_results` returns counts and per-scanner summaries. With `actionable_only` set, a response at the default `filter_level`, `full`, also has a `findings` list of the actionable findings, the unsuppressed ones at or above the threshold their scanner was judged by, each with `rule_id`, `severity`, `scanner`, `file_path`, and its lines, but no `id`. Take the `id` that `explain_finding` and `suggest_suppression` need from `ash.flat.json`.

Stop polling when `is_complete` is `true`. It is `true` for every ending: `status` is then one of `completed | incomplete | failed | cancelled`, and `results_available` says whether `get_scan_results` can read the results (`completed` and `incomplete`). Typical scans take 30-120 seconds.

For progress display, use `finished_scanners / total_scanners` (`completed_scanners` counts only scanners that PASSED) — but check `total_scanners > 0` first (it's zero during pre-flight before any scanner registers; show "initializing" in that case). The response also includes `severity_counts` and per-scanner breakdown to surface in user-facing updates.

- `run_ash_scan` takes no scanner list. To skip a scanner, the project's ASH config sets `scanners.<name>.enabled` to `false`. Its `severity_threshold` argument makes the config's `global_settings.severity_threshold` stricter for that scan, never looser: `LOW` over a configured `MEDIUM` makes LOW findings actionable, and `CRITICAL` changes nothing. It tightens a scanner's own `severity_threshold` option the same way. Every finding is reported either way.
- A scan runs inside the server process and stops if the server exits. Over stdio, the server exits when the agent disconnects from it.
- `cancel_scan` stops a running scan: no further scanner, phase, or reporter starts, so a scan canceled before its report phase writes no reports, and `ash_aggregated_results.json` is not written after the cancel. Previous results that the output directory held are put back in place of the results it wrote, and its log, `ash.log`, stays, while an `ash.log.jsonl` already there is left as it was. With none to put back, what it wrote before it stopped stays, but a cancel during the report phase removes that phase's reports, all but `reports/ash.unused-suppressions.md`. The status is `cancelled` at once. Until the scan has stopped, up to about 10 seconds, or until the scan it waits for ends if it was queued behind another scan of the session, a new scan of the same directory is refused as still stopping.
- The server keeps its list of scans in memory. After it restarts, `get_scan_progress` fails with `scan_not_found` for older scan ids; read their results from the output directory.
- `check_installation` reports the ASH version and whether each built-in scanner's tool is installed: `ready` is false when a scanner that ASH enables by default cannot run and no scan will install its tool, and `missing_dependencies` names those scanners. It does not read the project's config, so a scanner the project turns off can be listed. It installs and downloads nothing. When the tool of a scanner that ASH installs with uv is missing, the first scan installs it if the server is online and has uv; such a scanner is listed in `installs_on_first_scan` and counts toward `ready`, and otherwise it is in `missing_dependencies`. Offline, semgrep is also missing when it has no rules cache. A scanner that has files to scan and whose tool is missing ends as MISSING, listed in `incomplete_scanners`.
- The server's operator limits how many scans it holds at once, running or waiting (`max_concurrent_scans`, 3 by default), and how long one may run (`scan_timeout_seconds`, 1800 by default). A scan over the first limit is refused with an `error` that names it; start it again when a scan has finished. A scan over the second is stopped and ends `failed`.
- For a container scan, the user runs the ASH command line, `ash scan --mode container`, instead of the MCP server.

## Explain, suppress, and compare

- `explain_finding` takes a finding's `id` from `ash.flat.json` and `results_path` set to the output directory. It returns the scanner's description, why the finding is or is not actionable, and the matched code.
- `suggest_suppression` takes the `id`, `results_path` set to the `ash_aggregated_results.json` file in the output directory, and the user's reason as `justification`. It writes nothing and returns an entry for `global_settings.suppressions` in the project's ASH config. Leave out its `client_supplied` key. Fix a finding before you suppress it, and suppress only with a reason the user agrees with.
- `diff_scan_results` compares two `ash_aggregated_results.json` files, `before_path` and `after_path`. A scan replaces the previous file in its output directory once it has results of its own, so copy the file first.

| User goal | Filter combination |
|-----------|-------------------|
| "How bad is it?" | `filter_level="summary"` + `actionable_only=True` |
| "Show me the critical issues" | `filter_level="full"` + `severities="critical,high"` |
| "Audit Bandit only" | `scanners="bandit"` + `filter_level="full"` |
| "Generate exec summary" | Use `get_scan_result_paths`, then read `ash.summary.md` |

<!-- doctest: illustrative reason="calls the MCP tools, which need a client connected to ash mcp" -->
```python
get_scan_results(
    output_dir="/absolute/path/to/project/.ash/ash_output",
    filter_level="summary",
    severities="critical,high",
    actionable_only=True,
)
```

For HTML/SARIF/CSV reports, prefer `get_scan_result_paths` and read the files directly with native file tools — it avoids piping large payloads through MCP.

## Tool inventory

For full parameter details, see [tool-reference.md](02-tool-reference.md).

- `run_ash_scan` — Start a scan asynchronously
- `get_scan_progress` — Poll progress (call every 5s)
- `get_scan_results` — Fetch filtered results
- `get_scan_summary` — Counts only, no findings
- `get_scan_result_paths` — File paths to all reports
- `list_active_scans` — All current/recent scans
- `cancel_scan` — Stop a running scan
- `check_installation` — Verify ASH can scan, and which scanner tools are missing

## Choosing scanners

ASH runs all nine scanners by default. To run only a subset, edit `.ash/.ash.yaml` at the project root before scanning — `run_ash_scan` does not accept a scanners argument. To filter results post-scan, use the `scanners` parameter on `get_scan_results`.

For result-time filtering by scanner:

- **Python issues** → `scanners="bandit,semgrep"`
- **Secrets only** → `scanners="detect-secrets"`
- **IaC review** → `scanners="checkov,cfn_nag,cdk-nag"`
- **Dependencies** → `scanners="grype,npm-audit"`
- **SBOM generation** → `scanners="syft"`

## When something goes wrong

See [troubleshooting.md](02-troubleshooting.md) for the common failures: connection timeouts, empty results, stuck scans, container/Docker issues, suppression rules not applying.

The fast checks: scan never starts → run `check_installation` first. Scan returns no findings → ask for `filter_level="full"` with `actionable_only=True`, which is the only response with a `findings` list, and widen `severities`. The list holds the actionable findings only, those at or above the scan's severity threshold and not suppressed; the files `get_scan_result_paths` names have the rest. Stale progress visibility → you weren't polling every 5 seconds.
