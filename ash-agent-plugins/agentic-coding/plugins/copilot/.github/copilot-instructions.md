# ASH Security Scanner

Run ASH (Automated Security Helper) security scans via MCP — Bandit, Semgrep, detect-secrets, Checkov, Grype, Syft, and more across Python, JS, IaC, and dependencies.

---

# ASH MCP — Security Scanning Workflow

ASH (Automated Security Helper) wraps nine security scanners behind a single MCP interface. The server exposes scans as async tools — start a scan, poll for progress, fetch filtered results.

This skill assumes the ASH MCP server is configured (the plugin/power that ships this skill provides it).

## The mandatory three-step workflow

Every scan follows this exact pattern. Skipping the poll step means stale progress visibility — the scan keeps running server-side, but you lose real-time updates.

### Step 1 — Start the scan

Call `run_ash_scan` with the absolute path to the project. The call returns immediately with a `scan_id`.

```
run_ash_scan(
    source_dir="/absolute/path/to/project",
    config_path=None,              # Optional path to .ash.yaml
    clean_output=True
)
```

Leave `severity_threshold` unset: the scan then uses the config's `global_settings.severity_threshold`. The argument (`ALL | LOW | MEDIUM | HIGH | CRITICAL`) can only tighten that threshold for one scan, never loosen it — pass it (e.g. `"HIGH"`) only when the user asks for a stricter level. For a looser level, lower the setting in `.ash/.ash.yaml` and re-scan.

Returns a dict with `scan_id`, `status: "running"`, `directory_path` (the resolved absolute scan root), and an `important.next_steps` block. **Always store the `scan_id`** — every subsequent call needs it.

For the output directory, prefer reading `output_directory` from any subsequent `get_scan_progress` response (it pre-computes the path). If you need the output dir before the first poll, derive it from this response's `directory_path` as `<directory_path>/.ash/ash_output/`.

Poll until `progress['is_complete']` is `true`, as the server's `important.next_steps` block says, and then read `status`; see Step 2.

The MCP server always runs scans in local mode: on the server's own machine, with the scanner tools installed there, and never in a container. For container or precommit modes, use the ASH CLI directly. Scanner selection lives in `.ash/.ash.yaml`, not in tool parameters.

### Step 2 — Poll progress every 5 seconds

Loop on `get_scan_progress` until the scan is complete. The 5-second cadence is what the ASH MCP server's own docstring requests for reliable progress streaming over long scans.

```
get_scan_progress(scan_id="<uuid>")
```

Stop polling when `is_complete` is `true`. It is `true` for every ending: `status` is then one of `completed | incomplete | failed | cancelled`, and `results_available` says whether `get_scan_results` can read the results (`completed` and `incomplete`). Typical scans take 30-120 seconds.

For progress display, use `finished_scanners / total_scanners` (`completed_scanners` counts only scanners that PASSED) — but check `total_scanners > 0` first (it's zero during pre-flight before any scanner registers; show "initializing" in that case). The response also includes `severity_counts` and per-scanner breakdown to surface in user-facing updates.

The scan itself runs server-side regardless of polling cadence — polling is for progress visibility, not for keeping the scan alive.

### Step 3 — Fetch results with the right filter

Once the scan is complete, call `get_scan_results`. Match the filter to the user's intent.

| User goal | Filter combination |
|-----------|-------------------|
| "How bad is it?" | `filter_level="summary"` + `actionable_only=True` |
| "Show me the critical issues" | `filter_level="full"` + `severities="critical,high"` |
| "Audit Bandit only" | `scanners="bandit"` + `filter_level="full"` |
| "Generate exec summary" | Use `get_scan_result_paths`, then read `ash.summary.md` |

```
get_scan_results(
    output_dir="/absolute/path/to/project/.ash/ash_output",

[... see prompt files for details]
