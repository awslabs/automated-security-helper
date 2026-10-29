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

[... see prompt files for details]
