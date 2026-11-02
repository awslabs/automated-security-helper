# ASH troubleshooting

## The agent has no ASH tools

The MCP server did not start. The plugin starts it with `uvx`, which needs uv on the PATH the agent sees, and network access to GitHub the first time it runs. To see the error, the user can run the same command in a terminal:

**Cause:** Not polling on the 5-second cadence the ASH server's docstring requests. The scan itself runs server-side regardless of polling — only the progress channel suffers.

**Fix:** Poll `get_scan_progress(scan_id=...)` every 5 seconds while a scan is active. Even on small scans, this gives reliable per-scanner status. If the connection truly drops, reconnect and re-issue `get_scan_progress` with the stored `scan_id` — the server retains scan state.

## Scan returns immediately with no findings

**Symptom:** `get_scan_results` returns an empty `findings` list, but the project clearly has issues.

**Causes & fixes:**
1. `findings` is only in a response with `actionable_only=True` and `filter_level="full"`. A `summary` or `minimal` response, or one without `actionable_only`, has counts and no `findings` list.
2. `actionable_only=True` lists the actionable findings only, the ones that make the scan exit 2: unsuppressed and at or above the severity threshold the scan was judged by. To see the suppressed ones and those below the threshold too, read the SARIF or `ash_aggregated_results.json` file that `get_scan_result_paths` names.
3. `severities` filter is too tight — try `severities=None` first.
4. `severity_threshold` decides which findings are actionable. The scan still reports the findings below it, but `findings` leaves them out, so a high threshold can empty the list. Re-scan with `severity_threshold="LOW"` to make LOW findings actionable too.
5. Scanners didn't run — check `get_scan_summary` output for scanner-level failures.

## "ASH not installed"

**Symptom:** `check_installation` returns failure or `installed: false`, or `run_ash_scan` errors with "command not found."

`installed: false` means no enabled built-in scanner has its tool available, so a scan would run nothing. `ready: false` with `installed: true` means some scanners will not run: `missing_dependencies` names them, and a scan reports them as not run. On the server's host, `ash dependencies install` installs the tools ASH can install itself.

**Fix:** The MCP server needs ASH on its PATH. The standard install via `uvx`:
<!-- doctest: illustrative reason="installs ASH from GitHub over the network and starts the MCP server, which waits for a client" -->
```bash
uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.7.1 ash mcp
```

When the server starts, it waits for a client; Ctrl+C stops it. If ASH is already installed, the server command can be `ash` with the argument `mcp` instead. Desktop apps often see a shorter PATH than a shell, so an absolute path to `uvx` or `ash` can fix a server that starts in a terminal and not in the agent.

## Scanners are MISSING

**Causes:**
1. Project too large — the server stops a scan after `scan_timeout_seconds` (default 1800 s) and reports it `failed`. The operator sets that limit in the server's `ASH_CONFIG` file; a repository's `.ash/.ash.yaml` cannot raise it. Ask the operator for a higher limit, or scan a subdirectory.
2. Stuck scanner — call `cancel_scan(scan_id)`, wait a few seconds, then retry. Until the scan has stopped, `run_ash_scan` for the same directory can be refused as busy with `error_type: MCPResourceError` and `error_category: resource_exhausted`: retry after a few seconds. To isolate which scanner is hanging, narrow the scanner set in `.ash/.ash.yaml` and re-scan.
3. Server-side dependency stalled — restart the MCP server. The previous scan's state is lost, but the next scan will start clean.

## The scan does not reach a final status

Poll `get_scan_progress` until `is_complete` is true. It is true for every final status, `incomplete` included.

ASH stops a scanner's tool after its `scan_timeout` option, 1800 seconds unless the project's ASH config sets `scanners.<name>.options.scan_timeout`. The server also stops a whole scan after its operator's `scan_timeout_seconds`, 1800 seconds by default, and reports it `failed` with an `error_message` that names the limit; a project's config cannot change that limit. For a large project, scan a subdirectory, or disable the scanners you do not need in the config. To stop a scan, call `cancel_scan`.

## `run_ash_scan` returns `scan_start_failure`

The scan did not start, and `error` says why:

- `max_concurrent_scans limit`: the server is running as many scans as its operator allows. Start the scan again when one has finished, or cancel one you no longer need.
- `already has an active scan`: a scan of that directory is running. Wait for it, or cancel it.
- `still stopping`: a canceled scan of that directory has not stopped yet. Try again in a few seconds. A canceled scan that was waiting for another scan of its session stops only when that scan ends.

**Symptom:** `get_scan_progress` shows `scanners: {}` and `finished_scanners: 0`, `total_scanners: 0` for a long time.

- `get_scan_results` lists findings only with `actionable_only` set, in a response at the default `filter_level`, `full`, and then only the actionable ones: not suppressed, and at or above the threshold their scanner was judged by. A `summary` or `minimal` response has counts and no `findings` list. `reports/ash.flat.json` in the output directory has every finding, the suppressed ones with `is_suppressed` true.
- After a failed or canceled scan, `results_available` is false. When `output_holds_previous_results` is true, the files in the output directory are the previous scan's, and the results tools refuse that directory with `error_category` `scan_incomplete`.
- A scanner that did not run reports nothing. Check `incomplete_scanners` and `skipped_scanners` in the final progress response.
- Check which config the scan read. Without `config_path`, `run_ash_scan` uses the ASH config it finds in the project.

## `scan_target_not_permitted`

The server refuses to scan that directory. It always refuses system directories such as `/etc` and `/root`, and when `ASH_MCP_ALLOWED_ROOTS` is set in the server's environment it refuses everything outside the directories that variable names. Ask the user to scan another directory or to change the server's environment.

## `output_dir_not_permitted`

`.ash` or `.ash/ash_output` in the project is a symbolic link, and ASH does not write through one. Ask the user to replace it with a directory.

**Fix:** Confirm `.ash/.ash.yaml` exists at the project root and has the right syntax. Read the SARIF or `ash_aggregated_results.json` file that `get_scan_result_paths` names to see ALL findings (including suppressed) and verify the suppression rules match; a `get_scan_results` response lists findings only with `actionable_only=True`, which leaves the suppressed ones out.
