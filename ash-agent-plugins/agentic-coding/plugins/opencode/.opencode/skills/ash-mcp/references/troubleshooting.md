# ASH troubleshooting

## The agent has no ASH tools

The MCP server did not start. The plugin starts it with `uvx`, which needs uv on the PATH the agent sees, and network access to GitHub the first time it runs. To see the error, the user can run the same command in a terminal:

<!-- doctest: illustrative reason="installs ASH from GitHub, then starts the MCP server, which waits for a client on stdin" -->
```bash
uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.7.0 ash mcp
```

When the server starts, it waits for a client; Ctrl+C stops it. If ASH is already installed, the server command can be `ash` with the argument `mcp` instead. Desktop apps often see a shorter PATH than a shell, so an absolute path to `uvx` or `ash` can fix a server that starts in a terminal and not in the agent.

## Scanners are MISSING

`check_installation` checks ASH, not the scanner tools. A scanner whose tool is not installed ends as MISSING, and the scan ends `incomplete`. With the user's agreement, `ash dependencies install` installs the tools for the user that runs the server; then scan again. A tool installed only inside the scanned project does not count.

## The scan does not reach a final status

Poll `get_scan_progress` until `status` is `completed`, `incomplete`, `failed` or `cancelled`. `incomplete` is final. A loop that waits for `is_complete` alone does not end for a failed or cancelled scan that left no results.

ASH stops a scanner's tool after its `scan_timeout` option, 1800 seconds unless the project's ASH config sets `scanners.<name>.options.scan_timeout`. For a large project, scan a subdirectory, or disable the scanners you do not need in the config. `cancel_scan` does not stop a running scan; restarting the MCP server does, and the server then forgets its scans.

## No findings, but the project has problems

- `get_scan_results` does not list findings, and with `actionable_only` set its `findings` list is always empty. Read `reports/ash.flat.json` in the output directory.
- A scanner that did not run reports nothing. Check `incomplete_scanners` and `skipped_scanners` in the final progress response.
- Check which config the scan read. Without `config_path`, `run_ash_scan` uses the ASH config it finds in the project.

## `scan_target_not_permitted`

The server refuses to scan that directory. It always refuses system directories such as `/etc` and `/root`, and when `ASH_MCP_ALLOWED_ROOTS` is set in the server's environment it refuses everything outside the directories that variable names. Ask the user to scan another directory or to change the server's environment.

## `output_dir_not_permitted`

`.ash` or `.ash/ash_output` in the project is a symbolic link, and ASH does not write through one. Ask the user to replace it with a directory.

## A suppression does not apply

Suppressions go under `global_settings.suppressions` in the project's ASH config, and each entry needs `path` and `reason`. `path` is relative to the scanned directory, and a `path` that starts with `./` matches nothing. From its `expiration` date on, an entry no longer applies. `ash config get .ash/.ash.yaml` checks the config and exits with code 3, naming the field, when it is invalid. After the next scan, `reports/ash.unused-suppressions.json` lists the suppressions that matched no finding.
