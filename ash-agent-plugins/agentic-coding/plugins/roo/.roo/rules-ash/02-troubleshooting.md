# ASH troubleshooting

## The agent has no ASH tools

The MCP server did not start. The plugin starts it with `uvx`, which needs uv on the PATH the agent sees, and network access to GitHub the first time it runs. To see the error, the user can run the same command in a terminal:

<!-- doctest: illustrative reason="installs ASH from GitHub, then starts the MCP server, which waits for a client on stdin" -->
```bash
uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.7.0 ash mcp
```

When the server starts, it waits for a client; Ctrl+C stops it. If ASH is already installed, the server command can be `ash` with the argument `mcp` instead. Desktop apps often see a shorter PATH than a shell, so an absolute path to `uvx` or `ash` can fix a server that starts in a terminal and not in the agent.

## Scanners are MISSING

`check_installation` names each built-in scanner that ASH enables by default and whose tool is missing in `missing_dependencies`. A scanner whose tool the first scan installs with uv, when the server is online and has uv, is in `installs_on_first_scan` instead. A scanner whose tool is not installed, and that has files to scan, ends as MISSING, and the scan ends `incomplete`. With the user's agreement, `ash dependencies install` installs the tools for the user that runs the server; then scan again. A tool installed only inside the scanned project does not count.

## The scan does not reach a final status

Poll `get_scan_progress` until `is_complete` is true. It is true for every final status, `incomplete` included.

ASH stops a scanner's tool after its `scan_timeout` option, 1800 seconds unless the project's ASH config sets `scanners.<name>.options.scan_timeout`. The server also stops a whole scan after its operator's `scan_timeout_seconds`, 1800 seconds by default, and reports it `failed` with an `error_message` that names the limit; a project's config cannot change that limit. For a large project, scan a subdirectory, or disable the scanners you do not need in the config. To stop a scan, call `cancel_scan`.

## `run_ash_scan` returns `scan_start_failure`

The scan did not start, and `error` says why:

- `max_concurrent_scans limit`: the server is running as many scans as its operator allows. Start the scan again when one has finished, or cancel one you no longer need.
- `already has an active scan`: a scan of that directory is running. Wait for it, or cancel it.
- `still stopping`: a canceled scan of that directory has not stopped yet. Try again in a few seconds. A canceled scan that was waiting for another scan of its session stops only when that scan ends.

## No findings, but the project has problems

- `get_scan_results` lists findings only with `actionable_only` set, in a response at the default `filter_level`, `full`, and then only the actionable ones: not suppressed, and at or above the threshold their scanner was judged by. A `summary` or `minimal` response has counts and no `findings` list. `reports/ash.flat.json` in the output directory has every finding, the suppressed ones with `is_suppressed` true.
- After a failed or canceled scan, `results_available` is false. When `output_holds_previous_results` is true, the files in the output directory are the previous scan's, and the results tools refuse that directory with `error_category` `scan_incomplete`.
- A scanner that did not run reports nothing. Check `incomplete_scanners` and `skipped_scanners` in the final progress response.
- Check which config the scan read. Without `config_path`, `run_ash_scan` uses the ASH config it finds in the project.

## `scan_target_not_permitted`

The server refuses to scan that directory. It always refuses system directories such as `/etc` and `/root`, and when `ASH_MCP_ALLOWED_ROOTS` is set in the server's environment it refuses everything outside the directories that variable names. Ask the user to scan another directory or to change the server's environment.

## `output_dir_not_permitted`

`.ash` or `.ash/ash_output` in the project is a symbolic link, and ASH does not write through one. Ask the user to replace it with a directory.

## Delivering source to a remote server is refused

- `source_delivery_busy`: a scan of this session is running, or the session's source is being replaced. Call the tool again once the scan has finished.
- `session_workspace_busy`: the server is removing this session's workspace, which nobody used for longer than its time to live. Call `select_profile` again if the session had a profile, and send the upload again from chunk 0.
- `clone_host_not_permitted`: the server clones only from the hosts in its `ASH_MCP_GIT_ALLOWED_HOSTS`, none by default. Deliver the source as a zip with `set_source_zip_chunk` and `set_source_zip_finalize`, or ask the user to add the host.
- `local_clone_source_refused`: `set_source_git` never clones a local path or `file://` URL. Pass the directory as `run_ash_scan`'s `source_dir` instead.
- `ssh_key_not_registered`: leave out `ssh_key_id`; the server registers no SSH keys.
- `clone_url_not_permitted` or `clone_ref_not_permitted`: `set_source_git` takes only an `https` or `ssh` URL, and no URL or ref that begins with `-` or uses the `ext::` transport.
- `invalid_clone_depth`: `depth` is a whole number of commits, 1 or more. Leave it out for the latest commit.
- `git_clone_failed` or `git_checkout_failed`: git ran and failed; `error` has its message. Check the URL and ref, or deliver the source as a zip.
- `clone_timed_out`: a git command ran past 10 minutes. Deliver the source as a zip.
- `invalid_session_id`: the server refused the session ID the call carries. Tell the user.
- `session_identity_required`: the server runs stateless and cannot tell which session a call belongs to, so it refuses the tools that keep state for a session. Tell the user.

## A suppression does not apply

Suppressions go under `global_settings.suppressions` in the project's ASH config, and each entry needs `path` and `reason`. `path` is relative to the scanned directory, and a `path` that starts with `./` matches nothing. From its `expiration` date on, an entry no longer applies. `ash config validate`, run in the project, checks the config a scan there would use the way the scan loads it, names each invalid field, and exits with code 3 when a scan would refuse it; `--config <file>` checks another file. A key that a suppression does not have, such as `expiry`, is an error. After the next scan, `reports/ash.unused-suppressions.json` lists the suppressions that matched no finding.
