# Workspace mode over MCP

Workspace mode resolves a VS Code `.code-workspace` file into N projects, scans each one with its own ASH config and its own severity threshold, and aggregates the results into a single workspace payload. It was CLI-only (`ash --workspace foo.code-workspace`). Two MCP tools now expose it:

- `resolve_ash_workspace` — resolves the workspace and returns the plan. Scans nothing.
- `run_ash_workspace_scan` — resolves, scans every project, and returns the per-project verdict.

Both are registered on the same server as the single-directory tools documented in the [ASH MCP Server Guide](../mcp-server-guide.md), and both work over stdio and streamable-HTTP.

## When to use which

`resolve_ash_workspace` is the MCP equivalent of `ash --workspace ... --dry-run`. It reads the workspace definition and every project's own ASH config, then reports which directories became projects, what key each was given, which config file was found for it, which scanners that config enables, which threshold the project will be judged against, and which projects were dropped and why. Nothing is scanned, no output tree is written, and no registry slot is taken.

Call it first when a workspace is unfamiliar. Resolution is the cheap half; a workspace of eight repositories can take minutes to scan and milliseconds to resolve, and a definition problem — a folder nobody cloned, two entries naming one directory, a project config that will not parse — surfaces in the resolve call rather than after the scan has already run.

`run_ash_workspace_scan` then scans the same plan from the same inputs. Unlike `run_ash_scan`, it does not return early with a scan ID: it waits for the whole workspace and returns the verdict.

## resolve_ash_workspace

```python
resolve_ash_workspace(
    workspace_file="/srv/repos/platform/dev.code-workspace",
    workspace_config="/etc/ash/workspace-policy.yaml",   # optional
    allow_missing_projects=False,                        # optional
    config_overrides=["global_settings.severity_threshold=HIGH"],  # optional
)
```

| Argument | Meaning |
|---|---|
| `workspace_file` | Absolute path to the `.code-workspace` definition. |
| `workspace_config` | Path to a workspace policy file. Must exist when given; ASH does not fall back to searching for one, because that would apply different policy than the one you named. Omit it and the workspace root is searched, and having no policy is not an error. |
| `allow_missing_projects` | Mark project directories that are absent or unreadable as skipped instead of refusing the workspace. They stay in the plan, so the response still accounts for every folder the definition listed. |
| `config_overrides` | `key=value` overrides, applied to each project's config during resolution. Applied here and not only at scan time, so the threshold the plan reports is the threshold a scan will enforce. |

The response carries:

- `plan` — the rendered plan, the same text `ash --workspace ... --dry-run` prints. Written for a human to read; its layout is not a contract.
- `projects` — the same decisions as structured data. Read this if you need to branch on a threshold or a scanner list.
- `skipped_projects` — one entry per dropped project, with a reason.
- `exit_code` — `0` on success. See [Exit codes](#exit-codes).

## run_ash_workspace_scan

```python
run_ash_workspace_scan(
    workspace_file="/srv/repos/platform/dev.code-workspace",
    workspace_config="/etc/ash/workspace-policy.yaml",   # optional
    allow_missing_projects=False,                        # optional
    config_overrides=None,                               # optional
    output_dir=None,                                     # optional
    scanners=None,                                       # optional
    excluded_scanners=None,                              # optional
    offline=False,                                       # optional
    clean_output=True,                                   # optional
)
```

The first four arguments mean what they mean for `resolve_ash_workspace`. The rest:

| Argument | Meaning |
|---|---|
| `output_dir` | Where the workspace output tree goes. Defaults to `<workspace root>/.ash/ash_output`, with each project's own output under `<output_dir>/projects/<project key>/`. The default is beneath the workspace root and not beneath the server's working directory, which for a server launched by an editor or an agent is whatever that process happened to have. |
| `scanners` | Restrict every project to these scanner names. |
| `excluded_scanners` | Exclude these scanners from every project. Takes precedence over `scanners`. |
| `offline` | Run without network access. |
| `clean_output` | Remove each project's previous `ash_aggregated_results.json` before scanning. Runs after the confinement check, never before it. |

The response carries:

- `scan_ids` — a map from project key to registry scan ID. One entry per project that will actually be scanned.
- `projects` — each project's status, finding counts, threshold and whether it exceeded that threshold.
- `results_path` — where the unified workspace results were written.
- `exit_code` — the workspace verdict.

`success` reports whether the scan ran, not whether it passed. A scan that found actionable findings ran fine; the verdict is in `exit_code`.

### One registry entry per project

Every existing MCP scan is one directory and one registry entry, so "which scan is this" and "which directory is this" have always been the same question. A workspace scan is one tool call over N directories, so it registers N entries. Each project key in `scan_ids` maps to an ID you can hand to `get_scan_progress` and `get_scan_results` for that project alone.

A project skipped at resolution gets no entry and no ID. A registry entry is a claim that a scan is pending or running on a directory; making that claim for a directory nobody will scan would block a later legitimate scan of the same path and would make `list_active_scans` report work nobody is doing.

### Progress reporting

Progress arrives as completed projects over total projects, with the project key in the message — `payments-api complete (3/7 projects)`. `report_progress` carries three fields and none of them is a project, so the project has to travel in the message.

The denominator is projects and not scanners on purpose. ASH's per-scanner progress estimate only ever grows as more scanner result files appear, and each project's fraction is capped below 1.0, so summing per-project fractions produces a number that drifts and never arrives — a client watching it could not tell a stalled scan from a slow one. A project count terminates.

## Allowed roots govern the projects, not the workspace file

`ASH_MCP_ALLOWED_ROOTS` is the setting that bounds what the MCP server may scan. It applies to a workspace scan project by project: every project directory the workspace resolves to is checked against it.

That is a wider reach than the single-directory tools have, arrived at indirectly. `run_ash_scan` is handed one directory by the client. A workspace scan is handed one *file* and gets N directories out of it, none of which the client stated — so checking the workspace root alone would be worse than useless, since the resolver already guarantees every project sits below the root and one allowlisted root would then authorize the whole tree beneath it.

**One project outside the permitted roots refuses the whole workspace.** Nothing is scanned, and the error names the offending project keys. Scanning the projects that pass and reporting success is the failure workspace mode exists to prevent: a green result covering fewer projects than you asked for, with the passing projects supplying the reassurance. There is no `--allow-missing-projects` equivalent for this, because a confinement refusal is a fact about what the server is permitted to touch rather than a fact about this machine.

Two paths are deliberately **not** subject to the roots:

- the `.code-workspace` file itself, and
- the `workspace_config` policy file.

Both are config inputs. `ASH_MCP_ALLOWED_ROOTS` answers "which directories may the server read source from and write an output tree into", and neither of these is that — each is read once, nothing is written near it, and they are supplied by the same caller who supplies `config_path` on `run_ash_scan`, which the roots also leave alone. Confining them would break the ordinary arrangement where workspace definitions sit beside a checkout rather than inside one, and where one policy file governs several checkouts.

So a working configuration looks like this:

```bash
ASH_MCP_ALLOWED_ROOTS=/srv/repos ash mcp
```

with the definition at `/srv/repos/platform/dev.code-workspace`, its projects at `/srv/repos/platform/api` and `/srv/repos/platform/web`, and a shared policy at `/etc/ash/workspace-policy.yaml`. One root entry covers every project beneath it at any depth; you do not enumerate projects, and you do not re-edit the variable when the workspace gains one.

### With ASH_MCP_ALLOWED_ROOTS unset, only the minimal system-directory denylist applies

Say this plainly, because it is easy to assume otherwise: leaving the variable unset does not bound a workspace scan. It leaves the short fixed refusal list in force — on Linux and macOS `/boot`, `/dev`, `/etc`, `/proc`, `/root`, `/sys` and the filesystem root; on Windows the Windows directory, `Program Files`, `ProgramData` and a bare drive root. Everything else is accepted, including home directories, `/usr` and `/var`, because that is where code lives.

That list is a safety net, not a security boundary. It declines the handful of directories that hold host configuration and kernel interfaces rather than source code, and it says nothing about the rest of the filesystem. A `.code-workspace` file can list any folder below its own root, so on a server with the variable unset, a workspace definition is free to point the scanner at essentially any tree the server process can read. If you need the surface actually bounded, set `ASH_MCP_ALLOWED_ROOTS`; nothing else here does that job. Setting it replaces the default list rather than adding to it, which is also how a deliberate scan of a system directory is arranged.

## Ordering: resolve, then confine, then scan

The order is forced by what each step needs, and it shows up in the errors you get.

Confinement cannot run first, because it needs the resolved project directories and only resolution produces them. So a workspace file that is both malformed and outside the permitted roots reports the malformation — a folder nobody cloned, say — rather than the confinement refusal. That is the right way round: the malformation is the part you can act on, and reporting the refusal would send you to edit an environment variable when the real problem is a line in the workspace file.

Every filesystem write happens after the confinement check, including the `clean_output` deletion and the creation of each project's output directory. A refused workspace leaves nothing behind.

## Exit codes

Both tools return an `exit_code` alongside the standard error keys, carrying the code the CLI would have exited with, plus `exit_code_meaning` with the documented description. The distinction matters because it routes to different people:

| `exit_code` | Meaning | Who acts |
|---|---|---|
| `0` | Success. | — |
| `2` | Actionable findings above a threshold. The scan ran. | The owners of the projects listed with `exceeds_threshold` true. |
| `3` | Invalid project config. The workspace is fine and one project's own config is not. | That project's owner. The message names the project. |
| `4` | Workspace definition, policy, or confinement refusal. | Whoever owns the workspace file or the server's allowed roots. |
| `1` | Internal error — an ASH bug, not your input. | File an issue. |

An unexpected failure is reported as `1` and not as `4` on purpose. Reporting an ASH bug as a workspace error would send you to inspect a workspace file that is correct.

### Why these tools never exit the process

The CLI's workspace path is built to exit: `interactions/run_ash_scan.py` calls `sys.exit` on a non-zero workspace code, and `_run_workspace_mode` calls `sys.exit` on all three of its failure paths. That is correct for a process whose only job is one scan.

It would be fatal for a server. `SystemExit` derives from `BaseException` rather than `Exception`, so the `except Exception` handlers that wrap the MCP tools would not catch it: one malformed `.code-workspace` file from one client would terminate the interpreter and take every other session's in-flight scan with it — and silently from the clients' point of view, because the connection simply drops.

So the MCP tools call `resolve_workspace` and `execute_workspace` directly. Both raise and neither exits, and every failure comes back as a response dictionary carrying the exit code.

## Container mode

Workspace mode over MCP always runs locally. The MCP tools do not accept a run mode, and the local workspace branch is the one gated at `automated_security_helper/interactions/run_ash_scan.py:1085` on `opts.mode != RunMode.container`.

The CLI's `ash --workspace --mode container` works by running `ash --workspace` *inside* the container and reading the workspace payload back out. There is no MCP equivalent, and adding one would mean the server building or pulling an image and starting a container on behalf of a client — which is a materially different privilege from reading a directory. If you need workspace mode in a container, drive the CLI.

## Known limitations

- **The scan is synchronous.** `run_ash_workspace_scan` returns when the whole workspace is done. It runs off the event loop so the server stays responsive to other sessions, and it emits progress notifications, but there is no early-return-with-a-handle form the way `run_ash_scan` has. For a large workspace, make sure your client's tool timeout accommodates the full run.
- **Two spellings of one directory are a refusal, not a de-duplication.** A definition listing both `proj` and `proj/` is refused. De-duplicating silently would change what you asked for, and an operator who wrote two entries meant something by it.
- **A failed project writes no results file, so it never counts as complete in the progress stream.** Progress stops short rather than reaching the total. The verdict is in the return value, not in the progress notifications; progress is a liveness signal.

## Related documentation

- [ASH MCP Server Guide](../mcp-server-guide.md) — the single-directory tools, the scan registry, and the allowed-roots setting in full.
- [Streamable-HTTP MCP Deployment Guide](streamable-http.md) — running the server over the network, with per-session workspaces and config profiles.
- [CLI Reference](../cli-reference.md) — `ash --workspace` and its flags.
