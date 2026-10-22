# ASH MCP Server Guide

This guide provides comprehensive documentation for the ASH MCP server implementation, which uses a file-based approach to track scan progress and completion.

## Overview

The Automated Security Helper (ASH) MCP server provides a reliable interface for AI assistants to perform security scans on your codebase. The server implements the Model Context Protocol (MCP) to enable seamless integration with AI assistants.

The MCP server uses a file-based approach to track scan progress and completion, making it more reliable than event-based tracking. This approach ensures that scan progress and results are accurately tracked even in complex threading scenarios.

### Transport choice

`ash mcp` supports two transports:

- **stdio (default)** — local, single-user, launched as a subprocess by an IDE or local agent. This is what every example below assumes.
- **streamable-HTTP** — networked, multi-tenant, supports remote clients with per-session workspaces and config profiles. See [Streamable-HTTP MCP Deployment Guide](mcp/streamable-http.md).

Pick stdio for local IDE integration. Pick streamable-HTTP when ASH must be reachable over the network.

### Lifetime over stdio

A stdio server lives as long as its client. The client starts `ash mcp` and is the only thing that can talk to it, so when the client closes the connection the server stops: it cancels every scan still running, waits up to 1.5 seconds for them to stop, and exits. That is inside the window the MCP SDK's stdio client gives a server it shuts down, which is SIGTERM two seconds after it closes the server's stdin and SIGKILL two seconds after that. A scan stopped this way ends like one stopped with `cancel_scan`, except that its scanner's tool and every process it started get SIGKILL half a second after SIGTERM rather than ten, and the previous scan's results in its output directory are put back (see [Output formats](output-formats.md#generating-reports)), so none of the results it wrote half-way stays behind, only its logs, `ash.log` and `ash.log.jsonl`; a scan with no previous results keeps what it wrote before it stopped (see [cancel_scan](#cancel_scan)). On Linux and macOS, SIGTERM, from the client or anything else, SIGHUP, from a closed terminal or a supervisor, and Ctrl-C (SIGINT) are handled the same way, whether or not the client has closed stdin: the server stops its scans and exits, with status 0 for SIGTERM and SIGHUP and 130 for Ctrl-C, also when the signal arrives while the server waits for such a scan after the client has gone. On Windows, Ctrl-C reaches the server but not its scanners' tools, which run in process groups of their own, and the server stops its scans as it does when the client leaves, but it exits, with status 130, only once the client has closed stdin, because the MCP SDK reads stdin on a thread that Ctrl-C cannot interrupt. A scan still running after the 1.5 seconds, one busy outside a scanner's tool, is left to the process exit; its previous results stay in `.ash_previous_results/` and the next MCP scan in that directory takes them back.

A streamable-HTTP or SSE server stops its scans the same way when it shuts down: on Ctrl-C, SIGTERM or SIGHUP it stops them promptly, waits up to 1.5 seconds, and kills what is left of their scanners' tools. It then exits with status 130 on Ctrl-C and 0 on SIGHUP, also when a scan busy outside a scanner's tool is still running; that scan's previous results stay in `.ash_previous_results/`, as on stdio. On SIGTERM, uvicorn raises the signal again once it has stopped, so the process ends by SIGTERM (status 143 in a shell). Before any of that, uvicorn waits up to 5 seconds for the connections still open to close, and the scans go on running while it waits; then it cancels the requests still open and the stop above runs. The wait is short because a service manager follows SIGTERM with SIGKILL once a grace period of its own runs out ([`docker stop`](https://docs.docker.com/reference/cli/docker/container/stop/) waits 10 seconds for a Linux container), and a SIGKILL leaves the scanners' tools running. A second Ctrl-C during that wait kills the scanners' tools and exits with status 130 at once, without waiting for the scans; previous results a scan had not put back by then are taken back by the next MCP scan in its directory. If the server itself fails, it kills the tools on its way out.

On every transport, a server started with SIGINT ignored leaves it ignored. A shell starts a background job that way (`ash mcp --transport streamable-http &`), so a Ctrl-C meant for the job in the foreground does not stop the server. SIGTERM still does. Likewise a server started with SIGHUP ignored, as `nohup` starts one, leaves that ignored on every transport, so it outlives the terminal it was started from.

On any transport, a scanner's tool runs in a process group of its own, so a SIGKILL of the server alone, or a crash of the Python process, leaves the tool running. It writes into the scan's `.ash/ash_output` until it finishes, and that scan's previous results stay in `.ash_previous_results/`. Stop such a server with SIGTERM, or send the SIGKILL to the tool's process group as well.

This is deliberate. The alternative, finishing the scan after the client has gone, keeps a process running whose results nobody can poll or collect, and the next client starts a new server anyway. Use the streamable-HTTP transport when scans have to outlive a client's connection.

Exit status of `ash mcp` over stdio:

| Status | When |
|--------|------|
| `0` | The client closed the connection, including while the server was writing to it, or the server was stopped with SIGTERM or SIGHUP |
| `1` | The server failed while serving, or the MCP dependencies are not installed. The error is printed to stderr, also with `--quiet` |
| `3` | The options are invalid (for example `--quiet` with `--debug`, or an unreadable `--profile`) |
| `130` | The server was stopped with Ctrl-C (SIGINT). The same on every transport |

A scan that fails does not stop the server or set its exit status: the scan's status says it failed, and the server goes on serving.

Nothing but JSON-RPC frames is written to stdout, during the session or after it. ASH's own output, a scan's output, and the output of the tools a scan runs all go to stderr; MCP scans run without the live progress display, which is for a terminal.

A request line that the MCP SDK can't parse as JSON, for example one holding a lone surrogate escape such as `\udce9`, gets no reply; the client's request times out.

## Architecture

The ASH MCP server architecture consists of the following components:

1. **MCP Server**: The main server component that registers and exposes MCP tools
2. **Scan Registry**: A thread-safe registry that tracks active scans
3. **File-Based Tracking**: A system that uses file existence to track scan progress
4. **Error Handling**: Comprehensive error handling for various scenarios

### File-Based Tracking Approach

The file-based tracking approach works as follows:

1. When a scan is started, a unique scan ID is generated and registered in the scan registry
2. The scan process is started asynchronously
3. The scan progress is tracked by checking for the existence of result files:
   - `ash_aggregated_results.json`: Indicates the scan has completed
   - Individual scanner result files: Indicate which scanners have completed
4. The scan results are retrieved by parsing these files

This approach is more reliable than event-based tracking because it doesn't depend on in-memory state that could be lost due to threading issues.

### File Structure

The file structure used for tracking is as follows:

```
.ash/ash_output/
├── ash_aggregated_results.json       # Complete scan results
├── scanners/
│   ├── bandit/
│   │   ├── source/
│   │   │   └── ASH.ScanResults.json  # Bandit scanner results
│   ├── detect-secrets/
│   │   ├── source/
│   │   │   └── ASH.ScanResults.json  # Detect-secrets scanner results
│   └── ...
└── reports/
    ├── ash_report.csv                # CSV report
    ├── ash_report.html               # HTML report
    └── ash_report.md                 # Markdown report
```

## MCP Tools

The ASH MCP server provides the following tools:

### scan_directory

Starts a security scan asynchronously and returns a scan ID for tracking.

**Parameters:**
- `directory_path` (required): Path to the directory to scan
- `severity_threshold` (optional): The least severe finding that still counts as actionable (ALL, LOW, MEDIUM, HIGH, CRITICAL, in any case). It can make the config's `global_settings.severity_threshold` stricter for this scan, never looser: the scan runs at the stricter of the two, so `LOW` over a configured `HIGH` applies and `CRITICAL` over a configured `MEDIUM` does not. Omit it to use the config's own (MEDIUM unless the config sets one)
- `config_path` (optional): Path to ASH configuration file

**Returns:**
A dictionary with scan ID and status information.

**Example:**
```python
result = await mcp_scan_directory(
    directory_path="/path/to/your/code", severity_threshold="MEDIUM", config_path=None
)
```

**Example Response:**
```json
{
  "success": true,
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "directory_path": "/path/to/your/code",
  "output_directory": "/path/to/your/code/.ash/ash_output",
  "severity_threshold": "MEDIUM",
  "config_path": null,
  "start_time": "2025-07-16T12:34:56.789012",
  "message": "Scan started successfully. Use get_scan_progress to track progress."
}
```

### get_scan_progress

Gets the current progress of a running scan using file-based tracking. Only a
scan the calling session started is visible; another session's scan id gets the
same response as an id that was never issued.

**Parameters:**
- `scan_id` (required): The scan ID returned from scan_directory

**Returns:**
A dictionary with scan progress information.

**Example:**
```python
progress = await mcp_get_scan_progress(scan_id="550e8400-e29b-41d4-a716-446655440000")
```

**Example Response:**
```json
{
  "success": true,
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "completed_scanners": 2,
  "total_scanners": 5,
  "scanners": {
    "bandit": {
      "status": "completed",
      "target_type": "source",
      "finding_count": 3,
      "severity_counts": {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 0,
        "CRITICAL": 0
      }
    },
    "detect-secrets": {
      "status": "completed",
      "target_type": "source",
      "finding_count": 0,
      "severity_counts": {}
    },
    "semgrep": {
      "status": "running",
      "target_type": "source"
    },
    "checkov": {
      "status": "pending",
      "target_type": "source"
    },
    "cdk-nag": {
      "status": "pending",
      "target_type": "source"
    }
  },
  "start_time": "2025-07-16T12:34:56.789012",
  "current_time": "2025-07-16T12:36:23.456789",
  "duration": 86.667777,
  "timestamp": "2025-07-16T12:36:23.456789"
}
```

### get_scan_results

Gets the final results of a completed scan using file-based tracking.

**Parameters:**
- `scan_id` (required): The scan ID returned from scan_directory

**Returns:**
A dictionary with scan results information.

**Example:**
```python
results = await mcp_get_scan_results(scan_id="550e8400-e29b-41d4-a716-446655440000")
```

**Example Response:**
```json
{
  "success": true,
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "finding_count": 5,
  "severity_counts": {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 1,
    "CRITICAL": 0
  },
  "findings": [
    {
      "id": "finding-1",
      "title": "Hardcoded password",
      "severity": "HIGH",
      "scanner": "detect-secrets",
      "file_path": "config.py",
      "line_number": 42,
      "description": "Hardcoded password found in configuration file"
    },
    // Additional findings...
  ],
  "scan_duration": 124.567890,
  "start_time": "2025-07-16T12:34:56.789012",
  "end_time": "2025-07-16T12:37:01.356902",
  "timestamp": "2025-07-16T12:37:01.356902"
}
```

### list_active_scans

Lists the calling session's active and recent scans with their current status.
Another session's scans are not listed, and `stats` counts only this session's.
On stdio there is one client, so it sees every scan it started.

**Parameters:**
None

**Returns:**
A dictionary with information about all scans in the registry.

**Example:**
```python
scans = await mcp_list_active_scans()
```

**Example Response:**
```json
{
  "success": true,
  "active_scans": [
    {
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "status": "running",
      "directory_path": "/path/to/your/code",
      "start_time": "2025-07-16T12:34:56.789012"
    }
  ],
  "all_scans": [
    {
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "status": "running",
      "directory_path": "/path/to/your/code",
      "start_time": "2025-07-16T12:34:56.789012"
    },
    {
      "scan_id": "660e8400-e29b-41d4-a716-446655440000",
      "status": "completed",
      "directory_path": "/path/to/another/code",
      "start_time": "2025-07-16T11:22:33.444555",
      "end_time": "2025-07-16T11:25:12.345678"
    }
  ],
  "stats": {
    "total_scans": 2,
    "active_scans": 1,
    "status_counts": {
      "running": 1,
      "completed": 1,
      "failed": 0,
      "cancelled": 0
    }
  },
  "timestamp": "2025-07-16T12:36:23.456789"
}
```

### cancel_scan

Cancels a running scan and stops it. Only a scan the calling session started can be cancelled;
another session's scan id gets the same response as an id that was never issued. The scanner tool
running at the time is stopped with every
process it started (SIGTERM, then SIGKILL after 10 seconds). The scan stops at its next check: no
further scanner, phase or reporter starts, and no further results are written. Work already under
way that is not waiting on a child process, such as a scanner reading its tool's output, finishes
first and may still write under `scanners/` or `converted/`. The previous scan's results are then
put back in place of every result the cancelled scan wrote; its logs, `ash.log` and
`ash.log.jsonl`, stay. Without previous results, what it wrote before it stopped stays, except that its reports are removed when it stops during the report phase;
the unused-suppressions reporter's markdown file, which that reporter writes itself, stays even
then. The scan's status becomes `cancelled` at once, and the scan normally ends within a second, or
after the 10 seconds a scanner that ignores SIGTERM gets. Until it has, a new `run_ash_scan` of the
same directory is refused because the cancelled scan is still stopping. A scan that has already
finished cannot be cancelled: the response then has `success` set to `false` and the scan's status.
Cancelling one project of a workspace scan stops that project; the workspace's other projects carry
on, and its response reports the cancelled project as `failed`.

**Parameters:**
- `scan_id` (required): The scan ID to cancel

**Returns:**
A dictionary with cancellation result information.

**Example:**
```python
result = await mcp_cancel_scan(scan_id="550e8400-e29b-41d4-a716-446655440000")
```

**Example Response:**
```json
{
  "success": true,
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "cancelled",
  "message": "Scan cancelled successfully",
  "timestamp": "2025-07-16T12:36:45.123456"
}
```

### check_installation

Reports whether ASH can scan. Each built-in scanner is asked whether its dependencies are satisfied, by the same check `list_scanners` reports and a scan runs before starting a scanner. Each check may run the scanner's tool, so the call takes a few seconds. It installs and downloads nothing. A scanner whose tool is not installed yet, and that a scan installs with `uv` when it starts the scanner (bandit, checkov and semgrep on a fresh install, when the scan is not offline and `uv` is present), is listed in `installs_on_first_scan` rather than `missing_dependencies`. Only the scanners ASH ships are checked; community plugins are not loaded.

**Parameters:**
None

**Returns:**

- `installed`: ASH is installed and at least one enabled scanner can run, or will once the first scan installs its tool. `false` means a scan would run nothing.
- `ready`: every enabled scanner can run or is installed by the first scan, so a default scan is complete.
- `missing_dependencies`: enabled scanners whose tool is missing and that a scan cannot install. A scan reports them as not run.
- `installs_on_first_scan`: enabled scanners whose tool the first scan installs with `uv`. That scan needs network access, and takes longer while it installs them.
- `undetermined_dependencies`: enabled scanners whose check could not run.
- `scanners`: each built-in scanner's `name`, `enabled`, `dependencies_satisfied` (`true`, `false`, or `null` when undetermined), `installs_on_first_scan` and `version`.
- `ash_command_available` and `ash_command_output`: whether an `ash` executable is on `PATH`, and its path. The server scans in-process and does not need one.

**Example Response:**
```json
{
  "success": true,
  "installed": true,
  "ready": false,
  "version": "3.7.0",
  "scanners": [
    {"name": "bandit", "enabled": true, "dependencies_satisfied": true, "installs_on_first_scan": false, "version": "1.9.4"},
    {"name": "cdk_nag", "enabled": true, "dependencies_satisfied": false, "installs_on_first_scan": false, "version": null},
    {"name": "semgrep", "enabled": true, "dependencies_satisfied": false, "installs_on_first_scan": true, "version": null}
  ],
  "missing_dependencies": ["cdk_nag"],
  "installs_on_first_scan": ["semgrep"],
  "undetermined_dependencies": [],
  "ash_command_available": true,
  "ash_command_output": "/usr/local/bin/ash",
  "timestamp": "2026-10-11T12:37:12.345678"
}
```

### resolve_ash_workspace and run_ash_workspace_scan

Every tool above scans one directory. These two take a VS Code `.code-workspace`
file instead and cover N projects in one call, each with its own ASH config and
its own severity threshold. `resolve_ash_workspace` returns the plan without
scanning; `run_ash_workspace_scan` scans it and returns the per-project verdict,
registering one scan per project so progress and results can still be fetched
project by project.

Each project's coverage lists the converters that did not process their inputs in
`incomplete_converters`, next to the scanners in `incomplete_scanners`.

They differ from the single-directory tools in ways worth reading before you use
them: the allowed roots are checked per project and one project outside them
refuses the whole workspace, the workspace file and the workspace policy file are
not subject to the roots, and there is no container mode. See
[Workspace Mode over MCP](mcp/workspace-mode.md).

## Error Handling

The ASH MCP server provides comprehensive error handling for various scenarios. Each error response includes:

- `success`: Always `false` for error responses
- `operation`: The operation that was being performed
- `error`: Error message
- `error_type`: Type of error
- `error_category`: Category of error
- `context`: Additional context about the error
- `suggestions`: List of suggestions for resolving the error

### Error Categories

The following error categories are used:

- `file_not_found`: A required file or directory was not found
- `permission_denied`: Permission issues accessing files or directories
- `invalid_format`: File format or structure is invalid
- `invalid_parameter`: Invalid parameter values provided
- `invalid_path`: Path is invalid or improperly formatted
- `resource_exhausted`: System resources are exhausted
- `operation_timeout`: Operation took too long and timed out
- `scan_not_found`: Requested scan ID was not found in the registry
- `scan_incomplete`: Scan has not completed yet
- `plugin_module_refused`: The config's `ash_plugin_modules` entries are ones a scan refuses to import
- `unexpected_error`: An unexpected error occurred

### Config refusals

A config the server will not use is refused with its own `error_type`, so a client
can tell the reason apart from a scan that failed to start (`scan_start_failure`):

| `error_type` | Returned by | Meaning |
|---|---|---|
| `config_input_not_permitted` | `run_ash_scan`, `get_config`, and as a `validate_config` error `type` | The config path, or a base its `extends` chain names, is outside the directories this session may read a config from |
| `config_check_failed` | `run_ash_scan` | The check of the config sources in the scan target could not finish (an unreadable entry, a link loop), so the scan was not started. The config was not found outside the permitted roots; check the config files in the target for unreadable entries and link loops |
| `config_field_denied` | `run_ash_scan`, `get_config` | A config file an MCP client delivered or named sets a field the session's runtime-override policy denies; `error` names each field |
| `denied_by_runtime_policy` | `validate_config`, as an error `type` | The same, one error per field, with the field in `field` |
| `config_policy_unreadable` | `run_ash_scan`, `get_config`, and as a `validate_config` error `type` | The session's runtime-override policy cannot be established, for example because the profile it bound is no longer registered |
| `config_env_not_resolved` | `run_ash_scan`, `get_config`, and as a `validate_config` error `type` | A config file that may not use `!ENV` uses an `!ENV` tag, or a plain value that starts with a `${VAR}` or `${VAR:default}` reference. Which files that covers for a remote and for a stdio caller is in [Config files in delivered source](mcp/streamable-http.md#config-files-in-delivered-source) |

Delivering or clearing source while a scan of the same session runs is refused
as well: `set_source_git`, `set_source_zip_finalize` and `clear_source` return
`error_type: source_delivery_busy`. See
[Config files in delivered source](mcp/streamable-http.md#config-files-in-delivered-source).

### Example Error Response

```json
{
  "success": false,
  "operation": "get_scan_results",
  "error": "Scan 550e8400-e29b-41d4-a716-446655440000 not found",
  "error_type": "MCPResourceError",
  "error_category": "scan_not_found",
  "context": {
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "error_category": "scan_not_found"
  },
  "suggestions": [
    "Check that the scan ID is correct",
    "Verify that the scan exists in the registry",
    "The scan may have been cleaned up if it was completed a long time ago"
  ],
  "timestamp": "2025-07-16T12:37:12.345678"
}
```

## Configuration

### Server limits

The MCP server enforces two limits from the `mcp-resource-management` section. It reads them from
the operator's config, the file the `ASH_CONFIG` environment variable of the `ash mcp` process
names, and never from the config of a scan: a scanned repository's `.ash/.ash.yaml` or a config a
client delivers cannot change them. With no `ASH_CONFIG`, the defaults below apply.

```yaml
# The file ASH_CONFIG names for the ash mcp process
mcp-resource-management:
  max_concurrent_scans: 3      # default 3, up to 100; 0 or null for no limit
  scan_timeout_seconds: 1800   # default 1800 (30 min), 60-86400; 0 or null for no limit
```

The server reads its operator configuration from the file `ASH_CONFIG` names, for every scan that names no config of its own. It loads that file at startup, the way it loads each `--profile`. If `ASH_CONFIG` names a path that is not a file, or a file the server can't read, parse or validate, `ash mcp` refuses to start (exit 3) with an error naming the variable and the path. `python -m automated_security_helper.cli.mcp_server` starts the same way as `ash mcp` and makes the same checks.

### Configuration Options

- `max_concurrent_scans`: the most scans the server runs at once, counted across every session. A
  `run_ash_scan` or `run_ash_workspace_scan` beyond it is refused with `success: false` and an error
  naming the limit; start it again once a running scan finishes or is cancelled. A cancelled scan
  counts until it has stopped. A workspace scan counts as one scan however many projects it has, so
  a workspace with more projects than the limit can still run.
- `max_concurrent_scans_per_session`: Maximum number of scans one session of a network transport (streamable-http, sse) may run at once, default 2; `0` turns the per-session limit off. A `run_ash_workspace_scan` counts once, however many projects it has, and stdio's single session is not limited. A scan past the limit is refused with `error_type: session_scan_limit`, and other sessions are unaffected. Callers with no session the server issued (every caller of a stateless streamable-http server run without `--trust-upstream-session-id`, and a request that names no issued session) share one count under the same limit. Read only from the file `ASH_CONFIG` names, never from a config inside a scanned or delivered tree.
- `scan_timeout_seconds`: the longest one scan may run, counted from when it starts running, so
  the time a scan waits for another scan of its session is not counted. A scan still running then
  is stopped the way `cancel_scan` stops one, and reported as `failed` with an `error_message`
  naming the limit. For a workspace scan the limit covers the whole workspace: every project still
  running is stopped, every project is reported as `failed`, including one that had already
  finished (its files on disk are complete), and `run_ash_workspace_scan` returns
  `success: false` with `error_category` `operation_timeout` and the `scan_ids`.

The section declares more keys (`max_concurrent_tasks`, `thread_pool_max_workers`,
`operation_timeout_seconds`, `shutdown_timeout_seconds`, `memory_warning_threshold_mb`,
`memory_critical_threshold_mb`, `task_count_warning_threshold`, `max_message_size_bytes`,
`max_path_length`, `max_directory_size_mb`, `enable_health_checks`,
`health_check_interval_seconds`, `enable_resource_logging`, `log_resource_operations`). They are
accepted so existing configs keep validating, and nothing reads them.

### Tools and output inside the scanned directory

The server never runs a scanner or other tool found inside the scanned or delivered
directory, such as a project's `.venv/bin` or `node_modules/.bin`, whatever
`ASH_ALLOW_IN_TREE_TOOLS` says; install the scanners it uses outside the repository.
A scan whose `<target>/.ash` or `<target>/.ash/ash_output` is a symlink is refused
before it starts, with `error_type` `output_dir_not_permitted`. A scan with a symlink
at a working directory or a file ASH writes in that output tree, such as `reports` or
`ash.log`, fails before it writes anything, with `ASH exited with code 1:` followed by
the link and what to do. `run_ash_workspace_scan` refuses the whole call when its
`output_dir`, a directory or file ASH writes there, `projects/` or a project's
`projects/<key>` is a symlink. See
[Tools inside the scanned directory](advanced-usage.md#tools-inside-the-scanned-directory)
and [Output directory](concepts.md#output-directory).

### Restricting which directories can be scanned

An MCP client names the directory it wants scanned, and ASH writes its output
tree inside that directory (`<target>/.ash/ash_output`). `ASH_MCP_ALLOWED_ROOTS`
controls which directories the server will accept. It takes a list separated by
the platform path separator (`:` on Linux and macOS, `;` on Windows):

```bash
ASH_MCP_ALLOWED_ROOTS=/srv/repos:/home/build/work ash mcp
```

With it set, a scan target must resolve to one of those directories or
something beneath it; anything else is refused. Symlinks and `..` components are
resolved before the comparison, so a link inside an allowed root that points
outside it is refused. The per-session MCP workspace root is always allowed as
well, so source trees delivered over the protocol stay scannable.

With it unset, a caller on a network transport (sse or streamable-HTTP) may
scan only its own session workspace: every network caller is remote, whatever
headers it sends, and gets no fallback. See
[Session identity](mcp/streamable-http.md#session-identity).

With it unset on stdio, ASH refuses a short fixed list of system directories as
scan targets — on Linux and macOS `/boot`, `/dev`, `/etc`, `/proc`, `/root`, `/sys`
and the filesystem root; on Windows the Windows directory, `Program Files`,
`ProgramData` and a bare drive root. To scan one of these deliberately, name it
in `ASH_MCP_ALLOWED_ROOTS`, which replaces the list rather than adding to it.

That default is a safety net, not a security boundary. It declines a handful of
directories that hold host configuration and kernel interfaces rather than
source code, and it does not restrict anything else — home directories, `/usr`,
`/var` and the rest of the filesystem all remain valid scan targets, because
that is where code lives. If you need the scan surface actually bounded, set
`ASH_MCP_ALLOWED_ROOTS`; it is the only setting here that does that.

The same roots apply to the tools that take a caller-supplied results
*directory*: `get_scan_results`, `get_scan_summary`, `get_scan_result_paths` and
`explain_finding`. An output directory for a permitted scan lives at
`<source_dir>/.ash/ash_output`, beneath the target, so a root that allows a scan
already allows its results to be read; you do not list output directories
separately.

The roots do not govern the tools that take a path to an individual *file* —
`config_path` on `get_config`, `validate_config` and `run_ash_scan`, and the two
result files `diff_scan_results` compares. Those are a separate surface with
different requirements: profile configs are conventionally kept outside the
scanned tree (the deployment guide puts them in `/etc/ash/`), so applying the
scan roots to them would refuse the documented layout. If you need those
restricted, restrict them at the filesystem or with a fronting proxy.

`get_scan_progress` is not affected. It takes a scan ID, and the output
directory comes from the scan registry rather than from the caller, so polling a
running scan works regardless of what the roots name.

For `run_ash_workspace_scan` the roots are checked once per resolved project
directory, and one project outside them refuses the whole workspace rather than
scanning the rest. The `.code-workspace` file and the `workspace_config` policy
file are config inputs and are not subject to the roots, on the same reasoning as
`config_path` above. See
[Workspace Mode over MCP](mcp/workspace-mode.md#allowed-roots-govern-the-projects-not-the-workspace-file).

## Best Practices

When using the ASH MCP server, follow these best practices:

1. **Store scan IDs**: Always store the scan ID returned by `scan_directory` for later use
2. **Check scan progress**: Periodically check scan progress using `get_scan_progress`
3. **Handle errors gracefully**: Check the `success` field in responses and handle errors appropriately
4. **Clean up resources**: Cancel scans that are no longer needed using `cancel_scan`
5. **Validate parameters**: Ensure all parameters are valid before calling MCP tools
6. **Check installation**: Use `check_installation` to verify ASH is properly installed
7. **Configure appropriately**: Adjust configuration options based on your system resources and usage patterns
8. **Monitor resource usage**: Keep an eye on system resources during scans
9. **Implement timeouts**: Set appropriate timeouts for scans and operations
10. **Handle concurrent scans**: Limit the number of concurrent scans based on your system resources

## Examples

### Basic Scan Workflow

```python
# Start a scan
result = await mcp_scan_directory(
    directory_path="/path/to/your/code", severity_threshold="MEDIUM"
)

# Get the scan ID
scan_id = result["scan_id"]

# Check scan progress periodically
while True:
    progress = await mcp_get_scan_progress(scan_id=scan_id)

    if progress["status"] in ["completed", "failed", "cancelled"]:
        break

    # Wait before checking again
    await asyncio.sleep(5)

# Get scan results
if progress["status"] == "completed":
    results = await mcp_get_scan_results(scan_id=scan_id)
    # Process results
else:
    # Handle failure or cancellation
    print(f"Scan {scan_id} {progress['status']}")
```

### Handling Multiple Scans

```python
# Start multiple scans
scan_ids = []
for directory in directories:
    result = await mcp_scan_directory(
        directory_path=directory, severity_threshold="MEDIUM"
    )
    scan_ids.append(result["scan_id"])

# Check progress of all scans
completed_scans = set()
while len(completed_scans) < len(scan_ids):
    for scan_id in scan_ids:
        if scan_id in completed_scans:
            continue

        progress = await mcp_get_scan_progress(scan_id=scan_id)

        if progress["status"] in ["completed", "failed", "cancelled"]:
            completed_scans.add(scan_id)

    # Wait before checking again
    await asyncio.sleep(5)

# Get results for all completed scans
for scan_id in scan_ids:
    progress = await mcp_get_scan_progress(scan_id=scan_id)

    if progress["status"] == "completed":
        results = await mcp_get_scan_results(scan_id=scan_id)
        # Process results
    else:
        # Handle failure or cancellation
        print(f"Scan {scan_id} {progress['status']}")
```

### Error Handling Example

```python
# Start a scan with error handling
try:
    result = await mcp_scan_directory(
        directory_path="/path/to/your/code", severity_threshold="MEDIUM"
    )

    if not result["success"]:
        # Handle error
        print(f"Error: {result['error']}")
        print(f"Suggestions: {result['suggestions']}")
        return

    scan_id = result["scan_id"]

    # Check scan progress
    while True:
        progress = await mcp_get_scan_progress(scan_id=scan_id)

        if not progress["success"]:
            # Handle error
            print(f"Error: {progress['error']}")
            print(f"Suggestions: {progress['suggestions']}")
            return

        if progress["status"] in ["completed", "failed", "cancelled"]:
            break

        # Wait before checking again
        await asyncio.sleep(5)

    # Get scan results
    if progress["status"] == "completed":
        results = await mcp_get_scan_results(scan_id=scan_id)

        if not results["success"]:
            # Handle error
            print(f"Error: {results['error']}")
            print(f"Suggestions: {results['suggestions']}")
            return

        # Process results
    else:
        # Handle failure or cancellation
        print(f"Scan {scan_id} {progress['status']}")

except Exception as e:
    # Handle unexpected errors
    print(f"Unexpected error: {str(e)}")
```

## Related Documentation

- [MCP Tutorial](../tutorials/using-ash-with-mcp.md)
- [Workspace Mode over MCP](mcp/workspace-mode.md)
- [Streamable-HTTP MCP Deployment Guide](mcp/streamable-http.md)
- [MCP Performance and Scalability](mcp-performance-scalability.md)
- [Configuration Guide](configuration-guide.md)
- [ASH CLI Reference](cli-reference.md)