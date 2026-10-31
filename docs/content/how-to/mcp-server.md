# Run the MCP server

`ash mcp` starts ASH's Model Context Protocol server. An agent or IDE on your machine usually
starts it for you over stdio, as in [Connect an AI agent to ASH](../getting-started/agents.md).
This page is for running the server yourself: choosing a transport, limiting what clients can
reach, serving it over HTTP, and cleaning up after clients. Every option is listed in the
[CLI reference](../reference/cli.md#mcp), and every tool in the
[MCP tools reference](../reference/mcp-tools.md).

## How the server runs scans

- Scans run inside the server process, in local mode, with the scanner tools installed for
  the user that runs the server. Install them as that user with `ash dependencies install`.
  Nothing runs in a container.
- A scan writes its output to `.ash/ash_output` inside the directory it scans, so the server
  needs write access there. When the scan starts, it moves the previous scan's results into
  `.ash/ash_output/.ash_previous_results`, and it deletes them once it has results of its own.
  If the scan fails or is canceled, it puts them back in place of what it wrote, and
  `get_scan_progress` then reports `output_holds_previous_results` true; a first scan, with
  nothing to put back, leaves what it wrote. A call that `run_ash_scan` refuses leaves the
  previous results as they were. With `clean_output` false, the scan's own set-up moves the
  previous results a moment later instead.
- A scan uses the config ASH discovers in the scanned directory, or the file a client names
  with `config_path`. When there is neither, it uses the file `ASH_CONFIG` names in the
  server's environment, or the built-in defaults.
- If `.ash` or `.ash/ash_output` in the scanned directory is a symbolic link, `run_ash_scan`
  refuses before the scan starts, with `error_type` `output_dir_not_permitted`. A link deeper
  in the output directory, such as `reports` or `ash.log`, fails the scan, and
  `get_scan_progress` names the link in `error_message` and says to replace it in
  `.ash/ash_output` with a directory. `run_ash_workspace_scan` refuses an `output_dir` that is
  a link, or that has a link where ASH writes in it, including `projects` and
  `projects/<project>`, and asks for a directory that is not a link. [Output files](../reference/output-files.md#links) lists every path ASH checks.
- `run_ash_scan` also refuses before the scan starts when `source_dir` is a file, with
  `error_type` `source_dir_not_usable`, and when `.ash/ash_output` in it is a file or a
  directory the server cannot write, with `error_type` `output_dir_not_usable`.
  `run_ash_workspace_scan` refuses such an `output_dir` the same way. Each refusal has
  `exit_code` 5 and a message that names the case, such as
  `Output directory cannot be written: <path> (Permission denied)`, and nothing is created.
- A path that holds a NUL character is refused before the server looks it up, with
  `exit_code` 5: a `source_dir` is refused with `source_dir_not_usable`, and the `output_dir`
  of `run_ash_workspace_scan`, `get_scan_results`, `get_scan_summary` or
  `get_scan_result_paths` is refused with `output_dir_not_usable`. The workspace tools refuse
  a `workspace_file` or `workspace_config` that holds one with `exit_code` 4 and the message
  `Workspace definition is not a valid path: <path>` or
  `Workspace policy is not a valid path: <path>`. Each message shows the NUL as `\x00`, and
  nothing is created.
- MCP scans never run a tool found inside a scanned or delivered tree, whatever
  `ASH_ALLOW_IN_TREE_TOOLS` says, and `ash mcp` has no option to allow it. A scanner installed
  only inside the project, for example in its `.venv`, is reported as MISSING. See
  [Tools inside the scanned directory](../docs/advanced-usage.md#tools-inside-the-scanned-directory).

`ash mcp` exits with code 5 for an unknown option, a value of the wrong type, options that
cannot be combined, or an `ASH_MCP_TRANSPORT` that names no transport, and with code 3 when
a `--profile` file does not load, is kept inside the MCP workspace root where a client could
have supplied it (a config the server wrote there itself is fine), or sits inside a git checkout
under a scan root `ASH_MCP_ALLOWED_ROOTS` grants, or when an HTTP transport cannot listen on
its address. It also
exits with code 3 when `ASH_CONFIG` names no config file it can load. It exits
with code 1 when the MCP package is missing or the server fails, and prints the error to
standard error even with `--quiet`. Ctrl-C stops the server, and `ash mcp` exits with code
130 on every transport. A stdio server exits with code 0 when the client closes
the connection, and, on Linux and macOS, when it gets SIGTERM or SIGHUP. An HTTP server that
gets SIGTERM ends with the signal, which a shell reports as code 143. SIGHUP stops an HTTP
server the way SIGTERM does, and `ash mcp` then exits with code 0.

## Choose a transport

| Transport | Use it for | Clients connect to |
|-----------|------------|--------------------|
| `stdio`, the default | An agent or IDE on the same machine, which starts the server as a child process. | The server's standard input and output. |
| `streamable-http` | A client that cannot start a local process, or a server on another host. | `http://HOST:PORT/mcp` |
| `sse` | A client that supports only the older SSE transport, which the MCP SDK deprecates. | `http://HOST:PORT/sse` |

Use stdio whenever the client can start the server. The server is designed to serve one
trusted client. It does not keep clients apart, so do not share one server between users or
tools you would not trust with each other's source and results: run one server per user.

## Run over stdio

Clients start the server with this command and arguments:

<!-- doctest: config kind=mcp-client -->
```json
{
  "mcpServers": {
    "ash": {
      "command": "ash",
      "args": ["mcp"]
    }
  }
}
```

On stdio the server's standard output carries the protocol, so ASH writes every message and
log line to standard error, and so do the scans and the tools they run. `--quiet` hides the
startup messages. `--log-level`, `--verbose`, and `--debug` set the HTTP server's log level and
have no effect on stdio, and `--color` has no effect on any transport.

A stdio server lives as long as its client. When the client closes the connection, or, on
Linux and macOS, the server gets SIGTERM, SIGHUP, or Ctrl-C, it cancels every running scan as
`cancel_scan` would, except that each scanner's tool gets half a second after SIGTERM instead
of ten, waits up to 1.5 seconds for the scans to stop, and exits. SIGHUP comes from a closed
terminal or from a supervisor. SIGTERM, SIGHUP, and Ctrl-C stop the server this way even
while the client keeps the connection open, and it exits with code 0 for SIGTERM and SIGHUP
and 130 for Ctrl-C. A scan that stops in time leaves its output directory as
[`cancel_scan`](../reference/mcp-tools.md#cancel_scan) does: previous results are put
back, and with none, what the scan wrote before it stopped stays. Its log, `ash.log`, stays
either way, and an `ash.log.jsonl` already there is left as it was. A scan still busy after
the 1.5 seconds is left to the
process exit, and its previous results stay in `.ash/ash_output/.ash_previous_results`, where
the next MCP scan of that directory takes them back.

On Windows the server sets up no SIGTERM handling: a client or supervisor that ends the
process ends it at once, with the exit code that the ending process sets, and the running
scans are not stopped first. Their previous results stay in `.ash_previous_results` the same
way. Ctrl-C there does not reach the scanners' tools, which run in process groups of their
own, but the server stops its scans as it does when the client leaves. It exits, with code
130, only once the client has closed the connection, because the MCP SDK reads standard input
on a thread that Ctrl-C cannot interrupt.

On every transport, a server started with SIGINT ignored, as a non-interactive shell starts a
background job, keeps ignoring it, so a Ctrl-C meant for the job in the foreground does not
stop it. A server started with SIGHUP ignored, as `nohup` starts one, keeps ignoring that too,
and outlives the terminal it was started from. SIGTERM still stops either.

Over HTTP, a scan keeps running when its client disconnects, until it finishes or the server
stops. Use streamable HTTP when scans must outlive a client's connection.

### Limit what a local agent can scan

On stdio, with `ASH_MCP_ALLOWED_ROOTS` unset, an agent can scan, and read results from, any
directory the server's user can read, except the filesystem root, the workspaces of other
sessions, and a short list of system directories: `/boot`, `/dev`, `/etc`, `/proc`, `/root`,
and `/sys`, or on Windows the Windows, Program Files, and ProgramData directories. A project
inside one of them, such as `/root` when you work as root in a container, is refused until you
name it in the variable. To limit scan targets and result paths to the directories you name
and their subdirectories, set the variable in the server's environment:

<!-- doctest: config kind=mcp-client -->
```json
{
  "mcpServers": {
    "ash": {
      "command": "ash",
      "args": ["mcp"],
      "env": {
        "ASH_MCP_ALLOWED_ROOTS": "/home/me/src"
      }
    }
  }
}
```

Separate several directories with `:`, or with `;` on Windows. On stdio this does not limit
which config files a client can name with `config_path`: those are refused only in the
directories above. A file a client names counts as the client's, wherever it is, unless it is
in a directory `ASH_MCP_ALLOWED_CONFIG_ROOTS` names and no client delivered it (see
[What a delivered config cannot set](#what-a-delivered-config-cannot-set)).

## Run over streamable HTTP

The supported setup is one trusted client per server, an auth header on every request, and a
server that is reachable only on the loopback interface or through a proxy you control.

1. Choose a token:

    ```bash
    TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
    ```

2. Set the environment and start the server:

    <!-- doctest: illustrative reason="starts a server that runs until it is stopped" -->
    ```bash
    export ASH_MCP_TRANSPORT=streamable-http
    export ASH_MCP_ALLOWED_ROOTS="$HOME/src"
    ash mcp --transport streamable-http --auth-header-name X-ASH-Token --auth-header-value "$TOKEN"
    ```

    The server prints `Streamable-HTTP MCP server listening on http://127.0.0.1:8000/mcp` to
    standard error. `--host`, `--port`, and `--mount-path` change the address, which defaults
    to `127.0.0.1`, port `8000`, path `/mcp`.

3. Point the client at the URL and give it the header. In Claude Code, for example:

    <!-- doctest: illustrative reason="needs Claude Code" -->
    ```bash
    claude mcp add --transport http ash http://127.0.0.1:8000/mcp --header "X-ASH-Token: $TOKEN"
    ```

`--auth-header-name` and `--auth-header-value` must be given together; one without the other
is a usage error, and `ash mcp` exits with code 5 before it starts:

<!-- doctest: run expect-exit=5 -->
```bash
ash mcp --transport streamable-http --auth-header-name X-ASH-Token
```

The header name is matched without regard to case, and every request, on
every path and method, must carry the exact value. A request without it gets
`401 Unauthorized`. The auth header is the server's only access control. The value is passed
on the command line, so anyone who can list the host's processes can read it: run the server
where other users cannot read its command line. ASH writes no access log; log requests at
your proxy if you need a record.

Always set `ASH_MCP_TRANSPORT` to the transport you serve, `streamable-http` or `sse`. ASH
ignores the value's case and surrounding whitespace. A value that names no transport, one
other than `stdio`, `streamable-http`, or `sse`, makes `ash mcp` exit with code 5 before it
starts:

<!-- doctest: run expect-exit=5 -->
```bash
ASH_MCP_TRANSPORT=http ash mcp
```

`ash mcp` does not set the variable for you. With it set, ASH applies its rules for remote
clients to every call:

- A client can scan, and read results from, only the directories in `ASH_MCP_ALLOWED_ROOTS`
  and source delivered over MCP. With the variable unset, it can scan only delivered source.
- A client can name config files (`config_path`, every base an `extends` chain names, and
  workspace files) only in `ASH_MCP_ALLOWED_CONFIG_ROOTS`, the scan roots, and its session's
  `config/` directory. The workspace tools use a workspace policy file only from
  `ASH_MCP_ALLOWED_CONFIG_ROOTS`, on every transport
  ([Workspace scans over MCP](scale-large-repos.md#workspaces-mcp)).

These rules limit what the server's client can reach. They do not keep clients apart, so
serve one trusted client per server.

Ctrl-C, SIGTERM, or SIGHUP stops an HTTP server: it stops its running scans and their
scanners' tools, and `ash mcp` exits with code 130 for Ctrl-C and 0 for SIGHUP, or ends by
SIGTERM, which a shell reports as code 143. Before it stops the scans, the server waits for
the requests clients still hold open, for at most 5 seconds, and then cancels them. The wait is
bounded so that the whole stop fits inside the grace period a service manager gives before it
sends SIGKILL, such as the 10 seconds `docker stop` waits by default: a SIGKILL of the server
leaves the scanners' tools running. A second Ctrl-C during the wait ends the server at once,
with code 130. It kills the scanners' tools without waiting for the scans, and previous results
a scan had not put back stay in `.ash_previous_results`, where the next MCP scan of that
directory takes them back.

### Serve clients on another host

ASH serves plain HTTP. Put a proxy you control in front of it for TLS, and keep the server on
the loopback interface when the proxy runs on the same host. If the proxy forwards the
client's Host header, pass `--allowed-host` with that name even when the server listens on
loopback. If the server must listen on another address, name every Host header value it
should accept:

<!-- doctest: illustrative reason="starts a server that runs until it is stopped" -->
```bash
ash mcp --transport streamable-http --host 0.0.0.0 --allowed-host ash.example.com \
  --auth-header-name X-ASH-Token --auth-header-value "$TOKEN"
```

Always pass `--allowed-host` with a non-loopback `--host`. It names the Host header values the
server accepts, which protects against DNS rebinding. The option can be repeated. Each value
must match the Host header exactly, including case and any port the client sends. A value
ending in `:*` matches that name with any port, but not the name without one; list both if
clients send either. Once you pass the option, the loopback names are accepted only if you list
them too. ASH does not support browser-based clients. Limit who can reach the port with your
firewall or network rules as well.

ASH enforces this. With a non-loopback `--host` and neither `--allowed-host` nor
`--trust-upstream-host-check`, `ash mcp` refuses to start, because the server would answer any
Host and any Origin header. With `--allowed-host`, the server refuses every request that
carries an Origin header. On a loopback `--host` without `--allowed-host`, it accepts only its
own address as Host: `127.0.0.1`, `localhost`, or `[::1]` with the port it listens on, and on
port 80 also without the port. It accepts the same names as `http://` origins.

`--trust-upstream-host-check` is for a proxy or platform in front of ASH that checks the Host
and Origin headers itself. With it, ASH accepts any Host and any Origin, so the protection
against DNS rebinding is only what that proxy or platform provides. It applies only to the
HTTP transports with a non-loopback `--host`, and it cannot be combined with `--allowed-host`.
On stdio, with a loopback `--host`, or with `--allowed-host`, `ash mcp` refuses to start:

<!-- doctest: run expect-exit=5 -->
```bash
ash mcp --transport streamable-http --trust-upstream-host-check
```

### Behind a load balancer or a managed runtime

By default the server keeps one session per client: it issues an `Mcp-Session-Id` when a
client connects and refuses session IDs it did not issue. `--stateless-http` handles every
request on its own instead. It is for load balancers that may send consecutive requests to
different replicas, and for runtimes that set their own `Mcp-Session-Id`. It is accepted
only with `--transport streamable-http`; with another transport, the default `stdio`
included, it is a usage error, and `ash mcp` exits with code 5 before it starts:

<!-- doctest: run expect-exit=5 -->
```bash
ash mcp --stateless-http
```

In stateless mode the server issues no session IDs. Use it only where the platform requires
it, and keep to one trusted client per server with `ASH_MCP_TRANSPORT` set.

A stateless server identifies no session by itself, so the tools that keep state for a
session refuse every call with `error_type` `session_identity_required`: `run_ash_scan`,
`get_scan_progress`, `list_active_scans`, `cancel_scan`, `set_source_git`,
`set_source_zip_chunk`, `set_source_zip_finalize`, `clear_source`, and `select_profile`.
`run_ash_workspace_scan` returns its results in its response and needs no session. The session
is never what a client claims: on a stateful server an `Mcp-Session-Id` the server did not
issue names no session, and on SSE the session is the one the server issued for the event
stream. On a stateful server a request that names a protocol version outside the ones the
`initialize` handshake negotiates names no session either, whatever `Mcp-Session-Id` it
sends, and the refusal says so: send the `Mcp-Protocol-Version` the handshake negotiated
together with the `Mcp-Session-Id` it returned.

When a platform in front of ASH issues and authenticates `Mcp-Session-Id`, start the server
with `--trust-upstream-session-id` as well. The header then names the caller's session, so two
callers are kept apart only as well as the platform keeps their headers apart. ASH checks only
that the value can name one directory: letters, digits, and `.`, `_`, `-`, `~`, `+`, and `=`,
and not `.` or `..`. It refuses any other value instead of rewriting it, with `error_type`
`invalid_session_id`. The option applies
only to `--transport streamable-http --stateless-http`; anywhere else, `ash mcp` refuses to
start:

<!-- doctest: run expect-exit=5 -->
```bash
ash mcp --transport streamable-http --trust-upstream-session-id
```

The templates in `deploy/` run the server for you on AWS: see
[Deploy ASH on AWS](deploy-on-aws.md).

### SSE

`--transport sse` serves the SSE transport at `/sse`, unless you pass `--mount-path` with a
path other than `/mcp`. It takes the same host, port, and auth options as streamable HTTP, and
not `--stateless-http`. Use it only for a client that cannot use streamable HTTP, with
`ASH_MCP_TRANSPORT=sse` set and one trusted client.

## Environment variables the server reads

| Variable | When unset | Effect |
|----------|------------|--------|
| `ASH_MCP_TRANSPORT` | Not set by `ash mcp`. | Set it to `streamable-http` or `sse`, in any case, to apply the remote-client rules above to every call. A value that names no transport stops `ash mcp` from starting, with exit code 5. |
| `ASH_MCP_ALLOWED_ROOTS` | Local clients: everything outside the system directories, the filesystem root, and other sessions' workspaces. Remote clients: only delivered source. | Directories, and their subdirectories, that clients may scan and read results from. |
| `ASH_MCP_ALLOWED_CONFIG_ROOTS` | A remote client may read config only from the scan roots and its session's `config/` directory. | Extra directories remote clients may read config files from, such as a shared policy file. A config file a client names there counts as yours, not the client's, unless a client delivered it. |
| `ASH_MCP_GIT_ALLOWED_HOSTS` | No host: `set_source_git` clones from nowhere. | The hosts `set_source_git` may clone from, separated by spaces or commas, matched without regard to case. See [Deliver source to the server](#deliver-source-to-the-server). |
| `ASH_MCP_WORKSPACE_ROOT` | `$XDG_CACHE_HOME/ash-mcp`, or `~/.cache/ash-mcp` | Where each session's workspace lives: delivered source, uploads, and session configs. |
| `ASH_CONFIG` | The built-in defaults. | The server's own config. Its `global_settings.mcp.runtime_overrides` section is the policy that delivered configs are checked against, and its `mcp-resource-management` section [limits the scans](#limit-how-many-scans-run-and-for-how-long). When it names a path that is not a file, a file the server cannot read, or a config that does not load or validate, `ash mcp` refuses to start, on every transport, with exit code 3. An empty value counts as unset. Keep it outside every git checkout and the directories clients scan: inside one, its sandbox grants and plugin modules do not count ([Configuration trust model](../concepts/trust-model.md#how-the-tier-is-decided)). |

A missing `ASH_CONFIG` file stops the server before it serves anything, with an error that
names the variable and the path:

<!-- doctest: run expect-exit=3 -->
```bash
ASH_CONFIG=/nonexistent ash mcp
```

The [environment variable reference](../reference/environment-variables.md) lists every
variable ASH reads.

## Limit how many scans run and for how long

The server enforces two limits from the `mcp-resource-management` section of its own config,
the file `ASH_CONFIG` names in the environment of the `ash mcp` process. A scanned
repository's config and a config a client delivers cannot change them. Without `ASH_CONFIG`,
the defaults apply. The server reads the section again for each scan.

<!-- doctest: config kind=ash-fragment at=mcp-resource-management -->
```yaml
max_concurrent_scans: 3
scan_timeout_seconds: 1800
```

- `max_concurrent_scans`, 3 by default and at most 100, is the most scans the server holds at
  once, across every session: running, waiting for another scan of their session, or canceled
  and still stopping. `run_ash_scan` beyond the limit is refused with `error_type`
  `scan_start_failure` and an `error` that names the limit; the client starts the scan again
  once one has finished or been canceled.
- `scan_timeout_seconds`, 1800 by default, is the longest one scan may run, from 60 to 86400
  seconds. The clock starts when the scan starts running, so the time it waits for another scan
  of its session does not count. A scan still running then is stopped the way `cancel_scan`
  stops one, and ends `failed` with an `error_message` that names the limit.

`0` or `null` turns either limit off. A workspace scan, `run_ash_workspace_scan`, takes one
slot for all of its projects and is refused like any other scan when no slot is free.
`scan_timeout_seconds` covers the whole workspace scan: past it, every project still running
is stopped and ends `failed`, and the call returns `success` false with `error_category`
`operation_timeout` and the `scan_ids`. A workspace scan stopped this way writes no combined
results file and no workspace reports, unless it was stopped while writing them.
`cancel_scan` with one project's scan id stops that project, which ends
`failed`, and the other projects carry on. The section's other keys are accepted so that
existing configs keep validating, and nothing reads them.

## Deliver source to the server

A client that does not share a filesystem with the server sends the source over MCP, then calls
`run_ash_scan` without `source_dir` to scan it. Each session's source lands in
`<workspace root>/<session ID>/source`.

`set_source_git` clones a repository with git, so the server's host needs git. The clone is
shallow: `depth` is the number of commits it fetches, a positive whole number, 1 by default.
Any other value, `0` included, is refused before anything is created, with `error_type`
`invalid_clone_depth`.

It refuses these before it creates or clones anything:

- A URL or ref that begins with `-`, and URLs that use the `ext::` transport, with
  `error_type` `clone_url_not_permitted` or `clone_ref_not_permitted`.
- A local path or `file://` URL, with `error_type` `local_clone_source_refused`, whatever the
  scan roots allow. To scan a directory on the server's host, the client names it as
  `run_ash_scan`'s `source_dir`.
- A URL with a scheme other than `https` or `ssh`, with `error_type` `clone_url_not_permitted`.
- A host that `ASH_MCP_GIT_ALLOWED_HOSTS` does not list, with `error_type`
  `clone_host_not_permitted`. The variable is empty unless you set it, so the server clones
  from no host until you name the ones clients may clone from, separated by spaces or commas.
- Any `ssh_key_id`, with `error_type` `ssh_key_not_registered`. The server registers no SSH
  keys, and it never accepts a private key over MCP.

git then runs without the server's credentials or git configuration:

- Its environment keeps only `PATH`, the locale, the temporary directories, and the TLS trust
  settings `GIT_SSL_CAINFO`, `GIT_SSL_CAPATH`, `SSL_CERT_FILE`, and `SSL_CERT_DIR`, with `HOME`
  set to the session's directory. Tokens, proxy settings, SSH agent sockets, and `GIT_*`
  variables in the server's environment do not reach it, so a clone that needs a proxy fails.
- System and global git configuration are off, no credential helper or askpass program runs,
  and git starts no hook and no fsmonitor command.
- Only the `https` and `ssh` protocols are allowed, for submodules too, and git follows no HTTP
  redirect, so an allowed host cannot send it to another one.
- ssh runs with no configuration file, identity file, or agent, never prompts, and checks the
  host key against the system-wide known hosts file only.

Each git command, the clone and, for a `ref`, the fetch and the checkout, may run for 10
minutes. One that runs longer is stopped with every process it started, nothing it cloned is
kept, and the call fails with `error_type` `clone_timed_out`. A git command that runs and fails
gives `git_clone_failed` or `git_checkout_failed`, with git's own message in `error`.

- It deletes the session's previous tree before it clones, so a failed clone leaves the
  session with nothing to scan until the client delivers again.
- What git can reach over the network is what the server's host can reach. Restrict the host's
  outbound network to the hosts in `ASH_MCP_GIT_ALLOWED_HOSTS`.

`set_source_zip_chunk` and `set_source_zip_finalize` take a zipped tree in base64 chunks.

- Chunks arrive in order, each at most 1 MiB once decoded.
- The finished zip must match the SHA-256 the client gives, and may be at most 100 MiB, with
  at most 500 MiB and 50,000 entries once extracted.
- A zip with an entry that has an absolute path, a `..` component, or a symbolic link is
  refused as a whole, before anything is extracted.
- A new zip is extracted beside the old tree and replaces it only when extraction succeeds.

While a scan of a session runs, `clear_source`, `set_source_git`, and
`set_source_zip_finalize` are refused with `error_type` `source_delivery_busy`, because each
would remove or replace the tree the scan is reading. Call them again once the scan has
finished. A `run_ash_workspace_scan` over a workspace in the session's delivered tree holds the
tree the same way for the whole workspace scan. The other way round, `run_ash_scan` and
`run_ash_workspace_scan` are refused with the same `error_type` while one of those calls is
changing the session's tree. Chunks are still accepted, because they land beside the tree.
`set_source_zip_chunk` and `select_profile` are refused with `error_type`
`session_workspace_busy` while an HTTP server removes the workspace of a session for being
unused longer than `--session-workspace-ttl`. The upload and the bound profile are removed with
the workspace, so the client selects the profile again and sends the upload again from chunk 0.
A session whose SSE event stream is open is kept until it ends; see [Clean up](#clean-up).
ASH sets no quota on uploads per session or in total. The server's config limits how many scans run and
for how long; see [Limit how many scans run and for how long](#limit-how-many-scans-run-and-for-how-long).

## What a delivered config cannot set

A config file inside delivered source is an MCP-client file. So is a config file a client
names as `config_path` to `run_ash_scan`, `get_config`, or `validate_config`, wherever it is,
unless it is in a directory `ASH_MCP_ALLOWED_CONFIG_ROOTS` names or in its session's `config/`
directory, which only the server writes: a config in another checkout the server may scan is
that checkout's, not yours. ASH judges a config path a client names by where it sits as well as
by the file it reaches, so a symbolic link a client names is the client's wherever it points. A config file that ASH finds by
itself in a directory the server scans in place is a repository config, trusted the way the
CLI trusts it; see [Configuration trust model](../concepts/trust-model.md).

ASH checks every MCP-client file in a config chain against the server's policy, the
`global_settings.mcp.runtime_overrides` section of the server's own config, whether or not
`runtime_overrides.enabled` is set. Only what the file writes counts: a value equal to the
server's at the same key is accepted. Every operation in the file's `patch` is checked as
written, and one that targets a denied field is
refused even when it writes the server's value. A `test` operation in an MCP-client file is
refused outright, before any operation applies and whatever the configuration holds at its
path: a `test` against a base the operator owns would reveal, through whether the file loads,
a value the client may not read, so the message names the file and says the op is one a
config file chosen by this caller may not use. The policy's `denied_value_patterns` apply to
delivered files too.

With the default policy, a delivered config is refused as a whole, with `error_type`
`config_field_denied` and a message naming each field, if it sets any of these to a value other
than the server's own:

- the gate: `fail_on_findings`, `fail_on_incomplete_scanners`, `content_db_staleness`,
  `content_db_staleness_overrides`, and `content_db_staleness_offline_image_default`
- scanner options that drop findings by rule ID, by a baseline, or by a whole category, such as
  `exclude_rule`, `config`, and `severity` of `opengrep` and `semgrep`, checkov's `frameworks`,
  cfn-lint's `ignore_checks`, detect-secrets' `baseline_file` and `scan_settings`, and trivy's
  `scanners` and `ignore_unfixed`
- options that limit how much a scanner reads or reports, or that turn on its own network
  calls, such as ferret-scan's `finding_limit` and `recursive`, gitleaks'
  `max_target_megabytes`, and zizmor's `online_audits`
- any scanner's `offline` option
- options that name a scanner's own config file or another file or program its tool reads:
  every scanner's `config_file`, and others such as trivy's `ignore_file`, gitleaks'
  `baseline_path`, and actionlint's `shellcheck` and `pyflakes`
- which version of a tool runs: any scanner's or the `jupyter` converter's `tool_version`, and
  opengrep's `version` and `sha256`
- any setting of the reporters that send findings off the host, `aws-security-hub`,
  `bedrock-summary-reporter`, `cloudwatch-logs`, and `s3`, their `enabled` included
- the `gitlab-sast` reporter's `exclude_suppressed`, which leaves suppressed findings out of
  its report

`ash config init` writes the full default list into the config it creates, and the
[configuration reference](../reference/configuration.md#global_settings.mcp.runtime_overrides.denied_paths)
shows it. `validate_config` reports each such field as an error of type
`denied_by_runtime_policy`; for `config_content`, only when a remote client calls it. A
delivered workspace whose project config sets one fails to resolve. To scan, the client removes
those fields and delivers the config again.

A delivered config cannot turn a reporter that sends findings off the host on or off. Its
`enabled: false` for one of the four is not refused, but it has no effect: each runs as the
server's config says, or by the reporter's own default where that config sets nothing. The
same holds for a reporter a plugin module adds that declares destination options, and a
delivered value for one of those options is replaced by the server's instead of refused,
because the module is loaded only when the scan runs. A delivered config can still turn the
reporters that write only local files, such as `html`, `sarif`, and `yaml`, on or off and set
their options, apart from `gitlab-sast`'s `exclude_suppressed`.

If the policy itself cannot be loaded, because the file `ASH_CONFIG` names exists but does not
load, or has two sections that ASH reads as the same plugin, a config with an MCP-client file is
refused with `config_policy_unreadable`. A file that does not load stops the server when it
starts, so a call meets that case only when the file changed after the server started. A scan that reads no such file is unaffected.

Under the default `denied_paths`, a delivered config's sandbox settings and plugin modules may
restrict the server's own but not widen them. A file whose own `sandbox` section or
`ash_plugin_modules` list asks for more in one of these ways is refused with
`config_field_denied`, naming the setting; an equal or tighter value scans:

- `sandbox.network_scanners` may list only scanners the server's settings give a network. A
  shorter list takes the network away from the scanners it leaves out.
- `sandbox.extra_read_paths` may list only paths the server's settings grant.
- `sandbox.mode` can turn the sandbox on when the server's mode is `off`, and otherwise must
  equal the server's mode. The images that `deploy/` builds have neither bubblewrap nor
  firejail, so there a `bwrap` or `firejail` mode leaves the scanners it would wrap MISSING;
  see [Deploy ASH on AWS](deploy-on-aws.md#before).
- `ash_plugin_modules` may add only ASH's own plugin modules and modules installed outside
  every git checkout and the scanned directory, and never the AWS or Snyk plugin modules,
  or a module inside either.

Any other sandbox grant or plugin module a delivered file asks for, such as a
`read_path_scanners`, `env_scanners` or `environment` entry, is dropped with a warning, as for a repository's
config.

The server's settings are the ones in the file `ASH_CONFIG` names, and that file grants nothing
when it is inside a git checkout, or inside the directory a scan covers, so keep it outside
every checkout. A delivered config's
`global_settings.mcp` section has no effect.

An MCP-client file reads no environment variables, since the environment it would read is the
server's. A file in which a plain value starts with a `${VAR}` or `${VAR:default}` reference,
or that uses an `!ENV` tag, is refused: `run_ash_scan` and `get_config`, with or without
`raw`, return `error_type`
`config_env_not_resolved`, and `run_ash_scan` does not start the scan; `validate_config` reports
an error of that type. The rule follows where the file is, so a CLI scan of a delivered tree
refuses such a config too, with exit code 3. The refusal covers the file a client names as
`config_path` and every file a client delivered. A file in a directory
`ASH_MCP_ALLOWED_CONFIG_ROOTS` names keeps its references.

`get_config` never returns a value that a config read from the environment, since the server's
environment is not the client's. The resolved config shows such a value as `<from ${VAR}>`, and
with `raw` the reference appears as the file wrote it. For how a scan's results record such a
value, see [Read values from the environment](configure.md#environment).

Suppressions and ignore paths in a delivered config are applied, and marked as coming from the
client:

- Each entry from a delivered config file that the operator did not also supply has
  `client_supplied: true` in the results' copy of the config.
- In SARIF, the suppression justification starts with `(ASH, client-supplied config)` and the
  suppression carries `properties.clientSupplied: true`.
- Files under a delivered ignore path are still scanned. Their findings are kept and marked
  suppressed instead of being dropped.
- Path exclusions in scanner options, such as bandit's `excluded_paths`, are taken out of the
  options and handled the same way, and a delivered `scanners.trivy-repo.options.ignore_file`
  becomes marked suppressions instead of being passed to trivy. [Configuration trust
  model](../concepts/trust-model.md#client-supplied) says how each is matched.

[Suppressions, ignore paths, and scanner exclusions](../concepts/suppressions.md) explains how
suppressed findings affect the exit code and each report.

### Refuse delivered suppressions too

To refuse delivered suppressions and ignore paths, give the server's config a `denied_paths`
list of its own: the full default list, as `ash config init` writes it, followed by these two
entries, which say so explicitly:

<!-- doctest: config kind=other reason="two entries to append to the default denied_paths list, not a config on their own" -->
```yaml
- /global_settings/suppressions/**
- /global_settings/ignore_paths/**
```

A list of your own replaces the default list and is applied exactly as written, so keep every
default entry, start each one with `/`, and compare your list with the default again after you
upgrade ASH. A list equal to a default that ASH has shipped, such as the one an earlier
`ash config init` wrote, still counts as the default, and gets every entry of the current
default list. Any other list is your own, even the default list with one entry added or
removed, and every entry in it applies as written. While it keeps the default's
`/global_settings/suppressions` and `/global_settings/ignore_paths` entries, delivered
suppressions and ignore paths are refused. While it keeps the `/sandbox` and
`/ash_plugin_modules` entries, a delivered config that sets either to any value other than the
server's is refused, even a tighter one. If your list leaves the `/sandbox` and `/ash_plugin_modules` entries out, ASH does not
refuse a delivered file that asks for more: it drops the grants and modules instead, as it does
for a repository's config.

An entry matches a key spelled with `-` or `_`. Under `/scanners`, `/reporters`, and
`/converters`, an entry for a plugin's section also matches every spelling ASH reads as that
plugin. A glob in the plugin segment matches every key it matches as written, and also the other
spellings of the plugins that ship with ASH and of the plugins your server config configures,
so `/scanners/trivy-*/options/ignore_file` also covers `/scanners/TrivyRepo/options/ignore_file`;
to cover another plugin under every spelling, write its name.

## Config profiles

A profile is a named ASH config that clients can choose. Register profiles when you start the
server, with `--profile NAME=path/to/ash.yaml` once per profile, on any transport:

<!-- doctest: illustrative reason="starts a server that waits for a client on standard input" -->
```bash
ash mcp --profile strict=/etc/ash/strict.yaml --profile default=/etc/ash/default.yaml
```

The server loads and validates every profile when it starts. A spec without `=`, a missing
file, or a file that does not load, including one with an unknown top-level key, stops it
with exit code 3. The server reads each file once, so an edit takes effect when it restarts.
A client cannot add a profile.

- `list_profiles` returns each profile's `name` and `path_sha256`, a SHA-256 of the file's
  absolute path, sorted by name. It never returns the path or the file's contents.
- `select_profile` binds a profile to the calling session. A later `run_ash_scan` in that
  session that names no `config_path` scans under the profile, instead of the config ASH would
  find in the scanned directory. The workspace tools use it for each project that has no
  config of its own, and their `profile` argument names a profile for one call instead.
- `select_profile` with `patch_ops` or `override_yaml` changes the profile for that session,
  and the workspace tools' `config_overrides` argument changes the config for one call. Each
  change must be allowed by the `global_settings.mcp.runtime_overrides` section of the
  profile, or of the defaults when the session has no profile. Runtime overrides are off by
  default, so without a profile that turns them on, every change a client asks for is
  refused. A change that is refused, or that does not apply, is reported without its value:
  by its op and path, or, when an `override_yaml` does not parse or validate or a
  `config_overrides` entry leaves the config invalid, by the problem and where it is (the
  parser's position, the field, or the key).
- Such a change cannot turn a reporter that sends findings off the host on or off either.
  Turning one on, removing its section, or setting any of its options is refused. Its
  `enabled: false` for one of the four is not refused, but it has no effect: each runs as the
  profile says, and sends where the profile says.
- The copy of a profile the server writes into a session's workspace holds each value the
  profile read from the environment as the profile's file wrote it, not the value. A scan under
  the profile still uses the value from the server's environment, also when the client changed
  the profile.
- No op sees a value or key the profile read from the environment. A `test` at one fails
  whatever value it gives, a path through such a key names nothing, and an `add` of a key
  beside one is refused. A value an op or `override_yaml` writes is the client's text: the
  session's copy holds it, and `get_config` shows it, as the client wrote it, even where it
  equals what the profile read. A value the profile read keeps its reference wherever the ops
  move its list entry. A profile in which such a value is part of a longer string, such as a
  relative path that ASH takes from the profile's directory (`${VAR}/bandit.yaml`), can't be
  written to a session with its reference, so `select_profile`, and a workspace scan's
  `profile`, refuse it without naming the value. Set the variable to an absolute path, or to
  the whole string.

## Clean up

- `clear_source` deletes the calling session's workspace, `<workspace root>/<session ID>`.
- An HTTP server removes a session's workspace, with its delivered source, uploads, and bound
  profile, when it sees the session end: a stateful session's `DELETE`, a session the MCP SDK
  discarded, an SSE event stream that closes, and every session it issued when it shuts down.
- It also removes a workspace nobody used for `--session-workspace-ttl` seconds, 86400 (24
  hours) by default, which covers sessions whose end it cannot see, such as every stateless
  one. Each request that names a session counts as a use. A workspace whose scan is running,
  or whose tree is being changed, is kept, and so is anything under the workspace root that
  ASH did not create as a session workspace. A `set_source_zip_chunk` or `select_profile` call
  holds its session from the moment the tool starts, so a sweep that runs while the call
  writes keeps the session.
- A stateful session nobody has used for that long is removed like any other, whether or not
  the server has seen it end: the MCP SDK drops an idle stateful session without telling the
  server, so the server cannot keep it on that account. Only a session whose SSE event stream
  is still open is kept whatever its age, and the sweep marks that workspace used so another
  server sharing the root keeps it too. On a stateful server that stream is the session's
  standalone `GET` stream. A stateful session the sweep removes is ended: its next request
  names no session the server holds, so the tools that need a session refuse it with
  `error_type` `session_identity_required` and say that the session expired, and the client
  opens a new session with `initialize`.
- Servers that share one workspace root take a lock under the root before a sweep removes a
  session. A sweep that cannot take that lock within about a second, because another server
  holds it, removes nothing more and leaves the remaining sessions to its next sweep, so
  another server cannot hold up a stop signal.
- `--session-workspace-ttl` takes a positive number of seconds and applies only to the HTTP
  transports. On stdio, `ash mcp` refuses to start with it:

    <!-- doctest: run expect-exit=5 -->
    ```bash
    ash mcp --session-workspace-ttl 3600
    ```

- The stdio session's workspace is removed when the last stdio server that uses that workspace
  root exits.
- Scan output stays in each scanned directory's `.ash/ash_output`. If the server is killed
  during a scan, the previous results stay in `.ash/ash_output/.ash_previous_results`, and the
  next MCP scan of that directory takes them back.
- The server keeps its list of scans in memory. After a restart, `get_scan_progress` no longer
  knows earlier scan IDs, and their results are still readable from the output directory with
  `get_scan_results`.

## Checklist for an HTTP server

- Prefer stdio for an agent on the same machine.
- Serve one trusted client per server, and run one server per user.
- Keep the default stateful streamable HTTP; use `--stateless-http` or SSE only where the
  platform requires it.
- Always set `--auth-header-name` and `--auth-header-value`, and run the server where other
  users cannot read its command line.
- Bind to loopback, or put a proxy you control in front. Pass `--allowed-host` behind any proxy
  that forwards the Host header, and with any non-loopback `--host`.
- Set `ASH_MCP_TRANSPORT` to `streamable-http` or `sse`.
- Set `ASH_MCP_ALLOWED_ROOTS`, and `ASH_MCP_ALLOWED_CONFIG_ROOTS` if clients need shared
  config, to the directories the client needs and nothing more.
- Set `ASH_MCP_GIT_ALLOWED_HOSTS` only if clients clone with `set_source_git`, and only to the
  hosts they clone from.
- Set `max_concurrent_scans` and `scan_timeout_seconds` in the server's config to what the host
  can run.
- Run the server as a dedicated user without credentials the client should not use, and limit
  its network access.
- Lower `--session-workspace-ttl` if delivered source should not stay on the host for up to 24
  hours after its client stops using it.

[Scanning untrusted code](../concepts/scanning-untrusted-code.md) describes what protects the
host when the source a client sends is hostile. To scan a VS Code workspace over MCP, see
[Scale to large repositories](scale-large-repos.md).
