# Run the ASH MCP server

`ash mcp` starts ASH's Model Context Protocol server. An agent or IDE on your machine usually
starts it for you over stdio, as in [Connect an AI agent to ASH](../getting-started/agents.md).
This page is for running the server yourself: choosing a transport, limiting what clients can
reach, serving it over HTTP, and cleaning up after clients. Every option is listed in the
[CLI reference](../reference/cli.md#mcp) and every tool in the
[MCP tools reference](../reference/mcp-tools.md).

## How the server runs scans

- Scans run inside the server process, in local mode, with the scanner tools installed for
  the user that runs the server. Install them as that user with `ash dependencies install`.
  Nothing runs in a container.
- A scan writes its output to `.ash/ash_output` inside the directory it scans, so the server
  needs write access there. `run_ash_scan` deletes the previous `ash_aggregated_results.json`
  in that directory before the scan starts, unless the client passes `clean_output` false.
- A scan uses the config ASH discovers in the scanned directory, or the file a client names
  with `config_path`.
- MCP scans never run a tool found inside a scanned or delivered tree, whatever
  `ASH_ALLOW_IN_TREE_TOOLS` says, and `ash mcp` has no option to allow it. A scanner installed
  only inside the project, for example in its `.venv`, is reported as MISSING. See
  [Tools inside the scanned directory](../docs/advanced-usage.md#tools-inside-the-scanned-directory).

`ash mcp` exits with code 3 for invalid options, 2 for a scanner error that stops the server,
1 when the MCP package is missing or the server fails unexpectedly, and 0 when you stop it with
Ctrl-C.

## Choose a transport

| Transport | Use it for | Clients connect to |
|-----------|------------|--------------------|
| `stdio`, the default | An agent or IDE on the same machine, which starts the server as a child process. | The server's standard input and output. |
| `streamable-http` | A client that cannot start a local process, or a server on another host. | `http://HOST:PORT/mcp` |
| `sse` | A client that supports only the older SSE transport, which the MCP SDK deprecates. | `http://HOST:PORT/sse` |

Use stdio whenever the client can start the server. The server is designed to serve one
trusted client. It is not designed to be shared between users who must not see each other's
scans: run one server per user.

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
log line to standard error. `--quiet` hides the startup messages. `--log-level`, `--verbose`
and `--debug` set the HTTP server's log level and have no effect on stdio, and `--color` has no
effect on any transport.

### Limit what a local agent can scan

On stdio, with `ASH_MCP_ALLOWED_ROOTS` unset, an agent can scan, and read results from, any
directory the server's user can read, except a short list of system directories: `/boot`,
`/dev`, `/etc`, `/proc`, `/root` and `/sys`, or on Windows the Windows, Program Files and
ProgramData directories. A project inside one of them, such as `/root` when you work as root
in a container, is refused until you name it in the variable. To limit scan targets and
result paths to the directories you name, set the variable in the server's environment:

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

Separate several directories with `:`, or with `;` on Windows. On stdio this does not limit which
config files a client can name with `config_path`: those are refused only in the system
directories above.

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
    standard error. `--host`, `--port` and `--mount-path` change the address, which defaults
    to `127.0.0.1`, port `8000`, path `/mcp`.

3. Point the client at the URL and give it the header. In Claude Code, for example:

    <!-- doctest: illustrative reason="needs Claude Code" -->
    ```bash
    claude mcp add --transport http ash http://127.0.0.1:8000/mcp --header "X-ASH-Token: $TOKEN"
    ```

`--auth-header-name` and `--auth-header-value` must be given together; one without the other
exits with code 3. The header name is matched without regard to case, and every request, on
every path and method, must carry the exact value. A request without it gets
`401 Unauthorized`. The value is passed on the command line, so anyone who can list the
host's processes can read it: run the server where that is acceptable. ASH writes no access
log; log requests at your proxy if you need a record.

Always set `ASH_MCP_TRANSPORT` to the transport you serve. With it set, ASH applies its rules
for remote clients to every call:

- A client can scan, and read results from, only the directories in `ASH_MCP_ALLOWED_ROOTS`
  and the source it delivered itself. With the variable unset, it can scan only source it
  delivered.
- A client can name config files (`config_path`, every base an `extends` chain names,
  workspace files and workspace policy files) only in `ASH_MCP_ALLOWED_CONFIG_ROOTS`, the scan
  roots, and its own session's config directory.

`ash mcp` does not set `ASH_MCP_TRANSPORT` for you.

### Serve clients on another host

ASH serves plain HTTP. Put a proxy you control in front of it for TLS, and keep the server on
the loopback interface when the proxy runs on the same host. If the server must listen on
another address, name every Host header value it should accept:

<!-- doctest: illustrative reason="starts a server that runs until it is stopped" -->
```bash
ash mcp --transport streamable-http --host 0.0.0.0 --allowed-host ash.example.com \
  --auth-header-name X-ASH-Token --auth-header-value "$TOKEN"
```

The server checks the Host header, which protects against DNS rebinding, only when it is bound
to a loopback address or when you pass `--allowed-host`. Always pass `--allowed-host` with a
non-loopback `--host`. The option can be repeated. Each value must match the Host header
exactly, including a port if the client sends one, or end in `:*` to match any port. Once you
pass it, the loopback names are accepted only if you list them too. Requests that carry an
`Origin` header are refused, so browser-based clients cannot connect. Limit who can reach the
port with your firewall or network rules as well.

### Behind a load balancer or a managed runtime

By default the server keeps one session per client: it issues an `Mcp-Session-Id` when a
client connects and refuses session ids it did not issue. `--stateless-http` handles every
request on its own instead. It is for load balancers that may send consecutive requests to
different replicas, and for runtimes that set their own `Mcp-Session-Id`. It is accepted
only with `--transport streamable-http`; with another transport, `ash mcp` exits with code 3.
In stateless mode the server issues no session ids. Use it only where the platform requires
it, and keep to one trusted client per server with `ASH_MCP_TRANSPORT` set.

The templates in `deploy/` run the server for you on AWS: see
[Deploy ASH on AWS](deploy-on-aws.md).

### SSE

`--transport sse` serves the SSE transport at `/sse` unless you pass `--mount-path`. It takes
the same host, port and auth options as streamable HTTP, and not `--stateless-http`. Use it
only for a client that cannot use streamable HTTP, with `ASH_MCP_TRANSPORT=sse` set and one
trusted client.

## Environment variables the server reads

| Variable | When unset | Effect |
|----------|------------|--------|
| `ASH_MCP_TRANSPORT` | Not set by `ash mcp`. | Set it to `streamable-http` or `sse` to apply the remote-client rules above to every call. |
| `ASH_MCP_ALLOWED_ROOTS` | Local clients: everything outside the system directories. Remote clients: only their own delivered source. | Directories clients may scan and read results from. |
| `ASH_MCP_ALLOWED_CONFIG_ROOTS` | Remote clients may read config only from the scan roots and their own session. | Extra directories remote clients may read config files from, such as a shared policy file. |
| `ASH_MCP_WORKSPACE_ROOT` | `$XDG_CACHE_HOME/ash-mcp`, or `~/.cache/ash-mcp` | Where each session's workspace lives: delivered source, uploads and session configs. |
| `ASH_CONFIG` | The built-in defaults. | The server's own config. Its `global_settings.mcp.runtime_overrides` section is the policy that client-delivered configs are checked against. |

The [environment variable reference](../reference/environment-variables.md) lists every
variable ASH reads.

## Deliver source to the server

A client that does not share a filesystem with the server sends the source over MCP, then calls
`run_ash_scan` without `source_dir` to scan it. Each session's source lands in
`<workspace root>/<session id>/source`.

`set_source_git` clones a repository with `git clone --depth`, so the server's host needs git.

- It refuses a URL or ref that begins with `-`, and URLs that use the `ext::` transport.
- A local path or `file://` URL must be inside a directory the client may scan.
- The clone runs as the server's user, with that user's git configuration and credentials,
  and can reach any host that user can reach. The `ssh_key_id` parameter is accepted and has
  no effect. Run the server as a user that holds no credentials you would not give the client,
  and restrict its outbound network if clients should not reach arbitrary hosts.

`set_source_zip_chunk` and `set_source_zip_finalize` take a zipped tree in base64 chunks.

- Chunks arrive in order, each at most 1 MiB once decoded.
- The finished zip must match the SHA-256 the client gives, and may be at most 100 MiB, with
  at most 500 MiB and 50,000 entries once extracted.
- Entries with absolute paths, `..` components or symbolic links are refused before anything
  is extracted.
- A new delivery is extracted beside the old tree and replaces it only when extraction
  succeeds.

While a scan of a session is running, deliveries to that session are refused with
`error_type` `SourceDeliveryBusyError`. ASH sets no quota on uploads per session or in total,
no overall limit on concurrent scans, and no time limit on a scan.

## What a client-delivered config cannot set

A config file inside delivered source is a client-supplied config. A config in a directory the
server scans in place is a repository config, trusted the way the CLI trusts it; see
[Trust model](../concepts/trust-model.md).

ASH checks every client-supplied file in a config chain against the server's policy, the
`global_settings.mcp.runtime_overrides` section of the server's own config. With the default
policy, a delivered config is refused as a whole, with `error_type` `config_field_denied` and a
message naming each field, if it sets any of these:

- `fail_on_findings` or `fail_on_incomplete_scanners`
- `content_db_staleness` or `content_db_staleness_overrides`
- `exclude_rule` of the `opengrep` or `semgrep` scanner, or `baseline_file` of `detect-secrets`
- the `aws_*` options of `bedrock-summary-reporter`, or anything under `cloudwatch-logs`

The client then removes those fields and delivers again. If the policy itself cannot be
loaded, delivered configs are refused with `config_policy_unreadable`. Every limit on a
repository config applies as well: sandbox settings can only tighten the operator's, and
plugin modules inside the tree, the AWS and Snyk plugin modules, and reporter destinations
and credentials are ignored. A delivered config's `global_settings.mcp` section has no
effect.

Suppressions and ignore paths in a delivered config are applied, and marked as coming from the
client:

- Each entry has `client_supplied: true` in the results' copy of the config.
- In SARIF, the suppression justification starts with `(ASH, client-supplied config)` and the
  suppression carries `properties.clientSupplied: true`.
- Files under a client-supplied ignore path are still scanned. Their findings are kept and
  marked suppressed instead of being dropped.

To refuse delivered suppressions or ignore paths instead, list `/global_settings/suppressions`
or `/global_settings/ignore_paths` in your own policy's `denied_paths`.
[Suppressions](../concepts/suppressions.md) explains how suppressed findings affect the exit
code and each report.

The server cannot register config profiles: `ash mcp` has no option for it, so `list_profiles`
returns an empty list and `select_profile` always fails. Runtime overrides from clients, such
as the `config_overrides` argument of the workspace tools, need `runtime_overrides.enabled` in
the server's policy, which is false by default.

## Clean up

- `clear_source` deletes the calling session's workspace, `<workspace root>/<session id>`.
- The server does not delete a workspace when a client disconnects or its session expires.
  Workspaces stay until the client calls `clear_source` or you delete them. Remove old
  directories under the workspace root while the server is stopped.
- Scan output stays in each scanned directory's `.ash/ash_output`.
- The server keeps its list of scans in memory. After a restart, `get_scan_progress` no longer
  knows earlier scan ids, and their results are still readable from the output directory with
  `get_scan_results`.

## Checklist for an HTTP server

- Prefer stdio for an agent on the same machine.
- Serve one trusted client per server, and run one server per user.
- Always set `--auth-header-name` and `--auth-header-value`.
- Bind to loopback, or put a proxy you control in front and pass `--allowed-host`.
- Set `ASH_MCP_TRANSPORT` to the transport you serve.
- Set `ASH_MCP_ALLOWED_ROOTS`, and `ASH_MCP_ALLOWED_CONFIG_ROOTS` if clients need shared
  config, to the directories the client needs and nothing more.
- Run the server as a dedicated user without credentials the client should not use, and limit
  its network access.

[Scanning untrusted code](../concepts/scanning-untrusted-code.md) describes what protects the
host when the source a client sends is hostile. To scan a VS Code workspace over MCP, see
[Scale to large repositories](scale-large-repos.md).
