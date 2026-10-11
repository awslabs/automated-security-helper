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
  needs write access there. `run_ash_scan` deletes the previous `ash_aggregated_results.json`
  in that directory before the scan starts, even if the scan then fails to start, unless the
  client passes `clean_output` false.
- A scan uses the config ASH discovers in the scanned directory, or the file a client names
  with `config_path`. When there is neither, it uses the file `ASH_CONFIG` names in the
  server's environment, or the built-in defaults.
- MCP scans never run a tool found inside a scanned or delivered tree, whatever
  `ASH_ALLOW_IN_TREE_TOOLS` says, and `ash mcp` has no option to allow it. A scanner installed
  only inside the project, for example in its `.venv`, is reported as MISSING. See
  [Tools inside the scanned directory](../docs/advanced-usage.md#tools-inside-the-scanned-directory).

`ash mcp` exits with code 3 for options that cannot be combined, or when an HTTP transport
cannot listen on its address. It exits with code 2 for an unknown option or a value of the
wrong type, 1 when the MCP package is missing or the server fails unexpectedly, and 0 when you
stop it with Ctrl-C. On stdio, an error that stops the server is logged to standard error and
the command exits with code 0.

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
log line to standard error. `--quiet` hides the startup messages. `--log-level`, `--verbose`,
and `--debug` set the HTTP server's log level and have no effect on stdio, and `--color` has no
effect on any transport.

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
in a directory `ASH_MCP_ALLOWED_CONFIG_ROOTS` names (see
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
exits with code 3. The header name is matched without regard to case, and every request, on
every path and method, must carry the exact value. A request without it gets
`401 Unauthorized`. The auth header is the server's only access control. The value is passed
on the command line, so anyone who can list the host's processes can read it: run the server
where other users cannot read its command line. ASH writes no access log; log requests at
your proxy if you need a record.

Always set `ASH_MCP_TRANSPORT` to the transport you serve, exactly `streamable-http` or `sse`
in lower case; ASH ignores any other value, and `ash mcp` does not set it for you. With it set,
ASH applies its rules for remote clients to every call:

- A client can scan, and read results from, only the directories in `ASH_MCP_ALLOWED_ROOTS`
  and source delivered over MCP. With the variable unset, it can scan only delivered source.
- A client can name config files (`config_path`, every base an `extends` chain names,
  workspace files, and workspace policy files) only in `ASH_MCP_ALLOWED_CONFIG_ROOTS`, the
  scan roots, and its session's config directory.

These rules limit what the server's client can reach. They do not keep clients apart, so
serve one trusted client per server.

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

### Behind a load balancer or a managed runtime

By default the server keeps one session per client: it issues an `Mcp-Session-Id` when a
client connects and refuses session IDs it did not issue. `--stateless-http` handles every
request on its own instead. It is for load balancers that may send consecutive requests to
different replicas, and for runtimes that set their own `Mcp-Session-Id`. It is accepted
only with `--transport streamable-http`; with another transport, `ash mcp` exits with code 3.
In stateless mode the server issues no session IDs. Use it only where the platform requires
it, and keep to one trusted client per server with `ASH_MCP_TRANSPORT` set.

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
| `ASH_MCP_TRANSPORT` | Not set by `ash mcp`. | Set it to exactly `streamable-http` or `sse` to apply the remote-client rules above to every call. |
| `ASH_MCP_ALLOWED_ROOTS` | Local clients: everything outside the system directories, the filesystem root, and other sessions' workspaces. Remote clients: only delivered source. | Directories, and their subdirectories, that clients may scan and read results from. |
| `ASH_MCP_ALLOWED_CONFIG_ROOTS` | Remote clients may read config only from the scan roots and their session's config directory. | Extra directories remote clients may read config files from, such as a shared policy file. A config file a client names there counts as yours, not the client's. |
| `ASH_MCP_WORKSPACE_ROOT` | `$XDG_CACHE_HOME/ash-mcp`, or `~/.cache/ash-mcp` | Where each session's workspace lives: delivered source, uploads, and session configs. |
| `ASH_CONFIG` | The built-in defaults. | The server's own config. Its `global_settings.mcp.runtime_overrides` section is the policy that delivered configs are checked against. Check that the file exists: when it does not, ASH uses the built-in defaults without a warning. Keep it outside every git checkout: inside one, its sandbox grants and other restricted settings do not count. |

The [environment variable reference](../reference/environment-variables.md) lists every
variable ASH reads.

## Deliver source to the server

A client that does not share a filesystem with the server sends the source over MCP, then calls
`run_ash_scan` without `source_dir` to scan it. Each session's source lands in
`<workspace root>/<session ID>/source`.

`set_source_git` clones a repository with `git clone --depth`, so the server's host needs git.

- It refuses a URL or ref that begins with `-`, and URLs that use the `ext::` transport.
- A local path or `file://` URL must be inside a directory the client may scan.
- It deletes the session's previous tree before it clones, so a failed clone leaves the
  session with nothing to scan until the client delivers again.
- The clone runs as the server's user and can reach whatever that user can reach. Run the
  server as a dedicated user with no git or SSH credentials and no git configuration you have
  not reviewed, and restrict its outbound network to the hosts clients clone from.

`set_source_zip_chunk` and `set_source_zip_finalize` take a zipped tree in base64 chunks.

- Chunks arrive in order, each at most 1 MiB once decoded.
- The finished zip must match the SHA-256 the client gives, and may be at most 100 MiB, with
  at most 500 MiB and 50,000 entries once extracted.
- A zip with an entry that has an absolute path, a `..` component, or a symbolic link is
  refused as a whole, before anything is extracted.
- A new zip is extracted beside the old tree and replaces it only when extraction succeeds.

While a scan of a session runs, `set_source_zip_finalize` is refused with `error_type`
`SourceDeliveryBusyError`, and `set_source_git` with an error saying that a scan is running.
Chunks are still accepted. Call `clear_source` only after the session's scans finish. ASH sets
no quota on uploads per session or in total, no overall limit on concurrent scans, and no time
limit on a scan.

## What a delivered config cannot set

A config file inside delivered source is an MCP-client file. So is a config file a client
names as `config_path` to `run_ash_scan`, `get_config`, or `validate_config`, wherever it is,
unless it is in a directory `ASH_MCP_ALLOWED_CONFIG_ROOTS` names or in the session's own
`config/` directory: a config in another checkout the server may scan is that checkout's, not
yours. ASH judges a path by where it sits as well as by the file it reaches, so a symbolic
link a client delivered is the client's wherever it points. A config file that ASH finds by
itself in a directory the server scans in place is a repository config, trusted the way the
CLI trusts it; see [Configuration trust model](../concepts/trust-model.md).

ASH checks every MCP-client file in a config chain against the server's policy, the
`global_settings.mcp.runtime_overrides` section of the server's own config, whether or not
`runtime_overrides.enabled` is set. Only what the file writes counts: a value equal to the
server's at the same key is accepted. Every operation in the file's `patch` is checked as
written, and one that targets a denied field is
refused even when it writes the server's value. The policy's `denied_value_patterns` apply to
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
- any scanner's `offline` option
- options that name a scanner's own config file or another file or program its tool reads:
  every scanner's `config_file`, and others such as trivy's `ignore_file`, gitleaks'
  `baseline_path`, and actionlint's `shellcheck` and `pyflakes`
- which version of a tool runs: any scanner's or the `jupyter` converter's `tool_version`, and
  opengrep's `version` and `sha256`
- the AWS reporters' destinations and credentials, and anything under `cloudwatch-logs`

`ash config init` writes the full default list into the config it creates, and the
[configuration reference](../reference/configuration.md#global_settings.mcp.runtime_overrides.denied_paths)
shows it. `validate_config` reports each such field as an error of type
`denied_by_runtime_policy`; for `config_content`, only when a remote client calls it. A
delivered workspace whose project config sets one fails to resolve. To scan, the client removes
those fields and delivers the config again.

If the policy itself cannot be loaded, because the file `ASH_CONFIG` names exists but does not
load, or has two sections that ASH reads as the same plugin, a config with an MCP-client file is
refused with `config_policy_unreadable`. A scan that reads no such file is unaffected.

A delivered config's sandbox settings and plugin modules may restrict the server's own but not
widen them. A file that asks for more is refused with `config_field_denied`, naming the
setting; an equal or tighter value scans:

- `sandbox.network_scanners` may list only scanners the server's settings give a network. A
  shorter list takes the network away from the scanners it leaves out.
- `sandbox.extra_read_paths` may list only paths the server's settings grant.
- `sandbox.mode` can turn the sandbox on, but cannot turn it off or switch backends when the
  server's config sets a mode.
- `ash_plugin_modules` may add only ASH's own plugin modules and modules installed outside
  every git checkout and the scanned directory, and never the AWS or Snyk plugin modules, or a
  module inside either.

The server's settings are the ones in the file `ASH_CONFIG` names, and that file grants nothing
when it is inside a git checkout, so keep it outside every checkout. A delivered config's
`global_settings.mcp` section has no effect.

An MCP-client file reads no environment variables, since the environment it would read is the
server's. A file that uses a `${VAR:default}` reference or an `!ENV` tag is refused with
`error_type` `config_env_not_resolved` by `run_ash_scan`, which does not start the scan, and by
`get_config` and `validate_config`. A base it `extends` is judged on its own location, so a base
of yours keeps its references, and so does a file in a directory
`ASH_MCP_ALLOWED_CONFIG_ROOTS` names.

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

[Suppressions, ignore paths and scanner exclusions](../concepts/suppressions.md) explains how
suppressed findings affect the exit code and each report.

The server cannot register config profiles: `ash mcp` has no option for it, so `list_profiles`
returns an empty list and `select_profile` always fails. Runtime overrides from clients, such
as the `config_overrides` argument of the workspace tools, are always refused: they need a
registered profile, and the server cannot register one.

### Refuse delivered suppressions too

To refuse delivered suppressions and ignore paths, give the server's config a `denied_paths`
list of its own: the full default list, as `ash config init` writes it, followed by these two
entries:

<!-- doctest: config kind=other reason="two entries to append to the default denied_paths list, not a config on their own" -->
```yaml
- /global_settings/suppressions/**
- /global_settings/ignore_paths/**
```

A list of your own replaces the default list and is applied exactly as written, so keep every
default entry, start each one with `/`, and compare your list with the default again after you
upgrade ASH. A list equal to a default that ASH has shipped, such as the one an earlier
`ash config init` wrote, still counts as the default, and gets every entry of the current
default list. With a list of your own, a delivered config that sets `sandbox` or
`ash_plugin_modules` to a value other than the server's is refused too.

An entry matches a key spelled with `-` or `_`. Under `/scanners`, `/reporters`, and
`/converters`, an entry for a plugin's section also matches every spelling ASH reads as that
plugin. A glob in the plugin segment matches the plugins that ship with ASH and the plugins your
server config configures, so `/scanners/trivy-*/options/ignore_file` also covers
`/scanners/TrivyRepo/options/ignore_file`; for any other plugin, write its name.

## Clean up

- `clear_source` deletes the calling session's workspace, `<workspace root>/<session ID>`.
- Delivered source stays under the workspace root until the client calls `clear_source` or you
  delete it. Remove old directories under the workspace root while the server is stopped.
- Scan output stays in each scanned directory's `.ash/ash_output`.
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
- Set `ASH_MCP_TRANSPORT` to exactly `streamable-http` or `sse`.
- Set `ASH_MCP_ALLOWED_ROOTS`, and `ASH_MCP_ALLOWED_CONFIG_ROOTS` if clients need shared
  config, to the directories the client needs and nothing more.
- Run the server as a dedicated user without credentials the client should not use, and limit
  its network access.
- Delete old session workspaces.

[Scanning untrusted code](../concepts/scanning-untrusted-code.md) describes what protects the
host when the source a client sends is hostile. To scan a VS Code workspace over MCP, see
[Scale to large repositories](scale-large-repos.md).
