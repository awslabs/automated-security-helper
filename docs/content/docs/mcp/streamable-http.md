# Streamable-HTTP MCP Deployment Guide

This guide covers running the ASH MCP server over the streamable-HTTP transport so remote clients can drive scans against their own source trees and configs. It is the deployment counterpart to the local stdio transport documented in [ASH MCP Server Guide](../mcp-server-guide.md).

The behaviour described here lands under Track 10 of the ASH v3.x refactor (sections 10.1 through 10.7 in `tasks/todo.md`).

## When to use streamable-HTTP vs stdio

ASH ships two MCP transports:

- **stdio (default).** A single client (typically an IDE or a local agent) launches `ash mcp` as a subprocess and speaks JSON-RPC over the child's stdin/stdout. One process per user, no network surface, no auth needed. This is what `ash mcp` does today and remains the recommended setup for individual developer machines.
- **streamable-HTTP.** The MCP server is bound to a TCP port and accepts connections from remote clients. Each connection gets its own session workspace, its own selected config profile, and its own optional source-upload pipeline. Use this when you need a deployable, multi-tenant ASH service — for example, a shared scanner for CI runners, a hosted scanner an external agent can drive, or any setup where the client and the scanner run on different hosts.

Pick stdio for local single-user IDE integration. Pick streamable-HTTP when ASH must be reachable over the network.

## Starting the server

The full invocation form (Track 10.1):

```bash
ash mcp \
  --transport streamable-http \
  --host 0.0.0.0 \
  --port 8000 \
  --mount-path /mcp \
  --allowed-host ash-mcp.example.com \
  --auth-header-name x-ash-token \
  --auth-header-value-file /etc/ash/mcp-token \
  --profile default=/etc/ash/default.yaml \
  --profile strict=/etc/ash/strict.yaml
```

Flags:

- `--transport streamable-http` — selects the streamable-HTTP transport. Other accepted values: `stdio` (default) and `sse` (legacy, not covered here).
- `--host` — bind address. Use `127.0.0.1` for loopback-only deployments and `0.0.0.0` when fronted by a reverse proxy. Any address other than `127.0.0.1`, `localhost` or `::1` needs `--allowed-host` or `--trust-upstream-host-check`, or the server refuses to start (exit 3); see [Host and Origin checking](#host-and-origin-checking).
- `--allowed-host` — a Host header value the server accepts, repeatable: the name clients use to reach it, such as the proxy's hostname. ASH checks Host against this list and accepts no `Origin` header.
- `--trust-upstream-host-check` — a proxy or platform in front of ASH checks Host and Origin, so ASH checks neither. For a platform that restricts Host itself and cannot be given an allowlist in advance, such as Bedrock AgentCore Runtime. Refused together with `--allowed-host`, and refused with a loopback `--host` (`127.0.0.1`, `localhost`, `::1`), where ASH accepts only its own origin; behind a proxy on the same host, pass `--allowed-host` with the name the proxy forwards. Both refusals exit 3.
- `--port` — TCP port. Defaults are deliberately omitted; pick an explicit port that matches your proxy/firewall config.
- `--mount-path` — path under which the FastMCP app is mounted. Defaults to `/mcp`. Clients must connect to `http(s)://host:port<mount-path>`.
- `--auth-header-name` with `--auth-header-value-file PATH`, `--auth-header-value-fd N` or `--auth-header-value VALUE` — single-tenant header gate. Connections missing this header (or carrying a wrong value) are rejected before any tool dispatch. See [Auth](#auth) for how each form passes the value.
- `--stateless-http` — handle each request on its own instead of binding it to a server-held session, for a load balancer or a platform such as AgentCore. A stateless server issues no session; see [Session identity](#session-identity).
- `--trust-upstream-session-id` — stateless only: a platform in front of ASH issues and authenticates `Mcp-Session-Id`, so the header names the caller's session. See [Session identity](#session-identity).
- `--session-workspace-ttl SECONDS` — how long a session workspace may go unused before the server removes it (default 86400). See [Session lifecycle](#session-lifecycle).
- `--profile NAME=path/to/ash.yaml` — register a config profile under `NAME`. Repeatable. The YAML is loaded and validated through `AshConfig.from_file` at startup; bad profiles fail fast and the server refuses to start. See [Config profiles](#config-profiles).

The server logs the bound address and the registered profile names on startup. It does not log header values or profile contents.

### Host and Origin checking

The MCP SDK protects against DNS rebinding by checking the `Host` and `Origin` headers, and it turns that check on by itself only when the app is built for `127.0.0.1`, `localhost` or `::1`. For any other bind address, including `0.0.0.0`, `::`, a routable address and `127.0.0.2`, the check would be off and the server would answer any Host and any Origin. ASH therefore refuses to start a non-loopback bind unless the operator says how Host is checked:

- `--allowed-host NAME` (repeatable): ASH checks Host against the names given. Use the name clients and your proxy send.
- `--trust-upstream-host-check`: something in front of ASH checks Host and Origin, and ASH checks neither.

On a loopback bind with no `--allowed-host`, the server accepts only its own origin: Host `127.0.0.1:PORT`, `localhost:PORT` or `[::1]:PORT`, where PORT is `--port`, and the same as `http://` origins. The SDK's own loopback check accepts those names on any port; ASH accepts the bound port only. A request with no `Origin` header, which is what every non-browser MCP client sends, needs only the right Host. On port 80 the names without a port (`127.0.0.1`, `http://localhost`) are accepted too, because clients leave out the default port. With `--port 0` the system picks the port: ASH binds the socket first, builds the server for the port it got, and prints it at startup.

If you build the app yourself with `build_streamable_http_app` or `build_sse_app` on a loopback host without `allowed_hosts`, pass `port=` the port the server listens on; the builders refuse to build one without it (or with 0), because an app built for another port answers 421 to every request.

The refusal names both options. The Terraform container entrypoint passes `--trust-upstream-host-check` only when `ASH_MCP_TRUST_UPSTREAM_HOST_CHECK=true`, `ASH_MCP_ALLOWED_HOSTS` is empty and the bind is not loopback; the AgentCore module sets it. With neither variable set, an image bound to `0.0.0.0` refuses to start.

## Session identity

Source delivery, a bound profile and the scan registry all belong to a session, so the server has to know which session a call is part of. It decides that from the transport, never from a header alone:

| Transport | The caller's session |
| --- | --- |
| stdio | the single local client (`__default__`), with local trust |
| sse | the session the server issued for the event stream, named once in the message URL's `session_id`; an `Mcp-Session-Id` header on a message is ignored, and a URL that names `session_id` twice names no session |
| streamable-HTTP, stateful | the `Mcp-Session-Id` the server issued at `initialize`; a value it did not issue is ignored |
| streamable-HTTP, `--stateless-http` | none: the server issues no session and the header is client-chosen |
| streamable-HTTP, `--stateless-http --trust-upstream-session-id` | the `Mcp-Session-Id` header, which the operator declares a platform in front of ASH issues and authenticates |

Every caller on a network transport is remote, whatever headers it sends: it is confined to the operator's grants (`ASH_MCP_ALLOWED_ROOTS`, `ASH_MCP_ALLOWED_CONFIG_ROOTS`) plus its own session workspace, and never gets stdio's local trust. Local trust goes only to a caller ASH knows is the local client: `ash mcp` on stdio, or a program that drives the server through the MCP SDK's in-memory client inside `automated_security_helper.cli.mcp.session_identity.serving_local_client()`. Any other tool call that reaches the server with no HTTP request behind it, including an in-memory client outside that block, has no session identity.

`ASH_MCP_TRANSPORT` is an operator override on top of that: set to `streamable-http` or `sse`, it makes every caller in the process remote, in-process ones included. It is read stripped and in any case; empty, or only whitespace, it is unset. A value that names no transport (`http` or `streamable_http`, say) is treated as remote by an in-process caller, and `ash mcp` and `python -m automated_security_helper.cli.mcp_server` refuse to start with it, with exit 5 (a usage error), rather than serve with the override in an unknown state.

`ASH_CONFIG` is the operator's config for every scan the server runs without a config of its own. The server loads it at startup, the way it loads each `--profile`. When it names a path that is not a file (missing, or a directory), or a file the server can't read, parse or validate, `ash mcp` refuses to start on every transport (exit 3) with an error naming `ASH_CONFIG` and the path. Unset or empty, scans use the built-in default.

A caller with no session can still use the tools that take a path, inside the operator's grants. The tools that need a session refuse it with `error_type: session_identity_required` and an error naming `--trust-upstream-session-id`: `set_source_git`, `set_source_zip_chunk`, `set_source_zip_finalize`, `clear_source`, `select_profile`, `list_active_scans`, `get_scan_progress`, `cancel_scan`, and `run_ash_scan`, with or without `source_dir`: a scan it started could be neither followed nor cancelled. A stateless server behind a plain load balancer therefore scans with `run_ash_workspace_scan`, over a `.code-workspace` file and projects inside the operator's grants, whose response carries each project's result, and reads results by path; `run_ash_scan` and source delivery need a stateful server or a platform that issues the session header.

With `--trust-upstream-session-id`, isolation between two callers is exactly as strong as the platform makes the header: ASH cannot tell a header the platform set from one a client set. The names ASH keeps under the workspace root for itself, `__default__`, `__unidentified__` and `.stdio-servers`, are refused in any letter case, because a case-insensitive filesystem opens `__DEFAULT__` as the same directory as `__default__`. The flag is refused with any transport other than `streamable-http --stateless-http`, where the server issues its own sessions.

## Config profiles

A profile is a named, pre-validated `AshConfig` registered at server startup via `--profile NAME=path/yaml`. Profiles are immutable for the lifetime of the process. Clients select a profile per session and may optionally patch it within the runtime-override allowlist (Track 10.3).

Discover the profiles a deployment offers with:

```python
profiles = await mcp__ash__list_profiles()
# -> {"profiles": [{"name": "default", "path_sha256": "..."}], "count": 1}
```

Path hashes let clients detect that the operator rotated a profile file underneath them; the paths and the profile contents themselves are never returned. An empty list means the operator registered no profiles, not that the call failed.

### Selecting a profile

`mcp__ash__select_profile` binds a registered profile to the calling session. Three modes:

1. **Static.** `select_profile(profile_name="default")` — bind the profile as-is.
2. **Inherit-and-patch.** `select_profile(profile_name="default", patch_ops=[...])` — apply a JSON-Patch document, each op checked against the runtime-override allowlist first; a rejected op fails the whole call without mutating the session config. See [Runtime config overrides](#runtime-config-overrides).
3. **Full override.** `select_profile(profile_name="default", override_yaml="...")` — replace the resolved config with a client-supplied YAML string, validated through `AshConfig` and held to the same runtime-override allowlist as `patch_ops`. See [Overrides are patches](#overrides-are-patches).

`patch_ops` and `override_yaml` are mutually exclusive, and the parameter is `profile_name` — a profile must be named in every mode, including override.

Every later call in the session that does not name a config of its own runs under the bound one: `run_ash_scan`, `resolve_ash_workspace` and `run_ash_workspace_scan`. A `config_path` passed on the call still wins, because naming one is the more specific statement. In workspace mode the bound config is the fallback for a project that declares no `.ash.yaml` of its own; a project with one keeps it, which is what lets a single workspace span differently-configured repositories.

```python
await mcp__ash__select_profile(profile_name="strict")
# -> {"success": True, "mode": "static", "config_path": ".../config/ash.yaml", ...}
await mcp__ash__run_ash_scan()  # runs under "strict"
```

The returned `config_path` names a file the server materialized inside your session's own workspace. That is how the binding reaches the scan: the scan entry point takes a config path rather than a config object, so the resolved config is written out and the path passed down. The file is inside the session sandbox, so this session may read it and another session may not. `clear_source` removes it along with the rest of the session workspace, after which calls fall back to ordinary config discovery.

Sessions do not share a binding, and re-binding replaces the previous one for that session only.

#### Before v3.4

`select_profile` was implemented but not registered, and no client could invoke it. Three things were missing rather than one: there was no `--profile` flag, so the registry was always empty and `list_profiles` always returned `{"profiles": [], "count": 0}`; the tool was never passed to `@mcp.tool()`; and nothing read the binding, because the scan entry point takes a config path and a bound `AshConfig` had nowhere to go. All three are closed. If you worked around this with `config_path` on every call, that keeps working unchanged.

## Source delivery

A streamable-HTTP client typically does not share a filesystem with the server, so the source tree to scan must arrive over the protocol. ASH offers two paths (Track 10.2).

Both land the tree in the calling session's own workspace and record it as that session's `source_dir`. The session is the one the transport identifies (see [Session identity](#session-identity)), not a tool argument and not a header the server did not issue, so a client cannot choose a session it was not given. A session id is still a bearer value: anyone holding another session's id can act as that session, so keep ids out of logs and URLs others can read. On stdio there is a single client, so everything resolves to one default session.

Having delivered a tree, call `run_ash_scan` with **no** `source_dir`:

```python
result = await mcp__ash__set_source_zip_finalize(upload_id=..., expected_sha256=...)
await mcp__ash__run_ash_scan()
```

An omitted `source_dir` means "the tree I just gave you" whenever the session has one. Passing a path explicitly still works and still has to satisfy [the root policy](#restricting-scan-targets). Naming a path you never delivered is how you scan a repository the operator mounted into the server, not one you uploaded.

The no-argument form depends on the session id being the same on both calls, which holds whenever the client's own connection keeps its session. When it does not hold, the call is **refused rather than redirected**:

| Situation | Result |
| --- | --- |
| This session delivered a tree | it is scanned |
| stdio and nothing delivered | the working directory is scanned, as it always has been |
| A network caller with no session (see [Session identity](#session-identity)) | refused, `error_type: session_identity_required` |
| This session delivered nothing, another session did | refused, `error_type: session_source_mismatch` |
| This session delivered nothing, nor has any other | refused, `error_type: no_source_delivered` |

The two refusals exist because the alternative is worse than an error. Falling back to the server's working directory on a network transport scans a tree that holds none of the caller's code, completes normally, and reports no findings — a result a caller cannot distinguish from a clean repository. A scan that examined nothing and reads as clean is the failure mode this whole surface is meant to avoid, so the ambiguous cases say so instead. The mismatch error reports how many *other* sessions hold source, never which, so it diagnoses a rotating session id without disclosing one caller's session to another.

This matters most on Bedrock AgentCore Runtime, where it is **not** established that the id is stable: that platform mints its own session ids and, measured against live runtimes, returns a fresh one on nearly every response while honoring only the id from `initialize`. What the container sees per request could not be determined from outside. A stateless server identifies sessions there only when started with `--trust-upstream-session-id`, the declaration that the platform issues the header. On that target, capture the `source_dir` the delivery tool returns and pass it back to `run_ash_scan(source_dir=...)`; see [deploy/cdk/README.md](../../../../deploy/cdk/README.md) for the detail and for a two-call probe that settles the question.

### Git ref

```python
await mcp__ash__set_source_git(
    url="https://git.example.com/org/repo.git",
    ref="main",
    depth=1,
)
```

The client names the URL and the server runs git, so the operator decides what git may reach:

- Only hosts listed in `ASH_MCP_GIT_ALLOWED_HOSTS` (comma- or whitespace-separated host names, matched exactly and case-insensitively against the URL's host, any port) are cloned. An `ssh://` URL with `%`, `?`, `#`, `[` or `]` between `ssh://` and the path is refused with `error_type: clone_url_not_permitted`, so the host checked is the host git connects to. The list is empty by default, so every remote is refused until the operator names one: `ASH_MCP_GIT_ALLOWED_HOSTS=github.com,git.example.com`. A refusal has `error_type: clone_host_not_permitted`.
- `depth` is a positive whole number of commits; any other value is refused before anything is created for the session.
- Each git command a delivery runs (the clone, and for a `ref` the fetch and the checkout) has 10 minutes. A command still running then is stopped together with the processes it started (ssh, `git-remote-https`), the partial tree is removed, and the call fails with `error_type: clone_timed_out`.
- Only `https://`, `ssh://` and scp-like `user@host:path` URLs. `http://` and `git://` (no integrity protection), `file://` and plain paths (the server's own filesystem) are always refused, as are URLs that begin with `-` or use the `ext::` transport.
- git never uses the server's credentials or configuration. It runs with an environment built from a short allowlist (no ssh agent socket, askpass helper, proxy or token variables), with system and global git config switched off, with an empty `credential.helper`, with `GIT_TERMINAL_PROMPT=0`, with only the https and ssh protocols allowed, and without following http redirects. Every git command of a delivery (the clone, and for a ref the fetch and the checkout) passes `-c core.fsmonitor=false -c core.hooksPath=/dev/null`, so git starts no fsmonitor command and no hook, whatever a repository's config names. ssh runs with `-F /dev/null`, no identity file, no agent, batch mode and `StrictHostKeyChecking=yes`, so an ssh host's key must be in the system-wide known-hosts file (`/etc/ssh/ssh_known_hosts`).
- `ssh_key_id` must be omitted. The server registers no ssh keys, so any id is refused with `error_type: ssh_key_not_registered`. Raw private keys are never accepted over the wire.

Run the server as an account with no git or ssh credentials anyway: the rules above keep the server's credentials out of git, and a dedicated account keeps them off the host. An operator who needs git to go through a proxy cannot configure one here; deliver the tree as a zip instead.

`depth=1` is the default; increase only when the scan needs older revisions. The cloned working tree lands under the per-session workspace and becomes the session's `source_dir`.

### Chunked zip upload

For agents that don't have git access to the source, upload the tree as a zip in ≤1 MiB chunks, then finalize:

```python
import base64, hashlib

upload_id = "session-upload-1"
zip_bytes = open("repo.zip", "rb").read()
sha = hashlib.sha256(zip_bytes).hexdigest()

# Send in 1 MiB chunks
chunk_size = 1024 * 1024
chunks = [zip_bytes[i : i + chunk_size] for i in range(0, len(zip_bytes), chunk_size)]
for seq, chunk in enumerate(chunks):
    await mcp__ash__set_source_zip_chunk(
        upload_id=upload_id,
        sequence=seq,
        data_b64=base64.b64encode(chunk).decode(),
        last=(seq == len(chunks) - 1),
    )

await mcp__ash__set_source_zip_finalize(
    upload_id=upload_id,
    expected_sha256=sha,
)
```

Hard limits enforced server-side:

- Max zip size on the wire: **100 MiB**.
- Max extracted size: **500 MiB**.
- Max files: **50000**.

Any of these triggers an immediate failure. Out-of-order sequences, checksum mismatches, and zip entries with `..`, absolute paths, or symlinks pointing outside the session workspace are all rejected before extraction.

`mcp__ash__clear_source` wipes the session workspace and resets `source_dir` if you need to reload.

While a scan of the session runs, `clear_source`, `set_source_git` and `set_source_zip_finalize` are refused with `error_type: source_delivery_busy`: each would remove or replace the tree the scan is reading, and a scan whose tree changes under it can report clean for code it never examined. Call them again once `get_scan_progress` reports the scan finished. Uploading chunks is not refused, because chunks land beside the tree rather than in it. "Runs" starts when `run_ash_scan` returns the scan id, not when the scan begins reading, and a session that ends in that time keeps its tree until the scan returns. The other way round, `run_ash_scan` is refused with the same `error_type` while one of those calls is changing the session's tree. `run_ash_workspace_scan` by a session that has delivered a tree, or bound a profile, holds the session the same way until the scan's work is done, even when the call is cancelled first, and is refused the same way while the tree is changing. A session that has delivered nothing has nothing of its own for a workspace scan to hold, so its scan of a directory the operator granted takes no hold and creates nothing under the workspace root.

### Config files in delivered source

A delivered tree can carry its own `.ash.yaml`, and a client can name any file in its session workspace as `run_ash_scan`'s `config_path`. Such a file was written by the client, not the operator, so its sandbox settings are restrict-only, the same as a config file inside the scanned repository, wherever the scan target is:

- `sandbox.network_scanners`, `sandbox.extra_read_paths`, `sandbox.read_path_scanners` and `sandbox.env_scanners` come from the server instead: the profile this session bound with `select_profile`, or else `ASH_CONFIG` and the defaults. A server config file inside a git checkout grants nothing either, so `ASH_CONFIG` has to name a file outside every checkout for its grants to apply.
- The file's `network_scanners` list still applies as a limit, so it can take network away from a scanner but never give it one.
- `sandbox.mode` can turn the sandbox on, but cannot turn it off or move it to another backend when the server's config sets a mode.

Everything else in the file applies as usual. The config the server materializes for `select_profile`, under the session's `config/` directory, is the operator's and keeps its grants, as does a file under `ASH_MCP_ALLOWED_CONFIG_ROOTS`, as long as the file is outside every git checkout and outside the scanned directory.

`get_config` shows the sandbox section the same way, as a scan of the session's delivered source (or, with none delivered, the working directory) would apply it.

### Restricting scan targets

`run_ash_scan` also accepts a server-side path directly, and ASH writes its
output tree inside whatever directory it is given. `ASH_MCP_ALLOWED_ROOTS` bounds
that: it holds a list of directories, separated by the platform path separator,
and a scan target must resolve to one of them or to something beneath one.

```bash
ASH_MCP_ALLOWED_ROOTS=/srv/repos
```

Targets are resolved before the comparison, so a symlink sitting inside an
allowed root but pointing outside it is refused.

A session that has delivered source over the protocol also gets its own
workspace directory, `ASH_MCP_WORKSPACE_ROOT/<session_id>`, so
`set_source_git` and `set_source_zip_finalize` keep working regardless of what
the variable names — you do not need to list `ASH_MCP_WORKSPACE_ROOT` yourself.
Only the calling session's own directory is allowed, not the shared root, so one
tenant cannot name another tenant's workspace as a scan target.

Because setting the variable replaces the default list, list every directory the
server legitimately scans. In the container images that means including the
source mount `/src` alongside any workspace path, or a no-argument
`run_ash_scan()` — which defaults to the working directory — will be refused.

Set this on any deployment where clients are not fully trusted. Without it, ASH
falls back to refusing a short fixed list of system directories (`/boot`,
`/dev`, `/etc`, `/proc`, `/root`, `/sys`, the filesystem root, and the Windows
equivalents), which is a safety net rather than a boundary: every other
directory the server process can reach stays a valid target. Naming a directory
in `ASH_MCP_ALLOWED_ROOTS` replaces that list, which is also how you arrange a
deliberate scan of a system path.

## Runtime config overrides

The runtime-override surface is the security boundary that lets clients tweak a profile without giving them the whole config (Track 10.4). It is gated by a Pydantic-declared allowlist on `AshConfigGlobalSettingsSection.mcp.runtime_overrides`.

The allowlist defines:

- `enabled: bool = False` — the master switch. Defaults to off; runtime patches are denied unless the operator flips this on per profile.
- `allowed_paths: list[str]` — JSON-Pointer prefixes the client may target. A trailing `/*` means "this whole subtree". Example: `/scanners/*/options/severity_threshold`.
- `denied_paths: list[str]` — explicit blocks; always wins over `allowed_paths`. The defaults are `/fail_on_findings`, `/fail_on_incomplete_scanners`, `/content_db_staleness`, `/content_db_staleness_overrides`, `/honor_ignore_files`, `/sandbox` and `/sandbox/**`, `/ash_plugin_modules` and `/ash_plugin_modules/**`, detect-secrets' `scan_settings/filters_used` and `scan_settings/plugins_used` (each with `/**`) and `baseline_file` under `/scanners/detect-secrets/options` (a client could otherwise turn on secret verification, which sends candidate secrets to their issuers, or make the scanner import a file), `/global_settings/ignore_paths`, `/global_settings/suppressions`, `/reporters/bedrock-summary-reporter/options/aws_*`, the reporters that send results off the host, each whole: `/reporters/cloudwatch-logs/**`, `/reporters/aws-security-hub/**`, `/reporters/s3/**` and `/reporters/bedrock-summary-reporter/**` (`**` also matches the section itself, so a client can neither turn one on nor choose where it sends), the scanners that send data off the host, each whole: `/scanners/snyk-code/**` (the source), `/scanners/npm-audit/**` and `/scanners/trivy-repo/**` (dependency lists), `/scanners/detect-secrets/**` (candidate secrets, when verifying), and `/scanners/semgrep/**` and `/scanners/opengrep/**` (usage metrics), and the archive converter's four extraction limits, `/converters/archive/options/max_members`, `max_member_bytes`, `max_total_bytes` and `max_compression_ratio`, which also refuse a write at `/converters/archive/options`, `/converters/archive` or `/converters`. Those four, the `/sandbox` and `/ash_plugin_modules` entries, the detect-secrets settings and the entries for the reporters and scanners that send data off the host are kept in any `denied_paths` a profile sets, which otherwise replaces the defaults: a profile can add denials but cannot let a client raise the extraction limits, turn those settings on, or turn on, turn off or reconfigure a plugin that sends data off the host, and a whole-config write at the root pointer is refused for the same reason. A `denied_paths` entry, and a `denied_value_patterns` key, matches a path whatever mix of `-` and `_` either one is spelled with, because ASH reads `bedrock-summary-reporter` and `bedrock_summary_reporter` as the same key. Under `/scanners`, `/reporters` and `/converters`, an entry naming a plugin's section also matches every other spelling ASH reads as that plugin's config: case, punctuation and the words Scanner, Reporter and Converter are ignored, so `/reporters/BedrockSummary` is refused by the `bedrock-summary-reporter` entry. A plugin segment containing a glob character (`*`, `?`, `[`) is matched as written.
- `denied_value_patterns: dict[str, str]` — per-path regex denylist for dangerous values (e.g., scanner `extra_args` containing `--no-verify` or shell metacharacters).

Additional invariants enforced by `apply_runtime_patch`:

- `move` and `copy` ops are rejected outright (they sidestep target-path checks).
- Patch documents larger than **64 KiB** are rejected.
- Any rejection raises `RuntimePatchDeniedError` with the offending op and the rule that fired; nothing is applied.

The full allowlist is exposed at runtime via the `ash://schema/runtime-overrides` resource so clients can introspect what is patchable before composing a patch.

### Overrides are patches

`override_yaml` is checked by the same rules, not by a second copy of them. The server validates the YAML as an `AshConfig`, diffs it against the profile, and sends the resulting add/remove/replace ops through `apply_runtime_patch`. An override is accepted exactly when that patch would be: never while `enabled` is false, and only if every field it changes is in `allowed_paths`, outside `denied_paths`, and clear of `denied_value_patterns`. A refusal returns `success: false` with an `override denied:` error naming the op and the rule.

Because an override replaces the profile wholesale, a field the YAML leaves out reverts to its default, and that counts as a change. Omitting `sandbox` from an override of a profile that sets `sandbox.mode: bwrap` is a `replace` at `/sandbox/mode`, refused by the `/sandbox` entry. To change one field with `override_yaml`, restate the profile and edit that field; `patch_ops` is usually the shorter way to say the same thing.

### Safe example

A profile that has `mcp.runtime_overrides.enabled: true` and allows `/scanners/*/options/severity_threshold` plus `/global_settings/allowlist`. The client raises bandit's threshold to `HIGH` and narrows the allowlist:

```python
patch_ops = [
    {
        "op": "replace",
        "path": "/scanners/bandit/options/severity_threshold",
        "value": "HIGH",
    },
    {
        "op": "add",
        "path": "/global_settings/allowlist/allowed_paths",
        "value": ["src/", "lib/"],
    },
]

select_profile(profile_name="default", patch_ops=patch_ops)
```

### Unsafe example

The same profile receives a patch that targets a denied path:

```python
patch_ops = [
    {
        "op": "replace",
        "path": "/global_settings/fail_on_findings",
        "value": False,
    },
]

select_profile(profile_name="default", patch_ops=patch_ops)
# raises RuntimePatchDeniedError:
# {
#   "rejected_op": {"op": "replace", "path": "/global_settings/fail_on_findings", ...},
#   "reason": "path '/global_settings/fail_on_findings' matches denied_paths rule",
#   "rule": "denied_paths"
# }
```

The session config is unchanged. The client may inspect `ash://schema/runtime-overrides` to see why the path is blocked and either pick an allowed alternative or ask the operator to add it to `allowed_paths`.

## Session lifecycle

Per-connection state is held in a process-local `MCPSession` keyed by FastMCP connection id (Track 10.5):

```
MCPSession {
  id,
  source_dir,
  config,           # resolved AshConfig
  profile_name,
  patch_ops,        # JSON-Patch document, if any
  workspace_root,   # ASH_MCP_WORKSPACE_ROOT/<session_id>
}
```

Workspaces live under `ASH_MCP_WORKSPACE_ROOT` (defaults to `$XDG_CACHE_HOME/ash-mcp/<session_id>/`). A session's workspace (its delivered tree, uploads in progress and the config `select_profile` materialized) and its bound profile are removed when the session ends:

| Transport | The session ends |
| --- | --- |
| streamable-HTTP, stateful | when the client's `DELETE` is answered (the removal is complete before the response is sent), when the MCP SDK answers 404 on the server's endpoint (`--mount-path`) for a session it discarded (after its 30-minute idle timeout, say) and a client asks about it again (a 404 for any other path, which has no route, ends nothing), and for every session the server issued when the server shuts down |
| sse | when the event stream closes |
| stdio | when the last stdio server sharing the workspace root exits (every stdio server of one user shares `__default__`, so one server's exit leaves it in place while another runs) |
| streamable-HTTP, `--stateless-http` | never visibly: see the sweep below |

A session that ends while one of its scans runs keeps its tree until that scan returns.

The server cannot see every end: a stateless server has no session at all, and a stateful session the MCP SDK closes for being idle (after 30 minutes) sends nothing ASH observes unless a client uses its id again. So every HTTP server also sweeps the workspace root, before it answers its first request and then at most every five minutes, and removes the workspace of any session nobody used for longer than `--session-workspace-ttl` seconds (default 86400, 24 hours). Each request that names a session counts as a use. The sweep removes only directories ASH created as session workspaces, each of which carries a `.ash-mcp-session` marker file; it never removes anything else under the root, the stdio session's workspace (its own servers remove it), a symlink, or a workspace a running scan holds. A session whose scan is running, or whose tree is being changed, is skipped, not queued for removal when the scan returns, and its age is read again just before removal, so a session used meanwhile is kept. Give `ASH_MCP_WORKSPACE_ROOT` a directory that belongs to ASH alone anyway: session workspaces created before the marker existed are never swept. Servers that share one `ASH_MCP_WORKSPACE_ROOT` sweep each other's idle workspaces by the same rule, and each running scan holds a locked entry under `<root>/.ash-mcp-scans/<session id>/` so that no server's sweep removes a workspace another server is scanning. Those locks are file locks: a filesystem that does not share them between hosts does not carry that protection. The request that starts a sweep is answered once the sweep finishes; requests that arrive while it runs are not held for it.

Concurrency:

- Scans **within** a single session are serialized; one client cannot launch parallel scans against itself.
- Scans **across** sessions run in parallel under the existing `scan_registry` semantics — a noisy session can't block another tenant's scan.

Each session runs at most `mcp-resource-management.max_concurrent_scans_per_session` scans at once (default 2; `0` for no limit), set in the operator's config that `ASH_CONFIG` names and never in a scanned or delivered one. A `run_ash_scan` counts until its scan returns, and a `run_ash_workspace_scan` counts once, however many projects it has, until its work is done, even if the call is cancelled first. One more scan is refused with `error_type: session_scan_limit` until one finishes; other sessions go on scanning. Callers with no session share one count under the same limit. On a stateless server run without `--trust-upstream-session-id` that is every caller, so the limit there is for the whole server; `run_ash_workspace_scan` is the scan such a caller can start.

Scans are visible per session. `list_active_scans`, `get_scan_progress` and `cancel_scan` see and act on the calling session's own scans only, including the per-project scans `run_ash_workspace_scan` registers. Another session's scan id gets exactly the answer an id that was never issued gets, and a listing's `stats` count only the caller's scans. Two sessions cannot scan the same directory at once, because both would write its `.ash/ash_output`; the second is refused with "already has an active scan", and the refusal names the running scan's id only to the session that started it.

## Auth

The streamable-HTTP transport ships with one built-in gate: a static header check via `--auth-header-name` and the expected value. Connections without the configured header (or with the wrong value) are rejected before any tool dispatches.

The value can be given three ways, and only one at a time:

- `--auth-header-value-file PATH` reads it from a file once at startup. The file must be a regular file, not a symlink, with no permissions for its group or other users (`chmod 600`; the mode isn't checked on Windows). One trailing newline is dropped.
- `--auth-header-value-fd N` reads it from an inherited file descriptor, 3 or above, once at startup, and closes it. A file (a memfd, say) is read from its start, a pipe from where it is.
- `--auth-header-value VALUE` puts the value on the server's command line, which every local user can read (`/proc/<pid>/cmdline`, `ps`), including from outside a container on its host. It still works, and the server prints a warning naming the two options above.

An empty value, one with a line break or NUL, or one longer than 16 KiB is refused, as is more than one form. Every refusal exits 3 before anything is served.

This is sufficient for **single-tenant** deploys where one trusted client owns the server. For multi-tenant deployments:

- Run ASH behind a reverse proxy (nginx, traefik, an API gateway) that terminates TLS and authenticates the caller.
- Have the proxy inject the static header value so ASH only accepts traffic that has already been authenticated upstream.
- Run one server per tenant if their configs must differ. Per-tenant config selection over the protocol is not available yet — see [Selecting a profile is not available yet](#selecting-a-profile-is-not-available-yet) — so a single server cannot currently give two tenants two different configs.

The runtime-override allowlist (Track 10.4) plus per-session workspaces (Track 10.5) are the in-process isolation primitives. They are not a substitute for upstream tenant authentication.

## Docker example

Single-container invocation:

```bash
docker run \
  -p 8000:8000 \
  -v /etc/ash:/etc/ash:ro \
  -e ASH_MCP_WORKSPACE_ROOT=/var/cache/ash-mcp \
  -e ASH_MCP_ALLOWED_ROOTS=/src:/var/cache/ash-mcp \
  ash mcp \
    --transport streamable-http \
    --host 0.0.0.0 \
    --port 8000 \
    --allowed-host localhost:8000 \
    --allowed-host 127.0.0.1:8000 \
    --profile default=/etc/ash/default.yaml \
    --profile strict=/etc/ash/strict.yaml \
    --auth-header-name x-ash-token \
    --auth-header-value-file /etc/ash/mcp-token
```

`/etc/ash/mcp-token` holds the value, with mode 600 and owned by the user the container runs ASH as.

`docker-compose.yml` snippet pairing ASH with an nginx TLS terminator:

```yaml
services:
  ash-mcp:
    image: ash:latest
    command:
      - mcp
      - --transport=streamable-http
      - --host=0.0.0.0
      - --port=8000
      - --allowed-host=ash-mcp.example.com
      - --profile=default=/etc/ash/default.yaml
      - --profile=strict=/etc/ash/strict.yaml
      - --auth-header-name=x-ash-token
      - --auth-header-value-file=/etc/ash/mcp-token
    volumes:
      - /etc/ash:/etc/ash:ro
      - ash-workspace:/var/cache/ash-mcp
    environment:
      ASH_MCP_WORKSPACE_ROOT: /var/cache/ash-mcp
      ASH_MCP_ALLOWED_ROOTS: /src:/var/cache/ash-mcp
    expose:
      - "8000"

  nginx:
    image: nginx:1.27
    ports:
      - "443:443"
    volumes:
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
      - ./nginx/tls:/etc/nginx/tls:ro
    depends_on:
      - ash-mcp

volumes:
  ash-workspace:
```

The nginx config is responsible for TLS termination and for injecting `x-ash-token: ${ASH_TOKEN}` on every request that has already authenticated against the tenant's identity provider. It must forward the client's `Host` (`proxy_set_header Host $host;`), which is the `--allowed-host` value ASH checks.

## Security note

The streamable-HTTP transport puts the MCP server on the network. A few invariants to keep in mind:

- **The auth header is the only built-in gate.** There is no per-tool RBAC, no per-tenant rate limiting, no audit log beyond standard logging. Anything more sophisticated belongs in a fronting proxy.
- **Set `ASH_MCP_ALLOWED_ROOTS`.** Scan targets are confined to the roots it names, plus the per-session workspace. The fallback when it is unset refuses only a short list of system directories and leaves the rest of the server's filesystem available as a scan target, so on a network-reachable deployment it is not a substitute for naming the roots yourself. See [Restricting scan targets](#restricting-scan-targets).
- **Always run behind TLS in production.** ASH does not terminate TLS itself. Use nginx, traefik, an API gateway, or a service mesh sidecar.
- **The runtime-override allowlist defaults to disabled.** A profile must explicitly set `mcp.runtime_overrides.enabled: true` and enumerate `allowed_paths` for any client patching to succeed, through `patch_ops` or `override_yaml`. Leaving it off is the safe default — clients can still pick profiles, just not modify them.
- **`set_source_git` clones only from hosts in `ASH_MCP_GIT_ALLOWED_HOSTS`**, which is empty by default, and never with the server account's credentials or git configuration. See [Git ref](#git-ref).
- **Source-upload limits are per-session, not per-tenant.** A misbehaving tenant can still consume their session quota. Pair the transport with upstream rate limits if untrusted clients can connect.
- **Workspaces are removed when the session ends, or after `--session-workspace-ttl` unused.** Don't rely on session-resident state to survive reconnects; persisted state across server restarts is explicitly out of scope (Track 10.8). See [Session lifecycle](#session-lifecycle).

## Cross-references

- Local single-user MCP setup: [ASH MCP Server Guide](../mcp-server-guide.md)
- Performance tuning under concurrent sessions: [MCP Server Performance and Scalability](../mcp-performance-scalability.md)
- Full tool inventory: [MCP Tools Reference](../MCP-TOOLS-REFERENCE.md)
- Track 10 spec: `tasks/todo.md`, sections 10.1 through 10.9
