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

Every later call in the session that does not name a config of its own runs under the bound one: `run_ash_scan`, `resolve_ash_workspace` and `run_ash_workspace_scan`. A `config_path` passed on the call still wins, because naming one is the more specific statement. In workspace mode the bound profile is the operator's config for every project: each field the profile sets is final, a project's own `.ash.yaml` fills only the fields it leaves unset, and a project with no `.ash.yaml` runs under the bound config alone. A copy the client patched is not layered over a project's own config. A session that bound no profile layers the server's `ASH_CONFIG` file the same way, unless that file is under the MCP workspace root. See [Which config each project gets](workspace-mode.md#which-config-each-project-gets).

```python
await mcp__ash__select_profile(profile_name="strict")
# -> {"success": True, "mode": "static", "config_path": ".../config/ash.yaml", ...}
await mcp__ash__run_ash_scan()  # runs under "strict"
```

The returned `config_path` names a file the server materialized inside your session's own workspace. That is how the binding reaches the scan: the scan entry point takes a config path rather than a config object, so the resolved config is written out and the path passed down. The file is inside the session sandbox, so this session may read it and another session may not. `clear_source` removes it along with the rest of the session workspace, after which calls fall back to ordinary config discovery.

Where the file is depends on the mode. The profile as registered is always written to the session's `config/ash.yaml`, holding only the fields the profile sets (so it can be layered over a workspace project's own config), and a static binding (or one with an empty `patch_ops`) returns that path. A binding with a non-empty `patch_ops`, or with `override_yaml`, returns `client-config/ash.yaml`, which holds the profile after your change and counts as your config, not the operator's; see [A patched value is the client's](#a-patched-value-is-the-clients). Binding again without a patch removes `client-config/ash.yaml`.

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
- Each git command a delivery runs (the clone, and for a `ref` the fetch and the checkout) has 10 minutes. A command still running then is stopped together with the processes it started (ssh, `git-remote-https`), the partial tree is removed, and the call fails with `error_type: clone_timed_out`. A clone that grows the session's source directory past 500 MiB, the limit the zip channel puts on an extracted tree, is stopped the same way and fails with `error_type: clone_too_large`.
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

While a scan of the session runs, `clear_source`, `set_source_git` and `set_source_zip_finalize` are refused with `error_type: source_delivery_busy`: each would remove or replace the tree the scan is reading, and a scan whose tree changes under it can report clean for code it never examined. Call them again once `get_scan_progress` reports the scan finished. Uploading chunks is not refused while a scan runs, because chunks land beside the tree rather than in it. A chunk is refused (`error_type: session_workspace_busy`) while one of those calls is changing the session's tree, and `clear_source`, `set_source_git` and `set_source_zip_finalize` are refused (`error_type: source_delivery_busy`) while a chunk is being written; send the call again. The four delivery tools run on a separate pool of eight worker threads across all sessions, so a ninth concurrent delivery waits for a worker. A delivery whose call is cancelled finishes or times out on the server, and the session reads busy until then. "Runs" starts when `run_ash_scan` returns the scan id, not when the scan begins reading, and a session that ends in that time keeps its tree until the scan returns. The other way round, `run_ash_scan` is refused with the same `error_type` while one of those calls is changing the session's tree. `run_ash_workspace_scan` by a session that has delivered a tree, or bound a profile, holds the session the same way until the scan's work is done, even when the call is cancelled first, and is refused the same way while the tree is changing. A session that has delivered nothing has nothing of its own for a workspace scan to hold, so its scan of a directory the operator granted takes no hold and creates nothing under the workspace root.

### Config files in delivered source

A delivered tree can carry its own `.ash.yaml`, and a client can name any file in its session workspace as `run_ash_scan`'s `config_path`. Such a file was written by the client, not the operator. So was any other file a client names as `config_path` (or to `get_config` and `validate_config`), unless it is in a directory `ASH_MCP_ALLOWED_CONFIG_ROOTS` names or is one of the profile files the server writes in the session's own `config/` directory, `ash.yaml` and the per-call profiles, `call-profile-` followed by 16 lowercase hex digits and `.yaml` (or `call-profile.yaml`), directly in `config/` (a path in another session's workspace is refused). Any other file in `config/` is the client's, and neither `config/` nor `client-config/` may be a scan target or a workspace `output_dir`, so no scan writes there. A config in another checkout the server may scan is that checkout's, and the operator let the server scan it, not take its settings. A path is judged where it sits, at each symlink on the way, and by the file it reaches, so a link a client delivered is the client's wherever it points, and so is a file reached through a linked directory such as `.ash`, and every base such a file extends. A config named through a link in a delivered tree may extend only files in that tree. A refusal names the path the client used, not the file a link reaches, and a validation error for such a file names the file and where each problem is without quoting the values in it. A scan with no `config_path` reads the `.ash.yaml` it finds in the target only when the file it resolves to is in a directory the caller may read config from, the check `get_config` applies to a file it finds: one that links elsewhere is refused with `error_type: config_input_not_permitted` before it is read. The workspace tools check each project's `.ash.yaml` the same way, and every other config source in the project's directory, a `pyproject.toml` included, before discovery opens any of them; they refuse with exit code 4. The profile `select_profile` writes after a client's `patch_ops` or `override_yaml`, `client-config/ash.yaml`, is the client's too, and so are the workspace tools' `config_overrides` (see [A patched value is the client's](#a-patched-value-is-the-clients)). Everything below applies to all of these.

First, it may not change a field the session's runtime-override policy denies. `denied_paths` and `denied_value_patterns` apply to every file of the config's chain that a client delivered, as resolution parsed it, matched as for `patch_ops` (either `-` or `_`, every spelling of a plugin's section, globs). They apply whether or not runtime overrides are enabled, since a config file is not an override. Only what the file changes counts: a value equal to the server's at the same key (an `ash config init` file writes the defaults) is accepted, while every op in the file's `patch` is checked as written. A `denied_value_patterns` entry also matches mapping keys, and refuses a matching key in a delivered file even where the server's config has the same key; only the session's patched profile, `client-config/ash.yaml`, which repeats the registered profile with the client's checked patch applied, is not refused for a key the server's config has.

- The policy is the registered profile the session bound with `select_profile`, or else the one in `ASH_CONFIG` (the defaults when it sets none, or when `ASH_CONFIG` names a file under the MCP workspace root, which is a client's; ASH logs a warning then). It is never read from the session's copy of the profile, which a client's `patch_ops` produced, and `/global_settings/mcp` is a default `denied_paths` entry, so a client cannot change the policy.
- Under the default `denied_paths`, `sandbox` and `ash_plugin_modules` are checked against the server's own settings instead (below), and a delivered tree's own `global_settings.suppressions` and `global_settings.ignore_paths` apply, as they do on the CLI. Each suppression and ignore path the operator did not supply is marked `client_supplied: true` in the results' config, and a SARIF suppression from one carries `properties.clientSupplied`. Scanners and converters skip only the operator's ignore paths, so the files under a client-supplied ignore path are still scanned, and each finding there is kept as a suppressed result marked the same way rather than dropped. The results show what the client's config hid.
- What the marking looks like: in SARIF the suppression has a `justification` that starts with `(ASH, client-supplied config)` and names the entry, and `properties.clientSupplied: true`; its `kind` is `inSource` for a suppression entry and `external` for an ignore path or a scanner exclusion (below). See [Suppressions an MCP client's config supplied](../suppressions.md#suppressions-an-mcp-clients-config-supplied). The flat-json and CSV reports show the finding with `is_suppressed: true` and that justification as `suppression_justification`, and the GitLab SAST report quotes it in the finding's solution. A suppressed finding does not count toward `fail_on_findings`, as with any suppression.
- Exclusions in a scanner's own options are reported the same way rather than applied. An entry the delivered file adds to bandit's `excluded_paths`, checkov's `skip_path`, opengrep's or semgrep's `exclude`, syft's `exclude` or ferret-scan's `exclude_patterns` is removed from the option before the scanner runs, so the scanner sees those files, and each finding of that scanner the entry would have left out is suppressed and marked as above, naming the option (`scanners.bandit.options.excluded_paths entry 'tests'`). Each entry is matched as its scanner reads it: bandit's as the `**/<path>/**` glob ASH passes bandit, checkov's as checkov's own filter reads it (a regular expression found in, or a substring of, the path of the file or of a directory above it), and the others as globs matching the path or any directory in it. syft writes an SBOM, not findings, so each component a syft entry would have dropped is listed and carries an `ash:clientSuppliedExclusion` property instead. A `scanners.trivy.options.ignore_file` or `scanners.trivy-repo.options.ignore_file` from the delivered file is not passed to trivy. If it is a regular file inside the scanned tree, read without following a link, each unexpired ID in it (one per line, or the `id` and `paths` of a `.trivyignore.yaml`) suppresses and marks that scanner's findings with that rule ID; any other file, including a link to one, is not read, and the warning that says so quotes nothing from it. An entry the operator supplied (the scanner's default, the bound profile, or a file of the chain no client delivered) stays in the option and applies as before. Each moved entry is logged as a config warning and recorded in the results as a `config_warning` validation checkpoint.
- A `.semgrepignore` in the delivered tree is not honored, as in any tree: ASH runs semgrep and opengrep with `--x-ignore-semgrepignore-files` and their default exclusions, so it leaves no files out. The results name the file as client-supplied in a `config_warning` validation checkpoint. To leave files out, list them in `global_settings.ignore_paths`, where they apply marked as above.
- A profile's own `denied_paths` adds to the current default list: a list that is not one of ASH's defaults is denied together with every default entry, so listing one more field lifts nothing, and a list that holds some default entries but leaves others out still gets them, with a warning naming those it leaves out. `sandbox`, `ash_plugin_modules`, suppressions and ignore paths keep the handling above unless the profile's own list names them (the field itself, an entry above it, or one inside it, such as `/global_settings/suppressions`, `/global_settings/**` or `/sandbox/mode`); a field it names is decided by `denied_paths` like any other, as a whole, so a delivered file that sets it is refused. With `replace_default_denied_paths: true` the list is used as written instead, and each default entry it leaves out is named in a warning. `denied_value_patterns` apply everywhere. A list equal to any default ASH has shipped, as `ash config init` writes it, still counts as the default, and gets every entry of the current default list. Every `denied_paths` entry and `denied_value_patterns` key starts with `/`; one that does not would match nothing, so the config is refused as invalid.
- `global_settings.mcp` in a delivered file has no effect, since the policy never comes from one, so it is not checked.
- A file that changes a denied field is refused, not trimmed: `run_ash_scan` and `get_config` return `error_type: config_field_denied` with every such field named, `validate_config` lists each one as a `denied_by_runtime_policy` error (for content, only from a remote caller), and a workspace with such a project config fails to resolve. If the policy itself cannot be established (the bound profile is no longer registered, the server's default config cannot be loaded, or the profile has two sections that read as the same plugin), a config with a client-delivered file is refused with `error_type: config_policy_unreadable`; a scan that reads no such file is unaffected.

Its sandbox settings and plugin modules may restrict the server's but never widen them, wherever the scan target is. The server's settings are those of the profile this session bound with `select_profile`, or else `ASH_CONFIG` and the defaults (only the defaults when `ASH_CONFIG` names a file under the MCP workspace root). A file that asks for more is refused with `error_type: config_field_denied`, naming the setting; an equal or tighter value scans:

- `sandbox.network_scanners` may list only scanners the server's settings give network. A shorter list takes network away from the scanners it leaves out.
- `sandbox.extra_read_paths` may list only paths the server's settings grant.
- `sandbox.read_path_scanners` and `sandbox.env_scanners` come from the server's settings. A server config file inside a git checkout grants nothing either, so `ASH_CONFIG` has to name a file outside every checkout for its grants to apply.
- `sandbox.mode` can turn the sandbox on, but cannot turn it off or move it to another backend when the server's config sets a mode.
- `ash_plugin_modules` may add only an installed module outside the scanned tree, and never `automated_security_helper.plugin_modules.ash_aws_plugins` or `automated_security_helper.plugin_modules.ash_snyk_plugins` (or a module inside either), which send findings or source off the host with the operator's credentials. A scanner or reporter from either package that another module the file adds lists or imports is not selected unless the server's own config loads it. A plugin class a module the file adds registered is not selected by a later scan in the server that does not load that module itself, and neither is one `list_scanners` loaded. The plugin registry is the server process's, but each scan uses only the plugin modules it names: a module that one session's profile names, or that `list_scanners` loaded, adds no classes or event handlers to another scan that does not name it.

Its reporter destinations and credentials, each scanner's own config file, and which version of a tool runs are default `denied_paths` entries, so a file that sets one is refused. A config file inside the scanned tree is scanned without the first two, and may still choose a tool's version within the limits in [Settings a repository's config cannot choose](../configuration-guide.md#settings-a-repositorys-config-cannot-choose). The options a reporter from a plugin module declares in `destination_options` are not, because the module is imported after the file is checked: a file that sets one is scanned with the server's value, and a warning names it. See [Configs an MCP client delivered](../configuration-guide.md#configs-an-mcp-client-delivered).

`!ENV` reads the server's environment, so for a remote caller no config file resolves it unless the operator set the file aside: a file under `ASH_MCP_ALLOWED_CONFIG_ROOTS`, or the session's `config/ash.yaml`. That covers a file the client delivered or names, a file found in a directory it names (`get_config`'s `search_dir`), a scan target's own `.ash.yaml`, including one in a repository under `ASH_MCP_ALLOWED_ROOTS`, and every base such a file `extends`. A file that uses `!ENV`, tagged or as a plain value that starts with a `${VAR}` or `${VAR:default}` reference, is refused with a config error naming the file and the line or key. `run_ash_scan` and `get_config` return `error_type: config_env_not_resolved`, and `run_ash_scan` does not start the scan. `validate_config` lists the refusal as an error of `type` `config_env_not_resolved`, and refuses a remote caller's `config_content` that uses `!ENV` the same way. `resolve_ash_workspace` and `run_ash_workspace_scan` return `error_type: config_env_not_resolved` with exit code 3 for a project config that uses it. To use `!ENV` in a remote scan, put the setting in a registered profile or a file under `ASH_MCP_ALLOWED_CONFIG_ROOTS`. The server's own config, the file `ASH_CONFIG` names and each registered profile, resolves `!ENV` for every caller, wherever it is outside the MCP workspace root.

On stdio, where the caller launched the server and holds its environment already, only a file under the MCP workspace root is refused; a repository config the local user names or scans keeps `!ENV`. A symlink in a delivered tree counts as delivered wherever it points. With `raw`, `get_config` shows a reference in a file that may use `!ENV` as it is written.

Everything else in the file applies as usual. The registered profile the server materializes for `select_profile`, the session's `config/ash.yaml`, is the operator's and keeps its grants, as does a file under `ASH_MCP_ALLOWED_CONFIG_ROOTS` that is outside every git checkout and outside the scanned directory. A file under `ASH_MCP_ALLOWED_CONFIG_ROOTS` also resolves `!ENV` as usual. A patched profile in `client-config/ash.yaml` is the client's, and `config/ash.yaml` is the trusted base it is held to.

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
- `denied_paths: list[str]` — explicit blocks; always wins over `allowed_paths`. A profile's own list is added to the defaults below unless `replace_default_denied_paths: bool = False` is set to true, and every entry starts with `/`. The defaults are `/fail_on_findings`, `/fail_on_incomplete_scanners`, `/content_db_staleness`, `/content_db_staleness_overrides`, `/honor_ignore_files`, `/content_db_staleness_offline_image_default`, `/sandbox` and `/sandbox/**`, `/ash_plugin_modules` and `/ash_plugin_modules/**`, detect-secrets' `scan_settings/filters_used` and `scan_settings/plugins_used` (each with `/**`) and `baseline_file` under `/scanners/detect-secrets/options` (a client could otherwise turn on secret verification, which sends candidate secrets to their issuers, or make the scanner import a file), `/global_settings/ignore_paths`, `/global_settings/suppressions`, `/global_settings/mcp` and `/global_settings/mcp/**` (the policy itself), the scanner options that drop findings by rule ID, by a baseline or by category, such as `/scanners/opengrep/options/exclude_rule`, `/scanners/checkov/options/skip_frameworks` and `/scanners/*/options/offline`, each scanner's own config file and tool version, such as `/scanners/bandit/options/config_file` and `/scanners/*/options/tool_version`, the programs a scanner runs, the modules it loads, and whether it honors the ignore comments in the files it scans, such as `/scanners/actionlint/options/shellcheck`, `/scanners/trivy-repo/options/module_dir` and `/scanners/gitleaks/options/honor_inline_ignores`, `/scanners/zizmor/options/online_audits` (which lets the GitHub token reach zizmor), `/reporters/bedrock-summary-reporter/options/aws_*` and the Bedrock reporter's other destinations, such as `/reporters/bedrock-summary-reporter/options/model_id`, the whole section of each AWS reporter, `/reporters/s3/**`, `/reporters/aws-security-hub/**`, `/reporters/cloudwatch-logs/**` and `/reporters/bedrock-summary-reporter/**` (a client's `enabled: false` for one of the four AWS reporters is not refused under these entries, but it takes no effect: the profile's `enabled` applies, and a warning names the client's value. `enabled` of a reporter that writes only local files is not denied; all of them are listed in [Configs an MCP client delivered](../configuration-guide.md#configs-an-mcp-client-delivered)), the whole section of each scanner that sends data off the host: `/scanners/snyk-code/**` (the source), `/scanners/npm-audit/**` (dependency lists), `/scanners/detect-secrets/**` (candidate secrets, when verifying), `/scanners/semgrep/**` and `/scanners/opengrep/**` (usage metrics), `/scanners/trivy/**` and `/scanners/trivy-repo/**` (usage data, when telemetry is on), and `/scanners/zizmor/**` (the GitHub token, with online audits), and the archive converter's four extraction limits, `/converters/archive/options/max_members`, `max_member_bytes`, `max_total_bytes` and `max_compression_ratio`, which also refuse a write at `/converters/archive/options`, `/converters/archive` or `/converters`. Those four, the `/sandbox` and `/ash_plugin_modules` entries, the detect-secrets settings and the entries for the reporters and scanners that send data off the host are kept in any `denied_paths` a profile sets, `replace_default_denied_paths: true` included: a profile can add denials but cannot let a client raise the extraction limits, turn those settings on, or turn on or reconfigure a plugin that sends data off the host through config overrides (a workspace scan's `scanners` and `excluded_scanners` arguments, which are not overrides, can still leave a scanner out of a run, but not add one), and a whole-config write at the root pointer is refused for the same reason. A profile whose list equals a default ASH shipped earlier, as `ash config init` wrote it, gets the current default list. A `denied_paths` entry, and a `denied_value_patterns` key, matches a path whatever mix of `-` and `_` either one is spelled with, because ASH reads `bedrock-summary-reporter` and `bedrock_summary_reporter` as the same key. Under `/scanners`, `/reporters` and `/converters`, an entry naming a plugin's section also matches every other spelling ASH reads as that plugin's config: case, punctuation and the words Scanner, Reporter and Converter are ignored, so `/reporters/BedrockSummary` is refused by the `bedrock-summary-reporter` entry. A plugin segment that is a glob (`*`, `?`, `[`) stands for the keys of known plugins it matches, so `/scanners/trivy-*/options/ignore_file` also refuses `/scanners/TrivyRepo/options/ignore_file`. Known plugins are those that ship with ASH and any plugin whose section the profile already configures. Another plugin, from `ash_plugin_modules` or an installed plugin package, is covered by a glob entry only under spellings the glob matches as written; configure its section in the profile, or name it literally, to cover every spelling.
- `denied_value_patterns: dict[str, str]` — per-path regex denylist for dangerous values (e.g., scanner `extra_args` containing `--no-verify` or shell metacharacters).

Additional invariants enforced by `apply_runtime_patch`:

- `move` and `copy` ops are rejected outright (they sidestep target-path checks).
- No op may reach the reporters section of a reporter that isn't one of ASH's built-in reporters, whatever `allowed_paths` says. That covers the AWS reporters (`s3`, `aws-security-hub`, `cloudwatch-logs`, `bedrock-summary-reporter`, whose sections are also always-denied entries) and any reporter a plugin module brings. Such a reporter can send the findings off the host, to wherever its section says, with the server's credentials, so only the operator's own configuration sets that section.
  - Every spelling ASH reads as such a section counts, and so does every op type: a `test` would tell a client where the operator sends findings.
  - An `add` or `replace` of all of `/reporters`, or of the whole document, is refused when its value has such a section. A `test` or `remove` of `/reporters`, or a `test` of the whole document, is refused outright.
  - The one exception is a client's `enabled: false` of an AWS reporter, on its own. It's accepted and takes no effect, and a warning names it.
  - A client can still change a built-in reporter's section, such as `/reporters/markdown/enabled`, where the allowlist permits it.
- Patch documents larger than **64 KiB** are rejected.
- Any rejection raises `RuntimePatchDeniedError` with the offending op and the rule that fired; nothing is applied.

The full allowlist is exposed at runtime via the `ash://schema/runtime-overrides` resource so clients can introspect what is patchable before composing a patch.

### A patched value is the client's

The allowlist decides which keys a client may change. It does not make the value the client writes the operator's. So `select_profile` writes the profile after a non-empty `patch_ops`, or after `override_yaml`, to the session's `client-config/ash.yaml`, and the tools that use the session's bound config (`run_ash_scan` with no `config_path`, `resolve_ash_workspace` and `run_ash_workspace_scan`) resolve that file as a config the client delivered, as `get_config` and `validate_config` do when a client names it as `config_path`, with the rules in [Config files in delivered source](#config-files-in-delivered-source):

- A suppression or ignore path the patch added is marked `client_supplied`, and a finding it hides is reported suppressed and marked.
- An exclusion the patch added to a scanner's own options is reported, not applied. A `scanners.trivy.options.ignore_file` or `scanners.trivy-repo.options.ignore_file` it sets is not passed to trivy, and is read for marked suppressions only when it is inside the scanned tree, so a file in another checkout has no effect.
- A scanner config file the patch names (`config_file` of bandit, grype or syft) is replaced by the registered profile's, and a tool path inside the scanned tree or in a delivered file is refused as for any config.
- Its sandbox settings and plugin modules are restrict-only.

The trusted base is the profile as the operator registered it, written unpatched to the session's `config/ash.yaml`: the profile's own suppressions, sandbox grants and tool config files still apply, and only what the patch changed is the client's. The policy a patched profile is checked against is the registered profile's too, never the patched copy's.

The workspace tools' `config_overrides` get the same rules. An override the allowlist accepts changes each project's config, and what it sets is marked, reported or confined as a patched value is.

A profile a workspace tool is given for one call (`profile`) is the operator's, and is written to a file of its own per profile, `config/call-profile-<digest>.yaml` (the first 16 hex digits of the SHA-256 of the profile name), so it leaves the session's own binding as it was.

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

The server cannot see every end: a stateless server has no session at all, and a stateful session the MCP SDK closes for being idle (after 30 minutes) sends nothing ASH observes unless a client uses its id again. So every HTTP server also sweeps the workspace root, before it answers its first request and then at most every five minutes, and removes the workspace of any session nobody used for longer than `--session-workspace-ttl` seconds (default 86400, 24 hours). Each request that names a session counts as a use. The sweep removes only directories ASH created as session workspaces, each of which carries a `.ash-mcp-session` marker file; it never removes anything else under the root, the stdio session's workspace (its own servers remove it), a symlink, or a workspace a running scan holds. A session whose scan is running, or whose tree is being changed, is skipped, not queued for removal when the scan returns, and its age is read again just before removal, so a session used meanwhile is kept. So is a session that a chunk of an upload or a profile selection is writing; one that arrives while the sweep removes its session is refused with `error_type` `session_workspace_busy`, and is sent again (an upload from its first chunk), since the session's state is gone once the removal is done. That hold is the server's own: a server sharing the workspace root does not see a write in progress on another server. Give `ASH_MCP_WORKSPACE_ROOT` a directory that belongs to ASH alone anyway: session workspaces created before the marker existed are never swept. Servers that share one `ASH_MCP_WORKSPACE_ROOT` sweep each other's idle workspaces by the same rule, and each running scan holds a locked entry under `<root>/.ash-mcp-scans/<session id>/` so that no server's sweep removes a workspace another server is scanning. Those locks are file locks: a filesystem that does not share them between hosts does not carry that protection. The request that starts a sweep is answered once the sweep finishes; requests that arrive while it runs are not held for it.

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
