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
  --auth-header-name x-ash-token \
  --auth-header-value SECRET \
  --profile default=/etc/ash/default.yaml \
  --profile strict=/etc/ash/strict.yaml
```

Flags:

- `--transport streamable-http` — selects the streamable-HTTP transport. Other accepted values: `stdio` (default) and `sse` (legacy, not covered here).
- `--host` — bind address. Use `127.0.0.1` for loopback-only deployments and `0.0.0.0` when fronted by a reverse proxy.
- `--port` — TCP port. Defaults are deliberately omitted; pick an explicit port that matches your proxy/firewall config.
- `--mount-path` — path under which the FastMCP app is mounted. Defaults to `/mcp`. Clients must connect to `http(s)://host:port<mount-path>`.
- `--auth-header-name` / `--auth-header-value` — single-tenant header gate. Connections missing this header (or carrying a wrong value) are rejected before any tool dispatch. See [Auth](#auth).
- `--profile NAME=path/to/ash.yaml` — register a config profile under `NAME`. Repeatable. The YAML is loaded and validated through `AshConfig.from_file` at startup; bad profiles fail fast and the server refuses to start. See [Config profiles](#config-profiles).

The server logs the bound address and the registered profile names on startup. It does not log header values or profile contents.

## Config profiles

A profile is a named, pre-validated `AshConfig` registered at server startup via `--profile NAME=path/yaml`. Profiles are immutable for the lifetime of the process. Clients select a profile per session and may optionally patch it within the runtime-override allowlist (Track 10.3).

Discover the profiles a deployment offers with:

```python
profiles = await mcp__ash__list_profiles()
# -> {"profiles": [{"name": "default", "path_sha256": "..."}], "count": 1}
```

Path hashes let clients detect that the operator rotated a profile file underneath them; the paths and the profile contents themselves are never returned. An empty list means the operator registered no profiles, not that the call failed.

### Selecting a profile is not available yet

`mcp__ash__select_profile` is **not currently a callable tool.** The three selection modes below are implemented and tested at the function level, and the runtime-override allowlist that guards them is enforced, but the tool is not registered and no client can invoke it.

The reason is worth being precise about, because the function working is not the same as the feature working. Selecting a profile resolves a config and binds it to the session, and nothing in ASH reads that binding: the scan entry point takes a config *path*, not a resolved config object, so a bound config has nowhere to go. Registering the tool in that state would give you a call that returns success and changes nothing about the scan that follows. Until the config is threaded through to the scan, the honest surface is one that does not offer it.

Use `--profile NAME=path` at startup and `config_path` per call in the meantime. When it lands, the three modes will be:

1. **Static.** `select_profile(profile_name="default")` — bind the profile as-is.
2. **Inherit-and-patch.** `select_profile(profile_name="default", patch_ops=[...])` — apply a JSON-Patch document, each op checked against the runtime-override allowlist first; a rejected op fails the whole call without mutating the session config. See [Runtime config overrides](#runtime-config-overrides).
3. **Full override.** `select_profile(profile_name="default", override_yaml="...")` — replace the resolved config with a client-supplied YAML string, still validated through `AshConfig`.

Note that `patch_ops` and `override_yaml` are mutually exclusive, and that the parameter is `profile_name` — a profile must be named in every mode, including override.

## Source delivery

A streamable-HTTP client typically does not share a filesystem with the server, so the source tree to scan must arrive over the protocol. ASH offers two paths (Track 10.2).

Both land the tree in the calling session's own workspace and record it as that session's `source_dir`. The session is taken from the `Mcp-Session-Id` request header, not from a tool argument — so a client cannot name someone else's session. On stdio there is no header and a single client, so everything resolves to one default session.

Having delivered a tree, call `run_ash_scan` with **no** `source_dir`:

```python
result = await mcp__ash__set_source_zip_finalize(upload_id=..., expected_sha256=...)
await mcp__ash__run_ash_scan()
```

An omitted `source_dir` means "the tree I just gave you" whenever the session has one. Passing a path explicitly still works and still has to satisfy [the root policy](#restricting-scan-targets). Naming a path you never delivered is how you scan a repository the operator mounted into the server, not one you uploaded.

The no-argument form depends on the session id being the same on both calls, which holds whenever the client's own connection carries a stable `Mcp-Session-Id`. When it does not hold, the call is **refused rather than redirected**:

| Situation | Result |
| --- | --- |
| This session delivered a tree | it is scanned |
| No session header at all (stdio) and nothing delivered | the working directory is scanned, as it always has been |
| This session delivered nothing, another session did | refused, `error_type: session_source_mismatch` |
| This session delivered nothing, nor has any other | refused, `error_type: no_source_delivered` |

The two refusals exist because the alternative is worse than an error. Falling back to the server's working directory on a network transport scans a tree that holds none of the caller's code, completes normally, and reports no findings — a result a caller cannot distinguish from a clean repository. A scan that examined nothing and reads as clean is the failure mode this whole surface is meant to avoid, so the ambiguous cases say so instead. The mismatch error reports how many *other* sessions hold source, never which, so it diagnoses a rotating session id without disclosing one caller's session to another.

This matters most on Bedrock AgentCore Runtime, where it is **not** established that the id is stable: that platform mints its own session ids and, measured against live runtimes, returns a fresh one on nearly every response while honoring only the id from `initialize`. What the container sees per request could not be determined from outside. On that target, capture the `source_dir` the delivery tool returns and pass it back to `run_ash_scan(source_dir=...)`; see [deploy/cdk/README.md](../../../../deploy/cdk/README.md) for the detail and for a two-call probe that settles the question.

### Git ref

```python
await mcp__ash__set_source_git(
    url="git@github.com:org/repo.git",
    ref="main",
    ssh_key_id="ash-ci-deploy-key",
    depth=1,
)
```

`ssh_key_id` is a **server-side keyring lookup** — the operator pre-registers SSH keys on the host and the client only references them by name. Raw private keys are never accepted over the wire. `depth=1` is the default; increase only when the scan needs older revisions.

The cloned working tree lands under the per-session workspace and becomes the session's `source_dir`.

### Chunked zip upload

For agents that don't have git access to the source, upload the tree as a zip in ≤1 MiB chunks, then finalize:

```python
import base64, hashlib

upload_id = "session-upload-1"
zip_bytes = open("repo.zip", "rb").read()
sha = hashlib.sha256(zip_bytes).hexdigest()

# Send in 1 MiB chunks
chunk_size = 1024 * 1024
chunks = [zip_bytes[i:i+chunk_size] for i in range(0, len(zip_bytes), chunk_size)]
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
- `denied_paths: list[str]` — explicit blocks; always wins over `allowed_paths`. Defaults seed `/global_settings/fail_fast`, `/global_settings/ignore_paths`, `/scanners/bedrock_summary/options/aws_*`, and `/reporters/bedrock_summary/**`.
- `denied_value_patterns: dict[str, str]` — per-path regex denylist for dangerous values (e.g., scanner `extra_args` containing `--no-verify` or shell metacharacters).

Additional invariants enforced by `apply_runtime_patch`:

- `move` and `copy` ops are rejected outright (they sidestep target-path checks).
- Patch documents larger than **64 KiB** are rejected.
- Any rejection raises `RuntimePatchDeniedError` with the offending op and the rule that fired; nothing is applied.

The full allowlist is exposed at runtime via the `ash://schema/runtime-overrides` resource so clients can introspect what is patchable before composing a patch.

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

Workspaces live under `ASH_MCP_WORKSPACE_ROOT` (defaults to `$XDG_CACHE_HOME/ash-mcp/<session_id>/`). On disconnect, the workspace is `rmtree`'d and the session entry is dropped — no state survives a disconnect.

Concurrency:

- Scans **within** a single session are serialized; one client cannot launch parallel scans against itself.
- Scans **across** sessions run in parallel under the existing `scan_registry` semantics — a noisy session can't block another tenant's scan.

## Auth

The streamable-HTTP transport ships with one built-in gate: a static header check via `--auth-header-name` / `--auth-header-value`. Connections without the configured header (or with the wrong value) are rejected before any tool dispatches.

This is sufficient for **single-tenant** deploys where one trusted client owns the server. For multi-tenant deployments:

- Run ASH behind a reverse proxy (nginx, traefik, an API gateway) that terminates TLS and authenticates the caller.
- Have the proxy inject the static `--auth-header-value` so ASH only accepts traffic that has already been authenticated upstream.
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
    --profile default=/etc/ash/default.yaml \
    --profile strict=/etc/ash/strict.yaml \
    --auth-header-name x-ash-token \
    --auth-header-value "$ASH_TOKEN"
```

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
      - --profile=default=/etc/ash/default.yaml
      - --profile=strict=/etc/ash/strict.yaml
      - --auth-header-name=x-ash-token
      - --auth-header-value=${ASH_TOKEN}
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

The nginx config is responsible for TLS termination and for injecting `x-ash-token: ${ASH_TOKEN}` on every request that has already authenticated against the tenant's identity provider.

## Security note

The streamable-HTTP transport puts the MCP server on the network. A few invariants to keep in mind:

- **The auth header is the only built-in gate.** There is no per-tool RBAC, no per-tenant rate limiting, no audit log beyond standard logging. Anything more sophisticated belongs in a fronting proxy.
- **Set `ASH_MCP_ALLOWED_ROOTS`.** Scan targets are confined to the roots it names, plus the per-session workspace. The fallback when it is unset refuses only a short list of system directories and leaves the rest of the server's filesystem available as a scan target, so on a network-reachable deployment it is not a substitute for naming the roots yourself. See [Restricting scan targets](#restricting-scan-targets).
- **Always run behind TLS in production.** ASH does not terminate TLS itself. Use nginx, traefik, an API gateway, or a service mesh sidecar.
- **The runtime-override allowlist defaults to disabled.** A profile must explicitly set `mcp.runtime_overrides.enabled: true` and enumerate `allowed_paths` for any client patching to succeed. Leaving it off is the safe default — clients can still pick profiles, just not modify them.
- **Source-upload limits are per-session, not per-tenant.** A misbehaving tenant can still consume their session quota. Pair the transport with upstream rate limits if untrusted clients can connect.
- **Workspaces are wiped on disconnect.** Don't rely on session-resident state to survive reconnects; persisted state across server restarts is explicitly out of scope (Track 10.8).

## Cross-references

- Local single-user MCP setup: [ASH MCP Server Guide](../mcp-server-guide.md)
- Performance tuning under concurrent sessions: [MCP Server Performance and Scalability](../mcp-performance-scalability.md)
- Full tool inventory: [MCP Tools Reference](../MCP-TOOLS-REFERENCE.md)
- Track 10 spec: `tasks/todo.md`, sections 10.1 through 10.9
