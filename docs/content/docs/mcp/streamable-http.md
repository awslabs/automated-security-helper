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

### Selecting a profile

`mcp__ash__select_profile` binds a registered profile to the calling session. Three modes:

1. **Static.** `select_profile(profile_name="default")` — bind the profile as-is.
2. **Inherit-and-patch.** `select_profile(profile_name="default", patch_ops=[...])` — apply a JSON-Patch document, each op checked against the runtime-override allowlist first; a rejected op fails the whole call without mutating the session config. See [Runtime config overrides](#runtime-config-overrides).
3. **Full override.** `select_profile(profile_name="default", override_yaml="...")` — replace the resolved config with a client-supplied YAML string, validated through `AshConfig` and held to the same runtime-override allowlist as `patch_ops`. See [Overrides are patches](#overrides-are-patches).

`patch_ops` and `override_yaml` are mutually exclusive, and the parameter is `profile_name` — a profile must be named in every mode, including override.

Every later call in the session that does not name a config of its own runs under the bound one: `run_ash_scan`, `resolve_ash_workspace` and `run_ash_workspace_scan`. A `config_path` passed on the call still wins, because naming one is the more specific statement. In workspace mode the bound profile is the operator's config for every project: each field the profile sets is final, a project's own `.ash.yaml` fills only the fields it leaves unset, and a project with no `.ash.yaml` runs under the bound config alone. A copy the client patched is not layered over a project's own config. See [Which config each project gets](workspace-mode.md#which-config-each-project-gets).

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

### Config files in delivered source

A delivered tree can carry its own `.ash.yaml`, and a client can name any file in its session workspace as `run_ash_scan`'s `config_path`. Such a file was written by the client, not the operator. So was any other file a client names as `config_path` (or to `get_config` and `validate_config`), unless it is in a directory `ASH_MCP_ALLOWED_CONFIG_ROOTS` names or in the session's own `config/` directory (a path in another session's workspace is refused): a config in another checkout the server may scan is that checkout's, and the operator let the server scan it, not take its settings. A path is judged where it sits, at each symlink on the way, and by the file it reaches, so a link a client delivered is the client's wherever it points, and so is a file reached through a linked directory such as `.ash`, and every base such a file extends. A config named through a link in a delivered tree may extend only files in that tree. A refusal names the path the client used, not the file a link reaches, and a validation error for such a file names the file and where each problem is without quoting the values in it. A scan with no `config_path` reads the `.ash.yaml` it finds in the target only when the file it resolves to is in a directory the caller may read config from, the check `get_config` applies to a file it finds: one that links elsewhere is refused with `error_type: config_input_not_permitted` before it is read. The workspace tools check each project's `.ash.yaml` the same way, and refuse with exit code 4. The profile `select_profile` writes after a client's `patch_ops` or `override_yaml`, `client-config/ash.yaml`, is the client's too, and so are the workspace tools' `config_overrides` (see [A patched value is the client's](#a-patched-value-is-the-clients)). Everything below applies to all of these.

First, it may not change a field the session's runtime-override policy denies. `denied_paths` and `denied_value_patterns` apply to every file of the config's chain that a client delivered, as resolution parsed it, matched as for `patch_ops` (either `-` or `_`, every spelling of a plugin's section, globs). They apply whether or not runtime overrides are enabled, since a config file is not an override. Only what the file changes counts: a value equal to the server's at the same key (an `ash config init` file writes the defaults) is accepted, while every op in the file's `patch` is checked as written. A `denied_value_patterns` entry also matches mapping keys, and refuses a matching key in a delivered file even where the server's config has the same key; only the session's patched profile, `client-config/ash.yaml`, which repeats the registered profile with the client's checked patch applied, is not refused for a key the server's config has.

- The policy is the registered profile the session bound with `select_profile`, or else the one in `ASH_CONFIG` (the defaults when it sets none, or when `ASH_CONFIG` names a file under the MCP workspace root, which is a client's; ASH logs a warning then). It is never read from the session's copy of the profile, which a client's `patch_ops` produced, and `/global_settings/mcp` is a default `denied_paths` entry, so a client cannot change the policy.
- Under the default `denied_paths`, `sandbox` and `ash_plugin_modules` are checked against the server's own settings instead (below), and a delivered tree's own `global_settings.suppressions` and `global_settings.ignore_paths` apply, as they do on the CLI. Each suppression and ignore path the operator did not supply is marked `client_supplied: true` in the results' config, and a SARIF suppression from one carries `properties.clientSupplied`. Scanners and converters skip only the operator's ignore paths, so the files under a client-supplied ignore path are still scanned, and each finding there is kept as a suppressed result marked the same way rather than dropped. The results show what the client's config hid.
- What the marking looks like: in SARIF the suppression has a `justification` that starts with `(ASH, client-supplied config)` and names the entry, and `properties.clientSupplied: true`; its `kind` is `inSource` for a suppression entry and `external` for an ignore path or a scanner exclusion (below). See [Suppressions an MCP client's config supplied](../suppressions.md#suppressions-an-mcp-clients-config-supplied). The flat-json and CSV reports show the finding with `is_suppressed: true` and that justification as `suppression_justification`, and the GitLab SAST report quotes it in the finding's solution. A suppressed finding does not count toward `fail_on_findings`, as with any suppression.
- Exclusions in a scanner's own options are reported the same way rather than applied. An entry the delivered file adds to bandit's `excluded_paths`, checkov's `skip_path`, opengrep's or semgrep's `exclude`, syft's `exclude` or ferret-scan's `exclude_patterns` is removed from the option before the scanner runs, so the scanner sees those files, and each finding of that scanner the entry would have left out is suppressed and marked as above, naming the option (`scanners.bandit.options.excluded_paths entry 'tests'`). Each entry is matched as its scanner reads it: bandit's as the `**/<path>/**` glob ASH passes bandit, checkov's as checkov's own filter reads it (a regular expression found in, or a substring of, the path of the file or of a directory above it), and the others as globs matching the path or any directory in it. syft writes an SBOM, not findings, so each component a syft entry would have dropped is listed and carries an `ash:clientSuppliedExclusion` property instead. A `scanners.trivy-repo.options.ignore_file` from the delivered file is not passed to trivy. If it is a regular file inside the scanned tree, read without following a link, each unexpired ID in it (one per line, or the `id` and `paths` of a `.trivyignore.yaml`) suppresses and marks the trivy findings with that rule ID; any other file, including a link to one, is not read, and the warning that says so quotes nothing from it. An entry the operator supplied (the scanner's default, the bound profile, or a file of the chain no client delivered) stays in the option and applies as before. Each moved entry is logged as a config warning and recorded in the results as a `config_warning` validation checkpoint.
- A `.semgrepignore` in the delivered tree is not honored, as in any tree: ASH runs semgrep and opengrep with `--x-ignore-semgrepignore-files` and their default exclusions, so it leaves no files out. The results name the file as client-supplied in a `config_warning` validation checkpoint. To leave files out, list them in `global_settings.ignore_paths`, where they apply marked as above.
- A profile's own `denied_paths` adds to the current default list: a list that is not one of ASH's defaults is denied together with every default entry, so listing one more field lifts nothing, and a list that holds some default entries but leaves others out still gets them, with a warning naming those it leaves out. `sandbox`, `ash_plugin_modules`, suppressions and ignore paths keep the handling above unless the profile's own list names them (the field itself, an entry above it, or one inside it, such as `/global_settings/suppressions`, `/global_settings/**` or `/sandbox/mode`); a field it names is decided by `denied_paths` like any other, as a whole, so a delivered file that sets it is refused. With `replace_default_denied_paths: true` the list is used as written instead, and each default entry it leaves out is named in a warning. `denied_value_patterns` apply everywhere. A list equal to any default ASH has shipped, as `ash config init` writes it, still counts as the default, and gets every entry of the current default list. Every `denied_paths` entry and `denied_value_patterns` key starts with `/`; one that does not would match nothing, so the config is refused as invalid.
- `global_settings.mcp` in a delivered file has no effect, since the policy never comes from one, so it is not checked.
- A file that changes a denied field is refused, not trimmed: `run_ash_scan` and `get_config` return `error_type: config_field_denied` with every such field named, `validate_config` lists each one as a `denied_by_runtime_policy` error (for content, only from a remote caller), and a workspace with such a project config fails to resolve. If the policy itself cannot be established (the bound profile is no longer registered, the server's default config cannot be loaded, or the profile has two sections that read as the same plugin), a config with a client-delivered file is refused with `error_type: config_policy_unreadable`; a scan that reads no such file is unaffected.

Delivering source to a session while one of its scans runs is refused, so the files a scan checked are the files it reads. Both tools return `success: false` and `error_type: SourceDeliveryBusyError`. `set_source_git` sets `error` to `a scan of this session is running; deliver the source after it finishes`, and `set_source_zip_finalize` sets it to `Error finalizing source upload: a scan of this session is running; deliver the source after it finishes`. `set_source_zip_chunk` is not refused, so an upload can be sent while the scan runs and finalized after it ends.

Its sandbox settings and plugin modules may restrict the server's but never widen them, wherever the scan target is. The server's settings are those of the profile this session bound with `select_profile`, or else `ASH_CONFIG` and the defaults (only the defaults when `ASH_CONFIG` names a file under the MCP workspace root). A file that asks for more is refused with `error_type: config_field_denied`, naming the setting; an equal or tighter value scans:

- `sandbox.network_scanners` may list only scanners the server's settings give network. A shorter list takes network away from the scanners it leaves out.
- `sandbox.extra_read_paths` may list only paths the server's settings grant.
- `sandbox.mode` can turn the sandbox on, but cannot turn it off or move it to another backend when the server's config sets a mode.
- `ash_plugin_modules` may add only an installed module outside the scanned tree, and never `automated_security_helper.plugin_modules.ash_aws_plugins` or `automated_security_helper.plugin_modules.ash_snyk_plugins` (or a module inside either), which send findings or source off the host with the operator's credentials. A scanner or reporter from either package that another module the file adds lists or imports is not selected unless the server's own config loads it.

Its reporter destinations and credentials, each scanner's own config file, and which version of a tool runs are default `denied_paths` entries, so a file that sets one is refused. A config file inside the scanned tree is scanned without the first two, and may still choose a tool's version within the limits in [Settings a repository's config cannot choose](../configuration-guide.md#settings-a-repositorys-config-cannot-choose). The options a reporter from a plugin module declares in `destination_options` are not, because the module is imported after the file is checked: a file that sets one is scanned with the server's value, and a warning names it. See [Configs an MCP client delivered](../configuration-guide.md#configs-an-mcp-client-delivered).

`!ENV` reads the server's environment, so for a remote caller no config file resolves it unless the operator set the file aside: a file under `ASH_MCP_ALLOWED_CONFIG_ROOTS`, or the session's `config/ash.yaml`. That covers a file the client delivered or names, a file found in a directory it names (`get_config`'s `search_dir`), a scan target's own `.ash.yaml`, including one in a repository under `ASH_MCP_ALLOWED_ROOTS`, and every base such a file `extends`. A file that uses `!ENV`, tagged or as a plain value that starts with a `${VAR}` or `${VAR:default}` reference, is refused with a config error naming the file and the line or key. `run_ash_scan` and `get_config` return `error_type: config_env_not_resolved`, and `run_ash_scan` does not start the scan. `validate_config` lists the refusal as an error of `type` `config_env_not_resolved`, and refuses a remote caller's `config_content` that uses `!ENV` the same way. `resolve_ash_workspace` and `run_ash_workspace_scan` return `error_type: config_env_not_resolved` with exit code 3 for a project config that uses it. To use `!ENV` in a remote scan, put the setting in a registered profile or a file under `ASH_MCP_ALLOWED_CONFIG_ROOTS`. The server's own config, the file `ASH_CONFIG` names and each registered profile, resolves `!ENV` for every caller, wherever it is outside the MCP workspace root.

On stdio, where the caller launched the server and holds its environment already, only a file under the MCP workspace root is refused; a repository config the local user names or scans keeps `!ENV`. A symlink in a delivered tree counts as delivered wherever it points. With `raw`, `get_config` shows a reference in a file that may use `!ENV` as it is written.

Everything else in the file applies as usual. The registered profile the server materializes for `select_profile`, the session's `config/ash.yaml`, is the operator's and keeps its grants, as does a file under `ASH_MCP_ALLOWED_CONFIG_ROOTS`, which also resolves `!ENV` as usual. A patched profile in `client-config/ash.yaml` is the client's, and `config/ash.yaml` is the trusted base it is held to.

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
- `denied_paths: list[str]` — explicit blocks; always wins over `allowed_paths`. A profile's own list is added to the defaults below unless `replace_default_denied_paths: bool = False` is set to true, and every entry starts with `/`. The defaults are `/fail_on_findings`, `/fail_on_incomplete_scanners`, `/content_db_staleness`, `/content_db_staleness_overrides`, `/sandbox` and `/sandbox/**`, `/ash_plugin_modules` and `/ash_plugin_modules/**`, `/global_settings/ignore_paths`, `/global_settings/suppressions`, `/global_settings/mcp` and `/global_settings/mcp/**` (the policy itself), the scanner options that drop findings by rule ID, by a baseline or by category, such as `/scanners/opengrep/options/exclude_rule`, `/scanners/checkov/options/skip_frameworks` and `/scanners/*/options/offline`, each scanner's own config file and tool version, such as `/scanners/bandit/options/config_file` and `/scanners/*/options/tool_version`, `/reporters/bedrock-summary-reporter/options/aws_*` and the Bedrock reporter's other destinations, such as `/reporters/bedrock-summary-reporter/options/model_id`, and the whole section of each AWS reporter, `/reporters/s3/**`, `/reporters/aws-security-hub/**`, `/reporters/cloudwatch-logs/**` and `/reporters/bedrock-summary-reporter/**` (a client's `enabled: false` for one of the four AWS reporters is accepted under these entries, since it only sends less, and `enabled` of a reporter that writes only local files is not denied; all of them are listed in [Configs an MCP client delivered](../configuration-guide.md#configs-an-mcp-client-delivered)). A profile whose list equals a default ASH shipped earlier, as `ash config init` wrote it, gets the current default list. A `denied_paths` entry, and a `denied_value_patterns` key, matches a path whatever mix of `-` and `_` either one is spelled with, because ASH reads `bedrock-summary-reporter` and `bedrock_summary_reporter` as the same key. Under `/scanners`, `/reporters` and `/converters`, an entry naming a plugin's section also matches every other spelling ASH reads as that plugin's config: case, punctuation and the words Scanner, Reporter and Converter are ignored, so `/reporters/BedrockSummary` is refused by the `bedrock-summary-reporter` entry. A plugin segment that is a glob (`*`, `?`, `[`) stands for the keys of known plugins it matches, so `/scanners/trivy-*/options/ignore_file` also refuses `/scanners/TrivyRepo/options/ignore_file`. Known plugins are those that ship with ASH and any plugin whose section the profile already configures. Another plugin, from `ash_plugin_modules` or an installed plugin package, is covered by a glob entry only under spellings the glob matches as written; configure its section in the profile, or name it literally, to cover every spelling.
- `denied_value_patterns: dict[str, str]` — per-path regex denylist for dangerous values (e.g., scanner `extra_args` containing `--no-verify` or shell metacharacters).

Additional invariants enforced by `apply_runtime_patch`:

- `move` and `copy` ops are rejected outright (they sidestep target-path checks).
- Patch documents larger than **64 KiB** are rejected.
- Any rejection raises `RuntimePatchDeniedError` with the offending op and the rule that fired; nothing is applied.

The full allowlist is exposed at runtime via the `ash://schema/runtime-overrides` resource so clients can introspect what is patchable before composing a patch.

### A patched value is the client's

The allowlist decides which keys a client may change. It does not make the value the client writes the operator's. So `select_profile` writes the profile after a non-empty `patch_ops`, or after `override_yaml`, to the session's `client-config/ash.yaml`, and the tools that use the session's bound config (`run_ash_scan` with no `config_path`, `resolve_ash_workspace` and `run_ash_workspace_scan`) resolve that file as a config the client delivered, as `get_config` and `validate_config` do when a client names it as `config_path`, with the rules in [Config files in delivered source](#config-files-in-delivered-source):

- A suppression or ignore path the patch added is marked `client_supplied`, and a finding it hides is reported suppressed and marked.
- An exclusion the patch added to a scanner's own options is reported, not applied. A `scanners.trivy-repo.options.ignore_file` it sets is not passed to trivy, and is read for marked suppressions only when it is inside the scanned tree, so a file in another checkout has no effect.
- A scanner config file the patch names (`config_file` of bandit, grype or syft) is replaced by the registered profile's, and a tool path inside the scanned tree or in a delivered file is refused as for any config.
- Its sandbox settings and plugin modules are restrict-only.

The trusted base is the profile as the operator registered it, written unpatched to the session's `config/ash.yaml`: the profile's own suppressions, sandbox grants and tool config files still apply, and only what the patch changed is the client's. The policy a patched profile is checked against is the registered profile's too, never the patched copy's.

The workspace tools' `config_overrides` get the same rules. An override the allowlist accepts changes each project's config, and what it sets is marked, reported or confined as a patched value is.

A profile a workspace tool is given for one call (`profile`) is the operator's, and is written to `config/call-profile.yaml`, so it leaves the session's own binding as it was.

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
- **The runtime-override allowlist defaults to disabled.** A profile must explicitly set `mcp.runtime_overrides.enabled: true` and enumerate `allowed_paths` for any client patching to succeed, through `patch_ops` or `override_yaml`. Leaving it off is the safe default — clients can still pick profiles, just not modify them.
- **Source-upload limits are per-session, not per-tenant.** A misbehaving tenant can still consume their session quota. Pair the transport with upstream rate limits if untrusted clients can connect.
- **Workspaces are wiped on disconnect.** Don't rely on session-resident state to survive reconnects; persisted state across server restarts is explicitly out of scope (Track 10.8).

## Cross-references

- Local single-user MCP setup: [ASH MCP Server Guide](../mcp-server-guide.md)
- Performance tuning under concurrent sessions: [MCP Server Performance and Scalability](../mcp-performance-scalability.md)
- Full tool inventory: [MCP Tools Reference](../MCP-TOOLS-REFERENCE.md)
- Track 10 spec: `tasks/todo.md`, sections 10.1 through 10.9
