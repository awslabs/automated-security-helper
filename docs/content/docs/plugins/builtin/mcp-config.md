# MCP server config scanning

ASH reads the MCP server configuration files that live in a repository (`.mcp.json`, `.cursor/mcp.json`, `.codex/config.toml` and the other formats below) and checks each server entry against a set of policy options. A second, separate piece, the MCP config converter, writes each server that starts a local command as a small shell script, so the script scanners ASH already runs (semgrep and opengrep) read the command the config would launch. Findings from those scanners in a generated script are moved back to the entry in the original config file.

Neither piece runs, resolves or fetches anything a config names. The scanner reads the files in process, and the converter only writes text files. Both work offline, need no tool installed, and run under `--python-only`.

## Config files that are read

A file is read when its repo-relative path is exactly one of these. A file that is none of them is never guessed at.

| Format | Path | Server table |
| --- | --- | --- |
| Claude Code (project scope), GitHub Copilot | `.mcp.json` | `mcpServers` |
| Cursor | `.cursor/mcp.json` | `mcpServers` |
| VS Code | `.vscode/mcp.json` | `servers` |
| Gemini CLI | `.gemini/settings.json` | `mcpServers` (`url` is SSE, `httpUrl` is streamable HTTP) |
| Claude Desktop | `claude_desktop_config.json`, in any directory | `mcpServers` |
| Amazon Q Developer | `.amazonq/mcp.json` | `mcpServers` |
| Roo Code | `.roo/mcp.json` | `mcpServers` |
| Kiro | `.kiro/settings/mcp.json` | `mcpServers` |
| Devin | `.devin/mcp_config.json` | `mcpServers` |
| Codex CLI | `.codex/config.toml` | `mcp_servers` (TOML) |

Each entry is read into one normalized form: the server name, whether it starts a local command (stdio) or connects to a URL (remote), the command and arguments, the `env` table, the URL and headers, and the fields that approve tool calls without asking. An entry that spells both a command and a URL gets both treatments: its command goes through the command checks and the converter, and its URL through the URL checks, so a stray or decoy `url` key beside a command exempts nothing. A file that does not parse, or is larger than the size limit, is reported in the scan's notes and skipped; no finding quotes its content.

`.claude/settings.json` is not read. It is a policy file for Claude Code, and an `mcpServers` block in it is not a documented way to define servers. Zed's project-level `context_servers` file is not read either, because its project-file support is not confirmed.

## Enabling it

The scanner is `mcp-config` and is enabled by default. `scanners.mcp-config.enabled: false` turns it off, and `--scanners` and `--exclude-scanners` select it like any other scanner. A repository with none of the files above gives the scanner nothing to check.

The converter is `mcp_config` and is enabled by default. `converters.mcp_config.enabled: false` turns it off. It has no options of its own.

## Scanner options

```yaml
scanners:
  mcp-config:
    enabled: true
    options:
      forbid_privilege_escalation: true
      forbid_unpinned_runners: true
      forbid_auto_approval: true
      flag_env_secrets: true
      require_local: false
      remote_url_prefixes: []
      allowed_command_prefixes: []
```

<!-- doctest: options of=scanners.mcp-config -->
| Option | Default | Severity | What it flags |
| --- | --- | --- | --- |
| `forbid_privilege_escalation` | `true` | HIGH | `sudo`, `doas`, `su` or `pkexec` as the command, or as a whole argument, of any entry that declares a command. A word of a shell string handed to `-c` counts. `pseudo` does not. |
| `forbid_auto_approval` | `true` | HIGH | A setting that approves tool calls without asking: Gemini `trust: true`, a non-empty Kiro `autoApprove`, a non-empty Roo `alwaysAllow`, Codex `approval_mode` of `auto` or `full-auto`. |
| `forbid_unpinned_runners` | `true` | MEDIUM | `npx`, `bunx`, `pnpm dlx`, `pnpx` or `uvx` started with a package that has no exact version. `pkg@1.2.3` and `pkg==1.2.3` are pinned; `pkg`, `pkg@latest` and ranges are not. |
| `require_local` | `false` | MEDIUM | A remote entry (`url`, `httpUrl` or `serverUrl`) whose host is not loopback. `localhost`, `127.0.0.0/8` and `::1` count as local, however the IPv6 address is written. |
| `remote_url_prefixes` | `[]` | MEDIUM | With a list: a remote URL that does not start with a listed prefix, and a remote URL that is not loopback and is not `https`. An empty list turns both checks off. |
| `allowed_command_prefixes` | `[]` | MEDIUM | With a list: a declared command that is not a path starting with a listed prefix. A bare name such as `npx` is flagged. An empty list turns the check off. |
| `flag_env_secrets` | `true` | LOW | A literal value in an `env` entry whose name says key, token, secret or password. A reference such as `${NAME}` is fine. The value is never written into the finding. |

The three `forbid_*` checks are on by default because each is a hazard the MCP specification and the clients' own documentation name, and each fires on an exact whole-word or exact-flag match, so a clean repository stays quiet. The prefix policies depend on the site, so they stay off until configured. An unknown option name is refused, and an error message never repeats a configured value.

Prefix matching is on path and URL boundaries. `/opt/mcp` allows `/opt/mcp/server` and not `/opt/mcp-evil/server`. `https://api.example.com` allows `https://api.example.com/v1` and not `https://api.example.com.evil.test`. A command path is normalized before it is compared, so `/opt/mcp/../../bin/sh` is read as `/bin/sh`.

A finding's rule id is one of `MCP-PRIVILEGE-ESCALATION`, `MCP-AUTO-APPROVAL`, `MCP-UNPINNED-RUNNER`, `MCP-REMOTE-NOT-LOCAL`, `MCP-REMOTE-URL-PREFIX`, `MCP-REMOTE-URL-INSECURE`, `MCP-COMMAND-PREFIX` or `MCP-ENV-SECRET`. Its file, line and column are the position of the field in the original config file.

### Example: a team policy

```yaml
scanners:
  mcp-config:
    options:
      require_local: false
      remote_url_prefixes:
        - https://mcp.example.com/
      allowed_command_prefixes:
        - /usr/local/bin/
        - /opt/mcp/
```

With this, a remote server must live under `https://mcp.example.com/` and be reached over https, and a local server must be started from one of the two directories.

## What the converter writes

For each entry that declares a command the converter writes one script and one sidecar into its work directory, under a directory named for the config file (`.cursor/mcp.json` becomes `cursor__mcp.json`). This `.mcp.json` starts one server through `sudo`:

<!-- doctest: config kind=mcp-client save-as=.mcp.json -->
```json
{
  "mcpServers": {
    "elevated": {
      "command": "sudo",
      "args": ["/usr/local/bin/mcp-files", "--root", "/srv/data"]
    }
  }
}
```

The converter writes this script for it:

<!-- doctest: illustrative reason="the script the converter writes for the entry above; running it would run sudo" -->
```sh
#!/bin/sh
# ash-mcp-span: {"source":".mcp.json","pointer":"/mcpServers/elevated","line":3,"col":17}
exec 'sudo' '/usr/local/bin/mcp-files' '--root' '/srv/data'
```

- The command line is one logical line: the `env` assignments, then `exec`, then the command and each argument. Every value is single-quoted, and an embedded single quote is written with the `'"'"'` idiom. A newline or other control character is written as an ANSI-C `$'...'` word, so one config token is always one script token.
- An entry with no command writes no script: there is nothing in it to run, and the policy scanner covers its URL. An entry with both a command and a URL writes its script like any other.
- `<script>.spanmap.json` sits beside each script. It has one row for every script line, with the original file, the JSON pointer of the entry, and the entry's start and end line and column.
- ASH scans the converted directory with the same scanners it runs on the source tree, so semgrep and opengrep read the scripts. The bundled stargrep rule `sudo-in-shell-script` flags a whole-word `sudo` in a shell script outside a comment, which is how a server started through sudo is reported by those two scanners as well as by the policy scanner.

## Where a finding in a generated script lands

After the scanners finish, a finding located in a script that has a sidecar is moved to the original config file. Its file becomes the config file, its region the start and end line and column of the server entry, and it carries the property `converted_from` with the generated script's path. It no longer carries a converted path, so the finding is identified by the config file and its line, and a suppression written against `.mcp.json` matches it. The generated script's path is part of the finding's identity, so a result mapped to `.mcp.json` stays distinct from a source-tree scanner's result at the same place in that file. On a mapped result the generated script's context region, artifact index, location annotations, related locations, code flows, stacks and fixes are cleared, since their positions describe the script. The scanner's own `fingerprints` and `partialFingerprints` are kept, since they are its identity for the finding and not positions. Graphs, attachments and the analysis target are left as the scanner wrote them. A result is mapped when any of its locations is on a line with a row, and it is judged by its first location: if that location moved to the config file the finding is keyed by the config file, and if it stayed in the script the finding keeps the script's converted path.

Some limits to know:

- The span is the whole server entry. The script has one command line per server, so a finding in it cannot be narrowed to a single field. The policy scanner's own findings are the ones that point at a specific field.
- A finding on a line the sidecar has no row for, or in a converted file with no sidecar (an archive or notebook conversion, for example), is left on the generated file exactly as before.
- A sidecar is read as untrusted data, and only when the converter recorded both the script and its sidecar in its own record of converted files. A `.spanmap.json` that arrives any other way, such as inside an extracted archive, maps nothing. A sidecar that is missing, unreadable, over 4 MiB or not a JSON array of objects maps nothing. A row is skipped when a number in it is not a positive integer, when its end comes before its start, or when its source path is not the config file the converter recorded for that script, is absolute, starts with `file:` or a scheme such as `https://` or a drive such as `C:/`, has a `..` segment, or does not name an existing file inside the scanned tree. A colon or a backslash inside a file name is allowed, since it is a legitimate name on POSIX.
- Two secrets in one server entry are mapped to the same entry span, so they are told apart by their rule or message and not by position.
- In a TOML file (`.codex/config.toml`) the span of a key is the key's first line only, because the TOML reader gives no positions and the line is found by scanning for the key.
- A server entry whose command is built at run time (`"$CMD"`) is seen as written. The checks look at what the file says, not at what a shell would make of it.

## Running it

<!-- doctest: run expect-exit=2 -->
```sh
ash --source-dir . --scanners mcp-config --output-dir ash_output
```

The policy findings come from `mcp-config` alone. On the `.mcp.json` above it reports `MCP-PRIVILEGE-ESCALATION` (HIGH) at the server's `command`, so the scan exits 2. To have the generated scripts scanned as well, run semgrep or opengrep in the same scan:

<!-- doctest: illustrative reason="runs semgrep, whose default ruleset p/ci is fetched from the Semgrep registry over the network" -->
```sh
ash --source-dir . --scanners mcp-config,semgrep --output-dir ash_output
```
