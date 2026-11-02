# Install the ASH plugin for your agent

The repository ships a generated integration for each of several agent platforms, under
[`ash-agent-plugins/agentic-coding/plugins/`](https://github.com/awslabs/automated-security-helper/tree/main/ash-agent-plugins/agentic-coding/plugins).
Each one registers ASH's MCP server with the agent and adds instructions that tell the agent
how to use the tools: a skill, rules, commands, or an agent definition, depending on what the
platform supports. If you would rather add the server yourself, follow
[Connect an AI agent to ASH](../getting-started/agents.md).

Every MCP configuration in these files starts the server the same way:

<!-- doctest: config kind=mcp-client -->
```json
{
  "mcpServers": {
    "ash": {
      "command": "uvx",
      "args": [
        "--from=git+https://github.com/awslabs/automated-security-helper@v3.7.1",
        "ash",
        "mcp"
      ]
    }
  }
}
```

`uvx` installs ASH v3.7.1 from GitHub the first time the agent starts the server, and
reuses that copy afterward. The plugin does not need ASH installed separately.

## Prerequisites

- [uv](https://docs.astral.sh/uv/), with `uvx` on the `PATH` that the agent uses. On Linux and
  macOS, uv's installer is:

    <!-- doctest: illustrative reason="installs uv from the network" -->
    ```bash
    curl -LsSf https://astral.sh/uv/install.sh | sh
    ```

    Desktop apps often do not see your shell's `PATH`. If the agent cannot start the server,
    replace `uvx` in its config with the absolute path that `command -v uvx` prints.
- git, and network access to GitHub the first time the server starts.
- The scanner tools. Install them once for your user:

    <!-- doctest: illustrative reason="downloads ASH and scanner tools from the network" -->
    ```bash
    uvx --python 3.12 --from=git+https://github.com/awslabs/automated-security-helper@v3.7.1 ash dependencies install
    ```

    Without them the scans still run, but a scan ends with status `incomplete` when a scanner
    that has files to scan has no tool, and lists those scanners.
- The plugin files, from a clone of the repository:

    <!-- doctest: illustrative reason="clones from the network" -->
    ```bash
    git clone --depth 1 https://github.com/awslabs/automated-security-helper.git
    cd automated-security-helper/ash-agent-plugins/agentic-coding/plugins
    ```

The paths below are relative to that `plugins` directory.

### Pin the Python version

The generated configs let uv choose the Python version. Releases up to 3.7.x fail to install
under Python 3.15, which uv picks on a machine where it is the newest Python. Add
`"--python", "3.12"` at the start of the config's arguments; uv downloads Python 3.12 if it is
not installed:

<!-- doctest: config kind=mcp-client -->
```json
{
  "mcpServers": {
    "ash": {
      "command": "uvx",
      "args": [
        "--python",
        "3.12",
        "--from=git+https://github.com/awslabs/automated-security-helper@v3.7.1",
        "ash",
        "mcp"
      ]
    }
  }
}
```

### Directories the server refuses

The plugins do not set `ASH_MCP_ALLOWED_ROOTS`, so a project in a directory the server refuses
by default, such as `/root`, needs it added to the config's environment; see
[step 5 of the tutorial](../getting-started/agents.md#5-ask-for-a-scan).

## Choose your platform

| Platform | Directory | What it adds | Notes |
|----------|-----------|--------------|-------|
| Claude Code | `claude/` | MCP server, the `ash-mcp` skill, `scan` and `results` commands, and a security-scanner agent | |
| Codex CLI | `codex/` | MCP server, the `ash-mcp` skill | |
| Kiro | `kiro/` | A power: MCP server and instructions | |
| GitHub Copilot in VS Code | `copilot/` | `.vscode/mcp.json`, Copilot instructions, `scan` and `results` prompts, and an agent | |
| OpenCode | `opencode/` | MCP server, skill, commands, and agent | |
| Cursor | `cursor/` | MCP server and a rule | |
| Windsurf | `windsurf/` | A rule, and an `install.sh` that adds the `ash` server to your global MCP config | |
| Cline | `cline/` | Rules, and an `install.sh` that adds the `ash` server to your global MCP settings | macOS and Linux only. |
| Continue | `continue/` | MCP server and a rule | |
| Gemini CLI | `gemini/` | An extension: MCP server and instructions | |
| Goose | `goose/` | An extension and `AGENTS.md` | |
| Claude Desktop | `mcpb/` | An MCP bundle, `ash.mcpb` | |
| Roo Code | `roo/` | MCP server, rules, and a custom mode | Roo Code's maintainers announced its [shutdown](https://docs.roocode.com/sunset) for 2026-05-15. |
| Amazon Q Developer CLI | `amazonq/` | An agent definition | Amazon Q Developer CLI is now Kiro CLI. The script writes the Amazon Q Developer CLI agent location. |
| Aider | `aider/` | Conventions only | Aider does not support MCP, so it cannot call ASH's tools. |
| Any Agent Skills client | `generic-skill/`, and `skills/` at the repository root | The `ash-mcp` skill only, with no MCP server | See [Agent Skills](#agent-skills). |

`AGENTS.md` in the `plugins` directory holds the same instructions as a plain file, for agents
that read an `AGENTS.md` at the root of your repository.

## Install

### Claude Code

Start Claude Code with the plugin loaded:

<!-- doctest: illustrative reason="needs Claude Code" -->
```bash
claude --plugin-dir claude
```

`claude --plugin-dir` loads the plugin for that session only.

### Codex CLI

Add the directory as a plugin marketplace:

<!-- doctest: illustrative reason="needs Codex CLI" -->
```bash
codex plugin marketplace add ./codex
```

### Kiro

Add `kiro/` as a power from its GitHub directory. Kiro reads `POWER.md` for the instructions
and `mcp.json` for the server.

### GitHub Copilot, OpenCode, Cursor, Continue, and Roo Code

Copy the platform's files into the root of the repository you want to scan:

| Platform | Copy |
|----------|------|
| GitHub Copilot in VS Code | `copilot/.github/` and `copilot/.vscode/` |
| OpenCode | `opencode/opencode.json` and `opencode/.opencode/` |
| Cursor | `cursor/.cursor/`, and `cursor/AGENTS.md` if you want it |
| Continue | `continue/.continue/` |
| Roo Code | `roo/.roo/`, `roo/.roomodes`, and `roo/AGENTS.md` |

If the repository already has one of these files, such as `.vscode/mcp.json`, add the `ash`
entry to it instead of replacing it. VS Code's `mcp.json` names its servers under `servers`,
not `mcpServers`.

### Windsurf and Cline

Copy the rules into your repository: `windsurf/.windsurf/` for Windsurf, `cline/.clinerules/`
for Cline. Then run the platform's `install.sh`. It adds the `ash` entry under `mcpServers` in
the global MCP file and keeps every other server and setting there:
`~/.codeium/windsurf/mcp_config.json` for Windsurf, and `cline_mcp_settings.json` in VS Code's
global storage for the Cline extension.

- Before it changes the file, it saves the old one beside it as
  `<file>.ash-backup-<UTC time>`, with the file's own permissions. Running it again changes
  nothing while the `ash` entry is the one the script writes. An `ash` entry you changed, for
  example to add `ASH_MCP_ALLOWED_ROOTS` to its `env`, is replaced with the script's, after
  the backup.
- It needs `python3`. Without it, or when the file is not plain JSON (a comment or a trailing
  comma is enough) or cannot be written, it changes nothing, prints the entry to add by hand,
  and exits with code 1.
- The Cline script supports macOS and Linux. On other systems it exits with code 1 and names
  the file to edit. It also exits with code 1 when it does not find the Cline extension's
  settings in VS Code's user directory, as with VS Code Insiders or VSCodium.

### Gemini CLI

Install the directory as an extension:

<!-- doctest: illustrative reason="needs Gemini CLI" -->
```bash
gemini extensions install ./gemini
```

`gemini/install.sh` is the alternative. It adds the `ash` entry to `~/.gemini/settings.json`
the way the Windsurf and Cline scripts do, keeping the rest of the file and saving a backup.

### Goose

`goose/install.sh` appends `extension.yaml` to `~/.config/goose/config.yaml` when that file has
no `extensions:` section, after saving the old file, if there is one, beside it as
`config.yaml.ash-backup-<UTC time>`. When the section already lists the same ASH, the script
changes nothing and exits 0. When it lists another ASH version, the script names that version
and the `uvx --from` argument to change it to; when it has no ASH entry, it prints the entry to
merge by hand. Both exit with code 1 and change nothing. A commented-out line does not count
as listing an ASH. The script does not install
`AGENTS.md`; copy it into your repository if you want Goose to read it.

### Claude Desktop

Open `mcpb/ash.mcpb` with Claude Desktop. The bundle contains only a manifest that starts the
server with `uvx`, so `uvx` must be on the `PATH` that Claude Desktop sees.

### Amazon Q Developer CLI

`amazonq/install.sh` copies `agent.json` to `~/.aws/amazonq/cli-agents/ash.json`. Start the
agent with `q --agent ash`.

### Aider

Copy `aider/CONVENTIONS.md` and `aider/.aider.conf.yml` into your repository. Aider then reads
the conventions in every session. It has no MCP support, so it cannot run ASH's tools.

## Agent Skills

The `ash-mcp` skill follows the [Agent Skills](https://agentskills.io/specification) format:
`SKILL.md` and two reference files, `tool-reference.md` and `troubleshooting.md`. The same skill
is in `skills/ash-mcp/` at the repository root and in `generic-skill/skills/ash-mcp/`.

Install it with the `skills` command-line tool, which reads `skills/` at the root of the
repository:

<!-- doctest: illustrative reason="downloads from the network" -->
```bash
npx skills add awslabs/automated-security-helper
```

Or copy `skills/ash-mcp/` into your agent's skills directory. The skill contains no MCP
configuration, so also add the server as in [step 3 of the
tutorial](../getting-started/agents.md#3-connect-the-agent).

## Change the ASH version a plugin uses

Each file pins ASH v3.7.1, the release this repository's files were generated for. To
use another release, change the tag in the `uvx --from` argument of the installed MCP
configuration, for example in `.mcp.json`, `.cursor/mcp.json`, or `.vscode/mcp.json`. Older
releases have fewer MCP tools than the [MCP tools reference](../reference/mcp-tools.md) lists.

To use an ASH you installed yourself instead, replace `uvx` and its arguments:

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

## Regenerate the plugins

The plugin files are generated from
[`ash-agent-plugins/agentic-coding/transpiler/_base/`](https://github.com/awslabs/automated-security-helper/tree/main/ash-agent-plugins/agentic-coding/transpiler/_base).
Edit the files there, never the generated copies, and rebuild and check them as the
[transpiler README](https://github.com/awslabs/automated-security-helper/blob/main/ash-agent-plugins/agentic-coding/transpiler/README.md)
describes. CI fails when the generated files differ from what the transpiler produces. The
version pin comes from the `version` in `[tool.commitizen]` of `pyproject.toml`, and the
release bump rewrites it in `_base/`.
