# Agentic Coding Plugins for ASH

A unified source-of-truth (`agentic-coding/transpiler/_base/`) plus a config-driven Python transpiler that emits plugin packages for **15 AI coding agent platforms** from one canonical content set. Wraps the [ASH (Automated Security Helper)](https://github.com/awslabs/automated-security-helper) MCP server so any agent can run security scans through the same backing service.

## What this gets you

| # | Platform | Folder | How users install |
|---|----------|--------|-------------------|
| 1 | **Claude Code** | `agentic-coding/plugins/claude/` | `claude --plugin-dir ./agentic-coding/plugins/claude` |
| 2 | **Codex CLI** | `agentic-coding/plugins/codex/` | `codex plugin marketplace add ./agentic-coding/plugins/codex` |
| 3 | **Kiro IDE** | `agentic-coding/plugins/kiro/` | "Add power from GitHub" pointing at this repo's `agentic-coding/plugins/kiro/` |
| 4 | **GitHub Copilot** | `agentic-coding/plugins/copilot/` | Copy `.github/` and `.vscode/` into your repo (requires VS Code 1.104+) |
| 5 | **OpenCode** | `agentic-coding/plugins/opencode/` | Copy `opencode.json` and `.opencode/` into your repo |
| 6 | **Cursor** | `agentic-coding/plugins/cursor/` | Copy `.cursor/` into your repo |
| 7 | **Windsurf** | `agentic-coding/plugins/windsurf/` | Copy `.windsurf/`, then `bash install.sh` |
| 8 | **Cline** | `agentic-coding/plugins/cline/` | Copy `.clinerules/`, then `bash install.sh` |
| 9 | **Roo Code** | `agentic-coding/plugins/roo/` | Copy `.roo/` and `.roomodes` into your repo |
| 10 | **Continue.dev** | `agentic-coding/plugins/continue/` | Copy `.continue/` into your repo |
| 11 | **Gemini CLI** | `agentic-coding/plugins/gemini/` | `gemini extensions install ./agentic-coding/plugins/gemini` |
| 12 | **Block Goose** | `agentic-coding/plugins/goose/` | `bash install.sh` |
| 13 | **Amazon Q Dev CLI** | `agentic-coding/plugins/amazonq/` | `bash install.sh` then `q --agent ash` |
| 14 | **Aider** | `agentic-coding/plugins/aider/` | Copy `.aider.conf.yml` and `CONVENTIONS.md` (no MCP support in Aider) |
| 15 | **MCPB / Claude Desktop** | `agentic-coding/plugins/mcpb/` | Double-click `ash.mcpb` for one-click install in Claude Desktop |

Plus a **universal `AGENTS.md`** at `agentic-coding/plugins/AGENTS.md`, read natively by Codex, Cursor, Windsurf, OpenCode, Copilot (1.104+), Cline, Roo Code, Kiro, and Factory CLI.

## Architecture

**Single source of truth, declarative config, deterministic transpiler.** Humans edit `agentic-coding/transpiler/_base/` and `agentic-coding/transpiler/configs.yaml`. The transpiler regenerates all platform outputs. A pre-commit hook + CI verifies that committed plugin files match what the transpiler would produce.

```
agentic-coding/
├── transpiler/                         # The build tool
│   ├── pyproject.toml                  # Declares jinja2, pydantic, pyyaml deps
│   ├── transpile.py                    # ~700 lines — orchestrator + section emitters
│   ├── schema.py                       # Pydantic models that validate configs.yaml
│   ├── configs.yaml                    # Per-platform layout descriptions (15 entries)
│   ├── _base/                          # SOURCE OF TRUTH — humans only edit here
│   │   ├── manifest.json               # Plugin metadata: name, description, etc.
│   │   ├── skill.md                    # Main skill body (no frontmatter)
│   │   ├── references/
│   │   │   ├── tool-reference.md
│   │   │   └── troubleshooting.md
│   │   ├── commands/                   # Platform-neutral command bodies
│   │   ├── agents/                     # Platform-neutral agent system prompts
│   │   └── mcp.json                    # Canonical MCP server config
│   └── templates/                      # Jinja templates for frontmatter / YAML / etc.
│       ├── skill.md.j2                 # Generic frontmatter + body (used by skills/commands/agents)
│       ├── shared/                     # AGENTS.md, install.sh header
│       └── <platform>/                 # Per-platform templates for non-skill shapes
│
└── plugins/                            # GENERATED — committed for browse-by-platform
    ├── AGENTS.md                       # Universal repo-root instruction file
    ├── claude/, codex/, kiro/,         # 14 directory-style plugins
    ├── copilot/, opencode/, cursor/,
    ├── windsurf/, cline/, roo/,
    ├── continue/, gemini/, goose/,
    ├── amazonq/, aider/
    └── mcpb/                           # MCPB archive (manifest.json + ash.mcpb ZIP)
```

## How transpilation works

The transpiler reads `_base/` content and `configs.yaml` layout descriptions, then dispatches each platform through a generic `render_platform()` function. Each section in a platform's config (`plugin_manifest`, `mcp`, `skill`, `commands`, `agents`, `instruction_file`, `rules_dir`, `custom_modes`, `config_file`, `marketplace`, `extension_manifest`, `mcpb_bundle`) is handled by a corresponding emitter.

**Adding a new platform** is typically just a `configs.yaml` entry plus possibly one Jinja template if the layout has a genuinely new shape. No new Python render function is needed unless the platform requires output formats outside the existing dispatcher (JSON manifests, YAML configs, MCPB archives, install scripts).

**Each Jinja template stays under 20 lines.** The single `skill.md.j2` template handles all frontmatter+body files (skills, commands, agents) by parameterizing over `frontmatter_fields`. Per-platform templates exist only where a platform's shape is genuinely different (Roo `.roomodes`, Continue YAML mcpServers, Goose YAML extensions, instruction files like POWER.md / GEMINI.md / .goosehints / CONVENTIONS.md / copilot-instructions.md, Aider config).

## Development workflow

```bash
# 1. Install pre-commit hooks (one-time)
pip install pre-commit
pre-commit install

# 2. Edit _base/ content or configs.yaml
$EDITOR agentic-coding/transpiler/_base/skill.md
$EDITOR agentic-coding/transpiler/configs.yaml

# 3. Re-transpile (uv handles deps automatically)
uv run --project agentic-coding/transpiler transpile

# 4. Verify nothing else drifted
uv run --project agentic-coding/transpiler transpile --check

# 5. Commit — pre-commit re-runs the transpiler and the drift check
git commit -am "feat: improve scan workflow"
```

CI runs `uv run --project agentic-coding/transpiler transpile --check` on every push and PR. `--check` runs two passes: drift detection (do generated files match what the transpiler would produce?) followed by output validation (do generated files conform to each platform's spec?). Either failure surfaces details and exits non-zero. Drift is architecturally impossible to merge; spec violations are caught before they reach users.

## Output validation

The transpiler validates every generated file against its platform's spec via three tiers:

1. **External JSON Schemas** — `mcpb/manifest.json` validates against the official [MCPB Draft 07 schema](https://github.com/modelcontextprotocol/mcpb), and `opencode/opencode.json` validates against the [OpenCode Draft 2020-12 schema](https://opencode.ai/config.json). Both schemas are vendored at `agentic-coding/transpiler/schemas/`.
2. **Structural sanity** — every generated `.json` parses as JSON, every `.yaml`/`.yml` parses as YAML, every markdown file with `---` frontmatter has parseable YAML, and every path declared in `configs.yaml` exists in the output tree.
3. **Known platform constraints** — Claude plugin name kebab-case, Roo customMode slug regex, Windsurf `trigger` enum, Copilot 4000-char `copilot-instructions.md` cap, Windsurf 12000-byte rule cap, MCPB archive integrity (must contain `manifest.json` at root, manifest must validate against the MCPB schema).

To refresh the cached external schemas after upstream changes:

```bash
bash agentic-coding/transpiler/schemas/refresh.sh
git diff agentic-coding/transpiler/schemas/   # review what changed
uv run --project agentic-coding/transpiler transpile --check  # confirm we still validate
```

You can run validation independently of drift detection:

```bash
uv run --project agentic-coding/transpiler transpile --check          # drift + validation (CI gate)
uv run --project agentic-coding/transpiler transpile --validate-only  # validation alone
uv run --project agentic-coding/transpiler transpile --drift-only     # drift alone
```

## MCPB / Claude Desktop one-click install

`agentic-coding/plugins/mcpb/ash.mcpb` is a ZIP archive following the [Anthropic MCPB spec](https://github.com/modelcontextprotocol/mcpb). End-users download the file and double-click it in Claude Desktop to install ASH as an MCP server with no terminal commands.

The archive is **deterministic** — `zipfile` with a fixed mtime (1980-01-01) and stable compression — so re-running the transpiler produces a byte-identical archive. CI's drift check comparing committed archive bytes against freshly-built bytes works the same as text-file drift detection.

## AGENTS.md adoption

Per [agents.md](https://agents.md), the canonical project-level instruction file. The repo's `agentic-coding/plugins/AGENTS.md` is read natively by:

- Codex CLI (originated the spec)
- Cursor, Windsurf, Factory CLI (co-creators)
- OpenCode (canonical, falls back to `CLAUDE.md`)
- GitHub Copilot — VS Code 1.104+ via `chat.useAgentsMdFile`
- Cline, Roo Code, Kiro

**Non-adopters** bridge via:
- Claude Code — `@../AGENTS.md` import in generated `CLAUDE.md`
- Continue.dev — uses `.continue/rules/*.md` (transpiler emits a rule file)
- Gemini CLI — uses `GEMINI.md` (transpiler emits one)
- Aider — manual `read: CONVENTIONS.md` in `.aider.conf.yml` (transpiler emits both)

## License

Apache-2.0 (matching ASH itself). The plugin packages are thin wrappers around the upstream ASH MCP server at https://github.com/awslabs/automated-security-helper.

## Credits

- ASH: https://github.com/awslabs/automated-security-helper
- AGENTS.md spec: https://agents.md
- MCPB spec: https://github.com/modelcontextprotocol/mcpb
- Plugin specs verified against official documentation for each platform (see `agentic-coding/transpiler/_base/manifest.json` for ASH version pin)
