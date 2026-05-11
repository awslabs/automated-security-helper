"""Output formats — the shapes backends produce, decoupled from consumers.

Each Format describes a directory layout + canonical schema URL + validator
identity. Multiple agents can consume the same Format (claude + codex both
consume `claude-marketplace`; q-cli + kiro-cli both consume `amazonq-agent`).

When a backend declares `FORMAT = SOME_FORMAT`, smoke-test output shows the
shared format for cross-agent visibility, and future emitters can pull
layout from the Format instead of duplicating per-backend class vars.

Format definitions are deliberately metadata-only (no methods); the actual
emission still runs through the existing section-emitter dispatcher reading
class-var sections on each BaseBackend. This lets the Format abstraction land
incrementally without rewriting every backend at once.
"""
from __future__ import annotations

from .core import Format

# ---------------------------------------------------------------------------
# Formats that serve multiple agents
# ---------------------------------------------------------------------------

CLAUDE_MARKETPLACE = Format(
    name="claude-marketplace",
    description=(
        "Claude Code plugin marketplace layout: .claude-plugin/plugin.json + "
        "marketplace.json + skills/<name>/SKILL.md + commands/*.md + "
        "agents/*.md + hooks/hooks.json + .mcp.json. Codex CLI's plugin "
        "loader natively searches both .codex-plugin/plugin.json AND "
        ".claude-plugin/plugin.json (DISCOVERABLE_PLUGIN_MANIFEST_PATHS in "
        "codex-rs/utils/plugins/src/plugin_namespace.rs), so a single "
        "claude-marketplace artifact serves both Claude Code and Codex CLI."
    ),
    schema_url="https://json.schemastore.org/claude-code-plugin-manifest.json",
    spec_url="https://code.claude.com/docs/en/plugins-reference",
)

AMAZONQ_AGENT = Format(
    name="amazonq-agent",
    description=(
        "Amazon Q v1 agent format: a single agent.json with required `name`, "
        "optional `description`/`prompt`/`model`/`mcpServers`/`tools`/"
        "`toolAliases`/`allowedTools`/`resources`/`hooks`. Q's schema enforces "
        "`additionalProperties: false`; Kiro CLI accepts the same shape with "
        "extensions (`includeMcpJson`, `keyboardShortcut`, `welcomeMessage`, "
        "expanded hooks triggers). Strict-Q-shape files are bidirectionally "
        "compatible: `q agent validate --path` and `kiro-cli agent validate` "
        "both accept them."
    ),
    schema_url="https://raw.githubusercontent.com/aws/amazon-q-developer-cli/refs/heads/main/schemas/agent-v1.json",
    spec_url="https://github.com/aws/amazon-q-developer-cli/blob/main/docs/agent-format.md",
)

AGENTSKILLS = Format(
    name="agentskills",
    description=(
        "agentskills.io SKILL.md format: skills/<name>/SKILL.md with frontmatter "
        "`name` (^[a-z0-9]+(-[a-z0-9]+)*$, ≤64 chars), `description` (1–1024 chars), "
        "optional `license`/`compatibility`/`metadata`. Body is markdown, "
        "subdirectories `references/`, `scripts/`, `assets/` are spec-defined. "
        "Read natively by Claude Code, Codex CLI, OpenCode, Cline, Kiro — "
        "OpenCode and Cline also accept the SKILL.md from `.claude/skills/<name>/`."
    ),
    schema_url=None,
    spec_url="https://agentskills.io/specification",
)

# ---------------------------------------------------------------------------
# Single-agent formats (kept as Format objects so docs/CI tooling can
# reference them uniformly)
# ---------------------------------------------------------------------------

MCPB_BUNDLE = Format(
    name="mcpb-bundle",
    description=(
        "Anthropic MCP Bundle (formerly DXT): a ZIP archive with manifest.json "
        "at root, .mcpb extension. Required: name, version, description, "
        "author, server, manifest_version. Server types: node, python, binary, "
        "uv (added 0.4). Validators: `mcpb validate <path>` (schema), "
        "`mcpb verify <archive>` (PKCS#7 signature)."
    ),
    schema_url="https://raw.githubusercontent.com/modelcontextprotocol/mcpb/main/schemas/mcpb-manifest-v0.4.schema.json",
    spec_url="https://github.com/modelcontextprotocol/mcpb/blob/main/MANIFEST.md",
)

GEMINI_EXTENSION = Format(
    name="gemini-extension",
    description=(
        "Gemini CLI extension: gemini-extension.json with `name` (lowercase "
        "kebab, must match dir), `version` (semver), `description`, optional "
        "`mcpServers`, `contextFileName` (defaults to GEMINI.md), `excludeTools`, "
        "`settings[]`, `themes[]`. Validator: `gemini extensions validate <path>` "
        "(no LLM, no auth, exit 1 on failure)."
    ),
    schema_url=None,
    spec_url="https://github.com/google-gemini/gemini-cli/blob/main/docs/extensions/reference.md",
)

CONTINUE_CONFIG = Format(
    name="continue-config",
    description=(
        "Continue.dev config + rules + per-server MCP YAMLs. Validated by "
        "Zod schemas in `@continuedev/config-yaml` (TS package). No headless "
        "CLI validator — Node import + `validateConfigYaml()` is the offline "
        "path. Continue's mcpServers shape is an array of {name, command, "
        "args, ...}, NOT a Claude-shape object map."
    ),
    schema_url=None,
    spec_url="https://docs.continue.dev/customize/deep-dives/configuration",
)

OPENCODE_CONFIG = Format(
    name="opencode-config",
    description=(
        "OpenCode opencode.json: published JSON Schema at opencode.ai/config.json. "
        "MCP servers under top-level `mcp` key (NOT `mcpServers`). Skills, "
        "commands, agents in `.opencode/` subtree. OpenCode also reads "
        "`.claude/skills/<name>/SKILL.md` natively as Claude-compatible fallback."
    ),
    schema_url="https://opencode.ai/config.json",
    spec_url="https://opencode.ai/docs/config",
)

VSCODE_MCP = Format(
    name="vscode-mcp",
    description=(
        "GitHub Copilot in VS Code: .vscode/mcp.json with top-level key "
        "`servers` (NOT `mcpServers`!). Per-entry `type: stdio|http|sse`, "
        "plus VS Code extensions sandboxEnabled/sandbox.{filesystem,network}, "
        "dev.{watch,debug}. Plus root AGENTS.md (chat.useAgentsMdFile enabled "
        "by default in 1.104+) and .github/copilot-instructions.md."
    ),
    schema_url=None,
    spec_url="https://code.visualstudio.com/docs/copilot/reference/mcp-configuration",
)

CURSOR_RULES = Format(
    name="cursor-rules",
    description=(
        ".cursor/rules/*.mdc with frontmatter description/globs/alwaysApply, "
        "plus .cursor/mcp.json (Claude-shape). AGENTS.md natively read at "
        "root + nested. CLI binary is `agent`, not `cursor-agent`."
    ),
    schema_url=None,
    spec_url="https://cursor.com/docs/context/rules",
)

WINDSURF_RULES = Format(
    name="windsurf-rules",
    description=(
        ".windsurf/rules/*.md with frontmatter trigger/globs/description, "
        "12000-char/file cap. MCP at ~/.codeium/windsurf/mcp_config.json "
        "(Claude-shape, accepts `serverUrl` alias for `url`). AGENTS.md "
        "natively read (root = always-on, subdir = auto-glob)."
    ),
    schema_url=None,
    spec_url="https://docs.windsurf.com/windsurf/cascade/memories",
)

CLINE_RULES = Format(
    name="cline-rules",
    description=(
        ".clinerules/*.md or .txt files (concatenated; numeric prefix optional). "
        "Frontmatter optional `paths:` for conditional scoping. MCP at "
        "cline_mcp_settings.json (Claude-shape, in extension storage). "
        "Reads AGENTS.md natively per Cline docs. Headless CLI: `cline -y`."
    ),
    schema_url=None,
    spec_url="https://docs.cline.bot/features/cline-rules",
)

ROO_RULES = Format(
    name="roo-rules",
    description=(
        ".roo/rules/*.md and .roo/rules-{slug}/*.md (alphabetical sort). "
        ".roomodes for custom modes (slug regex [a-zA-Z0-9-]+). MCP at "
        ".roo/mcp.json (Claude-shape, requires explicit `type` for URL "
        "servers). NOTE: Roo Code shutdown is 2026-05-15."
    ),
    schema_url=None,
    spec_url="https://docs.roocode.com/features/custom-instructions",
)

GOOSE_CONFIG = Format(
    name="goose-config",
    description=(
        "~/.config/goose/config.yaml extensions block. Renames "
        "`command`→`cmd` and `env`→`envs` (different from a key swap). "
        "Goose natively reads AGENTS.md (default `[\"AGENTS.md\", \".goosehints\"]`). "
        "Validator: `goose recipe validate <wrapper.yaml>` works only on "
        "recipes, so extension validation requires wrapping as a minimal recipe."
    ),
    schema_url=None,
    spec_url="https://goose-docs.ai/docs/getting-started/using-extensions/",
)

AIDER_CONFIG = Format(
    name="aider-config",
    description=(
        ".aider.conf.yml with `read:` field accepting string or list. "
        "All keys optional. Aider reads AGENTS.md natively via `read: AGENTS.md` "
        "or CONVENTIONS.md via `read: CONVENTIONS.md`. Validator: "
        "`aider --exit --yes-always --config <path>` (de facto; loads model "
        "client so may trip on missing API keys)."
    ),
    schema_url=None,
    spec_url="https://aider.chat/docs/config/aider_conf.html",
)

# ---------------------------------------------------------------------------
# Registry — name → Format. Used by smoke-test summary and README docs.
# ---------------------------------------------------------------------------

ALL_FORMATS = (
    CLAUDE_MARKETPLACE, AMAZONQ_AGENT, AGENTSKILLS,
    MCPB_BUNDLE, GEMINI_EXTENSION, CONTINUE_CONFIG, OPENCODE_CONFIG,
    VSCODE_MCP, CURSOR_RULES, WINDSURF_RULES, CLINE_RULES, ROO_RULES,
    GOOSE_CONFIG, AIDER_CONFIG,
)

FORMATS_BY_NAME = {f.name: f for f in ALL_FORMATS}
