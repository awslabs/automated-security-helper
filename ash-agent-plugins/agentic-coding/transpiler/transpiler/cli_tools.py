"""Registry of CliTool definitions — install commands + validate argv +
version-pin keys for every CLI any backend can use.

A backend declares `CLI_TOOLS = (CLI_CLAUDE, CLI_CODEX, ...)` to express
which tools install or validate it. The matrix CI workflow reads this
list to generate one job per (backend, validator) pair.

Versions here are major.minor; the actual pinned version string lives
in `_base/cli_versions.json`. The `pin_key` defaults to the tool name.
"""

from __future__ import annotations

from .core import CliTool

# ---------------------------------------------------------------------------
# Tools with real schema validators (no LLM, no auth)
# ---------------------------------------------------------------------------

CLI_CLAUDE = CliTool(
    name="claude",
    role="both",
    install_cmd="npm install -g @anthropic-ai/claude-code@2.1",
    validate_argv_template=("claude", "plugin", "validate", "{out}"),
)

CLI_CODEX = CliTool(
    name="codex",
    role="both",
    install_cmd="npm install -g @openai/codex@0.130",
    # Codex has no `validate` verb; `marketplace add <local-dir>` is the
    # CI lever. We isolate via env CODEX_HOME to keep the runner clean.
    validate_argv_template=(
        "env",
        "CODEX_HOME={codex_home}",
        "codex",
        "plugin",
        "marketplace",
        "add",
        "{out}",
    ),
)

CLI_GEMINI = CliTool(
    name="gemini",
    role="both",
    install_cmd="npm install -g @google/gemini-cli@0.41",
    validate_argv_template=("gemini", "extensions", "validate", "{out}"),
)

CLI_MCPB = CliTool(
    name="mcpb",
    role="both",
    install_cmd="npm install -g @anthropic-ai/mcpb@2.1",
    validate_argv_template=("mcpb", "validate", "{archive}"),
)

CLI_Q = CliTool(
    name="q",
    role="both",
    install_cmd=(
        "curl --proto '=https' --tlsv1.2 -sSf "
        "'https://desktop-release.q.us-east-1.amazonaws.com/latest/q-x86_64-linux.zip' "
        "-o /tmp/q.zip && unzip -q /tmp/q.zip -d /tmp/ && /tmp/q/install.sh"
    ),
    # `q agent validate` always exits 0; the smoke_test must grep stderr
    # for `WARNING ` / `Error: `. Helper handles this.
    validate_argv_template=("q", "agent", "validate", "--path", "{agent_json}"),
)

CLI_KIRO_CLI = CliTool(
    name="kiro-cli",
    role="both",
    install_cmd=(
        "curl --proto '=https' --tlsv1.2 -sSf "
        "'https://desktop-release.q.us-east-1.amazonaws.com/latest/kirocli-x86_64-linux.zip' "
        "-o /tmp/kirocli.zip && unzip -q /tmp/kirocli.zip -d /tmp/ "
        "&& /tmp/kirocli/install.sh"
    ),
    validate_argv_template=("kiro-cli", "agent", "validate", "{agent_json}"),
)

CLI_AIDER = CliTool(
    name="aider",
    role="both",
    install_cmd="pipx install aider-chat==0.86.2",
    validate_argv_template=("aider", "--exit", "--yes-always", "--config", "{config}"),
)

CLI_GOOSE = CliTool(
    name="goose",
    role="both",
    # The release tarball, checked against its pinned SHA256 before it is
    # unpacked. This used to pipe goose's download_cli.sh into bash, which ran a
    # remote script unverified, and that script falls back to the *latest*
    # release when the pinned one fails to download. It installs to the same
    # place the script did ($HOME/.local/bin) and, like CONFIGURE=false, runs
    # nothing afterwards. The digest is the one GitHub lists for the v1.33.1
    # asset, and it matches the downloaded file.
    install_cmd=(
        "curl --proto '=https' --tlsv1.2 -fsSL -o /tmp/goose.tar.gz "
        "'https://github.com/aaif-goose/goose/releases/download/v1.33.1/goose-x86_64-unknown-linux-gnu.tar.gz' "
        "&& echo '437a32e2bd304e6544036bec117436712f7847f72ddbe46d6c2c4009e0ffcca8  /tmp/goose.tar.gz' "
        "| sha256sum -c - "
        '&& mkdir -p "$HOME/.local/bin" '
        '&& tar -xzf /tmp/goose.tar.gz -C "$HOME/.local/bin" ./goose'
    ),
    # `goose recipe validate` works on RECIPES; for raw extensions we'd
    # need to wrap as a recipe. Today smoke_test is structural only.
    validate_argv_template=(),
)

CLI_OPENCODE = CliTool(
    name="opencode",
    role="both",
    install_cmd="npm install -g opencode-ai@1.14",
    # No `validate` verb; closest non-LLM checks are `--version`, `agent list`,
    # `mcp list`. Smoke_test stays structural-only.
    validate_argv_template=(),
)

CLI_SKILLS_REF = CliTool(
    name="skills-ref",
    role="validator",
    # First-party agentskills.io validator. Install path TBD (npm or cargo);
    # treat as optional for now — smoke_test() falls back to structural.
    install_cmd="",
    validate_argv_template=("skills-ref", "validate", "{out}"),
    pin_key="",
)

# ---------------------------------------------------------------------------
# IDE-only / installer-only tools (no headless validate path)
# ---------------------------------------------------------------------------

CLI_VSCODE = CliTool(
    name="code",
    role="installer",
    install_cmd="",  # presumed pre-installed; or use code-server
    headless=False,
)

CLI_CURSOR = CliTool(
    name="cursor-agent",
    role="installer",
    # The versioned package that https://cursor.com/install fetched on
    # 2026-10-07, laid out the way that script lays it out, checked against a
    # pinned SHA256 first. Piping the script into bash ran it unverified and
    # installed whatever build it named that day. Cursor publishes no checksum
    # (the .sha256 and SHA256SUMS siblings answer 403), so the digest is the
    # one measured from the download. A bump replaces the build id and digest.
    install_cmd=(
        "curl --proto '=https' --tlsv1.2 -fsSL -o /tmp/cursor-agent.tar.gz "
        "'https://downloads.cursor.com/lab/2026.10.01-e373342/linux/x64/agent-cli-package.tar.gz' "
        "&& echo 'a79726c6e644520e993970be4c45775a6889802b67abe461a677a53219ae28e8  /tmp/cursor-agent.tar.gz' "
        "| sha256sum -c - "
        '&& D="$HOME/.local/share/cursor-agent/versions/2026.10.01-e373342" '
        '&& mkdir -p "$D" "$HOME/.local/bin" '
        '&& tar --strip-components=1 -xzf /tmp/cursor-agent.tar.gz -C "$D" '
        '&& ln -sf "$D/cursor-agent" "$HOME/.local/bin/cursor-agent" '
        '&& ln -sf "$D/cursor-agent" "$HOME/.local/bin/agent"'
    ),
    pin_key="cursor",
    headless=False,
)

CLI_CLINE = CliTool(
    name="cline",
    role="both",
    install_cmd="npm install -g cline@1.0",
    # Cline's CLI has no validate verb; structural only.
    validate_argv_template=(),
)

CLI_CONTINUE = CliTool(
    name="cn",
    role="installer",
    install_cmd="npm install -g @continuedev/cli",
    pin_key="continue",
)

CLI_WINDSURF = CliTool(
    name="windsurf",
    role="installer",
    install_cmd="",  # IDE-only
    headless=False,
)

CLI_ROO = CliTool(
    name="roo-cline",
    role="installer",
    install_cmd="",  # VS Code extension only; sunset 2026-05-15
    pin_key="roo",
    headless=False,
)

CLI_KIRO_IDE = CliTool(
    name="kiro-ide",
    role="installer",
    install_cmd="",  # Electron IDE; the `kiro-cli` companion is separate
    pin_key="kiro-cli",
    headless=False,
)

# ---------------------------------------------------------------------------
# Registry — name → CliTool. Used by matrix CI workflow generator.
# ---------------------------------------------------------------------------

ALL_CLI_TOOLS = (
    CLI_CLAUDE,
    CLI_CODEX,
    CLI_GEMINI,
    CLI_MCPB,
    CLI_Q,
    CLI_KIRO_CLI,
    CLI_AIDER,
    CLI_GOOSE,
    CLI_OPENCODE,
    CLI_SKILLS_REF,
    CLI_VSCODE,
    CLI_CURSOR,
    CLI_CLINE,
    CLI_CONTINUE,
    CLI_WINDSURF,
    CLI_ROO,
    CLI_KIRO_IDE,
)

CLI_TOOLS_BY_NAME = {t.name: t for t in ALL_CLI_TOOLS}
