"""Install-script generators for backends whose MCP config lives outside the repo
(user-level config dirs, VS Code globalStorage, etc.). Bash with conditional
logic is clearer here than Jinja templating.

Every config these scripts touch is the user's own and shared with other tools,
so none of them may replace it. The JSON configs (Cline, Windsurf, Gemini CLI)
are merged by `mcp_config_merge.py`, whose source is embedded into the script;
Goose's YAML is only appended to when that cannot collide with an existing key.
See tests/unit/test_agent_plugin_install_scripts.py at the repository root,
which runs the generated scripts against fixture configs.
"""

from __future__ import annotations

import json
from pathlib import Path

from .core import Manifest
from .jinja_renderer import render

_MERGE_PROGRAM = Path(__file__).with_name("mcp_config_merge.py")

# Delimiter of the heredoc that feeds the merge program to python3.
_PROGRAM_DELIMITER = "PY"


def _install_header(platform_label: str, behavior: str) -> str:
    return render(
        "shared/install_header.sh.j2", platform=platform_label, behavior=behavior
    )


def _server_entry(m: Manifest, base_dir: Path) -> dict:
    servers = json.loads((base_dir / "mcp.json").read_text())["mcpServers"]
    if m.name not in servers:
        raise ValueError(
            f"_base/mcp.json has no {m.name!r} entry under mcpServers; the install "
            "scripts merge exactly that entry into the user's config"
        )
    return servers[m.name]


def _merge_program() -> str:
    program = _MERGE_PROGRAM.read_text(encoding="utf-8")
    if _PROGRAM_DELIMITER in program.splitlines():
        raise ValueError(
            f"{_MERGE_PROGRAM.name} contains a line reading {_PROGRAM_DELIMITER!r}, "
            "which would end the heredoc that embeds it"
        )
    return program.rstrip("\n")


_JSON_MERGE_BEHAVIOR = (
    "Adds the ash server to the existing MCP config, keeping every other server "
    "and setting.\n# The previous file is saved beside it first. Re-running "
    "changes nothing once the entry is current."
)


def _json_merge(m: Manifest, base_dir: Path, servers_key: str) -> list[str]:
    """Shell lines that merge the ash entry into the JSON file named by $TARGET."""
    entry = json.dumps(_server_entry(m, base_dir), indent=2)
    if "'" in entry:
        raise ValueError(
            "the ash MCP entry contains a single quote, so it cannot be embedded "
            "in the single-quoted shell string the install scripts use"
        )
    return [
        f"ASH_MCP_ENTRY='{entry}'",
        "if ! command -v python3 >/dev/null 2>&1; then",
        (
            '  echo "python3 is not on PATH. It is needed to add ASH to $TARGET without'
            ' replacing the MCP servers already in it, so $TARGET was not changed." >&2'
        ),
        f"  echo 'Add this entry under \"{servers_key}\" in that file by hand:' >&2",
        f'  printf \'"{m.name}": %s\\n\' "$ASH_MCP_ENTRY" >&2',
        "  exit 1",
        "fi",
        (
            f'python3 -I - "$TARGET" {servers_key} {m.name} "$ASH_MCP_ENTRY"'
            f" <<'{_PROGRAM_DELIMITER}'\n{_merge_program()}\n{_PROGRAM_DELIMITER}"
        ),
    ]


def windsurf(m: Manifest, base_dir: Path) -> str:
    body = [
        'TARGET="$HOME/.codeium/windsurf/mcp_config.json"',
        'mkdir -p "$(dirname "$TARGET")"',
        *_json_merge(m, base_dir, "mcpServers"),
        'echo "Restart Windsurf for changes to take effect."',
    ]
    return _install_header("Windsurf", _JSON_MERGE_BEHAVIOR) + "\n".join(body) + "\n"


def cline(m: Manifest, base_dir: Path) -> str:
    body = [
        'EXT_DIR="User/globalStorage/saoudrizwan.claude-dev/settings"',
        'case "$(uname -s)" in',
        '  Darwin) BASE="$HOME/Library/Application Support/Code" ;;',
        '  Linux) BASE="$HOME/.config/Code" ;;',
        (
            "  *) echo \"Unsupported OS: $(uname -s). Add the ash entry to Cline's"
            ' cline_mcp_settings.json by hand." >&2; exit 1 ;;'
        ),
        "esac",
        'TARGET="$BASE/$EXT_DIR/cline_mcp_settings.json"',
        'if [[ ! -d "$BASE/$EXT_DIR" ]]; then',
        '  echo "Cline VS Code extension not detected at $BASE/$EXT_DIR" >&2',
        '  echo "Install Cline first, then re-run this script." >&2',
        "  exit 1",
        "fi",
        *_json_merge(m, base_dir, "mcpServers"),
        'echo "Reload the VS Code window for changes to take effect."',
    ]
    return (
        _install_header("Cline (VS Code)", _JSON_MERGE_BEHAVIOR)
        + "\n".join(body)
        + "\n"
    )


def gemini(m: Manifest, base_dir: Path) -> str:
    body = [
        'TARGET="$HOME/.gemini/settings.json"',
        'mkdir -p "$(dirname "$TARGET")"',
        *_json_merge(m, base_dir, "mcpServers"),
        'echo "Or install as an extension: gemini extensions install $SCRIPT_DIR"',
    ]
    return _install_header("Gemini CLI", _JSON_MERGE_BEHAVIOR) + "\n".join(body) + "\n"


def goose(m: Manifest, base_dir: Path) -> str:
    # The standard library has no YAML parser, so this never edits an existing
    # extensions block: it appends one only when the file has none.
    install_ref = "automated-security-helper@"
    # The exact `--from` argument this release installs, so an entry pinned to an
    # older ASH is reported as such rather than as current.
    current_from = next(
        arg
        for arg in _server_entry(m, base_dir)["args"]
        if arg.startswith("--from=") and install_ref in arg
    )
    if "'" in current_from:
        raise ValueError(
            "the ash MCP entry's --from argument contains a single quote, so it "
            "cannot be embedded in a single-quoted shell string"
        )
    body = [
        'TARGET="$HOME/.config/goose/config.yaml"',
        f"ASH_FROM='{current_from}'",
        'mkdir -p "$(dirname "$TARGET")"',
        'if [[ -f "$TARGET" ]] && grep -q "^extensions:" "$TARGET"; then',
        "  # Only uncommented lines are configuration. Read into a variable rather",
        "  # than piped into grep -q, whose early exit pipefail would report.",
        '  ACTIVE="$(grep -v -E \'^[[:space:]]*#\' "$TARGET" || true)"',
        '  if grep -qF -- "$ASH_FROM" <<<"$ACTIVE"; then',
        (
            '    echo "$TARGET already lists this ASH under extensions; nothing to'
            ' change."'
        ),
        "    exit 0",
        "  fi",
        f'  if grep -qF "{install_ref}" <<<"$ACTIVE"; then',
        (
            f"    FOUND=\"$(grep -m 1 -oE '{install_ref}[^\"[:space:]]+'"
            ' <<<"$ACTIVE" || true)"'
        ),
        (
            '    echo "$TARGET lists ASH as ${FOUND:-an older version}, not the one'
            ' this script installs, so $TARGET was not changed." >&2'
        ),
        '    echo "Change that entry\'s --from argument to: $ASH_FROM" >&2',
        "    exit 1",
        "  fi",
        (
            '  echo "$TARGET already has an extensions block, and a second one would'
            ' replace it, so $TARGET was not changed." >&2'
        ),
        "  echo 'Add this under its extensions: key by hand:' >&2",
        '  tail -n +2 "$SCRIPT_DIR/extension.yaml" >&2',
        "  exit 1",
        "fi",
        'BACKUP=""',
        'if [[ -s "$TARGET" ]]; then',
        '  BACKUP="$TARGET.ash-backup-$(date -u +%Y%m%dT%H%M%SZ)"',
        '  cp -p "$TARGET" "$BACKUP"',
        "  # Without this, a last line with no newline gets extensions: glued onto it.",
        '  if [[ -n "$(tail -c 1 "$TARGET")" ]]; then',
        "    printf '\\n' >> \"$TARGET\"",
        "  fi",
        "fi",
        'cat "$SCRIPT_DIR/extension.yaml" >> "$TARGET"',
        'echo "Added the ash extension to $TARGET."',
        'if [[ -n "$BACKUP" ]]; then',
        '  echo "The previous file is saved as $BACKUP."',
        "fi",
        'echo "Restart Goose to load the extension."',
    ]
    behavior = (
        "Appends the ash extension when the config has no extensions block, after"
        " saving the\n# previous file beside it; otherwise prints the entry to add"
        " by hand. Re-running changes\n# nothing once this ASH is listed; an entry"
        " for another ASH version is reported, not\n# changed."
    )
    return _install_header("Block Goose", behavior) + "\n".join(body) + "\n"


def amazonq(m: Manifest, base_dir: Path) -> str:
    body = [
        'TARGET_DIR="$HOME/.aws/amazonq/cli-agents"',
        'mkdir -p "$TARGET_DIR"',
        f'cp "$SCRIPT_DIR/agent.json" "$TARGET_DIR/{m.name}.json"',
        f'echo "Installed Amazon Q agent to $TARGET_DIR/{m.name}.json"',
        f'echo "Use the agent: q --agent {m.name}"',
    ]
    behavior = (
        f"Writes ASH's own agent file, {m.name}.json, and no other file. Re-running"
        " replaces that file."
    )
    return _install_header("Amazon Q Developer CLI", behavior) + "\n".join(body) + "\n"


INSTALL_SCRIPT_BUILDERS = {
    "windsurf": windsurf,
    "cline": cline,
    "gemini": gemini,
    "goose": goose,
    "amazonq": amazonq,
}
