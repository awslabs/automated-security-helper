"""Install-script generators for backends whose MCP config lives outside the repo
(user-level config dirs, VS Code globalStorage, etc.). Bash with conditional
logic is clearer here than Jinja templating."""
from __future__ import annotations

import json
from pathlib import Path

from .core import Manifest
from .jinja_renderer import render


def _install_header(platform_label: str) -> str:
    return render("shared/install_header.sh.j2", platform=platform_label)


def windsurf(m: Manifest, base_dir: Path) -> str:
    mcp_json = json.dumps(json.loads((base_dir / "mcp.json").read_text()), indent=2)
    body = [
        'TARGET="$HOME/.codeium/windsurf/mcp_config.json"',
        'mkdir -p "$(dirname "$TARGET")"',
        f'cat > "$TARGET" <<\'EOF\'\n{mcp_json}\nEOF',
        'echo "Wrote Windsurf MCP config to $TARGET"',
        'echo "Restart Windsurf for changes to take effect."',
    ]
    return _install_header("Windsurf") + "\n".join(body) + "\n"


def cline(m: Manifest, base_dir: Path) -> str:
    mcp_json = json.dumps(json.loads((base_dir / "mcp.json").read_text()), indent=2)
    body = [
        'EXT_DIR="User/globalStorage/saoudrizwan.claude-dev/settings"',
        'case "$(uname -s)" in',
        '  Darwin) BASE="$HOME/Library/Application Support/Code" ;;',
        '  Linux) BASE="$HOME/.config/Code" ;;',
        '  *) echo "Unsupported OS: $(uname -s). Edit $BASE manually." >&2; exit 1 ;;',
        'esac',
        'TARGET="$BASE/$EXT_DIR/cline_mcp_settings.json"',
        'if [[ ! -d "$BASE/$EXT_DIR" ]]; then',
        '  echo "Cline VS Code extension not detected at $BASE/$EXT_DIR" >&2',
        '  echo "Install Cline first, then re-run this script." >&2',
        '  exit 1',
        'fi',
        f'cat > "$TARGET" <<\'EOF\'\n{mcp_json}\nEOF',
        'echo "Wrote Cline MCP settings to $TARGET"',
        'echo "Reload the VS Code window for changes to take effect."',
    ]
    return _install_header("Cline (VS Code)") + "\n".join(body) + "\n"


def gemini(m: Manifest, base_dir: Path) -> str:
    mcp_json = json.dumps(json.loads((base_dir / "mcp.json").read_text()), indent=2)
    body = [
        'TARGET="$HOME/.gemini/settings.json"',
        'mkdir -p "$(dirname "$TARGET")"',
        'if [[ -f "$TARGET" ]]; then',
        '  echo "Existing $TARGET found. Merge MCP config manually:" >&2',
        f'  cat <<\'EOF\'\n{mcp_json}\nEOF',
        '  exit 0',
        'fi',
        f'cat > "$TARGET" <<\'EOF\'\n{mcp_json}\nEOF',
        'echo "Wrote Gemini settings to $TARGET"',
        'echo "Or install as an extension: gemini extensions install $SCRIPT_DIR"',
    ]
    return _install_header("Gemini CLI") + "\n".join(body) + "\n"


def goose(m: Manifest, base_dir: Path) -> str:
    body = [
        'TARGET="$HOME/.config/goose/config.yaml"',
        'mkdir -p "$(dirname "$TARGET")"',
        'if [[ -f "$TARGET" ]] && grep -q "^extensions:" "$TARGET"; then',
        '  echo "Existing extensions block in $TARGET. Merge manually from $SCRIPT_DIR/extension.yaml" >&2',
        '  exit 0',
        'fi',
        'cat "$SCRIPT_DIR/extension.yaml" >> "$TARGET"',
        'echo "Appended extension to $TARGET"',
        'echo "Restart Goose to load the extension."',
    ]
    return _install_header("Block Goose") + "\n".join(body) + "\n"


def amazonq(m: Manifest, base_dir: Path) -> str:
    body = [
        'TARGET_DIR="$HOME/.aws/amazonq/cli-agents"',
        'mkdir -p "$TARGET_DIR"',
        f'cp "$SCRIPT_DIR/agent.json" "$TARGET_DIR/{m.name}.json"',
        f'echo "Installed Amazon Q agent to $TARGET_DIR/{m.name}.json"',
        f'echo "Use the agent: q --agent {m.name}"',
    ]
    return _install_header("Amazon Q Developer CLI") + "\n".join(body) + "\n"


INSTALL_SCRIPT_BUILDERS = {
    "windsurf": windsurf,
    "cline": cline,
    "gemini": gemini,
    "goose": goose,
    "amazonq": amazonq,
}
