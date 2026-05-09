#!/usr/bin/env bash
# Install ASH MCP customization for Cline (VS Code).
# Idempotent: re-running overwrites the target config files.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

EXT_DIR="User/globalStorage/saoudrizwan.claude-dev/settings"
case "$(uname -s)" in
  Darwin) BASE="$HOME/Library/Application Support/Code" ;;
  Linux) BASE="$HOME/.config/Code" ;;
  *) echo "Unsupported OS: $(uname -s). Edit $BASE manually." >&2; exit 1 ;;
esac
TARGET="$BASE/$EXT_DIR/cline_mcp_settings.json"
if [[ ! -d "$BASE/$EXT_DIR" ]]; then
  echo "Cline VS Code extension not detected at $BASE/$EXT_DIR" >&2
  echo "Install Cline first, then re-run this script." >&2
  exit 1
fi
cat > "$TARGET" <<'EOF'
{
  "mcpServers": {
    "ash": {
      "command": "uvx",
      "args": [
        "--from=git+https://github.com/awslabs/automated-security-helper@v3.4.0",
        "ash",
        "mcp"
      ],
      "env": {
        "FASTMCP_LOG_LEVEL": "ERROR"
      },
      "timeout": 120000,
      "disabled": false
    }
  }
}
EOF
echo "Wrote Cline MCP settings to $TARGET"
echo "Reload the VS Code window for changes to take effect."
