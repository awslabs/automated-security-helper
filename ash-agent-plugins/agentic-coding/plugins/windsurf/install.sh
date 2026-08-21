#!/usr/bin/env bash
# Install ASH MCP customization for Windsurf.
# Idempotent: re-running overwrites the target config files.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TARGET="$HOME/.codeium/windsurf/mcp_config.json"
mkdir -p "$(dirname "$TARGET")"
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
echo "Wrote Windsurf MCP config to $TARGET"
echo "Restart Windsurf for changes to take effect."
