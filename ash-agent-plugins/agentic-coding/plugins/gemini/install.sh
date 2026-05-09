#!/usr/bin/env bash
# Install ASH MCP customization for Gemini CLI.
# Idempotent: re-running overwrites the target config files.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TARGET="$HOME/.gemini/settings.json"
mkdir -p "$(dirname "$TARGET")"
if [[ -f "$TARGET" ]]; then
  echo "Existing $TARGET found. Merge MCP config manually:" >&2
  cat <<'EOF'
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
  exit 0
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
echo "Wrote Gemini settings to $TARGET"
echo "Or install as an extension: gemini extensions install $SCRIPT_DIR"
