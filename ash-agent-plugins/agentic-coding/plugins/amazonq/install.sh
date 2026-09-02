#!/usr/bin/env bash
# Install ASH MCP customization for Amazon Q Developer CLI.
# Idempotent: re-running overwrites the target config files.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TARGET_DIR="$HOME/.aws/amazonq/cli-agents"
mkdir -p "$TARGET_DIR"
cp "$SCRIPT_DIR/agent.json" "$TARGET_DIR/ash.json"
echo "Installed Amazon Q agent to $TARGET_DIR/ash.json"
echo "Use the agent: q --agent ash"
