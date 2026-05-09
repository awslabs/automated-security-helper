#!/usr/bin/env bash
# Install ASH MCP customization for Block Goose.
# Idempotent: re-running overwrites the target config files.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TARGET="$HOME/.config/goose/config.yaml"
mkdir -p "$(dirname "$TARGET")"
if [[ -f "$TARGET" ]] && grep -q "^extensions:" "$TARGET"; then
  echo "Existing extensions block in $TARGET. Merge manually from $SCRIPT_DIR/extension.yaml" >&2
  exit 0
fi
cat "$SCRIPT_DIR/extension.yaml" >> "$TARGET"
echo "Appended extension to $TARGET"
echo "Restart Goose to load the extension."
