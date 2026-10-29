#!/usr/bin/env bash
# Install ASH MCP customization for Block Goose.
# Appends the ash extension when the config has no extensions block, after saving the
# previous file beside it; otherwise prints the entry to add by hand. Re-running changes
# nothing once this ASH is listed; an entry for another ASH version is reported, not
# changed.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TARGET="$HOME/.config/goose/config.yaml"
ASH_FROM='--from=git+https://github.com/awslabs/automated-security-helper@v3.7.1'
mkdir -p "$(dirname "$TARGET")"
if [[ -f "$TARGET" ]] && grep -q "^extensions:" "$TARGET"; then
  # Only uncommented lines are configuration. Read into a variable rather
  # than piped into grep -q, whose early exit pipefail would report.
  ACTIVE="$(grep -v -E '^[[:space:]]*#' "$TARGET" || true)"
  if grep -qF -- "$ASH_FROM" <<<"$ACTIVE"; then
    echo "$TARGET already lists this ASH under extensions; nothing to change."
    exit 0
  fi
  if grep -qF "automated-security-helper@" <<<"$ACTIVE"; then
    FOUND="$(grep -m 1 -oE 'automated-security-helper@[^"[:space:]]+' <<<"$ACTIVE" || true)"
    echo "$TARGET lists ASH as ${FOUND:-an older version}, not the one this script installs, so $TARGET was not changed." >&2
    echo "Change that entry's --from argument to: $ASH_FROM" >&2
    exit 1
  fi
  echo "$TARGET already has an extensions block, and a second one would replace it, so $TARGET was not changed." >&2
  echo 'Add this under its extensions: key by hand:' >&2
  tail -n +2 "$SCRIPT_DIR/extension.yaml" >&2
  exit 1
fi
BACKUP=""
if [[ -s "$TARGET" ]]; then
  BACKUP="$TARGET.ash-backup-$(date -u +%Y%m%dT%H%M%SZ)"
  cp -p "$TARGET" "$BACKUP"
  # Without this, a last line with no newline gets extensions: glued onto it.
  if [[ -n "$(tail -c 1 "$TARGET")" ]]; then
    printf '\n' >> "$TARGET"
  fi
fi
cat "$SCRIPT_DIR/extension.yaml" >> "$TARGET"
echo "Added the ash extension to $TARGET."
if [[ -n "$BACKUP" ]]; then
  echo "The previous file is saved as $BACKUP."
fi
echo "Restart Goose to load the extension."
