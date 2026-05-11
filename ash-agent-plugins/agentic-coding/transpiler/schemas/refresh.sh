#!/usr/bin/env bash
# Refresh the cached external JSON Schemas used by validate.py.
#
# These schemas are vendored — the transpiler validates generated outputs
# against the local copies, not against a network fetch — so refreshing is
# an explicit, reviewable action rather than a runtime surprise.
#
# Run this script when an upstream schema is updated and we want to pick up
# the changes. Review the diff carefully: a schema change can flip outputs
# from valid to invalid (or vice-versa) without any change to our code.
#
# Usage:
#   bash agentic-coding/transpiler/schemas/refresh.sh
#
# Then run `git diff agentic-coding/transpiler/schemas/` to inspect what
# changed and `uv run --project agentic-coding/transpiler transpile --check`
# to confirm our outputs still validate.

set -euo pipefail

cd "$(dirname "$0")"

# Map: local-filename -> upstream URL
# Each entry is one logical schema we depend on. Keep this list in sync with
# the EXTERNAL_SCHEMAS table in validate.py.
declare -a SCHEMAS=(
  "mcpb-manifest.schema.json|https://raw.githubusercontent.com/modelcontextprotocol/mcpb/main/schemas/mcpb-manifest-latest.schema.json"
  "opencode-config.schema.json|https://opencode.ai/config.json"
)

for entry in "${SCHEMAS[@]}"; do
  filename="${entry%%|*}"
  url="${entry##*|}"
  echo "Fetching $filename from $url"
  curl -fsSL --retry 3 --retry-delay 2 -o "$filename.tmp" "$url"
  # Sanity-check: the response should be a JSON object (Schema docs are objects)
  if ! python3 -c "import json,sys; d=json.load(open('$filename.tmp')); sys.exit(0 if isinstance(d, dict) else 1)"; then
    echo "ERROR: $url did not return a JSON object" >&2
    rm -f "$filename.tmp"
    exit 1
  fi
  mv "$filename.tmp" "$filename"
  echo "  -> $filename ($(wc -c < "$filename") bytes)"
done

echo
echo "Done. Review the diff and re-run --check:"
echo "  git diff $(pwd)"
echo "  uv run --project agentic-coding/transpiler transpile --check"
