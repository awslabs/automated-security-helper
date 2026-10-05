#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# The MCPB channel end to end:
#
#   scripts/e2e/mcpb.sh <work-dir>
#
#   E2E_INSPECTOR_VERSION  the @modelcontextprotocol/inspector version (default below;
#                          tests/unit/test_e2e_mcpb_inspector.py holds it equal to the
#                          pin in .github/actions/validate-mcp/action.yml)
#
# 1. Builds the bundle from this commit the way the release does
#    (.github/workflows/ash-tag-on-merge.yml, "Stage and verify the MCPB bundle"):
#    `agentic-plugins check --drift-only` rebuilds every backend into a sandbox and
#    byte-compares, so the committed ash.mcpb is proven to be what _base/ at this
#    commit produces, and `agentic-plugins release mcpb` stages it.
# 2. Builds the head wheel and an N-1 wheel from `git archive` exports. N-1 is this
#    tree with its [project] version lowered by packaging/verify-lib.sh's
#    vl_lower_version, the derivation packaging/build-test-wheels.sh uses. Both are
#    gated by the artifact-contents check.
# 3. Installs the pinned MCP Inspector into <work-dir>, never globally.
# 4. Runs the transpiler's archive-corruption tests, which prove the bundle's own
#    smoke test rejects damaged archives.
# 5. Hands everything to scripts/e2e/mcpb_inspector.py, which retargets the bundle at
#    the wheels and drives it: upgrade, stdio handshake, the three scan cases,
#    negative controls, uninstall. Its docstring says why the scans use
#    streamable HTTP.
#
# Nothing is published. The bundle, the wheels and the Inspector stay under
# <work-dir>; the N-1 wheel carries a version that was never released.
set -euo pipefail

WORK="${1:?usage: mcpb.sh <work-dir>}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSPECTOR_VERSION="${E2E_INSPECTOR_VERSION:-2.8.0}"
TRANSPILER="$REPO/ash-agent-plugins/agentic-coding/transpiler"

# vl_lower_version, and nothing else from it is used. Sourcing it only defines
# variables and functions.
# shellcheck source=packaging/verify-lib.sh
. "$REPO/packaging/verify-lib.sh"

say() { printf '== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
harness() { uv run --no-project --python 3.12 python "$@"; }

mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"

say "assert_outcome self-test"
harness "$REPO/scripts/e2e/assert_outcome.py" --self-test

# --------------------------------------------------------------------------
# 1. The bundle, from head.
# --------------------------------------------------------------------------
rm -rf "$WORK/bundle"
uv run --project "$TRANSPILER" agentic-plugins check --drift-only
uv run --project "$TRANSPILER" agentic-plugins release mcpb --dist "$WORK/bundle"
BUNDLES=("$WORK"/bundle/*.mcpb)
[ "${#BUNDLES[@]}" -eq 1 ] && [ -f "${BUNDLES[0]}" ] \
  || fail "agentic-plugins release wrote ${#BUNDLES[@]} .mcpb files into $WORK/bundle, expected 1"
BUNDLE="${BUNDLES[0]}"
say "bundle: $BUNDLE"

# --------------------------------------------------------------------------
# 2. N and N-1 wheels.
# --------------------------------------------------------------------------
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$REPO/pyproject.toml" | head -n 1)"
[ -n "$VERSION" ] || fail "no [project] version in pyproject.toml"
PREV_VERSION="$(vl_lower_version "$VERSION")" || fail "cannot derive a lower version from $VERSION"

rm -rf "$WORK/src-head" "$WORK/src-prev" "$WORK/dist-head" "$WORK/dist-prev"
mkdir -p "$WORK/src-head" "$WORK/src-prev"
git -C "$REPO" archive HEAD | tar -x -C "$WORK/src-head"
git -C "$REPO" archive HEAD | tar -x -C "$WORK/src-prev"
# Only the first `version = ` line, which is [project]'s; commitizen's stays as it was.
harness - "$WORK/src-prev/pyproject.toml" "$VERSION" "$PREV_VERSION" <<'PY'
import sys
path, old, new = sys.argv[1:]
text = open(path, encoding="utf-8").read()
needle = f'\nversion = "{old}"\n'
if needle not in text:
    sys.exit(f"no [project] version line {old!r} in {path}")
open(path, "w", encoding="utf-8", newline="").write(text.replace(needle, f'\nversion = "{new}"\n', 1))
PY
uv build --quiet --wheel --out-dir "$WORK/dist-head" "$WORK/src-head"
uv build --quiet --wheel --out-dir "$WORK/dist-prev" "$WORK/src-prev"
HEAD_WHEEL="$WORK/dist-head/automated_security_helper-${VERSION}-py3-none-any.whl"
PREV_WHEEL="$WORK/dist-prev/automated_security_helper-${PREV_VERSION}-py3-none-any.whl"
[ -f "$HEAD_WHEEL" ] || fail "uv build did not write $HEAD_WHEEL"
[ -f "$PREV_WHEEL" ] || fail "uv build did not write $PREV_WHEEL"
say "artifact-contents gate on both wheels"
harness "$REPO/.github/scripts/assert-artifact-contents.py" "$HEAD_WHEEL" "$PREV_WHEEL"
say "N = $VERSION, N-1 = $PREV_VERSION"

# --------------------------------------------------------------------------
# 3. The Inspector, pinned, local to this run.
# --------------------------------------------------------------------------
rm -rf "$WORK/inspector"
mkdir -p "$WORK/inspector"
npm install --prefix "$WORK/inspector" --no-audit --no-fund --no-save \
  "@modelcontextprotocol/inspector@${INSPECTOR_VERSION}"
INSPECTOR="$WORK/inspector/node_modules/.bin/mcp-inspector"
[ -x "$INSPECTOR" ] || fail "npm installed no mcp-inspector at $INSPECTOR"
"$INSPECTOR" --cli --help >/dev/null || fail "mcp-inspector --cli does not run"
installed="$(cd "$WORK/inspector" && node -p 'require("@modelcontextprotocol/inspector/package.json").version')"
[ "$installed" = "$INSPECTOR_VERSION" ] || fail "npm installed inspector $installed, not $INSPECTOR_VERSION"
say "inspector $installed"

# --------------------------------------------------------------------------
# 4. The bundle's own corruption tests.
# --------------------------------------------------------------------------
uv run --project "$TRANSPILER" --extra test pytest -p no:cacheprovider -o addopts="" \
  "$TRANSPILER/tests/test_mcpb_archive_corruption.py"

# --------------------------------------------------------------------------
# 5. Launch it.
# --------------------------------------------------------------------------
rm -rf "$WORK/run"
harness "$REPO/scripts/e2e/mcpb_inspector.py" \
  --bundle "$BUNDLE" \
  --wheel "$HEAD_WHEEL" \
  --prev-wheel "$PREV_WHEEL" \
  --inspector "$INSPECTOR" \
  --work "$WORK/run"
