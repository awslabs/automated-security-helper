#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# The MCPB channel end to end:
#
#   scripts/e2e/mcpb.sh <work-dir>
#
# 1. Builds the bundle from this commit the way the release does
#    (.github/workflows/ash-tag-on-merge.yml, "Stage and verify the MCPB bundle"):
#    `agentic-plugins check --drift-only` rebuilds every backend into a sandbox and
#    byte-compares, so the committed ash.mcpb is proven to be what _base/ at this
#    commit produces, and `agentic-plugins release mcpb` stages it.
# 2. Builds the head wheel, and takes N-1 from the latest published release
#    (E2E_PREV_REF, default latest-release; scripts/e2e/n1-ref.sh): the bundle that
#    release shipped, its committed ash-agent-plugins/agentic-coding/plugins/mcpb/ash.mcpb,
#    which is what a user of it downloaded, and the release's wheel built from its tag.
#    v3.7.1's bundle reports version 1.0.0 and launches v3.4.0; that recorded defect
#    (scripts/e2e/release_defects.py) is exempted for that one bundle only, and the
#    head bundle is held to the full check. Only the head wheel is gated by this tree's
#    artifact-contents check: the release's wheel is what it is.
# 3. Installs the MCP Inspector into <work-dir>, never globally, with `npm ci` from
#    the lockfile under scripts/e2e/inspector/, so every transitive dependency is the
#    one the lockfile records and is checked against its integrity hash. The version
#    is held equal to .github/actions/validate-mcp/action.yml's pin by
#    tests/unit/test_e2e_mcpb_inspector.py.
# 4. Runs the transpiler's archive-corruption tests, which prove the bundle's own
#    smoke test rejects damaged archives.
# 5. Hands everything to scripts/e2e/mcpb_inspector.py, which retargets the bundle at
#    the wheels and drives it: bundle and wheel upgrade, stdio handshake, a scan over
#    stdio, the three scan cases, negative controls, uninstall. Its docstring says
#    why most scans use streamable HTTP.
#
# Nothing is published. The bundle, the wheels and the Inspector stay under
# <work-dir>.
set -euo pipefail

WORK="${1:?usage: mcpb.sh <work-dir>}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSPECTOR_LOCK="$REPO/scripts/e2e/inspector"
TRANSPILER="$REPO/ash-agent-plugins/agentic-coding/transpiler"

PREV_REF="${E2E_PREV_REF:-latest-release}"

say() { printf '== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
harness() { uv run --no-project --python 3.12 python "$@"; }
# shellcheck source=scripts/e2e/n1-ref.sh
. "$REPO/scripts/e2e/n1-ref.sh"

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
PREV_BUNDLE_PATH="ash-agent-plugins/agentic-coding/plugins/mcpb/ash.mcpb"
n1_resolve pyproject.toml ash-agent-plugins/agentic-coding/plugins/mcpb/ash.mcpb
[ "$N1_IS_RELEASE" = yes ] \
  || fail "the MCPB leg upgrades from a published release's bundle; $PREV_REF is not a release"
PREV_RELEASE="${PREV_REF%% *}"

rm -rf "$WORK/src-head" "$WORK/src-prev" "$WORK/dist-head" "$WORK/dist-prev" "$WORK/bundle-prev"
mkdir -p "$WORK/src-head" "$WORK/src-prev" "$WORK/bundle-prev"
n1_export HEAD "$WORK/src-head"
n1_export "$PREV_SHA" "$WORK/src-prev"
PREV_VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$WORK/src-prev/pyproject.toml" | head -n 1)"
[ -n "$PREV_VERSION" ] || fail "no [project] version in $PREV_RELEASE's pyproject.toml"
uv build --quiet --wheel --out-dir "$WORK/dist-head" "$WORK/src-head"
uv build --quiet --wheel --out-dir "$WORK/dist-prev" "$WORK/src-prev"
HEAD_WHEEL="$WORK/dist-head/automated_security_helper-${VERSION}-py3-none-any.whl"
PREV_WHEEL="$WORK/dist-prev/automated_security_helper-${PREV_VERSION}-py3-none-any.whl"
[ -f "$HEAD_WHEEL" ] || fail "uv build did not write $HEAD_WHEEL"
[ -f "$PREV_WHEEL" ] || fail "uv build did not write $PREV_WHEEL"
# A published release is what it is; this tree's packaging rules gate what it builds.
say "artifact-contents gate on the head wheel (N-1 is the published $PREV_RELEASE)"
harness "$REPO/.github/scripts/assert-artifact-contents.py" "$HEAD_WHEEL"
say "N = $VERSION, N-1 = $PREV_VERSION ($PREV_REF, $PREV_SHA)"

# The bundle the release shipped, byte for byte.
cp "$WORK/src-prev/$PREV_BUNDLE_PATH" "$WORK/bundle-prev/ash.mcpb"
PREV_BUNDLE="$WORK/bundle-prev/ash.mcpb"
say "N-1 bundle: $PREV_BUNDLE, as $PREV_RELEASE shipped it"

# --------------------------------------------------------------------------
# 3. The Inspector, locked, local to this run.
# --------------------------------------------------------------------------
INSPECTOR_VERSION="$(node -p 'require(process.argv[1]).dependencies["@modelcontextprotocol/inspector"]' "$INSPECTOR_LOCK/package.json")"
[ -n "$INSPECTOR_VERSION" ] || fail "no inspector version in $INSPECTOR_LOCK/package.json"
rm -rf "$WORK/inspector"
mkdir -p "$WORK/inspector"
cp "$INSPECTOR_LOCK/package.json" "$INSPECTOR_LOCK/package-lock.json" "$WORK/inspector/"
# npm ci installs exactly the lockfile, and fails if package.json disagrees with it.
npm ci --prefix "$WORK/inspector" --no-audit --no-fund
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
  --prev-bundle "$PREV_BUNDLE" \
  --prev-release "$PREV_RELEASE" \
  --wheel "$HEAD_WHEEL" \
  --prev-wheel "$PREV_WHEEL" \
  --inspector "$INSPECTOR" \
  --work "$WORK/run"
