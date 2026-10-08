#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Builds the two wheels the native-package verifications consume, and gates both:
#
#   <outdir>/dist/       the wheel for this tree (N)
#   <outdir>/dist-prev/  the wheel for N-1: the previous commit (packaging/n1-source.sh)
#                        with its version lowered, built from that commit's own tree
#   <outdir>/prev/src/   that commit's tree, whose packaging/ the upgrade legs build
#                        the N-1 package with
#   <outdir>/n1.env      N1_SHA, N1_REF, N1_HEAD and N1_VERSION, for the legs' logs
#   <outdir>/dist-release/  with N1_BUILD_RELEASE=1 only: the wheel of the latest
#                        published release, built from its tag at its own version, for
#                        the from-release legs (verify-lib.sh vl_from_release). Needs the
#                        GitHub releases API (GITHUB_TOKEN raises its rate limit).
#
#   packaging/build-test-wheels.sh <outdir>
#
# Run inside the target container, from a checkout at $REPO (default: this script's
# repository) with its full history: N-1 is derived from the history, and a shallow
# clone fails the derivation and says so. The sources are exported with `git archive`
# first, because the build hook writes into the tree it builds and the checkout may be
# read-only.
#
# WHY THE WHEELS ARE BUILT IN EACH LEG RATHER THAN ONCE AND DOWNLOADED
#
# A shared build job would have to upload the wheels as a workflow artifact, and on a
# public repository an artifact is downloadable by anyone. The N-1 wheel in particular
# carries a version it is not, which must never be something a stranger can download.
# Building per leg costs a few seconds of `uv build` and publishes nothing. The wheel is
# built the way ash-package.yml builds the gated one, and is gated here by the same
# check before anything packages it.
#
# N-1's version is its own [project] version with the last non-zero component
# decremented (4.0.0 -> 3.0.0). It is not a real release; it makes the upgrade cross a
# real version change as well as a real code change.
set -euo pipefail

OUTDIR="${1:?usage: build-test-wheels.sh <outdir>}"
REPO="${REPO:-$(cd "$(dirname "$0")/.." && pwd)}"

# shellcheck source=packaging/verify-lib.sh
. "$REPO/packaging/verify-lib.sh"

vl_install_harness_tools
command -v git >/dev/null || vl_fail "git is required to export the tree"

# The first `version = ` line is [project]'s; `T;q` stops sed there, so the
# commitizen table's `version` is never read.
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p;T;q' "$REPO/pyproject.toml")"
[ -n "$VERSION" ] || vl_fail "no [project] version in $REPO/pyproject.toml"
vl_say "== building N=$VERSION, and N-1 from the history"

export_tree() {
  local dest="$1"
  mkdir -p "$dest"
  # safe.directory because the checkout is usually owned by a different uid than the
  # root user running this in a container, and git refuses such a repository otherwise.
  git -c safe.directory="$REPO" -C "$REPO" archive HEAD | tar -x -C "$dest"
}

# shellcheck source=packaging/n1-source.sh
. "$REPO/packaging/n1-source.sh"

rm -rf "$OUTDIR/dist" "$OUTDIR/dist-prev" "$OUTDIR/prev" "$OUTDIR/n1.env"
TREE="$(mktemp -d)"
export_tree "$TREE/n"
uv build --quiet --wheel --out-dir "$OUTDIR/dist" "$TREE/n"
rm -rf "$TREE"

n1_export "$OUTDIR/prev"
# The export is kept: the upgrade legs build N-1's package with its own packaging/.
# Its wheel is built from a copy, for the same reason N's is.
TREE="$(mktemp -d)"
cp -R "$N1_SRC" "$TREE/prev"
uv build --quiet --wheel --out-dir "$OUTDIR/dist-prev" "$TREE/prev"
rm -rf "$TREE"
{
  printf 'N1_SHA=%s\n' "$N1_SHA"
  printf 'N1_REF=%s\n' "$N1_REF"
  printf 'N1_HEAD=%s\n' "$N1_HEAD"
  printf 'N1_VERSION=%s\n' "$N1_VERSION"
} >"$OUTDIR/n1.env"

rm -rf "$OUTDIR/dist-release" "$OUTDIR/release"
if [ "${N1_BUILD_RELEASE:-}" = 1 ]; then
  # The latest published release, as `uv tool install git+...@<tag>` builds it: its
  # own tree at its own version. prev_tree.py fetches the tag if the clone lacks it.
  vl_say "== building the latest published release's wheel"
  release_json="$(GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0="$REPO" \
    vl_gate_python "$N1_PREV_TREE" --repo "$REPO" --prev-ref latest-release \
    --require pyproject.toml --out "$OUTDIR/release")" \
    || vl_fail "cannot derive the latest published release (scripts/e2e/prev_tree.py above says why)"
  vl_say "   $release_json"
  TREE="$(mktemp -d)"
  cp -R "$OUTDIR/release/src" "$TREE/release"
  uv build --quiet --wheel --out-dir "$OUTDIR/dist-release" "$TREE/release"
  rm -rf "$TREE"
fi

N_WHEEL="$OUTDIR/dist/automated_security_helper-${VERSION}-py3-none-any.whl"
PREV_WHEEL="$OUTDIR/dist-prev/automated_security_helper-${N1_VERSION}-py3-none-any.whl"
[ -f "$N_WHEEL" ] || vl_fail "uv build did not write $N_WHEEL"
[ -f "$PREV_WHEEL" ] || vl_fail "uv build did not write $PREV_WHEEL"

# Each wheel by its own tree's gate. N-1's tree is older code, and a commit that
# tightens the gate together with what it ships would otherwise fail N-1 for a rule
# N-1 was never written against.
vl_say "== gating each wheel with its own tree's artifact-contents check"
vl_gate_python "$REPO/.github/scripts/assert-artifact-contents.py" "$N_WHEEL"
vl_gate_python "$N1_SRC/.github/scripts/assert-artifact-contents.py" "$PREV_WHEEL"
