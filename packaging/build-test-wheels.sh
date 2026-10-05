#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Builds the two wheels the native-package verifications consume, and gates both:
#
#   <outdir>/dist/       the wheel for this tree (N)
#   <outdir>/dist-prev/  the same tree with a LOWER version (N-1), for the upgrade legs
#
#   packaging/build-test-wheels.sh <outdir>
#
# Run inside the target container, from a checkout at $REPO (default: this script's
# repository). The source is copied out with `git archive` first, because the build
# hook writes into the tree it builds and the checkout may be read-only.
#
# WHY THE WHEELS ARE BUILT IN EACH LEG RATHER THAN ONCE AND DOWNLOADED
#
# A shared build job would have to upload the wheels as a workflow artifact, and on a
# public repository an artifact is downloadable by anyone. The N-1 wheel in particular
# is this tree's code labeled with a version it is not, which must never be something
# a stranger can download. Building per leg costs a few seconds of `uv build` and
# publishes nothing. The wheel is built the way ash-package.yml builds the gated one,
# and is gated here by the same check before anything packages it.
#
# N-1 is the last non-zero component of N decremented (3.7.0 -> 3.6.0). It is not a
# real release; it exists so the maintainer scripts run across a real version change.
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
PREV_VERSION="$(vl_lower_version "$VERSION")" || vl_fail "cannot derive a lower version from $VERSION"
vl_say "== building N=$VERSION and N-1=$PREV_VERSION"

export_tree() {
  local dest="$1"
  mkdir -p "$dest"
  # safe.directory because the checkout is usually owned by a different uid than the
  # root user running this in a container, and git refuses such a repository otherwise.
  git -c safe.directory="$REPO" -C "$REPO" archive HEAD | tar -x -C "$dest"
}

rm -rf "$OUTDIR/dist" "$OUTDIR/dist-prev"
TREE="$(mktemp -d)"
export_tree "$TREE/n"
uv build --quiet --wheel --out-dir "$OUTDIR/dist" "$TREE/n"

export_tree "$TREE/prev"
# Only [project]'s version line: commitizen's would otherwise change too.
sed -i "0,/^version = \"${VERSION}\"\$/s//version = \"${PREV_VERSION}\"/" "$TREE/prev/pyproject.toml"
grep -q "^version = \"${PREV_VERSION}\"\$" "$TREE/prev/pyproject.toml" \
  || vl_fail "could not set the N-1 version in the exported pyproject.toml"
uv build --quiet --wheel --out-dir "$OUTDIR/dist-prev" "$TREE/prev"
rm -rf "$TREE"

N_WHEEL="$OUTDIR/dist/automated_security_helper-${VERSION}-py3-none-any.whl"
PREV_WHEEL="$OUTDIR/dist-prev/automated_security_helper-${PREV_VERSION}-py3-none-any.whl"
[ -f "$N_WHEEL" ] || vl_fail "uv build did not write $N_WHEEL"
[ -f "$PREV_WHEEL" ] || vl_fail "uv build did not write $PREV_WHEEL"

vl_say "== gating both wheels with the artifact-contents check"
vl_gate_python "$REPO/.github/scripts/assert-artifact-contents.py" "$N_WHEEL" "$PREV_WHEEL"
