#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# The plugin against a real ASH CLI built from this checkout, headless:
#
#   bash editors/jetbrains/e2e-real-cli.sh <work-dir>
#
# 1. Builds the wheel from a `git archive` of HEAD (so the build never writes into the
#    checkout) and installs it with --no-cache into a fresh venv, then checks the installed
#    console scripts answer `--version` with the head's version.
# 2. Negative control first: the real-CLI suite pointed at an empty directory must FAIL, and
#    fail because the CLI is absent. This is what proves the suite fails rather than skips
#    when its input is missing.
# 3. Runs the suite (`realCliTest`) against the venv, then its census (`assertRealCliTestsRan`).
#    AshScanRealCliTest runs each case in tests/e2e/fixtures/cases.json through the plugin and
#    judges the result with scripts/e2e/assert_outcome.py plus the plugin's own notifications,
#    highlights and coverage reading, and covers the fallback from `ashx` to `ash`.
#
# Needs a JDK 21, python3, git and uv on PATH; ash-jetbrains-ci.yml runs it in gradle:jdk21
# with uv from setup-uv. Nothing is published.
set -euo pipefail

WORK="${1:?usage: e2e-real-cli.sh <work-dir>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

# Never as root, for the reason verify-in-container.sh gives.
if [ "$(id -u)" = 0 ]; then
  exec bash "$HERE/run-unprivileged.sh" bash "$HERE/e2e-real-cli.sh" "$@"
fi

say() { printf '== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# shellcheck source=../../packaging/cli-name.sh
. "$REPO/packaging/cli-name.sh"
FALLBACK_NAME=ash

mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"
cd "$HERE"

say "provision defusedxml for the test census"
. "$HERE/provision-defusedxml.sh"

# --------------------------------------------------------------------------
# 1. Build the head wheel and install it fresh.
# --------------------------------------------------------------------------
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$REPO/pyproject.toml" | head -n 1)"
[ -n "$VERSION" ] || fail "no [project] version in pyproject.toml"
say "build the wheel ($VERSION) from HEAD $(git -C "$REPO" rev-parse HEAD)"
rm -rf "$WORK/src" "$WORK/dist" "$WORK/venv" "$WORK/empty-bin"
mkdir -p "$WORK/src" "$WORK/empty-bin"
git -C "$REPO" archive HEAD | tar -x -C "$WORK/src"
uv build --quiet --wheel --out-dir "$WORK/dist" "$WORK/src"
WHEEL="$WORK/dist/automated_security_helper-${VERSION}-py3-none-any.whl"
[ -f "$WHEEL" ] || fail "uv build did not write $WHEEL"

say "install it into a fresh venv"
# The image's python3, so the venv needs no interpreter download. uv provides the install,
# since the image has no pip.
uv venv --quiet --python "$(command -v python3)" "$WORK/venv"
uv pip install --quiet --no-cache --python "$WORK/venv/bin/python" "$WHEEL"
for name in "$ASH_CLI_NAME" "$FALLBACK_NAME"; do
  [ -x "$WORK/venv/bin/$name" ] || fail "the wheel installed no $name console script"
  # Without the vendored PYTHONPATH, as AshScanRealCliTest's wrapper runs the CLI: the
  # installed wheel has to work from its own venv alone.
  line="$(env -u PYTHONPATH -u PYTHONHOME "$WORK/venv/bin/$name" --version)" \
    || fail "$name --version failed from the venv alone; the wheel may be missing a requirement"
  case "$line" in
    *"v$VERSION"*) printf '   %s --version: %s\n' "$name" "$line" ;;
    *) fail "$name --version printed '$line', expected v$VERSION" ;;
  esac
done

# --------------------------------------------------------------------------
# 2. Negative control: no CLI where the suite is told to look.
# --------------------------------------------------------------------------
say "negative control: the real-CLI suite with no CLI installed must fail"
if ASH_JB_REAL_CLI_BIN="$WORK/empty-bin" ./gradlew --no-daemon --console=plain realCliTest > "$WORK/negative.log" 2>&1; then
  tail -n 30 "$WORK/negative.log"
  fail "realCliTest passed with no CLI installed; the suite cannot fail on a missing CLI"
fi
# Matched without the quotes around the name, which the JUnit XML may write as &apos;.
if ! cat build/test-results/realCliTest/TEST-*.xml | grep -q "holds no executable"; then
  tail -n 30 "$WORK/negative.log"
  fail "realCliTest failed, but not because the CLI was missing; see the log above"
fi
printf '   failed as required: %s test(s) reported the missing CLI\n' "$(cat build/test-results/realCliTest/TEST-*.xml | grep -c '<failure')"

# --------------------------------------------------------------------------
# 3. The suite against the real CLI, and its census.
# --------------------------------------------------------------------------
say "the real-CLI suite against $WORK/venv/bin"
ASH_JB_REAL_CLI_BIN="$WORK/venv/bin" ./gradlew --no-daemon --console=plain realCliTest assertRealCliTestsRan

echo
echo "JETBRAINS REAL-CLI E2E PASSED"
