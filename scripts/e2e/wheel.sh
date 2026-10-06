#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# The wheel channel end to end:
#
#   scripts/e2e/wheel.sh <work-dir>
#
#   E2E_PYTHON    the interpreter version for the venvs (default 3.12)
#   E2E_PREV_REF  the git ref the N-1 wheel is built from (default origin/v4-capabilities).
#                 When it names a commit with HEAD's tree, as on a push to that branch,
#                 HEAD's first parent is used instead, so the upgrade still crosses a code
#                 change.
#
# 1. Builds the head wheel and an N-1 wheel, from `git archive` exports so the build
#    hook never writes into the checkout, and gates both with the artifact-contents check.
#    N-1 is E2E_PREV_REF's tree with its [project] version lowered (3.7.0 -> 3.6.0), the
#    same derivation packaging/build-test-wheels.sh uses, so the upgrade crosses a real
#    version change as well as a real code change. The lowered version must sort below
#    head's, or the "upgrade" would be a no-op or a downgrade.
# 2. Installs the head wheel into a fresh venv with --no-cache, checks the installed
#    version, and runs the three cases from tests/e2e/fixtures/cases.json through
#    scripts/e2e/run_case.py: findings (exit 2, 3 findings), clean (exit 0) and
#    incomplete (exit 1, opengrep MISSING).
# 3. Installs N-1 into a second fresh venv, scans the findings case with it, upgrades to
#    the head wheel in place, checks the version moved, and scans again.
# 4. Negative controls, each of which must be seen failing: the findings case scanned
#    with --no-fail-on-findings must fail, and on the exit code; the clean case's real
#    output judged as a findings outcome must fail; and the entry-point-absence check
#    run before uninstalling must fail.
# 5. Uninstalls from the first venv and requires every console script gone and the
#    package no longer importable.
#
# Runs on Linux, macOS and Windows (Git Bash on the hosted runners). Nothing is
# published: the wheels stay under <work-dir>, and the N-1 wheel carries a version
# that was never released, which is why it must never become a workflow artifact.
set -euo pipefail

WORK="${1:?usage: wheel.sh <work-dir>}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${E2E_PYTHON:-3.12}"
PREV_REF="${E2E_PREV_REF:-origin/v4-capabilities}"

# shellcheck source=packaging/cli-name.sh
. "$REPO/packaging/cli-name.sh"

# Every console script the wheel declares. Uninstall must remove all of them.
ENTRY_POINTS=("$ASH_CLI_NAME" ash ashv3 automated-security-helper)

say() { printf '== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# The harness runs under uv's interpreter, never under a venv being tested: the
# uninstall leg has to be able to judge a venv that no longer holds ASH.
harness() { uv run --no-project --python "$PYTHON" python "$@"; }

mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"

# A venv's executable, whichever layout the platform uses.
venv_exe() {
  local venv="$1" name="$2" candidate
  for candidate in "$venv/bin/$name" "$venv/Scripts/$name.exe" "$venv/Scripts/$name"; do
    if [ -f "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

venv_python() { venv_exe "$1" python; }

# -I and a neutral cwd: run from the checkout, `python -c` would put the source tree's
# automated_security_helper/ on sys.path and every import check would pass on the
# checkout rather than on the venv.
venv_run_python() {
  local venv="$1" py
  shift
  py="$(venv_python "$venv")" || return 1
  (cd "$WORK" && "$py" -I "$@")
}

installed_version() {
  venv_run_python "$1" -c 'import importlib.metadata as m; print(m.version("automated-security-helper"))'
}

importable() { venv_run_python "$1" -c 'import automated_security_helper' 2>/dev/null; }

# Lists each declared console script still present in the venv. Exits 0 only when none is.
assert_no_entry_points() {
  local venv="$1" name found=()
  for name in "${ENTRY_POINTS[@]}"; do
    if venv_exe "$venv" "$name" >/dev/null; then
      found+=("$name")
    fi
  done
  if [ "${#found[@]}" -ne 0 ]; then
    printf 'console scripts still present in %s: %s\n' "$venv" "${found[*]}" >&2
    return 1
  fi
  return 0
}

run_case() {
  local cli="$1" case_name="$2" label="$3"
  shift 3
  harness "$REPO/scripts/e2e/run_case.py" --cli "$cli" --case "$case_name" --work "$WORK/scans" --label "$label" -- "$@"
}

say "assert_outcome self-test"
harness "$REPO/scripts/e2e/assert_outcome.py" --self-test

# --------------------------------------------------------------------------
# 1. Build N and N-1.
# --------------------------------------------------------------------------
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$REPO/pyproject.toml" | head -n 1)"
[ -n "$VERSION" ] || fail "no [project] version in pyproject.toml"

HEAD_SHA="$(git -C "$REPO" rev-parse HEAD)"
PREV_SHA="$(git -C "$REPO" rev-parse --verify --quiet "$PREV_REF^{commit}")" \
  || fail "E2E_PREV_REF $PREV_REF does not name a commit"
tree_of() { git -C "$REPO" rev-parse "$1^{tree}"; }
# On a push to the N-1 branch itself, N-1 and HEAD are the same tree and the upgrade
# would cross no code change. Step back to HEAD's first parent; the workflow fetches
# enough history for it to exist.
if [ "$(tree_of "$PREV_SHA")" = "$(tree_of HEAD)" ]; then
  say "$PREV_REF has HEAD's tree; using HEAD's first parent as N-1"
  PREV_REF="HEAD^"
  PREV_SHA="$(git -C "$REPO" rev-parse --verify --quiet "HEAD^1^{commit}")" \
    || fail "HEAD has no parent in this clone; fetch at least one more commit of history"
  [ "$(tree_of "$PREV_SHA")" != "$(tree_of HEAD)" ] \
    || fail "HEAD's first parent has HEAD's tree too; there is no code change to upgrade across"
fi

rm -rf "$WORK/src-head" "$WORK/src-prev" "$WORK/dist-head" "$WORK/dist-prev"
mkdir -p "$WORK/src-head" "$WORK/src-prev"
git -C "$REPO" archive HEAD | tar -x -C "$WORK/src-head"
git -C "$REPO" archive "$PREV_SHA" | tar -x -C "$WORK/src-prev"

PREV_BASE_VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$WORK/src-prev/pyproject.toml" | head -n 1)"
[ -n "$PREV_BASE_VERSION" ] || fail "no [project] version in $PREV_REF's pyproject.toml"
# The last non-zero component decremented, as packaging/verify-lib.sh vl_lower_version does.
PREV_VERSION="$(printf '%s\n' "$PREV_BASE_VERSION" | awk -F. '{
  n = NF; while (n > 0 && $n == 0) n--;
  if (n == 0) { exit 1 }
  $n = $n - 1; for (i = n + 1; i <= NF; i++) $i = 0;
  out = $1; for (i = 2; i <= NF; i++) out = out "." $i; print out }')" \
  || fail "cannot derive a lower version from $PREV_BASE_VERSION"
# Only the first `version = ` line, which is [project]'s; commitizen's stays as it was.
harness - "$WORK/src-prev/pyproject.toml" "$PREV_BASE_VERSION" "$PREV_VERSION" <<'PY'
import sys
path, old, new = sys.argv[1:]
text = open(path, encoding="utf-8").read()
needle = f'\nversion = "{old}"\n'
if needle not in text:
    sys.exit(f"no [project] version line {old!r} in {path}")
open(path, "w", encoding="utf-8", newline="").write(text.replace(needle, f'\nversion = "{new}"\n', 1))
PY
# Release segments compared as integers, so 3.10.0 sorts above 3.9.0. A version that is
# not plain dotted integers is refused rather than guessed at.
harness - "$PREV_VERSION" "$VERSION" <<'PY' \
  || fail "N-1 version $PREV_VERSION does not sort below head's $VERSION; the upgrade would not move forward"
import re, sys
prev, head = sys.argv[1:]
for v in (prev, head):
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)*", v):
        sys.exit(f"version {v!r} is not dotted integers")
def key(v):
    parts = [int(p) for p in v.split(".")]
    return parts + [0] * (8 - len(parts))
sys.exit(0 if key(prev) < key(head) else 1)
PY
say "N = $VERSION at $HEAD_SHA; N-1 = $PREV_VERSION from $PREV_REF ($PREV_SHA)"

uv build --quiet --wheel --out-dir "$WORK/dist-head" "$WORK/src-head"
uv build --quiet --wheel --out-dir "$WORK/dist-prev" "$WORK/src-prev"
HEAD_WHEEL="$WORK/dist-head/automated_security_helper-${VERSION}-py3-none-any.whl"
PREV_WHEEL="$WORK/dist-prev/automated_security_helper-${PREV_VERSION}-py3-none-any.whl"
[ -f "$HEAD_WHEEL" ] || fail "uv build did not write $HEAD_WHEEL"
[ -f "$PREV_WHEEL" ] || fail "uv build did not write $PREV_WHEEL"

say "artifact-contents gate on both wheels"
harness "$REPO/.github/scripts/assert-artifact-contents.py" "$HEAD_WHEEL" "$PREV_WHEEL"

# --------------------------------------------------------------------------
# 2. Fresh install of N and the three cases.
# --------------------------------------------------------------------------
FRESH="$WORK/venv-fresh"
rm -rf "$FRESH"
uv venv --quiet --python "$PYTHON" "$FRESH"
uv pip install --quiet --no-cache --python "$(venv_python "$FRESH")" "$HEAD_WHEEL"
got="$(installed_version "$FRESH")"
[ "$got" = "$VERSION" ] || fail "fresh venv holds $got, expected $VERSION"
CLI="$(venv_exe "$FRESH" "$ASH_CLI_NAME")" || fail "the wheel installed no $ASH_CLI_NAME console script"
version_line="$("$CLI" --version)"
case "$version_line" in
  *"v$VERSION"*) say "$ASH_CLI_NAME --version: $version_line" ;;
  *) fail "$ASH_CLI_NAME --version printed '$version_line', expected v$VERSION" ;;
esac

run_case "$CLI" findings fresh-findings
run_case "$CLI" clean fresh-clean
run_case "$CLI" incomplete fresh-incomplete

# --------------------------------------------------------------------------
# 3. N-1, then upgrade in place to N.
# --------------------------------------------------------------------------
UPGRADE="$WORK/venv-upgrade"
rm -rf "$UPGRADE"
uv venv --quiet --python "$PYTHON" "$UPGRADE"
uv pip install --quiet --no-cache --python "$(venv_python "$UPGRADE")" "$PREV_WHEEL"
got="$(installed_version "$UPGRADE")"
[ "$got" = "$PREV_VERSION" ] || fail "N-1 venv holds $got, expected $PREV_VERSION"
# N-1 may predate the $ASH_CLI_NAME command; the v3 name is the one it is sure to have.
PREV_CLI="$(venv_exe "$UPGRADE" "$ASH_CLI_NAME" || venv_exe "$UPGRADE" ash)" \
  || fail "the N-1 wheel installed neither $ASH_CLI_NAME nor ash"
say "N-1 command: $(basename "$PREV_CLI")"
run_case "$PREV_CLI" findings upgrade-before

uv pip install --quiet --no-cache --python "$(venv_python "$UPGRADE")" "$HEAD_WHEEL"
got="$(installed_version "$UPGRADE")"
[ "$got" = "$VERSION" ] || fail "after the upgrade the venv holds $got, expected $VERSION"
UPGRADED_CLI="$(venv_exe "$UPGRADE" "$ASH_CLI_NAME")" || fail "the upgrade left no $ASH_CLI_NAME console script"
venv_exe "$UPGRADE" ash >/dev/null || fail "the upgrade removed the deprecated ash console script, which v4 keeps"
run_case "$UPGRADED_CLI" findings upgrade-after
say "upgraded $PREV_VERSION -> $VERSION in place"

# --------------------------------------------------------------------------
# 4. Negative controls.
# --------------------------------------------------------------------------
say "negative control: findings scanned with --no-fail-on-findings must fail the exit-code check"
rc=0
neg_log="$WORK/negative-no-fail-on-findings.log"
run_case "$CLI" findings negative-no-fail-on-findings --no-fail-on-findings >"$neg_log" 2>&1 || rc=$?
cat "$neg_log"
[ "$rc" -eq 1 ] || fail "NEGATIVE CONTROL: run_case returned $rc for a findings scan that exited 0; expected 1"
# rc 1 alone would also come from a missing report or a wrong count. The control only
# controls anything if the exit-code check is what fired.
grep -q "exit code 0 (nothing actionable), expected exactly 2" "$neg_log" \
  || fail "NEGATIVE CONTROL: run_case rejected the --no-fail-on-findings scan, but not for its exit code 0"
say "   OK: rejected for exit code 0 (exit $rc)"

say "negative control: the clean output judged as a findings outcome must fail"
rc=0
harness "$REPO/scripts/e2e/assert_outcome.py" --output-dir "$WORK/scans/fresh-clean/out" --rc 0 \
  --expect-rc 2 --min-findings 1 --require-scanner detect-secrets --selected detect-secrets || rc=$?
[ "$rc" -eq 1 ] || fail "NEGATIVE CONTROL: assert_outcome returned $rc on a clean output expected to hold findings"
say "   OK: rejected (exit $rc)"

say "negative control: the import check must see the package while it is installed"
importable "$FRESH" || fail "NEGATIVE CONTROL: the import check cannot import an installed package"
say "   OK: importable before uninstall"

say "negative control: the entry-point-absence check must fail while ASH is installed"
rc=0
assert_no_entry_points "$FRESH" || rc=$?
[ "$rc" -ne 0 ] || fail "NEGATIVE CONTROL: the absence check passed on a venv that still holds ASH"
say "   OK: rejected (exit $rc)"

# --------------------------------------------------------------------------
# 5. Uninstall.
# --------------------------------------------------------------------------
uv pip uninstall --quiet --python "$(venv_python "$FRESH")" automated-security-helper
assert_no_entry_points "$FRESH" || fail "uninstall left console scripts behind"
if importable "$FRESH"; then
  fail "automated_security_helper is still importable after uninstall"
fi
say "uninstalled: no console scripts left, package not importable"

say "wheel e2e passed: N=$VERSION ($HEAD_SHA), N-1=$PREV_VERSION ($PREV_REF $PREV_SHA), python $PYTHON"
