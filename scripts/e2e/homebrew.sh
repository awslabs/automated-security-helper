#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# The Homebrew channel end to end, built from the commit under test:
#
#   scripts/e2e/homebrew.sh fresh|upgrade|negative <work-dir>
#
#   E2E_HARNESS_PYTHON  the interpreter for the stdlib-only e2e scripts (default python3).
#                       It is never the keg's Python: the uninstall checks have to run
#                       after the keg is gone.
#   E2E_PREV_REF        the git ref the N-1 formula comes from (default latest-release:
#                       the latest published GitHub release, drafts and prereleases
#                       skipped; scripts/e2e/n1-ref.sh). A release's Formula/ash.rb is
#                       installed verbatim, from the tag it names, as a user on that
#                       release has it. Any other ref is rendered from a git archive of its
#                       tree at a lowered version. A named ref with HEAD's tree falls back
#                       to HEAD's first parent, as in scripts/e2e/wheel.sh.
#
# Formula/ash.rb builds from the release tag on its `url` line, so installing it
# verbatim tests the last release. Every leg here installs a copy written by
# scripts/e2e/brew_formula.py instead: the same formula, with that one line pointed at a
# `git archive` tarball of the tree under test. The release formula is never edited.
# The copy lives in a throwaway local tap, because Homebrew refuses a formula outside
# one, and nothing is pushed or published.
#
# Legs, one per CI matrix entry because each is a full source build of every resource:
#
#   fresh     install N, check the version, run the formula's own `brew test` (which
#             runs ashx and checks the deprecated ash alias), run
#             scripts/e2e/alias_check.sh on the linked ash and ashx (one notice, same
#             output and exit codes, and an ash printing it twice rejected), run the
#             three cases from tests/e2e/fixtures/cases.json through
#             scripts/e2e/run_case.py (exit 2 with 3 findings, exit 0, exit 1 with
#             opengrep MISSING), two negative controls,
#             then `brew uninstall` and require every link, the keg and the opt link gone.
#   upgrade   install N-1 (E2E_PREV_REF's tree and its own formula, version lowered),
#             scan with it, point the tap at N, `brew upgrade`, require N linked and the
#             N-1 keg still present until `brew cleanup` removes it, scan again,
#             uninstall.
#   negative  install N from a copy missing the detect-secrets resource. Homebrew installs
#             with --no-deps, so the install and `ashx --version` still succeed; the
#             findings case and `brew test` must both fail, and for that reason.
set -euo pipefail

LEG="${1:?usage: homebrew.sh fresh|upgrade|negative <work-dir>}"
WORK="${2:?usage: homebrew.sh fresh|upgrade|negative <work-dir>}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS_PYTHON="${E2E_HARNESS_PYTHON:-python3}"
PREV_REF="${E2E_PREV_REF:-latest-release}"

case "$LEG" in
  fresh | upgrade | negative) ;;
  *) printf 'usage: homebrew.sh fresh|upgrade|negative <work-dir>\n' >&2; exit 3 ;;
esac

# shellcheck source=packaging/cli-name.sh
. "$REPO/packaging/cli-name.sh"
# shellcheck source=scripts/e2e/n1-ref.sh
. "$REPO/scripts/e2e/n1-ref.sh"

# Every console script the wheel declares; Homebrew links each into its bin.
ENTRY_POINTS=("$ASH_CLI_NAME" ash ashv3 automated-security-helper)
TAP="ash/local"
FORMULA="$TAP/ash"
# The resource the negative leg removes. detect-secrets is the one scanner these cases
# select, and DetectSecretsScanner imports the library lazily, so `--version` still works
# without it and only a scan shows the hole.
DROPPED_RESOURCE="detect-secrets"

# No auto-update: it would rewrite the brew under test mid-job. No install cleanup: the
# upgrade leg has to see the N-1 keg survive `brew upgrade` before `brew cleanup` runs.
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_ANALYTICS=1 \
  HOMEBREW_NO_ENV_HINTS=1

say() { printf '== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
harness() { "$HARNESS_PYTHON" "$@"; }

mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"
BREW_PREFIX="$(brew --prefix)"
BREW_BIN="$BREW_PREFIX/bin"
KEGS="$(brew --cellar)/ash"
OPT_LINK="$BREW_PREFIX/opt/ash"

say "Homebrew: $(brew --version | head -n 1); harness: $("$HARNESS_PYTHON" --version 2>&1)"
harness "$REPO/scripts/e2e/assert_outcome.py" --self-test
ALIAS_ASSERT="$REPO/.github/actions/validate-install/assert-deprecated-alias.sh"
bash "$REPO/scripts/e2e/alias_check.sh" self-test "$ALIAS_ASSERT"

version_of() { sed -n 's/^version = "\(.*\)"$/\1/p' "$1/pyproject.toml" | head -n 1; }

# `brew list --versions ash` prints "ash 3.6.0 3.7.0"; this prints the versions only.
installed_versions() {
  local line
  line="$(brew list --versions "$FORMULA" 2>/dev/null)" || return 1
  printf '%s\n' "${line#ash }"
}

# Lists each console script, the keg directory or the opt link still present. Exits 0
# only when none is.
assert_uninstalled() {
  local name found=()
  for name in "${ENTRY_POINTS[@]}"; do
    if [ -e "$BREW_BIN/$name" ] || [ -L "$BREW_BIN/$name" ]; then
      found+=("$BREW_BIN/$name")
    fi
  done
  if [ -e "$KEGS" ]; then
    found+=("$KEGS")
  fi
  if [ -e "$OPT_LINK" ] || [ -L "$OPT_LINK" ]; then
    found+=("$OPT_LINK")
  fi
  if brew list --versions "$FORMULA" >/dev/null 2>&1; then
    found+=("brew still lists $FORMULA")
  fi
  if [ "${#found[@]}" -ne 0 ]; then
    printf 'still present: %s\n' "${found[*]}" >&2
    return 1
  fi
  return 0
}

run_case() {
  local cli="$1" case_name="$2" label="$3"
  shift 3
  harness "$REPO/scripts/e2e/run_case.py" --cli "$cli" --case "$case_name" --work "$WORK/scans" --label "$label" -- "$@"
}

require_version_line() {
  local cli="$1" version="$2" line
  line="$("$cli" --version)" || fail "$cli --version exited non-zero"
  case "$line" in
    *"v$version"*) say "$(basename "$cli") --version: $line" ;;
    *) fail "$cli --version printed '$line', expected v$version" ;;
  esac
}

# The tap is created once per runner; a rerun on the same machine reuses it.
TAP_DIR=""
ensure_tap() {
  if ! brew tap | grep -qx "$TAP"; then
    brew tap-new "$TAP"
  fi
  TAP_DIR="$(brew --repository "$TAP")"
  mkdir -p "$TAP_DIR/Formula"
}

# Puts a rendered formula into the tap and shows that it differs from the formula it
# was rendered from only where brew_formula.py is meant to change it.
use_formula() {
  local rendered="$1" source_formula="$2"
  cp "$rendered" "$TAP_DIR/Formula/ash.rb"
  say "tap formula vs $source_formula:"
  local rc=0
  diff -u "$source_formula" "$TAP_DIR/Formula/ash.rb" || rc=$?
  # 1 is "they differ", which a rendered copy always must; 0 means the url line was
  # not rewritten and 2 means diff itself failed.
  [ "$rc" -eq 1 ] || fail "diff of the tap formula against $source_formula exited $rc, expected 1"
}

# A tarball of a tree, with the one top-level directory Homebrew expects to cd into.
tarball_of_head() {
  local version="$1" out="$2"
  n1_tarball HEAD "automated-security-helper-$version/" "$out"
}

render() {
  local formula="$1" tarball="$2" version="$3" out="$4"
  shift 4
  harness "$REPO/scripts/e2e/brew_formula.py" --formula "$formula" --tarball "$tarball" \
    --version "$version" --out "$out" "$@"
}

ensure_tap
if brew list --versions "$FORMULA" >/dev/null 2>&1; then
  fail "$FORMULA is already installed on this machine; a fresh-install leg needs it absent"
fi
assert_uninstalled || fail "leftovers from an earlier install; a fresh-install leg needs none"

VERSION="$(version_of "$REPO")"
[ -n "$VERSION" ] || fail "no [project] version in pyproject.toml"
HEAD_SHA="$(n1_head_sha)"
HEAD_TARBALL="$WORK/automated-security-helper-$VERSION.tar.gz"
tarball_of_head "$VERSION" "$HEAD_TARBALL"
HEAD_FORMULA="$WORK/formula-head/ash.rb"
render "$REPO/Formula/ash.rb" "$HEAD_TARBALL" "$VERSION" "$HEAD_FORMULA"
say "N = $VERSION at $HEAD_SHA"

uninstall_and_check() {
  say "negative control: the uninstall check must fail while ASH is installed"
  local rc=0
  assert_uninstalled 2>/dev/null || rc=$?
  [ "$rc" -ne 0 ] || fail "NEGATIVE CONTROL: the uninstall check passed with $FORMULA installed"
  say "   OK: rejected (exit $rc)"
  brew uninstall --formula "$FORMULA"
  assert_uninstalled || fail "brew uninstall left ASH behind"
  say "uninstalled: no links, no keg, no opt link, not listed"
}

leg_fresh() {
  use_formula "$HEAD_FORMULA" "$REPO/Formula/ash.rb"
  brew install --verbose --build-from-source --formula "$FORMULA"
  local got
  got="$(installed_versions)" || fail "brew does not list $FORMULA after installing it"
  [ "$got" = "$VERSION" ] || fail "brew lists ash $got, expected exactly $VERSION"
  local cli="$BREW_BIN/$ASH_CLI_NAME"
  [ -x "$cli" ] || fail "the install linked no $ASH_CLI_NAME into $BREW_BIN"
  require_version_line "$cli" "$VERSION"

  # The formula's own test block: ashx --version, the ash alias's deprecation line on
  # stderr, and a real scan with a non-zero SARIF count.
  brew test --verbose "$FORMULA"

  # The test block's assert_match passes on a notice printed twice and never compares
  # exit codes. The check pip and the container image get does both: exactly one notice,
  # and the same stdout and exit code as ashx. It then shows itself rejecting an ash
  # that prints the notice twice.
  PATH="$BREW_BIN:$PATH" bash "$REPO/scripts/e2e/alias_check.sh" check "$ALIAS_ASSERT" \
    || fail "the deprecated ash alias Homebrew linked is not ashx with one notice"

  run_case "$cli" findings fresh-findings
  run_case "$cli" clean fresh-clean
  run_case "$cli" incomplete fresh-incomplete

  say "negative control: findings scanned with --no-fail-on-findings must fail the exit-code check"
  local rc=0 log="$WORK/negative-no-fail-on-findings.log"
  run_case "$cli" findings negative-no-fail-on-findings --no-fail-on-findings >"$log" 2>&1 || rc=$?
  cat "$log"
  [ "$rc" -eq 1 ] || fail "NEGATIVE CONTROL: run_case returned $rc for a findings scan that exited 0; expected 1"
  grep -q "exit code 0 (nothing actionable), expected exactly 2" "$log" \
    || fail "NEGATIVE CONTROL: run_case rejected the --no-fail-on-findings scan, but not for its exit code 0"
  say "   OK: rejected for exit code 0 (exit $rc)"

  uninstall_and_check
  say "Homebrew fresh leg passed: $VERSION ($HEAD_SHA)"
}

leg_upgrade() {
  local prev_sha
  # N-1 is the latest published release by default, which carries its own formula.
  n1_resolve Formula/ash.rb pyproject.toml
  prev_sha="$PREV_SHA"

  local prev_root="$WORK/src-prev" base_version prev_version
  rm -rf "$prev_root"
  mkdir -p "$prev_root/tree"
  n1_export "$prev_sha" "$prev_root/tree"
  base_version="$(version_of "$prev_root/tree")"
  [ -n "$base_version" ] || fail "no [project] version in $PREV_REF's pyproject.toml"
  # A release keeps its own version; a development commit is lowered (n1-ref.sh).
  prev_version="$(n1_prev_version "$base_version" "$VERSION")"
  if [ "${N1_IS_RELEASE:-no}" = yes ]; then
    # The release's formula verbatim: its url names the release tag on GitHub, and
    # Homebrew fetches that, exactly as `brew install ash` did for a user of it.
    say "N-1 = $prev_version, the published $PREV_REF's own formula, installed verbatim"
    cp "$prev_root/tree/Formula/ash.rb" "$TAP_DIR/Formula/ash.rb"
    grep -q "tag: \"v$prev_version\"" "$TAP_DIR/Formula/ash.rb" \
      || fail "the $PREV_REF formula does not name tag v$prev_version"
  else
    if [ "$prev_version" != "$base_version" ]; then
      harness - "$prev_root/tree/pyproject.toml" "$base_version" "$prev_version" <<'PY'
import sys
path, old, new = sys.argv[1:]
text = open(path, encoding="utf-8").read()
needle = f'\nversion = "{old}"\n'
if needle not in text:
    sys.exit(f"no [project] version line {old!r} in {path}")
open(path, "w", encoding="utf-8", newline="").write(text.replace(needle, f'\nversion = "{new}"\n', 1))
PY
    fi
    mv "$prev_root/tree" "$prev_root/automated-security-helper-$prev_version"
    local prev_tarball="$WORK/automated-security-helper-$prev_version.tar.gz"
    tar -C "$prev_root" -czf "$prev_tarball" "automated-security-helper-$prev_version"
    # N-1's own formula, so its resource block matches its own dependencies.
    local prev_formula="$WORK/formula-prev/ash.rb"
    render "$prev_root/automated-security-helper-$prev_version/Formula/ash.rb" \
      "$prev_tarball" "$prev_version" "$prev_formula"
    say "N-1 = $prev_version from $PREV_REF ($prev_sha)"
    use_formula "$prev_formula" "$prev_root/automated-security-helper-$prev_version/Formula/ash.rb"
  fi
  brew install --verbose --build-from-source --formula "$FORMULA"
  local got prev_cli
  got="$(installed_versions)" || fail "brew does not list $FORMULA after installing N-1"
  [ "$got" = "$prev_version" ] || fail "brew lists ash $got, expected exactly $prev_version"
  # N-1 may predate the $ASH_CLI_NAME command; the v3 name is the one it is sure to have.
  if [ -x "$BREW_BIN/$ASH_CLI_NAME" ]; then
    prev_cli="$BREW_BIN/$ASH_CLI_NAME"
  elif [ -x "$BREW_BIN/ash" ]; then
    prev_cli="$BREW_BIN/ash"
  else
    fail "the N-1 install linked neither $ASH_CLI_NAME nor ash"
  fi
  local defect_rc=2
  if [ "${N1_IS_RELEASE:-no}" = yes ]; then
    # A release's keg may carry a defect it shipped with, recorded exactly in
    # scripts/e2e/release_defects.py (v3.7.1's formula installs ASH without its
    # dependencies). Exit 0 means it showed exactly that defect, 2 that the release has
    # none recorded and must work, anything else that it failed some other way.
    local version_rc=0
    "$prev_cli" --version >"$WORK/n1-version.log" 2>&1 || version_rc=$?
    cat "$WORK/n1-version.log"
    defect_rc=0
    harness "$REPO/scripts/e2e/release_defects.py" homebrew-version --release "${PREV_REF%% *}" \
      --rc "$version_rc" --output "$WORK/n1-version.log" || defect_rc=$?
    [ "$defect_rc" -eq 0 ] || [ "$defect_rc" -eq 2 ] \
      || fail "the $PREV_REF keg did not show its recorded defect; see above"
  fi
  if [ "$defect_rc" -eq 0 ]; then
    say "N-1 is the $PREV_REF keg as its users have it, which cannot start; the upgrade must repair it"
  else
    require_version_line "$prev_cli" "$prev_version"
    if [ "${N1_IS_RELEASE:-no}" = yes ]; then
      # A v3 release reports scanners it was not told to run MISSING when their tools
      # are absent (v4: SKIPPED); only its own scan is judged with that allowance.
      harness "$REPO/scripts/e2e/run_case.py" --cli "$prev_cli" --case findings --work "$WORK/scans" \
        --label upgrade-before --allow-unselected-missing
    else
      run_case "$prev_cli" findings upgrade-before
    fi
  fi

  use_formula "$HEAD_FORMULA" "$REPO/Formula/ash.rb"
  brew upgrade --verbose --build-from-source --formula "$FORMULA"
  [ -d "$KEGS/$VERSION" ] || fail "brew upgrade did not create the $VERSION keg"
  [ -d "$KEGS/$prev_version" ] \
    || fail "the $prev_version keg is gone before brew cleanup, so this leg cannot show cleanup removes it"
  local opt_target
  opt_target="$(cd "$OPT_LINK" && pwd -P)" || fail "no opt link at $OPT_LINK after the upgrade"
  [ "$opt_target" = "$(cd "$KEGS/$VERSION" && pwd -P)" ] \
    || fail "$OPT_LINK resolves to $opt_target, not the $VERSION keg"
  local cli="$BREW_BIN/$ASH_CLI_NAME"
  [ -x "$cli" ] || fail "the upgrade linked no $ASH_CLI_NAME"
  [ -x "$BREW_BIN/ash" ] || fail "the upgrade unlinked the deprecated ash command, which Homebrew keeps"
  require_version_line "$cli" "$VERSION"

  brew cleanup --prune=all "$FORMULA"
  [ ! -e "$KEGS/$prev_version" ] || fail "brew cleanup left the $prev_version keg in $KEGS"
  got="$(installed_versions)" || fail "brew does not list $FORMULA after cleanup"
  [ "$got" = "$VERSION" ] || fail "after cleanup brew lists ash $got, expected exactly $VERSION"
  say "upgraded $prev_version -> $VERSION; cleanup removed the old keg"

  run_case "$cli" findings upgrade-after
  # The formula's own test on the upgraded keg, the check v3.7.1's keg fails.
  brew test --verbose "$FORMULA"
  uninstall_and_check
  say "Homebrew upgrade leg passed: $prev_version ($PREV_REF $prev_sha) -> $VERSION ($HEAD_SHA)"
}

leg_negative() {
  local broken="$WORK/formula-broken/ash.rb"
  render "$REPO/Formula/ash.rb" "$HEAD_TARBALL" "$VERSION" "$broken" --drop-resource "$DROPPED_RESOURCE"
  use_formula "$broken" "$REPO/Formula/ash.rb"

  say "a formula missing the $DROPPED_RESOURCE resource still installs, because pip runs with --no-deps"
  brew install --verbose --build-from-source --formula "$FORMULA"
  local cli="$BREW_BIN/$ASH_CLI_NAME"
  [ -x "$cli" ] || fail "the broken formula linked no $ASH_CLI_NAME, so this control shows nothing about scans"
  require_version_line "$cli" "$VERSION"

  say "negative control: the findings case must fail on this install"
  local rc=0 log="$WORK/negative-missing-resource.log"
  run_case "$cli" findings negative-missing-resource >"$log" 2>&1 || rc=$?
  cat "$log"
  [ "$rc" -eq 1 ] || fail "NEGATIVE CONTROL: run_case returned $rc on an install without $DROPPED_RESOURCE; expected 1"
  grep -q "scanners did not complete: $DROPPED_RESOURCE=MISSING" "$log" \
    || fail "NEGATIVE CONTROL: the findings case failed, but not because $DROPPED_RESOURCE was MISSING"
  say "   OK: rejected, $DROPPED_RESOURCE MISSING (exit $rc)"

  say "negative control: the formula's own test block must fail on this install"
  rc=0
  log="$WORK/negative-brew-test.log"
  brew test --verbose "$FORMULA" >"$log" 2>&1 || rc=$?
  cat "$log"
  [ "$rc" -ne 0 ] || fail "NEGATIVE CONTROL: brew test passed on an install without $DROPPED_RESOURCE"
  # The test block's scan is what has to fail, not its --version or alias checks.
  grep -q "$DROPPED_RESOURCE: MISSING" "$log" \
    || fail "NEGATIVE CONTROL: brew test failed, but not on its scan reporting $DROPPED_RESOURCE MISSING"
  say "   OK: brew test failed on its scan, $DROPPED_RESOURCE MISSING (exit $rc)"

  uninstall_and_check
  say "Homebrew negative leg passed: a missing resource fails the scan and brew test"
}

"leg_$LEG"
