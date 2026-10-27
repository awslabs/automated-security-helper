#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Installs Formula/ash.rb with this machine's Homebrew, built from the commit under
# test, and checks that the installed ASH runs:
#
#   homebrew.sh <repo-dir> <tarball> <work-dir>
#
# <tarball> is `git archive --prefix=automated-security-helper-<version>/` of the
# commit, named automated-security-helper-<version>.tar.gz. The caller makes it, so
# this script needs only Homebrew and a Python 3 for the renderer.
#
# Formula/ash.rb builds the release tag on its `url` line, so it is not installed
# verbatim: .github/scripts/render-homebrew-formula.py writes a copy whose only
# change is that line, pointed at the tarball, into a local tap. Homebrew refuses
# formulae outside a tap. Nothing is pushed or published.
#
# This replaced a `ruby -c Formula/ash.rb` syntax check. The formula had no
# dependencies at all then; `brew install ash` succeeded and the first `ash` run
# died with "No module named 'typer'", which a syntax check cannot see.
set -euo pipefail

REPO="$(cd "${1:?usage: homebrew.sh <repo-dir> <tarball> <work-dir>}" && pwd)"
TARBALL="${2:?usage: homebrew.sh <repo-dir> <tarball> <work-dir>}"
WORK="${3:?usage: homebrew.sh <repo-dir> <tarball> <work-dir>}"
PYTHON="${PYTHON:-python3}"
TAP="ash-ci/local"
FORMULA="$TAP/ash"

# No auto-update: it would replace the brew under test partway through the job.
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_ANALYTICS=1 \
  HOMEBREW_NO_ENV_HINTS=1

say() { printf '== %s\n' "$*"; }
fail() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

# GitHub's Ubuntu images install Homebrew without putting it on PATH; macOS has it
# on PATH already.
if ! command -v brew >/dev/null 2>&1; then
  for candidate in /home/linuxbrew/.linuxbrew/bin/brew /opt/homebrew/bin/brew /usr/local/bin/brew; do
    if [ -x "$candidate" ]; then
      eval "$("$candidate" shellenv)"
      break
    fi
  done
fi
command -v brew >/dev/null 2>&1 || fail "Homebrew is not installed on this runner, so the formula cannot be tested here"
say "$(brew --version | head -n 1)"

version="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$REPO/pyproject.toml" | head -n 1)"
[ -n "$version" ] || fail "no [project] version in $REPO/pyproject.toml"
mkdir -p "$WORK"

if ! brew tap | grep -qx "$TAP"; then
  brew tap-new --no-git "$TAP"
fi
tap_dir="$(brew --repository "$TAP")"
"$PYTHON" "$REPO/.github/scripts/render-homebrew-formula.py" --formula "$REPO/Formula/ash.rb" \
  --tarball "$TARBALL" --version "$version" --out "$tap_dir/Formula/ash.rb"
say "the tap's formula differs from Formula/ash.rb only in its source:"
rc=0
diff -u "$REPO/Formula/ash.rb" "$tap_dir/Formula/ash.rb" || rc=$?
# 1 is "they differ", which the rendered copy must; 0 would mean the url line was
# not rewritten, and 2 that diff itself failed.
[ "$rc" -eq 1 ] || fail "diff of the tap's formula against Formula/ash.rb exited $rc, expected 1"

# Current Homebrew refuses to load a formula from a tap it has not been told to
# trust; older releases have no `brew trust` and no such check.
if brew help trust >/dev/null 2>&1; then
  brew trust "$TAP"
fi

brew install --formula --build-from-source "$FORMULA"
brew test "$FORMULA"

ash_bin="$(brew --prefix)/bin/ash"
line="$("$ash_bin" --version)" || fail "$ash_bin --version exited non-zero"
case "$line" in
  *"v$version"*) say "ash --version: $line" ;;
  *) fail "$ash_bin --version printed '$line', expected v$version" ;;
esac

# Local-mode scans. The first two are narrowed to detect-secrets for the reason
# action.yml gives; the second is the control that makes the first mean something:
# a scan that ran nothing would pass the clean case too.
clean="$WORK/clean"
planted="$WORK/planted"
mkdir -p "$clean" "$planted"
printf 'print("hello")\n' >"$clean/sample.py"
# Built at run time so this file does not itself carry a key header.
printf -- '-----BEGIN %s PRIVATE KEY-----\n' RSA >"$planted/key.pem"

rc=0
"$ash_bin" scan --source-dir "$clean" --output-dir "$WORK/out-clean" --simple \
  --phases scan --phases report --scanners detect-secrets || rc=$?
[ "$rc" -eq 0 ] || fail "scan of a clean directory exited $rc, expected 0"
say "clean scan: exit 0"

rc=0
"$ash_bin" scan --source-dir "$planted" --output-dir "$WORK/out-planted" --simple \
  --phases scan --phases report --scanners detect-secrets || rc=$?
[ "$rc" -eq 2 ] || fail "scan of a planted private key exited $rc, expected 2 (actionable findings)"
say "planted-key scan: exit 2"

# The committed fixture, tests/test_data/homebrew_scan: cdk-nag, which needs the
# cdk extra and Node.js that the formula installs, has to report the bucket in
# template.yaml, and bandit has to pass app.py. The scan must exit 2 and write its
# results. See scan-committed-fixture.sh.
PYTHON="$PYTHON" bash "$REPO/.github/actions/validate-install/scan-committed-fixture.sh" \
  "$ash_bin" "$REPO/tests/test_data/homebrew_scan" "$WORK"

# Precommit mode's fixed selection (bandit, detect-secrets, checkov, cdk-nag,
# npm-audit) is what the pre-commit hook runs. bandit and checkov are installed
# with the keg's uv at scan time and npm-audit needs Homebrew's npm, so this is
# the one scan here that uses every tool the formula provides.
rc=0
(cd "$clean" && "$ash_bin" --mode precommit --output-dir "$WORK/out-precommit") || rc=$?
[ "$rc" -eq 0 ] || fail "precommit-mode scan of a clean directory exited $rc, expected 0"
say "precommit-mode scan: exit 0"

# The default selection. Every scanner the formula provides for has to run, PASSED,
# FAILED or SKIPPED: the Python ones, cdk-nag and npm-audit. ERROR fails the check,
# as a crash is not a scan. gitleaks, grype, opengrep, syft, trivy and cfn-nag are
# separate programs the formula does not install (the README sends users to
# `ash dependencies install` and `gem install cfn-nag`), so they may be MISSING, and
# then the completeness gate exits 1. tests/unit/test_homebrew_formula_install.py
# pins this list.
rc=0
(cd "$clean" && "$ash_bin" scan --output-dir "$WORK/out-default") || rc=$?

# ASH does not print a scanner's own stderr when it refuses the scanner's result, so a
# scanner in ERROR leaves the job log with a summary and no cause. This prints what the
# scanner wrote, and what the host knew about memory, for the run that failed.
scanner_diagnostics() {
  echo "::group::scanner logs under $WORK/out-default"
  for log in "$WORK"/out-default/scanners/*/*/*.stderr.log; do
    [ -s "$log" ] || continue
    printf -- '-- %s (last 80 lines)\n' "$log"
    tail -n 80 "$log"
  done
  echo "::endgroup::"
  echo "::group::host memory and kernel kill messages"
  free -m || true
  ulimit -a || true
  (sudo -n dmesg 2>/dev/null || dmesg 2>/dev/null) | grep -i -E 'out of memory|oom|killed process|segfault|SIGSYS|audit.*seccomp' | tail -n 20 || true
  echo "::endgroup::"
}

missing="$("$PYTHON" "$REPO/.github/actions/validate-install/check-scanner-statuses.py" \
  "$WORK/out-default/ash_aggregated_results.json" --may-be-missing cfn-nag,gitleaks,grype,opengrep,syft,trivy)" ||
  {
    scanner_diagnostics
    fail "a default scan recorded a scanner the formula provides for as neither PASSED, FAILED nor SKIPPED (see above)"
  }
expected=0
[ -z "$missing" ] || expected=1
[ "$rc" -eq "$expected" ] || fail "a default scan of a clean directory exited $rc with MISSING: ${missing:-none}; expected $expected"
say "default scan: exit $rc, MISSING: ${missing:-none}"
