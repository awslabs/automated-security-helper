#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Usage: assert-deprecated-alias.sh
#
# Asserts that the deprecated `ash` console script an install put on PATH is the
# same program as `ashx`, plus exactly one deprecation line on stderr:
#
#   1. `ash --version` prints the same stdout as `ashx --version`, and exits with
#      the same code.
#   2. A command line the CLI rejects (an unknown option) exits with the same
#      non-zero code under both names, so the alias does not mask a failure.
#   3. In both runs, `ash`'s stderr carries the notice exactly once, and `ashx`'s
#      carries it zero times.
#
# `--help` is not compared byte for byte: the usage line names the program it was
# invoked as, so `ash --help` and `ashx --help` legitimately differ there.
#
# The notice text is automated_security_helper/cli/deprecations.py's
# deprecated_command_message("ash"). It is repeated here rather than imported
# because this runs against whatever the install method put on PATH, which may
# not be importable from the runner's own Python (pipx, uvx).
set -uo pipefail

NOTICE="warning: the 'ash' command is deprecated and is scheduled for removal; use 'ashx' instead."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

fail() {
  echo "::error::$*"
  failures=$((failures + 1))
}

# Runs "$1" with the remaining arguments, writing stdout, stderr (CR stripped,
# for Windows consoles) and the exit code under $work/<label>.
run_as() {
  local label="$1"
  shift
  "$@" >"$work/$label.out.raw" 2>"$work/$label.err.raw"
  echo "$?" >"$work/$label.rc"
  tr -d '\r' <"$work/$label.out.raw" >"$work/$label.out"
  tr -d '\r' <"$work/$label.err.raw" >"$work/$label.err"
}

notice_count() {
  grep -cxF -- "$NOTICE" "$1" || true
}

check_case() {
  local case_name="$1"
  shift
  run_as "ashx-$case_name" ashx "$@"
  run_as "ash-$case_name" ash "$@"
  local x_rc a_rc
  x_rc="$(cat "$work/ashx-$case_name.rc")"
  a_rc="$(cat "$work/ash-$case_name.rc")"
  echo "ashx $* exited ${x_rc}; ash $* exited ${a_rc}"
  if [ "$x_rc" != "$a_rc" ]; then
    fail "'ash $*' exited ${a_rc} but 'ashx $*' exited ${x_rc}. The deprecated alias must return the canonical command's exit code."
  fi
  local a_count x_count
  a_count="$(notice_count "$work/ash-$case_name.err")"
  x_count="$(notice_count "$work/ashx-$case_name.err")"
  if [ "$a_count" != "1" ]; then
    fail "'ash $*' printed the deprecation notice ${a_count} times on stderr; exactly 1 was expected. stderr was:"
    cat "$work/ash-$case_name.err"
  fi
  if [ "$x_count" != "0" ]; then
    fail "'ashx $*' printed the deprecation notice for 'ash' ${x_count} times; the canonical command must not print it."
  fi
}

check_case version --version
if [ "$(cat "$work/ashx-version.rc")" != "0" ]; then
  fail "'ashx --version' exited $(cat "$work/ashx-version.rc"); the comparison below is meaningless until it succeeds."
fi
if ! cmp -s "$work/ashx-version.out" "$work/ash-version.out"; then
  fail "'ash --version' and 'ashx --version' printed different stdout:"
  diff "$work/ashx-version.out" "$work/ash-version.out"
fi

check_case rejected --no-such-option-for-the-alias-check
if [ "$(cat "$work/ashx-rejected.rc")" = "0" ]; then
  fail "'ashx --no-such-option-for-the-alias-check' exited 0, so this case cannot show the alias preserves a non-zero exit code."
fi

if [ "$failures" -ne 0 ]; then
  echo "${failures} deprecated-alias check(s) failed."
  exit 1
fi
echo "The deprecated 'ash' alias matches 'ashx' and prints exactly one deprecation line."
