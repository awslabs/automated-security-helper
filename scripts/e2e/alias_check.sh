#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Runs .github/actions/validate-install/assert-deprecated-alias.sh for an e2e channel,
# and shows it failing:
#
#   scripts/e2e/alias_check.sh self-test <assert-deprecated-alias.sh>
#   scripts/e2e/alias_check.sh check     <assert-deprecated-alias.sh>
#
# self-test  needs no install. Builds stub `ashx` and `ash` commands in a scratch PATH
#            and runs the check against each: a correct alias must pass, and an alias
#            that prints the notice twice or not at all, an alias that returns 0 where
#            ashx fails, an `ashx` that prints the notice, and an alias whose --version
#            output differs must each fail, with that defect's own message.
# check      runs the check against the `ash` and `ashx` on PATH, which must pass. Then,
#            as the negative control on the same install, puts a wrapper in front of the
#            real `ash` that prints the notice one extra time, and requires the check to
#            reject it for printing the notice twice.
#
# The scripts/e2e Homebrew leg runs both on the runner. The container leg runs
# self-test on the runner and check inside the image, with both scripts mounted
# read-only, so the image under test is the one that was built.
#
# The notice text is read from the assert script, so the two cannot disagree about it.
set -uo pipefail

MODE="${1:?usage: alias_check.sh self-test|check <assert-deprecated-alias.sh>}"
ASSERT="${2:?usage: alias_check.sh self-test|check <assert-deprecated-alias.sh>}"
[ -f "$ASSERT" ] || { printf 'FAIL: no assert script at %s\n' "$ASSERT" >&2; exit 1; }

NOTICE="$(sed -n 's/^NOTICE="\(.*\)"$/\1/p' "$ASSERT")"
[ -n "$NOTICE" ] || { printf 'FAIL: no NOTICE="..." line in %s\n' "$ASSERT" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

say() { printf '== %s\n' "$*"; }
bad() {
  printf 'FAIL: %s\n' "$*" >&2
  failures=$((failures + 1))
}

# expect_rejected <label> <message> <PATH>: the check must exit 1 and print <message>.
expect_rejected() {
  local label="$1" message="$2" path="$3" rc=0 log="$work/$1.log"
  PATH="$path" bash "$ASSERT" >"$log" 2>&1 || rc=$?
  if [ "$rc" -ne 1 ]; then
    cat "$log"
    bad "$label: the alias check exited $rc, expected 1"
  elif ! grep -qF -- "$message" "$log"; then
    cat "$log"
    bad "$label: the alias check failed, but without '$message'"
  else
    say "   OK: $label rejected (exit $rc)"
  fi
}

# stub <dir> <name> <notices> <version line> <rejected rc>: a command that prints the
# notice <notices> times on stderr, then answers --version with <version line> and exit
# 0, and anything else with exit <rejected rc>.
stub() {
  local dir="$1" name="$2" notices="$3" version="$4" rejected_rc="$5"
  mkdir -p "$dir"
  cat >"$dir/$name" <<EOF
#!/bin/sh
i=0
while [ "\$i" -lt $notices ]; do printf '%s\n' "$NOTICE" >&2; i=\$((i + 1)); done
if [ "\$1" = "--version" ]; then echo "$version"; exit 0; fi
echo "error: no such option: \$1" >&2
exit $rejected_rc
EOF
  chmod +x "$dir/$name"
}

self_test() {
  local good="ash v9.9.9" base="/usr/bin:/bin"
  say "self-test: stub ash/ashx pairs through $(basename "$ASSERT")"

  stub "$work/ok" ashx 0 "$good" 2
  stub "$work/ok" ash 1 "$good" 2
  local rc=0
  PATH="$work/ok:$base" bash "$ASSERT" >"$work/ok.log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    cat "$work/ok.log"
    bad "a correct alias (one notice, same output and exit codes) was rejected, exit $rc"
  else
    say "   OK: a correct alias passes"
  fi

  stub "$work/twice" ashx 0 "$good" 2
  stub "$work/twice" ash 2 "$good" 2
  expect_rejected twice "printed the deprecation notice 2 times on stderr; exactly 1 was expected" \
    "$work/twice:$base"

  stub "$work/silent" ashx 0 "$good" 2
  stub "$work/silent" ash 0 "$good" 2
  expect_rejected silent "printed the deprecation notice 0 times on stderr; exactly 1 was expected" \
    "$work/silent:$base"

  stub "$work/masked" ashx 0 "$good" 2
  stub "$work/masked" ash 1 "$good" 0
  expect_rejected masked-exit-code \
    "exited 0 but 'ashx --no-such-option-for-the-alias-check' exited 2" "$work/masked:$base"

  stub "$work/loud" ashx 1 "$good" 2
  stub "$work/loud" ash 1 "$good" 2
  expect_rejected canonical-prints-notice "the canonical command must not print it" "$work/loud:$base"

  stub "$work/drift" ashx 0 "$good" 2
  stub "$work/drift" ash 1 "ash v0.0.1" 2
  expect_rejected version-differs "printed different stdout" "$work/drift:$base"
}

check() {
  say "the ash alias on PATH: $(command -v ash || echo none); ashx: $(command -v ashx || echo none)"
  local rc=0
  bash "$ASSERT" || rc=$?
  if [ "$rc" -ne 0 ]; then
    bad "the installed ash alias failed the check, exit $rc"
    return
  fi

  say "negative control: an ash that prints the notice twice must be rejected"
  local real
  real="$(command -v ash)" || { bad "no ash on PATH to wrap"; return; }
  mkdir -p "$work/wrap"
  cat >"$work/wrap/ash" <<EOF
#!/bin/sh
printf '%s\n' "$NOTICE" >&2
exec "$real" "\$@"
EOF
  chmod +x "$work/wrap/ash"
  expect_rejected installed-ash-twice \
    "printed the deprecation notice 2 times on stderr; exactly 1 was expected" "$work/wrap:$PATH"
}

case "$MODE" in
  self-test) self_test ;;
  check) check ;;
  *) printf 'usage: alias_check.sh self-test|check <assert-deprecated-alias.sh>\n' >&2; exit 3 ;;
esac

if [ "$failures" -ne 0 ]; then
  printf '%s alias-check expectation(s) failed.\n' "$failures" >&2
  exit 1
fi
say "alias_check $MODE passed"
