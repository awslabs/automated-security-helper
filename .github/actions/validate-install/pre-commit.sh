#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Runs the hooks in .pre-commit-hooks.yaml the way a user's configuration does,
# with `pre-commit try-repo` against fixture repositories:
#
#   pre-commit.sh <repo-dir> <work-dir>
#
# This replaced `pre-commit validate-manifest` alone, which checks the YAML against
# pre-commit's schema and passed while every hook failed: `ash` exited 1 on every
# run (cdk-nag MISSING, because the hook environment had no `cdk` extra) and
# `ash-full-scan` could not start ("Executable `.../ashv3` not found").
#
# `ash` runs for real and must exit 0 on a clean repository and 2 on one with a
# finding. `ash-simple-scan` is not run: tests/unit/test_pre_commit_hooks_manifest.py
# holds it identical to `ash`. `ash-full-scan` builds the ASH image, which takes
# minutes and a container runtime this job does not have; here a stub `finch`
# (first in ASH's runtime discovery order) records the commands ASH sends it, and
# the check is that the hook started, found ASH's own Dockerfile rather than the
# scanned repository's, and asked to build and then run the image. The container
# legs build the image itself.
set -euo pipefail

REPO="${1:?usage: pre-commit.sh <repo-dir> <work-dir>}"
WORK="${2:?usage: pre-commit.sh <repo-dir> <work-dir>}"

say() { printf '== %s\n' "$*"; }
fail() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

pre-commit --version
pre-commit validate-manifest "$REPO/.pre-commit-hooks.yaml"

# A git repository holding one committed file; try-repo needs a repository to run in.
make_fixture() {
  local dir="$1" body="$2"
  mkdir -p "$dir"
  printf '%s\n' "$body" >"$dir/app.py"
  git -C "$dir" init -q
  git -C "$dir" add app.py
  git -C "$dir" -c user.name=ci -c user.email=ci@example.invalid commit -q -m fixture
}

# Prints the hook's output, and returns pre-commit's exit code.
run_hook() {
  local hook="$1" dir="$2" log="$3" rc=0
  (cd "$dir" && pre-commit try-repo "$REPO" "$hook" --all-files --verbose) >"$log" 2>&1 || rc=$?
  cat "$log"
  return "$rc"
}

clean="$WORK/clean"
finding="$WORK/finding"
make_fixture "$clean" 'def greet(name):
    return "hello " + name'
# bandit B602, severity HIGH: above the default MEDIUM threshold.
make_fixture "$finding" 'import subprocess


def run(cmd):
    return subprocess.call(cmd, shell=True)'

rc=0
run_hook ash "$clean" "$WORK/ash-clean.log" || rc=$?
[ "$rc" -eq 0 ] || fail "the ash hook failed on a clean repository (pre-commit exit $rc)"
say "ash on a clean repository: passed"

rc=0
run_hook ash "$finding" "$WORK/ash-finding.log" || rc=$?
# pre-commit exits 1 for any failed hook and prints the hook's own code.
[ "$rc" -eq 1 ] || fail "pre-commit exited $rc on a repository with a finding, expected 1"
# [[:space:]]* because Python on Windows ends the line with \r\n.
grep -q -- '- exit code: 2[[:space:]]*$' "$WORK/ash-finding.log" ||
  fail "the ash hook failed on a repository with a finding, but not with ASH's findings exit code 2"
say "ash on a repository with a finding: exit 2"

case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*)
    say "ash-full-scan: not checked on Windows (the stub runtime is a shell script)"
    exit 0
    ;;
esac

stub_bin="$WORK/stub-runtime"
calls="$WORK/stub-runtime-calls"
mkdir -p "$stub_bin" "$calls"
cat >"$stub_bin/finch" <<'STUB'
#!/usr/bin/env bash
# Records one call per file, one argument per line, and does nothing else. For a
# build it also records whether the context (the last argument) held an ASH source
# tree, because try-repo deletes its clone before this script's caller can look.
n=$(find "$ASH_STUB_RUNTIME_CALLS" -name 'call-*' -type f | wc -l | tr -d ' ')
printf '%s\n' "$@" >"$ASH_STUB_RUNTIME_CALLS/call-$n"
for context in "$@"; do :; done
if [ -f "$context/Dockerfile" ] && [ -f "$context/pyproject.toml" ]; then
  echo ash-source >"$ASH_STUB_RUNTIME_CALLS/context-$n"
else
  echo other >"$ASH_STUB_RUNTIME_CALLS/context-$n"
fi
STUB
chmod +x "$stub_bin/finch"

rc=0
PATH="$stub_bin:$PATH" ASH_STUB_RUNTIME_CALLS="$calls" \
  run_hook ash-full-scan "$clean" "$WORK/full-scan.log" || rc=$?
if grep -q 'Executable .* not found' "$WORK/full-scan.log"; then
  fail "ash-full-scan did not start: pre-commit could not find its executable"
fi
build="$(grep -lx build "$calls"/call-* | head -n 1 || true)"
[ -n "$build" ] || fail "ash-full-scan never asked the container runtime to build the image"
grep -qx run "$calls"/call-* || fail "ash-full-scan built the image but never asked to run it"
dockerfile="$(awk 'previous == "--file" { print } { previous = $0 }' "$build")"
context="$(tail -n 1 "$build")"
[ "$dockerfile" = "$context/Dockerfile" ] ||
  fail "ash-full-scan built $dockerfile with context $context; expected the context's own Dockerfile"
[ "$(cat "$calls/context-${build##*/call-}")" = ash-source ] ||
  fail "ash-full-scan's build context $context held no Dockerfile and pyproject.toml when it built"
case "$context" in
  "$clean" | "$clean"/*) fail "ash-full-scan built the scanned repository ($context) instead of ASH" ;;
esac
say "ash-full-scan: built $dockerfile, then ran the image (stub runtime; pre-commit exit $rc)"
