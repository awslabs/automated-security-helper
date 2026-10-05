# shellcheck shell=bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Shared by packaging/deb/verify-in-container.sh and packaging/rpm/verify-in-container.sh.
# Sourced, never executed. Everything that does not depend on the package format lives
# here, so the two verifications cannot drift apart on what "a working scan" means:
# the fixture, the scan invocation, the exit-code check, the report checks, the payload
# gate and the negative controls that prove each of those can fail.
#
# WHAT A PASSING SCAN MEANS HERE
#
# Each install and each upgrade runs the three shared e2e cases from
# tests/e2e/fixtures/cases.json and judges them with scripts/e2e/assert_outcome.py:
# the planted secret must exit exactly 2 with exactly three results attributed to
# detect-secrets, the clean tree must exit exactly 0, and the incomplete case must exit
# exactly 1 with opengrep named incomplete in ash_aggregated_results.json. Both report
# files must exist at their exact paths. Each of those is a separate check because each
# one has failed independently of the others somewhere in this repository's history:
# an earlier version of these scripts captured the exit code into SCAN_RC and never
# compared it to anything, and a later one checked only that a clean scan was "not 2".
#
# Callers must set REPO (the repository root) before sourcing.

: "${REPO:?verify-lib.sh: REPO must be set before sourcing}"

# shellcheck source=packaging/cli-name.sh
. "$REPO/packaging/cli-name.sh"
: "${ASH_CLI_NAME:?packaging/cli-name.sh did not set ASH_CLI_NAME}"
: "${ASH_PKG_NAME:?packaging/cli-name.sh did not set ASH_PKG_NAME}"

ASH_LIB="/usr/lib/$ASH_PKG_NAME"
ASH_VENV="$ASH_LIB/venv"
FIXTURE_DIR=/opt/ash-fixture
SCAN_OUT=/tmp/ash-scan-out
SCAN_USER=ashscan
# Pinned to the floor pyproject.toml declares for uv (uv>=0.12.19,<0.13), so the tool
# is one ASH itself supports. Installed from the GitHub release tarball and checked
# against the SHA-256 digests below before it is unpacked; the digests were measured
# from the downloaded tarballs and match the .sha256 files published beside them. No
# environment override: a different version needs different digests, so changing it
# is an edit to these three lines together.
UV_VERSION=0.12.19
UV_SHA256_X86_64=23bf5552d220e0842b65c862097b2ebaeba0064b74eda5e565e77fd25969d8c8
UV_SHA256_AARCH64=0804e9b164c64b6914182d5920c08551958a095986f10a3731056df701126436
# The interpreter the gates run under. uv downloads its own, so nothing installed here
# satisfies a dependency of the package under test.
GATE_PYTHON="${GATE_PYTHON:-3.12}"

vl_say() { printf '%s\n' "$*"; }
vl_fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# --------------------------------------------------------------------------
# Harness prerequisites. None of these is a dependency of the package.
# --------------------------------------------------------------------------

# useradd and su run the scan as an unprivileged user; uv runs the two gate scripts.
# Installed before the package so the package manager's output for the package itself
# lists only what the package pulled in.
vl_install_harness_tools() {
  local missing=()
  command -v useradd >/dev/null 2>&1 || missing+=(useradd)
  command -v su >/dev/null 2>&1 || missing+=(su)
  if command -v dnf >/dev/null 2>&1; then
    # tar and gzip for the uv installer, findutils for build.sh, git for
    # build-test-wheels.sh. curl-minimal is in
    # both EL base images already.
    dnf -q -y install rpm-build findutils tar gzip git >/dev/null
    if [ "${#missing[@]}" -gt 0 ]; then
      dnf -q -y install shadow-utils util-linux >/dev/null
    fi
  else
    export DEBIAN_FRONTEND=noninteractive
    apt-get -qq update >/dev/null
    # curl for the uv installer. It pulls ca-certificates, which IS one of the .deb's
    # dependencies, so that one dependency is pre-satisfied on these legs and is not
    # evidence of anything. python3, python3-venv and python3-pip are deliberately NOT
    # installed: the package has to pull them in itself.
    apt-get -qq install -y --no-install-recommends curl ca-certificates git passwd util-linux >/dev/null
  fi
  local tool
  for tool in useradd su curl; do
    command -v "$tool" >/dev/null 2>&1 || vl_fail "harness tool $tool is still absent after installing it"
  done
  if ! command -v uv >/dev/null 2>&1; then
    vl_install_uv
  fi
  case "$(uv --version)" in *" $UV_VERSION"*) ;; *) vl_fail "uv reports '$(uv --version)', not the pinned $UV_VERSION" ;; esac
  vl_say "   harness: uv $UV_VERSION, useradd, su (none of them a package dependency)"
}

# Downloads the pinned uv release tarball, refuses it unless its SHA-256 matches the
# digest pinned above, and installs the binary to /usr/local/bin. Replaces piping the
# upstream install script into sh, which ran whatever that URL served.
vl_install_uv() {
  local triple sha tmp
  case "$(uname -m)" in
    x86_64) triple=x86_64-unknown-linux-gnu sha="$UV_SHA256_X86_64" ;;
    aarch64 | arm64) triple=aarch64-unknown-linux-gnu sha="$UV_SHA256_AARCH64" ;;
    *) vl_fail "no pinned uv checksum for architecture $(uname -m)" ;;
  esac
  tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/uv.tar.gz" \
    "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-${triple}.tar.gz" \
    || vl_fail "could not download uv $UV_VERSION for $triple"
  if ! printf '%s  %s\n' "$sha" "$tmp/uv.tar.gz" | sha256sum -c --quiet - >/dev/null 2>&1; then
    vl_fail "uv-${triple}.tar.gz has SHA-256 $(sha256sum "$tmp/uv.tar.gz" | cut -d' ' -f1), not the pinned $sha"
  fi
  tar -xzf "$tmp/uv.tar.gz" -C "$tmp"
  install -m 0755 "$tmp/uv-${triple}/uv" /usr/local/bin/uv
  rm -rf "$tmp"
}

vl_gate_python() {
  uv run --quiet --no-project --python "$GATE_PYTHON" python "$@"
}

# --------------------------------------------------------------------------
# The payload gate.
# --------------------------------------------------------------------------
vl_payload_gate() {
  vl_gate_python "$REPO/packaging/assert-package-payload.py" \
    --artifact-gate "$REPO/.github/scripts/assert-artifact-contents.py" "$1"
}

# --------------------------------------------------------------------------
# The command the package puts on PATH, and the one it must not.
# --------------------------------------------------------------------------
#
# The package ships exactly one command, /usr/bin/$ASH_CLI_NAME, and never /usr/bin/ash.
# `ash` is the Almquist shell's name: Debian's `ash` package owns /bin/ash, and on a
# merged-/usr host that is the same file as /usr/bin/ash, so dpkg does not see a second
# package's /usr/bin/ash as a conflict. A package that installed it would replace the
# shell. See packaging/cli-name.sh.
#
# Reads a package's file list on stdin, one path per line, absolute or `./`-relative,
# as `dpkg -L`, `rpm -ql`, `rpm -qlp` and the last column of `dpkg-deb -c` print them.
# $1 labels the list in messages. Returns non-zero rather than exiting, so the negative
# control can observe it firing.
vl_check_command_paths() {
  local label="$1" paths bin_entries rc=0
  paths="$(sed -e 's|^\./|/|' -e 's|/$||' | grep -v '^\.\?$' || true)"
  if [ -z "$paths" ]; then
    printf 'FAIL: %s: the file list is empty, so nothing below could be checked\n' "$label" >&2
    return 1
  fi
  if grep -qxF "/usr/bin/$ASH_CLI_NAME" <<<"$paths"; then :; else
    printf 'FAIL: %s does not list /usr/bin/%s\n' "$label" "$ASH_CLI_NAME" >&2
    rc=1
  fi
  if grep -xE '/(usr/)?bin/ash' <<<"$paths" >&2; then
    printf 'FAIL: %s lists the path above; /usr/bin/ash and /bin/ash belong to the Almquist shell\n' "$label" >&2
    rc=1
  fi
  # Exactly one command: anything else under a bin directory is a second name on PATH.
  bin_entries="$(grep -E '^/(usr/)?s?bin/.' <<<"$paths" | grep -vxF "/usr/bin/$ASH_CLI_NAME" || true)"
  if [ -n "$bin_entries" ]; then
    printf 'FAIL: %s puts more than /usr/bin/%s on PATH:\n%s\n' "$label" "$ASH_CLI_NAME" "$bin_entries" >&2
    rc=1
  fi
  [ "$rc" -eq 0 ] && vl_say "   $label: /usr/bin/$ASH_CLI_NAME is the only command; no /usr/bin/ash"
  return "$rc"
}

# The distribution's `ash` shell must still be what /usr/bin/ash is: a working shell
# that runs POSIX arithmetic, not the package's wrapper, and what `ash` on PATH
# resolves to. $1 names the package that owns the shell. Returns non-zero rather than
# exiting, so the negative control can observe it firing.
vl_assert_shell_intact() {
  local owner="$1" resolved out found
  [ -e /usr/bin/ash ] || { printf 'FAIL: /usr/bin/ash is missing; %s should have installed it\n' "$owner" >&2; return 1; }
  resolved="$(readlink -f /usr/bin/ash)"
  if grep -qF "/usr/lib/$ASH_PKG_NAME" "$resolved"; then
    printf 'FAIL: /usr/bin/ash (%s) is the %s wrapper, not the %s shell\n' "$resolved" "$ASH_PKG_NAME" "$owner" >&2
    return 1
  fi
  out="$(/usr/bin/ash -c 'x=$((6 * 7)); echo "shell:$x"' 2>&1)" || true
  if [ "$out" != "shell:42" ]; then
    printf "FAIL: /usr/bin/ash -c 'echo \$((6 * 7))' printed '%s', so it is not a working shell\n" "$out" >&2
    return 1
  fi
  found="$(command -v ash || true)"
  case "$found" in
    /usr/bin/ash | /bin/ash) ;;
    *) printf 'FAIL: ash on PATH resolves to [%s], not the shell\n' "$found" >&2; return 1 ;;
  esac
  vl_say "   /usr/bin/ash -> $resolved ($owner) runs \$((6 * 7)) = 42; ash on PATH is $found"
}

# The coexistence check: the shell intact AND the package's command working beside it.
vl_assert_shell_coexists() {
  vl_assert_shell_intact "$1" || return 1
  "$ASH_CLI_NAME" --version >/dev/null 2>&1 \
    || { printf 'FAIL: %s --version failed with the %s shell installed\n' "$ASH_CLI_NAME" "$1" >&2; return 1; }
  vl_say "   coexistence: $ASH_CLI_NAME --version works with the $1 shell installed"
}

# --------------------------------------------------------------------------
# Version checks.
# --------------------------------------------------------------------------

# The version the installed CLI reports AND the version of the distribution inside the
# venv must both be the one expected. The two are checked separately because the rpm
# upgrade defect this exists for had the package manager reporting the new version
# while the venv still ran the old one.
vl_assert_installed_version() {
  local expected="$1" reported venv_version
  command -v "$ASH_CLI_NAME" >/dev/null || vl_fail "$ASH_CLI_NAME is not on PATH"
  [ "$(command -v "$ASH_CLI_NAME")" = "/usr/bin/$ASH_CLI_NAME" ] \
    || vl_fail "$ASH_CLI_NAME resolves to $(command -v "$ASH_CLI_NAME"), not the packaged /usr/bin/$ASH_CLI_NAME"
  reported="$("$ASH_CLI_NAME" --version)" || vl_fail "$ASH_CLI_NAME --version exited non-zero"
  vl_say "   $ASH_CLI_NAME --version: $reported"
  case "$reported" in
    *"v$expected") ;;
    *) vl_fail "$ASH_CLI_NAME --version reports '$reported', expected v$expected" ;;
  esac
  venv_version="$("$ASH_VENV/bin/python" -c \
    'import importlib.metadata as m; print(m.version("automated-security-helper"))')"
  vl_say "   venv distribution: automated-security-helper $venv_version"
  [ "$venv_version" = "$expected" ] \
    || vl_fail "the venv holds automated-security-helper $venv_version, expected $expected"
}

# --------------------------------------------------------------------------
# The scans: the shared e2e cases, judged by the shared e2e verdict.
# --------------------------------------------------------------------------
#
# The fixtures, the scanner selection, the per-case arguments and environment, and the
# expected outcome of each case all come from tests/e2e/fixtures/cases.json, and the
# verdict is scripts/e2e/assert_outcome.py, the one every other install channel uses.
# Nothing about what a passing scan means is restated here, so this channel cannot
# come to check less than its siblings. The three cases are:
#
#   findings    exit exactly 2, exactly 3 actionable results, attributed to
#               detect-secrets
#   clean       exit exactly 0, no results
#   incomplete  exit exactly 1, with opengrep MISSING or ERROR in the aggregated
#               results (the measured trigger in tests/e2e/README.md), so a crash
#               cannot pass as "incomplete"
#
# assert_outcome.py is standard-library Python. It runs under the harness interpreter
# uv provides, never under the package's venv, so a broken venv cannot judge itself.

VL_CASES="$REPO/tests/e2e/fixtures/cases.json"
VL_ASSERT_OUTCOME="$REPO/scripts/e2e/assert_outcome.py"
SCAN_LOG=/tmp/ash-scan.log

# Prints one field of case $1, read through assert_outcome.load_case so a case that
# does not exist fails here the same way it fails the verdict:
#   source     the fixture directory name under tests/e2e/fixtures
#   scan-args  --scanners and the case's own args, shell-quoted
#   env        the case's environment as shell-quoted NAME=VALUE words
vl_case_field() {
  vl_gate_python - "$REPO/scripts/e2e" "$VL_CASES" "$1" "$2" <<'PY'
import shlex
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import assert_outcome  # noqa: E402

case = assert_outcome.load_case(Path(sys.argv[2]), sys.argv[3])
field = sys.argv[4]
args = case.get("args") or []
env = case.get("env") or {}
if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
    sys.exit(f"the case's args must be a list of strings, not {args!r}")
if not isinstance(env, dict):
    sys.exit(f"the case's env must be an object, not {env!r}")
if field == "source":
    print(case["source"])
elif field == "scan-args":
    words = ["--scanners", ",".join(case["scanners"]), *args]
    print(" ".join(shlex.quote(w) for w in words))
elif field == "env":
    print(" ".join(shlex.quote(f"{k}={v}") for k, v in sorted(env.items())))
else:
    sys.exit(f"unknown case field {field}")
PY
}

# Copies case $1's fixture to $FIXTURE_DIR, root-owned and unwritable by the scanning
# user. ASH's default output directory is inside the scanned tree, so a scan of a
# checkout the user does not own fails while writing reports; scanning as root, or a
# tree the user owns, would hide that.
vl_make_fixture() {
  local source
  source="$(vl_case_field "$1" source)" || vl_fail "cannot read case $1 from $VL_CASES"
  [ -d "$REPO/tests/e2e/fixtures/$source" ] || vl_fail "case $1 names fixture $source, which does not exist"
  rm -rf "$FIXTURE_DIR"
  cp -R "$REPO/tests/e2e/fixtures/$source" "$FIXTURE_DIR"
  chown -R 0:0 "$FIXTURE_DIR"
  chmod -R u=rwX,go=rX "$FIXTURE_DIR"
  id -u "$SCAN_USER" >/dev/null 2>&1 || useradd --create-home "$SCAN_USER"
  # A read must succeed before a failed write means anything: `su ... test -w` also
  # fails when su itself is broken.
  su -s /bin/sh "$SCAN_USER" -c "ls -A $FIXTURE_DIR | grep -q . && test -r $FIXTURE_DIR" \
    || vl_fail "$SCAN_USER cannot list a non-empty $FIXTURE_DIR, so su or the fixture is broken"
  if su -s /bin/sh "$SCAN_USER" -c "test -w $FIXTURE_DIR"; then
    vl_fail "$FIXTURE_DIR is writable by $SCAN_USER, so the read-only-source case is not exercised"
  fi
}

# Runs case $1 over $FIXTURE_DIR as $SCAN_USER, with the case's scanners, args and
# environment, and sets SCAN_RC and SCAN_CASE. Further arguments are appended to
# `ashx scan` after the case's own; the negative controls use that.
vl_scan() {
  local case="$1" scan_args env_words extra=""
  shift
  scan_args="$(vl_case_field "$case" scan-args)" || vl_fail "cannot read case $case's scan arguments"
  env_words="$(vl_case_field "$case" env)" || vl_fail "cannot read case $case's environment"
  if [ "$#" -gt 0 ]; then
    extra="$(printf ' %q' "$@")"
  fi
  rm -rf "$SCAN_OUT"
  install -d -o "$SCAN_USER" -g "$SCAN_USER" -m 0755 "$SCAN_OUT"
  vl_say "   [$case] ${env_words:+$env_words }$ASH_CLI_NAME scan --source-dir $FIXTURE_DIR --output-dir $SCAN_OUT --no-progress $scan_args$extra"
  set +e
  su -s /bin/bash "$SCAN_USER" -c \
    "cd /tmp && env $env_words $ASH_CLI_NAME scan --source-dir '$FIXTURE_DIR' --output-dir '$SCAN_OUT' \
       --no-progress $scan_args$extra" >"$SCAN_LOG" 2>&1
  SCAN_RC=$?
  set -e
  SCAN_CASE="$case"
  tail -n 3 "$SCAN_LOG"
  vl_say "   [$case] $ASH_CLI_NAME scan rc=$SCAN_RC"
}

# Judges the last scan's exit code and output directory as case $1 with
# assert_outcome.py; further arguments override the case's expectations. Returns the
# verdict's exit code (0 match, 1 mismatch, 3 usage error) rather than exiting, so a
# negative control can observe a rejection.
vl_assert_case() {
  local case="$1"
  shift
  vl_gate_python "$VL_ASSERT_OUTCOME" --cases "$VL_CASES" --case "$case" \
    --rc "$SCAN_RC" --output-dir "$SCAN_OUT" "$@"
}

# One case end to end: fixture, scan, verdict. Exits on a mismatch.
vl_scan_and_assert_case() {
  vl_make_fixture "$1"
  vl_scan "$1"
  if ! vl_assert_case "$1"; then
    tail -n 40 "$SCAN_LOG" >&2
    vl_fail "the $1 case did not produce its expected outcome"
  fi
}

# The full positive check: all three cases, so every install and every upgrade is
# shown producing exit 2, exit 0 and exit 1, each for its own reason.
vl_scan_and_assert() {
  local case
  for case in findings clean incomplete; do
    vl_scan_and_assert_case "$case"
  done
}

# --------------------------------------------------------------------------
# Negative controls: each check above must be seen failing on a real install.
# --------------------------------------------------------------------------

# Requires the verdict to REJECT the last scan judged as case $1: exit 1, not 0 and not
# 3 (a usage error proves nothing about the scan). $2 is the exact number of problems
# it must report, or `any`; each further argument is a problem text the rejection
# must contain, so the control shows the check it is aimed at firing, not some other.
vl_require_rejection() {
  local case="$1" want_count="$2" out rc=0 count text
  shift 2
  out="$(vl_assert_case "$case" 2>&1)" || rc=$?
  printf '%s\n' "$out" | sed 's/^/   | /'
  [ "$rc" -eq 1 ] \
    || vl_fail "NEGATIVE CONTROL: the verdict exited $rc judging the $SCAN_CASE scan as the $case case; 1 (rejected) was required"
  count="$(grep -c '^::error::' <<<"$out" || true)"
  if [ "$want_count" != any ] && [ "$count" -ne "$want_count" ]; then
    vl_fail "NEGATIVE CONTROL: the verdict reported $count problems; exactly $want_count was required, so a check other than the one under test fired"
  fi
  for text in "$@"; do
    grep -qF -- "$text" <<<"$out" \
      || vl_fail "NEGATIVE CONTROL: the rejection does not name the problem under test: $text"
  done
  vl_say "   OK: the verdict rejected the $SCAN_CASE scan judged as $case ($count problem(s))"
}

# The finding removed from the fixture. The clean scan must itself be exactly right
# (exit 0, nothing found), and the same real output judged as the findings case must
# be rejected on both the exit code and the finding count.
vl_negative_findings() {
  vl_scan_and_assert_case clean
  vl_require_rejection findings any \
    "exit code 0 (nothing actionable), expected exactly 2" \
    "0 actionable SARIF results, expected exactly 3"
}

# The secret is still there and still reported, but the scan is told not to fail on
# findings, so it exits 0 with a populated report. The count and attribution checks
# pass, so the exit-code check is the only thing that can catch this: the rejection
# must name it and nothing else.
vl_negative_scan_rc() {
  vl_make_fixture findings
  vl_scan findings --no-fail-on-findings
  [ "$SCAN_RC" -eq 0 ] || vl_fail "NEGATIVE CONTROL setup: --no-fail-on-findings exited $SCAN_RC, not 0"
  vl_require_rejection findings 1 "exit code 0 (nothing actionable), expected exactly 2"
}

# Exit 1 must be told apart from exit 2 in both directions. The real incomplete output
# judged as the findings case must be rejected for the incomplete scanner; the real
# findings output judged as the incomplete case must be rejected because the trigger
# did not fire. A verdict that ignored scanner status would accept either.
vl_negative_incomplete() {
  vl_scan_and_assert_case incomplete
  vl_require_rejection findings any \
    "exit code 1 (scan incomplete or crashed), expected exactly 2" \
    "scanners did not complete: opengrep="
  vl_scan_and_assert_case findings
  vl_require_rejection incomplete any \
    "exit code 2 (actionable findings), expected exactly 1" \
    "the incomplete trigger did not fire"
}

# --------------------------------------------------------------------------
# Upgrade helpers.
# --------------------------------------------------------------------------

# Points the Python package index at nothing, so the maintainer script's dependency
# resolve fails the way an outage does. /etc/hosts rather than a pip environment
# variable, so nothing about the maintainer script's own pip invocation is changed.
vl_blackhole_index() {
  cp /etc/hosts /tmp/hosts.verify-backup
  printf '127.0.0.1 pypi.org files.pythonhosted.org\n' >> /etc/hosts
}
vl_restore_index() {
  cp /tmp/hosts.verify-backup /etc/hosts
  rm -f /tmp/hosts.verify-backup
}

# The lower version for the N-1 package: the last non-zero component of N decremented
# and everything after it zeroed (3.7.0 -> 3.6.0, 4.0.0 -> 3.0.0).
vl_lower_version() {
  printf '%s\n' "$1" | awk -F. '{
    n = NF; while (n > 0 && $n == 0) n--;
    if (n == 0) { exit 1 }
    $n = $n - 1; for (i = n + 1; i <= NF; i++) $i = 0;
    out = $1; for (i = 2; i <= NF; i++) out = out "." $i; print out }'
}

# The venv layout: $ASH_VENV is a symlink to exactly one venv-<id>
# directory, and nothing an interrupted install would leave is present.
vl_assert_venv_layout() {
  [ -L "$ASH_VENV" ] || vl_fail "$ASH_VENV is not a symlink"
  local dirs=() d
  for d in "$ASH_LIB"/venv-*; do
    if [ -d "$d" ]; then
      dirs+=("$d")
    fi
  done
  [ "${#dirs[@]}" -eq 1 ] || vl_fail "expected exactly one $ASH_LIB/venv-* directory, found ${#dirs[@]}: ${dirs[*]}"
  [ "$(readlink -f "$ASH_VENV")" = "${dirs[0]}" ] || vl_fail "$ASH_VENV does not point at ${dirs[0]}"
  for d in "$ASH_LIB"/venv.previous "$ASH_LIB"/venv.swap-*; do
    if [ -e "$d" ] || [ -L "$d" ]; then
      vl_fail "left behind by the install: $d"
    fi
  done
  vl_say "   venv layout: $ASH_VENV -> $(readlink "$ASH_VENV"), no other venv present"
}

# Puts the host back on the layout the packages used before the symlink swap: the live
# venv as a real directory AT $ASH_VENV, built from the wheel the package
# installed, with the interpreter the current venv uses. The next install has to migrate
# it, which is the one path through the post-install step that moves a directory.
vl_make_directory_layout() {
  local wheel="$1" py
  py="$(readlink -f "$ASH_VENV/bin/python3")"
  [ -x "$py" ] || vl_fail "cannot find the interpreter behind $ASH_VENV"
  rm -rf "$ASH_VENV" "$ASH_LIB"/venv-*
  "$py" -m venv "$ASH_VENV"
  "$ASH_VENV/bin/pip" install --quiet --disable-pip-version-check "$wheel"
  if [ -L "$ASH_VENV" ] || [ ! -d "$ASH_VENV" ]; then
    vl_fail "$ASH_VENV is not a plain directory, so the migration is not exercised"
  fi
  "$ASH_VENV/bin/$ASH_CLI_NAME" --version >/dev/null || vl_fail "the directory-layout venv does not run"
  vl_say "   directory layout in place: $ASH_VENV is a real directory built with $py"
}

# Samples, every 50 ms for as long as an install runs, whether the command and the
# interpreter behind $ASH_VENV exist. Any miss is a moment in which the
# installed CLI could not have started.
vl_probe_start() {
  rm -f /tmp/venv-probe.log /tmp/venv-probe.stop
  (
    while [ ! -e /tmp/venv-probe.stop ]; do
      if [ -x "$ASH_VENV/bin/$ASH_CLI_NAME" ] && [ -x "$ASH_VENV/bin/python3" ]; then
        echo ok
      else
        echo miss
      fi
      sleep 0.05
    done
  ) >/tmp/venv-probe.log 2>&1 &
  VL_PROBE_PID=$!
}

vl_probe_stop_and_assert() {
  touch /tmp/venv-probe.stop
  wait "$VL_PROBE_PID"
  local samples misses
  samples="$(awk 'END { print NR }' /tmp/venv-probe.log)"
  misses="$(awk '$0 == "miss" { n++ } END { print n + 0 }' /tmp/venv-probe.log)"
  vl_say "   availability probe: $samples samples, $misses with no usable $ASH_VENV"
  # A floor on the sample count, so a probe that never ran cannot pass.
  [ "$samples" -ge 20 ] || vl_fail "the availability probe took only $samples samples"
  [ "$misses" -eq 0 ] || vl_fail "$ASH_VENV was unusable in $misses of $samples samples during the install"
}

# --------------------------------------------------------------------------
# Removal.
# --------------------------------------------------------------------------
vl_assert_nothing_left() {
  local leftover=()
  local path
  for path in "$ASH_LIB" "/usr/bin/$ASH_CLI_NAME" "/usr/share/doc/$ASH_PKG_NAME" "/usr/share/licenses/$ASH_PKG_NAME"; do
    if [ -e "$path" ]; then
      leftover+=("$path")
    fi
  done
  if [ "${#leftover[@]}" -gt 0 ]; then
    ls -la "${leftover[@]}" >&2
    vl_fail "left behind after removal: ${leftover[*]}"
  fi
  vl_say "   OK: $ASH_LIB, /usr/bin/$ASH_CLI_NAME and the package's doc and license directories are gone"
}
