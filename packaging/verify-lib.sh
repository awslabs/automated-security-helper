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
# `ashx scan` exits 0 when it finds nothing and 2 when it finds something, because
# fail_on_findings defaults to true. On a fixture planted with a secret, 0 is therefore
# the FAILING outcome, and 1 is an execution error. So the scan must exit exactly 2, the
# SARIF report and ash_aggregated_results.json must both exist, and
# packaging/assert-scan-findings.py must find at least one result attributed to
# detect-secrets. Each of those is a separate check because each one has failed
# independently of the others somewhere in this repository's history: an earlier
# version of these scripts captured the exit code into SCAN_RC and never compared it
# to anything.
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
# The scan.
# --------------------------------------------------------------------------

# $1: "secret" plants AWS's published example key, which detect-secrets reports and
#     which is non-functional by construction. "clean" plants nothing to find.
vl_make_fixture() {
  rm -rf "$FIXTURE_DIR"
  mkdir -p "$FIXTURE_DIR"
  if [ "$1" = clean ]; then
    printf 'print("hello")\n' > "$FIXTURE_DIR/leak.py"
  else
    cat > "$FIXTURE_DIR/leak.py" <<'PY'
# Fixture for packaging verification. Not a real credential.
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PY
  fi
  # Root-owned and unwritable by the scanning user. ASH's default output directory is
  # inside the scanned tree, so a scan of a checkout the user does not own fails while
  # writing reports; scanning as root would hide that.
  chmod 0755 "$FIXTURE_DIR"
  chmod 0644 "$FIXTURE_DIR/leak.py"
  id -u "$SCAN_USER" >/dev/null 2>&1 || useradd --create-home "$SCAN_USER"
  rm -rf "$SCAN_OUT"
  install -d -o "$SCAN_USER" -g "$SCAN_USER" -m 0755 "$SCAN_OUT"
  # A read must succeed before a failed write means anything: `su ... test -w` also
  # fails when su itself is broken.
  su -s /bin/sh "$SCAN_USER" -c "test -r $FIXTURE_DIR/leak.py" \
    || vl_fail "$SCAN_USER cannot read the fixture, so su or the fixture is broken"
  if su -s /bin/sh "$SCAN_USER" -c "test -w $FIXTURE_DIR"; then
    vl_fail "$FIXTURE_DIR is writable by $SCAN_USER, so the read-only-source case is not exercised"
  fi
}

# Runs the scan as $SCAN_USER and sets SCAN_RC. Extra arguments go to `ashx scan`.
#
# --scanners detect-secrets because it is the one default scanner that arrives with ASH
# itself (a [project] dependency driven in process); the rest are recorded SKIPPED
# rather than reported MISSING for tools this container never had.
vl_scan() {
  local extra="$*"
  set +e
  su -s /bin/bash "$SCAN_USER" -c \
    "cd /tmp && $ASH_CLI_NAME scan --source-dir '$FIXTURE_DIR' --output-dir '$SCAN_OUT' \
       --scanners detect-secrets --no-progress $extra" >/tmp/ash-scan.log 2>&1
  SCAN_RC=$?
  set -e
  tail -n 3 /tmp/ash-scan.log
  vl_say "   $ASH_CLI_NAME scan rc=$SCAN_RC"
}

# The exit-code gate. Returns non-zero rather than exiting, so the negative control can
# observe it firing.
vl_check_scan_rc() {
  if [ "$SCAN_RC" -ne 2 ]; then
    printf 'FAIL: %s scan exited %s on a fixture planted with a secret; 2 (findings) is the only passing value.\n' \
      "$ASH_CLI_NAME" "$SCAN_RC" >&2
    printf 'FAIL: 0 means nothing was reported as actionable and 1 means the scan did not complete.\n' >&2
    tail -n 40 /tmp/ash-scan.log >&2
    return 1
  fi
  return 0
}

vl_check_reports() {
  local sarif="$SCAN_OUT/reports/ash.sarif" aggregated="$SCAN_OUT/ash_aggregated_results.json"
  [ -f "$sarif" ] || vl_fail "no SARIF report at $sarif"
  [ -f "$aggregated" ] || vl_fail "no aggregated results at $aggregated"
  vl_gate_python -c 'import json, sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$aggregated" \
    || vl_fail "$aggregated is not valid JSON"
  vl_say "   reports present: reports/ash.sarif, ash_aggregated_results.json"
}

vl_check_findings() {
  vl_gate_python "$REPO/packaging/assert-scan-findings.py" "$SCAN_OUT/reports/ash.sarif" \
    --minimum 1 --require-scanner detect-secrets
}

# The full positive check: planted secret, exit 2, both reports, attributed findings.
vl_scan_and_assert() {
  vl_make_fixture secret
  vl_scan
  vl_check_scan_rc || exit 1
  vl_check_reports
  vl_check_findings || vl_fail "the findings gate rejected the scan"
}

# --------------------------------------------------------------------------
# Negative controls: each check above must be seen failing on a real install.
# --------------------------------------------------------------------------

# The finding removed from the fixture. The scan exits 0, and the findings gate must
# reject the report.
vl_negative_findings() {
  vl_make_fixture clean
  vl_scan
  local rc=0
  vl_check_findings || rc=$?
  if [ "$rc" -eq 0 ]; then
    vl_fail "NEGATIVE CONTROL: the findings gate ACCEPTED a scan of a fixture with nothing to find"
  fi
  vl_say "   OK: the findings gate rejected a scan that found nothing (exit $rc)"
  rc=0
  vl_check_scan_rc 2>/dev/null || rc=$?
  [ "$rc" -ne 0 ] || vl_fail "NEGATIVE CONTROL: the exit-code gate accepted rc=$SCAN_RC on a clean fixture"
  vl_say "   OK: the exit-code gate also rejected rc=$SCAN_RC"
}

# The secret is still there and still reported, but the scan is told not to fail on
# findings, so it exits 0 with a populated report. The findings gate passes; the
# exit-code gate is the only thing that can catch this, and it must.
vl_negative_scan_rc() {
  vl_make_fixture secret
  vl_scan --no-fail-on-findings
  vl_check_findings || vl_fail "NEGATIVE CONTROL setup: the findings gate should PASS here, so that only the exit-code gate is under test"
  local rc=0
  vl_check_scan_rc || rc=$?
  [ "$rc" -ne 0 ] || vl_fail "NEGATIVE CONTROL: the exit-code gate ACCEPTED rc=$SCAN_RC with findings present"
  vl_say "   OK: the exit-code gate rejected rc=$SCAN_RC although the report had findings"
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
