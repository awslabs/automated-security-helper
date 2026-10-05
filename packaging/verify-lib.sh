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
# `ash scan` exits 0 when it finds nothing and 2 when it finds something, because
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

ASH_VENV=/usr/lib/ash/venv
FIXTURE_DIR=/opt/ash-fixture
SCAN_OUT=/tmp/ash-scan-out
SCAN_USER=ashscan
# Pinned: the standalone uv installer follows `latest` otherwise. This is the floor
# pyproject.toml declares for uv, so the tool is one ASH itself supports.
UV_VERSION="${UV_VERSION:-0.12.15}"
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
    curl -LsSf "https://astral.sh/uv/${UV_VERSION}/install.sh" \
      | env UV_INSTALL_DIR=/usr/local/bin INSTALLER_NO_MODIFY_PATH=1 sh >/dev/null 2>&1
  fi
  case "$(uv --version)" in *" $UV_VERSION"*) ;; *) vl_fail "uv reports '$(uv --version)', not the pinned $UV_VERSION" ;; esac
  vl_say "   harness: uv $UV_VERSION, useradd, su (none of them a package dependency)"
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

# Runs the scan as $SCAN_USER and sets SCAN_RC. Extra arguments go to `ash scan`.
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

# --------------------------------------------------------------------------
# Removal.
# --------------------------------------------------------------------------
vl_assert_nothing_left() {
  local leftover=()
  local path
  for path in /usr/lib/ash "/usr/bin/$ASH_CLI_NAME" /usr/share/doc/ash /usr/share/licenses/ash; do
    if [ -e "$path" ]; then
      leftover+=("$path")
    fi
  done
  if [ "${#leftover[@]}" -gt 0 ]; then
    ls -la "${leftover[@]}" >&2
    vl_fail "left behind after removal: ${leftover[*]}"
  fi
  vl_say "   OK: /usr/lib/ash, /usr/bin/$ASH_CLI_NAME and the package's doc and license directories are gone"
}
