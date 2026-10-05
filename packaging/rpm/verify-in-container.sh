#!/usr/bin/env bash
#
# Builds the .rpm, installs it with dnf, and runs a real scan -- the plan's requirement
# that a package be exercised rather than syntax-checked. Run INSIDE an
# amazonlinux:2023 or ubi9 container with the repository at $REPO (default /src,
# read-only is fine) and the wheel built and gated by CI in $DIST (default
# $REPO/dist).
#
#   verify-in-container.sh [--mode MODE]
#
# MODE is one of:
#   assert             build, gate the payload, install, scan, erase (the default)
#   upgrade            install N-1 built from $PREV_DIST, upgrade to N, require the venv
#                      to be replaced; then fail an upgrade on purpose and require the
#                      working install to survive it; then erase
#   negative-findings  the fixture with its finding removed must FAIL the findings gate
#   negative-scan-rc   a scan exiting 0 with findings must FAIL the exit-code gate
#   negative-install   a package whose %post fails must FAIL the install step
#   negative-payload   a package with an empty payload must FAIL the payload gate
#   version-map        PEP 440 pre/post/dev versions must sort correctly under the
#                      distribution's own version comparator
#
# The system python3 on both targets is 3.9, below ASH's floor. The package declares
# (python3.11 or python3.12 or python3.13) and dnf must satisfy that itself, so nothing
# here installs an interpreter for the package; the gates run under uv's own Python.
set -euo pipefail

MODE=assert
if [ "${1:-}" = "--mode" ]; then
  MODE="${2:?--mode needs a value}"
  shift 2
fi
[ "$#" -eq 0 ] || { echo "usage: $0 [--mode MODE]" >&2; exit 2; }

REPO="${REPO:-/src}"
DIST="${DIST:-$REPO/dist}"
PREV_DIST="${PREV_DIST:-$REPO/dist-prev}"
OUT="${OUT:-/tmp/rpmbuild-out}"

# shellcheck source=packaging/verify-lib.sh
. "$REPO/packaging/verify-lib.sh"

one_wheel() {
  local dir="$1" found=()
  shopt -s nullglob
  found=("$dir"/*.whl)
  shopt -u nullglob
  [ "${#found[@]}" -eq 1 ] || vl_fail "expected exactly one wheel in $dir, found ${#found[@]}"
  printf '%s\n' "${found[0]}"
}

wheel_version() {
  basename "$1" | sed -n 's/^automated_security_helper-\([^-]*\)-py3-none-any\.whl$/\1/p'
}

build_rpm() {
  "$REPO/packaging/rpm/build.sh" "$1" "$2"
}

# dnf and rpm both exit 0 when %post fails: rpm treats a failed scriptlet as a warning
# and registers the package anyway. Measured on amazonlinux:2023 with a package whose
# %post is `exit 1`: `dnf install` exit 0, `rpm -i` exit 0, and the only trace is
#   warning: %post(...) scriptlet failed, exit status 1
# So the exit code alone cannot say whether the install worked, and the log is read
# for that warning as well. The step FAILS on either signal; there is no `|| true`.
#
# $1 is the dnf verb (install or upgrade), $2 the package.
rpm_install() {
  local verb="$1" pkg="$2" rc=0
  dnf -y "$verb" "$pkg" >/tmp/dnf-install.log 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    tail -n 30 /tmp/dnf-install.log >&2
    echo "FAIL: dnf $verb $(basename "$pkg") exited $rc" >&2
    return 1
  fi
  if grep -E 'scriptlet failed|Error in [A-Z]+ scriptlet' /tmp/dnf-install.log >&2; then
    echo "FAIL: dnf $verb exited 0 but a scriptlet failed; rpm registers the package anyway" >&2
    return 1
  fi
  sed -n -E 's/^ *(Installing|Upgrading) *: /   \1: /p' /tmp/dnf-install.log
}

interpreter_installed() {
  # The list is captured before it is searched. `rpm -q` on three names exits non-zero
  # whenever any one is absent, and piping `rpm -qa` into `grep -q` lets grep exit on the
  # first match and rpm die of SIGPIPE; under pipefail both read as "not installed".
  local names
  names="$(rpm -qa --qf '%{NAME}\n')"
  grep -q -E '^python3\.1[1-3]$' <<<"$names"
}

erase_and_check() {
  dnf -y -q remove ash >/tmp/dnf-remove.log 2>&1 || { tail -n 20 /tmp/dnf-remove.log >&2; vl_fail "dnf remove ash failed"; }
  if rpm -q ash >/dev/null 2>&1; then
    vl_fail "rpm still lists ash after erase"
  fi
  vl_assert_nothing_left
}

echo "== distribution: $(. /etc/os-release && echo "$PRETTY_NAME"); mode: $MODE"
echo "   system python3 (below ASH's floor, on purpose): $(python3 -V 2>&1)"

echo "== 1. harness prerequisites (none of them a package dependency)"
vl_install_harness_tools
echo "   rpmbuild $(rpmbuild --version | awk '{print $NF}')"

WHEEL="$(one_wheel "$DIST")"
VERSION="$(wheel_version "$WHEEL")"
[ -n "$VERSION" ] || vl_fail "cannot read a version from $(basename "$WHEEL")"

# A copy of packaging/rpm with its spec edited, built by the real build.sh. The spec is
# the only thing changed; build.sh finds cli-name.sh and LICENSE relative to itself, so
# those are copied alongside.
build_variant() {
  local edit="$1" wheel="$2" out="$3" tree
  tree="$(mktemp -d)"
  mkdir -p "$tree/packaging"
  cp -r "$REPO/packaging/rpm" "$tree/packaging/rpm"
  cp "$REPO/packaging/cli-name.sh" "$tree/packaging/"
  cp "$REPO/LICENSE" "$tree/"
  vl_gate_python - "$tree/packaging/rpm/ash.spec" "$edit" <<'PY'
import re, sys
path, edit = sys.argv[1], sys.argv[2]
spec = open(path, encoding="utf-8").read()
if edit == "empty-payload":
    # %install and %files emptied: the package carries no payload at all.
    spec = re.sub(r"(?ms)^%install\n.*?(?=^%files\n)", "%install\n\n", spec)
    spec = re.sub(r"(?ms)^%files\n.*?(?=^# Creates the venv)", "%files\n\n", spec)
elif edit == "failing-post":
    # %post's final `exit 0` becomes `exit 1`, after a working venv has been built.
    head, sep, tail = spec.partition("\n%post\n")
    body, sep2, rest = tail.partition("\n%postun\n")
    if body.count("\nexit 0\n") != 1:
        sys.exit("could not find the single top-level `exit 0` in %post")
    spec = head + sep + body.replace("\nexit 0\n", "\nexit 1\n") + sep2 + rest
else:
    sys.exit(f"unknown edit {edit}")
open(path, "w", encoding="utf-8").write(spec)
PY
  "$tree/packaging/rpm/build.sh" "$wheel" "$out"
}

if [ "$MODE" = version-map ]; then
  echo "== package versions must sort the way PEP 440 does"
  exec bash "$REPO/packaging/test-version-map.sh" rpm "$WHEEL"
fi

case "$MODE" in
  negative-payload)
    echo "== NEGATIVE CONTROL: an empty-payload .rpm must FAIL the payload gate"
    EMPTY="$(build_variant empty-payload "$WHEEL" "$OUT/empty")"
    rpm -qp --list "$EMPTY" | sed 's/^/   listed: /'
    rc=0
    vl_payload_gate "$EMPTY" || rc=$?
    [ "$rc" -eq 1 ] || vl_fail "NEGATIVE CONTROL: the payload gate exited $rc on an empty payload; 1 (rejected) was required"
    echo "   OK: the payload gate rejected the empty payload (exit $rc)"
    echo; echo "RPM NEGATIVE CONTROL (payload) PASSED"
    exit 0
    ;;
  negative-install)
    echo "== NEGATIVE CONTROL: an .rpm whose %post exits 1 must FAIL the install step"
    BROKEN="$(build_variant failing-post "$WHEEL" "$OUT/broken")"
    rc=0
    rpm_install install "$BROKEN" || rc=$?
    [ "$rc" -ne 0 ] || vl_fail "NEGATIVE CONTROL: the install step ACCEPTED a package whose %post failed"
    echo "   OK: the install step rejected the failing %post"
    echo; echo "RPM NEGATIVE CONTROL (install) PASSED"
    exit 0
    ;;
esac

echo "== 2. build and gate the package"
RPM="$(build_rpm "$WHEEL" "$OUT")"
echo "   built: $RPM"
rpm -qp --qf '   Name: %{NAME}\n   Version: %{VERSION}\n   Release: %{RELEASE}\n   Arch: %{ARCH}\n' "$RPM"
echo "   Requires: $(rpm -qp --requires "$RPM" | grep -v '^rpmlib(' | tr '\n' ' ')"
vl_payload_gate "$RPM"

if [ "$MODE" = upgrade ]; then
  PREV_WHEEL="$(one_wheel "$PREV_DIST")"
  PREV_VERSION="$(wheel_version "$PREV_WHEEL")"
  [ -n "$PREV_VERSION" ] || vl_fail "cannot read a version from $(basename "$PREV_WHEEL")"
  PREV_RPM="$(build_rpm "$PREV_WHEEL" "$OUT/prev")"
  echo "   built N-1: $PREV_RPM"
  vl_payload_gate "$PREV_RPM"

  echo "== 3. install N-1 ($PREV_VERSION)"
  rpm_install install "$PREV_RPM"
  vl_assert_installed_version "$PREV_VERSION"
  # The layout is asserted after the upgrade below, not here, so the availability
  # probe is the first check that sees an install which breaks the venv mid-upgrade.
  OLD_VENV="$(readlink -f "$ASH_VENV")"

  echo "== 4. upgrade to N ($VERSION): the venv must be REPLACED, and never absent"
  vl_probe_start
  rpm_install upgrade "$RPM"
  vl_probe_stop_and_assert
  # shellcheck source=packaging/version-map.sh
  . "$REPO/packaging/version-map.sh"
  [ "$(rpm -q --qf '%{VERSION}' ash)" = "$(pkg_version "$VERSION" rpm)" ] \
    || vl_fail "rpm reports $(rpm -q ash) after the upgrade"
  vl_assert_installed_version "$VERSION"
  vl_assert_venv_layout
  [ "$(readlink -f "$ASH_VENV")" != "$OLD_VENV" ] || vl_fail "the venv is the one N-1 created"
  [ ! -e "$OLD_VENV" ] || vl_fail "the N-1 venv $OLD_VENV survived a successful upgrade"
  echo "   OK: the venv was rebuilt from the N wheel and the N-1 venv is gone"

  echo "== 5. scan with the upgraded install"
  vl_scan_and_assert

  echo "== 6. an upgrade whose dependency resolve fails must leave the working install"
  LIVE_VENV="$(readlink -f "$ASH_VENV")"
  vl_blackhole_index
  rc=0
  vl_probe_start
  PIP_RETRIES=0 PIP_TIMEOUT=5 rpm_install reinstall "$RPM" >/tmp/dnf-fail.out 2>&1 || rc=$?
  vl_probe_stop_and_assert
  vl_restore_index
  sed -n "s/^$ASH_CLI_NAME: /   $ASH_CLI_NAME: /p" /tmp/dnf-install.log
  [ "$rc" -ne 0 ] || vl_fail "the reinstall with no reachable index was reported as a success, so it did not exercise a failed upgrade"
  echo "   the reinstall's %post failed as intended"
  vl_assert_installed_version "$VERSION"
  vl_assert_venv_layout
  [ "$(readlink -f "$ASH_VENV")" = "$LIVE_VENV" ] || vl_fail "the failed upgrade repointed $ASH_VENV"
  echo "   OK: the failed upgrade left the working venv in place and nothing behind"

  echo "== 7. the documented recovery works once the index is back"
  rpm_install reinstall "$RPM"
  vl_assert_installed_version "$VERSION"

  echo "== 8. erase leaves nothing behind"
  erase_and_check
  echo; echo "RPM UPGRADE VERIFICATION PASSED"
  exit 0
fi

echo "== 3. install it with dnf; dnf must resolve the interpreter dependency itself"
if interpreter_installed; then
  vl_fail "a python3.11+ is already installed, so this run cannot show the package's own Requires works"
fi
rpm_install install "$RPM"
interpreter_installed || vl_fail "no python3.11+ is installed after installing the package"
echo "   interpreter dnf pulled in: $(rpm -qa 'python3.1[1-3]' --qf '%{NAME}-%{VERSION} ')"
echo "   venv built with: $(readlink -f "$ASH_VENV/bin/python3")"
vl_assert_installed_version "$VERSION"

case "$MODE" in
  negative-findings)
    echo "== NEGATIVE CONTROL: the finding removed from the fixture must FAIL the findings gate"
    vl_negative_findings
    erase_and_check
    echo; echo "RPM NEGATIVE CONTROL (findings) PASSED"
    exit 0
    ;;
  negative-scan-rc)
    echo "== NEGATIVE CONTROL: a scan exiting 0 with findings must FAIL the exit-code gate"
    vl_negative_scan_rc
    erase_and_check
    echo; echo "RPM NEGATIVE CONTROL (scan exit code) PASSED"
    exit 0
    ;;
  assert) ;;
  *) vl_fail "unknown mode $MODE" ;;
esac

echo "== 4. scan a fixture with a KNOWN finding"
vl_scan_and_assert

echo "== 5. erase leaves nothing behind"
erase_and_check

echo
echo "RPM VERIFICATION PASSED"
