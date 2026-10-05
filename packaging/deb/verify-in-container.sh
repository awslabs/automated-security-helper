#!/usr/bin/env bash
#
# Builds the .deb, installs it with apt, and runs a real scan -- the plan's requirement
# that a package be exercised rather than syntax-checked. Run INSIDE a Debian or Ubuntu
# container with the repository at $REPO (default /src, read-only is fine) and the
# wheel built and gated by CI in $DIST (default $REPO/dist).
#
#   verify-in-container.sh [--mode MODE]
#
# MODE is one of:
#   assert             build, gate the payload, install, scan, purge (the default)
#   upgrade            install N-1 built from $PREV_DIST, upgrade to N, require the venv
#                      to be replaced; then fail an upgrade on purpose and require the
#                      working install to survive it; then purge
#   negative-findings  the fixture with its finding removed must FAIL the findings gate
#   negative-scan-rc   a scan exiting 0 with findings must FAIL the exit-code gate
#   negative-install   a package whose postinst fails must FAIL the install step
#   negative-payload   a package with an empty payload must FAIL the payload gate
#
# Every check here exists because a weaker version of it passed something broken. The
# negative modes are how each one is shown to be capable of failing; a check that has
# never been seen red passes forever.
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
OUT="${OUT:-/tmp/debbuild}"
export DEBIAN_FRONTEND=noninteractive

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

build_deb() {
  "$REPO/packaging/deb/build.sh" "$1" "$2"
}

# Installs with apt so Depends is resolved the way a user's install resolves it, and
# FAILS on any failure. The previous version of this step was
#
#   apt-get install -y "$DEB" || dpkg -i "$DEB" || true
#   apt-get install -f -y || true
#
# which carried on past a failed postinst and a half-configured package, so a package
# whose maintainer script exited non-zero still reached the scan and could pass.
deb_install() {
  local pkg="$1" rc=0 status
  apt-get install -y -q "$pkg" >/tmp/apt-install.log 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    tail -n 30 /tmp/apt-install.log >&2
    echo "FAIL: apt-get install $(basename "$pkg") exited $rc" >&2
    return 1
  fi
  status="$(dpkg-query -W -f='${Status}' ash 2>/dev/null)" || status="not known to dpkg"
  if [ "$status" != "install ok installed" ]; then
    echo "FAIL: after installing, dpkg reports ash as '$status', not 'install ok installed'" >&2
    return 1
  fi
  sed -n -E 's/^Setting up ((python3|ash)[^ ]* .*)/   Setting up \1/p' /tmp/apt-install.log
}

key_dependency_installed() {
  [ "$(dpkg-query -W -f='${Status}' python3-venv 2>/dev/null)" = "install ok installed" ]
}

purge_and_check() {
  apt-get purge -y -q ash >/tmp/apt-purge.log 2>&1 || { tail -n 20 /tmp/apt-purge.log >&2; vl_fail "apt-get purge ash failed"; }
  local status
  status="$(dpkg-query -W -f='${Status}' ash 2>/dev/null)" || status="unknown to dpkg"
  case "$status" in
    "unknown to dpkg" | *" not-installed") ;;
    *) vl_fail "dpkg reports ash as '$status' after purge" ;;
  esac
  vl_assert_nothing_left
}

echo "== distribution: $(. /etc/os-release && echo "$PRETTY_NAME"); mode: $MODE"

echo "== 1. harness prerequisites (none of them a package dependency)"
vl_install_harness_tools
echo "   dpkg-deb $(dpkg-deb --version | head -1 | awk '{print $NF}')"

WHEEL="$(one_wheel "$DIST")"
VERSION="$(wheel_version "$WHEEL")"
[ -n "$VERSION" ] || vl_fail "cannot read a version from $(basename "$WHEEL")"

case "$MODE" in
  negative-payload)
    echo "== NEGATIVE CONTROL: an empty-payload .deb must FAIL the payload gate"
    STAGE="$(mktemp -d)"
    install -d "$STAGE/DEBIAN"
    sed -e "s/@DEB_VERSION@/${VERSION}/" "$REPO/packaging/deb/debian/control.in" > "$STAGE/DEBIAN/control"
    mkdir -p "$OUT"
    EMPTY="$OUT/ash_${VERSION}_all.deb"
    dpkg-deb --build -Zgzip --root-owner-group "$STAGE" "$EMPTY" >/dev/null
    rc=0
    vl_payload_gate "$EMPTY" || rc=$?
    [ "$rc" -eq 1 ] || vl_fail "NEGATIVE CONTROL: the payload gate exited $rc on an empty payload; 1 (rejected) was required"
    echo "   OK: the payload gate rejected the empty payload (exit $rc)"
    echo; echo "DEB NEGATIVE CONTROL (payload) PASSED"
    exit 0
    ;;
esac

echo "== 2. build and gate the package"
DEB="$(build_deb "$WHEEL" "$OUT")"
echo "   built: $DEB"
dpkg-deb --field "$DEB" Package Version Architecture Depends | sed 's/^/   /'
vl_payload_gate "$DEB"

if [ "$MODE" = negative-install ]; then
  echo "== NEGATIVE CONTROL: a .deb whose postinst exits 1 must FAIL the install step"
  # The real package with one change: postinst's final `exit 0` becomes `exit 1`, after
  # it has already built a working venv. That is the case the old `|| true` install hid
  # completely, because the CLI works and the scan passes.
  BROKEN_ROOT="$(mktemp -d)"
  dpkg-deb -R "$DEB" "$BROKEN_ROOT"
  sed -i 's/^exit 0$/exit 1/' "$BROKEN_ROOT/DEBIAN/postinst"
  grep -q '^exit 1$' "$BROKEN_ROOT/DEBIAN/postinst" || vl_fail "could not plant the failing exit in postinst"
  mkdir -p "$OUT/broken"
  BROKEN="$OUT/broken/ash_${VERSION}_all.deb"
  dpkg-deb --build -Zgzip --root-owner-group "$BROKEN_ROOT" "$BROKEN" >/dev/null
  rc=0
  deb_install "$BROKEN" || rc=$?
  [ "$rc" -ne 0 ] || vl_fail "NEGATIVE CONTROL: the install step ACCEPTED a package whose postinst failed"
  echo "   OK: the install step rejected the failing postinst"
  echo; echo "DEB NEGATIVE CONTROL (install) PASSED"
  exit 0
fi

if [ "$MODE" = upgrade ]; then
  PREV_WHEEL="$(one_wheel "$PREV_DIST")"
  PREV_VERSION="$(wheel_version "$PREV_WHEEL")"
  [ -n "$PREV_VERSION" ] || vl_fail "cannot read a version from $(basename "$PREV_WHEEL")"
  dpkg --compare-versions "$PREV_VERSION" lt "$VERSION" \
    || vl_fail "the N-1 wheel ($PREV_VERSION) does not sort below N ($VERSION)"
  PREV_DEB="$(build_deb "$PREV_WHEEL" "$OUT/prev")"
  echo "   built N-1: $PREV_DEB"
  vl_payload_gate "$PREV_DEB"

  echo "== 3. install N-1 ($PREV_VERSION)"
  deb_install "$PREV_DEB"
  vl_assert_installed_version "$PREV_VERSION"
  OLD_VENV_ID="$(stat -c '%i' "$ASH_VENV")"

  echo "== 4. upgrade to N ($VERSION): the venv must be REPLACED, not kept"
  deb_install "$DEB"
  vl_assert_installed_version "$VERSION"
  [ "$(stat -c '%i' "$ASH_VENV")" != "$OLD_VENV_ID" ] || vl_fail "the venv directory is the one N-1 created"
  [ ! -e /usr/lib/ash/venv.previous ] || vl_fail "the parked N-1 venv survived a successful upgrade"
  echo "   OK: the venv was rebuilt and nothing was left parked"

  echo "== 5. scan with the upgraded install"
  vl_scan_and_assert

  echo "== 6. prerm must keep the venv on upgrade and failed-upgrade"
  for arg in upgrade failed-upgrade; do
    /var/lib/dpkg/info/ash.prerm "$arg" "$VERSION"
    [ -x "$ASH_VENV/bin/$ASH_CLI_NAME" ] || vl_fail "prerm $arg deleted the venv"
    echo "   OK: prerm $arg left $ASH_VENV in place"
  done

  echo "== 7. an upgrade whose dependency resolve fails must leave the working install"
  vl_blackhole_index
  rc=0
  PIP_RETRIES=0 PIP_TIMEOUT=5 apt-get install -y -q --reinstall "$DEB" >/tmp/apt-fail.log 2>&1 || rc=$?
  vl_restore_index
  sed -n "s/^$ASH_CLI_NAME: /   $ASH_CLI_NAME: /p" /tmp/apt-fail.log
  [ "$rc" -ne 0 ] || vl_fail "the reinstall with no reachable index exited 0, so it did not exercise a failed upgrade"
  echo "   the reinstall failed as intended (exit $rc)"
  vl_assert_installed_version "$VERSION"
  [ ! -e /usr/lib/ash/venv.previous ] || vl_fail "the parked venv was left behind instead of restored"
  echo "   OK: the previous venv was restored and still runs"

  echo "== 8. the documented recovery works once the index is back"
  dpkg --configure -a >/tmp/dpkg-configure.log 2>&1 || { tail -n 20 /tmp/dpkg-configure.log >&2; vl_fail "dpkg --configure -a failed"; }
  [ "$(dpkg-query -W -f='${Status}' ash)" = "install ok installed" ] || vl_fail "ash is not configured after recovery"
  vl_assert_installed_version "$VERSION"

  echo "== 9. purge leaves nothing behind"
  purge_and_check
  echo; echo "DEB UPGRADE VERIFICATION PASSED"
  exit 0
fi

echo "== 3. install it with apt; apt must pull in the interpreter itself"
if key_dependency_installed; then
  vl_fail "python3-venv is already installed, so this run cannot show the package's own Depends works"
fi
deb_install "$DEB"
key_dependency_installed || vl_fail "python3-venv is still absent after installing the package"
echo "   python3-venv was pulled in by the package's Depends"
vl_assert_installed_version "$VERSION"

case "$MODE" in
  negative-findings)
    echo "== NEGATIVE CONTROL: the finding removed from the fixture must FAIL the findings gate"
    vl_negative_findings
    purge_and_check
    echo; echo "DEB NEGATIVE CONTROL (findings) PASSED"
    exit 0
    ;;
  negative-scan-rc)
    echo "== NEGATIVE CONTROL: a scan exiting 0 with findings must FAIL the exit-code gate"
    vl_negative_scan_rc
    purge_and_check
    echo; echo "DEB NEGATIVE CONTROL (scan exit code) PASSED"
    exit 0
    ;;
  assert) ;;
  *) vl_fail "unknown mode $MODE" ;;
esac

echo "== 4. scan a fixture with a KNOWN finding"
vl_scan_and_assert

echo "== 5. purge leaves nothing behind"
purge_and_check

echo
echo "DEB VERIFICATION PASSED"
