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
#   assert             build, gate the payload, install beside Debian's `ash` shell,
#                      scan, purge (the default)
#   upgrade            install N-1 (the previous commit's package, built from the
#                      $PREV_DIST wheel by that commit's own build script; see
#                      packaging/n1-source.sh), upgrade to N, require the venv
#                      to be replaced; then fail an upgrade on purpose and require the
#                      working install to survive it; then migrate a venv left as a
#                      directory by an older release to the symlink layout; then purge
#   negative-findings  the clean case must exit exactly 0, and its real output judged
#                      as the findings case must FAIL on exit code and count
#   negative-scan-rc   a scan exiting 0 with findings must FAIL the exit-code check,
#                      and only that check
#   negative-incomplete
#                      the real incomplete output judged as the findings case, and
#                      the real findings output judged as the incomplete case, must
#                      each FAIL
#   negative-install   a package whose postinst fails must FAIL the install step
#   negative-payload   a package with an empty payload must FAIL the payload gate
#   negative-alternatives
#                      a package whose postinst registers /usr/bin/ash as an
#                      alternative must FAIL the maintainer-script check, and
#                      installing it must either be refused or FAIL the host check
#   negative-shell-path
#                      a build that also installs /usr/bin/ash must FAIL the command
#                      path check, and installing it beside the `ash` shell must
#                      either be refused or FAIL the coexistence check
#   version-map        PEP 440 pre/post/dev versions must sort correctly under the
#                      distribution's own version comparator
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

# The command-path check on a built .deb's file list. `dpkg-deb -c` prints tar's long
# listing, and the path is its sixth column.
check_deb_paths() {
  dpkg-deb -c "$1" | awk '{ print $6 }' | vl_check_command_paths "dpkg-deb -c $(basename "$1")"
}

# Every maintainer script in a built .deb, concatenated, for vl_check_maintainer_scripts.
deb_maintainer_scripts() {
  local ctl name
  ctl="$(mktemp -d)"
  dpkg-deb -e "$1" "$ctl"
  for name in preinst postinst prerm postrm config; do
    if [ -f "$ctl/$name" ]; then
      cat "$ctl/$name"
    fi
  done
  rm -rf "$ctl"
}

# Debian's `ash` package, the Almquist shell's name (a compatibility package for
# dash), which owns /bin/ash. Installed before the package under test, so that
# install is the one that would replace it.
install_distro_ash() {
  apt-get -qq install -y --no-install-recommends ash >/tmp/apt-ash.log 2>&1 \
    || { tail -n 20 /tmp/apt-ash.log >&2; vl_fail "apt-get install ash failed"; }
  [ "$(dpkg-query -W -f='${Status}' ash)" = "install ok installed" ] || vl_fail "Debian's ash package is not installed"
  vl_say "   installed Debian's ash $(dpkg-query -W -f='${Version}' ash), owner of $(dpkg -L ash | grep -E '/bin/ash$')"
}

# The real build.sh run from a copy of packaging/deb whose build.sh also installs the
# wrapper as /usr/bin/ash: what a revert to ASH_CLI_NAME=ash, or an added alias,
# would produce. The edit is planted before the final dpkg-deb --build.
build_variant_with_ash_path() {
  local wheel="$1" out="$2" tree
  tree="$(mktemp -d)"
  mkdir -p "$tree/packaging"
  cp -r "$REPO/packaging/deb" "$tree/packaging/deb"
  cp "$REPO/packaging/cli-name.sh" "$REPO/packaging/version-map.sh" "$tree/packaging/"
  cp "$REPO/LICENSE" "$tree/"
  if vl_gate_python - "$tree/packaging/deb/build.sh" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
anchor = 'DEB="$OUTDIR/${PKG}_${DEB_VERSION}_all.deb"\n'
if text.count(anchor) != 1:
    sys.exit("could not find the single DEB= line in build.sh")
plant = 'cp -p "$STAGE/usr/bin/${ASH_CLI_NAME}" "$STAGE/usr/bin/ash"\n'
open(path, "w", encoding="utf-8").write(text.replace(anchor, plant + anchor))
PY
  then :; else
    # Inside $(...) errexit does not apply, so a failed edit would otherwise go on to
    # build an unedited package and hand the caller a correct one as the variant.
    echo "FAIL: could not plant /usr/bin/ash in the copied build.sh" >&2
    return 1
  fi
  "$tree/packaging/deb/build.sh" "$wheel" "$out"
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
  status="$(dpkg-query -W -f='${Status}' "$ASH_PKG_NAME" 2>/dev/null)" || status="not known to dpkg"
  if [ "$status" != "install ok installed" ]; then
    echo "FAIL: after installing, dpkg reports $ASH_PKG_NAME as '$status', not 'install ok installed'" >&2
    return 1
  fi
  sed -n -E "s/^Setting up ((python3|${ASH_PKG_NAME})[^ ]* .*)/   Setting up \1/p" /tmp/apt-install.log
}

# `apt-get install --reinstall` with the same checks as deb_install.
deb_install_reinstall() {
  local pkg="$1" rc=0
  apt-get install -y -q --reinstall "$pkg" >/tmp/apt-install.log 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    tail -n 30 /tmp/apt-install.log >&2
    vl_fail "apt-get install --reinstall $(basename "$pkg") exited $rc"
  fi
  [ "$(dpkg-query -W -f='${Status}' "$ASH_PKG_NAME")" = "install ok installed" ] \
    || vl_fail "$ASH_PKG_NAME is not 'install ok installed' after the reinstall"
}

key_dependency_installed() {
  [ "$(dpkg-query -W -f='${Status}' python3-venv 2>/dev/null)" = "install ok installed" ]
}

purge_and_check() {
  apt-get purge -y -q "$ASH_PKG_NAME" >/tmp/apt-purge.log 2>&1 || { tail -n 20 /tmp/apt-purge.log >&2; vl_fail "apt-get purge $ASH_PKG_NAME failed"; }
  local status
  status="$(dpkg-query -W -f='${Status}' "$ASH_PKG_NAME" 2>/dev/null)" || status="unknown to dpkg"
  case "$status" in
    "unknown to dpkg" | *" not-installed") ;;
    *) vl_fail "dpkg reports $ASH_PKG_NAME as '$status' after purge" ;;
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

if [ "$MODE" = version-map ]; then
  echo "== package versions must sort the way PEP 440 does"
  exec bash "$REPO/packaging/test-version-map.sh" deb "$WHEEL"
fi

case "$MODE" in
  negative-shell-path)
    echo "== NEGATIVE CONTROL: a .deb that also installs /usr/bin/ash must FAIL the command path check"
    VARIANT="$(build_variant_with_ash_path "$WHEEL" "$OUT/with-ash")"
    dpkg-deb -c "$VARIANT" | awk '$6 ~ /bin\// { print "   listed: " $6 }'
    rc=0
    check_deb_paths "$VARIANT" || rc=$?
    [ "$rc" -ne 0 ] || vl_fail "NEGATIVE CONTROL: the command path check ACCEPTED a package listing /usr/bin/ash"
    echo "   OK: the command path check rejected the package (exit $rc)"
    echo "== NEGATIVE CONTROL: installed beside Debian's ash, that package must be refused or caught"
    install_distro_ash
    vl_assert_shell_intact ash || vl_fail "the shell is broken before the variant was installed"
    rc=0
    deb_install "$VARIANT" 2>/tmp/variant-install.err || rc=$?
    if [ "$rc" -ne 0 ]; then
      tail -n 5 /tmp/variant-install.err | sed 's/^/   /'
      echo "   OK: the install was refused (dpkg saw the conflict)"
    else
      echo "   dpkg installed it without reporting a conflict over /usr/bin/ash"
      rc=0
      vl_assert_shell_intact ash || rc=$?
      [ "$rc" -ne 0 ] || vl_fail "NEGATIVE CONTROL: the coexistence check ACCEPTED a host where the package installed /usr/bin/ash"
      echo "   OK: the coexistence check rejected the host: the package replaced the shell (exit $rc)"
    fi
    echo; echo "DEB NEGATIVE CONTROL (shell path) PASSED"
    exit 0
    ;;
  negative-payload)
    echo "== NEGATIVE CONTROL: an empty-payload .deb must FAIL the payload gate"
    STAGE="$(mktemp -d)"
    install -d "$STAGE/DEBIAN"
    sed -e "s/@DEB_VERSION@/${VERSION}/" -e "s/@ASH_PKG@/${ASH_PKG_NAME}/g" -e "s/@ASH_CLI@/${ASH_CLI_NAME}/g" "$REPO/packaging/deb/debian/control.in" > "$STAGE/DEBIAN/control"
    mkdir -p "$OUT"
    EMPTY="$OUT/${ASH_PKG_NAME}_${VERSION}_all.deb"
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
# No relationship field may name `ash`, Debian's package for the Almquist shell's name:
# Conflicts or Breaks would remove it, Replaces would let this package take its files,
# and Provides would satisfy a dependency on the shell with a scanner.
for field in Provides Conflicts Breaks Replaces; do
  value="$(dpkg-deb --field "$DEB" "$field")"
  [ -z "$value" ] || vl_fail "the package declares $field: $value; it must carry no $field field"
done
vl_payload_gate "$DEB"
check_deb_paths "$DEB" || vl_fail "the package's file list must carry /usr/bin/$ASH_CLI_NAME and no other command"
deb_maintainer_scripts "$DEB" | vl_check_maintainer_scripts "the maintainer scripts of $(basename "$DEB")" \
  || vl_fail "the package's maintainer scripts must register no alternative and no diversion"

if [ "$MODE" = negative-alternatives ]; then
  echo "== NEGATIVE CONTROL: a .deb whose postinst registers /usr/bin/ash as an alternative must FAIL"
  # The real package with one line added before postinst's final `exit 0`: what an
  # `ash` alias done through update-alternatives instead of a shipped file would be.
  ALT_ROOT="$(mktemp -d)"
  dpkg-deb -R "$DEB" "$ALT_ROOT"
  sed -i "s|^exit 0\$|update-alternatives --install /usr/bin/ash ash /usr/bin/${ASH_CLI_NAME} 100\nexit 0|" "$ALT_ROOT/DEBIAN/postinst"
  grep -q '^update-alternatives --install /usr/bin/ash ' "$ALT_ROOT/DEBIAN/postinst" \
    || vl_fail "could not plant the update-alternatives call in postinst"
  mkdir -p "$OUT/alternatives"
  ALT="$OUT/alternatives/${ASH_PKG_NAME}_${VERSION}_all.deb"
  dpkg-deb --build -Zgzip --root-owner-group "$ALT_ROOT" "$ALT" >/dev/null
  rc=0
  deb_maintainer_scripts "$ALT" | vl_check_maintainer_scripts "the maintainer scripts of the variant" || rc=$?
  [ "$rc" -ne 0 ] || vl_fail "NEGATIVE CONTROL: the maintainer-script check ACCEPTED a postinst calling update-alternatives"
  echo "   OK: the maintainer-script check rejected the package (exit $rc)"
  echo "== NEGATIVE CONTROL: installed beside Debian's ash, that package must be refused or caught"
  install_distro_ash
  vl_assert_no_alternatives || vl_fail "the host already has an alternative into the package before the variant was installed"
  rc=0
  deb_install "$ALT" 2>/tmp/variant-install.err || rc=$?
  if [ "$rc" -ne 0 ]; then
    tail -n 5 /tmp/variant-install.err | sed 's/^/   /'
    # Refused counts only if the planted call is what failed, not anything else.
    grep -qF update-alternatives /tmp/apt-install.log \
      || vl_fail "NEGATIVE CONTROL: the install failed, but not in the planted update-alternatives call"
    echo "   OK: the install was refused in the planted update-alternatives call"
  else
    rc=0
    vl_assert_no_alternatives || rc=$?
    [ "$rc" -ne 0 ] || vl_fail "NEGATIVE CONTROL: the host check ACCEPTED an install that registered an alternative"
    echo "   OK: the host check rejected the alternative the postinst registered (exit $rc)"
    rc=0
    vl_assert_shell_intact ash || rc=$?
    echo "   for the record, the shell check on that host exited $rc"
  fi
  echo; echo "DEB NEGATIVE CONTROL (alternatives) PASSED"
  exit 0
fi

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
  BROKEN="$OUT/broken/${ASH_PKG_NAME}_${VERSION}_all.deb"
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
  # shellcheck source=packaging/version-map.sh
  . "$REPO/packaging/version-map.sh"
  dpkg --compare-versions "$(pkg_version "$PREV_VERSION" deb)" lt "$(pkg_version "$VERSION" deb)" \
    || vl_fail "the N-1 wheel ($PREV_VERSION) does not sort below N ($VERSION)"
  vl_load_n1
  vl_report_script_delta packaging/deb/debian/postinst packaging/deb/debian/prerm packaging/deb/build.sh
  PREV_DEB="$("$PREV_SRC/packaging/deb/build.sh" "$PREV_WHEEL" "$OUT/prev")"
  echo "   built N-1 with N-1's own packaging/deb/build.sh: $PREV_DEB"
  vl_payload_gate_n1 "$PREV_DEB"

  echo "== 3. install N-1 ($PREV_VERSION)"
  deb_install "$PREV_DEB"
  vl_assert_installed_version "$PREV_VERSION"
  # The layout is asserted after the upgrade below, not here, so the availability
  # probe is the first check that sees an install which breaks the venv mid-upgrade.
  OLD_VENV="$(readlink -f "$ASH_VENV")"

  echo "== 4. upgrade to N ($VERSION): the venv must be REPLACED, and never absent"
  vl_probe_start
  deb_install "$DEB"
  vl_probe_stop_and_assert
  vl_assert_installed_version "$VERSION"
  vl_assert_venv_layout
  vl_assert_no_alternatives || vl_fail "the upgrade registered an alternative or a diversion"
  [ "$(readlink -f "$ASH_VENV")" != "$OLD_VENV" ] || vl_fail "the venv is the one N-1 created"
  [ ! -e "$OLD_VENV" ] || vl_fail "the N-1 venv $OLD_VENV survived a successful upgrade"
  echo "   OK: the venv was rebuilt and the N-1 venv is gone"

  echo "== 5. the three e2e cases with the upgraded install"
  vl_scan_and_assert

  echo "== 6. prerm must keep the venv on upgrade and failed-upgrade"
  for arg in upgrade failed-upgrade; do
    "/var/lib/dpkg/info/$ASH_PKG_NAME.prerm" "$arg" "$VERSION"
    [ -x "$ASH_VENV/bin/$ASH_CLI_NAME" ] || vl_fail "prerm $arg deleted the venv"
    echo "   OK: prerm $arg left $ASH_VENV in place"
  done

  echo "== 7. an upgrade whose dependency resolve fails must leave the working install"
  LIVE_VENV="$(readlink -f "$ASH_VENV")"
  vl_blackhole_index
  rc=0
  vl_probe_start
  PIP_RETRIES=0 PIP_TIMEOUT=5 apt-get install -y -q --reinstall "$DEB" >/tmp/apt-fail.log 2>&1 || rc=$?
  vl_probe_stop_and_assert
  vl_restore_index
  sed -n "s/^$ASH_CLI_NAME: /   $ASH_CLI_NAME: /p" /tmp/apt-fail.log
  [ "$rc" -ne 0 ] || vl_fail "the reinstall with no reachable index exited 0, so it did not exercise a failed upgrade"
  echo "   the reinstall failed as intended (exit $rc)"
  vl_assert_installed_version "$VERSION"
  vl_assert_venv_layout
  [ "$(readlink -f "$ASH_VENV")" = "$LIVE_VENV" ] || vl_fail "the failed upgrade repointed $ASH_VENV"
  echo "   OK: the failed upgrade left the working venv in place and nothing behind"

  echo "== 8. the documented recovery works once the index is back"
  dpkg --configure -a >/tmp/dpkg-configure.log 2>&1 || { tail -n 20 /tmp/dpkg-configure.log >&2; vl_fail "dpkg --configure -a failed"; }
  [ "$(dpkg-query -W -f='${Status}' "$ASH_PKG_NAME")" = "install ok installed" ] || vl_fail "$ASH_PKG_NAME is not configured after recovery"
  vl_assert_installed_version "$VERSION"
  vl_assert_venv_layout

  echo "== 9. a host still on the directory layout is migrated to the symlink"
  vl_make_directory_layout "$(one_wheel "$ASH_LIB/wheels")"
  deb_install_reinstall "$DEB"
  vl_assert_installed_version "$VERSION"
  vl_assert_venv_layout
  echo "   OK: the directory venv was replaced by a link and nothing was left behind"

  echo "== 10. purge leaves nothing behind"
  purge_and_check
  echo; echo "DEB UPGRADE VERIFICATION PASSED"
  exit 0
fi

if [ "$MODE" = assert ]; then
  echo "== 3a. install Debian's ash shell first, so the package is installed beside it"
  install_distro_ash
  vl_assert_shell_intact ash || vl_fail "Debian's ash shell does not work before the package is installed"
fi

echo "== 3. install it with apt; apt must pull in the interpreter itself"
if key_dependency_installed; then
  vl_fail "python3-venv is already installed, so this run cannot show the package's own Depends works"
fi
deb_install "$DEB"
key_dependency_installed || vl_fail "python3-venv is still absent after installing the package"
echo "   python3-venv was pulled in by the package's Depends"
vl_assert_installed_version "$VERSION"
dpkg -L "$ASH_PKG_NAME" | vl_check_command_paths "dpkg -L $ASH_PKG_NAME" \
  || vl_fail "the installed package's file list must carry /usr/bin/$ASH_CLI_NAME and no other command"
vl_assert_no_alternatives || vl_fail "the install registered an alternative or a diversion"

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
  negative-incomplete)
    echo "== NEGATIVE CONTROL: exit 1 and exit 2 must each FAIL as the other"
    vl_negative_incomplete
    purge_and_check
    echo; echo "DEB NEGATIVE CONTROL (incomplete) PASSED"
    exit 0
    ;;
  assert) ;;
  *) vl_fail "unknown mode $MODE" ;;
esac

echo "== 3b. the package and Debian's ash shell work side by side"
vl_assert_shell_coexists ash || vl_fail "the package and Debian's ash shell do not coexist"

echo "== 4. the three e2e cases: findings (exit 2), clean (exit 0), incomplete (exit 1)"
vl_scan_and_assert

echo "== 4b. scanners are selected after install: --tool grype installs and verifies it, an unknown name is refused"
vl_assert_dependency_selection

echo "== 5. purge leaves nothing behind, and leaves the shell alone"
purge_and_check
[ "$(dpkg-query -W -f='${Status}' ash)" = "install ok installed" ] || vl_fail "purging $ASH_PKG_NAME removed Debian's ash package"
vl_assert_shell_intact ash || vl_fail "purging $ASH_PKG_NAME broke Debian's ash shell"

echo
echo "DEB VERIFICATION PASSED"
