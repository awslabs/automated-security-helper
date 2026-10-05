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
#   assert             build, gate the payload, install beside a package that owns
#                      /usr/bin/ash, scan, erase (the default)
#   upgrade            install N-1 built from $PREV_DIST, upgrade to N, require the venv
#                      to be replaced; then fail an upgrade on purpose and require the
#                      working install to survive it; then migrate a venv left as a
#                      directory by an older release to the symlink layout; then erase
#   negative-findings  the fixture with its finding removed must FAIL the findings gate
#   negative-scan-rc   a scan exiting 0 with findings must FAIL the exit-code gate
#   negative-install   a package whose %post fails must FAIL the install step
#   negative-payload   a package with an empty payload must FAIL the payload gate
#   negative-shell-path
#                      a build that also installs /usr/bin/ash must FAIL the command
#                      path check, and installing it beside the package that owns
#                      /usr/bin/ash must either be refused or FAIL the coexistence check
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

# Exit 0 when $1 sorts strictly below $2 under rpm's own comparator, the same call
# packaging/test-version-map.sh makes, rather than a reimplementation of it.
rpm_sorts_below() {
  [ "$(rpm --eval "%{lua: print(rpm.vercmp('$1', '$2'))}")" = "-1" ]
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
  dnf -y -q remove "$ASH_PKG_NAME" >/tmp/dnf-remove.log 2>&1 || { tail -n 20 /tmp/dnf-remove.log >&2; vl_fail "dnf remove $ASH_PKG_NAME failed"; }
  if rpm -q "$ASH_PKG_NAME" >/dev/null 2>&1; then
    vl_fail "rpm still lists $ASH_PKG_NAME after erase"
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
# the only thing changed; build.sh sources cli-name.sh and version-map.sh and reads
# LICENSE relative to itself, so those are copied alongside.
build_variant() {
  local edit="$1" wheel="$2" out="$3" tree
  tree="$(mktemp -d)"
  mkdir -p "$tree/packaging"
  cp -r "$REPO/packaging/rpm" "$tree/packaging/rpm"
  cp "$REPO/packaging/cli-name.sh" "$REPO/packaging/version-map.sh" "$tree/packaging/"
  cp "$REPO/LICENSE" "$tree/"
  if vl_gate_python - "$tree/packaging/rpm/ash.spec" "$edit" <<'PY'
import re, sys
path, edit = sys.argv[1], sys.argv[2]
spec = open(path, encoding="utf-8").read()
if edit == "empty-payload":
    # %install and %files emptied: the package carries no payload at all.
    spec = re.sub(r"(?ms)^%install\n.*?(?=^%files\n)", "%install\n\n", spec)
    spec = re.sub(r"(?ms)^%files\n.*?(?=^# Creates the venv)", "%files\n\n", spec)
elif edit == "ships-ash-path":
    # The wrapper also installed as /usr/bin/ash and listed in %files: what a revert to
    # ASH_CLI_NAME=ash, or an added alias, would produce.
    install_line = "chmod 0755 %{buildroot}%{_bindir}/%{ash_cli}\n"
    files_line = "\n%{_bindir}/%{ash_cli}\n"
    if spec.count(install_line) != 1 or spec.count(files_line) != 1:
        sys.exit("could not find the wrapper's chmod and %files lines")
    spec = spec.replace(
        install_line,
        install_line + "cp -p %{buildroot}%{_bindir}/%{ash_cli} %{buildroot}%{_bindir}/ash\n",
    )
    spec = spec.replace(files_line, files_line + "%{_bindir}/ash\n")
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
  then :; else
    # Inside $(...) errexit does not apply, so a failed edit would otherwise go on to
    # build the unedited spec and hand the caller a correct package as the variant.
    echo "FAIL: could not apply the $edit edit to the spec" >&2
    return 1
  fi
  "$tree/packaging/rpm/build.sh" "$wheel" "$out"
}

if [ "$MODE" = version-map ]; then
  echo "== package versions must sort the way PEP 440 does"
  exec bash "$REPO/packaging/test-version-map.sh" rpm "$WHEEL"
fi

check_rpm_paths() {
  rpm -qlp "$1" | vl_check_command_paths "rpm -qlp $(basename "$1")"
}

# Neither Amazon Linux 2023 nor RHEL 9 ships an Almquist shell: measured with
#   dnf repoquery --whatprovides '*/bin/ash'
# which lists nothing on either image. Debian's legs install the real one. Here a
# minimal package named `ash` stands in for it: it owns /usr/bin/ash, as a script that
# hands its arguments to /bin/sh, so rpm's own file-conflict detection and dnf's
# name resolution see exactly what they would see with a real `ash` installed. It is
# installed before the package under test, so that install is the one that would
# replace it.
install_ash_standin() {
  local top
  top="$(mktemp -d)"
  mkdir -p "$top"/{SPECS,BUILD,BUILDROOT,RPMS,SRPMS,SOURCES}
  cat > "$top/SPECS/ash-standin.spec" <<'SPEC'
Name:           ash
Version:        0.0.1
Release:        1
Summary:        Stand-in for an Almquist shell that owns /usr/bin/ash (test only)
License:        Apache-2.0
BuildArch:      noarch

%description
Owns /usr/bin/ash, so the package under test is installed beside a package that does.

%install
install -d -m 0755 %{buildroot}%{_bindir}
printf '#!/bin/sh\nexec /bin/sh "$@"\n' > %{buildroot}%{_bindir}/ash
chmod 0755 %{buildroot}%{_bindir}/ash

%files
%{_bindir}/ash
SPEC
  rpmbuild --define "_topdir $top" -bb "$top/SPECS/ash-standin.spec" >/tmp/ash-standin.log 2>&1 \
    || { tail -n 20 /tmp/ash-standin.log >&2; vl_fail "could not build the ash stand-in"; }
  rpm_install install "$(find "$top/RPMS" -name 'ash-*.rpm' -print -quit)" >/dev/null \
    || vl_fail "could not install the ash stand-in"
  rpm -q ash >/dev/null || vl_fail "the ash stand-in is not installed"
  vl_say "   installed the ash stand-in $(rpm -q ash), owner of $(rpm -qf /usr/bin/ash --qf '%{NAME}'):/usr/bin/ash"
}

case "$MODE" in
  negative-shell-path)
    echo "== NEGATIVE CONTROL: an .rpm that also installs /usr/bin/ash must FAIL the command path check"
    VARIANT="$(build_variant ships-ash-path "$WHEEL" "$OUT/with-ash")"
    rpm -qlp "$VARIANT" | grep '/bin/' | sed 's/^/   listed: /'
    rc=0
    check_rpm_paths "$VARIANT" || rc=$?
    [ "$rc" -ne 0 ] || vl_fail "NEGATIVE CONTROL: the command path check ACCEPTED a package listing /usr/bin/ash"
    echo "   OK: the command path check rejected the package (exit $rc)"
    echo "== NEGATIVE CONTROL: installed beside a package owning /usr/bin/ash, it must be refused or caught"
    install_ash_standin
    vl_assert_shell_intact "ash stand-in" || vl_fail "the shell is broken before the variant was installed"
    rc=0
    rpm_install install "$VARIANT" 2>/tmp/variant-install.err || rc=$?
    if [ "$rc" -ne 0 ]; then
      grep -E 'conflicts|Error' /tmp/dnf-install.log | head -n 3 | sed 's/^/   /'
      echo "   OK: the install was refused (rpm saw the file conflict)"
    else
      echo "   rpm installed it without reporting a conflict over /usr/bin/ash"
      rc=0
      vl_assert_shell_intact "ash stand-in" || rc=$?
      [ "$rc" -ne 0 ] || vl_fail "NEGATIVE CONTROL: the coexistence check ACCEPTED a host where the package installed /usr/bin/ash"
      echo "   OK: the coexistence check rejected the host (exit $rc)"
    fi
    echo; echo "RPM NEGATIVE CONTROL (shell path) PASSED"
    exit 0
    ;;
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
# No Provides, Conflicts or Obsoletes may name `ash`, the Almquist shell's package name.
# rpm adds Provides for the package's own name, so only a dependency on `ash` itself is
# refused.
for kind in provides conflicts obsoletes; do
  if rpm -qp "--$kind" "$RPM" | grep -E '^ash([ (]|$)'; then
    vl_fail "the package's $kind names ash, the Almquist shell's package name"
  fi
done
vl_payload_gate "$RPM"
check_rpm_paths "$RPM" || vl_fail "the package's file list must carry /usr/bin/$ASH_CLI_NAME and no other command"

if [ "$MODE" = upgrade ]; then
  PREV_WHEEL="$(one_wheel "$PREV_DIST")"
  PREV_VERSION="$(wheel_version "$PREV_WHEEL")"
  [ -n "$PREV_VERSION" ] || vl_fail "cannot read a version from $(basename "$PREV_WHEEL")"
  # shellcheck source=packaging/version-map.sh
  . "$REPO/packaging/version-map.sh"
  # If N-1 does not sort below N, `dnf upgrade` below is not an upgrade and nothing
  # after it means what its message says. The deb leg makes the same check.
  rpm_sorts_below "$(pkg_version "$PREV_VERSION" rpm)" "$(pkg_version "$VERSION" rpm)" \
    || vl_fail "the N-1 wheel ($PREV_VERSION) does not sort below N ($VERSION)"
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
  [ "$(rpm -q --qf '%{VERSION}' "$ASH_PKG_NAME")" = "$(pkg_version "$VERSION" rpm)" ] \
    || vl_fail "rpm reports $(rpm -q "$ASH_PKG_NAME") after the upgrade"
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
  vl_assert_venv_layout

  echo "== 8. a host still on the directory layout is migrated to the symlink"
  vl_make_directory_layout "$(one_wheel "$ASH_LIB/wheels")"
  rpm_install reinstall "$RPM"
  vl_assert_installed_version "$VERSION"
  vl_assert_venv_layout
  echo "   OK: the directory venv was replaced by a link and nothing was left behind"

  echo "== 9. erase leaves nothing behind"
  erase_and_check
  echo; echo "RPM UPGRADE VERIFICATION PASSED"
  exit 0
fi

if [ "$MODE" = assert ]; then
  echo "== 3a. install a package that owns /usr/bin/ash first, so the package is installed beside it"
  install_ash_standin
  vl_assert_shell_intact "ash stand-in" || vl_fail "the ash stand-in does not work before the package is installed"
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
rpm -ql "$ASH_PKG_NAME" | vl_check_command_paths "rpm -ql $ASH_PKG_NAME" \
  || vl_fail "the installed package's file list must carry /usr/bin/$ASH_CLI_NAME and no other command"

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

echo "== 3b. the package and the package owning /usr/bin/ash work side by side"
vl_assert_shell_coexists "ash stand-in" || vl_fail "the package and the ash stand-in do not coexist"
[ "$(rpm -qf /usr/bin/ash --qf '%{NAME}')" = ash ] || vl_fail "/usr/bin/ash is not owned by the ash stand-in"

echo "== 4. scan a fixture with a KNOWN finding"
vl_scan_and_assert

echo "== 5. erase leaves nothing behind, and leaves /usr/bin/ash alone"
erase_and_check
rpm -q ash >/dev/null || vl_fail "erasing $ASH_PKG_NAME removed the ash stand-in"
vl_assert_shell_intact "ash stand-in" || vl_fail "erasing $ASH_PKG_NAME broke /usr/bin/ash"

echo
echo "RPM VERIFICATION PASSED"
