#!/usr/bin/env bash
#
# Builds the ASH .rpm from an already-built wheel.
#
# Takes the wheel rather than building one, for the same reason the release workflow
# attests what it built: a packaging step that also builds its own payload can ship a
# different wheel than the one the contents gate approved.
#
# Usage: build.sh <wheel> <outdir>
set -euo pipefail

WHEEL="${1:?usage: build.sh <wheel> <outdir>}"
OUTDIR="${2:?usage: build.sh <wheel> <outdir>}"
SPECDIR="$(cd "$(dirname "$0")" && pwd)"

[ -f "$WHEEL" ] || { echo "error: no such wheel: $WHEEL" >&2; exit 1; }
command -v rpmbuild >/dev/null || { echo "error: rpmbuild not found" >&2; exit 1; }

WHEEL_BASE="$(basename "$WHEEL")"
VERSION="$(printf '%s\n' "$WHEEL_BASE" | sed -n 's/^automated_security_helper-\([^-]*\)-py3-none-any\.whl$/\1/p')"
if [ -z "$VERSION" ]; then
  echo "error: could not read a version from '$WHEEL_BASE'." >&2
  echo "       expected automated_security_helper-<version>-py3-none-any.whl" >&2
  exit 1
fi

# RPM forbids '-' in Version. PEP 440 pre-release and local versions contain it
# (1.0.0-rc1, 1.0.0+local), so translate rather than emitting a spec rpmbuild rejects
# with a message that does not mention the wheel.
RPM_VERSION="${VERSION//-/'~'}"
RPM_VERSION="${RPM_VERSION//+/'~'}"

TOP="$(mktemp -d)"
trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP"/{SOURCES,SPECS,BUILD,BUILDROOT,RPMS,SRPMS}
cp "$WHEEL" "$TOP/SOURCES/"
cp "$SPECDIR/README.rpm" "$TOP/SOURCES/"
cp "$SPECDIR/ash.spec" "$TOP/SPECS/"

mkdir -p "$OUTDIR"
# rpmbuild traces its own %install shell to stderr, so both streams are captured and
# replayed only on failure. Letting it through would bury this script's own output --
# and swallowing stderr unconditionally would hide the reason a build failed.
BUILD_LOG="$TOP/rpmbuild.log"
if ! rpmbuild \
      --define "_topdir $TOP" \
      --define "ash_version $RPM_VERSION" \
      --define "ash_wheel $WHEEL_BASE" \
      --define "dist %{nil}" \
      -bb "$TOP/SPECS/ash.spec" >"$BUILD_LOG" 2>&1; then
  echo "error: rpmbuild failed. Its output follows:" >&2
  cat "$BUILD_LOG" >&2
  exit 1
fi

RPM="$(find "$TOP/RPMS" -name '*.rpm' -print -quit)"
[ -n "$RPM" ] || { echo "error: rpmbuild wrote no rpm" >&2; exit 1; }
cp "$RPM" "$OUTDIR/"
FINAL="$OUTDIR/$(basename "$RPM")"

# rpmbuild exiting 0 is not evidence it wrote a usable package; ask rpm to read it back.
rpm -qp --info "$FINAL" >/dev/null
rpm -qp --list "$FINAL" >/dev/null

echo "$FINAL"
