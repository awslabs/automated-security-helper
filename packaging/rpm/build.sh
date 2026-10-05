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
REPO_ROOT="$(cd "$SPECDIR/../.." && pwd)"

# The CLI and package names live in one file so renaming either is a one-line change. See
# packaging/cli-name.sh. They reach the spec as the ash_cli and ash_pkg macros.
# shellcheck source=packaging/cli-name.sh
. "$SPECDIR/../cli-name.sh"
: "${ASH_CLI_NAME:?packaging/cli-name.sh did not set ASH_CLI_NAME}"
: "${ASH_PKG_NAME:?packaging/cli-name.sh did not set ASH_PKG_NAME}"

[ -f "$WHEEL" ] || { echo "error: no such wheel: $WHEEL" >&2; exit 1; }
command -v rpmbuild >/dev/null || { echo "error: rpmbuild not found" >&2; exit 1; }

WHEEL_BASE="$(basename "$WHEEL")"
VERSION="$(printf '%s\n' "$WHEEL_BASE" | sed -n 's/^automated_security_helper-\([^-]*\)-py3-none-any\.whl$/\1/p')"
if [ -z "$VERSION" ]; then
  echo "error: could not read a version from '$WHEEL_BASE'." >&2
  echo "       expected automated_security_helper-<version>-py3-none-any.whl" >&2
  exit 1
fi

# Mapped so rpm sorts it the way PEP 440 does: 3.8.0rc1 becomes 3.8.0~rc1, which
# sorts below 3.8.0, where the verbatim string would sort above it and the release
# would never replace the candidate. See packaging/version-map.sh.
# shellcheck source=packaging/version-map.sh
. "$SPECDIR/../version-map.sh"
RPM_VERSION="$(pkg_version "$VERSION" rpm)"

TOP="$(mktemp -d)"
trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP"/{SOURCES,SPECS,BUILD,BUILDROOT,RPMS,SRPMS}
cp "$WHEEL" "$TOP/SOURCES/"
cp "$SPECDIR/README.rpm" "$TOP/SOURCES/"
cp "$REPO_ROOT/LICENSE" "$TOP/SOURCES/"
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
      --define "ash_cli $ASH_CLI_NAME" \
      --define "ash_pkg $ASH_PKG_NAME" \
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
