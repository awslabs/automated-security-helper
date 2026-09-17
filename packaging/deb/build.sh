#!/usr/bin/env bash
#
# Builds the ASH .deb from an already-built wheel.
#
# Takes the wheel rather than building one, for the same reason the release workflow
# attests what it built: a packaging step that also builds its own payload can ship a
# different wheel than the one the contents gate approved. Pass the artifact that
# passed the gate.
#
# Requires dpkg-deb, which is why CI runs this inside a Debian job container rather
# than on the ubuntu-latest host -- ubuntu-latest has dpkg-deb, but building the
# package in the same image that tests it would let a missing dependency pass because
# the build host happened to provide it.
#
# Usage: build.sh <wheel> <outdir>
set -euo pipefail

WHEEL="${1:?usage: build.sh <wheel> <outdir>}"
OUTDIR="${2:?usage: build.sh <wheel> <outdir>}"

[ -f "$WHEEL" ] || { echo "error: no such wheel: $WHEEL" >&2; exit 1; }
command -v dpkg-deb >/dev/null || { echo "error: dpkg-deb not found" >&2; exit 1; }

# Version comes from the wheel filename, not from pyproject.toml or a git tag. The
# wheel is the thing being packaged, so reading anything else introduces a way for
# the package version and its payload to disagree.
WHEEL_BASE="$(basename "$WHEEL")"
VERSION="$(printf '%s\n' "$WHEEL_BASE" | sed -n 's/^automated_security_helper-\([^-]*\)-py3-none-any\.whl$/\1/p')"
if [ -z "$VERSION" ]; then
  echo "error: could not read a version from '$WHEEL_BASE'." >&2
  echo "       expected automated_security_helper-<version>-py3-none-any.whl" >&2
  exit 1
fi

# Debian upstream versions may not contain '-'. PEP 440 pre-release and local
# versions do (1.0.0-rc1, 1.0.0+local), so translate rather than emitting a package
# dpkg-deb will reject with a message that does not mention the wheel.
DEB_VERSION="${VERSION//-/'~'}"
DEB_VERSION="${DEB_VERSION//+/'~'}"

mkdir -p "$OUTDIR"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

install -d -m 0755 "$STAGE/DEBIAN" "$STAGE/usr/lib/ash/wheels" "$STAGE/usr/bin" \
              "$STAGE/usr/share/doc/ash"
install -m 0644 "$WHEEL" "$STAGE/usr/lib/ash/wheels/"

# postinst's failure message points users here, so the doc has to be in the package.
# An error message citing a path the package never installed is worse than no message.
install -m 0644 "$(dirname "$0")/debian/README.Debian" "$STAGE/usr/share/doc/ash/README.Debian"

# Architecture is `all`: the wheel is py3-none-any and carries no compiled extension.
# Dependencies that do build native code are resolved by pip on the target, so they
# match the target's architecture rather than the builder's.
#
# python3-venv and python3-pip are separate packages on Debian and neither is pulled in
# by python3, so both are named. Omitting python3-venv is the classic Debian Python
# packaging failure: `python3 -m venv` exits 1 with a message telling the user to
# apt-get install a package the .deb should have depended on.
# debian/control.in carries NO comments, and must not gain any. dpkg-deb parses the
# generated DEBIAN/control verbatim and rejects a '#' line with
#   "field name '#' must be followed by colon"
# which fails the build rather than being ignored. Measured, after an earlier revision
# put the Maintainer rationale in that file. Any explanation about a control field
# therefore lives here instead.
#
# On Maintainer specifically: the field is mandatory in a Debian control file, but this
# project declares no maintainer contact anywhere -- pyproject.toml has no authors or
# maintainers table and no tracked file carries an address. control.in uses the GitHub
# noreply form for the owning org rather than inventing a personal or internal address.
# If the maintainers want a real contact, set it in pyproject.toml and read it here.
sed -e "s/@DEB_VERSION@/${DEB_VERSION}/" \
    "$(dirname "$0")/debian/control.in" > "$STAGE/DEBIAN/control"

# Assert the generated control file is comment-free before handing it to dpkg-deb, so a
# future edit to control.in fails here with a message naming the cause rather than in
# dpkg-deb's parser.
if grep -q '^#' "$STAGE/DEBIAN/control"; then
  echo "error: DEBIAN/control contains a '#' line; dpkg-deb rejects comments there." >&2
  echo "       Put the explanation in build.sh instead of debian/control.in." >&2
  exit 1
fi

install -m 0755 "$(dirname "$0")/debian/postinst" "$STAGE/DEBIAN/postinst"
install -m 0755 "$(dirname "$0")/debian/prerm"    "$STAGE/DEBIAN/prerm"

# The wrapper, not a symlink into the venv. `ash` shells out to sys.executable for the
# container runner, and a symlink leaves sys.executable pointing at /usr/bin/ash.
cat > "$STAGE/usr/bin/ash" <<'WRAPPER'
#!/bin/sh
# Installed by the ash .deb. The venv is created by the package's postinst, not
# shipped inside it, so this is also the check for a half-completed install.
if [ ! -x /usr/lib/ash/venv/bin/ash ]; then
  echo "ash: /usr/lib/ash/venv is missing or incomplete." >&2
  echo "ash: reinstall the package, or run: dpkg-reconfigure ash" >&2
  exit 127
fi
exec /usr/lib/ash/venv/bin/ash "$@"
WRAPPER
chmod 0755 "$STAGE/usr/bin/ash"

DEB="$OUTDIR/ash_${DEB_VERSION}_all.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$DEB" >/dev/null

# dpkg-deb exiting 0 is not evidence it wrote a usable package; ask dpkg to read it
# back. `--info` parses the control archive and `--contents` the data archive, so
# between them a truncated member surfaces here rather than on a user's machine.
dpkg-deb --info "$DEB" >/dev/null
dpkg-deb --contents "$DEB" >/dev/null

echo "$DEB"
