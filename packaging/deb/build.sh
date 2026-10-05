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
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

# The CLI and package names live in one file so renaming either is a one-line change.
# See packaging/cli-name.sh.
# shellcheck source=packaging/cli-name.sh
. "$HERE/../cli-name.sh"
: "${ASH_CLI_NAME:?packaging/cli-name.sh did not set ASH_CLI_NAME}"
: "${ASH_PKG_NAME:?packaging/cli-name.sh did not set ASH_PKG_NAME}"
# Debian policy 5.6.1. Checked here because the name is also substituted into the
# maintainer scripts' rm -rf paths, so it must be a plain path component.
if ! printf '%s\n' "$ASH_PKG_NAME" | grep -Eqx '[a-z0-9][a-z0-9+.-]+'; then
  echo "error: ASH_PKG_NAME '$ASH_PKG_NAME' is not a valid Debian package name." >&2
  exit 1
fi
PKG="$ASH_PKG_NAME"

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

# Mapped so dpkg sorts it the way PEP 440 does: 3.8.0rc1 becomes 3.8.0~rc1, which
# sorts below 3.8.0, where the verbatim string would sort above it and the release
# would never replace the candidate. See packaging/version-map.sh.
# shellcheck source=packaging/version-map.sh
. "$HERE/../version-map.sh"
DEB_VERSION="$(pkg_version "$VERSION" deb)"

mkdir -p "$OUTDIR"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Every path staged here is pinned by packaging/assert-package-payload.py, which fails
# the build on a payload member it does not list. Adding a file means adding it there
# in the same commit, which is the point: the payload of a package that must not carry
# third-party scanner code is enumerated, not discovered.
install -d -m 0755 "$STAGE/DEBIAN" "$STAGE/usr/lib/$PKG/wheels" "$STAGE/usr/bin" \
              "$STAGE/usr/share/doc/$PKG"
install -m 0644 "$WHEEL" "$STAGE/usr/lib/$PKG/wheels/"

# postinst's failure message points users here, so the doc has to be in the package.
# An error message citing a path the package never installed is worse than no message.
install -m 0644 "$HERE/debian/README.Debian" "$STAGE/usr/share/doc/$PKG/README.Debian"
# Debian policy 12.5: every binary package ships its license as
# /usr/share/doc/<package>/copyright.
install -m 0644 "$REPO_ROOT/LICENSE" "$STAGE/usr/share/doc/$PKG/copyright"

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
sed -e "s/@DEB_VERSION@/${DEB_VERSION}/" -e "s/@ASH_PKG@/${PKG}/g" \
    -e "s/@ASH_CLI@/${ASH_CLI_NAME}/g" \
    "$HERE/debian/control.in" > "$STAGE/DEBIAN/control"
if grep -q '@[A-Z_]*@' "$STAGE/DEBIAN/control"; then
  echo "error: DEBIAN/control still carries an unsubstituted @...@ token." >&2
  exit 1
fi

# Assert the generated control file is comment-free before handing it to dpkg-deb, so a
# future edit to control.in fails here with a message naming the cause rather than in
# dpkg-deb's parser.
if grep -q '^#' "$STAGE/DEBIAN/control"; then
  echo "error: DEBIAN/control contains a '#' line; dpkg-deb rejects comments there." >&2
  echo "       Put the explanation in build.sh instead of debian/control.in." >&2
  exit 1
fi

# The maintainer scripts carry @ASH_CLI@ where they name the console script and
# @ASH_PKG@ where they name the package's directories, so both names are substituted
# from packaging/cli-name.sh rather than written into each one.
for script in postinst prerm; do
  sed -e "s/@ASH_CLI@/${ASH_CLI_NAME}/g" -e "s/@ASH_PKG@/${PKG}/g" \
    "$HERE/debian/$script" > "$STAGE/DEBIAN/$script"
  chmod 0755 "$STAGE/DEBIAN/$script"
  if grep -q '@ASH_CLI@\|@ASH_PKG@' "$STAGE/DEBIAN/$script"; then
    echo "error: a @ASH_CLI@ or @ASH_PKG@ token was not substituted in DEBIAN/$script." >&2
    exit 1
  fi
done

# The wrapper, not a symlink into the venv. The CLI shells out to sys.executable for
# the container runner, and a symlink leaves sys.executable pointing at /usr/bin.
cat > "$STAGE/usr/bin/${ASH_CLI_NAME}" <<WRAPPER
#!/bin/sh
# Installed by the ${PKG} .deb. The venv is created by the package's postinst, not
# shipped inside it, so this is also the check for a half-completed install.
if [ ! -x /usr/lib/${PKG}/venv/bin/${ASH_CLI_NAME} ]; then
  echo "${ASH_CLI_NAME}: /usr/lib/${PKG}/venv is missing or incomplete." >&2
  echo "${ASH_CLI_NAME}: re-run the install step with: dpkg --configure -a" >&2
  echo "${ASH_CLI_NAME}: or reinstall the package from its .deb." >&2
  exit 127
fi
exec /usr/lib/${PKG}/venv/bin/${ASH_CLI_NAME} "\$@"
WRAPPER
chmod 0755 "$STAGE/usr/bin/${ASH_CLI_NAME}"

DEB="$OUTDIR/${PKG}_${DEB_VERSION}_all.deb"
# -Zgzip, not dpkg-deb's default. bookworm defaults to xz and newer Debian and Ubuntu
# to zstd, and zstd has no Python standard-library decompressor before 3.14.
# packaging/assert-package-payload.py reads the package with the standard library
# alone rather than with dpkg-deb, because a check that opens an artifact with the
# tool that wrote it inherits that tool's blind spots, so the payload compression is
# pinned to one it can always read. The cost is a few hundred KB.
dpkg-deb --build -Zgzip --root-owner-group "$STAGE" "$DEB" >/dev/null

# dpkg-deb exiting 0 is not evidence it wrote a usable package; ask dpkg to read it
# back. `--info` parses the control archive and `--contents` the data archive, so
# between them a truncated member surfaces here rather than on a user's machine.
dpkg-deb --info "$DEB" >/dev/null
dpkg-deb --contents "$DEB" >/dev/null

echo "$DEB"
