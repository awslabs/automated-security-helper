#!/usr/bin/env bash
#
# Builds the ASH Flatpak bundle from an already-built wheel.
#
# Takes the wheel rather than building one, for the same reason the release workflow
# attests what it built: a packaging step that also builds its own payload can ship a
# different wheel than the one the contents gate approved. Pass the artifact that
# passed the gate.
#
# Requires flatpak and flatpak-builder, plus the org.freedesktop Platform and Sdk
# runtimes named in the manifest. flatpak-builder drives bwrap, which needs to create a
# user namespace, so this does not run in a container that withholds that -- see
# README.flatpak for the measured behavior under Docker.
#
# Usage: build.sh <wheel> <outdir>
set -euo pipefail

WHEEL="${1:?usage: build.sh <wheel> <outdir>}"
OUTDIR="${2:?usage: build.sh <wheel> <outdir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
APP_ID="io.github.awslabs.automated_security_helper"
MANIFEST="$HERE/$APP_ID.yml"
BRANCH="stable"

[ -f "$WHEEL" ] || { echo "error: no such wheel: $WHEEL" >&2; exit 1; }
[ -f "$MANIFEST" ] || { echo "error: no manifest at $MANIFEST" >&2; exit 1; }
command -v flatpak >/dev/null || { echo "error: flatpak not found" >&2; exit 1; }
command -v flatpak-builder >/dev/null || {
  echo "error: flatpak-builder not found" >&2
  exit 1
}

# Version comes from the wheel filename, not from pyproject.toml or a git tag. The
# wheel is the thing being packaged, so reading anything else introduces a way for the
# package version and its payload to disagree.
#
# Unlike the .deb and .rpm there is no version translation here. Those two reject '-'
# in a version field, so both rewrite PEP 440 pre-release and local versions
# (1.0.0-rc1, 1.0.0+local) to use '~'. Nothing in a Flatpak carries the version as a
# constrained field: it goes into this bundle's filename and nowhere else, so the PEP
# 440 string is used verbatim. A reader arriving from packaging/deb/build.sh will look
# for the translation, which is why its absence is stated rather than left implied.
WHEEL_BASE="$(basename "$WHEEL")"
VERSION="$(printf '%s\n' "$WHEEL_BASE" | sed -n 's/^automated_security_helper-\([^-]*\)-py3-none-any\.whl$/\1/p')"
if [ -z "$VERSION" ]; then
  echo "error: could not read a version from '$WHEEL_BASE'." >&2
  echo "       expected automated_security_helper-<version>-py3-none-any.whl" >&2
  exit 1
fi

ARCH="$(flatpak --default-arch)"

mkdir -p "$OUTDIR"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# The manifest is copied into a staging directory rather than built in place, because
# flatpak-builder resolves every source `path` relative to the manifest's own directory
# and writes .flatpak-builder/, a build dir and a repo beside it. Building in
# packaging/flatpak/ would drop all of that into the checkout, where the next `git
# status` reports it and a careless `git add -A` commits it.
install -d -m 0755 "$STAGE/wheels"
install -m 0644 "$MANIFEST" "$STAGE/$APP_ID.yml"
install -m 0755 "$HERE/ash-launcher.sh" "$STAGE/ash-launcher.sh"
install -m 0644 "$WHEEL" "$STAGE/wheels/"

BUILD_DIR="$STAGE/build-dir"
REPO="$STAGE/repo"

# --disable-download and --disable-updates: the manifest has no remote sources, so
# neither should do anything. They are passed so that a future source with a `url`
# fails the build here instead of quietly fetching -- an accidental
# `flatpak-pip-generator` paste is the specific edit these two flags are aimed at, and
# it is the edit that would put third-party code in the bundle.
#
# NOT passed: --share=network in build-options. flatpak-builder gives the build sandbox
# no network unless a manifest asks for it, so a `pip install` of ASH's dependencies at
# build time cannot succeed even if someone adds one. That is what keeps this bundle at
# one wheel by mechanism rather than by review.
#
# flatpak-builder writes its own progress to stdout and the module's build output to
# both streams, so everything is captured and replayed only on failure. Letting it
# through buries this script's output; discarding stderr would hide why a build failed.
BUILD_LOG="$STAGE/flatpak-builder.log"
if ! flatpak-builder \
      --disable-download \
      --disable-updates \
      --force-clean \
      --default-branch="$BRANCH" \
      --repo="$REPO" \
      "$BUILD_DIR" "$STAGE/$APP_ID.yml" >"$BUILD_LOG" 2>&1; then
  echo "error: flatpak-builder failed. Its output follows:" >&2
  cat "$BUILD_LOG" >&2
  exit 1
fi

# flatpak-builder exiting 0 is not evidence it assembled a usable app, and the checks
# below are the ones that can be made against a directory tree before anything is
# installed. The install-and-scan checks live in verify-in-container.sh.

# 1. The payload must be ASH's wheel and nothing else. This is the invariant check at
#    the package layer: the contents gate covers the wheel, this covers what the
#    Flatpak adds. It is stricter here than for the .deb and .rpm, because a Flatpak
#    build step could have pip-installed dependencies into /app as loose modules rather
#    than as wheels -- so the count below is paired with a check that site-packages was
#    never created inside the app.
WHEELDIR="$BUILD_DIR/files/share/ash/wheels"
# Tested separately from the count. `find` on a missing directory writes to stderr and
# exits non-zero while `wc -l` still prints 0, so under `set -o pipefail` the two cases
# "no wheels directory" and "no wheels in it" would both surface as a bare find error
# with the script's own message never printed.
[ -d "$WHEELDIR" ] || {
  echo "error: the built app has no $WHEELDIR." >&2
  echo "       The manifest's build-commands did not install the wheel." >&2
  exit 1
}
PAYLOAD_WHEELS="$(find "$WHEELDIR" -maxdepth 1 -name '*.whl' | wc -l)"
if [ "$PAYLOAD_WHEELS" -ne 1 ]; then
  echo "error: expected exactly 1 bundled wheel, found $PAYLOAD_WHEELS." >&2
  echo "       Bundling dependency wheels would put detect-secrets, a scanner, in a" >&2
  echo "       published artifact. See packaging/README.md." >&2
  exit 1
fi

# 2. No third-party Python distribution may have been installed into the app. A wheel
#    count alone would miss it: `pip install --target /app/lib` leaves no .whl behind,
#    only unpacked modules and .dist-info directories. Any .dist-info under /app is
#    therefore the signal, and there must be none -- ASH itself is installed at first
#    run into the user's data directory, never into /app.
#    No -maxdepth: the built app is one wheel and three scripts, so an unbounded walk
#    costs nothing and cannot miss a depth. `pip install --target /app` leaves .dist-info
#    at depth 1 and `--prefix /app` leaves it at depth 4, so any fixed bound here would
#    be a guess about which mistake someone made.
STRAY="$(find "$BUILD_DIR/files" \( -name '*.dist-info' -o -name '*.egg-info' \) | head -5)"
if [ -n "$STRAY" ]; then
  echo "error: the built app contains installed Python distributions:" >&2
  printf '       %s\n' $STRAY >&2
  echo "       Nothing may be pip-installed into /app; the app carries one wheel and" >&2
  echo "       resolves dependencies at first run. See packaging/README.md." >&2
  exit 1
fi

# 3. All three entry-point names must be present. The wheel declares ash, ashv3 and
#    automated-security-helper, and a package that installs a subset would leave the
#    escape-hatch name missing on exactly the hosts it exists for.
for name in ash ashv3 automated-security-helper; do
  [ -x "$BUILD_DIR/files/bin/$name" ] || {
    echo "error: $BUILD_DIR/files/bin/$name is missing or not executable." >&2
    exit 1
  }
done

# 4. The sandbox permissions must have landed in the app's metadata. This is the check
#    for the failure this package exists to avoid: a Flatpak whose finish-args were
#    dropped or narrowed installs perfectly, runs `ash --version` perfectly, and then
#    cannot read the tree it was asked to scan -- because ASH's default source is the
#    process CWD, which is on the host. Reading it back from metadata catches an edited
#    manifest here rather than in a bug report.
METADATA="$BUILD_DIR/metadata"
[ -f "$METADATA" ] || { echo "error: no $METADATA" >&2; exit 1; }
if ! grep -Eq '^filesystems=(.*;)?host(;|$)' "$METADATA"; then
  echo "error: $METADATA does not grant filesystems=host." >&2
  echo "       Without it ASH installs and cannot scan: its default source directory" >&2
  echo "       is the process CWD and its default output directory is inside the tree" >&2
  echo "       being scanned, so both are outside the sandbox. README.flatpak explains" >&2
  echo "       why no narrower grant works." >&2
  grep -n '^filesystems=' "$METADATA" >&2 || echo "       (no filesystems= line at all)" >&2
  exit 1
fi
if ! grep -Eq '^shared=(.*;)?network(;|$)' "$METADATA"; then
  echo "error: $METADATA does not grant shared=network." >&2
  echo "       The first run resolves ASH's dependencies from a Python index, so" >&2
  echo "       without network the app can never finish its own bootstrap." >&2
  exit 1
fi

BUNDLE="$OUTDIR/ash-${VERSION}-${ARCH}.flatpak"
flatpak build-bundle "$REPO" "$BUNDLE" "$APP_ID" "$BRANCH" >/dev/null

# build-bundle exiting 0 is not evidence it wrote a usable bundle either. There is no
# `flatpak bundle --info`, so the readback that exists at this layer is a size check;
# the authoritative one is `flatpak install --bundle` in verify-in-container.sh, which
# fails on a truncated or malformed bundle.
[ -s "$BUNDLE" ] || { echo "error: build-bundle wrote an empty file" >&2; exit 1; }

echo "$BUNDLE"
