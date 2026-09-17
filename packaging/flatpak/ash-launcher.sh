#!/bin/sh
#
# Installed as /app/bin/ash inside the Flatpak, with /app/bin/ashv3 and
# /app/bin/automated-security-helper as symlinks to it. All three names come from the
# wheel's [project.scripts]; the launcher dispatches on its own basename so one file
# covers all three and cannot drift between them.
#
# WHY A LAUNCHER AND NOT THE WHEEL'S OWN ENTRY POINT
#
# The .deb and .rpm both create the venv in a post-install scriptlet and put a wrapper
# on PATH that execs it. Flatpak has no post-install hook -- an installed app is an
# immutable read-only OSTree checkout at /app, and there is no point in the install
# where arbitrary code runs on the user's machine. So the venv has to be built on first
# run instead, and this script is the thing that notices it is missing.
#
# The alternative was to pip-install ASH's dependencies into /app at BUILD time, which
# is the conventional Flatpak Python shape (flatpak-pip-generator emits exactly that).
# It is not available here: a built Flatpak carries whatever is in /app, so a build-time
# dependency install would put 27 third-party distributions inside a published artifact.
# packaging/README.md is the rule that forbids it. Building the venv at first run keeps
# the shipped artifact at exactly one wheel -- ASH's own -- which is countable.
#
# WHY THE VENV PATH CONTAINS THE WHEEL NAME AND THE PYTHON VERSION
#
# Two upgrade failures, both silent, both removed by putting the inputs in the path:
#
#   1. A new ASH version. The .deb's postinst does `rm -rf $VENV` before rebuilding,
#      because an in-place `pip install --upgrade` leaves a renamed entry point behind.
#      Nothing runs at Flatpak upgrade time to do that, so a venv keyed only on "venv"
#      would keep serving the OLD ASH after the app was upgraded, and `ash --version`
#      would report the old number with no error anywhere. The wheel filename carries
#      the version, so keying on it makes a stale venv unreachable rather than
#      undetected.
#
#   2. A new runtime branch. org.freedesktop.Sdk 24.08 ships one python3 minor version
#      and a later branch will ship another. A venv records the interpreter it was made
#      with in pyvenv.cfg and puts its packages under lib/python3.N/site-packages, so
#      after such an upgrade `venv/bin/python3` still runs -- it is a symlink to
#      /usr/bin/python3, which still exists -- and imports nothing. That reads as a
#      corrupt ASH install rather than as a stale venv.
#
# The cost is that old venvs linger under the app's data directory after an upgrade.
# That is disk, not correctness, and README.flatpak gives the one-line cleanup.
#
# NOT SET -e, deliberately, for the same reason the .deb's postinst is not: a bare
# non-zero exit here leaves the user with no idea which of venv creation, the index
# fetch, or the entry point was the problem. Every step is checked and reports what to
# do about it.
set -u

SELF="$(basename "$0")"
WHEELS=/app/share/ash/wheels

die() {
  printf '%s: %s\n' "$SELF" "$1" >&2
  shift
  for line in "$@"; do printf '%s: %s\n' "$SELF" "$line" >&2; done
  exit 1
}

# XDG_DATA_HOME is set by flatpak to $HOME/.var/app/$FLATPAK_ID/data, which is the one
# directory an app can always write regardless of its filesystem permissions -- it is
# outside every --filesystem grant, including host, and flatpak mounts it for the app
# by construction. The fallback is the XDG default and only applies when this script is
# run outside a sandbox, which the verification script does on purpose.
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"

# Exactly one wheel, asserted here as well as in the manifest's build-commands and in
# verify-in-container.sh. Three checks on one invariant is not redundancy: this is the
# only one that runs on a user's machine, so it is the only one that can catch a bundle
# assembled by something other than build.sh.
#
# Counted with a for loop and NOT with `set -- "$WHEELS"/*.whl; [ "$#" -eq 1 ]`, which is
# the shorter idiom and is wrong here: set -- replaces the positional parameters, so the
# "$@" this script ends by passing to ASH would be the wheel path instead of the user's
# arguments. Measured, on an earlier revision -- `ash --version` reported
#   No such command '/app/share/ash/wheels/automated_security_helper-<version>-...whl'
# The version is elided on purpose: nothing under packaging/flatpak/ carries one, so
# nothing here is in [tool.commitizen] version_files and nothing here goes stale on a
# release. build.sh reads the version out of the wheel filename at build time.
# because the launcher had handed ASH its own payload as an argv.
#
# The -f test inside the loop is what distinguishes "no wheels" from "one wheel": an
# unmatched glob is left literal, so the loop still runs once with a name that is not a
# file.
WHEEL=
WHEEL_COUNT=0
for candidate in "$WHEELS"/*.whl; do
  [ -f "$candidate" ] || continue
  WHEEL="$candidate"
  WHEEL_COUNT=$((WHEEL_COUNT + 1))
done
if [ "$WHEEL_COUNT" -ne 1 ]; then
  die "expected exactly 1 wheel under $WHEELS, found $WHEEL_COUNT." \
      "This build is malformed. A Flatpak carrying dependency wheels would put" \
      "third-party scanner code in a published artifact; see packaging/README.md."
fi

# One python call gets the floor check and the venv tag. Below 3.10 fails here with a
# message naming the runtime rather than inside pip, which would report ASH's
# requires-python and say nothing about which runtime-version to change.
PYTAG="$(python3 -c 'import sys; sys.exit(1) if sys.version_info < (3, 10) else sys.stdout.write("py%d.%d" % sys.version_info[:2])' 2>/dev/null)"
if [ -z "$PYTAG" ]; then
  die "the runtime's python3 is missing or older than 3.10, which ASH requires." \
      "ASH declares requires-python >=3.10,<4. Raise runtime-version in" \
      "packaging/flatpak/io.github.awslabs.automated_security_helper.yml."
fi

VENV="$DATA/$(basename "$WHEEL" .whl)-$PYTAG"

# -f and not -x throughout. The exec at the bottom passes the venv's console script to
# the venv's interpreter as an argument rather than executing it, so that script's execute
# bit is not what decides whether the venv is usable, and testing for it would reject a
# venv that works.
if [ ! -f "$VENV/bin/$SELF" ]; then
  # Built under a temporary name and moved into place, so an interrupted first run
  # leaves no half-populated venv that the next run would treat as complete. The move
  # is also how two concurrent first runs settle: both build, one wins the rename, and
  # the loser discards its copy rather than merging into the winner's.
  TMP="$VENV.incomplete.$$"
  rm -rf "$TMP"

  python3 -m venv "$TMP" || die \
    "failed to create a virtualenv at $TMP." \
    "The runtime's python3 must provide the venv and ensurepip modules."

  # The wheel comes from the local path; its DEPENDENCIES come from a Python index.
  # That split is why this package is not self-contained, and it is the same split the
  # .deb and .rpm make. README.flatpak documents staging an offline index.
  #
  # --share=network is in finish-args for this line specifically. Without it the first
  # run fails here and every later run repeats the failure.
  "$TMP/bin/python3" -m pip install --quiet --disable-pip-version-check "$WHEEL" || {
    rm -rf "$TMP"
    die "failed to install $(basename "$WHEEL") into a virtualenv." \
        "This step needs a reachable Python package index to resolve ASH's runtime" \
        "dependencies. See README.flatpak for how to stage one offline."
  }

  # Assert the entry point exists rather than trusting pip's exit code: a wheel can
  # install cleanly and still produce no console script if its metadata is wrong, and
  # the exec below would then fail for every user with a bare "not found".
  if [ ! -f "$TMP/bin/$SELF" ]; then
    rm -rf "$TMP"
    die "$(basename "$WHEEL") installed but produced no '$SELF' entry point."
  fi

  mv "$TMP" "$VENV" 2>/dev/null || rm -rf "$TMP"
  [ -f "$VENV/bin/$SELF" ] || die "the virtualenv at $VENV is incomplete."
fi

# The interpreter is named explicitly and the console script is passed to it as an
# argument, rather than executing the console script and letting its shebang find the
# interpreter. Two reasons, and the first is a bug this line exists to fix:
#
#   1. A virtualenv is not relocatable. pip writes the interpreter's absolute path into
#      the shebang of every console script it installs, so after the rename above every
#      entry point in the venv still points at the temporary directory. Measured: the
#      first run of an earlier revision of this script died with
#      "...-py3.12.incomplete.2/bin/python3: No such file or directory". This is the same
#      property packaging/README.md cites for why the .deb and .rpm build their venv on
#      the target instead of shipping one -- it applies just as much to a rename on the
#      same machine. Handing the script to a working interpreter bypasses the shebang,
#      and $VENV/bin/python3 is a symlink to the runtime's python3, which is an absolute
#      path that the rename does not touch.
#
#   2. It puts the right value in sys.executable. packaging/README.md notes that a
#      symlink into the venv breaks sys.executable discovery for the container runner,
#      which shells out to itself; invoking the venv's own python3 makes sys.executable
#      that interpreter, which is what a re-exec needs.
#
# sys.argv[0] is the console script's path, so its basename still selects the program
# name typer prints in usage and errors -- "ash", "ashv3" or "automated-security-helper"
# rather than a python invocation.
exec "$VENV/bin/python3" "$VENV/bin/$SELF" "$@"
