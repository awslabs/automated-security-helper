#!/usr/bin/env bash
#
# Runs a command as the unprivileged user that owns the repository checkout. When the
# caller is already unprivileged, the command runs unchanged.
#
# WHY THIS EXISTS
#
# The plugin's test suite includes tests for unreadable reports and undeletable stale
# files. They work by chmod'ing a file to 000 or a directory to read-only and checking that
# the runner refuses to treat it as a current result. Root ignores both: a mode-000 file
# opens, and a read-only directory accepts deletes. Under root those tests do not exercise
# the path they name. They fail with a message about a different code path, and that is
# what happened in CI, where gradle:jdk21 runs every step as root. Each of those tests now
# checks first that permissions are enforced and fails, naming root, when they are not.
# This script is the other half: the build, not the test, is what has to change.
#
# WHOSE uid. The checkout's owner, read from the repository root. Two callers:
#
#   - A developer running `docker run -v "$PWD":/work gradle:jdk21 ...` gets a checkout
#     owned by their host uid. Running as that uid means the build can write build/ and
#     .gradle/ in the mount, and leaves nothing root-owned behind on the host.
#   - CI checks out as root, so the workflow hands the checkout to the image's `gradle` user
#     (uid 1000) first. The owner is then that user.
#
# A checkout owned by root is refused rather than silently built as root. Picking some other
# uid would leave the build unable to write into the tree, and the error would be a Gradle
# I/O failure several minutes in rather than this message.
#
# Dropped with setpriv (util-linux, present in gradle:jdk21) rather than su or runuser:
# a uid from a host bind mount usually has no passwd entry in the image, and su and runuser
# take only user names.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 2
fi

if [ "$(id -u)" != 0 ]; then
  exec "$@"
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OWNER_UID="$(stat -c %u "$REPO_ROOT")"
OWNER_GID="$(stat -c %g "$REPO_ROOT")"
if [ "$OWNER_UID" = 0 ]; then
  echo "FAIL: running as root, and the checkout at $REPO_ROOT is owned by root." >&2
  echo "The JetBrains build must not run as root: root bypasses file permissions, so the" >&2
  echo "tests for unreadable and undeletable reports cannot exercise what they test." >&2
  echo "Give the checkout to an unprivileged user (CI uses: chown -R gradle:gradle <checkout>)," >&2
  echo "or start the container with --user <uid>:<gid>." >&2
  exit 1
fi

# HOME from the passwd entry when the uid has one (the image's gradle user does); otherwise a
# private directory, because a bind-mounted host uid has no entry and HOME=/root would be
# unwritable to it. Gradle's user home follows HOME unless the caller set GRADLE_USER_HOME,
# which is passed through so a warm cache can be mounted in.
OWNER_ENTRY="$(getent passwd "$OWNER_UID" || true)"
OWNER_NAME="$(printf '%s' "$OWNER_ENTRY" | cut -d: -f1)"
OWNER_HOME="$(printf '%s' "$OWNER_ENTRY" | cut -d: -f6)"
if [ -z "$OWNER_HOME" ] || [ ! -d "$OWNER_HOME" ]; then
  OWNER_HOME="/tmp/ash-jetbrains-home-$OWNER_UID"
  mkdir -p "$OWNER_HOME"
  chown "$OWNER_UID:$OWNER_GID" "$OWNER_HOME"
  chmod 700 "$OWNER_HOME"
fi

echo "== running as uid $OWNER_UID:$OWNER_GID (the checkout's owner) instead of root, HOME=$OWNER_HOME"
exec setpriv --reuid="$OWNER_UID" --regid="$OWNER_GID" --clear-groups \
  env HOME="$OWNER_HOME" USER="${OWNER_NAME:-uid$OWNER_UID}" LOGNAME="${OWNER_NAME:-uid$OWNER_UID}" "$@"
