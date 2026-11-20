#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Proves packaging/n1-source.sh, the N-1 the deb, rpm and Flatpak upgrade legs build
# from, can refuse a history it must not build from, and takes the right commit from
# one it can.
#
#   packaging/test-n1-source.sh
#
# Each case is a small git history built here, judged by n1_export itself (not by a
# copy of its logic):
#
#   same-tree      HEAD is an empty commit over its parent: every candidate has HEAD's
#                  tree, so there is no code change to upgrade across. Must FAIL.
#   no-channel     the only earlier commit predates the packaging: there is no older
#                  package to upgrade from. Must FAIL.
#   shallow        a one-commit clone of a good history. Must FAIL and say the clone is
#                  shallow, rather than look like a history with no N-1.
#   good           the parent differs and carries the packaging. Must PASS, with
#                  N1_SHA the parent, the version lowered, and the export at DEST/src
#                  with git's executable bits.
#
# Needs git and uv (vl_gate_python); none of the package toolchains. Runs in the
# self-tests job of ash-native-packages.yml.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=packaging/verify-lib.sh
. "$REPO/packaging/verify-lib.sh"
# shellcheck source=packaging/n1-source.sh
. "$REPO/packaging/n1-source.sh"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
failures=0

commit_all() {
  git -C "$1" add -A
  git -C "$1" -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty -m "$2"
}

# A repository at $1 with pyproject.toml at version 4.0.0 and, when $2 is "with",
# every path n1_export requires.
new_history() {
  local dir="$1" with="$2" path
  git init -q "$dir"
  printf '[project]\nname = "x"\nversion = "4.0.0"\n' >"$dir/pyproject.toml"
  if [ "$with" = with ]; then
    for path in "${N1_REQUIRE[@]}"; do
      mkdir -p "$dir/$(dirname "$path")"
      [ -e "$dir/$path" ] || printf 'stand-in for %s\n' "$path" >"$dir/$path"
      case "$path" in *.sh) chmod 0755 "$dir/$path" ;; esac
    done
  fi
  commit_all "$dir" base
}

# Runs n1_export over the history at $1 in a subshell; its stderr is captured.
run_export() {
  (REPO="$1"; n1_export "$SCRATCH/out-$(basename "$1")") >"$SCRATCH/$(basename "$1").log" 2>&1
}

expect_refusal() {
  local name="$1" dir="$2" text="$3"
  if run_export "$dir"; then
    echo "FAIL [$name]: n1_export accepted a history it must refuse" >&2
    sed 's/^/  | /' "$SCRATCH/$name.log" >&2
    failures=$((failures + 1))
  elif ! grep -qF -- "$text" "$SCRATCH/$name.log"; then
    echo "FAIL [$name]: refused, but not for the reason under test ($text)" >&2
    sed 's/^/  | /' "$SCRATCH/$name.log" >&2
    failures=$((failures + 1))
  else
    echo "OK   [$name]: refused: $(grep -F -- "$text" "$SCRATCH/$name.log" | head -1)"
  fi
}

# same-tree: HEAD changes nothing.
new_history "$SCRATCH/same-tree" with
commit_all "$SCRATCH/same-tree" "no change"
# Both commits carry the packaging, so tree equality is the only reason left to refuse.
expect_refusal same-tree "$SCRATCH/same-tree" "no release tag or ancestor of HEAD differs from it"

# no-channel: the packaging arrives in HEAD.
new_history "$SCRATCH/no-channel" without
for path in "${N1_REQUIRE[@]}"; do
  mkdir -p "$SCRATCH/no-channel/$(dirname "$path")"
  [ -e "$SCRATCH/no-channel/$path" ] || printf 'stand-in\n' >"$SCRATCH/no-channel/$path"
done
commit_all "$SCRATCH/no-channel" "add packaging"
expect_refusal no-channel "$SCRATCH/no-channel" "introduces the channel"

# good: a real code change over a parent that has the packaging.
new_history "$SCRATCH/good" with
printf 'changed\n' >"$SCRATCH/good/packaging/rpm/build.sh"
commit_all "$SCRATCH/good" change
PARENT="$(git -C "$SCRATCH/good" rev-parse HEAD^)"

# shallow: one commit of that history.
git clone -q --depth 1 "file://$SCRATCH/good" "$SCRATCH/shallow"
expect_refusal shallow "$SCRATCH/shallow" "shallow clone"

if (
  REPO="$SCRATCH/good"
  n1_export "$SCRATCH/out-good"
  [ "$N1_SHA" = "$PARENT" ] || { echo "N1_SHA is $N1_SHA, not the parent $PARENT" >&2; exit 1; }
  [ "$N1_VERSION" = 3.0.0 ] || { echo "N1_VERSION is $N1_VERSION, not 3.0.0" >&2; exit 1; }
  grep -qx 'version = "3.0.0"' "$N1_SRC/pyproject.toml" \
    || { echo "the export's pyproject.toml was not lowered" >&2; exit 1; }
  grep -qx 'stand-in for packaging/deb/build.sh' "$N1_SRC/packaging/deb/build.sh" \
    || { echo "the export is not the parent's tree" >&2; exit 1; }
  # The export goes through a zip; git's recorded modes must come back with it.
  [ -x "$N1_SRC/packaging/deb/build.sh" ] || { echo "the export lost build.sh's executable bit" >&2; exit 1; }
  [ ! -x "$N1_SRC/packaging/rpm/ash.spec" ] || { echo "the export made ash.spec executable" >&2; exit 1; }
) >"$SCRATCH/good.log" 2>&1; then
  echo "OK   [good]: N-1 is the parent $PARENT at 3.0.0, exported with its own packaging"
else
  echo "FAIL [good]: n1_export did not take the parent from a good history" >&2
  sed 's/^/  | /' "$SCRATCH/good.log" >&2
  failures=$((failures + 1))
fi

[ "$failures" -eq 0 ] || { echo "$failures case(s) failed" >&2; exit 1; }
echo "n1-source: 4 of 4 cases judged as required"
