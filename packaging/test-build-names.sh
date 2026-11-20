#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Proves the deb and rpm builds agree on which names packaging/cli-name.sh may set, and
# that the docs the packages ship name the paths those names produce.
#
#   packaging/test-build-names.sh
#
# Needs neither dpkg-deb nor rpmbuild: the name check runs before either build looks
# for its tool, and the doc substitution is a function in cli-name.sh. So this runs on
# any host, and in CI on the self-tests job.
#
# 1. For every name below, a copy of packaging/ with that name in cli-name.sh is built
#    with BOTH packaging/deb/build.sh and packaging/rpm/build.sh, and the payload
#    checker is imported from the same copy. A bad name must be refused by all three,
#    by the name check (its message is matched, so a later failure for an unrelated
#    reason does not count); a good name must get past the check in all three.
# 2. Each shipped README is substituted with a renamed package and command, and must
#    then name only the renamed paths. A literal /usr/lib/automated-security-helper in a
#    README describes a directory a renamed package does not have.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
NAME_MESSAGE="is not a valid package or command name"
failures=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

# A copy of packaging/ whose cli-name.sh sets $1 to $2, at $SCRATCH/<n>/packaging.
tree_with() {
  local variable="$1" value="$2" tree
  tree="$(mktemp -d "$SCRATCH/tree.XXXXXX")"
  cp -R "$HERE" "$tree/packaging"
  grep -v "^${variable}=" "$HERE/cli-name.sh" > "$tree/packaging/cli-name.sh"
  # %q so a value like $(id) is written as a literal and never executed on sourcing.
  printf '%s=%q\n' "$variable" "$value" >> "$tree/packaging/cli-name.sh"
  printf '%s\n' "$tree"
}

# The wheel need not be real: the name check runs before anything opens it.
WHEEL="$SCRATCH/automated_security_helper-3.7.0-py3-none-any.whl"
: > "$WHEEL"

echo "== 1. both builds and the payload checker accept and refuse the same names"
check_name() {
  local variable="$1" value="$2" expect="$3" tree consumer out rc
  tree="$(tree_with "$variable" "$value")"
  for consumer in deb rpm payload; do
    rc=0
    if [ "$consumer" = payload ]; then
      out="$(python3 "$tree/packaging/assert-package-payload.py" --self-test 2>&1)" || rc=$?
    else
      out="$(bash "$tree/packaging/$consumer/build.sh" "$WHEEL" "$tree/out" 2>&1)" || rc=$?
    fi
    case "$expect" in
      refuse)
        if [ "$rc" -eq 0 ] || ! grep -qF "$NAME_MESSAGE" <<<"$out"; then
          fail "$consumer did not refuse $variable=[$value] by the name check (rc=$rc): $(head -c 300 <<<"$out")"
        fi
        ;;
      accept)
        # The builds go on to fail on the empty wheel, so for them only the name
        # check's silence is required; the payload checker's self-test must pass.
        if grep -qF "$NAME_MESSAGE" <<<"$out"; then
          fail "$consumer refused the valid $variable=[$value]"
        elif [ "$consumer" = payload ] && [ "$rc" -ne 0 ]; then
          fail "the payload self-test failed with $variable=[$value] (rc=$rc)"
        fi
        ;;
    esac
  done
  echo "   ok: deb, rpm and the payload checker ${expect} $variable=[$value]"
}

for variable in ASH_PKG_NAME ASH_CLI_NAME; do
  # Each bad name is one a builder would otherwise act on: a path separator or a
  # traversal reaches rm -rf in the maintainer scripts, a glob or a space splits it,
  # and uppercase or `_` is legal to rpm and refused by dpkg, which is the
  # disagreement this test exists for. A name with a newline is valid on its first
  # line alone, so a line-by-line match (grep -x) accepts it where Python's
  # fullmatch refuses it.
  for bad in '../etc' 'a/b' 'a*' 'a b' '$(id)' 'Ash' 'a_b' '-ash' 'a' $'ash\n../etc' $'ash\n'; do
    check_name "$variable" "$bad" refuse
  done
  # ashx and automated-security-helper are the names cli-name.sh sets; ash is the v3
  # name, still a valid name for the check even though the packages no longer use it.
  for good in ash ashx automated-security-helper ash-tool ash2.0+x; do
    check_name "$variable" "$good" accept
  done
done

echo "== 2. the shipped READMEs name the paths the configured names produce"
# shellcheck source=packaging/cli-name.sh
. "$HERE/cli-name.sh"
ASH_PKG_NAME=renamedpkg
ASH_CLI_NAME=renamedcli
for readme in deb/debian/README.Debian rpm/README.rpm; do
  out="$SCRATCH/$(basename "$readme")"
  ash_substitute_names "$HERE/$readme" "$out" || { fail "could not substitute $readme"; continue; }
  # A path component spelled as a configured name, or as the v3 name `ash`, is a
  # default left in the text. /usr/bin/ash followed by punctuation is prose about the
  # Almquist shell's path, which no rename changes.
  stale="$(grep -nE '/(lib|bin|doc|licenses)/(ash|ashx|automated-security-helper)([/ ]|$)' "$out" || true)"
  [ -z "$stale" ] || fail "$readme still names the default paths after a rename:"$'\n'"$stale"
  grep -q "/usr/lib/renamedpkg/wheels/" "$out" || fail "$readme does not name /usr/lib/renamedpkg/wheels/"
  grep -q "/usr/bin/renamedcli" "$out" || fail "$readme does not name /usr/bin/renamedcli"
  # A heading's underline must be as long as the heading, which the substituted name
  # changes.
  short="$(awk 'prev != "" && /^(=+|-+)$/ && length($0) >= 3 && length($0) != length(prev) {
    printf "line %d: %d-character underline under a %d-character heading\n", NR, length($0), length(prev)
  } { prev = $0 }' "$out")"
  [ -z "$short" ] || fail "$readme has underlines that do not fit their headings after a rename:"$'\n'"$short"
  echo "   checked $readme"
done

if [ "$failures" -ne 0 ]; then
  echo "test-build-names FAILED ($failures)" >&2
  exit 1
fi
echo "test-build-names OK"
