#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Proves packaging/version-map.sh orders package versions the way PEP 440 does, using
# the distribution's own comparator rather than a reimplementation of it.
#
#   packaging/test-version-map.sh <deb|rpm> <wheel>
#
# Run inside a Debian/Ubuntu container for deb (dpkg --compare-versions) or an
# Amazon Linux/RHEL container for rpm (rpm's own vercmp, through its Lua interpreter).
#
# Three parts, each of which has to pass:
#   1. A CONTROL on the comparator: the verbatim pre-release string must sort ABOVE the
#      final release. That is the defect being fixed; if the comparator does not show
#      it, nothing below is evidence of anything.
#   2. A ladder of PEP 440 versions in ascending PEP 440 order. Every adjacent pair of
#      mapped versions must compare strictly ascending.
#   3. A REAL PACKAGE: the given wheel is copied under a release-candidate filename,
#      packaged by the real build.sh, and the Version the package actually carries must
#      sort below the final release's.
set -euo pipefail

FORMAT="${1:?usage: test-version-map.sh <deb|rpm> <wheel>}"
WHEEL="${2:?usage: test-version-map.sh <deb|rpm> <wheel>}"
REPO="${REPO:-$(cd "$(dirname "$0")/.." && pwd)}"

# shellcheck source=packaging/version-map.sh
. "$REPO/packaging/version-map.sh"

# Exit 0 when $1 sorts strictly below $2 under the real tool.
lower_than() {
  case "$FORMAT" in
    deb) dpkg --compare-versions "$1" lt "$2" ;;
    rpm)
      local result
      result="$(rpm --eval "%{lua: print(rpm.vercmp('$1', '$2'))}")"
      [ "$result" = "-1" ]
      ;;
    *) echo "unknown format $FORMAT" >&2; exit 2 ;;
  esac
}

if [ "$FORMAT" = deb ]; then
  echo "== comparator: dpkg $(dpkg-query -W -f='${Version}' dpkg)"
else
  echo "== comparator: $(rpm --version)"
fi

echo "== 1. control: the verbatim pre-release must sort ABOVE the release"
if lower_than 3.8.0rc1 3.8.0; then
  echo "FAIL: the comparator puts 3.8.0rc1 below 3.8.0, so it cannot show the defect" >&2
  exit 1
fi
echo "   OK: 3.8.0rc1 sorts above 3.8.0 when written verbatim"

echo "== 2. the mapped ladder sorts in PEP 440 order"
LADDER=(
  3.7.9
  3.8.0.dev1
  3.8.0a1
  3.8.0a2
  3.8.0b1
  3.8.0rc1.dev2
  3.8.0rc1
  3.8.0rc2
  3.8.0
  3.8.0.post1.dev2
  3.8.0.post1
  3.8.0.post2
  3.8.1
)
failures=0
prev_pep="" prev_pkg=""
for pep in "${LADDER[@]}"; do
  pkg="$(pkg_version "$pep" "$FORMAT")"
  if [ -n "$prev_pkg" ]; then
    if lower_than "$prev_pkg" "$pkg"; then
      echo "   OK: $prev_pep ($prev_pkg) < $pep ($pkg)"
    else
      echo "FAIL: $prev_pep maps to $prev_pkg, which does NOT sort below $pep ($pkg)" >&2
      failures=$((failures + 1))
    fi
  fi
  prev_pep="$pep" prev_pkg="$pkg"
done
[ "$failures" -eq 0 ] || exit 1

echo "== 3. a real package built from a release-candidate wheel sorts below the release"
base="$(basename "$WHEEL" | sed -n 's/^automated_security_helper-\([0-9.]*\)-py3-none-any\.whl$/\1/p')"
[ -n "$base" ] || { echo "FAIL: $WHEEL is not a final-release wheel" >&2; exit 2; }
work="$(mktemp -d)"
rc_wheel="$work/automated_security_helper-${base}rc1-py3-none-any.whl"
cp "$WHEEL" "$rc_wheel"
case "$FORMAT" in
  deb)
    built="$("$REPO/packaging/deb/build.sh" "$rc_wheel" "$work/out")"
    carried="$(dpkg-deb --field "$built" Version)"
    ;;
  rpm)
    built="$("$REPO/packaging/rpm/build.sh" "$rc_wheel" "$work/out")"
    carried="$(rpm -qp --qf '%{VERSION}' "$built")"
    ;;
esac
echo "   ${base}rc1 wheel -> package Version: $carried"
if ! lower_than "$carried" "$(pkg_version "$base" "$FORMAT")"; then
  echo "FAIL: the package built from ${base}rc1 carries $carried, which does not sort below $base" >&2
  exit 1
fi
echo "   OK: $carried sorts below $base"
rm -rf "$work"

echo
echo "VERSION MAP VERIFICATION PASSED ($FORMAT)"
