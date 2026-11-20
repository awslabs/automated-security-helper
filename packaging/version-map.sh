# shellcheck shell=bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Maps a PEP 440 version, as it appears in a wheel filename, to a package version that
# dpkg and rpm sort in the same order PEP 440 does. Sourced by packaging/deb/build.sh
# and packaging/rpm/build.sh; tested against the real comparators by
# packaging/test-version-map.sh.
#
#   pkg_version <pep440-version> <deb|rpm>
#
# WHY A MAPPING AT ALL
#
# Written verbatim, 3.8.0rc1 sorts ABOVE 3.8.0 in both dpkg and rpm (the trailing
# "rc1" is just more version), so a release candidate would never be replaced by the
# release it precedes. Both tools sort `~` below everything, including the end of the
# string, which is the pre-release marker each documents:
#
#   PEP 440            package version      why
#   3.8.0.dev1         3.8.0~~dev1          a dev release precedes every pre-release:
#                                           `~~` sorts below `~`, so ~~dev1 < ~a1
#   3.8.0a1            3.8.0~a1             a < b < rc compares lexically, as PEP 440 orders
#   3.8.0rc1.dev2      3.8.0~rc1~dev2       a dev release of a pre-release precedes it
#   3.8.0              3.8.0
#   3.8.0.post1        3.8.0+post1 (deb)    above 3.8.0, below 3.8.1
#                      3.8.0^post1 (rpm)    `+` is not a post-release marker in rpm; `^`
#                                           is, and sorts above the bare version
#   3.8.0.post1.dev2   3.8.0+post1~dev2     below 3.8.0.post1, above 3.8.0
#
# rpm supports `~` from 4.10 and `^` from 4.15; Amazon Linux 2023 and RHEL 9 ship 4.16.
#
# A local version (`+local`) is REFUSED rather than mapped. It is not publishable, and
# the previous mapping turned `+` into `~`, which sorted a local build below the
# release it was built from.
#
# Prints the mapped version, or prints an error to stderr and returns 2.
pkg_version() {
  local version="$1" format="$2"
  local re='^([0-9]+(\.[0-9]+)*)((a|b|rc)([0-9]+))?(\.post([0-9]+))?(\.dev([0-9]+))?$'
  if [[ ! "$version" =~ $re ]]; then
    echo "error: '$version' is not a normalized PEP 440 public version this package can carry." >&2
    echo "       Local versions (+local) and non-normalized spellings are refused." >&2
    return 2
  fi
  local release="${BASH_REMATCH[1]}" pre_kind="${BASH_REMATCH[4]}" pre_num="${BASH_REMATCH[5]}"
  local post_num="${BASH_REMATCH[7]}" dev_num="${BASH_REMATCH[9]}"
  local out="$release" post_sep
  case "$format" in
    deb) post_sep="+" ;;
    rpm) post_sep="^" ;;
    *) echo "error: unknown package format '$format'" >&2; return 2 ;;
  esac
  if [ -n "$pre_kind" ]; then
    out="${out}~${pre_kind}${pre_num}"
  fi
  if [ -n "$post_num" ]; then
    out="${out}${post_sep}post${post_num}"
  fi
  if [ -n "$dev_num" ]; then
    if [ -z "$pre_kind" ] && [ -z "$post_num" ]; then
      # A dev release of a final release precedes that release's pre-releases too.
      out="${out}~~dev${dev_num}"
    else
      out="${out}~dev${dev_num}"
    fi
  fi
  printf '%s\n' "$out"
}
