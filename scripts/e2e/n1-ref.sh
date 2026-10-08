# shellcheck shell=bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Sourced, not run. The N-1 commit for the upgrade legs that export and build N-1
# themselves: scripts/e2e/wheel.sh, container.sh, homebrew.sh and
# editors/jetbrains/e2e-ide-cycle.sh.
#
#   n1_resolve PATH...
#
# Resolves $PREV_REF with scripts/e2e/prev_tree.py --resolve-only and sets PREV_SHA to
# the commit and PREV_REF to what was used ("HEAD^", or for `auto` a label such as
# "v4.0.0 (newest release tag)", "HEAD^ 1a2b3c4d5e6f (first parent)" or
# "ancestor 1a2b3c4d5e6f"). Every PATH is passed as --require: N-1 must carry each of
# them, or it has no package of the channel to upgrade from.
#
# The default for PREV_REF in every caller is `auto`, which names no branch. It takes
# the first of the newest release tag reachable from HEAD, HEAD's first parent (on a
# pull request's merge ref, the base), and the newest ancestor in date order, that
# differs from HEAD's tree and carries every PATH, so it keeps working once the branch
# a leg was developed on is merged and deleted. A named ref still works, with the HEAD^
# fallback when it has HEAD's tree. prev_tree.py's docstring has the whole derivation.
#
# This file is also the only place a leg runs git. The helpers below are the whole of
# what the legs need from it, and each refuses any revision but HEAD and the PREV_SHA
# n1_resolve set, at run time:
#
#   n1_head_sha                 print HEAD's commit
#   n1_export REV DIR [PATH...] unpack REV's tree (or PATHs of it) into DIR
#   n1_tarball REV PREFIX OUT   write REV's tree as a .tar.gz under PREFIX
#   n1_unchanged PATH...        true when PATHs are the same in N-1 and HEAD
#
# tests/unit/test_e2e_n1_fetch.py holds the callers to that: a leg script may not
# mention git outside a comment, nor write E2E_PREV_REF, PREV_REF or PREV_SHA itself.
#
# The caller defines REPO, fail and harness (a Python that can run a stdlib-only
# script) before calling this.

n1_resolve() {
  local args=() path line
  for path in "$@"; do args+=(--require "$path"); done
  line="$(harness "$REPO/scripts/e2e/prev_tree.py" --repo "$REPO" --prev-ref "$PREV_REF" \
    "${args[@]}" --resolve-only)" || fail "cannot derive N-1 from E2E_PREV_REF=$PREV_REF"
  # A Windows Python ends the line with CRLF; $(...) drops only the LF.
  line="${line%$'\r'}"
  PREV_SHA="${line%% *}"
  PREV_REF="${line#* }"
  # yes when N-1 is a published release: an artifact this tree's gates never built and
  # cannot change, so a leg holds only N to this tree's packaging rules.
  # shellcheck disable=SC2034 # read by the leg that sources this file
  case "$PREV_REF" in
    *" (latest published release)") N1_IS_RELEASE=yes ;;
    *) N1_IS_RELEASE=no ;;
  esac
  case "$PREV_SHA" in
    *[!0-9a-f]* | "") fail "prev_tree.py printed '$line', not '<sha> <label>'" ;;
  esac
  [ "${#PREV_SHA}" -ge 40 ] || fail "prev_tree.py printed '$line', not '<sha> <label>'"
}

# Refuses every revision but HEAD and the commit n1_resolve chose.
n1_revision() {
  case "$1" in
    HEAD) ;;
    *)
      [ -n "${PREV_SHA:-}" ] && [ "$1" = "$PREV_SHA" ] \
        || fail "n1-ref.sh: revision '$1' is neither HEAD nor the N-1 n1_resolve chose"
      ;;
  esac
}

n1_head_sha() {
  git -C "$REPO" rev-parse HEAD
}

n1_export() {
  local rev="$1" dir="$2"
  shift 2
  n1_revision "$rev"
  # tar reads the archive in DIR rather than being handed DIR: on a Windows runner a
  # native C:\... directory reaches MSYS tar as a remote host:path it cannot open, and
  # bash's own cd resolves both forms.
  git -C "$REPO" archive "$rev" "$@" | (cd "$dir" && tar -x)
}

n1_tarball() {
  local rev="$1" prefix="$2" out="$3"
  n1_revision "$rev"
  git -C "$REPO" archive --format=tar.gz --prefix="$prefix" -o "$out" "$rev"
}

n1_unchanged() {
  n1_revision "${PREV_SHA:-}"
  git -C "$REPO" diff --quiet "$PREV_SHA" HEAD -- "$@"
}

# The version N-1 is installed at. A release is installed at its own version, which
# already sorts below HEAD's; a development commit that shares HEAD's version has its
# last non-zero component decremented (4.0.0 -> 3.0.0), so the upgrade moves forward.
# Fails when even that does not sort below HEAD's version.
n1_prev_version() {
  harness - "$1" "$2" <<'PY' || fail "N-1 version $1 cannot be placed below head's $2"
import re, sys
base, head = sys.argv[1:]
for v in (base, head):
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)*", v):
        sys.exit(f"version {v!r} is not dotted integers")
def key(v):
    parts = [int(p) for p in v.split(".")]
    return parts + [0] * (8 - len(parts))
if key(base) < key(head):
    print(base)
    sys.exit(0)
parts = [int(p) for p in base.split(".")]
i = len(parts) - 1
while i >= 0 and parts[i] == 0:
    i -= 1
if i < 0:
    sys.exit(f"cannot lower {base}")
parts[i] -= 1
parts[i + 1:] = [0] * (len(parts) - i - 1)
lowered = ".".join(map(str, parts))
if not key(lowered) < key(head):
    sys.exit(f"{lowered} does not sort below {head}")
print(lowered)
PY
}
