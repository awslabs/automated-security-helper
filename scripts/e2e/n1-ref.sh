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
# The callers are held to using only this: tests/unit/test_e2e_n1_fetch.py refuses a
# leg script that writes E2E_PREV_REF, PREV_REF or PREV_SHA itself, or hands git any
# revision but HEAD and the PREV_SHA set here.
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
  case "$PREV_SHA" in
    *[!0-9a-f]* | "") fail "prev_tree.py printed '$line', not '<sha> <label>'" ;;
  esac
  [ "${#PREV_SHA}" -ge 40 ] || fail "prev_tree.py printed '$line', not '<sha> <label>'"
}
