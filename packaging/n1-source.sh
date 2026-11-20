# shellcheck shell=bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Sourced, not run. The N-1 source tree the deb, rpm and Flatpak upgrade legs build
# their old package from, with that tree's OWN packaging scripts.
#
#   n1_export DEST
#
# Exports N-1 into DEST with scripts/e2e/prev_tree.py and sets:
#
#   N1_SHA      the commit N-1 was taken from
#   N1_REF      what prev_tree.py used ("ancestor 1a2b3c4d5e6f", or a release tag)
#   N1_HEAD     HEAD's commit
#   N1_VERSION  the lowered version written into DEST/pyproject.toml
#
# WHY THE PREVIOUS COMMIT AND NOT THIS TREE AT A LOWER VERSION
#
# These legs used to build N-1 from HEAD's own tree with only its version lowered. That
# upgrade runs N's postinst and %post over an install N's own scripts made, so it can
# never see the defect class the legs exist for: a new maintainer script meeting the
# state an older one left behind. The rpm venv that survived an upgrade and the deb
# prerm that deleted the venv on upgrade were both that shape.
#
# HOW N-1 IS CHOSEN
#
# --prev-ref auto, the same derivation every other upgrade leg uses: the newest
# release tag reachable from HEAD, else the newest ancestor, whose tree differs from
# HEAD's and which carries every path in N1_REQUIRE. A commit with HEAD's tree is
# passed over, never built, so the upgrade always crosses a code change, and a clone
# too shallow to hold such a commit fails and says so. The checkout therefore needs the
# full history (fetch-depth 0). prev_tree.py's docstring has the whole derivation.
#
# N1_REQUIRE names what N-1 must carry to be built here at all: each format's build
# script and the scripts the legs read from the N-1 tree. A release from before the
# native packages existed is passed over rather than half-built.
#
# The caller sources packaging/verify-lib.sh first (for vl_gate_python and vl_fail)
# and sets REPO.

N1_REQUIRE=(
  pyproject.toml
  packaging/cli-name.sh
  packaging/version-map.sh
  packaging/deb/build.sh
  packaging/rpm/build.sh
  packaging/rpm/ash.spec
  packaging/flatpak/build.sh
  packaging/flatpak/ash-launcher.sh
  packaging/assert-package-contents.py
  packaging/assert-package-payload.py
  .github/scripts/assert-artifact-contents.py
)

# prev_tree.py is read from beside this file rather than from $REPO, so the test
# (packaging/test-n1-source.sh) can point REPO at a history built to break it.
N1_PREV_TREE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/e2e/prev_tree.py"

n1_export() {
  local dest="$1" args=() path json
  for path in "${N1_REQUIRE[@]}"; do args+=(--require "$path"); done
  # git refuses a repository owned by another uid, which a container's root sees in a
  # checkout the runner's user wrote. Passed through the environment so prev_tree.py's
  # own git calls see it too, without touching any git config file.
  json="$(GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0="$REPO" \
    vl_gate_python "$N1_PREV_TREE" --repo "$REPO" --prev-ref auto \
    "${args[@]}" --out "$dest")" || vl_fail "cannot derive the N-1 tree (scripts/e2e/prev_tree.py above says why)"
  # One JSON object; read with the harness interpreter, never with string slicing.
  eval "$(vl_gate_python - "$json" <<'PY'
import json, shlex, sys
d = json.loads(sys.argv[1])
for var, key in (("N1_SHA", "prev_sha"), ("N1_REF", "prev_ref"), ("N1_HEAD", "head_sha"),
                 ("N1_VERSION", "prev_version"), ("N1_SRC", "src")):
    print(f"{var}={shlex.quote(str(d[key]))}")
PY
)" || vl_fail "prev_tree.py printed something that is not its JSON result: $json"
  # prev_tree.py refuses a same-tree N-1 itself. Checked again here because everything
  # downstream reads "N-1" as "older code", and that is the one claim worth two checks.
  [ "$N1_SHA" != "$N1_HEAD" ] || vl_fail "N-1 is HEAD ($N1_HEAD)"
  [ "$(git -c safe.directory="$REPO" -C "$REPO" rev-parse "$N1_SHA^{tree}")" \
    != "$(git -c safe.directory="$REPO" -C "$REPO" rev-parse "HEAD^{tree}")" ] \
    || vl_fail "N-1 ($N1_SHA) has HEAD's tree, so the upgrade would cross no code change"
  [ "$N1_SRC" = "$(cd "$dest" && pwd -P)/src" ] || vl_fail "prev_tree.py exported to $N1_SRC, not $dest/src"
  # prev_tree.py exports through a zip, which keeps no file modes. Put back the
  # executable bit git records (100755), so N-1's build scripts, and the maintainer
  # scripts and launchers they copy into a package, are what N-1's tree has.
  local name count=0
  while IFS= read -r name; do
    chmod 0755 "$N1_SRC/$name"
    count=$((count + 1))
  done < <(git -c safe.directory="$REPO" -C "$REPO" ls-tree -r --full-tree "$N1_SHA" \
    | awk -F '\t' '$1 ~ /^100755 / { print $2 }')
  [ "$count" -gt 0 ] || vl_fail "N-1's tree records no executable file, so its modes were not read"
  vl_say "== N-1 is $N1_SHA ($N1_REF) at version $N1_VERSION; N is HEAD $N1_HEAD"
}
