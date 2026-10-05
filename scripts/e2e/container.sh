#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# The container channel end to end. The image is built locally and never leaves the
# host: nothing here logs in to a registry or pushes, and
# .github/scripts/assert-no-image-publish.py fails CI if anything starts to.
#
#   scripts/e2e/container.sh <work-dir>
#
#   E2E_PYTHON     interpreter for the host venv that drives `ashx scan --mode container`
#                  (default 3.12)
#   E2E_PREV_REF   the git ref the N-1 image is built from (default origin/v4-capabilities).
#                  When it has HEAD's tree, HEAD's first parent is used instead, as in
#                  scripts/e2e/wheel.sh.
#   E2E_IMAGE_TAG  the image repository:tag prefix to build under (default
#                  ash-e2e-container:local). CI makes it unique per run. Two tags are
#                  derived from it, <prefix>-fresh and <prefix>-upgrade, and both are
#                  removed at the end.
#
# 1. Exports head and N-1 with `git archive` and lowers N-1's [project] version the way
#    wheel.sh does, so the upgrade crosses a version change and a code change. Builds
#    both wheels. Container mode is driven by a host `ashx`, so an install of this
#    channel is a host CLI plus the image it builds; the head wheel goes into a fresh
#    host venv for step 2.
# 2. Fresh install: requires the fresh tag to be absent, runs `ashx build-image --no-run
#    --ash-revision LOCAL` from the head export, and proves the image carries head's code
#    byte for byte (scripts/e2e/image_provenance.py) and reports head's version. Then the
#    three cases from tests/e2e/fixtures/cases.json through scripts/e2e/run_case.py with
#    `--mode container --no-build`: findings (exit 2, 3 findings), clean (exit 0) and
#    incomplete (exit 1, opengrep MISSING).
# 3. Upgrade: installs the N-1 wheel into a second venv and has that CLI build N-1
#    under the upgrade tag. Proves the image is N-1 (its code is not head's, which is
#    also the provenance check's negative control) and scans findings with N-1's CLI.
#    Then upgrades the venv to the head wheel, has the upgraded CLI rebuild over the same
#    tag, requires the tag to point at a new image with head's code and version, and
#    scans findings again. N-1's CLI drives N-1's image because the host CLI names the
#    in-image command, and N-1 may predate the `ashx` name.
# 4. Negative controls, each seen failing: findings with --no-fail-on-findings fails on
#    its exit code; the clean output judged as a findings outcome fails; the
#    image-absence check fails while the images exist.
# 5. Uninstall: `docker rmi` both tags and the N-1 image the upgrade left behind, then
#    requires `docker image inspect` to fail for each.
#
# WHY THE INCOMPLETE CASE GETS --offline HERE
#
# The case sets ASH_OFFLINE=YES and an empty OPENGREP_RULES_CACHE_DIR in the environment
# of `ashx`. In container mode that `ashx` is the host process, and
# run_ash_container.py forwards a fixed set of variables into `docker run`; neither of
# these is one of them. Measured on this image: without --offline the in-container
# opengrep runs online, ends PASSED, and the scan exits 2. `--offline` is the CLI's own
# way to say it: it passes `-e ASH_OFFLINE=YES` and `--network=none`. Inside, opengrep's
# offline rules come from the image's OPENGREP_RULES_CACHE_DIR (/deps/.opengrep), which
# only an image built with --offline populates. This image is built online, so the cache
# is empty and opengrep fails closed as MISSING, the same mechanism the case relies on
# elsewhere (tests/e2e/README.md). The expectations are the case's, unchanged.
set -euo pipefail

WORK="${1:?usage: container.sh <work-dir>}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${E2E_PYTHON:-3.12}"
PREV_REF="${E2E_PREV_REF:-origin/v4-capabilities}"
TAG_PREFIX="${E2E_IMAGE_TAG:-ash-e2e-container:local}"
TAG_FRESH="${TAG_PREFIX}-fresh"
TAG_UPGRADE="${TAG_PREFIX}-upgrade"
OCI=docker

# shellcheck source=packaging/cli-name.sh
. "$REPO/packaging/cli-name.sh"

# A layer cache exported to the Actions cache would publish the image's layers from a
# public repository. run_ash_container.py only exports one when ACTIONS_RUNTIME_TOKEN is
# in the environment, which a `run:` step does not get, but that is an accident of the
# runner; this makes it a decision.
export ASH_DISABLE_GHA_BUILD_CACHE=1

say() { printf '== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
harness() { uv run --no-project --python "$PYTHON" python "$@"; }

mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"

image_id() { "$OCI" image inspect --format '{{.Id}}' "$1"; }
image_size() { "$OCI" image inspect --format '{{.Size}}' "$1" | awk '{ printf "%.2f GB", $1 / 1e9 }'; }

# Two full images share a hosted runner's disk at the peak, so each build records what
# it left free. A run that dies of ENOSPC then says so in its own log.
disk_report() {
  local root
  root="$("$OCI" info --format '{{.DockerRootDir}}')"
  say "disk after $1: $(df -h --output=avail "$root" | tail -n 1 | tr -d ' ') free under $root; image $(image_size "$2")"
}

# Exits 0 only when none of the named images exists.
assert_images_absent() {
  local ref found=()
  for ref in "$@"; do
    if "$OCI" image inspect "$ref" >/dev/null 2>&1; then
      found+=("$ref")
    fi
  done
  if [ "${#found[@]}" -ne 0 ]; then
    printf 'images still present: %s\n' "${found[*]}" >&2
    return 1
  fi
  return 0
}

# In-image commands run with no network: they read the image, nothing else.
in_image() {
  local ref="$1"
  shift
  "$OCI" run --rm -i --network none "$ref" "$@"
}

# provenance <image> <source tree> <label>: exit 0 when the image carries that tree's code.
provenance() {
  local ref="$1" tree="$2" label="$3" json="$WORK/provenance-$3.json"
  in_image "$ref" python3 -I - manifest --package automated_security_helper \
    <"$REPO/scripts/e2e/image_provenance.py" >"$json"
  harness "$REPO/scripts/e2e/image_provenance.py" compare \
    --source "$tree/automated_security_helper" --installed "$json" --label "$label"
}

image_version() {
  in_image "$1" sh -c "command -v $ASH_CLI_NAME >/dev/null && exec $ASH_CLI_NAME --version || exec ash --version"
}

# build <cli> <export dir> <tag> [build-image args]: the user-facing build, from the
# export so its Dockerfile and its source are the build context. --ash-revision LOCAL
# keeps it from cloning a published revision instead; provenance() is what proves it
# did not.
build() {
  local cli="$1" tree="$2" tag="$3"
  shift 3
  (cd "$tree" && ASH_IMAGE_NAME="$tag" "$cli" build-image --no-run --ash-revision LOCAL "$@")
}

# run_case <cli> <image> <case> <label> [scan args]
run_case() {
  local cli="$1" image="$2" case_name="$3" label="$4"
  shift 4
  ASH_IMAGE_NAME="$image" harness "$REPO/scripts/e2e/run_case.py" --cli "$cli" \
    --case "$case_name" --work "$WORK/scans" --label "$label" -- \
    --mode container --no-build "$@"
}

say "self-tests: assert_outcome, image_provenance, assert-no-image-publish"
harness "$REPO/scripts/e2e/assert_outcome.py" --self-test
harness "$REPO/scripts/e2e/image_provenance.py" --self-test
harness "$REPO/.github/scripts/assert-no-image-publish.py" --self-test
harness "$REPO/.github/scripts/assert-no-image-publish.py"
"$OCI" version --format 'docker client {{.Client.Version}}, server {{.Server.Version}}'

# --------------------------------------------------------------------------
# 1. Export N and N-1, build the host CLI.
# --------------------------------------------------------------------------
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$REPO/pyproject.toml" | head -n 1)"
[ -n "$VERSION" ] || fail "no [project] version in pyproject.toml"
HEAD_SHA="$(git -C "$REPO" rev-parse HEAD)"
PREV_SHA="$(git -C "$REPO" rev-parse --verify --quiet "$PREV_REF^{commit}")" \
  || fail "E2E_PREV_REF $PREV_REF does not name a commit"
tree_of() { git -C "$REPO" rev-parse "$1^{tree}"; }
if [ "$(tree_of "$PREV_SHA")" = "$(tree_of HEAD)" ]; then
  say "$PREV_REF has HEAD's tree; using HEAD's first parent as N-1"
  PREV_REF="HEAD^"
  PREV_SHA="$(git -C "$REPO" rev-parse --verify --quiet "HEAD^1^{commit}")" \
    || fail "HEAD has no parent in this clone; fetch at least one more commit of history"
  [ "$(tree_of "$PREV_SHA")" != "$(tree_of HEAD)" ] \
    || fail "HEAD's first parent has HEAD's tree too; there is no code change to upgrade across"
fi
# The upgrade is only an upgrade of the image if the package code differs.
if git -C "$REPO" diff --quiet "$PREV_SHA" HEAD -- automated_security_helper; then
  fail "N-1 ($PREV_SHA) and HEAD have the same automated_security_helper/; the provenance checks could not tell the images apart"
fi

SRC_HEAD="$WORK/src-head"
SRC_PREV="$WORK/src-prev"
rm -rf "$SRC_HEAD" "$SRC_PREV" "$WORK/dist-head" "$WORK/dist-prev" "$WORK/venv-host" "$WORK/venv-upgrade"
mkdir -p "$SRC_HEAD" "$SRC_PREV"
git -C "$REPO" archive HEAD | tar -x -C "$SRC_HEAD"
git -C "$REPO" archive "$PREV_SHA" | tar -x -C "$SRC_PREV"

PREV_BASE_VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$SRC_PREV/pyproject.toml" | head -n 1)"
[ -n "$PREV_BASE_VERSION" ] || fail "no [project] version in $PREV_REF's pyproject.toml"
# The same derivation as wheel.sh and packaging/verify-lib.sh vl_lower_version.
PREV_VERSION="$(printf '%s\n' "$PREV_BASE_VERSION" | awk -F. '{
  n = NF; while (n > 0 && $n == 0) n--;
  if (n == 0) { exit 1 }
  $n = $n - 1; for (i = n + 1; i <= NF; i++) $i = 0;
  out = $1; for (i = 2; i <= NF; i++) out = out "." $i; print out }')" \
  || fail "cannot derive a lower version from $PREV_BASE_VERSION"
harness - "$SRC_PREV/pyproject.toml" "$PREV_BASE_VERSION" "$PREV_VERSION" <<'PY'
import sys
path, old, new = sys.argv[1:]
text = open(path, encoding="utf-8").read()
needle = f'\nversion = "{old}"\n'
if needle not in text:
    sys.exit(f"no [project] version line {old!r} in {path}")
open(path, "w", encoding="utf-8", newline="").write(text.replace(needle, f'\nversion = "{new}"\n', 1))
PY
[ "$PREV_VERSION" != "$VERSION" ] || fail "N-1 version equals head's ($VERSION)"
say "N = $VERSION at $HEAD_SHA; N-1 = $PREV_VERSION from $PREV_REF ($PREV_SHA)"

# A base image that moved between N-1 and head is pulled by N-1's own digest, so the N-1
# build is pinned too. When they agree, as usual, the build takes the base image the
# workflow pre-pulled and verified (.github/actions/prepull-base-image).
dockerfile_arg() { sed -n "s/^ARG $2=\\(.*\\)\$/\\1/p" "$1/Dockerfile" | head -n 1; }
HEAD_BASE="$(dockerfile_arg "$SRC_HEAD" BASE_IMAGE)@$(dockerfile_arg "$SRC_HEAD" BASE_IMAGE_DIGEST)"
PREV_BASE_REPO="$(dockerfile_arg "$SRC_PREV" BASE_IMAGE)"
PREV_BASE_DIGEST="$(dockerfile_arg "$SRC_PREV" BASE_IMAGE_DIGEST)"
PREV_BUILD_ARGS=()
if [ "${PREV_BASE_REPO}@${PREV_BASE_DIGEST}" != "$HEAD_BASE" ]; then
  [ -n "$PREV_BASE_REPO" ] && [ -n "$PREV_BASE_DIGEST" ] \
    || fail "N-1's Dockerfile has no BASE_IMAGE / BASE_IMAGE_DIGEST pair"
  PREV_BUILD_ARGS=(--custom-build-arg "BASE_IMAGE=${PREV_BASE_REPO%:*}@${PREV_BASE_DIGEST}")
  say "N-1's base image differs from head's; pinning it to ${PREV_BUILD_ARGS[1]}"
fi

uv build --quiet --wheel --out-dir "$WORK/dist-head" "$SRC_HEAD"
uv build --quiet --wheel --out-dir "$WORK/dist-prev" "$SRC_PREV"
HEAD_WHEEL="$WORK/dist-head/automated_security_helper-${VERSION}-py3-none-any.whl"
PREV_WHEEL="$WORK/dist-prev/automated_security_helper-${PREV_VERSION}-py3-none-any.whl"
[ -f "$HEAD_WHEEL" ] || fail "uv build did not write $HEAD_WHEEL"
[ -f "$PREV_WHEEL" ] || fail "uv build did not write $PREV_WHEEL"
uv venv --quiet --python "$PYTHON" "$WORK/venv-host"
uv pip install --quiet --no-cache --python "$WORK/venv-host/bin/python" "$HEAD_WHEEL"
CLI="$WORK/venv-host/bin/$ASH_CLI_NAME"
[ -x "$CLI" ] || fail "the head wheel installed no $ASH_CLI_NAME console script"
say "host CLI: $("$CLI" --version)"

# --------------------------------------------------------------------------
# 2. Fresh install of N and the three cases.
# --------------------------------------------------------------------------
# A rerun of this script on one host may find its own tags from last time. Only these two
# tags are touched; CI's are unique per run, so there the removal is a no-op.
for ref in "$TAG_FRESH" "$TAG_UPGRADE"; do
  if "$OCI" image inspect "$ref" >/dev/null 2>&1; then
    say "removing $ref left by an earlier run on this host"
    "$OCI" image rm "$ref" >/dev/null
  fi
done
assert_images_absent "$TAG_FRESH" "$TAG_UPGRADE" || fail "could not start from a host without the e2e images"

say "build N as $TAG_FRESH"
build "$CLI" "$SRC_HEAD" "$TAG_FRESH"
FRESH_ID="$(image_id "$TAG_FRESH")"
disk_report "the N build" "$TAG_FRESH"
say "built $TAG_FRESH = $FRESH_ID, target $(in_image "$TAG_FRESH" printenv ASH_TARGET)"
provenance "$TAG_FRESH" "$SRC_HEAD" fresh || fail "$TAG_FRESH does not carry head's code"
version_line="$(image_version "$TAG_FRESH")"
case "$version_line" in
  *"v$VERSION"*) say "in-image $ASH_CLI_NAME --version: $version_line" ;;
  *) fail "in-image $ASH_CLI_NAME --version printed '$version_line', expected v$VERSION" ;;
esac

run_case "$CLI" "$TAG_FRESH" findings fresh-findings
run_case "$CLI" "$TAG_FRESH" clean fresh-clean
run_case "$CLI" "$TAG_FRESH" incomplete fresh-incomplete --offline

# --------------------------------------------------------------------------
# 3. N-1 under the upgrade tag, then N rebuilt over it.
# --------------------------------------------------------------------------
UPGRADE_VENV="$WORK/venv-upgrade"
uv venv --quiet --python "$PYTHON" "$UPGRADE_VENV"
uv pip install --quiet --no-cache --python "$UPGRADE_VENV/bin/python" "$PREV_WHEEL"
if [ -x "$UPGRADE_VENV/bin/$ASH_CLI_NAME" ]; then
  PREV_CLI="$UPGRADE_VENV/bin/$ASH_CLI_NAME"
elif [ -x "$UPGRADE_VENV/bin/ash" ]; then
  PREV_CLI="$UPGRADE_VENV/bin/ash"
else
  fail "the N-1 wheel installed neither $ASH_CLI_NAME nor ash"
fi
say "N-1 host CLI: $(basename "$PREV_CLI"), $("$PREV_CLI" --version)"

say "build N-1 as $TAG_UPGRADE"
build "$PREV_CLI" "$SRC_PREV" "$TAG_UPGRADE" ${PREV_BUILD_ARGS[@]+"${PREV_BUILD_ARGS[@]}"}
PREV_ID="$(image_id "$TAG_UPGRADE")"
disk_report "the N-1 build" "$TAG_UPGRADE"
provenance "$TAG_UPGRADE" "$SRC_PREV" n-1 || fail "$TAG_UPGRADE does not carry N-1's code"
version_line="$(image_version "$TAG_UPGRADE")"
case "$version_line" in
  *"v$PREV_VERSION"*) say "N-1 in-image --version: $version_line" ;;
  *) fail "N-1 in-image --version printed '$version_line', expected v$PREV_VERSION" ;;
esac

say "negative control: the provenance check must reject N-1's image as head's"
rc=0
provenance "$TAG_UPGRADE" "$SRC_HEAD" n-1-as-head >"$WORK/negative-provenance.log" 2>&1 || rc=$?
tail -n 3 "$WORK/negative-provenance.log"
[ "$rc" -eq 1 ] || fail "NEGATIVE CONTROL: provenance returned $rc for N-1's image judged against head; expected 1"
say "   OK: rejected (exit $rc)"

run_case "$PREV_CLI" "$TAG_UPGRADE" findings upgrade-before

say "upgrade the host CLI to N, then rebuild N over $TAG_UPGRADE"
uv pip install --quiet --no-cache --python "$UPGRADE_VENV/bin/python" "$HEAD_WHEEL"
UPGRADED_CLI="$UPGRADE_VENV/bin/$ASH_CLI_NAME"
[ -x "$UPGRADED_CLI" ] || fail "the upgrade left no $ASH_CLI_NAME console script"
case "$("$UPGRADED_CLI" --version)" in
  *"v$VERSION"*) ;;
  *) fail "the upgraded host CLI does not report v$VERSION" ;;
esac
build "$UPGRADED_CLI" "$SRC_HEAD" "$TAG_UPGRADE"
UPGRADED_ID="$(image_id "$TAG_UPGRADE")"
disk_report "the N rebuild" "$TAG_UPGRADE"
[ "$UPGRADED_ID" != "$PREV_ID" ] || fail "the rebuild left $TAG_UPGRADE on the N-1 image $PREV_ID"
provenance "$TAG_UPGRADE" "$SRC_HEAD" upgraded || fail "after the upgrade $TAG_UPGRADE does not carry head's code"
version_line="$(image_version "$TAG_UPGRADE")"
case "$version_line" in
  *"v$VERSION"*) say "upgraded in-image --version: $version_line" ;;
  *) fail "after the upgrade in-image --version printed '$version_line', expected v$VERSION" ;;
esac
run_case "$UPGRADED_CLI" "$TAG_UPGRADE" findings upgrade-after
say "upgraded $TAG_UPGRADE: $PREV_ID ($PREV_VERSION) -> $UPGRADED_ID ($VERSION)"

# --------------------------------------------------------------------------
# 4. Negative controls.
# --------------------------------------------------------------------------
say "negative control: findings scanned with --no-fail-on-findings must fail the exit-code check"
rc=0
neg_log="$WORK/negative-no-fail-on-findings.log"
run_case "$CLI" "$TAG_FRESH" findings negative-no-fail-on-findings --no-fail-on-findings >"$neg_log" 2>&1 || rc=$?
cat "$neg_log"
[ "$rc" -eq 1 ] || fail "NEGATIVE CONTROL: run_case returned $rc for a findings scan that exited 0; expected 1"
grep -q "exit code 0 (nothing actionable), expected exactly 2" "$neg_log" \
  || fail "NEGATIVE CONTROL: run_case rejected the --no-fail-on-findings scan, but not for its exit code 0"
say "   OK: rejected for exit code 0 (exit $rc)"

say "negative control: the clean output judged as a findings outcome must fail"
rc=0
harness "$REPO/scripts/e2e/assert_outcome.py" --output-dir "$WORK/scans/fresh-clean/out" --rc 0 \
  --expect-rc 2 --min-findings 1 --require-scanner detect-secrets --selected detect-secrets || rc=$?
[ "$rc" -eq 1 ] || fail "NEGATIVE CONTROL: assert_outcome returned $rc on a clean output expected to hold findings"
say "   OK: rejected (exit $rc)"

say "negative control: the image-absence check must fail while the images exist"
rc=0
assert_images_absent "$TAG_FRESH" "$TAG_UPGRADE" "$PREV_ID" || rc=$?
[ "$rc" -ne 0 ] || fail "NEGATIVE CONTROL: the absence check passed while the e2e images exist"
say "   OK: rejected (exit $rc)"

# --------------------------------------------------------------------------
# 5. Uninstall.
# --------------------------------------------------------------------------
"$OCI" image rm "$TAG_FRESH" "$TAG_UPGRADE" >/dev/null
# The upgrade untagged N-1's image rather than deleting it; removing it is part of
# uninstalling. Only when no other tag holds it, which on CI is always.
if "$OCI" image inspect "$PREV_ID" >/dev/null 2>&1; then
  "$OCI" image rm "$PREV_ID" >/dev/null
fi
assert_images_absent "$TAG_FRESH" "$TAG_UPGRADE" "$PREV_ID" || fail "docker image rm left e2e images behind"
say "uninstalled: $TAG_FRESH, $TAG_UPGRADE and the N-1 image are gone"

say "container e2e passed: N=$VERSION ($HEAD_SHA, $FRESH_ID), N-1=$PREV_VERSION ($PREV_REF $PREV_SHA), python $PYTHON"
