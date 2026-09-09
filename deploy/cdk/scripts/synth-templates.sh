#!/usr/bin/env bash
#
# Emit the committed CloudFormation templates, or verify they have not drifted.
#
#   ./scripts/synth-templates.sh           # write templates/
#   ./scripts/synth-templates.sh --check   # fail if templates/ is stale
#
# WHY THE TEMPLATES ARE COMMITTED AT ALL
# --------------------------------------
# They are the deliverable. An adopter gets a one-click CloudFormation launch
# from a URL pointing at a template in this repository; they do not run `cdk`.
# That only works if what is committed is exactly what this app synthesizes,
# which is what --check is for.
#
# WHAT MAKES THE OUTPUT REPRODUCIBLE
# ----------------------------------
# Three things, all decided in bin/ash.ts and relied on here:
#   1. Stacks are environment-agnostic, so no account id or region is baked in
#      and the output does not depend on who ran it.
#   2. Nothing uses a CDK asset, so there are no content hashes to vary and no
#      staging bucket to require.
#   3. `analyticsReporting: false` removes the CDKMetadata resource, whose
#      contents are keyed to the library version.
# The synth is NOT given any context beyond cdk.json's, so a local `cdk.context.json`
# cannot leak into the committed output.
#
# KNOWN LIMITATION: the output is reproducible for a fixed `aws-cdk-lib` version.
# Bumping the pinned version in package.json will legitimately change the
# templates — CDK changes generated logical ids, default properties and policy
# shapes between releases. That is a real diff to review, not drift to suppress.
#
# WHY THE STACK LIST IS DISCOVERED AND NOT WRITTEN DOWN
# -----------------------------------------------------
# It used to be a five-element literal array. A stack added to bin/ash.ts and not
# to that array was invisible here: the script iterated the five it knew, found
# them all current, and printed "templates/ matches a fresh synth (5 stacks)"
# while .github/workflows/ash-iac-drift.yml -- which discovers stacks from the
# assembly and copies cdk.out/*.template.json wholesale -- failed the required
# gate on the sixth, uncommitted template. A local check that reports clean while
# the gate reports drift is worse than no local check, because it is trusted.
#
# Discovered by globbing the assembly's *.template.json rather than by parsing
# manifest.json, because globbing is exactly what the workflow does. Reading the
# manifest would be more principled and is the wrong choice here: the property
# that matters is that this script and the gate consider the same set of files, and
# two different enumerations can disagree -- a template written without a manifest
# entry, or an artifact type the parser does not recognize. Sharing the
# enumeration makes agreement structural instead of something to keep in sync.
set -euo pipefail

cd "$(dirname "$0")/.."

TEMPLATE_DIR="templates"
CHECK_ONLY="no"
if [[ "${1:-}" == "--check" ]]; then
  CHECK_ONLY="yes"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --all so every stack in the app is synthesized rather than whatever the app's
# default selection happens to be; the gate passes it, and a script that did not
# would compare a different set of stacks than the gate compares.
#
# --no-lookups so a context lookup fails loudly instead of reaching for AWS
# credentials. A lookup-dependent template cannot be reproducibly synthesized
# offline, and one that silently resolved differently per run is drift nobody
# could explain. Again, the gate passes it.
#
# `--output` keeps the assembly out of the default cdk.out so a --check run
# cannot be fooled by a stale assembly left behind by an earlier plain synth.
npx cdk synth --all --no-lookups --quiet --output "$WORK/assembly" >/dev/null

# maxdepth 1: the assembly also holds a nested cdk.out directory, and *.assets.json,
# *.metadata.json and the cdk-nag reports, none of which are templates.
STACKS=()
while IFS= read -r template; do
  STACKS+=("$(basename "$template" .template.json)")
done < <(find "$WORK/assembly" -maxdepth 1 -type f -name '*.template.json' | sort)

# A zero here means synth ran and produced nothing, which would make every
# comparison below vacuously true and print a clean verdict for an empty set. The
# gate has the identical guard for the identical reason.
if [[ "${#STACKS[@]}" -eq 0 ]]; then
  echo "cdk synth produced no *.template.json under $WORK/assembly." >&2
  echo "Nothing would be compared, so this check would prove nothing." >&2
  exit 1
fi

mkdir -p "$TEMPLATE_DIR"
status=0
for stack in "${STACKS[@]}"; do
  src="$WORK/assembly/${stack}.template.json"
  dest="$TEMPLATE_DIR/${stack}.template.json"
  if [[ ! -f "$src" ]]; then
    echo "synth produced no template for ${stack}" >&2
    exit 1
  fi
  if [[ "$CHECK_ONLY" == "yes" ]]; then
    if [[ ! -f "$dest" ]]; then
      echo "DRIFT: ${dest} does not exist but the app synthesizes ${stack}" >&2
      status=1
    elif ! diff -q "$src" "$dest" >/dev/null; then
      echo "DRIFT: ${dest} differs from a fresh synth" >&2
      diff -u "$dest" "$src" | head -40 >&2
      status=1
    fi
  else
    cp "$src" "$dest"
    echo "wrote ${dest}"
  fi
done

# A template committed for a stack the app no longer synthesizes would be served
# to adopters forever without anyone regenerating it.
#
# --check reports it as drift; a write run deletes it. The asymmetry is what lets
# the CI gate name this script as its regeneration command: if writing left the
# orphan in place, running the script as instructed would produce a tree the gate
# still rejects, and the developer would be told to run a command that does not
# fix the problem. Only the generated pattern is deleted, so a README or a LICENSE
# kept alongside the templates survives.
while IFS= read -r committed; do
  name="$(basename "$committed" .template.json)"
  found="no"
  for stack in "${STACKS[@]}"; do
    [[ "$stack" == "$name" ]] && found="yes"
  done
  if [[ "$found" == "no" ]]; then
    if [[ "$CHECK_ONLY" == "yes" ]]; then
      echo "DRIFT: ${committed} has no corresponding stack in the app" >&2
      status=1
    else
      rm -f "$committed"
      echo "removed ${committed} (no corresponding stack in the app)"
    fi
  fi
done < <(find "$TEMPLATE_DIR" -name '*.template.json' -type f 2>/dev/null || true)

if [[ "$CHECK_ONLY" == "yes" && "$status" -eq 0 ]]; then
  echo "templates/ matches a fresh synth (${#STACKS[@]} stacks)"
fi
exit "$status"
