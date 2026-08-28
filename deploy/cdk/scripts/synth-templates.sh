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
set -euo pipefail

cd "$(dirname "$0")/.."

STACKS=(AshImagePipeline AshAgentCore AshFargate AshCodeCommitGate AshDistributedPipeline)
TEMPLATE_DIR="templates"
CHECK_ONLY="no"
if [[ "${1:-}" == "--check" ]]; then
  CHECK_ONLY="yes"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# `--output` keeps the assembly out of the default cdk.out so a --check run
# cannot be fooled by a stale assembly left behind by an earlier plain synth.
npx cdk synth --quiet --output "$WORK/assembly" >/dev/null

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
while IFS= read -r committed; do
  name="$(basename "$committed" .template.json)"
  found="no"
  for stack in "${STACKS[@]}"; do
    [[ "$stack" == "$name" ]] && found="yes"
  done
  if [[ "$found" == "no" ]]; then
    echo "DRIFT: ${committed} has no corresponding stack in the app" >&2
    status=1
  fi
done < <(find "$TEMPLATE_DIR" -name '*.template.json' -type f 2>/dev/null || true)

if [[ "$CHECK_ONLY" == "yes" && "$status" -eq 0 ]]; then
  echo "templates/ matches a fresh synth (${#STACKS[@]} stacks)"
fi
exit "$status"
