#!/usr/bin/env bash
#
# Regenerate the expected diff between the CDK and Terraform copies of the S3
# sync helper.
#
#   ./scripts/gen-s3-sync-diff-fixture.sh
#
# WHY A FIXTURE OF THE DIFF, RATHER THAN A NORMALIZED COMPARISON
# -------------------------------------------------------------
# deploy/cdk and deploy/terraform each carry their own copy of the helper,
# because the two deployment trees are independently consumable. The copies are
# behaviourally identical and must stay that way, but they legitimately differ in
# their docstring and log prefix -- so a byte comparison cannot be the test.
#
# The obvious fix, normalizing both sides before comparing, is worse than no test:
# a normalization permissive enough to excuse a docstring difference is also
# permissive enough to excuse a logic change, so it would launder drift rather
# than catch it.
#
# Pinning the EXACT diff has neither problem. It excuses precisely the
# differences that exist today and nothing else. The moment any new difference
# appears -- in either copy, in either direction -- the test fails and a human
# reads the diff and decides: prose, in which case regenerate this fixture, or
# logic, in which case the two copies have diverged and one of them is wrong.
#
# The test that consumes this is in test/ash-container-scripts.test.ts. It builds
# the diff the same way this script does, so the two cannot disagree about how the
# comparison is made.
set -euo pipefail

cd "$(dirname "$0")/.."

TERRAFORM_COPY="../terraform/modules/codepipeline-executor/files/ash_s3_sync.py"
FIXTURE="test/fixtures/ash-s3-sync-vs-terraform.diff"

if [[ ! -f "$TERRAFORM_COPY" ]]; then
  echo "$TERRAFORM_COPY is absent, so there is nothing to compare against." >&2
  echo "The Terraform tree has not landed on this ref. Leaving the fixture alone." >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Extract the constant through the app's own module rather than by parsing the
# TypeScript, so this cannot disagree with what the stack actually emits.
npx ts-node -e '
  import { ASH_S3_SYNC_SCRIPT } from "./lib/ash-container-scripts";
  process.stdout.write(ASH_S3_SYNC_SCRIPT);
' > "$WORK/cdk.py"

mkdir -p "$(dirname "$FIXTURE")"

# --label, so the header lines carry stable names instead of temp paths that
# change every run. diff exits 1 when the files differ, which is expected here.
diff -u --label cdk/ash-container-scripts.ts:ASH_S3_SYNC_SCRIPT \
        --label terraform/codepipeline-executor/files/ash_s3_sync.py \
        "$WORK/cdk.py" "$TERRAFORM_COPY" > "$FIXTURE" || true

if [[ ! -s "$FIXTURE" ]]; then
  echo "The two copies are byte-identical; the fixture is empty." >&2
fi

echo "wrote $FIXTURE ($(wc -l < "$FIXTURE") lines)"
