#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# The quick-create channel end to end:
#
#   scripts/e2e/quick_create.sh <work-dir>
#
#   E2E_CFN_LINT  the cfn-lint command line (default: uv run --frozen --only-group dev
#                 cfn-lint, which is the version uv.lock pins)
#
# This channel installs nothing and runs no scan. What it ships is a document of
# CloudFormation quick-create links rendered from the committed templates, so the leg
# renders that document from the checked-out head against two scratch hosting files and
# judges the result with scripts/e2e/assert_quick_create.py, which shares no code with
# the renderer.
#
# 1. The renderer's own --self-test, and the committed hosting file still configures
#    no bucket.
# 2. A dotted bucket, two launch regions and a key prefix that needs percent-encoding.
#    `render --hosting --out`, then `check` on that render, then the assertion with
#    path-style addressing and cfn-lint over every template a link names, in the
#    regions its links launch in.
# 3. An undotted bucket. Same steps, asserting virtual-hosted addressing.
# 4. Negative controls, each of which must be seen failing, for the reason named:
#    a. the renderer forced to address the dotted bucket virtual-hosted: `check` must
#       exit 1 naming the period, and the path-style assertion must exit 1;
#    b. the undotted render judged as path-style must exit 1 on templateURL;
#    c. the dotted render with one link removed must exit 1 on the missing link;
#    d. cfn-lint over a copy of the templates with one resource type broken must exit 1.
# 5. The committed document and hosting file are unchanged, so nothing above wrote into
#    the checkout.
set -euo pipefail

WORK="${1:?usage: quick_create.sh <work-dir>}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CFN_LINT="${E2E_CFN_LINT:-uv run --frozen --only-group dev cfn-lint}"
# Errors only. cfn-lint exits with a bit mask (2 error, 4 warning, 8 informational),
# and the committed templates carry W3005 warnings for DependsOn entries the CDK
# emits. The question this leg asks is whether CloudFormation would accept the
# template a link launches, which is the error level. The EKS stack's lint job
# decides the policy for warnings over these same files.
LINT="$CFN_LINT --non-zero-exit-code error"
RENDER="$REPO/scripts/render_quick_create_links.py"
ASSERT="$REPO/scripts/e2e/assert_quick_create.py"

say() { printf '== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# Runs a command that must fail with exit 1 and print $2 on stderr.
expect_fail() {
  local label="$1" needle="$2"
  shift 2
  local err="$WORK/neg-$label.err" rc=0
  "$@" >"$WORK/neg-$label.out" 2>"$err" || rc=$?
  if [ "$rc" -ne 1 ]; then
    cat "$err" >&2
    fail "negative control $label: expected exit 1, got $rc"
  fi
  if ! grep -qF -- "$needle" "$err"; then
    cat "$err" >&2
    fail "negative control $label: exit 1, but stderr does not mention '$needle'"
  fi
  say "negative control $label failed as required (exit 1, '$needle')"
}

mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"
cd "$REPO"

before="$(git status --porcelain --untracked-files=all -- deploy/quick-create-links.md deploy/quick-create-hosting.json)"

say "1. renderer self-test and the committed hosting default"
python3 "$RENDER" check --self-test
python3 - <<'PY'
import json, sys
hosting = json.load(open("deploy/quick-create-hosting.json", encoding="utf-8"))
if hosting.get("bucket"):
    sys.exit(f"deploy/quick-create-hosting.json configures bucket {hosting['bucket']!r}; it must stay empty")
print("committed hosting file configures no bucket")
PY

write_hosting() {
  python3 - "$1" "$2" "$3" "$4" "$5" <<'PY'
import json, sys
path, bucket, region, prefix, regions = sys.argv[1:]
json.dump({"bucket": bucket, "bucket_region": region, "key_prefix": prefix,
           "launch_regions": regions.split()}, open(path, "w", encoding="utf-8"))
PY
}

DOTTED="$WORK/hosting-dotted.json"
UNDOTTED="$WORK/hosting-undotted.json"
write_hosting "$DOTTED" "ash-e2e.quick-create.invalid" eu-west-2 "e2e prefix+v4/" "us-east-1 eu-west-2"
write_hosting "$UNDOTTED" "ash-e2e-quick-create-invalid" us-east-1 "" "us-east-1"

say "2. dotted bucket: render, check, path-style assertion, cfn-lint"
python3 "$RENDER" render --hosting "$DOTTED" --out "$WORK/dotted.md"
python3 "$RENDER" check --hosting "$DOTTED" --out "$WORK/dotted.md"
python3 "$ASSERT" --doc "$WORK/dotted.md" --hosting "$DOTTED" --addressing path --lint-cmd "$LINT"

say "3. undotted bucket: render, check, virtual-hosted assertion, cfn-lint"
python3 "$RENDER" render --hosting "$UNDOTTED" --out "$WORK/undotted.md"
python3 "$RENDER" check --hosting "$UNDOTTED" --out "$WORK/undotted.md"
python3 "$ASSERT" --doc "$WORK/undotted.md" --hosting "$UNDOTTED" --addressing virtual --lint-cmd "$LINT"

say "4. negative controls"
# a. The renderer itself, with template_url replaced by the virtual-hosted form for
#    every bucket. This is the regression the dotted rule exists to prevent.
python3 - "$RENDER" "$DOTTED" "$WORK/forced-virtual.md" <<'PY'
import importlib.util, sys
render, hosting, out = sys.argv[1:]
spec = importlib.util.spec_from_file_location("renderer", render)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
quote = module.urllib.parse.quote
module.template_url = lambda h, stack: (
    f"https://{h['bucket']}.s3.{h['bucket_region']}.amazonaws.com/"
    + quote(f"{h['key_prefix']}{stack}.template.json", safe="/")
)
sys.exit(module.main(["render_quick_create_links.py", "render", "--hosting", hosting, "--out", out]))
PY
expect_fail a-check "contains a period" \
  python3 "$RENDER" check --hosting "$DOTTED" --out "$WORK/forced-virtual.md"
expect_fail a-assert "path addressing" \
  python3 "$ASSERT" --doc "$WORK/forced-virtual.md" --hosting "$DOTTED" --addressing path
# b.
expect_fail b-addressing "path addressing" \
  python3 "$ASSERT" --doc "$WORK/undotted.md" --hosting "$UNDOTTED" --addressing path
# c. Drop the first launch link from the dotted render.
python3 - "$WORK/dotted.md" "$WORK/dotted-missing.md" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
text, n = re.subn(r"\[Launch in [a-z0-9-]+\]\([^)]*\)", "", text, count=1)
assert n == 1, "no launch link to remove"
open(sys.argv[2], "w", encoding="utf-8").write(text)
PY
expect_fail c-missing "no link launches" \
  python3 "$ASSERT" --doc "$WORK/dotted-missing.md" --hosting "$DOTTED" --addressing path
# d. One template's first resource given a type CloudFormation does not have.
rm -rf "$WORK/broken-templates"
cp -R deploy/cdk/templates "$WORK/broken-templates"
python3 - "$WORK/broken-templates/AshImagePipeline.template.json" <<'PY'
import json, sys
path = sys.argv[1]
doc = json.load(open(path, encoding="utf-8"))
first = next(iter(doc["Resources"]))
doc["Resources"][first]["Type"] = "AWS::E2E::NoSuchResource"
json.dump(doc, open(path, "w", encoding="utf-8"), indent=1)
PY
expect_fail d-lint "AshImagePipeline" \
  python3 "$ASSERT" --doc "$WORK/undotted.md" --hosting "$UNDOTTED" --addressing virtual \
  --templates "$WORK/broken-templates" --lint-cmd "$LINT"

say "5. the checkout is unchanged"
after="$(git status --porcelain --untracked-files=all -- deploy/quick-create-links.md deploy/quick-create-hosting.json)"
[ "$before" = "$after" ] || fail "the committed quick-create files changed: $after"
python3 "$RENDER" check

say "quick-create e2e passed"
