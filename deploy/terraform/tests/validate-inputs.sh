#!/usr/bin/env bash
#
# Exercise the modules' input variable validation rules. No AWS account needed.
#
# Why this exists: `terraform validate` does NOT evaluate variable validation
# rules. It checks syntax, provider schema, and references, so a module whose
# validation condition is wrong — including a cross-variable rule — passes
# validate and only errors at plan time. A green fmt-and-validate gate therefore
# says the configuration parses, not that its input contracts work.
#
# The gap is cheap to close, because `terraform plan` evaluates input variable
# validation BEFORE it initializes the provider or needs credentials. A plan with
# a deliberately invalid value fails on the rule's own error_message and never
# reaches AWS. That is what this script relies on, and it is why no credentials
# are configured below and IMDS is disabled.
#
# Every rule is checked in BOTH directions, which is the point rather than
# thoroughness for its own sake. A check that only ever feeds in the failing value
# cannot tell "the rule fired" apart from "plan failed for an unrelated reason and
# the grep happened to match":
#
#   must     - the invalid value MUST produce the rule's error_message, AND the
#              plan MUST have failed at the input-variable stage.
#   mustnot  - a valid value MUST NOT produce it, AND the plan MUST have got past
#              the input-variable stage, proving validation was passed rather than
#              skipped.
#
# WHY THE mustnot DIRECTION IS ASSERTED THIS WAY
# ----------------------------------------------
# It used to assert only the absence of the fragment, and print a line claiming
# the plan "stopped later: <credential error>" as evidence that validation had
# been reached. Two things were wrong with that, and together they made the
# direction unable to fail for the reason it claimed:
#
#   1. The evidence was printed, never asserted. terraform's exit status was
#      discarded, so any failure that did not happen to contain the matched
#      fragment scored PASS. Deleting or renaming a variable the case passes with
#      -var makes terraform emit "Value for undeclared variable" -- which contains
#      no rule error_message -- so the mustnot case passed while its must twin
#      still fired, and the script reported pass=19 fail=0 with the variable gone.
#
#   2. The claim about credentials was mostly false. Measured across the eight
#      mustnot cases, six plans SUCCEED: these modules plan offline without ever
#      needing credentials. The old grep was matching the bare word "credentials"
#      inside successful plan output, so "plan stopped later: credentials" was
#      printed for plans that did not stop at all. Promoting that grep to an
#      assertion would have failed two correct cases, which reach the resource
#      stage and mention credentials nowhere.
#
# So the assertion is positional rather than about credentials: the plan must show
# it got past variable evaluation, and must carry no input-variable error. Both
# are needed and neither is redundant. The absence check catches a failure AT the
# variable stage; the progress check catches terraform dying BEFORE it, where
# there would be no variable error to find and the case would pass vacuously --
# an uninitialized module directory being the obvious way in.
#
# Usage:
#   deploy/terraform/tests/validate-inputs.sh
#
# Requires terraform >= 1.9 (the fargate module uses a cross-variable rule) and a
# prior `terraform init -backend=false` in each module directory.

set -uo pipefail

# Nothing here may reach AWS. Disabling IMDS also stops the provider from
# blocking on a metadata timeout in the mustnot cases.
export AWS_EC2_METADATA_DISABLED=true
export AWS_REGION="${AWS_REGION:-us-east-1}"
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE 2>/dev/null || true

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MODULES="$(cd -- "$SCRIPT_DIR/../modules" && pwd)"

LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT

PASS=0
FAIL=0

# Every error terraform raises while evaluating input variables. Their presence
# means the plan stopped at the variable stage; their absence is half of what
# proves it got past. "Invalid value for variable" is a failed validation
# condition; the other three are the ways a -var can be wrong without tripping any
# validation block, and "Value for undeclared variable" in particular is what a
# renamed or deleted variable produces.
VAR_STAGE_ERROR='Invalid value for variable|Value for undeclared variable|No value for required variable|Invalid value for input variable'

# Proof the plan evaluated the configuration. One of these appears in all eight
# mustnot cases as measured -- whether the plan then succeeded, failed on
# credentials, or failed on a resource attribute. Asserting a *positive* marker is
# what stops a case passing when terraform died before reading variables at all,
# where there is no variable error to find.
PAST_VARIABLES='Terraform will perform the following actions|Plan: [0-9]+ to add|No changes'

# run_case <label> <must|mustnot> <error-fragment> <module-dir> [terraform args...]
run_case() {
  local label="$1" expect="$2" fragment="$3" dir="$4"; shift 4

  terraform -chdir="$dir" plan -input=false -no-color "$@" > "$LOG" 2>&1

  local found=no var_stage=no past_variables=no
  grep -qF "$fragment" "$LOG" && found=yes
  grep -qE "$VAR_STAGE_ERROR" "$LOG" && var_stage=yes
  grep -qE "$PAST_VARIABLES" "$LOG" && past_variables=yes

  local ok why
  if [[ "$expect" == must ]]; then
    # The fragment alone would be satisfied by any failure whose text happened to
    # contain the error_message. Requiring the failure to be AT the variable stage
    # is what makes it the rule firing rather than a coincidence.
    if [[ "$found" == yes && "$var_stage" == yes ]]; then
      ok=yes; why="rule fired at the variable stage"
    else
      ok=no; why="need fragment+var-stage, got fragment=$found var_stage=$var_stage"
    fi
  else
    if [[ "$found" == no && "$var_stage" == no && "$past_variables" == yes ]]; then
      ok=yes; why="rule silent, and the plan evaluated the configuration"
    else
      ok=no
      why="need no-fragment+no-var-stage+past-variables, got fragment=$found var_stage=$var_stage past_variables=$past_variables"
    fi
  fi

  if [[ "$ok" == yes ]]; then
    printf '  PASS  %-58s %s\n' "$label" "$why"
    PASS=$((PASS + 1))
  else
    printf '  FAIL  %-58s %s\n' "$label" "$why"
    tail -15 "$LOG"
    FAIL=$((FAIL + 1))
  fi
}

# Placeholder identifiers only. These never reach AWS, and account ids are reduced to a
# single 0, which the ARN pattern accepts, so the repository carries no
# 12-digit strings for a secret scanner to flag.
FARGATE_BASE=(
  -var container_image_uri=example.dkr.ecr.us-east-1.amazonaws.com/ash:latest
  -var vpc_id=vpc-example
  -var 'service_subnet_ids=["subnet-example-a"]'
  -var 'alb_subnet_ids=["subnet-example-a","subnet-example-b"]'
)

EXEC_BASE=(
  -var codecommit_repository_arn=arn:aws:codecommit:us-east-1:0:repo
  -var container_image_uri=example.dkr.ecr.us-east-1.amazonaws.com/ash:latest
)

echo "### fargate: cross-variable rule (the reason these modules need Terraform >= 1.9)"
run_case "auth header + plain HTTP -> refused" must \
  "mcp_auth_header_value is set but the listener would be plain HTTP" \
  "$MODULES/fargate" "${FARGATE_BASE[@]}" -var mcp_auth_header_value=placeholder
run_case "auth header + explicit opt-out -> allowed" mustnot \
  "mcp_auth_header_value is set but the listener would be plain HTTP" \
  "$MODULES/fargate" "${FARGATE_BASE[@]}" -var mcp_auth_header_value=placeholder -var allow_plaintext_auth_header=true
run_case "auth header + certificate -> allowed" mustnot \
  "mcp_auth_header_value is set but the listener would be plain HTTP" \
  "$MODULES/fargate" "${FARGATE_BASE[@]}" -var mcp_auth_header_value=placeholder \
  -var certificate_arn=arn:aws:acm:us-east-1:0:certificate/placeholder

echo
echo "### fargate: single-variable rules"
run_case "alb_subnet_ids with one subnet -> refused" must \
  "must contain at least two subnets" \
  "$MODULES/fargate" -var container_image_uri=x -var vpc_id=v \
  -var 'service_subnet_ids=["a"]' -var 'alb_subnet_ids=["a"]'
run_case "ephemeral_storage_gib below Fargate's 20 GiB default -> refused" must \
  "must be between 21 and 200" \
  "$MODULES/fargate" "${FARGATE_BASE[@]}" -var ephemeral_storage_gib=20

echo
echo "### codepipeline-executor"
run_case "shard_count 101 -> refused (100 parallel actions per stage)" must \
  "shard_count must be between 1 and 100" \
  "$MODULES/codepipeline-executor" "${EXEC_BASE[@]}" -var shard_count=101
run_case "shard_count 8 -> allowed" mustnot \
  "shard_count must be between 1 and 100" \
  "$MODULES/codepipeline-executor" "${EXEC_BASE[@]}" -var shard_count=8
run_case "min_severity outside ASH's ladder -> refused" must \
  "min_severity must be one of" \
  "$MODULES/codepipeline-executor" "${EXEC_BASE[@]}" -var min_severity=catastrophic
# ASH ranks no "info" level and does `_SEVERITY_RANK.get(value, 1)`, so it would
# silently treat info as "low" — a gate running at a threshold nobody chose. This
# validation is the only thing that turns that into an error.
run_case "min_severity info -> refused (ASH ranks no such level)" must \
  "min_severity must be one of" \
  "$MODULES/codepipeline-executor" "${EXEC_BASE[@]}" -var min_severity=info
run_case "min_severity high -> allowed" mustnot \
  "min_severity must be one of" \
  "$MODULES/codepipeline-executor" "${EXEC_BASE[@]}" -var min_severity=high
run_case "min_severity low (the default) -> allowed" mustnot \
  "min_severity must be one of" \
  "$MODULES/codepipeline-executor" "${EXEC_BASE[@]}" -var min_severity=low

echo
echo "### ash-image-pipeline"
OVERSIZED_CONFIG="$(python3 -c "print('k: ' + 'v' * 9000)")"
run_case "ash_base_config_yaml over the 8 KB SSM ceiling -> refused" must \
  "exceeds 8192 bytes" \
  "$MODULES/ash-image-pipeline" -var ash_version=v3.6.0 -var "ash_base_config_yaml=$OVERSIZED_CONFIG"
run_case "small ash_base_config_yaml -> allowed" mustnot \
  "exceeds 8192 bytes" \
  "$MODULES/ash-image-pipeline" -var ash_version=v3.6.0 -var 'ash_base_config_yaml=reporters: {}'
run_case "rebuild_schedule not rate()/cron() -> refused" must \
  "must be an EventBridge schedule expression" \
  "$MODULES/ash-image-pipeline" -var ash_version=v3.6.0 -var 'rebuild_schedule=daily'
run_case "target_architecture outside x86_64/arm64 -> refused" must \
  "must be either x86_64 or arm64" \
  "$MODULES/ash-image-pipeline" -var ash_version=v3.6.0 -var target_architecture=riscv

echo
echo "### agentcore"
run_case "name_prefix with a hyphen -> refused (AgentCore rejects it)" must \
  "AgentCore runtime names do not accept hyphens" \
  "$MODULES/agentcore" -var container_image_uri=x -var name_prefix=ash-mcp
run_case "name_prefix with an underscore -> allowed" mustnot \
  "AgentCore runtime names do not accept hyphens" \
  "$MODULES/agentcore" -var container_image_uri=x -var name_prefix=ash_mcp

echo
echo "### codecommit-gate"
run_case "malformed repository ARN -> refused" must \
  "must be a CodeCommit repository ARN" \
  "$MODULES/codecommit-gate" -var codecommit_repository_arn=not-an-arn -var base_image_uri=x
run_case "well-formed repository ARN -> allowed" mustnot \
  "must be a CodeCommit repository ARN" \
  "$MODULES/codecommit-gate" -var codecommit_repository_arn=arn:aws:codecommit:us-east-1:0:repo -var base_image_uri=x

echo
echo "validate-inputs: pass=$PASS fail=$FAIL"
[[ "$FAIL" -eq 0 ]]
