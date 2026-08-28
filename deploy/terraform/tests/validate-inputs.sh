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
#   must     - the invalid value MUST produce the rule's error_message.
#   mustnot  - a valid value MUST NOT produce it. Plan is still expected to fail
#              here, on credentials, and that later failure is the evidence that
#              validation was passed rather than skipped.
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

# run_case <label> <must|mustnot> <error-fragment> <module-dir> [terraform args...]
run_case() {
  local label="$1" expect="$2" fragment="$3" dir="$4"; shift 4

  terraform -chdir="$dir" plan -input=false -no-color "$@" > "$LOG" 2>&1

  local found=no
  grep -qF "$fragment" "$LOG" && found=yes

  if [[ "$expect" == must && "$found" == yes ]]; then
    printf '  PASS  %-58s rule fired\n' "$label"
    PASS=$((PASS + 1))
  elif [[ "$expect" == mustnot && "$found" == no ]]; then
    local why
    why=$(grep -oiE 'no valid credential sources|credentials|InvalidClientTokenId|Unable to locate|failed to get shared config' "$LOG" | head -1)
    printf '  PASS  %-58s rule silent (plan stopped later: %s)\n' "$label" "${why:-see log}"
    PASS=$((PASS + 1))
  else
    printf '  FAIL  %-58s expected=%s found=%s\n' "$label" "$expect" "$found"
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
