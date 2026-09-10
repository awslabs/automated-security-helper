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
#   2. The claim about credentials was imprecise, and the grep behind it was
#      loose. The old grep matched the bare word "credentials", which also occurs
#      in successful plan output, so "plan stopped later: credentials" was printed
#      for plans that did not stop at all.
#
#      Whether a mustnot plan stops at all is a property of the ENVIRONMENT, not of
#      these modules. On a workstation with a ~/.aws/credentials default profile the
#      AWS provider configures and six of the eight plans run to completion, which
#      is where the since-removed claim that "these modules plan offline without
#      ever needing credentials" came from. It does not hold in CI, which has no
#      credentials file: there all eight stop at provider configuration. Unsetting
#      the AWS_* variables at the top of this script does not close that gap,
#      because it does not hide the file. Run this with HOME pointed at an empty
#      directory to measure what CI measures.
#
# So the assertion is positional rather than about credentials: the plan must show
# it got past variable evaluation, and must carry no input-variable error. Both
# are needed and neither is redundant. The absence check catches a failure AT the
# variable stage; the progress check catches terraform dying BEFORE it, where
# there would be no variable error to find and the case would pass vacuously --
# an uninitialized module directory being the obvious way in.
#
# "Got past variable evaluation" therefore has to admit a plan that stopped just
# after it, not only one that finished. See PAST_VARIABLES below.
#
# WHAT THE CASE COUNT MEANS, AND WHY IT IS EASY TO OVERSTATE
# ----------------------------------------------------------
# There are 42 validation blocks across the five modules -- agentcore 4,
# ash-image-pipeline 11, codecommit-gate 11, codepipeline-executor 8, fargate 8 --
# and every one now has a `must` case proven to fire it.
#
# It reached 42 from 10, and the interesting part is that it was first reported as
# 13. Three rules were counted as covered on the strength of an error_message
# appearing in some case's output, when the case that produced it was exercising a
# DIFFERENT rule:
#
#   * codecommit-gate min_severity shares its message verbatim with
#     codepipeline-executor's, and no codecommit-gate case passed min_severity.
#   * codecommit-gate lambda_architecture ends in the same six words as
#     ash-image-pipeline's target_architecture ("must be either x86_64 or arm64"),
#     and the existing case greps only that shared tail.
#   * codepipeline-executor codecommit_repository_arn shares the ARN message with
#     codecommit-gate's, and every codepipeline-executor case passed a VALID ARN --
#     so the rule was evaluated on every run and never once asked to refuse
#     anything.
#
# A grep for an error_message cannot tell which rule produced it. Worse, good
# message writing actively encourages the collision: the same constraint should
# read the same way in every module, so the duplicates are correct and should not
# be perturbed to make this script's greps easier. The count therefore inflates in
# exactly the direction that flatters the harness.
#
# Two things keep it honest, and both are needed:
#
#   1. Attribution by directory. A case names the module directory it plans, and a
#      plan of module A cannot emit module B's diagnostics. The five module roots
#      are independent -- none declares a `module` block pointing at another (the
#      cross-module `source` references in this repository are all under
#      examples/basic/, which this script never plans) -- so the directory, not the
#      fragment, is what attributes a failure to a rule.
#   2. Mutation. Each rule was neutered in turn and the case claiming to cover it
#      was required to flip PASS -> FAIL. See the note in run_case's must branch.
#
# Where a fragment can carry the variable name, it does, so that a reader can see
# which rule a case is about without cross-referencing. Some cannot: two modules'
# name_prefix messages are byte-identical, as are their min_severity and ARN
# messages. For those, the directory and the mutation are the whole of the
# evidence, and no amount of fragment-tightening would add to it.
#
# WHAT THE PREVIOUS 32 UNCOVERED RULES WERE NOT
# ---------------------------------------------
# They were not broken, and nothing here fixes a validation rule. "This suite says
# nothing about this rule" is a different statement from "this rule does not work".
# Most of the 32 were never evaluated against a failing value at all, because no
# case supplied the variable and it sat at its default. A few were evaluated with a
# valid value and observed to stay silent, but never asked to refuse a bad one.
# Neither is evidence of a defect. Every one of the 32 fired correctly the first
# time it was given something invalid.
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

# Proof the plan got PAST input-variable evaluation. Asserting a *positive* marker
# is what stops a case passing when terraform died before reading variables at
# all, where there is no variable error to find. There are two observable ways to
# be past that stage, and both alternatives below are needed:
#
#   * the plan ran to completion -- the first three alternatives; or
#   * it failed at a stage strictly after variable evaluation. Terraform
#     configures a provider only once every input variable has been evaluated, so
#     a diagnostic attributed to a provider block proves the variable stage is
#     behind us. That attribution is the `with provider["..."]` line terraform's
#     own diagnostic renderer emits.
#
# The provider alternative is not optional, and leaving it out is what shipped
# this script red: the list once held only the first three, which are emitted by a
# plan that COMPLETES. On a runner with no credentials file none of the eight
# mustnot plans completes, so the suite reported pass=11 fail=8 with every failure
# reading past_variables=no -- see point 2 in the header for why that did not show
# up when the list was written.
#
# Matching the attribution rather than the credential message keeps this from
# being coupled to one provider's wording. It also keeps the guard the positive
# marker exists for. Measured with .terraform/ moved aside: plan emits "Required
# plugins are not installed" and no attribution line, so an uninitialized
# directory still scores past_variables=no and its cases still fail rather than
# passing vacuously.
#
# A loose marker here cannot excuse a real validation failure on its own, because
# the mustnot branch below also requires the rule's fragment to be absent and no
# variable-stage error to have been raised. Both absences are checked
# independently of this one.
PAST_VARIABLES='Terraform will perform the following actions|Plan: [0-9]+ to add|No changes|with provider\["'

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
    #
    # Neither conjunct can be satisfied by the credential error that ends the
    # mustnot plans on a runner with no credentials: that text carries no
    # module's error_message, and none of the four VAR_STAGE_ERROR strings.
    # Mutation-measured rather than argued, once per rule -- each of the 42
    # rules across the five modules was rewritten to a tautology that still
    # references its variable (`var.X == var.X`, because terraform rejects a
    # validation condition that does not refer to var.<self>, so a bare `true`
    # would not load), and every case flipped PASS -> FAIL, including both cases
    # of the one rule that carries two. In that state the plan reaches provider
    # configuration, so "No valid credential sources found" IS present in the
    # failing case's output and the case fails anyway. A case that still passed
    # with its rule neutered would not be testing the rule.
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

GATE_BASE=(
  -var codecommit_repository_arn=arn:aws:codecommit:us-east-1:0:repo
  -var base_image_uri=example.dkr.ecr.us-east-1.amazonaws.com/ash:latest
)

AGENTCORE_BASE=(
  -var container_image_uri=example.dkr.ecr.us-east-1.amazonaws.com/ash:latest
)

# ash_version has no default, so every ash-image-pipeline case has to supply one.
IMAGE_BASE=(
  -var ash_version=v3.6.0
)

# A base array only holds a module's REQUIRED variables, and a case adds the one
# variable it is about. Never both: terraform takes the FIRST -var for a given
# variable and silently ignores a later one, so appending an override after a
# base array leaves the base value in place. Measured, not assumed -- appending
# `-var 'service_subnet_ids=[]'` after FARGATE_BASE plans with the base's
# one-element list and raises no duplicate-flag warning. A case built that way
# would exercise nothing while looking correct, which is why the
# service_subnet_ids case below spells its variables out instead of reusing
# FARGATE_BASE.

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
# "1-25", not "1-33": this module's ceiling is lower than the other three
# because ALB and target group names are derived from the prefix, and that is
# what keeps this fragment from matching any other module's name_prefix rule.
run_case "name_prefix uppercase -> refused" must \
  "name_prefix must be 1-25 characters" \
  "$MODULES/fargate" "${FARGATE_BASE[@]}" -var name_prefix=ASH
# Spelled out rather than reusing FARGATE_BASE, which already sets
# service_subnet_ids -- see the note above the base arrays.
run_case "service_subnet_ids empty -> refused" must \
  "service_subnet_ids must contain at least one subnet" \
  "$MODULES/fargate" -var container_image_uri=x -var vpc_id=v \
  -var 'service_subnet_ids=[]' -var 'alb_subnet_ids=["subnet-a","subnet-b"]'
# Fargate spells the architecture uppercase where ash-image-pipeline spells it
# lowercase, and `contains` is case-sensitive, so the ECS spelling of a value
# that is valid in the image module is refused here.
run_case "cpu_architecture lowercase x86_64 -> refused" must \
  "cpu_architecture must be either X86_64 or ARM64" \
  "$MODULES/fargate" "${FARGATE_BASE[@]}" -var cpu_architecture=x86_64
run_case "desired_count negative -> refused" must \
  "desired_count must be zero or greater" \
  "$MODULES/fargate" "${FARGATE_BASE[@]}" -var desired_count=-1
run_case "mcp_mount_path without a leading slash -> refused" must \
  "mcp_mount_path must begin with a forward slash" \
  "$MODULES/fargate" "${FARGATE_BASE[@]}" -var mcp_mount_path=mcp

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
run_case "name_prefix uppercase -> refused" must \
  "name_prefix must be 1-33 characters of lowercase letters" \
  "$MODULES/codepipeline-executor" "${EXEC_BASE[@]}" -var name_prefix=ASH
# EXEC_BASE deliberately unused: it supplies a WELL-FORMED ARN, and this rule
# cannot be observed to fire without a malformed one. That is the whole gap --
# the rule was evaluated on every codepipeline-executor case and never once
# asked to refuse anything, while a grep for its error_message found the
# byte-identical message from codecommit-gate's rule and read as coverage.
run_case "malformed repository ARN -> refused" must \
  "codecommit_repository_arn must be a CodeCommit repository ARN" \
  "$MODULES/codepipeline-executor" -var codecommit_repository_arn=not-an-arn -var container_image_uri=x
run_case "build_environment_type outside the two CodeBuild types -> refused" must \
  "build_environment_type must be either LINUX_CONTAINER" \
  "$MODULES/codepipeline-executor" "${EXEC_BASE[@]}" -var build_environment_type=WINDOWS_CONTAINER
run_case "shard_build_timeout_minutes below 5 -> refused" must \
  "shard_build_timeout_minutes must be between 5 and 480" \
  "$MODULES/codepipeline-executor" "${EXEC_BASE[@]}" -var shard_build_timeout_minutes=4
run_case "merge_build_timeout_minutes above 480 -> refused" must \
  "merge_build_timeout_minutes must be between 5 and 480" \
  "$MODULES/codepipeline-executor" "${EXEC_BASE[@]}" -var merge_build_timeout_minutes=481
run_case "results_retention_days zero -> refused" must \
  "results_retention_days must be at least 1" \
  "$MODULES/codepipeline-executor" "${EXEC_BASE[@]}" -var results_retention_days=0

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
# This module's name_prefix message is the codecommit-gate and
# codepipeline-executor one plus a trailing clause, so the fragment has to be
# that clause. A fragment taken from the shared opening would match all three.
run_case "name_prefix uppercase -> refused" must \
  "must start with a letter or digit" \
  "$MODULES/ash-image-pipeline" "${IMAGE_BASE[@]}" -var name_prefix=ASH
# ash_version is required and has no default, so the only way to reach its rule
# is to pass a value that trimspace() empties.
run_case "ash_version all whitespace -> refused" must \
  "ash_version must be a non-empty git ref" \
  "$MODULES/ash-image-pipeline" -var 'ash_version=   '
run_case "ash_image_target outside the Dockerfile's stages -> refused" must \
  "ash_image_target must be one of: core, ci, non-root" \
  "$MODULES/ash-image-pipeline" "${IMAGE_BASE[@]}" -var ash_image_target=base
run_case "ecr_image_tag_mutability lowercase -> refused" must \
  "ecr_image_tag_mutability must be either MUTABLE or IMMUTABLE" \
  "$MODULES/ash-image-pipeline" "${IMAGE_BASE[@]}" -var ecr_image_tag_mutability=mutable
run_case "image_retention_count zero -> refused" must \
  "image_retention_count must be between 1 and 1000" \
  "$MODULES/ash-image-pipeline" "${IMAGE_BASE[@]}" -var image_retention_count=0
run_case "ssm_parameter_tier not an SSM tier -> refused" must \
  "ssm_parameter_tier must be one of: Standard, Advanced" \
  "$MODULES/ash-image-pipeline" "${IMAGE_BASE[@]}" -var ssm_parameter_tier=Basic
run_case "build_timeout_minutes above CodeBuild's 480 ceiling -> refused" must \
  "build_timeout_minutes must be between 5 and 480" \
  "$MODULES/ash-image-pipeline" "${IMAGE_BASE[@]}" -var build_timeout_minutes=481
# 45 is not in CloudWatch Logs' accepted set, and a plausible-looking value is
# the point: the rule exists because the API rejects anything off the list.
run_case "log_retention_days off CloudWatch's accepted list -> refused" must \
  "log_retention_days must be a retention value CloudWatch Logs" \
  "$MODULES/ash-image-pipeline" "${IMAGE_BASE[@]}" -var log_retention_days=45

echo
echo "### agentcore"
run_case "name_prefix with a hyphen -> refused (AgentCore rejects it)" must \
  "AgentCore runtime names do not accept hyphens" \
  "$MODULES/agentcore" -var container_image_uri=x -var name_prefix=ash-mcp
run_case "name_prefix with an underscore -> allowed" mustnot \
  "AgentCore runtime names do not accept hyphens" \
  "$MODULES/agentcore" -var container_image_uri=x -var name_prefix=ash_mcp
# agent_runtime_name carries the same no-hyphens constraint as name_prefix but
# in its own rule, so `ash-mcp` -- valid in every other module -- is refused
# twice over in this one, once per rule. This case names the second rule.
run_case "agent_runtime_name with a hyphen -> refused" must \
  "agent_runtime_name must start with a letter" \
  "$MODULES/agentcore" "${AGENTCORE_BASE[@]}" -var agent_runtime_name=ash-mcp
run_case "network_mode outside PUBLIC/VPC -> refused" must \
  "network_mode must be either PUBLIC or VPC" \
  "$MODULES/agentcore" "${AGENTCORE_BASE[@]}" -var network_mode=PRIVATE
# A header name starting with a digit fails AgentCore's allowlist pattern. This
# rule matters because an unallowlisted header is silently dropped rather than
# rejected, so a name the platform will not carry has to fail here.
run_case "mcp_auth_header_name starting with a digit -> refused" must \
  "mcp_auth_header_name must match AgentCore's allowlist" \
  "$MODULES/agentcore" "${AGENTCORE_BASE[@]}" -var mcp_auth_header_name=1-invalid

echo
echo "### codecommit-gate"
run_case "malformed repository ARN -> refused" must \
  "must be a CodeCommit repository ARN" \
  "$MODULES/codecommit-gate" -var codecommit_repository_arn=not-an-arn -var base_image_uri=x
run_case "well-formed repository ARN -> allowed" mustnot \
  "must be a CodeCommit repository ARN" \
  "$MODULES/codecommit-gate" -var codecommit_repository_arn=arn:aws:codecommit:us-east-1:0:repo -var base_image_uri=x
run_case "name_prefix uppercase -> refused" must \
  "name_prefix must be 1-33 characters of lowercase letters" \
  "$MODULES/codecommit-gate" "${GATE_BASE[@]}" -var name_prefix=ASH
run_case "trigger_events empty -> refused (the gate would never run)" must \
  "trigger_events must name at least one event" \
  "$MODULES/codecommit-gate" "${GATE_BASE[@]}" -var 'trigger_events=[]'
# This module's min_severity rule, not codepipeline-executor's. The two carry
# byte-identical error_messages -- correctly, since it is the same constraint --
# so no fragment can tell them apart and only running the case against THIS
# module's directory attributes the failure here.
run_case "min_severity outside ASH's ladder -> refused" must \
  "min_severity must be one of" \
  "$MODULES/codecommit-gate" "${GATE_BASE[@]}" -var min_severity=catastrophic
run_case "approval_rule_approvals_required zero -> refused" must \
  "approval_rule_approvals_required must be between 1 and 100" \
  "$MODULES/codecommit-gate" "${GATE_BASE[@]}" -var approval_rule_approvals_required=0
# 901 is one second past Lambda's own hard maximum, which is the limitation this
# whole target is bounded by.
run_case "lambda_timeout_seconds past Lambda's 900 ceiling -> refused" must \
  "lambda_timeout_seconds must be between 30 and 900" \
  "$MODULES/codecommit-gate" "${GATE_BASE[@]}" -var lambda_timeout_seconds=901
run_case "lambda_memory_mb below 512 -> refused" must \
  "lambda_memory_mb must be between 512 and 10240" \
  "$MODULES/codecommit-gate" "${GATE_BASE[@]}" -var lambda_memory_mb=511
run_case "lambda_ephemeral_storage_mb above 10240 -> refused" must \
  "lambda_ephemeral_storage_mb must be between 512 and 10240" \
  "$MODULES/codecommit-gate" "${GATE_BASE[@]}" -var lambda_ephemeral_storage_mb=10241
# The fragment carries the variable name deliberately. ash-image-pipeline's
# target_architecture rule ends in the same six words, and the existing case for
# that rule greps only the shared tail -- which is how this rule was counted as
# covered while no codecommit-gate case ever passed lambda_architecture.
run_case "lambda_architecture outside x86_64/arm64 -> refused" must \
  "lambda_architecture must be either x86_64 or arm64" \
  "$MODULES/codecommit-gate" "${GATE_BASE[@]}" -var lambda_architecture=riscv
run_case "max_comment_chars below 500 -> refused" must \
  "max_comment_chars must be at least 500" \
  "$MODULES/codecommit-gate" "${GATE_BASE[@]}" -var max_comment_chars=499
run_case "ecr_image_tag_mutability lowercase -> refused" must \
  "ecr_image_tag_mutability must be either MUTABLE or IMMUTABLE" \
  "$MODULES/codecommit-gate" "${GATE_BASE[@]}" -var ecr_image_tag_mutability=mutable

echo
echo "validate-inputs: pass=$PASS fail=$FAIL"
[[ "$FAIL" -eq 0 ]]
