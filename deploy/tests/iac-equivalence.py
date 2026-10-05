#!/usr/bin/env python3
"""Keeps ASH's CloudFormation stacks and its Terraform modules describing the
same infrastructure.

WHY THIS EXISTS
---------------
deploy/ ships two independent implementations of the same five deployment
targets: a CDK app whose synthesized templates are committed under
deploy/cdk/templates/, and hand-written Terraform under
deploy/terraform/modules/. Before this check, nothing compared them.

ash-iac-drift.yml already keeps each representation honest against ITS OWN
source -- the templates must match a fresh `cdk synth`, the buildspecs must
match their generator, the Terraform must format, initialize and validate. All
of those are single-representation checks. A resource added to the CDK app
appears in the template, the template is regenerated, the drift gate goes
green, and the Terraform module silently no longer describes the same
deployment. An adopter who chose Terraform then gets a deployment that is
missing whatever was added, and nothing in CI said a word.

That is the gap this closes: it is the only check here that reads BOTH
representations and compares them to each other.

WHAT IT COMPARES, AND WHY THAT GRANULARITY
------------------------------------------
The comparison is a PRESENCE CENSUS over resource kinds: for each pair, does
each side provision at least one resource of each canonical kind. Not counts,
not properties, not named resources.

Counts are deliberately not compared, and this is the measurement that decided
it. Across the five pairs the two sides never agree on resource counts and
cannot be made to:

    AshAgentCore            28 CFN resources   vs   agentcore            6
    AshDistributedPipeline  88 CFN resources   vs   codepipeline-executor 20

CDK synthesizes an implicit AWS::IAM::Policy for every `grant*()` call, so
AshDistributedPipeline carries 50 of them against 4 `aws_iam_role_policy`
blocks that say the same thing in fewer, larger documents. A count comparison
would fire on all five pairs forever and its only available "fix" would be to
weaken it until it stopped meaning anything.

Named-resource correspondence -- a map from CFN logical id to Terraform address
-- was considered and rejected for this first cut. It is strictly more precise
and strictly more maintenance: CDK logical ids carry a generated hash suffix
(`EncryptionKey1B843E66`) that moves whenever the construct path changes, so
the map would need updating on refactors that change nothing an adopter sees.

A presence census over kinds is what catches the failure mode actually
described above -- a resource kind appearing on one side and not the other --
with a mapping a reviewer can read in one sitting.

THE PART THAT GIVES IT TEETH
----------------------------
Nothing unclassified is ever skipped, at either of the two levels where
something can be unclassified.

An unmapped resource TYPE is a failure. Every type on both sides must appear in
KINDS or in one of the two EXCLUDED tables. So when somebody adds a resource of
a kind this file has never heard of, the gate goes red and names it -- whether
or not the Terraform side happens to be missing it.

An unclassified STACK is also a failure. check_stack_coverage() globs CFN_DIR
and requires every committed template to be named in PAIRS or in
STACKS_WITHOUT_TERRAFORM. This level was missing at first and the omission was
exactly the failure class this file exists to prevent: PAIRS was the only list
of stacks and load_cfn() was only called for names in it, so a sixth committed
template was never opened, its AWS::EKS::* types were never checked against the
vocabulary, and the run still printed "no unrecorded divergence" and exited 0.
The type-level teeth could not engage because the gap sat one level above them.

Discovery is therefore a glob, never a list. A hardcoded list cannot report the
thing it is missing.

WHAT THIS CHECK DOES NOT CATCH
------------------------------
Stated plainly, because a drift check whose limits are unstated gets trusted
past them. This check is blind to all of the following:

1. PROPERTY-LEVEL DIVERGENCE. Both sides declaring the same kind is enough. A
   bucket encrypted with a customer-managed key on one side and AES256 on the
   other reads as a match. This is not hypothetical -- it is the live KMS
   divergence recorded in BASELINE below, which was found by hand and is only
   visible here because the KEY ITSELF is a separate resource kind. Had CDK
   configured encryption inline, this check would have seen nothing.
2. COUNTS. Two CodeBuild projects against one is a match. See above for why.
3. NAMED CORRESPONDENCE. Nothing checks that the CFN role and the Terraform
   role are the SAME role, only that both sides have roles.
4. IAM POLICY CONTENT. AWS::IAM::Policy and aws_iam_role_policy are one kind.
   A statement granting `*` on one side and nothing on the other is invisible.
5. EVERYTHING INSIDE AN EXTERNAL MODULE. The Fargate example gets its VPC from
   `aws-ia/vpc/aws`. This check does not fetch or parse registry modules, so
   the 11 EC2 kinds in AshFargate.template.json are baselined as unverified
   rather than confirmed. A change inside that module is not visible here.
6. RESOURCES EXCLUDED AS PROPERTY-EQUIVALENTS. Terraform models bucket
   encryption, versioning, and public-access blocking as separate resources
   where CloudFormation models them as properties of AWS::S3::Bucket. Those
   Terraform types are excluded by name (see TF_EXCLUDED), which means
   DELETING `aws_s3_bucket_server_side_encryption_configuration` outright
   would not fail this check. Item 1 is the same blind spot from the other
   direction and it is the most important limitation on this list.
7. CONDITIONAL RESOURCES. A Terraform `resource` block with
   `count = 0` or a CloudFormation resource behind a false `Condition` still
   counts as present. Presence here means "declared", not "will exist".
8. TERRAFORM THAT IS NOT A `resource` BLOCK. `data` sources, `locals`,
   `moved` blocks and provider configuration are not read. Comments are
   stripped first (strip_hcl_comments), so a block commented out with `#`,
   `//` or `/* */` is not counted.
9. NESTED DIRECTORIES INSIDE A MODULE. load_tf() reads only the `*.tf` files
   at a module's root, the same set Terraform loads for that module. A
   resource in a subdirectory is part of the module only if the root calls
   that subdirectory as a local `module`, and this check does not follow
   such calls, so its resources would not be counted. No module here has a
   nested module directory today; adding one means extending load_tf() or
   adding the subdirectory to PAIRS as a module of its own.

Closing 1 and 6 means mapping properties across two schemas that disagree
about shape, which is a materially larger piece of work than this file. It is
the right next increment; it is not this increment.

HOW A DIVERGENCE IS RECORDED RATHER THAN SMOOTHED AWAY
------------------------------------------------------
The five pairs DO diverge today. Every divergence is itemized in BASELINE
below, one entry per (pair, direction, kind), each with the reason it exists.
There is no wildcard and no pattern -- an entry names exactly one kind on
exactly one side of exactly one pair.

A divergence that is NOT in BASELINE fails the check. That is what makes new
drift red.

A BASELINE entry that no longer matches ALSO fails the check. Without that, a
baseline quietly becomes the wildcard it was written to avoid: entries
accumulate, stop describing reality, and the next reader cannot tell which ones
still mean something.

But an entry can stop matching for three reasons that call for OPPOSITE
actions, and conflating them is how a gate talks a maintainer into damage:

  * both sides declare the kind now -> genuinely fixed, delete the entry;
  * neither side declares it now    -> NOT a fix. Consistent with the kind
    having been removed from the side that had it, and this entry is the only
    remaining record of that. Deleting it to go green erases the evidence;
  * only the other side declares it -> the divergence reversed, not closed.

The middle case is why compare() keeps per-stack kind sets rather than reading
the answer off cfn_only/tf_only alone: a kind absent from both sides appears in
neither list, so on that evidence a deletion and a fix are the same
observation. Measured before the fix -- dropping the CDK access-log buckets
produced "the divergence was fixed -- delete this baseline entry", which is the
tool instructing the one repair that destroys the record.

RUN IT
------
    python3 deploy/tests/iac-equivalence.py

Needs no credentials, no network, no node, and no terraform binary. It reads
committed files only. Exit 0 means every pair matches its baseline exactly.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, TypedDict

# deploy/tests/iac-equivalence.py -> deploy/
DEPLOY = Path(__file__).resolve().parent.parent
CFN_DIR = DEPLOY / "cdk" / "templates"
TF_MODULES = DEPLOY / "terraform" / "modules"

# Top-level HCL blocks sit at column 0 in formatted Terraform, and
# ash-iac-drift.yml's terraform-hygiene job already enforces
# `terraform fmt -check -recursive`. Anchoring at column 0 is what keeps this
# from matching the word "resource" inside an indented heredoc or a nested
# block. If the fmt check is ever removed, this anchor stops being safe.
TF_RESOURCE = re.compile(r'^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE)
TF_MODULE_SOURCE = re.compile(
    r'^module\s+"[^"]+"\s*\{(?:[^{}]|\{[^{}]*\})*?source\s*=\s*"([^"]+)"',
    re.MULTILINE,
)
TF_HEREDOC_START = re.compile(r"<<-?([A-Za-z_][A-Za-z0-9_-]*)[ \t]*\n")


def _scan_string_body(text: str, j: int) -> tuple[int, bool]:
    """Scan a quoted string's body from j to its end or to a template opener.

    Returns (index just past what was consumed, whether a `${` or `%{` template
    sequence was opened). `$${` and `%%{` are HCL's escapes for a literal
    opener and do not open one. An unterminated string runs to end of text.
    """
    n = len(text)
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
        elif c == '"':
            return j + 1, False
        elif text[j : j + 3] in ("$${", "%%{"):
            j += 3
        elif text[j : j + 2] in ("${", "%{"):
            return j + 2, True
        else:
            j += 1
    return n, False


def strip_hcl_comments(text: str) -> str:
    """Remove `#`, `//` and `/* */` comments from HCL, keeping every newline.

    Both regexes above run over the result, so a commented-out `resource` or
    `module` block is not counted. Before this existed, wrapping a resource in
    `/* */` left it counted as present.

    The scan is string-aware because a regex that only looks for comment
    markers is wrong on this tree: IAM resource ARNs such as
    "arn:...:repository/*" contain `/*` inside a quoted string, and treating
    that as the start of a block comment would swallow every resource up to
    the next `*/`. So it tracks quoted strings (with backslash escapes and
    nested `${ }` / `%{ }` template sequences, which can hold quotes of their
    own) and heredocs (`<<EOT` / `<<-EOT` up to a line holding only the
    marker), and only treats a marker as a comment outside both.

    Newlines inside a block comment are kept so that what follows the comment
    stays on its own line and the column-0 anchor still means what it says.
    """
    out: list[str] = []
    i, n = 0, len(text)
    # One entry per open template sequence, holding its unmatched `{` count.
    # Non-empty means we are in code inside a string, not at the top level.
    interp: list[int] = []
    while i < n:
        c = text[i]
        two = text[i : i + 2]
        if two == "/*":
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            out.append("\n" * text.count("\n", i, end))
            i = end
        elif c == "#" or two == "//":
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif two == "<<" and (m := TF_HEREDOC_START.match(text, i)):
            j = m.end()
            while j < n:
                eol = text.find("\n", j)
                eol = n if eol == -1 else eol + 1
                line = text[j:eol]
                j = eol
                if line.strip() == m.group(1):
                    break
            out.append(text[i:j])
            i = j
        elif c == '"' or (interp and c == "}" and interp[-1] == 0):
            # Opening a string, or closing a template sequence and so resuming
            # the string it was opened in.
            if c == "}":
                interp.pop()
            j, opened = _scan_string_body(text, i + 1)
            if opened:
                interp.append(0)
            out.append(text[i:j])
            i = j
        else:
            if interp and c == "{":
                interp[-1] += 1
            elif interp and c == "}":
                interp[-1] -= 1
            out.append(c)
            i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# The canonical vocabulary.
#
# One entry per kind of thing a deployment can provision, naming the
# CloudFormation type(s) and the Terraform type(s) that realize it. This table
# is the whole semantic content of the check and is meant to be read.
# ---------------------------------------------------------------------------
KINDS: dict[str, dict[str, tuple[str, ...]]] = {
    # --- compute and runtimes ---
    "agentcore-runtime": {
        "cfn": ("AWS::BedrockAgentCore::Runtime",),
        "tf": ("aws_bedrockagentcore_agent_runtime",),
    },
    "agentcore-runtime-endpoint": {
        "cfn": (),
        "tf": ("aws_bedrockagentcore_agent_runtime_endpoint",),
    },
    "ecs-cluster": {
        "cfn": ("AWS::ECS::Cluster",),
        "tf": ("aws_ecs_cluster",),
    },
    "ecs-service": {
        "cfn": ("AWS::ECS::Service",),
        "tf": ("aws_ecs_service",),
    },
    "ecs-task-definition": {
        "cfn": ("AWS::ECS::TaskDefinition",),
        "tf": ("aws_ecs_task_definition",),
    },
    "lambda-function": {
        "cfn": ("AWS::Lambda::Function",),
        "tf": ("aws_lambda_function",),
    },
    "lambda-permission": {
        "cfn": ("AWS::Lambda::Permission",),
        "tf": ("aws_lambda_permission",),
    },
    # --- build and delivery ---
    "codebuild-project": {
        "cfn": ("AWS::CodeBuild::Project",),
        "tf": ("aws_codebuild_project",),
    },
    "codepipeline": {
        "cfn": ("AWS::CodePipeline::Pipeline",),
        "tf": ("aws_codepipeline",),
    },
    "ecr-repository": {
        "cfn": ("AWS::ECR::Repository",),
        "tf": ("aws_ecr_repository",),
    },
    "codecommit-approval-rule-template": {
        "cfn": (),
        "tf": ("aws_codecommit_approval_rule_template",),
    },
    "codecommit-approval-rule-template-association": {
        "cfn": (),
        "tf": ("aws_codecommit_approval_rule_template_association",),
    },
    # --- identity ---
    "iam-role": {
        "cfn": ("AWS::IAM::Role",),
        "tf": ("aws_iam_role",),
    },
    # AWS::IAM::Policy is an inline policy attached to a role, which is what
    # aws_iam_role_policy is. CDK emits one per grant() call and the Terraform
    # modules write fewer, larger documents, so these agree on presence and
    # never on count -- see the module docstring on why counts are not
    # compared.
    "iam-role-policy": {
        "cfn": ("AWS::IAM::Policy",),
        "tf": ("aws_iam_role_policy",),
    },
    # --- data and secrets ---
    "kms-key": {
        "cfn": ("AWS::KMS::Key",),
        "tf": ("aws_kms_key",),
    },
    "s3-bucket": {
        "cfn": ("AWS::S3::Bucket",),
        "tf": ("aws_s3_bucket",),
    },
    "s3-bucket-policy": {
        "cfn": ("AWS::S3::BucketPolicy",),
        "tf": ("aws_s3_bucket_policy",),
    },
    "secret": {
        "cfn": ("AWS::SecretsManager::Secret",),
        "tf": ("aws_secretsmanager_secret",),
    },
    "ssm-parameter": {
        "cfn": ("AWS::SSM::Parameter",),
        "tf": ("aws_ssm_parameter",),
    },
    # --- observability and events ---
    "log-group": {
        "cfn": ("AWS::Logs::LogGroup",),
        "tf": ("aws_cloudwatch_log_group",),
    },
    "eventbridge-rule": {
        "cfn": ("AWS::Events::Rule",),
        "tf": ("aws_cloudwatch_event_rule",),
    },
    # --- load balancing ---
    "load-balancer": {
        "cfn": ("AWS::ElasticLoadBalancingV2::LoadBalancer",),
        "tf": ("aws_lb",),
    },
    "lb-listener": {
        "cfn": ("AWS::ElasticLoadBalancingV2::Listener",),
        "tf": ("aws_lb_listener",),
    },
    "lb-target-group": {
        "cfn": ("AWS::ElasticLoadBalancingV2::TargetGroup",),
        "tf": ("aws_lb_target_group",),
    },
    # --- network ---
    "security-group": {
        "cfn": ("AWS::EC2::SecurityGroup",),
        "tf": ("aws_security_group",),
    },
    # The Terraform modules use the modern single-rule resources rather than
    # inline ingress/egress blocks, which is the shape that maps onto
    # CloudFormation's separate SecurityGroupIngress/Egress types.
    "security-group-ingress-rule": {
        "cfn": ("AWS::EC2::SecurityGroupIngress",),
        "tf": ("aws_vpc_security_group_ingress_rule",),
    },
    "security-group-egress-rule": {
        "cfn": ("AWS::EC2::SecurityGroupEgress",),
        "tf": ("aws_vpc_security_group_egress_rule",),
    },
    "vpc": {"cfn": ("AWS::EC2::VPC",), "tf": ("aws_vpc",)},
    "subnet": {"cfn": ("AWS::EC2::Subnet",), "tf": ("aws_subnet",)},
    "route-table": {"cfn": ("AWS::EC2::RouteTable",), "tf": ("aws_route_table",)},
    "route": {"cfn": ("AWS::EC2::Route",), "tf": ("aws_route",)},
    "subnet-route-table-association": {
        "cfn": ("AWS::EC2::SubnetRouteTableAssociation",),
        "tf": ("aws_route_table_association",),
    },
    "internet-gateway": {
        "cfn": ("AWS::EC2::InternetGateway",),
        "tf": ("aws_internet_gateway",),
    },
    # CloudFormation attaches a gateway to a VPC with a distinct resource;
    # Terraform's aws_internet_gateway takes vpc_id directly, so there is no
    # separate attachment resource to find. Kept as its own kind rather than
    # folded into internet-gateway so the asymmetry is visible in the report
    # instead of hidden in a mapping.
    "vpc-gateway-attachment": {
        "cfn": ("AWS::EC2::VPCGatewayAttachment",),
        "tf": (),
    },
    "nat-gateway": {"cfn": ("AWS::EC2::NatGateway",), "tf": ("aws_nat_gateway",)},
    "elastic-ip": {"cfn": ("AWS::EC2::EIP",), "tf": ("aws_eip",)},
    "vpc-flow-log": {"cfn": ("AWS::EC2::FlowLog",), "tf": ("aws_flow_log",)},
}


# ---------------------------------------------------------------------------
# Types excluded from the census, by name, each with the reason.
#
# Two reasons appear here and they are different:
#
#   PROPERTY-EQUIVALENT -- the other representation expresses the same thing as
#     a property of a resource that IS compared. Including it would make one
#     side look like it provisions more resources than the other when both
#     describe the same deployment.
#   NO COUNTERPART CONCEPT -- the thing exists only in one tool's model.
#
# Excluding a property-equivalent has a real cost: this check cannot see it
# disappear. Limitation 6 in the module docstring says so.
# ---------------------------------------------------------------------------
CFN_EXCLUDED: dict[str, str] = {
    "Custom::AshImageBootstrap": (
        "NO COUNTERPART CONCEPT. A CDK custom resource that CDK invokes during "
        "deployment to start the ASH image build, so the stack does not finish "
        "with a service pointing at an empty repository. Terraform has no "
        "deploy-time-action resource; deploy/terraform/README.md documents the "
        "equivalent as a manual `aws codebuild start-build` after apply, "
        "surfaced through each module's bootstrap_command output. Its provider "
        "Lambda is excluded too -- see provider_functions() for why that is "
        "resolved structurally rather than listed here by name."
    ),
}

TF_EXCLUDED: dict[str, str] = {
    "aws_cloudwatch_event_target": (
        "PROPERTY-EQUIVALENT. CloudFormation carries targets in the Targets "
        "property of AWS::Events::Rule. The rule itself is compared, under "
        "eventbridge-rule."
    ),
    "aws_ecr_lifecycle_policy": (
        "PROPERTY-EQUIVALENT. CloudFormation carries this in the "
        "LifecyclePolicy property of AWS::ECR::Repository, which is compared "
        "under ecr-repository."
    ),
    "aws_iam_role_policy_attachment": (
        "PROPERTY-EQUIVALENT. Attaches an AWS-managed policy to a role. "
        "CloudFormation uses the ManagedPolicyArns property of AWS::IAM::Role, "
        "which is compared under iam-role."
    ),
    "aws_s3_bucket_lifecycle_configuration": (
        "PROPERTY-EQUIVALENT. CloudFormation uses the LifecycleConfiguration "
        "property of AWS::S3::Bucket, compared under s3-bucket."
    ),
    "aws_s3_bucket_public_access_block": (
        "PROPERTY-EQUIVALENT. CloudFormation uses the "
        "PublicAccessBlockConfiguration property of AWS::S3::Bucket, compared "
        "under s3-bucket."
    ),
    "aws_s3_bucket_server_side_encryption_configuration": (
        "PROPERTY-EQUIVALENT. CloudFormation uses the BucketEncryption "
        "property of AWS::S3::Bucket, compared under s3-bucket. Excluding it "
        "means this check cannot see bucket encryption removed -- limitation 6."
    ),
    "aws_s3_bucket_versioning": (
        "PROPERTY-EQUIVALENT. CloudFormation uses the VersioningConfiguration "
        "property of AWS::S3::Bucket, compared under s3-bucket."
    ),
    "aws_secretsmanager_secret_version": (
        "PROPERTY-EQUIVALENT. CloudFormation seeds the value through the "
        "SecretString property of AWS::SecretsManager::Secret. The secret is "
        "compared under secret."
    ),
}


# ---------------------------------------------------------------------------
# The pairs.
#
# A CloudFormation stack is self-contained -- it has to deploy from a single
# template with no build step ahead of it -- so it carries
# the image build inside it. Terraform composes instead: deploy/terraform's
# README states that ash-image-pipeline is "the shared image build every one of
# them depends on" and that "Every other module depends on this one." So a
# stack's Terraform counterpart is the UNION of the target module and the
# image-pipeline module, not the target module alone.
#
# Measured, not assumed: every non-image module's examples/basic/main.tf
# composes ../../../ash-image-pipeline. check_composition() below re-derives
# that from the examples on every run and fails if this table and the examples
# disagree, so the table cannot go stale silently.
#
# `external` names registry modules the example pulls in whose contents this
# check does not read. It is informational -- the kinds those modules provide
# are itemized in BASELINE, so they are visible as unverified rather than
# assumed present.
# ---------------------------------------------------------------------------
class Pair(TypedDict):
    """One CloudFormation stack and the Terraform it is compared against."""

    stack: str
    modules: tuple[str, ...]
    example: str
    external: tuple[str, ...]


PAIRS: tuple[Pair, ...] = (
    {
        "stack": "AshImagePipeline",
        "modules": ("ash-image-pipeline",),
        "example": "ash-image-pipeline",
        "external": (),
    },
    {
        "stack": "AshAgentCore",
        "modules": ("ash-image-pipeline", "agentcore"),
        "example": "agentcore",
        "external": (),
    },
    {
        "stack": "AshCodeCommitGate",
        "modules": ("ash-image-pipeline", "codecommit-gate"),
        "example": "codecommit-gate",
        "external": (),
    },
    {
        "stack": "AshDistributedPipeline",
        "modules": ("ash-image-pipeline", "codepipeline-executor"),
        "example": "codepipeline-executor",
        "external": (),
    },
    {
        "stack": "AshFargate",
        "modules": ("ash-image-pipeline", "fargate"),
        "example": "fargate",
        "external": ("aws-ia/vpc/aws",),
    },
)


# ---------------------------------------------------------------------------
# Committed templates that have NO Terraform counterpart, named with the reason.
#
# A stack listed here is not census-compared, because there is nothing to
# compare it against. It is still READ: its resource types are checked against
# the vocabulary, so an unclassified type in it fails exactly as it would in a
# paired stack. "No counterpart" removes the census, not the type check.
#
# WHY THIS TABLE EXISTS AT ALL
# ----------------------------
# Because the alternative is an absence, and an absence is what this check got
# wrong. PAIRS used to be the only list of stacks, and load_cfn() was only ever
# called for names in it -- so a committed template absent from PAIRS was never
# opened, and the run still printed "no unrecorded divergence" and exited 0.
#
# Measured on a six-template tree: exit 0, the sixth stack's name absent from
# the output, and its AWS::EKS::* resource types -- which are in no KINDS entry
# -- never reported as unclassified. The file's stated teeth ("an unmapped
# resource type is a FAILURE, not a skipped row") could not engage, because the
# gap sat one level above them: an unmapped STACK, not an unmapped type.
#
# check_stack_coverage() closes that by globbing CFN_DIR and requiring every
# template to be named in PAIRS or here. The same principle, applied one level
# up: a stack nobody has classified is refused, not skipped.
#
# deploy/cdk/scripts/render_quick-create-links equivalents in this repo learned
# the same lesson -- discover by glob, never by a hardcoded array, because the
# array is what goes stale.
# ---------------------------------------------------------------------------
STACKS_WITHOUT_TERRAFORM: dict[str, str] = {
    # Empty on this ref: all five committed templates have a Terraform
    # counterpart. An entry looks like:
    #
    #   "AshEksOperator": (
    #       "No Terraform module implements this target. The deploy/terraform "
    #       "tree ships four targets plus the shared image build, and an EKS "
    #       "operator is not among them, so there is nothing to compare. "
    #       "Adopters of this target have only the CloudFormation path."
    #   ),
    #
    # Write what an adopter loses, not just that the module is missing -- the
    # point of the entry is that somebody decided this asymmetry is acceptable.
}


# ---------------------------------------------------------------------------
# BASELINE: every divergence that exists today, itemized.
#
# Keyed (stack, direction, kind) -> reason.
#   "cfn-only" -- CloudFormation provisions this kind and Terraform does not.
#   "tf-only"  -- Terraform provisions it and CloudFormation does not.
#
# An unlisted divergence fails. A listed divergence that has been fixed fails
# as stale. Adding an entry here is a deliberate, reviewable act that records a
# known difference between the two representations; it is not a way to silence
# the check.
# ---------------------------------------------------------------------------
_CMK = (
    "The CDK stacks each create a customer-managed KMS key "
    "(`EncryptionKey`, 'Encrypts ASH CodeBuild project output for this "
    "stack'). The Terraform modules create no key: they take an OPTIONAL "
    "kms_key_arn / ecr_kms_key_arn input and fall back to AES256 or the "
    "AWS-managed key when it is null. So the two representations give an "
    "adopter a different default encryption posture -- CloudFormation "
    "always a CMK, Terraform only when one is supplied. This is the most "
    "consequential divergence on this list and it is a real difference, "
    "not a modelling artifact. Recorded rather than fixed because which "
    "default is right is the deploy lane's call: a CMK carries a recurring "
    "per-key cost, which is the reason the Terraform modules give for not "
    "imposing one (see the CKV_AWS_158 skip note in "
    "modules/codepipeline-executor/main.tf)."
)

_ACCESS_LOGS = (
    "The CDK app provisions a pair of access-log buckets (`AccessLogs` and "
    "`AccessLogsArchive`) from a shared construct. The Terraform fargate "
    "module provisions none, and says so in its own words: the aws_lb "
    "resource carries `#checkov:skip=CKV_AWS_91:Needs a receiving S3 bucket "
    "and ELB-account bucket policy that this module has no input` for, and "
    "names an access_logs_bucket input as a follow-up. So the Terraform "
    "adopter gets no load-balancer access logging. A real gap on the "
    "Terraform side, acknowledged there, not a shape difference."
)

_BUCKET_POLICY = (
    "CDK attaches a generated AWS::S3::BucketPolicy to each bucket it "
    "creates (SSL enforcement, and the regional ELB-account grant that "
    "access logging requires). The Terraform modules create buckets with no "
    "aws_s3_bucket_policy, so those grants are absent -- the same gap "
    "_ACCESS_LOGS describes, seen from the policy side. Distinct from the "
    "property-equivalent exclusions in TF_EXCLUDED: a bucket policy is its "
    "own resource in BOTH tools, so this is a genuine divergence rather than "
    "a modelling mismatch."
)

_VPC_FROM_REGISTRY = (
    "AshFargate.template.json builds its own VPC; the Terraform fargate "
    "module takes subnet and VPC ids as inputs and its basic example "
    "sources the network from the `aws-ia/vpc/aws` registry module. This "
    "check does not fetch or parse registry modules, so this kind is "
    "recorded as UNVERIFIED rather than confirmed present. That is "
    "limitation 5 in the module docstring: a change inside aws-ia/vpc is "
    "invisible here."
)

BASELINE: dict[tuple[str, str, str], str] = {
    # --- the customer-managed key, on every pair ---
    ("AshImagePipeline", "cfn-only", "kms-key"): _CMK,
    ("AshAgentCore", "cfn-only", "kms-key"): _CMK,
    ("AshCodeCommitGate", "cfn-only", "kms-key"): _CMK,
    ("AshDistributedPipeline", "cfn-only", "kms-key"): _CMK,
    ("AshFargate", "cfn-only", "kms-key"): _CMK,
    # --- where the base-config parameter lives ---
    ("AshImagePipeline", "tf-only", "ssm-parameter"): (
        "A PLACEMENT difference, not a missing resource. CDK creates the "
        "base-config SSM parameter inside each of the four TARGET stacks "
        "(`ConfigBaseConfig`) and not in AshImagePipeline. Terraform creates it "
        "once in ash-image-pipeline and the targets consume it by name and arn "
        "through base_config_ssm_parameter_name / _arn, which "
        "deploy/terraform/README.md documents as the indirect form of "
        "AshBaseConfigYaml. Because every other pair is compared against the "
        "UNION of the target module and ash-image-pipeline, the parameter "
        "reconciles on those four and only shows up here, on the pair that is "
        "the image build alone."
    ),
    # --- AgentCore's DEFAULT endpoint ---
    ("AshAgentCore", "tf-only", "agentcore-runtime-endpoint"): (
        "AWS::BedrockAgentCore::Runtime creates its DEFAULT endpoint as part of "
        "the runtime and CloudFormation exposes no separate resource type for "
        "it. The AWS provider does, so the Terraform module manages it "
        'explicitly -- `name = coalesce(var.endpoint_name, "DEFAULT")` behind '
        "`count = var.create_endpoint ? 1 : 0`. Same endpoint either way; only "
        "one of the two tools models it as a resource."
    ),
    # --- the MCP auth secret on targets that cannot use it ---
    ("AshCodeCommitGate", "cfn-only", "secret"): (
        "CDK's shared Config construct creates the McpAuthHeaderValue secret "
        "(`ConfigMcpAuthHeaderSecret`) in all four target stacks, including this "
        "one -- which runs ASH as a one-shot Lambda and serves no MCP endpoint. "
        "Measured: the secret's only reference in the template is "
        "ScanFunctionRoleDefaultPolicy, an IAM grant to READ it. It reaches no "
        "environment variable and no output, so nothing consumes its value. "
        "deploy/terraform/README.md's variable contract lists McpAuthHeaderValue "
        "as applying to agentcore and fargate only, and the Terraform modules "
        "follow that. The divergence is CDK provisioning -- and granting read on "
        "-- a secret this target cannot use, so the Terraform side is the one "
        "that matches the documented contract."
    ),
    ("AshDistributedPipeline", "cfn-only", "secret"): (
        "Same as AshCodeCommitGate, and wider: the secret is referenced by five "
        "IAM policies (each shard project's role plus the merge project's), all "
        "of them grants to read it, and by nothing that consumes its value. This "
        "target runs sharded CodeBuild jobs and serves no MCP endpoint."
    ),
    # --- a CloudFormation capability gap ---
    ("AshCodeCommitGate", "tf-only", "codecommit-approval-rule-template"): (
        "A platform gap, stated in the CDK source itself: "
        "deploy/cdk/lib/ash-codecommit-gate-stack.ts records that "
        "'CloudFormation has no resource type for a CodeCommit approval rule "
        "template, so the stack cannot create one'. The CDK stack instead "
        "exposes ScanFunctionRoleArn as an output for an operator to wire into "
        "an approval rule by hand. Terraform can create it, and does, behind "
        "`count = var.create_approval_rule_template ? 1 : 0`. Not drift: the two "
        "tools have different capabilities here."
    ),
    (
        "AshCodeCommitGate",
        "tf-only",
        "codecommit-approval-rule-template-association",
    ): (
        "The association that attaches the template above to the caller's "
        "repository. Same CloudFormation capability gap, and opt-in for the same "
        "reason -- it changes settings on a repository the module does not own."
    ),
    # --- access logging and bucket policies ---
    ("AshFargate", "cfn-only", "s3-bucket"): _ACCESS_LOGS,
    ("AshFargate", "cfn-only", "s3-bucket-policy"): _BUCKET_POLICY,
    ("AshDistributedPipeline", "cfn-only", "s3-bucket-policy"): _BUCKET_POLICY,
    # --- the network, which Terraform sources from a registry module ---
    ("AshFargate", "cfn-only", "vpc"): _VPC_FROM_REGISTRY,
    ("AshFargate", "cfn-only", "subnet"): _VPC_FROM_REGISTRY,
    ("AshFargate", "cfn-only", "route-table"): _VPC_FROM_REGISTRY,
    ("AshFargate", "cfn-only", "route"): _VPC_FROM_REGISTRY,
    ("AshFargate", "cfn-only", "subnet-route-table-association"): _VPC_FROM_REGISTRY,
    ("AshFargate", "cfn-only", "internet-gateway"): _VPC_FROM_REGISTRY,
    ("AshFargate", "cfn-only", "vpc-gateway-attachment"): _VPC_FROM_REGISTRY,
    ("AshFargate", "cfn-only", "nat-gateway"): _VPC_FROM_REGISTRY,
    ("AshFargate", "cfn-only", "elastic-ip"): _VPC_FROM_REGISTRY,
    ("AshFargate", "cfn-only", "vpc-flow-log"): _VPC_FROM_REGISTRY,
}


def validate_tables(errors: list[str]) -> None:
    """Integrity checks on KINDS and the two EXCLUDED tables.

    The tables above are the whole semantic content of this check, and three
    ways of getting them wrong produce a check that still exits 0:

      * a type mapped to two different kinds -- whichever wins is arbitrary, so
        the census silently depends on dict ordering;
      * a type in both KINDS and an EXCLUDED table -- the exclusion wins and the
        mapping is dead, so a reviewer reading KINDS believes something is
        compared that is not;
      * a kind with no types on either side -- a leftover that can never match
        anything and misleads anyone counting the vocabulary.

    None of these is reachable from the census itself, which is why they are
    asserted directly rather than left to be noticed.
    """
    for side, excluded in (("cfn", CFN_EXCLUDED), ("tf", TF_EXCLUDED)):
        owner: dict[str, str] = {}
        for kind, mapping in KINDS.items():
            for rtype in mapping[side]:
                if rtype in owner:
                    errors.append(
                        f"table error: {side} type '{rtype}' is mapped to both "
                        f"'{owner[rtype]}' and '{kind}'. A type must belong to "
                        "exactly one kind or the census depends on iteration "
                        "order."
                    )
                owner[rtype] = kind
                if rtype in excluded:
                    errors.append(
                        f"table error: {side} type '{rtype}' is both mapped to "
                        f"kind '{kind}' and listed in "
                        f"{'CFN' if side == 'cfn' else 'TF'}_EXCLUDED. The "
                        "exclusion wins, so the mapping is dead code that reads "
                        "as coverage. Remove one."
                    )

    for kind, mapping in KINDS.items():
        if not mapping["cfn"] and not mapping["tf"]:
            errors.append(
                f"table error: kind '{kind}' names no type on either side, so "
                "it can never match anything. Remove it or fill it in."
            )

    # A BASELINE key that can never match is worse than useless: it is reported
    # as stale on every run, so the real stale entries get lost in the noise and
    # the habit becomes deleting whatever the gate complains about.
    paired = {str(p["stack"]) for p in PAIRS}
    for stack, direction, kind in sorted(BASELINE):
        if stack not in paired:
            errors.append(
                f"table error: BASELINE names stack '{stack}', which is not in "
                "PAIRS. Only paired stacks get a census, so this entry can never "
                "match and will be reported stale on every run. Remove it, or "
                "add the stack to PAIRS."
            )
        if direction not in ("cfn-only", "tf-only"):
            errors.append(
                f"table error: BASELINE entry ({stack}, {direction}, {kind}) has "
                "an unknown direction. Use 'cfn-only' or 'tf-only'."
            )
        if kind not in KINDS:
            errors.append(
                f"table error: BASELINE entry ({stack}, {direction}, {kind}) "
                "names a kind that is not in KINDS, so it can never match. Fix "
                "the spelling or add the kind."
            )

    for stack in sorted(set(STACKS_WITHOUT_TERRAFORM) & paired):
        errors.append(
            f"table error: '{stack}' is in both PAIRS and "
            "STACKS_WITHOUT_TERRAFORM. It cannot both have and not have a "
            "Terraform counterpart; the census would run and the stack would "
            "also be reported as uncompared. Remove one."
        )


def provider_functions(resources: dict[str, Any]) -> set[str]:
    """Logical ids of Lambdas that exist only to back a custom resource.

    A CDK custom resource is implemented as a Lambda the CloudFormation service
    calls during deployment. That Lambda is CDK's implementation mechanism, not
    part of the deployment an adopter gets, and Terraform has no analogue -- so
    counting it makes every stack carrying a custom resource look like it has a
    Lambda the Terraform module is missing. Measured: the only
    AWS::Lambda::Function in AshAgentCore and AshFargate is
    `ImageBootstrapStarter`, the provider for `Custom::AshImageBootstrap`.

    Resolved structurally, from the ServiceToken each custom resource declares,
    rather than by listing logical ids or matching a name pattern. Two reasons.
    A CDK logical id carries a generated hash suffix that moves when the
    construct path changes, so a literal list would rot. And a name pattern
    would also swallow a REAL Lambda that happened to match -- whereas this
    only ever removes a function some custom resource actually points at.

    Fails open on purpose: a ServiceToken that is not a plain Fn::GetAtt (a Ref
    to a parameter, an Fn::ImportValue) names no in-template function, so
    nothing is excluded. That direction is safe -- an unexcluded Lambda shows up
    as a divergence and gets reported, which is the conservative outcome.
    """
    providers: set[str] = set()
    for body in resources.values():
        rtype = (body or {}).get("Type") or ""
        if not (
            rtype.startswith("Custom::")
            or rtype == "AWS::CloudFormation::CustomResource"
        ):
            continue
        token = (body.get("Properties") or {}).get("ServiceToken")
        if isinstance(token, dict):
            target = token.get("Fn::GetAtt")
            if isinstance(target, list) and target and isinstance(target[0], str):
                providers.add(target[0])
    return {
        logical_id
        for logical_id in providers
        if (resources.get(logical_id) or {}).get("Type") == "AWS::Lambda::Function"
    }


def load_cfn(stack: str) -> dict[str, int]:
    """Resource types in a committed template, with counts for the report."""
    path = CFN_DIR / f"{stack}.template.json"
    if not path.exists():
        raise FileNotFoundError(
            f"{path} is missing. PAIRS names stack '{stack}' but its template is "
            "not committed, so this pair could not be compared."
        )
    try:
        doc = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not parseable JSON: {exc}") from exc

    resources = doc.get("Resources")
    if not isinstance(resources, dict) or not resources:
        raise ValueError(
            f"{path} declares no Resources. Nothing would be compared for this "
            "pair, so this is a failure rather than an empty match."
        )

    providers = provider_functions(resources)
    counts: dict[str, int] = {}
    for logical_id, body in resources.items():
        rtype = (body or {}).get("Type")
        if not isinstance(rtype, str) or not rtype:
            raise ValueError(
                f"{path}: resource '{logical_id}' has no Type. Refusing to "
                "compare a template this check cannot read completely."
            )
        if logical_id in providers:
            continue
        counts[rtype] = counts.get(rtype, 0) + 1
    return counts


def load_tf(module: str) -> dict[str, int]:
    """Resource types in a module's own root .tf files.

    Examples are excluded on purpose: an example is a CALLER of the module and
    composes other modules, so counting its resources would attribute a
    sibling module's resources to this one and double-count in the union.
    """
    root = TF_MODULES / module
    if not root.is_dir():
        raise FileNotFoundError(
            f"{root} is missing. PAIRS names Terraform module '{module}' but "
            "that directory does not exist, so this pair could not be compared."
        )
    files = sorted(root.glob("*.tf"))
    if not files:
        raise ValueError(
            f"{root} holds no root .tf file. Nothing would be compared for "
            "this module, so this is a failure rather than an empty match."
        )

    counts: dict[str, int] = {}
    found_any = False
    for path in files:
        for rtype, _name in TF_RESOURCE.findall(strip_hcl_comments(path.read_text())):
            counts[rtype] = counts.get(rtype, 0) + 1
            found_any = True
    if not found_any:
        raise ValueError(
            f"{root} declares no `resource` block in any root .tf file. Either "
            "the module is empty or this check's parser stopped matching; "
            "both are failures rather than an empty match."
        )
    return counts


def check_stack_coverage(errors: list[str]) -> list[str]:
    """Every committed template must be classified. Returns the unpaired ones.

    Discovery is a glob over CFN_DIR, deliberately, because the alternative --
    trusting PAIRS to be the list of stacks -- is the defect this function was
    added to fix. A hardcoded list cannot report the thing it is missing.

    Three failures, all of them fail-closed:

      * a template named in neither PAIRS nor STACKS_WITHOUT_TERRAFORM. It was
        never read, so nothing checked it, and the run would otherwise exit 0.
      * a name in STACKS_WITHOUT_TERRAFORM with no template. A stale entry, and
        it would suppress the coverage error for a stack that no longer exists.
      * no templates at all, which would make every check below vacuous.

    A PAIRS entry with no template is not checked here: load_cfn raises for it
    with a message naming the pair, which is more specific than this one.
    """
    present = sorted(
        p.name[: -len(".template.json")] for p in CFN_DIR.glob("*.template.json")
    )
    if not present:
        errors.append(
            f"no *.template.json under {CFN_DIR}. Nothing was compared, so this "
            "check proved nothing. If the CDK tree has not landed, the workflow's "
            "discover job should have skipped this check rather than running it."
        )
        return []

    paired = {str(p["stack"]) for p in PAIRS}
    declared = set(STACKS_WITHOUT_TERRAFORM)

    for stack in present:
        if stack in paired or stack in declared:
            continue
        errors.append(
            f"{stack}.template.json is committed but classified nowhere. It was "
            "NOT read, so nothing compared it and nothing checked its resource "
            "types against the vocabulary -- this run would otherwise have "
            "reported no divergence while never opening the file. Either add it "
            "to PAIRS with the Terraform module(s) that implement it, or -- if "
            "no Terraform module does -- to STACKS_WITHOUT_TERRAFORM with the "
            "reason and what an adopter of that target loses. A stack with no "
            "counterpart is a named, reasoned entry, not an absence."
        )

    for stack in sorted(declared - set(present)):
        errors.append(
            f"STACKS_WITHOUT_TERRAFORM names '{stack}', but "
            f"{stack}.template.json is not committed. Remove the entry: while it "
            "is there it would suppress the coverage error for a stack that does "
            "not exist."
        )

    return [s for s in present if s in declared]


def check_composition(errors: list[str]) -> None:
    """Re-derive each pair's module set from its example and compare to PAIRS.

    A positive control on the pair table itself. If an example stops composing
    the image build, or starts composing something new, PAIRS is now wrong and
    every census built on it is measuring the wrong union.
    """
    for pair in PAIRS:
        example = pair["example"]
        stack = pair["stack"]
        main = TF_MODULES / str(example) / "examples" / "basic" / "main.tf"
        if not main.exists():
            errors.append(
                f"{stack}: {main} is missing, so the module set in PAIRS could "
                "not be verified against the example that demonstrates it."
            )
            continue

        sources = TF_MODULE_SOURCE.findall(strip_hcl_comments(main.read_text()))
        if not sources:
            errors.append(
                f"{stack}: no `module` block with a source was found in {main}. "
                "PAIRS could not be verified, and a composition this check "
                "cannot read is not a composition it may assume."
            )
            continue

        local: set[str] = set()
        external: set[str] = set()
        for src in sources:
            if not src.startswith((".", "/")):
                # A registry address such as "aws-ia/vpc/aws".
                external.add(src)
            elif src == "../..":
                # The module the example demonstrates, reached from
                # modules/<name>/examples/basic/.
                local.add(str(example))
            else:
                # A sibling module, e.g. "../../../ash-image-pipeline".
                local.add(Path(src).name)

        declared = set(pair["modules"])
        if local != declared:
            errors.append(
                f"{stack}: PAIRS says its Terraform counterpart is "
                f"{sorted(declared)}, but {main} composes {sorted(local)}. The "
                "pair table and the example disagree, so the census for this "
                "pair is built on the wrong module set. Update whichever is "
                "wrong."
            )
        declared_ext = set(pair["external"])
        if external != declared_ext:
            errors.append(
                f"{stack}: PAIRS declares external modules {sorted(declared_ext)} "
                f"but {main} composes {sorted(external)}. The kinds an external "
                "module provides are baselined as unverified, so this list "
                "changing means the baseline no longer covers the right set."
            )


def canonicalize(
    types: dict[str, int],
    side: str,
    where: str,
    unmapped: dict[tuple[str, str], set[str]],
) -> dict[str, int]:
    """Map raw resource types onto canonical kinds.

    An unmapped type is an error. This is the check's teeth: a resource kind
    nobody has classified is a divergence risk by definition, because nothing
    here knows whether the other side has a counterpart.

    Unmapped types are ACCUMULATED rather than reported here, and deduplicated
    by (side, type) in main(). ash-image-pipeline is part of all five pairs, so
    one unclassified resource in it would otherwise produce five identical
    errors and bury the one line a reader needs.
    """
    excluded = CFN_EXCLUDED if side == "cfn" else TF_EXCLUDED
    lookup = {t: kind for kind, m in KINDS.items() for t in m[side]}

    kinds: dict[str, int] = {}
    for rtype, count in sorted(types.items()):
        if rtype in excluded:
            continue
        kind = lookup.get(rtype)
        if kind is None:
            unmapped.setdefault((side, rtype), set()).add(where)
            continue
        kinds[kind] = kinds.get(kind, 0) + count
    return kinds


def compare(errors: list[str], unmapped: dict[tuple[str, str], set[str]]) -> list[str]:
    """Run the census over every pair. Returns report lines."""
    report: list[str] = []
    seen_baseline: set[tuple[str, str, str]] = set()
    # Per-stack canonical kind sets, kept so the stale-baseline pass below can
    # tell WHY an entry stopped matching. Without them, "both sides declare it
    # now" and "neither side declares it any more" are the same observation --
    # the entry is simply not in cfn_only or tf_only -- and the second is a
    # regression being reported as a fix.
    kinds_seen: dict[str, tuple[set[str], set[str]]] = {}

    for pair in PAIRS:
        stack = str(pair["stack"])
        modules = pair["modules"]

        cfn_kinds = canonicalize(
            load_cfn(stack), "cfn", f"{stack}.template.json", unmapped
        )

        # Canonicalized per module and then merged, rather than over the union.
        # The merge is identical either way -- canonicalize is a per-type map --
        # but this attributes an unclassified type to the MODULE that declares
        # it instead of to the pair, and ash-image-pipeline appears in all five
        # pairs.
        tf_kinds: dict[str, int] = {}
        for module in modules:
            per_module = canonicalize(
                load_tf(str(module)), "tf", f"modules/{module}", unmapped
            )
            for kind, count in per_module.items():
                tf_kinds[kind] = tf_kinds.get(kind, 0) + count

        kinds_seen[stack] = (set(cfn_kinds), set(tf_kinds))
        cfn_only = sorted(set(cfn_kinds) - set(tf_kinds))
        tf_only = sorted(set(tf_kinds) - set(cfn_kinds))
        shared = sorted(set(cfn_kinds) & set(tf_kinds))

        report.append("")
        report.append(f"=== {stack}  <->  {' + '.join(map(str, modules))}")
        report.append(
            f"    {len(shared)} kind(s) on both sides, "
            f"{len(cfn_only)} CloudFormation-only, {len(tf_only)} Terraform-only"
        )

        for direction, kinds in (("cfn-only", cfn_only), ("tf-only", tf_only)):
            for kind in kinds:
                key = (stack, direction, kind)
                reason = BASELINE.get(key)
                if reason is None:
                    side = (
                        "CloudFormation provisions it and Terraform does not"
                        if direction == "cfn-only"
                        else "Terraform provisions it and CloudFormation does not"
                    )
                    errors.append(
                        f"{stack}: '{kind}' diverges -- {side}. This is not in "
                        "BASELINE, so it is either new drift (fix the "
                        "representation that is missing it) or a known "
                        "difference nobody has recorded (add it to BASELINE "
                        "with the reason it exists)."
                    )
                    report.append(f"      {direction:<9} {kind}  <-- UNBASELINED")
                else:
                    seen_baseline.add(key)
                    report.append(f"      {direction:<9} {kind}  (baselined)")

    # A baseline entry that no longer matches is reported -- but WHY it stopped
    # matching decides what the maintainer should do, and the three reasons
    # call for opposite actions.
    #
    # The message here used to say "the divergence was fixed -- delete this
    # baseline entry" in every case. On a DELETION that inverted the diagnosis
    # and then instructed the harmful repair: drop the CDK access-log buckets
    # and the gate reported the AshFargate s3-bucket divergence as fixed, so a
    # maintainer following the instruction literally would delete the entry, go
    # green, and erase the record that CDK ever provisioned those buckets. That
    # is the baseline becoming the wildcard it exists to avoid, reached by
    # following the tool's own advice.
    for key, reason in sorted(BASELINE.items()):
        if key in seen_baseline:
            continue
        stack, direction, kind = key
        cfn_seen, tf_seen = kinds_seen.get(stack, (set(), set()))
        in_cfn = kind in cfn_seen
        in_tf = kind in tf_seen
        carried = f" Reason it carried: {' '.join(reason.split())[:160]}"

        if in_cfn and in_tf:
            # Converged: the side that was missing it now has it.
            errors.append(
                f"{stack}: BASELINE records a '{direction}' divergence for "
                f"'{kind}', but BOTH representations now declare it. The "
                "divergence was fixed -- delete this baseline entry." + carried
            )
        elif not in_cfn and not in_tf:
            # The dangerous case. Nothing was fixed; the kind left both sides.
            errors.append(
                f"{stack}: BASELINE records a '{direction}' divergence for "
                f"'{kind}', but NEITHER representation declares it any more. "
                "This is not a fix -- it is consistent with the kind having been "
                "REMOVED from the side that had it, which is a regression this "
                "entry is the only remaining record of. Do NOT delete the entry "
                "to make this green. Establish which side dropped it: if the "
                "removal was intended, remove the entry in the same change that "
                "records why; if it was not, restore the resource." + carried
            )
        else:
            # Present on exactly one side -- the other one. The divergence did
            # not close, it reversed, and the opposite-direction entry is
            # separately reported as unbaselined above.
            now = "CloudFormation" if in_cfn else "Terraform"
            errors.append(
                f"{stack}: BASELINE records a '{direction}' divergence for "
                f"'{kind}', but the divergence REVERSED -- only {now} declares "
                "it now. Nothing was fixed and the two sides still disagree. "
                "Replace this entry with one for the new direction, stating why "
                "the implementations swapped." + carried
            )

    return report


def main() -> int:
    errors: list[str] = []
    unmapped: dict[tuple[str, str], set[str]] = {}

    if not CFN_DIR.is_dir():
        print(f"::error::{CFN_DIR} is missing; nothing to compare.")
        return 1
    if not TF_MODULES.is_dir():
        print(f"::error::{TF_MODULES} is missing; nothing to compare.")
        return 1

    validate_tables(errors)
    uncompared = check_stack_coverage(errors)
    check_composition(errors)

    try:
        report = compare(errors, unmapped)
        # A stack with no Terraform counterpart gets no census, but it is still
        # READ: its types go through the vocabulary so an unclassified one fails
        # here exactly as it would in a paired stack. Skipping the file outright
        # is what let a sixth template's AWS::EKS::* types go unreported.
        for stack in uncompared:
            kinds = canonicalize(
                load_cfn(stack), "cfn", f"{stack}.template.json", unmapped
            )
            report.append("")
            report.append(f"=== {stack}  <->  (no Terraform counterpart)")
            report.append(
                f"    {len(kinds)} kind(s), NOT census-compared by declaration. "
                "Resource types were still checked against the vocabulary."
            )
            report.append(
                f"      reason: {' '.join(STACKS_WITHOUT_TERRAFORM[stack].split())[:200]}"
            )
    except (FileNotFoundError, ValueError) as exc:
        # The accumulated errors are printed too, and BEFORE the exception.
        # A tree with no templates at all raises here on the first pair, and
        # "AshImagePipeline.template.json is missing" is the symptom while
        # "the directory holds no template" is the diagnosis -- reporting only
        # the exception would discard the more useful of the two. Measured:
        # deleting every template made this path report a missing file for one
        # pair and swallow the coverage error entirely.
        for err in errors:
            print(f"::error::{err}")
        print(f"::error::{exc}")
        return 1

    # One error per unclassified type, listing everywhere it was seen, rather
    # than one per (pair, type). See canonicalize().
    for (side, rtype), places in sorted(unmapped.items()):
        table = "CFN_EXCLUDED" if side == "cfn" else "TF_EXCLUDED"
        errors.append(
            f"resource type '{rtype}' is not in this check's vocabulary. Seen "
            f"in: {', '.join(sorted(places))}. Add it to KINDS in "
            f"{Path(__file__).name} alongside its counterpart on the other "
            f"side, or -- if it genuinely has no counterpart -- to {table} with "
            "the reason. An unclassified type is refused rather than skipped: "
            "skipping it would let a resource be added to one representation "
            "and never the other without this check noticing."
        )

    print("CloudFormation <-> Terraform resource-kind census")
    print(
        f"vocabulary: {len(KINDS)} kind(s); "
        f"excluded by name: {len(CFN_EXCLUDED)} CloudFormation, "
        f"{len(TF_EXCLUDED)} Terraform; "
        f"baselined divergences: {len(BASELINE)}"
    )
    for line in report:
        print(line)

    print()
    if errors:
        print(f"::error::{len(errors)} problem(s) found.")
        for err in errors:
            print(f"::error::{err}")
        print()
        print(
            "This check compares which KINDS of resource each representation "
            "provisions. It does not compare properties, counts, or named "
            "resources -- read the 'WHAT THIS CHECK DOES NOT CATCH' section of "
            f"{Path(__file__).name} before concluding the two sides match."
        )
        return 1

    print("Every pair matches its baseline. No unrecorded divergence.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
