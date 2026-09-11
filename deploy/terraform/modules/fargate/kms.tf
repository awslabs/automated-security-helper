#
# The customer-managed key this module owns, and what has to be true for
# CloudWatch Logs to use it.
#
# WHY THIS IS ITS OWN FILE
# ------------------------
# The key, the one policy statement that makes it usable, and the grants the
# writers and readers need are a single concern with a single failure mode. Keeping
# them in one file means a second log group cannot pick up the key while missing the
# grant -- which does not fail validation, only deployment.
#
# WHY THE MODULE CREATES A KEY RATHER THAN ONLY ACCEPTING ONE
# ----------------------------------------------------------
# A Terraform module is the closest analogue to a CloudFormation stack here, and
# the CDK implementation of this target creates one key per stack. Accepting a key
# ARN and nothing else was the alternative and was rejected: the default would then
# be no customer-managed key at all, which is the gap this closes, and a required
# input would break every example in the repository.
#
# `kms_key_arn` is the way back out. An adopter composing several ASH modules can
# create one key and pass it to all of them rather than paying for one per module,
# since a KMS key carries a standing monthly charge whether or not anything is
# encrypted under it.
#
# WHY ONE KEY FOR THE TASK LOG AND THE AUTH SECRET RATHER THAN ONE EACH
# --------------------------------------------------------------------
# AWS recommends a key per encrypted log group, and this deliberately does not
# follow it. That recommendation exists so a key policy can be narrowed to a single
# log group ARN; here the task log and the MCP auth header sit inside one trust
# boundary -- the same operators hold both, and a task log can carry scan output for
# whatever the caller asked ASH to scan -- so a second key would buy no isolation and
# would double a standing charge.
#
# WHY THE ENCRYPTION-CONTEXT CONDITION IS ACCOUNT-SCOPED
# -----------------------------------------------------
# The tighter form of the condition names the log group's own ARN. It cannot be
# used: the key policy would reference the log group, the log group references the
# key through kms_key_id, and Terraform rejects the cycle outright -- the same
# reason CloudFormation cannot express it either. AWS documents the account-scoped
# variant for exactly this case, describing it as limiting the key to the specified
# account while remaining usable for any log group, so that is the boundary this
# enforces.
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html
#
# WHAT THE DEPLOYING PRINCIPAL NEEDS
# ----------------------------------
# kms:DescribeKey on this key. AWS requires it of whoever calls CreateLogGroup
# with a kmsKeyId and fails the call with AccessDeniedException otherwise, so the
# log group fails to create rather than being created unencrypted. The default
# statement below grants the account root kms:*, so any principal in this account
# whose own identity policy allows KMS satisfies it. A deployment role with KMS
# carved out of it does not, and fails on the log group.
#
# WHY SETTING kms_key_id ALONE IS NOT ENOUGH
# -----------------------------------------
# aws_cloudwatch_log_group.kms_key_id creates no key policy. A log group pointed at
# a key CloudWatch Logs has not been granted plans cleanly, validates cleanly, and
# then fails at CreateLogGroup. The statement below is what makes the association
# legal, which is why it lives next to the key rather than being left to the adopter.
#
# WHY THE TASK AND EXECUTION ROLES ARE GRANTED IN main.tf AND NOT HERE
# -------------------------------------------------------------------
# The default statement below already delegates to IAM for principals in this
# account, so an identity policy is enough for them and naming them in the key
# policy would be redundant. Only a service principal -- which is not an IAM
# identity and cannot be granted through an identity policy -- has to be named
# here.
#
# It is worth being precise about what this does NOT avoid, because an earlier
# version of this comment claimed a dependency cycle and there is none: role
# policies here are separate `aws_iam_role_policy` resources, so naming a role in
# the key policy would make the key depend on the role while the role's policy
# depends on the key, and those are two different resources. Terraform would build
# that graph happily. The reason to keep identity-side grants identity-side is the
# redundancy above, plus that it is the placement AWS's own guidance and CDK's
# `@aws-cdk/aws-kms:defaultKeyPolicies` feature flag both move toward -- not a
# cycle.
#
# The CDK target does place its secret-decrypt grant in the key policy, because
# this app has not enabled that feature flag. The two implementations therefore
# read differently: on CDK you learn who may decrypt the secret from the key
# policy, here from the role policy. deploy/README.md records that divergence and
# the parity gate names it as out of scope, deliberately, rather than pretending
# one placement is the parity criterion when CDK itself uses both.
#

locals {
  create_kms_key = var.kms_key_arn == null

  encryption_key_arn = local.create_kms_key ? aws_kms_key.this[0].arn : var.kms_key_arn

  # Regional, not logs.amazonaws.com. AWS documents the regionalized principal and
  # states it must be in the same region as the key.
  logs_service_principal = "logs.${data.aws_region.current.region}.amazonaws.com"

  # Confines the task role's decrypt grant to calls Secrets Manager makes on its
  # behalf, so that grant cannot read the task log the same key protects.
  secretsmanager_via_service = "secretsmanager.${data.aws_region.current.region}.amazonaws.com"
}

# Not already declared in main.tf, which needs only the region and the partition.
data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "encryption_key" {
  # The key's own default policy, restated rather than inherited. The `policy`
  # argument REPLACES the default policy instead of adding to it, so omitting this
  # statement produces a key no principal in the account can administer --
  # including the next `terraform apply`, which can then neither read the policy nor
  # schedule the key for deletion.
  statement {
    sid       = "EnableIAMUserPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowCloudWatchLogsEncryption"
    effect = "Allow"

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]

    # A key policy's Resource is the key the policy is attached to. "*" is the only
    # value accepted here and it widens nothing.
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = [local.logs_service_principal]
    }

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:*"]
    }
  }
}

resource "aws_kms_key" "this" {
  count = local.create_kms_key ? 1 : 0

  description = "Encrypts the ASH Fargate service's CloudWatch log group and MCP auth header secret."

  # Nothing outside this module reads the task log or the auth secret, so a rotation
  # needs no coordination, and both CloudWatch Logs and Secrets Manager keep
  # decrypting material written under an earlier rotation of the same key.
  enable_key_rotation = true

  deletion_window_in_days = var.kms_key_deletion_window_days

  policy = data.aws_iam_policy_document.encryption_key.json

  tags = var.tags
}
