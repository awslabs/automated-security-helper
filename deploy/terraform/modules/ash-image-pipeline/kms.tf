#
# The customer-managed key this module owns, and what has to be true for
# CloudWatch Logs to use it.
#
# WHY THIS IS ITS OWN FILE
# ------------------------
# The key, the one policy statement that makes it usable, and the grants the
# writers need are a single concern with a single failure mode. Keeping them in
# one file means a sixth resource encrypted with the key cannot pick up the key
# while missing the grant -- which does not fail validation, only deployment.
#
# WHY THE MODULE CREATES A KEY RATHER THAN ONLY ACCEPTING ONE
# ----------------------------------------------------------
# A Terraform module is the closest analogue to a CloudFormation stack here, and
# the CDK implementation of this target creates one key per stack. Accepting a key
# ARN and nothing else was the alternative and was rejected: the default would
# then be no customer-managed key at all, which is the gap this closes, and a
# required input would break every example in the repository.
#
# `kms_key_arn` is the way back out. An adopter composing several ASH modules can
# create one key and pass it to all of them rather than paying for one per module,
# since a KMS key carries a standing monthly charge whether or not anything is
# encrypted under it.
#
# WHY ONE KEY FOR THE BUILD LOG AND THE BUILD OUTPUT RATHER THAN ONE EACH
# ----------------------------------------------------------------------
# AWS recommends a key per encrypted log group, and this deliberately does not
# follow it. That recommendation exists so a key policy can be narrowed to a
# single log group ARN; here the build log and the build output it describes sit
# inside one trust boundary -- the same operators read both, and the log contains
# the materialized ASH configuration the output was built from -- so a second key
# would buy no isolation and would double a standing charge.
#
# WHY THE ENCRYPTION-CONTEXT CONDITION IS ACCOUNT-SCOPED
# -----------------------------------------------------
# The tighter form of the condition names the log group's own ARN. It cannot be
# used: the key policy would reference the log group, the log group references the
# key through kms_key_id, and Terraform rejects the cycle outright -- the same
# reason CloudFormation cannot express it either. AWS documents the account-scoped
# variant for exactly this case, describing it as limiting the key to the
# specified account while remaining usable for any log group, so that is the
# boundary this enforces.
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html
#
# WHAT THE DEPLOYING PRINCIPAL NEEDS
# ----------------------------------
# kms:DescribeKey on this key. AWS requires it of whoever calls CreateLogGroup
# with a kmsKeyId and fails the call with AccessDeniedException otherwise, so the
# log group fails to create rather than being created unencrypted. The default
# statement below grants the account root kms:*, so any principal in this account
# whose own identity policy allows KMS satisfies it. A deployment role with KMS
# carved out of it does not, and fails on the first log group.
#
# WHY SETTING kms_key_id ALONE IS NOT ENOUGH
# -----------------------------------------
# aws_cloudwatch_log_group.kms_key_id creates no key policy. A log group pointed
# at a key CloudWatch Logs has not been granted plans cleanly, validates cleanly,
# and then fails at CreateLogGroup. The statement below is what makes the
# association legal, which is why it lives next to the key rather than being left
# to the adopter.
#

locals {
  create_kms_key = var.kms_key_arn == null

  encryption_key_arn = local.create_kms_key ? aws_kms_key.this[0].arn : var.kms_key_arn

  # Regional, not logs.amazonaws.com. AWS documents the regionalized principal
  # and states it must be in the same region as the key.
  logs_service_principal = "logs.${data.aws_region.current.region}.amazonaws.com"
}

# Not already declared in main.tf, which needs only the region.
data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_iam_policy_document" "encryption_key" {
  # The key's own default policy, restated rather than inherited. The `policy`
  # argument REPLACES the default policy instead of adding to it, so omitting
  # this statement produces a key no principal in the account can administer --
  # including the next `terraform apply`, which can then neither read the policy
  # nor schedule the key for deletion.
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

    # A key policy's Resource is the key the policy is attached to. "*" is the
    # only value accepted here and it widens nothing.
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

  description = "Encrypts the ASH image build's CodeBuild output and CloudWatch log group."

  # Nothing outside this module reads the build output or the log, so a rotation
  # needs no coordination, and CloudWatch Logs keeps decrypting data written under
  # an earlier rotation of the same key.
  enable_key_rotation = true

  deletion_window_in_days = var.kms_key_deletion_window_days

  policy = data.aws_iam_policy_document.encryption_key.json

  tags = var.tags
}
