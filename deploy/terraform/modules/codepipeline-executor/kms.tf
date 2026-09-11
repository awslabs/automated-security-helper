#
# The customer-managed key this module owns, and what has to be true for
# CloudWatch Logs to use it.
#
# WHY THIS IS ITS OWN FILE
# ------------------------
# The key, the one policy statement that makes it usable, and the grants the
# writers need are a single concern with a single failure mode. Keeping them in
# one file means a third log group cannot pick up the key while missing the grant
# -- which does not fail validation, only deployment.
#
# WHY THE KEY IS NO LONGER OPTIONAL
# --------------------------------
# kms_key_arn used to default to null and mean "no customer-managed key": the
# artifact bucket fell back to SSE-S3 and the two build log groups were encrypted
# with an Amazon-owned key nobody here can see the policy for. Null now means
# "create one", so the default deployment is encrypted under a key this
# configuration owns. That is a behavior change for anyone who was relying on the
# old default and it is deliberate; the cost is one KMS key's standing monthly
# charge per module.
#
# A Terraform module is the closest analogue to a CloudFormation stack here, and
# the CDK implementation of this target creates one key per stack. Keeping the
# input as ARN-only was the alternative and was rejected: it leaves the default
# unencrypted, which is the gap this closes, and making it required would break
# every example in the repository.
#
# WHY ONE KEY FOR THE ARTIFACTS AND BOTH LOG GROUPS RATHER THAN ONE EACH
# ---------------------------------------------------------------------
# AWS recommends a key per encrypted log group, and this deliberately does not
# follow it. That recommendation exists so a key policy can be narrowed to a single
# log group ARN; here the shard log, the merge log and the scan results in S3 sit
# inside one trust boundary -- the same operators read all of them, and the logs
# describe the results -- so a second key would buy no isolation and would multiply
# a standing charge. An adopter who wants one key for a whole deployment instead of
# one per module passes it in through kms_key_arn.
#
# WHY THE ENCRYPTION-CONTEXT CONDITION IS ACCOUNT-SCOPED
# -----------------------------------------------------
# The tighter form of the condition names each log group's own ARN. It cannot be
# used: the key policy would reference the log groups, the log groups reference the
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

  description = "Encrypts the sharded ASH scan's results bucket, pipeline artifacts, CodeBuild output and CloudWatch log groups."

  # Scan results and logs are read only from inside this deployment, so a rotation
  # needs no coordination. S3 keeps the key version each object was written under,
  # and CloudWatch Logs keeps decrypting data written under an earlier rotation of
  # the same key.
  enable_key_rotation = true

  deletion_window_in_days = var.kms_key_deletion_window_days

  policy = data.aws_iam_policy_document.encryption_key.json

  tags = var.tags
}
