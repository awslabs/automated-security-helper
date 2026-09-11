#
# The customer-managed key this module owns, and what has to be true to use it.
#
# WHY THIS IS ITS OWN FILE
# ------------------------
# The same key, the same policy statement and the same failure mode recur in all
# five ASH modules. Keeping the whole concern in one file per module means the
# key and the grants that make it usable are read together, and a sixth resource
# encrypted with the key cannot pick up the key while missing the grant.
#
# WHY THE MODULE CREATES A KEY RATHER THAN ONLY ACCEPTING ONE
# ----------------------------------------------------------
# A Terraform module is the closest analogue to a CloudFormation stack here, and
# the CDK implementation of this target creates one key per stack. Taking a key
# ARN and nothing else was the alternative, and it was rejected: the default
# would then be no customer-managed key at all, which is the gap this is meant to
# close, and a required input would break every example in the repository.
#
# `kms_key_arn` is the way back out. An adopter composing several ASH modules can
# create one key and pass it to all of them rather than paying for one per module,
# because a KMS key carries a standing monthly charge whether or not anything is
# encrypted under it.
#
# WHY THE KEY IS CONDITIONAL HERE AND UNCONDITIONAL IN THE OTHER MODULES
# ---------------------------------------------------------------------
# The auth secret is the only thing this module can encrypt, and it is itself
# optional -- it exists only when mcp_auth_header_value is set. A key created
# regardless would bill monthly for a deployment that has nothing to put under
# it. The other four modules always create log groups, so their keys are
# unconditional.
#
# WHY THIS KEY POLICY HAS NO CLOUDWATCH LOGS STATEMENT
# ---------------------------------------------------
# Unlike the other four modules, this one creates no log group. AgentCore writes
# runtime logs to a service-managed group under /aws/bedrock-agentcore/runtimes
# that this configuration neither creates nor can associate a key with -- see the
# log_group_name output. Granting the CloudWatch Logs service principal here
# would widen the key and encrypt nothing, so the policy is the default statement
# and nothing else.
#
# WHAT THE READER OF THE SECRET NEEDS, AND WHY IT IS NOT IN THIS POLICY
# --------------------------------------------------------------------
# Secrets Manager decrypts using the *caller's* credentials, so the execution
# role's secretsmanager:GetSecretValue is not enough on its own once the secret
# is under a customer-managed key: it also needs kms:Decrypt. That grant is in the
# execution role's own policy in main.tf rather than here, because the default
# statement below already delegates to IAM for principals in this account. Only a
# service principal -- which is not an IAM identity and cannot be granted through
# an identity policy -- needs naming in a key policy.
#

locals {
  # Only when there is something to encrypt; see the header.
  create_kms_key = var.kms_key_arn == null && local.manage_auth_secret

  encryption_key_arn = local.create_kms_key ? aws_kms_key.this[0].arn : var.kms_key_arn

  # Restricts the grant in the execution role's policy to calls Secrets Manager
  # makes on the role's behalf, so that grant cannot decrypt anything else this
  # key comes to protect.
  secretsmanager_via_service = "secretsmanager.${data.aws_region.current.region}.amazonaws.com"
}

data "aws_iam_policy_document" "encryption_key" {
  # The key's own default policy, restated rather than inherited. The `policy`
  # argument REPLACES the default policy instead of adding to it, so omitting
  # this statement produces a key that no principal in the account can
  # administer -- including the next `terraform apply`, which can then neither
  # read the policy nor schedule the key for deletion.
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
}

resource "aws_kms_key" "this" {
  count = local.create_kms_key ? 1 : 0

  description = "Encrypts the MCP auth header secret for the ASH AgentCore runtime."

  # The secret is read only by this module's own runtime, so a rotation needs no
  # coordination with anything, and Secrets Manager keeps decrypting material
  # written under an earlier rotation of the same key.
  enable_key_rotation = true

  deletion_window_in_days = var.kms_key_deletion_window_days

  policy = data.aws_iam_policy_document.encryption_key.json

  tags = var.tags
}
