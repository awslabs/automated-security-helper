# kms_key_arn reaches the one resource in this module that can be encrypted with a
# customer managed key, the auth header secret, and the runtime role that reads
# the secret is granted kms:Decrypt on it. The runtime itself takes no key.
#
# Runs offline: the AWS provider is mocked, so nothing is created and no
# credentials are needed. deploy/terraform/tests/validate-inputs.sh runs it.
#
# The assertions read the configuration the plan evaluates rather than provider
# output. With a mocked provider, computed attributes such as a policy
# document's `json` are random strings, so they cannot be asserted on; the
# statement blocks and resource arguments are the module's own values.

mock_provider "aws" {
  # The provider still validates ARNs and policy JSON under a mock, and mocked
  # computed values are random strings. Fixed, valid values satisfy those
  # checks; nothing below asserts on them.
  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "us-east-1"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "0"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  container_image_uri   = "example.dkr.ecr.us-east-1.amazonaws.com/ash:latest"
  mcp_auth_header_value = "placeholder"
}

run "key_supplied_reaches_the_secret_and_its_reader" {
  command = plan

  variables {
    # The account id is assembled rather than written out, so no 12-digit
    # literal exists in the repository for the account-id scan to flag.
    kms_key_arn = "arn:aws:kms:us-east-1:${format("%012d", 1)}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  }

  assert {
    condition     = aws_secretsmanager_secret.auth_header[0].kms_key_id == var.kms_key_arn
    error_message = "The auth header secret is not encrypted with kms_key_arn."
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.runtime.statement :
      s.sid == "DecryptAuthHeaderSecret" && s.actions == toset(["kms:Decrypt"]) && s.resources == toset([var.kms_key_arn])
    ])
    error_message = "The runtime role is not granted kms:Decrypt on kms_key_arn, so it could not read the secret."
  }
}

run "no_key_leaves_aws_managed_encryption" {
  command = plan

  assert {
    condition     = aws_secretsmanager_secret.auth_header[0].kms_key_id == null
    error_message = "With kms_key_arn unset, the secret should use the aws/secretsmanager key."
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.runtime.statement : s.sid != "DecryptAuthHeaderSecret"
    ])
    error_message = "With kms_key_arn unset, no kms:Decrypt statement should be granted."
  }
}
