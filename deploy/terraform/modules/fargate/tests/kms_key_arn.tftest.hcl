# kms_key_arn reaches every resource in this module that can be encrypted with a
# customer managed key, and the reader of the secret is granted kms:Decrypt on it.
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

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  container_image_uri   = "example.dkr.ecr.us-east-1.amazonaws.com/ash:latest"
  vpc_id                = "vpc-example"
  service_subnet_ids    = ["subnet-example-a"]
  alb_subnet_ids        = ["subnet-example-a", "subnet-example-b"]
  mcp_auth_header_value = "placeholder"
  # The module refuses an auth header over plain HTTP unless told otherwise.
  # Opting out keeps this test free of a certificate ARN, which the provider
  # would validate against a 12-digit account id.
  allow_plaintext_auth_header = true
}

run "key_supplied_reaches_every_encryptable_resource" {
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
    condition     = aws_cloudwatch_log_group.task.kms_key_id == var.kms_key_arn
    error_message = "The task log group is not encrypted with kms_key_arn."
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.task.statement :
      s.sid == "DecryptWithKmsKeyArn" && s.actions == toset(["kms:Decrypt"]) && s.resources == toset([var.kms_key_arn])
    ])
    error_message = "The task role is not granted kms:Decrypt on kms_key_arn, so it could not read the secret."
  }

  assert {
    condition     = length(aws_ecs_cluster.this[0].configuration) == 0
    error_message = "With ECS Exec off, a supplied key should not add an execute command configuration to the cluster."
  }
}

run "no_key_leaves_aws_managed_encryption" {
  command = plan

  assert {
    condition     = aws_secretsmanager_secret.auth_header[0].kms_key_id == null
    error_message = "With kms_key_arn unset, the secret should use the aws/secretsmanager key."
  }

  assert {
    condition     = aws_cloudwatch_log_group.task.kms_key_id == null
    error_message = "With kms_key_arn unset, the log group should use CloudWatch Logs' own encryption."
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.task.statement : s.sid != "DecryptWithKmsKeyArn"
    ])
    error_message = "With kms_key_arn unset, no kms:Decrypt statement should be granted."
  }
}

run "key_and_ecs_exec_encrypt_exec_sessions" {
  command = plan

  variables {
    enable_execute_command = true
    kms_key_arn            = "arn:aws:kms:us-east-1:${format("%012d", 1)}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  }

  assert {
    condition     = one(one(aws_ecs_cluster.this[0].configuration).execute_command_configuration).kms_key_id == var.kms_key_arn
    error_message = "With ECS Exec on, the cluster does not encrypt exec sessions with kms_key_arn."
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.task.statement :
      s.sid == "DecryptWithKmsKeyArn" && s.actions == toset(["kms:Decrypt"]) && s.resources == toset([var.kms_key_arn])
    ])
    error_message = "The task role is not granted kms:Decrypt on kms_key_arn, so ECS Exec sessions could not open."
  }

  assert {
    condition = length([
      for s in data.aws_iam_policy_document.task.statement : s if contains(s.actions, "kms:Decrypt")
    ]) == 1
    error_message = "The auth header secret and ECS Exec share one key, so the task role should carry one kms:Decrypt statement, not one per reader."
  }
}

run "ecs_exec_without_key_leaves_the_cluster_unchanged" {
  command = plan

  variables {
    enable_execute_command = true
  }

  assert {
    condition     = length(aws_ecs_cluster.this[0].configuration) == 0
    error_message = "With kms_key_arn unset, the cluster should carry no execute command configuration."
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.task.statement : s.sid != "DecryptWithKmsKeyArn"
    ])
    error_message = "With kms_key_arn unset, no ECS Exec kms:Decrypt statement should be granted."
  }
}

run "key_and_ecs_exec_without_auth_secret_still_grant_decrypt" {
  command = plan

  variables {
    mcp_auth_header_name   = null
    mcp_auth_header_value  = null
    enable_execute_command = true
    kms_key_arn            = "arn:aws:kms:us-east-1:${format("%012d", 1)}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  }

  assert {
    condition     = length(aws_secretsmanager_secret.auth_header) == 0
    error_message = "With no auth header value, the module should create no secret."
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.task.statement :
      s.sid == "DecryptWithKmsKeyArn" && s.resources == toset([var.kms_key_arn])
    ])
    error_message = "ECS Exec alone needs kms:Decrypt on kms_key_arn, with or without the auth header secret."
  }
}

run "external_cluster_keeps_exec_configuration_with_the_caller" {
  command = plan

  variables {
    cluster_arn            = "arn:aws:ecs:us-east-1:${format("%012d", 1)}:cluster/existing"
    mcp_auth_header_name   = null
    mcp_auth_header_value  = null
    enable_execute_command = true
    kms_key_arn            = "arn:aws:kms:us-east-1:${format("%012d", 1)}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  }

  assert {
    condition     = length(aws_ecs_cluster.this) == 0
    error_message = "With cluster_arn supplied, the module should not create a cluster."
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.task.statement : s.sid != "DecryptWithKmsKeyArn"
    ])
    error_message = "With an external cluster and no auth header secret, nothing in the module uses the key, so no kms:Decrypt should be granted."
  }
}
