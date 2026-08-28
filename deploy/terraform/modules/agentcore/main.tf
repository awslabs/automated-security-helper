#
# ASH MCP server on Amazon Bedrock AgentCore Runtime.
#
# The container contract this module targets is documented at
# https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-mcp-protocol-contract.html
# and pins four things the module cannot vary:
#
#   * streamable-http transport, and stateless mode by default
#   * host 0.0.0.0, port 8000
#   * an arm64 container
#   * POST /mcp
#
# The platform also injects its own Mcp-Session-Id header on every request and
# requires the server to accept it rather than reject it. See the
# mcp_stateless_http variable for what happens when it does not.
#

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_partition" "current" {}

locals {
  runtime_name = coalesce(var.agent_runtime_name, "${var.name_prefix}_mcp")

  # nonsensitive() applies to the emptiness test, not the value. Whether a
  # secret was supplied is not itself secret, and leaving the boolean tainted
  # would propagate sensitivity into resource count and into the secret's ARN
  # output, neither of which reveals the credential.
  manage_auth_secret = nonsensitive(var.mcp_auth_header_value != null)
  use_auth_header    = var.mcp_auth_header_name != null
  use_base_config    = var.base_config_ssm_parameter_name != null
  use_jwt_authorizer = var.jwt_authorizer_discovery_url != null

  ecr_pull_resource_arns = coalesce(
    var.ecr_pull_resource_arns,
    ["arn:${data.aws_partition.current.partition}:ecr:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:repository/*"]
  )

  # AgentCore writes runtime logs to a service-managed log group under this
  # prefix. The module does not create the group; the execution role is granted
  # permission to create and write it, which is what the service expects.
  log_group_prefix = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/bedrock-agentcore/runtimes"

  workload_identity_directory = "arn:${data.aws_partition.current.partition}:bedrock-agentcore:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:workload-identity-directory/default"

  # AgentCore drops any request header that is not allowlisted, so a static auth
  # header that is not listed here never reaches ASH and every request fails the
  # header check. Deriving the list from mcp_auth_header_name rather than asking
  # the caller to repeat it removes the chance of the two disagreeing.
  request_header_allowlist = local.use_auth_header ? [var.mcp_auth_header_name] : []

  # Environment-driven rather than baked into the image: AgentCore has no
  # container command override, so the image's CMD is a launcher that reads these.
  # That keeps every MCP setting a deploy-time decision on this target too.
  mcp_environment = {
    ASH_MCP_TRANSPORT             = "streamable-http"
    ASH_MCP_HOST                  = "0.0.0.0"
    ASH_MCP_PORT                  = "8000"
    ASH_MCP_MOUNT_PATH            = var.mcp_mount_path
    ASH_MCP_STATELESS_HTTP        = var.mcp_stateless_http ? "true" : "false"
    ASH_OFFLINE                   = var.ash_offline_mode ? "YES" : "NO"
    ASH_MCP_ALLOWED_HOSTS         = join(",", var.mcp_allowed_host)
    ASH_MCP_AUTH_HEADER_NAME      = local.use_auth_header ? var.mcp_auth_header_name : ""
    ASH_BASE_CONFIG_SSM_PARAMETER = local.use_base_config ? var.base_config_ssm_parameter_name : ""
    ASH_MCP_AUTH_SECRET_ARN       = local.manage_auth_secret ? aws_secretsmanager_secret.auth_header[0].arn : ""
  }

  # Caller-supplied values go first so local.mcp_environment wins on a key
  # collision: a typo in additional_environment_variables cannot quietly change
  # the port or the transport out from under the AgentCore contract.
  environment_variables = merge(var.additional_environment_variables, local.mcp_environment)
}

#
# MCP auth header value
#
# Held in Secrets Manager rather than in the runtime's environment_variables,
# which anyone able to describe the runtime can read.
#

resource "aws_secretsmanager_secret" "auth_header" {
  count = local.manage_auth_secret ? 1 : 0

  name        = "${var.name_prefix}-agentcore-mcp-auth-header"
  description = "Expected value of the static MCP auth header for the ASH AgentCore runtime."

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "auth_header" {
  count = local.manage_auth_secret ? 1 : 0

  secret_id     = aws_secretsmanager_secret.auth_header[0].id
  secret_string = var.mcp_auth_header_value
}

#
# Execution role
#

data "aws_iam_policy_document" "assume_role" {
  statement {
    sid     = "AssumeRolePolicy"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["bedrock-agentcore.amazonaws.com"]
    }

    # Confusably scoped service principals are a standing risk for any role a
    # service assumes, so both conditions from the AgentCore documentation are
    # applied rather than just the principal.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:bedrock-agentcore:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:*"]
    }
  }
}

resource "aws_iam_role" "runtime" {
  name               = "${var.name_prefix}-agentcore-runtime"
  description        = "Execution role AgentCore Runtime assumes to run the ASH MCP server."
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = var.tags
}

data "aws_iam_policy_document" "runtime" {
  statement {
    sid    = "EcrImageAccess"
    effect = "Allow"

    actions = [
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]

    resources = local.ecr_pull_resource_arns
  }

  # Not resource-scopable: ECR authorizes the registry as a whole.
  statement {
    sid       = "EcrTokenAccess"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid    = "RuntimeLogGroup"
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:DescribeLogStreams",
    ]

    resources = ["${local.log_group_prefix}/*"]
  }

  statement {
    sid       = "RuntimeLogResourcePolicy"
    effect    = "Allow"
    actions   = ["logs:PutResourcePolicy"]
    resources = ["${local.log_group_prefix}/${local.runtime_name}-*"]
  }

  # DescribeLogGroups cannot be narrowed below the log-group namespace.
  statement {
    sid       = "DescribeLogGroups"
    effect    = "Allow"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:*"]
  }

  statement {
    sid    = "RuntimeLogStreams"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["${local.log_group_prefix}/*:log-stream:*"]
  }

  statement {
    sid    = "Tracing"
    effect = "Allow"

    actions = [
      "xray:GetSamplingRules",
      "xray:GetSamplingTargets",
      "xray:PutTelemetryRecords",
      "xray:PutTraceSegments",
    ]

    resources = ["*"]
  }

  statement {
    sid       = "RuntimeMetrics"
    effect    = "Allow"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["bedrock-agentcore"]
    }
  }

  # Scoped to GetWorkloadAccessToken and the JWT variant. The ForUserId variant
  # is deliberately omitted: it mints a workload token from a caller-supplied
  # user identifier with no IdP verification, which the AgentCore documentation
  # recommends denying outside development.
  statement {
    sid    = "GetAgentAccessToken"
    effect = "Allow"

    actions = [
      "bedrock-agentcore:GetWorkloadAccessToken",
      "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
    ]

    resources = [
      local.workload_identity_directory,
      "${local.workload_identity_directory}/workload-identity/${local.runtime_name}-*",
    ]
  }

  dynamic "statement" {
    for_each = local.use_base_config ? [1] : []

    content {
      sid    = "ReadBaseConfig"
      effect = "Allow"

      actions = [
        "ssm:GetParameter",
      ]

      resources = [var.base_config_ssm_parameter_arn]
    }
  }

  dynamic "statement" {
    for_each = local.manage_auth_secret ? [1] : []

    content {
      sid       = "ReadAuthHeaderSecret"
      effect    = "Allow"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [aws_secretsmanager_secret.auth_header[0].arn]
    }
  }

  dynamic "statement" {
    for_each = var.enable_bedrock_model_invocation ? [1] : []

    content {
      sid    = "BedrockModelInvocation"
      effect = "Allow"

      actions = [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
      ]

      resources = [
        "arn:${data.aws_partition.current.partition}:bedrock:*::foundation-model/*",
        "arn:${data.aws_partition.current.partition}:bedrock:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:*",
      ]
    }
  }
}

resource "aws_iam_role_policy" "runtime" {
  name   = "${var.name_prefix}-agentcore-runtime"
  role   = aws_iam_role.runtime.id
  policy = data.aws_iam_policy_document.runtime.json
}

#
# Runtime
#

resource "aws_bedrockagentcore_agent_runtime" "this" {
  agent_runtime_name = local.runtime_name
  description        = "ASH security scanner exposed over MCP."
  role_arn           = aws_iam_role.runtime.arn

  environment_variables = local.environment_variables

  agent_runtime_artifact {
    container_configuration {
      container_uri = var.container_image_uri
    }
  }

  network_configuration {
    network_mode = var.network_mode

    dynamic "network_mode_config" {
      for_each = var.network_mode == "VPC" ? [1] : []

      content {
        subnets         = var.vpc_subnet_ids
        security_groups = var.vpc_security_group_ids
      }
    }
  }

  # Fixed rather than configurable. This module exists to serve ASH over MCP;
  # HTTP, A2A, and AGUI are the other accepted values and none of them describe
  # what the container speaks.
  protocol_configuration {
    server_protocol = "MCP"
  }

  dynamic "request_header_configuration" {
    for_each = length(local.request_header_allowlist) > 0 ? [1] : []

    content {
      request_header_allowlist = local.request_header_allowlist
    }
  }

  dynamic "authorizer_configuration" {
    for_each = local.use_jwt_authorizer ? [1] : []

    content {
      custom_jwt_authorizer {
        discovery_url    = var.jwt_authorizer_discovery_url
        allowed_audience = var.jwt_authorizer_allowed_audience
        allowed_clients  = var.jwt_authorizer_allowed_clients
      }
    }
  }

  dynamic "lifecycle_configuration" {
    for_each = (var.idle_session_timeout_seconds != null || var.max_session_lifetime_seconds != null) ? [1] : []

    content {
      idle_runtime_session_timeout = var.idle_session_timeout_seconds
      max_lifetime                 = var.max_session_lifetime_seconds
    }
  }

  tags = var.tags

  depends_on = [aws_iam_role_policy.runtime]
}

resource "aws_bedrockagentcore_agent_runtime_endpoint" "this" {
  count = var.create_endpoint ? 1 : 0

  agent_runtime_id = aws_bedrockagentcore_agent_runtime.this.agent_runtime_id
  name             = coalesce(var.endpoint_name, "DEFAULT")
  description      = "Endpoint for the ASH MCP runtime."

  tags = var.tags
}
