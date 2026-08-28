#
# ASH pull-request gate for an existing CodeCommit repository.
#
# EventBridge rule on CodeCommit pull-request state change -> container Lambda ->
# ASH scan -> PostCommentForPullRequest, and optionally an approval rule.
#
# The customer supplies the repository. This module never creates, modifies, or
# deletes it: there is no aws_codecommit_repository resource here, and there will
# not be one. The only thing it touches on the repository is an approval rule
# template association, which is opt-in and reversible.
#

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_partition" "current" {}

locals {
  # The comment and approval APIs take a repository name; EventBridge filters on
  # the ARN. A CodeCommit ARN's resource part is the bare repository name, so the
  # name is the sixth colon-separated element.
  repository_name = element(split(":", var.codecommit_repository_arn), 5)

  use_base_config = var.base_config_ssm_parameter_name != null
  chain_rebuild   = var.base_image_codebuild_project_arn != null

  gate_image_uri = "${aws_ecr_repository.gate.repository_url}:${var.image_tag}"
  ecr_registry   = split("/", aws_ecr_repository.gate.repository_url)[0]

  blocking_severities = [for severity in var.blocking_severities : lower(severity)]

  buildspec = templatefile("${path.module}/buildspec.yml.tftpl", {
    gate_dockerfile_b64 = filebase64("${path.module}/files/gate.Dockerfile")
    handler_b64         = filebase64("${path.module}/files/ash_pr_gate.py")
  })

  build_environment_type = var.lambda_architecture == "arm64" ? "ARM_CONTAINER" : "LINUX_CONTAINER"

  build_image = var.lambda_architecture == "arm64" ? "aws/codebuild/amazonlinux-aarch64-standard:3.0" : "aws/codebuild/amazonlinux-x86_64-standard:6.0"
}

#
# Gate image
#
# A second, thin image rather than reusing the shared one directly: Lambda cannot
# invoke an image with no runtime interface client, and neither the client nor
# git-remote-codecommit is wanted in the images the other three targets run.
#

resource "aws_ecr_repository" "gate" {
  name                 = "${var.name_prefix}-lambda"
  image_tag_mutability = var.ecr_image_tag_mutability
  force_delete         = var.ecr_force_delete

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = var.tags
}

resource "aws_ecr_lifecycle_policy" "gate" {
  repository = aws_ecr_repository.gate.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire all but the most recent ${var.image_retention_count} images."
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = var.image_retention_count
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "build" {
  name              = "/aws/codebuild/${var.name_prefix}-image-build"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

data "aws_iam_policy_document" "build_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "build" {
  name               = "${var.name_prefix}-image-build"
  assume_role_policy = data.aws_iam_policy_document.build_assume_role.json

  tags = var.tags
}

data "aws_iam_policy_document" "build" {
  statement {
    sid    = "WriteBuildLogs"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["${aws_cloudwatch_log_group.build.arn}:*"]
  }

  statement {
    sid       = "EcrAuth"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  # Pull covers the shared base image, push covers the gate repository. Scoped to
  # this account's repositories because the base image ARN is not known here.
  statement {
    sid    = "PullBaseAndPushGate"
    effect = "Allow"

    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]

    resources = [
      aws_ecr_repository.gate.arn,
      "arn:${data.aws_partition.current.partition}:ecr:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:repository/*",
    ]
  }
}

resource "aws_iam_role_policy" "build" {
  name   = "${var.name_prefix}-image-build"
  role   = aws_iam_role.build.id
  policy = data.aws_iam_policy_document.build.json
}

resource "aws_codebuild_project" "gate_image" {
  name          = "${var.name_prefix}-image-build"
  description   = "Adds a Lambda runtime interface client and the gate handler to the ASH image."
  service_role  = aws_iam_role.build.arn
  build_timeout = var.build_timeout_minutes

  source {
    type      = "NO_SOURCE"
    buildspec = local.buildspec
  }

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    type            = local.build_environment_type
    compute_type    = "BUILD_GENERAL1_MEDIUM"
    image           = local.build_image
    privileged_mode = true # required to run docker build

    environment_variable {
      name  = "BASE_IMAGE_URI"
      value = var.base_image_uri
    }

    environment_variable {
      name  = "IMAGE_URI"
      value = local.gate_image_uri
    }

    environment_variable {
      name  = "ECR_REGISTRY"
      value = local.ecr_registry
    }
  }

  logs_config {
    cloudwatch_logs {
      group_name = aws_cloudwatch_log_group.build.name
    }
  }

  tags = var.tags
}

#
# Chain the gate image rebuild off the base image rebuild
#
# Without this, a daily base rebuild would leave the gate Lambda running an image
# built on a base that no longer exists, which is exactly the staleness the
# schedule was meant to prevent.
#

data "aws_iam_policy_document" "chain_assume_role" {
  count = local.chain_rebuild ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "chain" {
  count = local.chain_rebuild ? 1 : 0

  name               = "${var.name_prefix}-rebuild-chain"
  assume_role_policy = data.aws_iam_policy_document.chain_assume_role[0].json

  tags = var.tags
}

data "aws_iam_policy_document" "chain" {
  count = local.chain_rebuild ? 1 : 0

  statement {
    sid       = "StartGateImageBuild"
    effect    = "Allow"
    actions   = ["codebuild:StartBuild"]
    resources = [aws_codebuild_project.gate_image.arn]
  }
}

resource "aws_iam_role_policy" "chain" {
  count = local.chain_rebuild ? 1 : 0

  name   = "${var.name_prefix}-rebuild-chain"
  role   = aws_iam_role.chain[0].id
  policy = data.aws_iam_policy_document.chain[0].json
}

resource "aws_cloudwatch_event_rule" "base_image_built" {
  count = local.chain_rebuild ? 1 : 0

  name        = "${var.name_prefix}-base-image-built"
  description = "Rebuilds the gate image after the shared ASH image is rebuilt."

  event_pattern = jsonencode({
    source        = ["aws.codebuild"]
    "detail-type" = ["CodeBuild Build State Change"]
    detail = {
      "build-status" = ["SUCCEEDED"]
      "project-name" = [element(split("/", var.base_image_codebuild_project_arn), 1)]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "base_image_built" {
  count = local.chain_rebuild ? 1 : 0

  rule      = aws_cloudwatch_event_rule.base_image_built[0].name
  target_id = "gate-image-build"
  arn       = aws_codebuild_project.gate_image.arn
  role_arn  = aws_iam_role.chain[0].arn
}

#
# Gate function
#

resource "aws_cloudwatch_log_group" "gate" {
  name              = "/aws/lambda/${var.name_prefix}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

data "aws_iam_policy_document" "gate_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "gate" {
  name               = "${var.name_prefix}-lambda"
  description        = "Role the ASH pull-request gate runs as."
  assume_role_policy = data.aws_iam_policy_document.gate_assume_role.json

  tags = var.tags
}

data "aws_iam_policy_document" "gate" {
  statement {
    sid    = "WriteLogs"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["${aws_cloudwatch_log_group.gate.arn}:*"]
  }

  # Every action here is scoped to the single supplied repository. Read actions
  # plus commenting; nothing that could create or delete a repository.
  statement {
    sid    = "ReadRepositoryAndComment"
    effect = "Allow"

    actions = [
      "codecommit:BatchGetCommits",
      "codecommit:GetBranch",
      "codecommit:GetCommit",
      "codecommit:GetDifferences",
      "codecommit:GetPullRequest",
      "codecommit:GetRepository",
      "codecommit:GitPull",
      "codecommit:PostCommentForPullRequest",
    ]

    resources = [var.codecommit_repository_arn]
  }

  dynamic "statement" {
    for_each = var.manage_approval_state ? [1] : []

    content {
      sid       = "UpdateApprovalState"
      effect    = "Allow"
      actions   = ["codecommit:UpdatePullRequestApprovalState"]
      resources = [var.codecommit_repository_arn]
    }
  }

  dynamic "statement" {
    for_each = local.use_base_config ? [1] : []

    content {
      sid       = "ReadBaseConfig"
      effect    = "Allow"
      actions   = ["ssm:GetParameter"]
      resources = [var.base_config_ssm_parameter_arn]
    }
  }
}

resource "aws_iam_role_policy" "gate" {
  name   = "${var.name_prefix}-lambda"
  role   = aws_iam_role.gate.id
  policy = data.aws_iam_policy_document.gate.json
}

resource "aws_lambda_function" "gate" {
  function_name = var.name_prefix
  description   = "Scans a CodeCommit pull request with ASH and comments the result."
  role          = aws_iam_role.gate.arn

  package_type  = "Image"
  image_uri     = local.gate_image_uri
  architectures = [var.lambda_architecture]

  timeout     = var.lambda_timeout_seconds
  memory_size = var.lambda_memory_mb

  reserved_concurrent_executions = var.reserved_concurrent_executions

  ephemeral_storage {
    size = var.lambda_ephemeral_storage_mb
  }

  environment {
    variables = {
      ASH_BLOCKING_SEVERITIES   = join(",", local.blocking_severities)
      ASH_MAX_COMMENT_CHARS     = tostring(var.max_comment_chars)
      ASH_MANAGE_APPROVAL_STATE = var.manage_approval_state ? "true" : "false"
      ASH_SCAN_EXTRA_ARGS       = var.ash_scan_extra_args
      ASH_OFFLINE               = var.ash_offline_mode ? "YES" : "NO"

      # Both the clone and the scan output land in /tmp, the only writable path.
      ASH_CONFIG_DIR                = "/tmp/ash-config"
      ASH_BASE_CONFIG_SSM_PARAMETER = local.use_base_config ? var.base_config_ssm_parameter_name : ""
    }
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.gate.name
  }

  tags = var.tags

  depends_on = [
    aws_iam_role_policy.gate,
    aws_cloudwatch_log_group.gate,
  ]
}

#
# Trigger
#

resource "aws_cloudwatch_event_rule" "pull_request" {
  name        = "${var.name_prefix}-pull-request"
  description = "Starts an ASH scan when a pull request on ${local.repository_name} changes."

  # resources scopes the rule to the one supplied repository, so a rule in an
  # account with many repositories does not fire for all of them.
  event_pattern = jsonencode({
    source        = ["aws.codecommit"]
    "detail-type" = ["CodeCommit Pull Request State Change"]
    resources     = [var.codecommit_repository_arn]
    detail = {
      event = var.trigger_events
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "pull_request" {
  rule      = aws_cloudwatch_event_rule.pull_request.name
  target_id = "ash-pr-gate"
  arn       = aws_lambda_function.gate.arn
}

resource "aws_lambda_permission" "pull_request" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.gate.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.pull_request.arn
}

#
# Approval rule
#

resource "aws_codecommit_approval_rule_template" "this" {
  count = var.create_approval_rule_template ? 1 : 0

  name        = "${var.name_prefix}-approval"
  description = "Requires approval before a pull request scanned by ASH can merge."

  content = jsonencode({
    Version               = "2018-11-08"
    DestinationReferences = ["refs/heads/*"]
    Statements = [
      {
        Type                    = "Approvers"
        NumberOfApprovalsNeeded = var.approval_rule_approvals_required
        ApprovalPoolMembers     = ["arn:${data.aws_partition.current.partition}:sts::${data.aws_caller_identity.current.account_id}:assumed-role/${aws_iam_role.gate.name}/*"]
      }
    ]
  })
}

# Associates the template with the customer's repository. This changes the
# repository's settings, which is why it is opt-in. It does not create, modify,
# or delete the repository or any of its content.
resource "aws_codecommit_approval_rule_template_association" "this" {
  count = var.create_approval_rule_template ? 1 : 0

  approval_rule_template_name = aws_codecommit_approval_rule_template.this[0].name
  repository_name             = local.repository_name
}
