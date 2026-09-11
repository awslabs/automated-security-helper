#
# ASH image pipeline.
#
# ASH publishes no container image to any public registry, so every deployment
# target has to build the image into the customer's own ECR repository first.
# That makes this module the bootstrap, not merely a freshness mechanism:
# nothing downstream can start until the first build has succeeded.
#
# The scheduled rebuild is a second, separate reason to exist. ASH bundles
# third-party scanners and their rulesets, so an image left alone scans with
# stale detections even though ASH itself has not changed.
#

data "aws_region" "current" {}

locals {
  name = var.name_prefix

  # Native builds rather than cross-architecture emulation: an emulated ASH
  # image build is slow enough to run into the CodeBuild timeout, and several
  # bundled scanners ship architecture-specific binaries.
  default_build_images = {
    x86_64 = "aws/codebuild/amazonlinux-x86_64-standard:6.0"
    arm64  = "aws/codebuild/amazonlinux-aarch64-standard:3.0"
  }

  build_environment_types = {
    x86_64 = "LINUX_CONTAINER"
    arm64  = "ARM_CONTAINER"
  }

  build_image = coalesce(
    var.build_image_override,
    local.default_build_images[var.target_architecture]
  )

  build_environment_type = local.build_environment_types[var.target_architecture]
  build_compute_type     = coalesce(var.build_compute_type, "BUILD_GENERAL1_LARGE")

  # Derived from the repository URL rather than assembled from account id and
  # region, so the registry hostname stays correct in every partition without
  # this module hardcoding a DNS suffix.
  ecr_registry = split("/", aws_ecr_repository.this.repository_url)[0]
  image_uri    = "${aws_ecr_repository.this.repository_url}:${var.image_tag}"

  manage_config_parameter = var.ash_base_config_yaml != null

  config_parameter_name = "/${local.name}/base-config-yaml"

  buildspec = templatefile("${path.module}/buildspec.yml.tftpl", {
    wrapper_dockerfile_b64 = filebase64("${path.module}/files/wrapper.Dockerfile")
    init_script_b64        = filebase64("${path.module}/files/ash-container-init")
    serve_script_b64       = filebase64("${path.module}/files/ash-mcp-serve")
  })
}

#
# Image repository
#

resource "aws_ecr_repository" "this" {
  name                 = local.name
  image_tag_mutability = var.ecr_image_tag_mutability
  force_delete         = var.ecr_force_delete

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = var.ecr_kms_key_arn == null ? "AES256" : "KMS"
    kms_key         = var.ecr_kms_key_arn
  }

  tags = var.tags
}

resource "aws_ecr_lifecycle_policy" "this" {
  repository = aws_ecr_repository.this.name

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

#
# Base ASH configuration
#
# Stored here rather than passed as a container environment variable because
# AgentCore Runtime exposes only a flat environment map, and a real .ash.yaml
# does not comfortably fit in one. The container entrypoint reads this parameter
# and writes .ash/.ash.yaml at start.
#

resource "aws_ssm_parameter" "base_config" {
  count = local.manage_config_parameter ? 1 : 0

  name        = local.config_parameter_name
  description = "Base ASH configuration materialized to .ash/.ash.yaml at container start."
  type        = "String"
  tier        = var.ssm_parameter_tier
  value       = var.ash_base_config_yaml

  tags = var.tags
}

#
# Build project
#

resource "aws_cloudwatch_log_group" "build" {
  name              = "/aws/codebuild/${local.name}-image-build"
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
  name               = "${local.name}-image-build"
  assume_role_policy = data.aws_iam_policy_document.build_assume_role.json
  tags               = var.tags
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

  # GetAuthorizationToken is not resource-scoped by ECR; it authorizes the
  # registry as a whole, so it cannot be narrowed to this repository.
  statement {
    sid       = "EcrAuth"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid    = "PushImage"
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

    resources = [aws_ecr_repository.this.arn]
  }
}

resource "aws_iam_role_policy" "build" {
  name   = "${local.name}-image-build"
  role   = aws_iam_role.build.id
  policy = data.aws_iam_policy_document.build.json
}

resource "aws_codebuild_project" "this" {
  name           = "${local.name}-image-build"
  description    = "Builds the ASH container image from ${var.ash_version} into ${aws_ecr_repository.this.name}."
  service_role   = aws_iam_role.build.arn
  build_timeout  = var.build_timeout_minutes
  encryption_key = var.ecr_kms_key_arn

  source {
    type      = "NO_SOURCE"
    buildspec = local.buildspec
  }

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    type            = local.build_environment_type
    compute_type    = local.build_compute_type
    image           = local.build_image
    privileged_mode = true # required to run docker build

    environment_variable {
      name  = "ASH_VERSION"
      value = var.ash_version
    }

    environment_variable {
      name  = "ASH_REPO_CLONE_URL"
      value = var.ash_repository_clone_url
    }

    environment_variable {
      name  = "ASH_IMAGE_TARGET"
      value = var.ash_image_target
    }

    # The Dockerfile's OFFLINE argument is a YES/NO string, and it is what sets
    # ASH_OFFLINE inside the image.
    environment_variable {
      name  = "ASH_OFFLINE"
      value = var.ash_offline_mode ? "YES" : "NO"
    }

    environment_variable {
      name  = "TARGET_ARCH"
      value = var.target_architecture
    }

    environment_variable {
      name  = "ECR_REGISTRY"
      value = local.ecr_registry
    }

    environment_variable {
      name  = "ECR_REPOSITORY_URL"
      value = aws_ecr_repository.this.repository_url
    }

    environment_variable {
      name  = "IMAGE_URI"
      value = local.image_uri
    }

    environment_variable {
      name  = "ASH_VERSION_TAG_PREFIX"
      value = var.ash_version_tag_prefix
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
# Scheduled rebuild
#

data "aws_iam_policy_document" "schedule_assume_role" {
  count = var.enable_scheduled_rebuild ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "schedule" {
  count = var.enable_scheduled_rebuild ? 1 : 0

  name               = "${local.name}-image-rebuild-schedule"
  assume_role_policy = data.aws_iam_policy_document.schedule_assume_role[0].json
  tags               = var.tags
}

data "aws_iam_policy_document" "schedule" {
  count = var.enable_scheduled_rebuild ? 1 : 0

  statement {
    sid       = "StartImageBuild"
    effect    = "Allow"
    actions   = ["codebuild:StartBuild"]
    resources = [aws_codebuild_project.this.arn]
  }
}

resource "aws_iam_role_policy" "schedule" {
  count = var.enable_scheduled_rebuild ? 1 : 0

  name   = "${local.name}-image-rebuild-schedule"
  role   = aws_iam_role.schedule[0].id
  policy = data.aws_iam_policy_document.schedule[0].json
}

resource "aws_cloudwatch_event_rule" "rebuild" {
  count = var.enable_scheduled_rebuild ? 1 : 0

  name                = "${local.name}-image-rebuild"
  description         = "Rebuilds the ASH image on a schedule so bundled scanners and rulesets stay current."
  schedule_expression = var.rebuild_schedule

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "rebuild" {
  count = var.enable_scheduled_rebuild ? 1 : 0

  rule      = aws_cloudwatch_event_rule.rebuild[0].name
  target_id = "image-build"
  arn       = aws_codebuild_project.this.arn
  role_arn  = aws_iam_role.schedule[0].arn
}
