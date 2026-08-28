#
# Sharded ASH scan as a CodePipeline: fan out N shards, then collect.
#
# Stage layout:
#
#   Source  -> CodeCommit
#   Scan    -> N CodeBuild actions, all at run_order 1 so they run in parallel,
#              each `ash scan --shard-index <i> --shard-count <n>`
#   Merge   -> one CodeBuild action, `ash merge --results ... --output-dir ...`
#
# The merge action owns the verdict. This is the single most important property of
# the design: a shard that happens to own no findings exits 0, so gating on shard
# exit codes would report a clean scan whenever the findings landed in some other
# shard. Shards therefore run with --no-fail-on-findings and only fail on a real
# crash, and the pass/fail decision is computed from the *merged* results.
#
# Shard results move through S3 rather than as pipeline artifacts. A CodeBuild
# action accepts only 1 to 5 input artifacts, which would cap the fan-in at five
# shards; a stage may hold up to 100 parallel actions. S3 is what makes
# shard_count > 5 possible.
#

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_partition" "current" {}

locals {
  repository_name = element(split(":", var.codecommit_repository_arn), 5)

  use_base_config = var.base_config_ssm_parameter_name != null
  use_kms         = var.kms_key_arn != null

  blocking_severities = join(",", [for severity in var.blocking_severities : lower(severity)])

  shard_indices = range(var.shard_count)

  results_arn_prefix = "${aws_s3_bucket.artifacts.arn}/${var.results_prefix}"

  # Implicit variable in CodePipeline's reserved namespace, resolved per
  # execution. It is what gives every action in one run a shared, unique S3
  # prefix, so two concurrent executions cannot read each other's shards.
  execution_id_ref = "#{codepipeline.PipelineExecutionId}"

  shard_buildspec = templatefile("${path.module}/buildspec-shard.yml.tftpl", {
    s3_sync_b64 = filebase64("${path.module}/files/ash_s3_sync.py")
  })

  merge_buildspec = templatefile("${path.module}/buildspec-merge.yml.tftpl", {
    s3_sync_b64        = filebase64("${path.module}/files/ash_s3_sync.py")
    verdict_script_b64 = filebase64("${path.module}/files/ash_merge_verdict.py")
  })

  common_build_environment_variables = [
    {
      name  = "ASH_OFFLINE"
      value = var.ash_offline_mode ? "YES" : "NO"
    },
    {
      name  = "ASH_BASE_CONFIG_SSM_PARAMETER"
      value = local.use_base_config ? var.base_config_ssm_parameter_name : ""
    },
    {
      name  = "RESULTS_BUCKET"
      value = aws_s3_bucket.artifacts.bucket
    },
    {
      name  = "RESULTS_PREFIX"
      value = var.results_prefix
    },
    {
      name  = "SHARD_COUNT"
      value = tostring(var.shard_count)
    },
  ]
}

#
# Artifact and results storage
#

resource "aws_s3_bucket" "artifacts" {
  bucket_prefix = "${var.name_prefix}-"
  force_destroy = var.artifact_bucket_force_destroy

  tags = var.tags
}

# CodePipeline requires versioning on its artifact bucket.
resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.use_kms ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = local.use_kms
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-scan-results"
    status = "Enabled"

    filter {
      prefix = "${var.results_prefix}/"
    }

    expiration {
      days = var.results_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.results_retention_days
    }
  }

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.artifacts]
}

#
# Build roles
#
# Separate roles for the shard and merge actions, because their access to the
# results prefix differs in direction: shards write their own shard, merge reads
# every shard and writes the merged output.
#

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

resource "aws_cloudwatch_log_group" "shard" {
  name              = "/aws/codebuild/${var.name_prefix}-shard"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "merge" {
  name              = "/aws/codebuild/${var.name_prefix}-merge"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

resource "aws_iam_role" "shard" {
  name               = "${var.name_prefix}-shard"
  assume_role_policy = data.aws_iam_policy_document.build_assume_role.json

  tags = var.tags
}

resource "aws_iam_role" "merge" {
  name               = "${var.name_prefix}-merge"
  assume_role_policy = data.aws_iam_policy_document.build_assume_role.json

  tags = var.tags
}

# Shared statements: pulling the ASH image, reading the source artifact, and the
# optional base config and KMS key.
data "aws_iam_policy_document" "build_common" {
  statement {
    sid       = "EcrAuth"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  # The ASH image is the CodeBuild environment image and it is private, so the
  # project pulls it with this role.
  statement {
    sid    = "PullAshImage"
    effect = "Allow"

    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]

    resources = ["arn:${data.aws_partition.current.partition}:ecr:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:repository/*"]
  }

  statement {
    sid    = "ReadSourceArtifact"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetBucketLocation",
    ]

    resources = [
      aws_s3_bucket.artifacts.arn,
      "${aws_s3_bucket.artifacts.arn}/*",
    ]
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

  dynamic "statement" {
    for_each = local.use_kms ? [1] : []

    content {
      sid    = "UseKmsKey"
      effect = "Allow"

      actions = [
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "kms:ReEncrypt*",
      ]

      resources = [var.kms_key_arn]
    }
  }
}

data "aws_iam_policy_document" "shard" {
  source_policy_documents = [data.aws_iam_policy_document.build_common.json]

  statement {
    sid    = "WriteShardLogs"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["${aws_cloudwatch_log_group.shard.arn}:*"]
  }

  # Write only, and only under the results prefix. A shard has no reason to read
  # another shard's output.
  statement {
    sid       = "WriteShardResults"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${local.results_arn_prefix}/*"]
  }
}

data "aws_iam_policy_document" "merge" {
  source_policy_documents = [data.aws_iam_policy_document.build_common.json]

  statement {
    sid    = "WriteMergeLogs"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["${aws_cloudwatch_log_group.merge.arn}:*"]
  }

  statement {
    sid    = "ReadAndWriteResults"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:PutObject",
    ]

    resources = ["${local.results_arn_prefix}/*"]
  }

  # ListBucket is what lets the merge action discover which shards actually
  # uploaded, which is how a missing shard is detected rather than silently
  # merged around.
  statement {
    sid       = "ListResults"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.artifacts.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${var.results_prefix}/*"]
    }
  }
}

resource "aws_iam_role_policy" "shard" {
  name   = "${var.name_prefix}-shard"
  role   = aws_iam_role.shard.id
  policy = data.aws_iam_policy_document.shard.json
}

resource "aws_iam_role_policy" "merge" {
  name   = "${var.name_prefix}-merge"
  role   = aws_iam_role.merge.id
  policy = data.aws_iam_policy_document.merge.json
}

#
# Build projects
#
# One shard project serving N actions, rather than N identical projects. The
# per-shard index arrives as an action-level environment variable override, so
# adding a shard is one more action rather than one more project.
#

resource "aws_codebuild_project" "shard" {
  name          = "${var.name_prefix}-shard"
  description   = "Runs one shard of a sharded ASH scan."
  service_role  = aws_iam_role.shard.arn
  build_timeout = var.shard_build_timeout_minutes

  source {
    type      = "CODEPIPELINE"
    buildspec = local.shard_buildspec
  }

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    type         = var.build_environment_type
    compute_type = var.build_compute_type

    # The ASH image is the build environment, so `ash` is on PATH with no
    # Docker-in-Docker and no privileged_mode. SERVICE_ROLE credentials are
    # required for a private ECR image.
    image                       = var.container_image_uri
    image_pull_credentials_type = "SERVICE_ROLE"

    dynamic "environment_variable" {
      for_each = local.common_build_environment_variables

      content {
        name  = environment_variable.value.name
        value = environment_variable.value.value
      }
    }
  }

  logs_config {
    cloudwatch_logs {
      group_name = aws_cloudwatch_log_group.shard.name
    }
  }

  tags = var.tags
}

resource "aws_codebuild_project" "merge" {
  name          = "${var.name_prefix}-merge"
  description   = "Merges every shard's ASH results and forms the pipeline verdict."
  service_role  = aws_iam_role.merge.arn
  build_timeout = var.merge_build_timeout_minutes

  source {
    type      = "CODEPIPELINE"
    buildspec = local.merge_buildspec
  }

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    type                        = var.build_environment_type
    compute_type                = var.build_compute_type
    image                       = var.container_image_uri
    image_pull_credentials_type = "SERVICE_ROLE"

    dynamic "environment_variable" {
      for_each = local.common_build_environment_variables

      content {
        name  = environment_variable.value.name
        value = environment_variable.value.value
      }
    }

    environment_variable {
      name  = "BLOCKING_SEVERITIES"
      value = local.blocking_severities
    }
  }

  logs_config {
    cloudwatch_logs {
      group_name = aws_cloudwatch_log_group.merge.name
    }
  }

  tags = var.tags
}

#
# Pipeline role
#

data "aws_iam_policy_document" "pipeline_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codepipeline.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "pipeline" {
  name               = "${var.name_prefix}-pipeline"
  assume_role_policy = data.aws_iam_policy_document.pipeline_assume_role.json

  tags = var.tags
}

data "aws_iam_policy_document" "pipeline" {
  statement {
    sid    = "ArtifactStore"
    effect = "Allow"

    actions = [
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:ListBucket",
      "s3:PutObject",
    ]

    resources = [
      aws_s3_bucket.artifacts.arn,
      "${aws_s3_bucket.artifacts.arn}/*",
    ]
  }

  # Read-only against the repository, scoped to the one supplied ARN. Nothing here
  # can create, modify, or delete it.
  statement {
    sid    = "CodeCommitSource"
    effect = "Allow"

    actions = [
      "codecommit:CancelUploadArchive",
      "codecommit:GetBranch",
      "codecommit:GetCommit",
      "codecommit:GetRepository",
      "codecommit:GetUploadArchiveStatus",
      "codecommit:UploadArchive",
    ]

    resources = [var.codecommit_repository_arn]
  }

  statement {
    sid    = "StartBuilds"
    effect = "Allow"

    actions = [
      "codebuild:BatchGetBuilds",
      "codebuild:StartBuild",
      "codebuild:StopBuild",
    ]

    resources = [
      aws_codebuild_project.shard.arn,
      aws_codebuild_project.merge.arn,
    ]
  }

  dynamic "statement" {
    for_each = local.use_kms ? [1] : []

    content {
      sid    = "UseKmsKey"
      effect = "Allow"

      actions = [
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "kms:ReEncrypt*",
      ]

      resources = [var.kms_key_arn]
    }
  }
}

resource "aws_iam_role_policy" "pipeline" {
  name   = "${var.name_prefix}-pipeline"
  role   = aws_iam_role.pipeline.id
  policy = data.aws_iam_policy_document.pipeline.json
}

#
# Pipeline
#

resource "aws_codepipeline" "this" {
  name     = var.name_prefix
  role_arn = aws_iam_role.pipeline.arn

  artifact_store {
    location = aws_s3_bucket.artifacts.bucket
    type     = "S3"

    dynamic "encryption_key" {
      for_each = local.use_kms ? [1] : []

      content {
        id   = var.kms_key_arn
        type = "KMS"
      }
    }
  }

  stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeCommit"
      version          = "1"
      output_artifacts = ["source"]

      configuration = {
        RepositoryName = local.repository_name
        BranchName     = var.source_branch

        # EventBridge drives the pipeline instead; polling adds latency and
        # consumes request quota against the repository.
        PollForSourceChanges = var.enable_eventbridge_trigger ? "false" : "true"
      }
    }
  }

  # All shard actions share run_order 1, which is what makes them run in parallel
  # rather than in sequence.
  stage {
    name = "Scan"

    dynamic "action" {
      for_each = local.shard_indices

      content {
        name            = "Shard${action.value}"
        category        = "Build"
        owner           = "AWS"
        provider        = "CodeBuild"
        version         = "1"
        run_order       = 1
        input_artifacts = ["source"]

        configuration = {
          ProjectName = aws_codebuild_project.shard.name
          EnvironmentVariables = jsonencode([
            {
              name  = "SHARD_INDEX"
              value = tostring(action.value)
              type  = "PLAINTEXT"
            },
            {
              name  = "PIPELINE_EXECUTION_ID"
              value = local.execution_id_ref
              type  = "PLAINTEXT"
            },
          ])
        }
      }
    }
  }

  # A single collect action. It takes only the source artifact as input, not the
  # shards' output: a CodeBuild action accepts at most 5 input artifacts, so
  # fanning N shard artifacts in would break above 5. The shard results are read
  # from S3 instead.
  stage {
    name = "Merge"

    action {
      name            = "Merge"
      category        = "Build"
      owner           = "AWS"
      provider        = "CodeBuild"
      version         = "1"
      run_order       = 1
      input_artifacts = ["source"]

      configuration = {
        ProjectName = aws_codebuild_project.merge.name
        EnvironmentVariables = jsonencode([
          {
            name  = "PIPELINE_EXECUTION_ID"
            value = local.execution_id_ref
            type  = "PLAINTEXT"
          },
        ])
      }
    }
  }

  tags = var.tags

  depends_on = [
    aws_iam_role_policy.pipeline,
    aws_s3_bucket_versioning.artifacts,
  ]
}

#
# Trigger
#

data "aws_iam_policy_document" "trigger_assume_role" {
  count = var.enable_eventbridge_trigger ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "trigger" {
  count = var.enable_eventbridge_trigger ? 1 : 0

  name               = "${var.name_prefix}-trigger"
  assume_role_policy = data.aws_iam_policy_document.trigger_assume_role[0].json

  tags = var.tags
}

data "aws_iam_policy_document" "trigger" {
  count = var.enable_eventbridge_trigger ? 1 : 0

  statement {
    sid       = "StartPipeline"
    effect    = "Allow"
    actions   = ["codepipeline:StartPipelineExecution"]
    resources = [aws_codepipeline.this.arn]
  }
}

resource "aws_iam_role_policy" "trigger" {
  count = var.enable_eventbridge_trigger ? 1 : 0

  name   = "${var.name_prefix}-trigger"
  role   = aws_iam_role.trigger[0].id
  policy = data.aws_iam_policy_document.trigger[0].json
}

resource "aws_cloudwatch_event_rule" "source_change" {
  count = var.enable_eventbridge_trigger ? 1 : 0

  name        = "${var.name_prefix}-source-change"
  description = "Starts the sharded ASH scan when ${var.source_branch} changes."

  event_pattern = jsonencode({
    source        = ["aws.codecommit"]
    "detail-type" = ["CodeCommit Repository State Change"]
    resources     = [var.codecommit_repository_arn]
    detail = {
      event         = ["referenceCreated", "referenceUpdated"]
      referenceType = ["branch"]
      referenceName = [var.source_branch]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "source_change" {
  count = var.enable_eventbridge_trigger ? 1 : 0

  rule      = aws_cloudwatch_event_rule.source_change[0].name
  target_id = "start-pipeline"
  arn       = aws_codepipeline.this.arn
  role_arn  = aws_iam_role.trigger[0].arn
}
