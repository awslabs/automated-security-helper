variable "name_prefix" {
  description = "Prefix applied to every resource name this module creates."
  type        = string
  default     = "ash-scan"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,32}$", var.name_prefix))
    error_message = "name_prefix must be 1-33 characters of lowercase letters, digits, or hyphens."
  }
}

variable "codecommit_repository_arn" {
  description = <<-EOT
    Contract name: CodeCommitRepositoryArn.

    ARN of the **existing** CodeCommit repository the pipeline scans. This module
    never creates, modifies, or deletes the repository; it reads from it as a
    pipeline source.
  EOT
  type        = string

  validation {
    condition     = can(regex("^arn:[a-z0-9-]+:codecommit:[a-z0-9-]+:[0-9]+:[\\w.-]+$", var.codecommit_repository_arn))
    error_message = "codecommit_repository_arn must be a CodeCommit repository ARN, for example arn:aws:codecommit:<region>:<account>:<repository-name>."
  }
}

variable "source_branch" {
  description = "Branch the pipeline scans."
  type        = string
  default     = "main"
}

variable "container_image_uri" {
  description = <<-EOT
    Fully qualified ASH image URI, normally the `image_uri` output of the
    ash-image-pipeline module.

    Used as the CodeBuild **environment image** for both the shard and merge
    actions, so `ash` is on PATH with no Docker-in-Docker and no privileged
    build. Because the image is private, CodeBuild pulls it with the project's
    service role.
  EOT
  type        = string
}

variable "shard_count" {
  description = <<-EOT
    Contract name: ShardCount.

    How many parallel shards the scan is split across. Each shard runs
    `ash scan --shard-index <i> --shard-count <n>` with a zero-based index, and
    every index from 0 to shard_count - 1 runs exactly once.

    All shards occupy one pipeline stage. CodePipeline permits up to 100 parallel
    actions per stage and that quota is not adjustable, so 100 is the ceiling
    here. Note that shard results travel through S3 rather than as pipeline
    artifacts, which is what allows more than five.
  EOT
  type        = number
  default     = 4

  validation {
    condition     = var.shard_count >= 1 && var.shard_count <= 100
    error_message = "shard_count must be between 1 and 100. CodePipeline allows at most 100 parallel actions in a stage, and that quota is not adjustable."
  }
}

variable "blocking_severities" {
  description = <<-EOT
    Severities that fail the pipeline, evaluated by the merge action against the
    merged results. Everything else is still reported.
  EOT
  type        = list(string)
  default     = ["critical", "high"]

  validation {
    condition = length(setsubtract(
      [for severity in var.blocking_severities : lower(severity)],
      ["critical", "high", "medium", "low", "info"]
    )) == 0
    error_message = "blocking_severities may contain only: critical, high, medium, low, info."
  }
}

variable "enable_eventbridge_trigger" {
  description = <<-EOT
    Trigger the pipeline from an EventBridge rule on repository state change,
    rather than by CodePipeline polling the repository.

    EventBridge is the recommended pattern: polling adds latency and consumes
    request quota against the repository.
  EOT
  type        = bool
  default     = true
}

variable "ash_offline_mode" {
  description = "Contract name: AshOfflineMode. Sets ASH_OFFLINE so ASH skips network tool installation. Requires an offline-built image."
  type        = bool
  default     = false
}

variable "base_config_ssm_parameter_name" {
  description = <<-EOT
    Contract name: AshBaseConfigYaml (indirect).

    SSM parameter holding the base ASH configuration. Both the shard and merge
    actions read it through the image entrypoint, so every shard scans with the
    same configuration — which is what makes the shards' results mergeable.
  EOT
  type        = string
  default     = null
}

variable "base_config_ssm_parameter_arn" {
  description = "ARN of the same parameter, used to scope ssm:GetParameter. Required whenever base_config_ssm_parameter_name is set."
  type        = string
  default     = null
}

variable "build_compute_type" {
  description = "CodeBuild compute type for the shard and merge actions. Scanners are CPU-bound, so a larger type shortens wall-clock time per shard."
  type        = string
  default     = "BUILD_GENERAL1_LARGE"
}

variable "build_environment_type" {
  description = "CodeBuild environment type. Must match the architecture container_image_uri was built for: LINUX_CONTAINER for x86_64, ARM_CONTAINER for arm64."
  type        = string
  default     = "LINUX_CONTAINER"

  validation {
    condition     = contains(["LINUX_CONTAINER", "ARM_CONTAINER"], var.build_environment_type)
    error_message = "build_environment_type must be either LINUX_CONTAINER or ARM_CONTAINER."
  }
}

variable "shard_build_timeout_minutes" {
  description = "Timeout for each shard action. CodeBuild's own action timeout ceiling in CodePipeline is 36 hours, so this is the practical limit rather than a hard one."
  type        = number
  default     = 120

  validation {
    condition     = var.shard_build_timeout_minutes >= 5 && var.shard_build_timeout_minutes <= 480
    error_message = "shard_build_timeout_minutes must be between 5 and 480."
  }
}

variable "merge_build_timeout_minutes" {
  description = "Timeout for the merge action, which only reads and combines results."
  type        = number
  default     = 60

  validation {
    condition     = var.merge_build_timeout_minutes >= 5 && var.merge_build_timeout_minutes <= 480
    error_message = "merge_build_timeout_minutes must be between 5 and 480."
  }
}

variable "results_prefix" {
  description = "S3 key prefix under which per-execution shard results and merged output are stored."
  type        = string
  default     = "shard-results"
}

variable "results_retention_days" {
  description = <<-EOT
    Days before shard results and merged output expire. Scan output accumulates
    per pipeline execution, so leaving it forever is a quiet cost.
  EOT
  type        = number
  default     = 90

  validation {
    condition     = var.results_retention_days >= 1
    error_message = "results_retention_days must be at least 1."
  }
}

variable "artifact_bucket_force_destroy" {
  description = "Allow `terraform destroy` to delete the artifact and results bucket while it still holds objects."
  type        = bool
  default     = false
}

variable "kms_key_arn" {
  description = <<-EOT
    Customer managed KMS key ARN for the artifact and results bucket and for the
    pipeline's artifact encryption. When null, SSE-S3 with an Amazon-managed key
    is used.
  EOT
  type        = string
  default     = null
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the shard and merge build logs, in days."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags applied to every resource this module creates."
  type        = map(string)
  default     = {}
}
