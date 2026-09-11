variable "name_prefix" {
  description = "Prefix applied to every resource name this module creates."
  type        = string
  default     = "ash-pr-gate"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,32}$", var.name_prefix))
    error_message = "name_prefix must be 1-33 characters of lowercase letters, digits, or hyphens."
  }
}

variable "codecommit_repository_arn" {
  description = <<-EOT
    Contract name: CodeCommitRepositoryArn.

    ARN of an **existing** CodeCommit repository to gate.

    This module never creates, modifies, or deletes the repository itself. It
    only reads from it and posts comments to its pull requests. The repository
    name is derived from this ARN, since the comment and approval APIs take a
    name while EventBridge filters on the ARN.
  EOT
  type        = string

  validation {
    condition     = can(regex("^arn:[a-z0-9-]+:codecommit:[a-z0-9-]+:[0-9]+:[\\w.-]+$", var.codecommit_repository_arn))
    error_message = "codecommit_repository_arn must be a CodeCommit repository ARN, for example arn:aws:codecommit:<region>:<account>:<repository-name>."
  }
}

variable "base_image_uri" {
  description = <<-EOT
    Fully qualified ASH image URI to build the gate image on top of, normally the
    `image_uri` output of the ash-image-pipeline module.

    This module does not run that image directly. Lambda cannot invoke it: the
    ASH image is not built from a Lambda base image and carries no runtime
    interface client. A small chained build adds one, plus
    git-remote-codecommit for cloning. See the README.
  EOT
  type        = string
}

variable "base_image_codebuild_project_arn" {
  description = <<-EOT
    ARN of the CodeBuild project that builds the base ASH image, from the
    ash-image-pipeline `codebuild_project_arn` output.

    When set, the gate image rebuild is chained off that project's successful
    builds, so the gate image is never left running on a base that has since been
    replaced. When null, no chaining rule is created and you must rebuild the gate
    image yourself after every base rebuild.
  EOT
  type        = string
  default     = null
}

variable "trigger_events" {
  description = <<-EOT
    Which pull-request events start a scan.

    The two defaults are the ones that change what would be merged. Adding
    pullRequestStatusChanged causes a rescan when a pull request is closed, which
    is normally wasted work.
  EOT
  type        = list(string)
  default     = ["pullRequestCreated", "pullRequestSourceBranchUpdated"]

  validation {
    condition     = length(var.trigger_events) > 0
    error_message = "trigger_events must name at least one event, or the gate never runs."
  }
}

variable "min_severity" {
  description = <<-EOT
    Lowest severity that counts as actionable for the gate, passed straight
    through to `ash scan --min-severity`.

    This is a FLOOR on what counts as actionable, so a lower value is a stricter
    gate. ASH compares `rank(finding) >= rank(min_severity)`, which makes the
    direction the opposite of what the name suggests:

      min_severity = "low"       low, medium and high findings all fail   strictest
      min_severity = "medium"    medium and high fail; low is ignored
      min_severity = "high"      only high fails; low and medium ignored  laxest

    Note "critical" and "high" share a rank in ASH's ladder, so they cannot be
    distinguished here. Findings below the threshold still appear in the
    pull-request comment; they just do not fail the gate.

    Defaults to "low", matching ASH, because on a security gate the surprise has
    to run toward failing a pull request for something you did not care about,
    never toward passing one that had findings. Raise it deliberately if that is
    what you want.

    The comparison is made by ASH, never in the handler. `ash scan` routes its exit
    code through _compute_exit_code, the same function `ash merge` uses, so this
    gate's verdict cannot disagree with a scan's over identical findings.
  EOT
  type        = string
  default     = "low"

  # Restricted to the values ASH's ladder actually ranks. ASH does not validate
  # this option itself -- it does `_SEVERITY_RANK.get(min_severity.lower(), 1)`,
  # so an unrecognized value silently becomes rank 1, which is "low". A typo would
  # therefore produce a working gate at a threshold nobody chose. This validation
  # is what turns that into an error.
  #
  # Worth knowing which way that fails: rank 1 is "low", the strictest setting, so
  # the silent substitution errs toward failing pull requests rather than passing
  # them. A fat-fingered "hihg" gets a gate that blocks on medium findings with no
  # explanation -- irritating and hard to diagnose, but it cannot quietly weaken a
  # gate. That is why this is a correctness-and-clarity fix rather than a
  # vulnerability.
  #
  # "info" is deliberately not accepted: ASH has no such rank, so it would be
  # silently reinterpreted as "low". "none" is not accepted either, because rank 0
  # skips the severity filter path entirely rather than meaning "everything".
  validation {
    condition     = contains(["critical", "high", "medium", "low"], lower(var.min_severity))
    error_message = "min_severity must be one of: critical, high, medium, low. ASH ranks no other value and would silently treat it as \"low\"."
  }
}

variable "fail_on_findings" {
  description = <<-EOT
    Pass `--fail-on-findings` to `ash scan`, so findings at or above min_severity
    produce the "findings" outcome.

    Passed explicitly rather than left to ASH's default, which falls back to the
    scan configuration. A base config carrying `fail_on_findings: false` would
    otherwise make every pull request report as passing while findings were still
    listed in the comment.

    Set false for a comment-only gate that reports but never blocks.
  EOT
  type        = bool
  default     = true
}

variable "create_approval_rule_template" {
  description = <<-EOT
    Create a CodeCommit approval rule template and associate it with the
    repository, so the gate's approval counts toward merging.

    Defaults to false because the association is a change to *your* repository's
    settings. The module still never creates or deletes the repository itself.
  EOT
  type        = bool
  default     = false
}

variable "manage_approval_state" {
  description = <<-EOT
    Let the Lambda call UpdatePullRequestApprovalState.

    Approval is only ever set to APPROVE, and only on a clean scan. A scan that
    fails to complete deliberately leaves the approval state untouched rather
    than revoking it, so an infrastructure failure cannot be mistaken for a
    security judgment.
  EOT
  type        = bool
  default     = false
}

variable "approval_rule_approvals_required" {
  description = "Number of approvals the created approval rule template requires. Used only when create_approval_rule_template is true."
  type        = number
  default     = 1

  validation {
    condition     = var.approval_rule_approvals_required >= 1 && var.approval_rule_approvals_required <= 100
    error_message = "approval_rule_approvals_required must be between 1 and 100."
  }
}

variable "lambda_timeout_seconds" {
  description = <<-EOT
    Lambda timeout. Capped at 900 by Lambda itself, which is the central
    limitation of this target: a repository whose clone plus scan exceeds fifteen
    minutes cannot be gated this way. See the README.
  EOT
  type        = number
  default     = 900

  validation {
    condition     = var.lambda_timeout_seconds >= 30 && var.lambda_timeout_seconds <= 900
    error_message = "lambda_timeout_seconds must be between 30 and 900. Lambda's hard maximum is 900."
  }
}

variable "lambda_memory_mb" {
  description = <<-EOT
    Lambda memory in MB. Lambda allocates CPU in proportion to memory, so this
    also sets how fast the scan runs; ASH is CPU-bound, so a low value costs wall
    clock against a fixed 900 second ceiling.
  EOT
  type        = number
  default     = 4096

  validation {
    condition     = var.lambda_memory_mb >= 512 && var.lambda_memory_mb <= 10240
    error_message = "lambda_memory_mb must be between 512 and 10240."
  }
}

variable "lambda_ephemeral_storage_mb" {
  description = <<-EOT
    Size of /tmp in MB, which is the only writable path in the execution
    environment and therefore holds both the cloned repository and the scan
    output. The 512 MB default is too small for most real repositories.
  EOT
  type        = number
  default     = 4096

  validation {
    condition     = var.lambda_ephemeral_storage_mb >= 512 && var.lambda_ephemeral_storage_mb <= 10240
    error_message = "lambda_ephemeral_storage_mb must be between 512 and 10240."
  }
}

variable "lambda_architecture" {
  description = "Lambda instruction set. Must match the architecture the base image was built for."
  type        = string
  default     = "x86_64"

  validation {
    condition     = contains(["x86_64", "arm64"], var.lambda_architecture)
    error_message = "lambda_architecture must be either x86_64 or arm64."
  }
}

variable "reserved_concurrent_executions" {
  description = <<-EOT
    Reserved concurrency for the gate function. -1 leaves it unreserved.

    Worth setting on a busy repository: every push to a pull request branch
    starts another full scan, and an unbounded fan-out of long CPU-heavy
    invocations is the likeliest way this target surprises someone on cost.
  EOT
  type        = number
  default     = -1
}

variable "ash_scan_extra_args" {
  description = <<-EOT
    Extra arguments appended to the `ash scan` command line, split on whitespace.

    `--changed-files-only` together with `--base-ref` is worth considering here:
    it scales scan time with the size of the change rather than the size of the
    repository, which is what makes the 900 second ceiling reachable.
  EOT
  type        = string
  default     = ""
}

variable "ash_offline_mode" {
  description = "Contract name: AshOfflineMode. Sets ASH_OFFLINE so ASH skips network tool installation. Requires an offline-built base image."
  type        = bool
  default     = false
}

variable "base_config_ssm_parameter_name" {
  description = "Contract name: AshBaseConfigYaml (indirect). SSM parameter the entrypoint reads to write .ash/.ash.yaml. Pass the ash-image-pipeline output."
  type        = string
  default     = null
}

variable "base_config_ssm_parameter_arn" {
  description = "ARN of the same parameter, used to scope ssm:GetParameter. Required whenever base_config_ssm_parameter_name is set."
  type        = string
  default     = null
}

variable "max_comment_chars" {
  description = <<-EOT
    Cap on the pull-request comment length, above which the comment is truncated.

    Defensive rather than a documented limit: the PostCommentForPullRequest API
    reference states no maximum for the content field, but a full ASH report can
    be very large and a rejected comment would lose the result entirely.
  EOT
  type        = number
  default     = 10000

  validation {
    condition     = var.max_comment_chars >= 500
    error_message = "max_comment_chars must be at least 500, or the comment cannot carry a verdict."
  }
}

variable "ecr_image_tag_mutability" {
  description = "Tag mutability for the gate image repository. MUTABLE, so the chained rebuild can republish the same tag."
  type        = string
  default     = "MUTABLE"

  validation {
    condition     = contains(["MUTABLE", "IMMUTABLE"], var.ecr_image_tag_mutability)
    error_message = "ecr_image_tag_mutability must be either MUTABLE or IMMUTABLE."
  }
}

variable "ecr_force_delete" {
  description = "Allow `terraform destroy` to delete the gate ECR repository while it still holds images."
  type        = bool
  default     = false
}

variable "image_tag" {
  description = "Tag for the gate image."
  type        = string
  default     = "latest"
}

variable "image_retention_count" {
  description = "How many gate images to keep before the lifecycle policy expires older ones."
  type        = number
  default     = 10
}

variable "build_timeout_minutes" {
  description = "CodeBuild timeout for the gate image build. Short, because it only layers two pip packages onto an existing image."
  type        = number
  default     = 30
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the Lambda and build logs, in days."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags applied to every resource this module creates."
  type        = map(string)
  default     = {}
}
