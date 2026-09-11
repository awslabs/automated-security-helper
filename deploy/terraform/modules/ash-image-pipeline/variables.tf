variable "name_prefix" {
  description = <<-EOT
    Prefix applied to every resource name this module creates. Keep it short:
    ECR repository names, CodeBuild project names, and IAM role names are all
    derived from it.
  EOT
  type        = string
  default     = "ash"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,32}$", var.name_prefix))
    error_message = "name_prefix must be 1-33 characters of lowercase letters, digits, or hyphens, and must start with a letter or digit."
  }
}

variable "ash_version" {
  description = <<-EOT
    Contract name: AshVersion.

    The ASH revision to build, as a git ref. A release tag, a branch name, or a
    full commit SHA are all accepted, because the build fetches the ref rather
    than using `git clone --branch` (which rejects a SHA).

    There is deliberately no default. ASH publishes no container image, so this
    build is the only source of the image every deployment target consumes;
    defaulting it would silently pin every deployment to whatever this module
    was written against.
  EOT
  type        = string

  validation {
    condition     = length(trimspace(var.ash_version)) > 0
    error_message = "ash_version must be a non-empty git ref (a release tag, branch, or full commit SHA)."
  }
}

variable "ash_repository_clone_url" {
  description = <<-EOT
    Git URL the image build clones ASH from. Override to build from a fork or
    from a mirror reachable inside a private network.
  EOT
  type        = string
  default     = "https://github.com/awslabs/automated-security-helper.git"
}

variable "ash_offline_mode" {
  description = <<-EOT
    Contract name: AshOfflineMode.

    When true, the image is built with the Dockerfile's OFFLINE=YES build
    argument, which vendors scanner rulesets into the image and sets ASH_OFFLINE
    so ASH skips network tool installation at scan time.

    Offline images are larger and take longer to build, but a scan does not
    depend on reaching an external package index or ruleset host.
  EOT
  type        = bool
  default     = false
}

variable "ash_image_target" {
  description = <<-EOT
    Which stage of the ASH Dockerfile to build. `non-root` runs ASH as an
    unprivileged user and is the default. `ci` runs as root, which some scanners
    and some CI environments require. `core` is the shared base and is rarely
    what you want directly.
  EOT
  type        = string
  default     = "non-root"

  validation {
    condition     = contains(["core", "ci", "non-root"], var.ash_image_target)
    error_message = "ash_image_target must be one of: core, ci, non-root."
  }
}

variable "target_architecture" {
  description = <<-EOT
    CPU architecture of the produced image. The build runs natively on a
    CodeBuild fleet of the same architecture rather than emulating, so this also
    selects the build compute image.

    Bedrock AgentCore Runtime requires arm64; its container contract admits no
    other architecture. The Fargate, Lambda, and CodeBuild targets accept
    either.
  EOT
  type        = string
  default     = "x86_64"

  validation {
    condition     = contains(["x86_64", "arm64"], var.target_architecture)
    error_message = "target_architecture must be either x86_64 or arm64."
  }
}

variable "image_tag" {
  description = <<-EOT
    Tag that deployment targets reference. The scheduled rebuild overwrites it,
    which is the point: targets pull a patched image without a Terraform change.

    Each build additionally pushes an immutable audit tag derived from
    ash_version, so a specific build remains addressable for rollback.
  EOT
  type        = string
  default     = "latest"
}

variable "ash_version_tag_prefix" {
  description = "Prefix for the per-build audit tag, which is this prefix followed by a sanitized ash_version."
  type        = string
  default     = "ash-"
}

variable "ecr_image_tag_mutability" {
  description = <<-EOT
    ECR tag mutability. This defaults to MUTABLE because the freshness model
    depends on it: the scheduled rebuild republishes the same image_tag so that
    running targets pick up patched scanners. IMMUTABLE would make every
    scheduled rebuild fail on the push.

    Set IMMUTABLE only if you also set enable_scheduled_rebuild = false and
    advance image_tag yourself on every deployment.
  EOT
  type        = string
  default     = "MUTABLE"

  validation {
    condition     = contains(["MUTABLE", "IMMUTABLE"], var.ecr_image_tag_mutability)
    error_message = "ecr_image_tag_mutability must be either MUTABLE or IMMUTABLE."
  }
}

variable "ecr_force_delete" {
  description = "Allow `terraform destroy` to delete the ECR repository while it still holds images."
  type        = bool
  default     = false
}

variable "ecr_kms_key_arn" {
  description = <<-EOT
    Customer managed KMS key ARN for ECR encryption at rest. When null, the
    repository uses AES256 server-side encryption with an Amazon-owned key. The
    same key is also given to the image build's CodeBuild project.

    Set this at the first apply. ECR fixes a repository's encryption
    configuration when the repository is created, so changing this value on a
    live deployment replaces the repository and deletes every image in it.

    Nothing in the plan says so, which is the part worth knowing: image_uri is
    built from the repository URL, and that URL is derived from account, Region,
    and repository name, so it survives the replacement unchanged and no
    deployment target consuming it plans a change. If the delete succeeds, the
    apply finishes green with every target pointed at a tag that no longer
    resolves. With the default ecr_force_delete = false the delete instead fails
    on a non-empty repository and the apply stops partway.

    To change the key later: set ecr_force_delete = true for that one apply, then
    run the bootstrap_command output to rebuild and republish the image.
  EOT
  type        = string
  default     = null
}

variable "image_retention_count" {
  description = <<-EOT
    How many images to keep. The lifecycle policy expires older images beyond
    this count, so daily rebuilds do not accumulate indefinitely. Keep enough
    history to roll back to a known-good build.
  EOT
  type        = number
  default     = 10

  validation {
    condition     = var.image_retention_count >= 1 && var.image_retention_count <= 1000
    error_message = "image_retention_count must be between 1 and 1000."
  }
}

variable "rebuild_schedule" {
  description = <<-EOT
    Contract name: RebuildSchedule.

    EventBridge schedule expression for the rebuild that keeps the image
    patched. Accepts `rate(...)` or `cron(...)`.

    A daily rebuild matters more for ASH than for a typical application image:
    ASH bundles third-party scanners and their rulesets, so a stale image scans
    with stale detections.
  EOT
  type        = string
  default     = "rate(1 day)"

  validation {
    condition     = can(regex("^(rate\\(|cron\\()", var.rebuild_schedule))
    error_message = "rebuild_schedule must be an EventBridge schedule expression beginning with rate( or cron(."
  }
}

variable "enable_scheduled_rebuild" {
  description = <<-EOT
    Whether to create the scheduled rebuild rule. Disable only if an external
    system already rebuilds and pushes the image; the first build still has to
    happen for anything to deploy.
  EOT
  type        = bool
  default     = true
}

variable "ash_base_config_yaml" {
  description = <<-EOT
    Contract name: AshBaseConfigYaml.

    A complete ASH configuration document (the contents of an `.ash.yaml`).
    When set, it is stored in an SSM parameter and the container entrypoint
    materializes it to `.ash/.ash.yaml` at start, exporting ASH_CONFIG to point
    at it.

    It travels through SSM rather than a container environment variable because
    AgentCore Runtime offers only a flat environment map and a real ASH config
    does not comfortably fit there.

    Size ceiling: SSM caps a parameter value at 4 KB on the Standard tier and
    8 KB on Advanced, and 8 KB is a hard ceiling with no higher tier. A config
    larger than that has to be baked into the image instead.
  EOT
  type        = string
  default     = null

  validation {
    condition     = var.ash_base_config_yaml == null || length(var.ash_base_config_yaml) <= 8192
    error_message = "ash_base_config_yaml exceeds 8192 bytes, the hard maximum for an SSM Advanced-tier parameter value. Bake a config this large into the image instead."
  }
}

variable "ssm_parameter_tier" {
  description = <<-EOT
    Tier for the SSM parameter holding ash_base_config_yaml.

    Intelligent-Tiering is the default: Parameter Store selects Advanced only
    when the value exceeds the Standard 4 KB limit, so a small config is not
    billed at Advanced rates and a large one still stores successfully.

    Note that a parameter can be upgraded from Standard to Advanced but never
    downgraded. Shrinking a config below 4 KB does not move the parameter back.
  EOT
  type        = string
  default     = "Intelligent-Tiering"

  validation {
    condition     = contains(["Standard", "Advanced", "Intelligent-Tiering"], var.ssm_parameter_tier)
    error_message = "ssm_parameter_tier must be one of: Standard, Advanced, Intelligent-Tiering."
  }
}

variable "build_compute_type" {
  description = <<-EOT
    CodeBuild compute type. When null, the module selects a default sized for an
    ASH image build, which compiles and installs a large set of scanners:
    BUILD_GENERAL1_LARGE for x86_64 and BUILD_GENERAL1_LARGE for arm64.
  EOT
  type        = string
  default     = null
}

variable "build_image_override" {
  description = <<-EOT
    CodeBuild managed image identifier. When null, the module selects the
    current Amazon Linux 2023 standard image matching target_architecture.
  EOT
  type        = string
  default     = null
}

variable "build_timeout_minutes" {
  description = <<-EOT
    CodeBuild timeout. An offline ASH image build installs many scanners and
    their rulesets, so this is deliberately generous.
  EOT
  type        = number
  default     = 120

  validation {
    condition     = var.build_timeout_minutes >= 5 && var.build_timeout_minutes <= 480
    error_message = "build_timeout_minutes must be between 5 and 480."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the image build logs, in days."
  type        = number
  default     = 30

  validation {
    condition = contains(
      [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653],
      var.log_retention_days
    )
    error_message = "log_retention_days must be a retention value CloudWatch Logs accepts (for example 1, 7, 30, 90, 365)."
  }
}

variable "tags" {
  description = "Tags applied to every resource this module creates."
  type        = map(string)
  default     = {}
}
