# Gates pull requests on an existing CodeCommit repository with an ASH scan.
#
# Region and credentials come from the ambient environment.
provider "aws" {}

variable "codecommit_repository_arn" {
  description = <<-EOT
    ARN of the CodeCommit repository to gate. It must already exist: neither this
    example nor the module creates or deletes a repository.
  EOT
  type        = string
}

module "ash_image" {
  source = "../../../ash-image-pipeline"

  name_prefix         = "ash-pr-gate"
  ash_version         = "v3.6.0"
  target_architecture = "x86_64"
  rebuild_schedule    = "rate(1 day)"

  ash_base_config_yaml = <<-EOT
    reporters:
      sarif:
        enabled: true
  EOT
}

module "ash_pr_gate" {
  source = "../.."

  name_prefix               = "ash-pr-gate"
  codecommit_repository_arn = var.codecommit_repository_arn

  base_image_uri = module.ash_image.image_uri

  # Chains the gate image rebuild off the shared image rebuild, so the daily
  # refresh reaches this target too instead of leaving it on a stale base.
  base_image_codebuild_project_arn = module.ash_image.codebuild_project_arn

  base_config_ssm_parameter_name = module.ash_image.base_config_ssm_parameter_name
  base_config_ssm_parameter_arn  = module.ash_image.base_config_ssm_parameter_arn

  # Must match the base image architecture.
  lambda_architecture = "x86_64"

  blocking_severities = ["critical", "high"]

  # Scan only what the pull request changes. This is what keeps a real repository
  # inside Lambda's hard 900 second ceiling, since it scales with the size of the
  # change rather than the size of the repository.
  ash_scan_extra_args = "--changed-files-only --base-ref origin/main"

  # One scan per pull-request push, so an active repository cannot fan out into
  # an unbounded number of concurrent CPU-heavy invocations.
  reserved_concurrent_executions = 5

  tags = {
    Project = "ash-example"
  }
}

output "build_the_images_in_this_order" {
  description = "The gate image build pulls the shared image as its base, so the order matters."
  value = [
    module.ash_image.bootstrap_command,
    module.ash_pr_gate.bootstrap_command,
  ]
}

output "gate_function_name" {
  description = "Name of the gate Lambda."
  value       = module.ash_pr_gate.function_name
}

output "log_group_name" {
  description = "Where to look when a scan reports an error outcome."
  value       = module.ash_pr_gate.log_group_name
}
