# Sharded ASH scan across 8 parallel CodeBuild jobs, then a merge that decides
# pass or fail.
#
# Region and credentials come from the ambient environment.
provider "aws" {}

variable "codecommit_repository_arn" {
  description = <<-EOT
    ARN of the CodeCommit repository to scan. It must already exist: neither this
    example nor the module creates or deletes a repository.
  EOT
  type        = string
}

module "ash_image" {
  source = "../../../ash-image-pipeline"

  name_prefix         = "ash-scan-pipeline"
  ash_version         = "v3.6.0"
  target_architecture = "x86_64"
  rebuild_schedule    = "rate(1 day)"

  # Every shard reads this same configuration, which is what makes their partial
  # results mergeable.
  ash_base_config_yaml = <<-EOT
    reporters:
      sarif:
        enabled: true
  EOT
}

module "ash_scan_pipeline" {
  source = "../.."

  name_prefix               = "ash-scan"
  codecommit_repository_arn = var.codecommit_repository_arn
  source_branch             = "main"

  # Used as the CodeBuild environment image, so `ash` is on PATH with no
  # Docker-in-Docker and no privileged build.
  container_image_uri = module.ash_image.image_uri

  # 8 is above the 5-input-artifact limit on a CodeBuild action, which is exactly
  # why shard results travel through S3 rather than as pipeline artifacts.
  shard_count = 8

  # Must match the image architecture.
  build_environment_type = "LINUX_CONTAINER"

  base_config_ssm_parameter_name = module.ash_image.base_config_ssm_parameter_name
  base_config_ssm_parameter_arn  = module.ash_image.base_config_ssm_parameter_arn

  # Evaluated by the merge action against the merged results, never against an
  # individual shard's exit code.
  blocking_severities = ["critical", "high"]

  tags = {
    Project = "ash-example"
  }
}

output "pipeline_name" {
  description = "Name of the pipeline."
  value       = module.ash_scan_pipeline.pipeline_name
}

output "run_the_first_build" {
  description = "The shard and merge actions cannot pull their environment image until this has succeeded."
  value       = module.ash_image.bootstrap_command
}

output "where_the_verdict_is_printed" {
  description = "The merge build's log group. The pass or fail decision is printed here."
  value       = module.ash_scan_pipeline.merge_log_group_name
}

output "merged_results_location_template" {
  description = "Where merged results land for a given execution."
  value       = module.ash_scan_pipeline.merged_results_location_template
}
