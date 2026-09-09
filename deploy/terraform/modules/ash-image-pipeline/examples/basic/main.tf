# Builds the ASH image into a new ECR repository in the caller's own account,
# and rebuilds it daily so bundled scanners and rulesets stay current.
#
# Region and credentials come from the ambient environment (AWS_REGION, or a
# profile), so this example is portable across accounts and partitions.
provider "aws" {}

module "ash_image" {
  source = "../.."

  name_prefix = "ash-example"

  # Pin the revision. There is no default: the image this builds is the only
  # one any deployment target can consume, so the pin is a deliberate choice.
  ash_version = "v3.6.0"

  # Daily rebuild. ASH bundles third-party scanners, so a stale image scans
  # with stale detections even when ASH itself has not changed.
  rebuild_schedule = "rate(1 day)"

  # A small base configuration, stored in SSM and written to .ash/.ash.yaml when
  # a container starts.
  ash_base_config_yaml = <<-EOT
    reporters:
      sarif:
        enabled: true
      markdown:
        enabled: true
  EOT

  tags = {
    Project = "ash-example"
  }
}

output "image_uri" {
  description = "Pass this to a deployment target module."
  value       = module.ash_image.image_uri
}

output "run_the_first_build" {
  description = "The repository is empty until this runs. Deployments cannot pull before it succeeds."
  value       = module.ash_image.bootstrap_command
}

output "codebuild_project_name" {
  description = "Build project name, for starting a build by hand."
  value       = module.ash_image.codebuild_project_name
}
