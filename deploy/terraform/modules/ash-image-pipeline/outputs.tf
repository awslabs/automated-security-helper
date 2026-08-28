output "image_uri" {
  description = <<-EOT
    Fully qualified image URI every deployment target should consume. This is the
    moving tag: the scheduled rebuild republishes it, so targets pick up patched
    scanners without a Terraform change.

    This URI resolves only after the build has run at least once. See
    bootstrap_command.
  EOT
  value       = local.image_uri
}

output "ecr_repository_url" {
  description = "Repository URL without a tag, for constructing references to the per-build audit tags."
  value       = aws_ecr_repository.this.repository_url
}

output "ecr_repository_arn" {
  description = "ARN of the ECR repository, for granting pull permission to a deployment target."
  value       = aws_ecr_repository.this.arn
}

output "ecr_repository_name" {
  description = "Name of the ECR repository."
  value       = aws_ecr_repository.this.name
}

output "codebuild_project_name" {
  description = "Name of the CodeBuild project that builds the image."
  value       = aws_codebuild_project.this.name
}

output "codebuild_project_arn" {
  description = "ARN of the CodeBuild project, for chaining another build off its completion."
  value       = aws_codebuild_project.this.arn
}

output "base_config_ssm_parameter_name" {
  description = <<-EOT
    Name of the SSM parameter holding the base ASH configuration, or null when
    ash_base_config_yaml was not set. Pass this to a deployment target so its
    container entrypoint materializes the config at start.
  EOT
  value       = local.manage_config_parameter ? aws_ssm_parameter.base_config[0].name : null
}

output "base_config_ssm_parameter_arn" {
  description = "ARN of the base config SSM parameter, or null when ash_base_config_yaml was not set. Use it to scope ssm:GetParameter on a target's role."
  value       = local.manage_config_parameter ? aws_ssm_parameter.base_config[0].arn : null
}

output "bootstrap_command" {
  description = <<-EOT
    Command that runs the first image build.

    Read this as a required deployment step, not a convenience. ASH publishes no
    container image, so the repository is empty until this build succeeds and any
    target pointed at image_uri will fail to pull. Terraform cannot perform the
    build itself: it creates the build project, and running a build is an action
    rather than a resource.

    The scheduled rebuild would eventually populate the repository on its own,
    but only after the schedule first fires.
  EOT
  value       = "aws codebuild start-build --project-name ${aws_codebuild_project.this.name} --region ${data.aws_region.current.region}"
}

output "build_log_group_name" {
  description = "CloudWatch Logs group holding the image build logs."
  value       = aws_cloudwatch_log_group.build.name
}
