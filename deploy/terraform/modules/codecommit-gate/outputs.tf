output "function_name" {
  description = "Name of the gate Lambda function."
  value       = aws_lambda_function.gate.function_name
}

output "function_arn" {
  description = "ARN of the gate Lambda function."
  value       = aws_lambda_function.gate.arn
}

output "role_arn" {
  description = "ARN of the role the gate runs as. Every CodeCommit permission it holds is scoped to the supplied repository."
  value       = aws_iam_role.gate.arn
}

output "gate_image_uri" {
  description = "Image URI the Lambda runs, produced by the chained build in this module."
  value       = local.gate_image_uri
}

output "gate_ecr_repository_url" {
  description = "ECR repository holding the gate image."
  value       = aws_ecr_repository.gate.repository_url
}

output "gate_image_codebuild_project_name" {
  description = "CodeBuild project that builds the gate image."
  value       = aws_codebuild_project.gate_image.name
}

output "bootstrap_command" {
  description = <<-EOT
    Command that builds the gate image for the first time.

    Required, and it has an ordering constraint: the shared ASH image must
    already exist, because this build pulls it as a base. Run the
    ash-image-pipeline bootstrap first, then this one.
  EOT
  value       = "aws codebuild start-build --project-name ${aws_codebuild_project.gate_image.name} --region ${data.aws_region.current.region}"
}

output "event_rule_arn" {
  description = "ARN of the EventBridge rule that triggers a scan."
  value       = aws_cloudwatch_event_rule.pull_request.arn
}

output "repository_name" {
  description = "Repository name derived from codecommit_repository_arn, used by the comment and approval APIs."
  value       = local.repository_name
}

output "approval_rule_template_name" {
  description = "Name of the created approval rule template, or null when create_approval_rule_template is false."
  value       = var.create_approval_rule_template ? aws_codecommit_approval_rule_template.this[0].name : null
}

output "log_group_name" {
  description = "CloudWatch Logs group the gate writes to."
  value       = aws_cloudwatch_log_group.gate.name
}
