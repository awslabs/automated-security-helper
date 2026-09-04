output "pipeline_name" {
  description = "Name of the pipeline."
  value       = aws_codepipeline.this.name
}

output "pipeline_arn" {
  description = "ARN of the pipeline."
  value       = aws_codepipeline.this.arn
}

output "shard_count" {
  description = "Number of parallel shards. Every index from 0 to this minus 1 runs exactly once."
  value       = var.shard_count
}

output "shard_project_name" {
  description = "CodeBuild project that runs each shard. One project serves all shard actions; the index arrives as a per-action environment variable."
  value       = aws_codebuild_project.shard.name
}

output "merge_project_name" {
  description = "CodeBuild project that merges the shards and forms the verdict."
  value       = aws_codebuild_project.merge.name
}

output "artifact_bucket_name" {
  description = "Bucket holding both pipeline artifacts and per-execution shard results."
  value       = aws_s3_bucket.artifacts.bucket
}

output "results_prefix" {
  description = "Key prefix under which results are written, as <prefix>/<pipeline-execution-id>/shard-<i>/ and <prefix>/<pipeline-execution-id>/merged/."
  value       = var.results_prefix
}

output "merged_results_location_template" {
  description = "Where the merged results for an execution land. Substitute the pipeline execution id."
  value       = "s3://${aws_s3_bucket.artifacts.bucket}/${var.results_prefix}/<pipeline-execution-id>/merged/"
}

output "min_severity" {
  description = "Threshold passed to `ash merge --min-severity`. ASH evaluates it; this module does not."
  value       = var.min_severity
}

output "fail_on_findings" {
  description = "Whether `--fail-on-findings` is passed to `ash merge`, making actionable findings fail the pipeline."
  value       = var.fail_on_findings
}

output "shard_log_group_name" {
  description = "CloudWatch Logs group for the shard builds."
  value       = aws_cloudwatch_log_group.shard.name
}

output "merge_log_group_name" {
  description = "CloudWatch Logs group for the merge build, which is where the verdict is printed."
  value       = aws_cloudwatch_log_group.merge.name
}

output "pipeline_role_arn" {
  description = "ARN of the pipeline's service role."
  value       = aws_iam_role.pipeline.arn
}

output "shard_role_arn" {
  description = "ARN of the role shard builds run as."
  value       = aws_iam_role.shard.arn
}

output "merge_role_arn" {
  description = "ARN of the role the merge build runs as."
  value       = aws_iam_role.merge.arn
}
