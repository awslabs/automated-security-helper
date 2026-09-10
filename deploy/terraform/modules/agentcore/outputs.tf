output "agent_runtime_arn" {
  description = "ARN of the AgentCore runtime. Clients pass this to InvokeAgentRuntime."
  value       = aws_bedrockagentcore_agent_runtime.this.agent_runtime_arn
}

output "agent_runtime_id" {
  description = "Identifier of the AgentCore runtime."
  value       = aws_bedrockagentcore_agent_runtime.this.agent_runtime_id
}

output "agent_runtime_name" {
  description = "Name of the AgentCore runtime."
  value       = aws_bedrockagentcore_agent_runtime.this.agent_runtime_name
}

output "agent_runtime_version" {
  description = "Version of the runtime that this apply produced."
  value       = aws_bedrockagentcore_agent_runtime.this.agent_runtime_version
}

output "agent_runtime_endpoint_arn" {
  description = "ARN of the runtime endpoint, or null when create_endpoint is false."
  value       = var.create_endpoint ? aws_bedrockagentcore_agent_runtime_endpoint.this[0].agent_runtime_endpoint_arn : null
}

output "execution_role_arn" {
  description = "ARN of the execution role AgentCore assumes to run the container."
  value       = aws_iam_role.runtime.arn
}

output "execution_role_name" {
  description = "Name of the execution role, for attaching further policies."
  value       = aws_iam_role.runtime.name
}

output "auth_header_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the MCP auth header value, or null when mcp_auth_header_value was not set."
  value       = local.manage_auth_secret ? aws_secretsmanager_secret.auth_header[0].arn : null
}

output "log_group_name" {
  description = <<-EOT
    Service-managed CloudWatch Logs group AgentCore writes runtime logs to. This
    module does not create the group; AgentCore does, using the execution role.

    Read it to discover the Host header AgentCore sends, which is what
    mcp_allowed_host would need to match.
  EOT
  value       = "/aws/bedrock-agentcore/runtimes/${local.runtime_name}"
}

output "request_header_allowlist" {
  description = "Headers AgentCore forwards to the container. Empty unless mcp_auth_header_name is set, since AgentCore drops anything not listed."
  value       = local.request_header_allowlist
}
