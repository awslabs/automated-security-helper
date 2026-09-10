# ASH's MCP server on Bedrock AgentCore Runtime.
#
# Region and credentials come from the ambient environment.
provider "aws" {}

# AgentCore requires arm64. Its container contract admits no other
# architecture, so the image has to be built on an arm64 fleet.
module "ash_image" {
  source = "../../../ash-image-pipeline"

  name_prefix         = "ash-agentcore"
  ash_version         = "v3.6.0"
  target_architecture = "arm64"
  rebuild_schedule    = "rate(1 day)"

  ash_base_config_yaml = <<-EOT
    reporters:
      sarif:
        enabled: true
  EOT
}

module "ash_agentcore" {
  source = "../.."

  # Underscores, not hyphens: AgentCore runtime names reject a hyphen.
  name_prefix = "ash_agentcore"

  container_image_uri = module.ash_image.image_uri

  # Narrow the execution role to the one repository it pulls from, rather than
  # every repository in the account.
  ecr_pull_resource_arns = [module.ash_image.ecr_repository_arn]

  base_config_ssm_parameter_name = module.ash_image.base_config_ssm_parameter_name
  base_config_ssm_parameter_arn  = module.ash_image.base_config_ssm_parameter_arn

  # Leave stateless on. AgentCore injects an Mcp-Session-Id the server never
  # issued; a stateful server answers that with 404 "Session not found".
  mcp_stateless_http = true

  tags = {
    Project = "ash-example"
  }
}

output "agent_runtime_arn" {
  description = "Pass this to InvokeAgentRuntime."
  value       = module.ash_agentcore.agent_runtime_arn
}

output "run_the_first_build" {
  description = "The runtime cannot pull an image until this has succeeded."
  value       = module.ash_image.bootstrap_command
}

output "log_group_name" {
  description = "Where AgentCore writes the runtime's logs."
  value       = module.ash_agentcore.log_group_name
}
