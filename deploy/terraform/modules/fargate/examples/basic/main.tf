# ASH's MCP server on ECS Fargate behind an internal Application Load Balancer.
#
# Region and credentials come from the ambient environment.
provider "aws" {}

locals {
  vpc_cidr = "10.0.0.0/16"
}

# aws-ia's VPC module. This is the one place in these deployment targets where an
# aws-ia module genuinely fits: it is verified, actively maintained, and its
# output surface covers what the service needs.
module "vpc" {
  # CKV_TF_1 asks for a commit hash, which only a git source can carry. This is a
  # Terraform Registry source, where the pin is the version constraint below, and
  # the registry protocol offers no revision to name instead.
  #checkov:skip=CKV_TF_1:Registry sources are pinned by version constraint, not commit hash; there is no revision to name for a registry module.
  source  = "aws-ia/vpc/aws"
  version = "~> 4.9"

  name       = "ash-mcp-example"
  cidr_block = local.vpc_cidr
  az_count   = 2

  subnets = {
    # The NAT gateway is what gives the tasks a route to ECR, CloudWatch Logs,
    # SSM, and Secrets Manager. Interface endpoints would work too and would keep
    # the traffic off the internet entirely.
    public = {
      netmask                   = 24
      nat_gateway_configuration = "single_az"
    }
    private = {
      netmask                 = 24
      connect_to_public_natgw = true
    }
  }
}

module "ash_image" {
  source = "../../../ash-image-pipeline"

  name_prefix         = "ash-mcp-fargate"
  ash_version         = "v3.6.0"
  target_architecture = "x86_64"
  rebuild_schedule    = "rate(1 day)"

  ash_base_config_yaml = <<-EOT
    reporters:
      sarif:
        enabled: true
  EOT
}

module "ash_mcp" {
  source = "../.."

  name_prefix         = "ash-mcp"
  container_image_uri = module.ash_image.image_uri

  vpc_id = module.vpc.vpc_attributes.id

  # natgw_subnet_ids is the flat list of private subnets that actually have a
  # route to the NAT gateway, so tasks placed here can reach ECR.
  service_subnet_ids = module.vpc.natgw_subnet_ids

  # An internal load balancer belongs in private subnets. Application Load
  # Balancer requires at least two Availability Zones, which az_count = 2 gives.
  internal       = true
  alb_subnet_ids = module.vpc.natgw_subnet_ids

  # Nothing reaches the listener until something is allowed to. Callers inside
  # this VPC only.
  ingress_cidr_blocks = [local.vpc_cidr]

  # Must match the image architecture.
  cpu_architecture = "X86_64"

  base_config_ssm_parameter_name = module.ash_image.base_config_ssm_parameter_name
  base_config_ssm_parameter_arn  = module.ash_image.base_config_ssm_parameter_arn

  # Leave stateless on. The load balancer may route consecutive requests from one
  # client to different tasks, and a stateful server on the task that did not
  # issue the session answers 404 "Session not found".
  mcp_stateless_http = true

  # No mcp_allowed_host entries are needed here: the module already passes the
  # load balancer's own DNS name to ASH's --allowed-host, which keeps the MCP
  # SDK's DNS-rebinding protection on. Add a value here only for an additional
  # name that fronts the load balancer, such as a Route 53 alias.

  tags = {
    Project = "ash-example"
  }
}

output "mcp_endpoint_url" {
  description = "POST MCP requests here from inside the VPC."
  value       = module.ash_mcp.mcp_endpoint_url
}

output "allowed_hosts" {
  description = "Host header values ASH accepts. A client dialing anything else is rejected."
  value       = module.ash_mcp.allowed_hosts
}

output "run_the_first_build" {
  description = "The service cannot pull an image until this has succeeded."
  value       = module.ash_image.bootstrap_command
}
