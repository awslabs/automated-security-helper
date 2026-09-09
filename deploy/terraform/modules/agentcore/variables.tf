variable "name_prefix" {
  description = "Prefix applied to created resource names, including the agent runtime name when agent_runtime_name is null."
  type        = string
  default     = "ash"

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_]{0,32}$", var.name_prefix))
    error_message = "name_prefix must start with a letter and contain only letters, digits, and underscores, because AgentCore runtime names do not accept hyphens."
  }
}

variable "agent_runtime_name" {
  description = <<-EOT
    Name of the AgentCore runtime. When null, `<name_prefix>_mcp` is used.

    AgentCore runtime names accept letters, digits, and underscores only. A
    hyphen is rejected, which is why this module's name_prefix validation
    differs from the other modules'.

    Differs, not "stricter": the two constraints are not ordered, so neither
    accepts a superset of the other. This module accepts uppercase and an
    underscore and rejects a hyphen; the others accept a hyphen and a leading
    digit and reject uppercase and an underscore. `ash-mcp` is valid elsewhere and
    invalid here, and `ash_MCP` is the reverse.
  EOT
  type        = string
  default     = null

  validation {
    condition     = var.agent_runtime_name == null || can(regex("^[a-zA-Z][a-zA-Z0-9_]{0,47}$", var.agent_runtime_name))
    error_message = "agent_runtime_name must start with a letter and contain only letters, digits, and underscores."
  }
}

variable "container_image_uri" {
  description = <<-EOT
    Fully qualified ECR image URI to run, normally the `image_uri` output of the
    ash-image-pipeline module.

    The image must be arm64. AgentCore Runtime's container contract requires it
    and admits no other architecture, so build the image with
    `target_architecture = "arm64"`.
  EOT
  type        = string
}

variable "ecr_pull_resource_arns" {
  description = <<-EOT
    ECR repository ARNs the execution role may pull from. When null, the role is
    scoped to every repository in the current account and Region, matching the
    scope in the AgentCore documentation's own example execution role.

    Pass the ash-image-pipeline `ecr_repository_arn` output to narrow it to the
    one repository that matters.
  EOT
  type        = list(string)
  default     = null
}

variable "network_mode" {
  description = <<-EOT
    AgentCore network mode. PUBLIC gives the runtime managed egress. VPC places
    egress in your VPC and requires vpc_subnet_ids and vpc_security_group_ids.
  EOT
  type        = string
  default     = "PUBLIC"

  validation {
    condition     = contains(["PUBLIC", "VPC"], var.network_mode)
    error_message = "network_mode must be either PUBLIC or VPC."
  }
}

variable "vpc_subnet_ids" {
  description = "Subnet IDs for network_mode = \"VPC\". Ignored when network_mode is PUBLIC."
  type        = list(string)
  default     = []
}

variable "vpc_security_group_ids" {
  description = "Security group IDs for network_mode = \"VPC\". Ignored when network_mode is PUBLIC."
  type        = list(string)
  default     = []
}

variable "mcp_stateless_http" {
  description = <<-EOT
    Contract name: McpStatelessHttp.

    Defaults to true, and on this target that default is close to mandatory.

    AgentCore injects its own `Mcp-Session-Id` header on every request, including
    the first. Measured against ASH directly: given a session id the server never
    issued, a stateful MCP server returns 404 "Session not found" while a
    stateless server returns 200. The platform contract states the server must
    accept the platform-provided session id rather than reject it.

    Setting this to false is supported by AgentCore for servers that need
    elicitation or sampling, but ASH's MCP server does not use either, so on this
    target false buys nothing and breaks every request.
  EOT
  type        = bool
  default     = true
}

variable "mcp_mount_path" {
  description = <<-EOT
    Contract name: McpMountPath.

    HTTP path the MCP transport listens on. AgentCore routes MCP traffic to
    `POST /mcp` and nothing else, so changing this away from /mcp makes the
    runtime unreachable on this target. It stays configurable only so the
    variable surface matches the other targets.
  EOT
  type        = string
  default     = "/mcp"
}

variable "mcp_auth_header_name" {
  description = <<-EOT
    Contract name: McpAuthHeaderName.

    Name of a static HTTP header ASH requires on every MCP request. When set,
    this module automatically adds the header to the runtime's
    request_header_allowlist, because AgentCore does not forward a header to the
    container unless it is allowlisted; without that, ASH would reject every
    request for a missing header that the platform had silently dropped.

    This is a shared-secret check, not identity. For real authorization use
    jwt_authorizer_discovery_url.
  EOT
  type        = string
  default     = null

  validation {
    condition     = var.mcp_auth_header_name == null || can(regex("^[A-Za-z][A-Za-z0-9_-]{0,255}$", var.mcp_auth_header_name))
    error_message = "mcp_auth_header_name must match AgentCore's allowlist pattern: start with a letter, then letters, digits, underscores, or hyphens, up to 256 characters."
  }
}

variable "mcp_auth_header_value" {
  description = <<-EOT
    Contract name: McpAuthHeaderValue.

    Expected value of mcp_auth_header_name. Stored in Secrets Manager and read by
    the container entrypoint at start, rather than placed in the runtime's
    environment variables, which are readable by anyone who can describe the
    runtime.
  EOT
  type        = string
  default     = null
  sensitive   = true
}

variable "mcp_allowed_host" {
  description = <<-EOT
    Contract name: McpAllowedHost.

    Host header values ASH accepts, keeping the MCP SDK's DNS-rebinding
    protection on while the server binds 0.0.0.0.

    Defaults to empty on this target, deliberately. The value has to match the
    Host header AgentCore's front end actually sends to the container, and that
    is not stated in the AgentCore container contract. Setting it to a guess
    would reject every request. Populate it only after observing the Host header
    in the runtime's own logs.

    On the Fargate target this is straightforward, because the Host header there
    is the load balancer's own DNS name.
  EOT
  type        = list(string)
  default     = []
}

variable "ash_offline_mode" {
  description = <<-EOT
    Contract name: AshOfflineMode.

    Sets ASH_OFFLINE in the runtime so ASH skips network tool installation. This
    only makes sense against an image that was built offline; see the
    ash-image-pipeline variable of the same name.
  EOT
  type        = bool
  default     = false
}

variable "base_config_ssm_parameter_name" {
  description = <<-EOT
    Contract name: AshBaseConfigYaml (indirect).

    Name of the SSM parameter holding the base ASH configuration. The container
    entrypoint reads it and writes `.ash/.ash.yaml` at start.

    Pass the ash-image-pipeline `base_config_ssm_parameter_name` output. Leave
    null to run with ASH's own defaults.
  EOT
  type        = string
  default     = null
}

variable "base_config_ssm_parameter_arn" {
  description = "ARN of the same parameter, used to scope ssm:GetParameter on the execution role. Required whenever base_config_ssm_parameter_name is set."
  type        = string
  default     = null
}

variable "jwt_authorizer_discovery_url" {
  description = <<-EOT
    OpenID Connect discovery URL for inbound JWT authorization. When null, the
    runtime is reachable with SigV4 only.

    Prefer this over the static auth header for anything beyond a smoke test.
  EOT
  type        = string
  default     = null
}

variable "jwt_authorizer_allowed_audience" {
  description = "Accepted `aud` claim values. Used only when jwt_authorizer_discovery_url is set."
  type        = list(string)
  default     = []
}

variable "jwt_authorizer_allowed_clients" {
  description = "Accepted client IDs. Used only when jwt_authorizer_discovery_url is set."
  type        = list(string)
  default     = []
}

variable "idle_session_timeout_seconds" {
  description = "How long an idle runtime session is held before AgentCore reclaims it. Null uses the service default."
  type        = number
  default     = null
}

variable "max_session_lifetime_seconds" {
  description = "Hard ceiling on a runtime session's lifetime. Null uses the service default."
  type        = number
  default     = null
}

variable "additional_environment_variables" {
  description = <<-EOT
    Extra environment variables merged into the runtime's environment. Keys this
    module sets itself take precedence, so a typo here cannot silently break the
    MCP contract.
  EOT
  type        = map(string)
  default     = {}
}

variable "create_endpoint" {
  description = "Whether to create a named runtime endpoint alongside the runtime."
  type        = bool
  default     = true
}

variable "endpoint_name" {
  description = "Name of the runtime endpoint. When null, `DEFAULT` is used."
  type        = string
  default     = null
}

variable "enable_bedrock_model_invocation" {
  description = <<-EOT
    Grant the execution role bedrock:InvokeModel. ASH's MCP server does not call
    Bedrock models, so this defaults to false; enable it only if you have added a
    plugin that does.
  EOT
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags applied to every resource this module creates."
  type        = map(string)
  default     = {}
}
