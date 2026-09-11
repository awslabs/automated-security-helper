variable "name_prefix" {
  description = "Prefix applied to every resource name this module creates."
  type        = string
  default     = "ash-mcp"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,24}$", var.name_prefix))
    error_message = "name_prefix must be 1-25 characters of lowercase letters, digits, or hyphens. Load balancer and target group names are derived from it and are length-limited."
  }
}

variable "container_image_uri" {
  description = <<-EOT
    Fully qualified ECR image URI, normally the `image_uri` output of the
    ash-image-pipeline module.

    The image is expected to carry that module's entrypoint convention: an
    ENTRYPOINT that materializes config and secrets, and
    `/usr/local/bin/ash-mcp-serve` as the command that reads MCP settings from
    the environment. A differently built image needs `container_command`
    overridden.
  EOT
  type        = string
}

variable "container_command" {
  description = "Command the task runs. Defaults to the ash-image-pipeline MCP launcher."
  type        = list(string)
  default     = ["/usr/local/bin/ash-mcp-serve"]
}

variable "vpc_id" {
  description = "VPC the load balancer and tasks run in."
  type        = string
}

variable "service_subnet_ids" {
  description = <<-EOT
    Subnets the Fargate tasks run in. These need outbound reachability to ECR,
    CloudWatch Logs, SSM, and Secrets Manager, whether by NAT gateway or by VPC
    endpoints.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.service_subnet_ids) > 0
    error_message = "service_subnet_ids must contain at least one subnet."
  }
}

variable "alb_subnet_ids" {
  description = <<-EOT
    Subnets for the load balancer, in at least two Availability Zones, which the
    service requires. Public subnets for an internet-facing load balancer,
    private ones for an internal load balancer.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.alb_subnet_ids) >= 2
    error_message = "alb_subnet_ids must contain at least two subnets in different Availability Zones, which Application Load Balancer requires."
  }
}

variable "internal" {
  description = <<-EOT
    Whether the load balancer is internal. Defaults to true: this endpoint drives
    a security scanner over an API that has no authentication of its own beyond
    what you configure, so exposing it to the internet should be a deliberate
    act.
  EOT
  type        = bool
  default     = true
}

variable "certificate_arn" {
  description = <<-EOT
    ACM certificate ARN. When set, the listener is HTTPS on listener_port and
    terminates TLS at the load balancer. When null, the listener is plain HTTP.

    Setting mcp_auth_header_value without a certificate is refused, because the
    header would cross the network in the clear on every request. See
    allow_plaintext_auth_header if you have a reason to accept that.
  EOT
  type        = string
  default     = null
}

variable "allow_plaintext_auth_header" {
  description = <<-EOT
    Escape hatch that permits mcp_auth_header_value on a plain HTTP listener.

    Only reasonable where the whole path from client to load balancer is already
    confidential and attested some other way. The header is a static shared
    secret replayed on every request, so anything that can read one request can
    impersonate the client indefinitely.
  EOT
  type        = bool
  default     = false
}

variable "ssl_policy" {
  description = "ALB security policy for the HTTPS listener. Ignored when certificate_arn is null."
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

variable "listener_port" {
  description = "Port the load balancer listens on. Defaults to 443 with a certificate, 80 without."
  type        = number
  default     = null
}

variable "container_port" {
  description = "Port ASH's MCP server binds inside the container. ASH's own default is 8000."
  type        = number
  default     = 8000
}

variable "ingress_cidr_blocks" {
  description = <<-EOT
    CIDR blocks allowed to reach the load balancer. Empty by default, so nothing
    reaches it until you say what should. Set this or
    ingress_security_group_ids, or the listener is unreachable.
  EOT
  type        = list(string)
  default     = []
}

variable "ingress_security_group_ids" {
  description = "Security groups allowed to reach the load balancer. Preferred over CIDR blocks for callers inside the same VPC."
  type        = list(string)
  default     = []
}

variable "cluster_arn" {
  description = "Existing ECS cluster ARN to deploy into. When null, this module creates a cluster."
  type        = string
  default     = null
}

variable "task_cpu" {
  description = <<-EOT
    Fargate task CPU units. ASH runs many scanners, several of which are
    CPU-bound, so this is larger than a typical web service default.
  EOT
  type        = number
  default     = 2048
}

variable "task_memory" {
  description = "Fargate task memory in MiB. Must be a combination Fargate accepts for the chosen task_cpu."
  type        = number
  default     = 8192
}

variable "ephemeral_storage_gib" {
  description = <<-EOT
    Task ephemeral storage in GiB. ASH clones and scans source trees and writes
    scanner output, so the 20 GiB Fargate default is often tight. Null leaves the
    default in place. Valid range when set is 21 to 200.
  EOT
  type        = number
  default     = null

  validation {
    condition     = var.ephemeral_storage_gib == null || (var.ephemeral_storage_gib >= 21 && var.ephemeral_storage_gib <= 200)
    error_message = "ephemeral_storage_gib must be between 21 and 200 when set. Fargate's default is 20 GiB and the override must exceed it."
  }
}

variable "cpu_architecture" {
  description = <<-EOT
    Task CPU architecture, which must match the architecture the image was built
    for. ARM64 is cheaper per unit of work on Fargate; X86_64 is the safer choice
    if any scanner in your configuration lacks an arm64 build.
  EOT
  type        = string
  default     = "X86_64"

  validation {
    condition     = contains(["X86_64", "ARM64"], var.cpu_architecture)
    error_message = "cpu_architecture must be either X86_64 or ARM64."
  }
}

variable "desired_count" {
  description = <<-EOT
    Number of tasks to run. More than one is safe only with mcp_stateless_http
    left true, since the load balancer may route consecutive requests from one
    client to different tasks.
  EOT
  type        = number
  default     = 1

  validation {
    condition     = var.desired_count >= 0
    error_message = "desired_count must be zero or greater."
  }
}

variable "mcp_stateless_http" {
  description = <<-EOT
    Contract name: McpStatelessHttp.

    Defaults to true. Behind a load balancer, consecutive requests from one
    client can land on different tasks, and a stateful MCP server on the task
    that did not issue the session rejects the request with
    404 "Session not found".

    With desired_count = 1 a stateful server can work, but it turns
    horizontal scaling into a correctness question rather than a capacity one.
  EOT
  type        = bool
  default     = true
}

variable "mcp_mount_path" {
  description = "Contract name: McpMountPath. HTTP path the MCP transport listens on, and the path the target group health check probes."
  type        = string
  default     = "/mcp"

  validation {
    condition     = startswith(var.mcp_mount_path, "/")
    error_message = "mcp_mount_path must begin with a forward slash."
  }
}

variable "mcp_auth_header_name" {
  description = <<-EOT
    Contract name: McpAuthHeaderName.

    Name of a static HTTP header ASH requires on every MCP request. A shared
    secret, not identity. Requires mcp_auth_header_value.
  EOT
  type        = string
  default     = null
}

variable "mcp_auth_header_value" {
  description = <<-EOT
    Contract name: McpAuthHeaderValue.

    Expected value of mcp_auth_header_name. Stored in Secrets Manager and read by
    the container entrypoint at start, rather than placed in the task
    definition, which is readable by anyone who can describe the task.
  EOT
  type        = string
  default     = null
  sensitive   = true

  validation {
    condition     = var.mcp_auth_header_value == null || var.certificate_arn != null || var.allow_plaintext_auth_header
    error_message = "mcp_auth_header_value is set but the listener would be plain HTTP. Set certificate_arn to terminate TLS, or set allow_plaintext_auth_header = true to accept sending the shared secret in the clear."
  }
}

variable "mcp_allowed_host" {
  description = <<-EOT
    Contract name: McpAllowedHost.

    Additional Host header values ASH accepts, beyond the load balancer's own DNS
    name which this module adds for you.

    Behind a load balancer the Host header is the name the client dialed, not the
    container's. Rather than disabling the MCP SDK's DNS-rebinding protection,
    this module passes the load balancer DNS name (with and without the listener
    port) through ASH's repeatable --allowed-host flag, so protection stays on for
    a known hostname.

    Add a value here for every additional name that fronts the load balancer: a
    Route 53 alias, a CloudFront distribution, or a custom domain on the
    certificate.
  EOT
  type        = list(string)
  default     = []
}

variable "ash_offline_mode" {
  description = "Contract name: AshOfflineMode. Sets ASH_OFFLINE so ASH skips network tool installation. Requires an offline-built image."
  type        = bool
  default     = false
}

variable "base_config_ssm_parameter_name" {
  description = "Contract name: AshBaseConfigYaml (indirect). SSM parameter the entrypoint reads to write .ash/.ash.yaml. Pass the ash-image-pipeline output."
  type        = string
  default     = null
}

variable "base_config_ssm_parameter_arn" {
  description = "ARN of the same parameter, used to scope ssm:GetParameter on the task role. Required whenever base_config_ssm_parameter_name is set."
  type        = string
  default     = null
}

variable "health_check_matcher" {
  description = <<-EOT
    HTTP status codes the target group treats as healthy.

    The wide default is deliberate. ASH's MCP server exposes no health endpoint —
    it serves only the MCP mount path — so the health check has to probe that
    path with a GET, which is not a valid MCP request. When mcp_auth_header_name
    is set the auth middleware also rejects the unauthenticated probe. Any HTTP
    response therefore proves the server is up and accepting connections, while a
    connection failure, a timeout, or a 5xx still marks the target unhealthy.

    Narrow this only after observing what your configuration actually returns.
  EOT
  type        = string
  default     = "200-499"
}

variable "health_check_interval_seconds" {
  description = "Seconds between target group health checks."
  type        = number
  default     = 30
}

variable "health_check_grace_period_seconds" {
  description = <<-EOT
    Seconds the service ignores health checks after a task starts. ASH's MCP
    server imports a large dependency tree and, when not built offline, may
    install scanner tooling on first run, so a short grace period causes a
    restart loop that looks like a crash.
  EOT
  type        = number
  default     = 300
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the task logs, in days."
  type        = number
  default     = 30
}

variable "enable_execute_command" {
  description = "Enable ECS Exec on the service, which allows an interactive shell into a running task. Useful for diagnosis, and an additional access path to control."
  type        = bool
  default     = false
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection on the load balancer."
  type        = bool
  default     = false
}

variable "additional_environment_variables" {
  description = "Extra container environment variables. Keys this module sets take precedence."
  type        = map(string)
  default     = {}
}

variable "kms_key_arn" {
  description = <<-EOT
    ARN of an existing customer managed KMS key to encrypt the task log group and
    the MCP auth header secret with, instead of the key this module creates.

    Leave it null and the module creates its own key. There is no third option:
    the log group and the secret are always under a customer managed key, never
    under `aws/secretsmanager` or an Amazon-owned logs key, whose policies this
    configuration cannot narrow and whose use does not appear per-caller in
    CloudTrail.

    Set it when composing several ASH modules, so they share one key rather than
    creating one each -- a KMS key carries a standing monthly charge whether or not
    anything is encrypted under it. Every ASH module exposes its key as the
    `kms_key_arn` output, so one module's key can be passed to the rest.

    A supplied key must already grant the CloudWatch Logs service principal
    kms:Encrypt, kms:Decrypt, kms:ReEncrypt*, kms:GenerateDataKey* and
    kms:Describe* under a `kms:EncryptionContext:aws:logs:arn` condition that
    matches this account. Terraform cannot check that, and a key without it plans
    and validates cleanly, then fails at CreateLogGroup. kms.tf has the policy this
    module writes for its own key; copy it.

    The key must be symmetric and in the same region as this deployment.
  EOT
  type        = string
  default     = null

  validation {
    condition     = var.kms_key_arn == null || can(regex("^arn:[a-z0-9-]+:kms:[a-z0-9-]+:[0-9]+:key/", var.kms_key_arn))
    error_message = "kms_key_arn must be a KMS key ARN, for example arn:aws:kms:<region>:<account>:key/<key-id>. An alias ARN is not accepted, because CloudWatch Logs and Secrets Manager record the resolved key."
  }
}

variable "kms_key_deletion_window_days" {
  description = <<-EOT
    Days KMS waits before destroying this module's key after `terraform destroy`
    schedules its deletion. Ignored when kms_key_arn is set.

    This is the recovery window, and it is why there is no `prevent_destroy` on
    the key. Deleting a key that encrypted log data makes that data permanently
    unreadable -- AWS states it plainly -- so the CDK implementation of this
    target marks its key RETAIN. Terraform's equivalent, a `prevent_destroy`
    lifecycle block, cannot be made conditional, because the meta-argument takes
    a literal rather than a variable. It would make `terraform destroy` fail for
    every adopter and for every example in this repository, including the ones the
    READMEs tell you to tear down because they cost money while they exist.

    The window is the honest analogue: while the key is pending deletion it cannot
    decrypt, but nothing is lost, and `aws kms cancel-key-deletion` restores it.
    Defaults to the maximum.
  EOT
  type        = number
  default     = 30

  validation {
    condition     = var.kms_key_deletion_window_days >= 7 && var.kms_key_deletion_window_days <= 30
    error_message = "kms_key_deletion_window_days must be between 7 and 30, the range KMS accepts."
  }
}

variable "tags" {
  description = "Tags applied to every resource this module creates."
  type        = map(string)
  default     = {}
}
