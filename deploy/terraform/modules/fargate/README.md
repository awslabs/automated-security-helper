# fargate

Runs ASH's MCP server as an ECS Fargate service behind an Application Load
Balancer.

Consumes the `image_uri` output of `ash-image-pipeline`.

## The Host header, and why `--allowed-host` matters here

Behind a load balancer the `Host` header on an inbound request is the name the
**client** dialed — the load balancer's DNS name — not the container's. The MCP
SDK's DNS-rebinding protection compares against that header, and it is active
only when the server binds a loopback address. This server binds `0.0.0.0`, so
out of the box the protection is off.

ASH exposes a repeatable `--allowed-host` flag precisely for this: it keeps the
protection **on** for a known hostname instead of disabling it. So this module
does not turn the protection off. It computes the allowlist from the load
balancer it just created and passes it through:

- `<alb-dns-name>`
- `<alb-dns-name>:<listener-port>`

Both forms are included because whether a client appends the port to `Host`
depends on whether the listener port is the scheme default, and a mismatch
surfaces as an opaque rejection from inside the SDK rather than a clear error.

Anything else that fronts the load balancer — a Route 53 alias, a CloudFront
distribution, a custom domain on the certificate — has to be added through
`mcp_allowed_host`. The effective list is the `allowed_hosts` output.

## Health checks, and an honest limitation

ASH's MCP server exposes **no** health endpoint. It builds a Starlette app that
serves the MCP mount path and nothing else. So the target group health check has
to probe the mount path with a `GET`, which is not a valid MCP request, and when
`mcp_auth_header_name` is set the auth middleware rejects the unauthenticated
probe as well.

`health_check_matcher` therefore defaults to `200-499`: any HTTP response proves
the process is up and serving, while a connection failure, a timeout, or a 5xx
still marks the target unhealthy. This is weaker than a real readiness probe — it
does not prove ASH can actually scan. Narrow the matcher once you have observed
what your configuration returns.

## Why stateless is the default

With more than one task, the load balancer can route consecutive requests from
one client to different tasks. A stateful MCP server on the task that did not
issue the session rejects the request with 404 "Session not found". Leaving
`mcp_stateless_http = true` makes `desired_count` a capacity decision instead of
a correctness one.

## TLS and the static auth header

`mcp_auth_header_value` on a plain HTTP listener is refused at plan time. The
header is a static shared secret replayed on every request, so anything that can
observe one request can impersonate the client indefinitely. Set
`certificate_arn`, or set `allow_plaintext_auth_header = true` if the whole path
is already confidential by other means.

That check is a cross-variable variable validation, which is why this module
requires Terraform >= 1.9.0. Note that it fires at **plan** time —
`terraform validate` does not evaluate variable validation rules.

## Variables

| Variable | Contract | Type | Default | Notes |
|---|---|---|---|---|
| `container_image_uri` | — | `string` | *required* | Architecture must match `cpu_architecture`. |
| `vpc_id` | — | `string` | *required* | |
| `service_subnet_ids` | — | `list(string)` | *required* | Need egress to ECR, Logs, SSM, Secrets Manager. |
| `alb_subnet_ids` | — | `list(string)` | *required* | At least two AZs. |
| `mcp_stateless_http` | `McpStatelessHttp` | `bool` | `true` | See above. |
| `mcp_mount_path` | `McpMountPath` | `string` | `"/mcp"` | Also the health check path. |
| `mcp_auth_header_name` | `McpAuthHeaderName` | `string` | `null` | Static shared secret, not identity. |
| `mcp_auth_header_value` | `McpAuthHeaderValue` | `string` (sensitive) | `null` | Secrets Manager. Requires TLS or an explicit opt-out. |
| `mcp_allowed_host` | `McpAllowedHost` | `list(string)` | `[]` | *Additional* hosts; the ALB DNS name is added automatically. |
| `ash_offline_mode` | `AshOfflineMode` | `bool` | `false` | Sets `ASH_OFFLINE`. |
| `base_config_ssm_parameter_name` | `AshBaseConfigYaml` (indirect) | `string` | `null` | From the image module. |
| `base_config_ssm_parameter_arn` | — | `string` | `null` | Scopes `ssm:GetParameter`. |
| `name_prefix` | — | `string` | `"ash-mcp"` | Max 25 characters; ALB and target group names derive from it. |
| `container_command` | — | `list(string)` | MCP launcher | Override for an image not built by `ash-image-pipeline`. |
| `internal` | — | `bool` | `true` | Internet exposure should be deliberate. |
| `certificate_arn` | — | `string` | `null` | Set to get an HTTPS listener. |
| `allow_plaintext_auth_header` | — | `bool` | `false` | Opt out of the TLS requirement above. |
| `ssl_policy` | — | `string` | TLS 1.3 policy | HTTPS listeners only. |
| `listener_port` | — | `number` | `null` | Defaults to 443 with a certificate, else 80. |
| `container_port` | — | `number` | `8000` | ASH's own MCP default. |
| `ingress_cidr_blocks` | — | `list(string)` | `[]` | Empty means unreachable. Set this or the SG list. |
| `ingress_security_group_ids` | — | `list(string)` | `[]` | Preferred for in-VPC callers. |
| `cluster_arn` | — | `string` | `null` | Reuse a cluster instead of creating one. |
| `task_cpu` | — | `number` | `2048` | Scanners are CPU-bound. |
| `task_memory` | — | `number` | `8192` | Must be valid for `task_cpu`. |
| `ephemeral_storage_gib` | — | `number` | `null` | 21-200 when set; Fargate's default is 20. |
| `cpu_architecture` | — | `string` | `"X86_64"` | Must match the image. |
| `desired_count` | — | `number` | `1` | Above 1 requires stateless MCP. |
| `health_check_matcher` | — | `string` | `"200-499"` | See above. |
| `health_check_interval_seconds` | — | `number` | `30` | |
| `health_check_grace_period_seconds` | — | `number` | `300` | Short values cause a restart loop. |
| `log_retention_days` | — | `number` | `30` | |
| `enable_execute_command` | — | `bool` | `false` | ECS Exec is an extra access path. |
| `enable_deletion_protection` | — | `bool` | `false` | |
| `additional_environment_variables` | — | `map(string)` | `{}` | Module keys win on collision. |
| `tags` | — | `map(string)` | `{}` | |

## Outputs

`mcp_endpoint_url`, `load_balancer_dns_name`, `load_balancer_arn`,
`load_balancer_zone_id`, `listener_arn`, `target_group_arn`, `allowed_hosts`,
`cluster_arn`, `service_name`, `task_definition_arn`, `task_role_arn`,
`execution_role_arn`, `service_security_group_id`, `alb_security_group_id`,
`auth_header_secret_arn`, `log_group_name`.

## Constraints and known limitations

**Health checks prove liveness, not readiness.** See above. A task that is
serving HTTP but cannot scan reads as healthy.

**Terraform cannot verify the image architecture.** A `cpu_architecture` that
disagrees with the image plans and applies cleanly, then fails when the task
starts.

**Egress is open.** The task security group allows all outbound, because the
right narrowing depends on whether the VPC reaches AWS APIs through NAT or
through interface endpoints, which this module does not know. Tightening it is a
reasonable follow-up in a VPC using endpoints.

**Two roles, and the task role does the secret reading.** The container entrypoint
reads the SSM parameter and the Secrets Manager secret itself, using the task
role, rather than relying on ECS secret injection through the execution role.
That is a deliberate trade: one entrypoint code path works identically on all
four deployment targets, and AgentCore has no secret-injection mechanism at all.
The cost is that the container needs `ssm:GetParameter` and
`secretsmanager:GetSecretValue` at runtime.

**`ingress_cidr_blocks` and `ingress_security_group_ids` both default to empty**,
so a fresh deployment is unreachable until one is set. That is intentional: an
open default on a security-scanning API is worse than an obviously broken one.

## What is first-party and what is not

All resources here are first-party `hashicorp/aws`.

**No aws-ia ECS module is used, and that is a considered decision, not an
oversight.** The two candidates were both examined:

- `aws-ia/ecs-fargate/aws` — latest version **0.0.2**, published 2021-09-01,
  ~6.5k downloads. Its entire input surface is 16 variables and its only output
  is `public_lb_dns_name`. It cannot express container environment variables,
  secrets, a task role, `runtime_platform` (so no architecture choice), a health
  check path or matcher, log configuration, or ephemeral storage — every one of
  which this target needs. It also discovers subnets by a `network_tag` filter
  and defaults `region` to a hardcoded value.
- `aws-ia/ecs-cluster/aws` — latest version **0.0.1**, published 2021-09-08,
  thinner still.

Both are pre-1.0 and neither has been updated in roughly five years. Using either
would mean wrapping it with first-party resources for everything that matters,
which is more code than writing the service directly and leaves a dependency that
looks like coverage without providing it.

The aws-ia VPC module **is** used, in `examples/basic/` — see there. That one is
verified, current (4.9.0, published 2026-08-19), and fits.
