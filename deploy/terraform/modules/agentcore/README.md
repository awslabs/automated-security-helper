# agentcore

Runs ASH's MCP server as an Amazon Bedrock AgentCore Runtime.

Consumes the `image_uri` output of `ash-image-pipeline`, built for **arm64**.

## The provider resource question, answered

The AWS provider **does** have first-class AgentCore runtime resources as of
`hashicorp/aws` 6.62.0. This module uses them:

- `aws_bedrockagentcore_agent_runtime`
- `aws_bedrockagentcore_agent_runtime_endpoint`

That was verified by dumping `terraform providers schema -json` against the
pinned provider rather than by reading documentation, because a resource present
in docs but absent from the binary is the failure mode that matters. The dump
shows 21 `aws_bedrockagentcore_*` resources.

The `awscc` provider also carries `awscc_bedrockagentcore_runtime`. It is **not**
used here: the first-party `aws` resource covers the whole contract this module
needs, and mixing providers for one resource costs a second provider dependency
for nothing.

## The container contract

From
[the MCP protocol contract](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-mcp-protocol-contract.html),
re-read and confirmed:

| Requirement | Value | Configurable here? |
|---|---|---|
| Transport | `streamable-http` (required) | No |
| Host | `0.0.0.0` | No |
| Port | `8000` | No |
| Platform | arm64 container (required) | Set on the image module |
| Path | `POST /mcp` | `mcp_mount_path`, but only /mcp is routed |
| Session management | Platform injects `Mcp-Session-Id` | `mcp_stateless_http` |
| Default mode | stateless (`stateless_http=True`) | `mcp_stateless_http` |

`serverProtocol` is fixed to `MCP`. The API accepts `MCP | HTTP | A2A | AGUI`;
none of the other three describes what this container speaks, so the module does
not expose the choice.

`networkMode` accepts `PUBLIC | VPC`, and both are supported through
`network_mode`.

## Why stateless defaults to true

AgentCore injects its own `Mcp-Session-Id` header on every request, including the
first. Measured against ASH directly: given a session id the server never issued,

- **stateful** (`--no-stateless-http`) returns **404 "Session not found"**
- **stateless** (`--stateless-http`) returns **200**

The platform contract says the same thing from the other direction: "Your MCP
server must accept the platform-provided session ID (do not reject it)."

So on this target, stateful mode fails every request. AgentCore does support
stateful servers for elicitation and sampling, but ASH's MCP server uses neither,
so there is nothing to gain by turning it off.

## Why the auth header is allowlisted automatically

AgentCore forwards only headers named in `requestHeaderAllowlist`; everything
else is dropped before the container sees it. If you set `mcp_auth_header_name`
and the header is not allowlisted, ASH rejects every request for a missing header
that the platform silently removed — a failure that looks like an ASH bug and is
not.

This module therefore derives the allowlist from `mcp_auth_header_name` rather
than asking you to set both and keeping them in sync. The variable is validated
against the API's own pattern (`[A-Za-z][A-Za-z0-9_-]{0,255}`, max 20 entries).

## Variables

| Variable | Contract | Type | Default | Notes |
|---|---|---|---|---|
| `container_image_uri` | — | `string` | *required* | Must be an arm64 image. |
| `mcp_stateless_http` | `McpStatelessHttp` | `bool` | `true` | See above. Leave it alone. |
| `mcp_mount_path` | `McpMountPath` | `string` | `"/mcp"` | AgentCore routes only `/mcp`. |
| `mcp_auth_header_name` | `McpAuthHeaderName` | `string` | `null` | Auto-added to the request header allowlist. |
| `mcp_auth_header_value` | `McpAuthHeaderValue` | `string` (sensitive) | `null` | Stored in Secrets Manager, read at container start. |
| `mcp_allowed_host` | `McpAllowedHost` | `list(string)` | `[]` | Empty by design. See limitations. |
| `ash_offline_mode` | `AshOfflineMode` | `bool` | `false` | Sets `ASH_OFFLINE`. Needs an offline-built image. |
| `base_config_ssm_parameter_name` | `AshBaseConfigYaml` (indirect) | `string` | `null` | From the image module's output. |
| `base_config_ssm_parameter_arn` | — | `string` | `null` | Scopes `ssm:GetParameter`. |
| `name_prefix` | — | `string` | `"ash"` | Underscores only, no hyphens. |
| `agent_runtime_name` | — | `string` | `null` | Defaults to `<name_prefix>_mcp`. |
| `ecr_pull_resource_arns` | — `list(string)` | | `null` | Defaults to all repositories in this account and Region. |
| `network_mode` | — | `string` | `"PUBLIC"` | `PUBLIC` or `VPC`. |
| `vpc_subnet_ids` | — | `list(string)` | `[]` | Required for `VPC`. |
| `vpc_security_group_ids` | — | `list(string)` | `[]` | Required for `VPC`. |
| `jwt_authorizer_discovery_url` | — | `string` | `null` | OIDC discovery URL for inbound JWT auth. |
| `jwt_authorizer_allowed_audience` | — | `list(string)` | `[]` | Accepted `aud` values. |
| `jwt_authorizer_allowed_clients` | — | `list(string)` | `[]` | Accepted client IDs. |
| `idle_session_timeout_seconds` | — | `number` | `null` | Service default when null. |
| `max_session_lifetime_seconds` | — | `number` | `null` | Service default when null. |
| `additional_environment_variables` | — | `map(string)` | `{}` | Module-set keys win on collision. |
| `create_endpoint` | — | `bool` | `true` | Creates a named runtime endpoint. |
| `endpoint_name` | — | `string` | `null` | Defaults to `DEFAULT`. |
| `enable_bedrock_model_invocation` | — | `bool` | `false` | ASH's MCP server does not call Bedrock models. |
| `tags` | — | `map(string)` | `{}` | Applied to everything created. |

## Outputs

`agent_runtime_arn`, `agent_runtime_id`, `agent_runtime_name`,
`agent_runtime_version`, `agent_runtime_endpoint_arn`, `execution_role_arn`,
`execution_role_name`, `auth_header_secret_arn`, `log_group_name`,
`request_header_allowlist`.

## Constraints and known limitations

**`mcp_allowed_host` is empty by default, and that is a gap, not an oversight.**
Enabling the MCP SDK's DNS-rebinding protection needs the exact Host header the
caller sends. Behind an ALB that is the load balancer's DNS name, which Terraform
knows. AgentCore's container contract does not state what Host header its front
end sends, and I did not find it documented. Setting the variable to a guess
rejects every request. Read the `log_group_name` output, observe the Host header,
then set it. Until then the server binds `0.0.0.0` with protection off, which is
the MCP SDK's own default for a non-loopback bind.

**The image architecture is not checked by Terraform.** Passing an x86_64
`container_image_uri` plans and applies cleanly and then fails at runtime.
Terraform cannot inspect an image manifest, so this is enforced by documentation
only. Build with `target_architecture = "arm64"`.

**No container command override exists.** `container_configuration` accepts only
`container_uri`. That is why the image's baked `CMD` reads MCP settings from
environment variables — see `ash-image-pipeline`. If you supply an image not built
by that module, it must implement the same convention or ignore these variables.

**Runtime logs are service-managed.** This module does not create the log group;
AgentCore creates it under `/aws/bedrock-agentcore/runtimes/` using the execution
role. `log_group_name` is the computed name, not a managed resource, so it exists
only after the runtime has run.

**`GetWorkloadAccessTokenForUserId` is deliberately not granted.** It mints a
workload token from a caller-supplied user identifier with no IdP verification.
The AgentCore documentation recommends denying it outside development, so the
execution role gets only `GetWorkloadAccessToken` and the JWT variant.

## What is first-party and what is not

All first-party `hashicorp/aws`. No aws-ia module covers AgentCore; nothing in the
aws-ia namespace addresses this service at all.
