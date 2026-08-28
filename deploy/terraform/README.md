# ASH deployment targets: Terraform

Terraform modules for running ASH on AWS in four shapes, plus the shared image
build every one of them depends on.

| Module | What it deploys |
|---|---|
| [`ash-image-pipeline`](modules/ash-image-pipeline/) | ECR repository plus a CodeBuild project that builds the ASH image from a pinned revision, rebuilt on a schedule. **Every other module depends on this one.** |
| [`agentcore`](modules/agentcore/) | ASH's MCP server as a Bedrock AgentCore Runtime |
| [`fargate`](modules/fargate/) | ASH's MCP server as an ECS Fargate service behind an ALB |
| [`codecommit-gate`](modules/codecommit-gate/) | Pull-request gate: EventBridge -> container Lambda -> scan -> pull-request comment |
| [`codepipeline-executor`](modules/codepipeline-executor/) | Sharded scan: N parallel CodeBuild jobs, then a merge that owns the verdict |

## Start here: there is no published image

ASH publishes **no container image to any public registry**, and will not. There
is nothing to `docker pull`.

Every deployment target therefore builds ASH into **your own** ECR repository as
part of deployment. `ash-image-pipeline` is the bootstrap, not a freshness
optimization layered over a published image. Until its first build succeeds, the
repository is empty and every target fails to pull.

Terraform creates the build project; running a build is an action, not a resource,
so it cannot run it for you. After `apply`:

```console
aws codebuild start-build --project-name "$(terraform output -raw codebuild_project_name)"
```

Each module exposes a `bootstrap_command` output that prints this with the region
filled in. `codecommit-gate` has a second build that must run **after** the shared
one, because it uses the shared image as its base.

The scheduled rebuild (`rate(1 day)` by default) is a separate concern: ASH bundles
third-party scanners and their rulesets, so an image left alone keeps scanning with
stale detections even when ASH itself has not changed.

## Variable contract

These names are shared with the CDK implementation of the same targets. Terraform
uses `snake_case`; the mapping is one to one. Not every target takes every
variable — a blank cell means the variable does not apply there.

| Shared name | Terraform name | image-pipeline | agentcore | fargate | codecommit-gate | codepipeline-executor |
|---|---|---|---|---|---|---|
| `AshOfflineMode` | `ash_offline_mode` | yes | yes | yes | yes | yes |
| `AshBaseConfigYaml` | `ash_base_config_yaml` | yes | | | | |
| `AshVersion` | `ash_version` | yes | | | | |
| `McpStatelessHttp` | `mcp_stateless_http` | | yes | yes | | |
| `McpAuthHeaderName` | `mcp_auth_header_name` | | yes | yes | | |
| `McpAuthHeaderValue` | `mcp_auth_header_value` | | yes | yes | | |
| `McpMountPath` | `mcp_mount_path` | | yes | yes | | |
| `McpAllowedHost` | `mcp_allowed_host` | | yes | yes | | |
| `RebuildSchedule` | `rebuild_schedule` | yes | | | | |
| `ShardCount` | `shard_count` | | | | | yes |
| `CodeCommitRepositoryArn` | `codecommit_repository_arn` | | | | yes | yes |

`AshVersion`, `AshBaseConfigYaml`, and `RebuildSchedule` belong to the image build,
because that is where they take effect. The four targets consume the result through
`base_config_ssm_parameter_name` and `base_config_ssm_parameter_arn`, which is the
indirect form of `AshBaseConfigYaml`.

### How the two long-form values travel

`AshBaseConfigYaml` is a full `.ash.yaml` document. It goes into an **SSM
parameter** (`Intelligent-Tiering` by default, so Parameter Store selects Advanced
only when the value exceeds the Standard 4 KB limit), and the container entrypoint
materializes it to `.ash/.ash.yaml` at start and exports `ASH_CONFIG` to that path.

It travels through SSM rather than a container environment variable because
AgentCore Runtime exposes only a flat environment map, and a real config does not
comfortably fit there. Ceiling: 8 KB, the Advanced-tier maximum, which is validated.

`McpAuthHeaderValue` is a credential. It is `sensitive = true` and is stored in
**Secrets Manager**, read by the container entrypoint at start rather than placed
in a task definition or an AgentCore environment map, both of which are readable
by anyone able to describe the resource.

## Which target to use

**AgentCore** — you want ASH available to agents over MCP and want the platform to
manage the runtime. Requires an **arm64** image; its container contract admits no
other architecture.

**Fargate** — you want ASH over MCP on infrastructure you control, reachable at a
stable endpoint, with your own network boundary and TLS.

**CodeCommit gate** — you want every pull request scanned and commented. Bounded by
Lambda's hard 900-second timeout, so best with
`--changed-files-only --base-ref <default-branch>`.

**CodePipeline executor** — you want a full scan of a large repository, and wall
clock matters more than simplicity. Scales across up to 100 parallel shards, with
no fifteen-minute ceiling.

## aws-ia modules: where they are used and where they are not

Being precise about this, because implying coverage that does not exist would be
worse than having none.

**Used:** `aws-ia/vpc/aws ~> 4.9` in
[`modules/fargate/examples/basic/`](modules/fargate/examples/basic/). Verified,
current (4.9.0, published 2026-08-19, aws provider `>= 6.27.0`), and its output
surface covers what the service needs.

**Not used, and why:** every resource in all five modules is first-party
`hashicorp/aws`.

- **ECS.** Both aws-ia candidates were examined and rejected on the specifics.
  `aws-ia/ecs-fargate/aws` is at **0.0.2**, published 2021-09-01; its 16 inputs
  cannot express container environment variables, secrets, a task role,
  `runtime_platform` (so no architecture choice), a health check path or matcher,
  log configuration, or ephemeral storage — all of which this target needs — and its
  only output is `public_lb_dns_name`. `aws-ia/ecs-cluster/aws` is at **0.0.1**,
  published 2021-09-08, and thinner. Neither has been updated in roughly five years.
  Wrapping either would be more code than writing the service directly, and would
  leave a dependency that looks like coverage without being it.
- **AgentCore, ECR, CodeBuild, CodePipeline, Lambda, EventBridge, CodeCommit.** No
  aws-ia module covers any of these. The namespace has nothing for AgentCore at all.

## Providers

Pinned with `~>` in a `versions.tf` per module, at the current versions:

- `hashicorp/aws ~> 6.62` (6.62.0 is current)

The AWS provider is the only provider any module requires. `hashicorp/awscc` is
**not** used — see below. It does appear in the Fargate example's dependency graph,
transitively, because `aws-ia/vpc` requires it.

Terraform `>= 1.9.0` for all modules except `ash-image-pipeline` and `agentcore`,
which need only `>= 1.5.0`. The 1.9 floor is for input variable validation rules
that reference other variables.

### AgentCore does have first-party resources

Worth stating plainly, since it is the one place a provider gap was plausible: the
AWS provider **does** carry AgentCore runtime resources, and the `agentcore` module
uses them.

- `aws_bedrockagentcore_agent_runtime`
- `aws_bedrockagentcore_agent_runtime_endpoint`

That was established by dumping `terraform providers schema -json` against the
pinned provider rather than by reading documentation, because a resource that
appears in docs but not in the binary is the failure mode that matters. The dump
shows 21 `aws_bedrockagentcore_*` resources.

`awscc_bedrockagentcore_runtime` also exists. It is not used: the first-party
resource covers the whole contract, and reaching for a second provider would add a
dependency for nothing.

## Verification

Run per module and per example:

```console
terraform fmt -check -recursive .
terraform init -backend=false
terraform validate
```

`terraform validate` checks syntax, provider schema, and references. It does
**not** evaluate variable validation rules, so a module whose validation condition
is wrong — including a cross-variable rule — passes validate and only errors at
plan time. A green fmt-and-validate run says the configuration parses, not that its
input contracts work.

That gap is covered separately, and without an AWS account:

```console
deploy/terraform/tests/validate-inputs.sh
```

Variable validation is evaluated *before* Terraform initializes the provider or
needs credentials, so a plan carrying a deliberately invalid value fails on the
rule's own `error_message` and never reaches AWS. The script exercises 19 cases
across all five modules in **both** directions — an invalid value must produce the
message, and a valid one must not — because a check that only ever feeds in the
failing value cannot tell "the rule fired" apart from "plan failed for an unrelated
reason and the grep happened to match". In the passing direction the plan still
fails, on credentials, and that later failure is the evidence that validation was
passed rather than skipped.

No module or example has been applied, and nothing here has been run against a real
account.

Do not run `terraform apply` from an example without reading its README first —
several create NAT gateways, load balancers, and CodeBuild projects that cost money
while they exist.
