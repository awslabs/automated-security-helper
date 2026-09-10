# ash-image-pipeline

Builds the ASH container image into your own ECR repository, and rebuilds it on a
schedule.

Every other module in `deploy/terraform/modules/` consumes this module's
`image_uri`.

## Why this module is mandatory

ASH publishes no container image to any public registry. There is nothing to
`docker pull`. So the image build is the **bootstrap** for all four deployment
targets, not a freshness optimization layered on top of a published image. Until
the first build succeeds, the ECR repository is empty and any target pointed at
`image_uri` fails to pull.

The scheduled rebuild is a second, independent reason this module exists. ASH
bundles third-party scanners and their rulesets. An image left alone keeps
scanning with the detections it was built with, so the image goes stale even
when ASH itself has not changed. The default `rate(1 day)` republishes the same
tag, which is why `ecr_image_tag_mutability` defaults to `MUTABLE`.

## Bootstrap is a manual step

Terraform creates the build project. Running a build is an action, not a
resource, so Terraform cannot do it. After `apply`:

```console
aws codebuild start-build --project-name "$(terraform output -raw codebuild_project_name)"
```

The `bootstrap_command` output prints this with the region filled in. Waiting for
the schedule to fire also works, but the first firing may be up to a full
interval away.

## What it builds

Two stacked Docker builds:

1. The ASH image itself, from the ASH `Dockerfile` at the pinned `ash_version`.
   The build fetches the ref and then builds with
   `INSTALL_ASH_REVISION=LOCAL`, rather than letting the Dockerfile re-clone.
   That matters because the Dockerfile's own remote path uses
   `git clone --branch`, which cannot resolve a commit SHA — doing the fetch
   outside is what makes SHA pinning possible.
2. A thin wrapper (`files/wrapper.Dockerfile`) adding two scripts:
   - `ash-container-init` (the `ENTRYPOINT`) materializes the base config from
     SSM to `.ash/.ash.yaml`, resolves the MCP auth header value from Secrets
     Manager, then `exec`s whatever command it was given.
   - `ash-mcp-serve` (the `CMD`) builds an `ash mcp` command line from
     environment variables and execs it.

The wrapper exists because Bedrock AgentCore Runtime has **no container command
override** — its `container_configuration` block accepts only `container_uri`.
Anything that target needs to run must be the image's own `ENTRYPOINT`/`CMD`.
Baking a fixed argv would freeze the MCP flags at build time, so the baked
command reads its flags from the environment instead. That keeps transport, port,
mount path, stateless mode, and the Host allowlist as deploy-time settings on all
four targets.

## Variables

The names below in **Contract** are the shared names used across both the
Terraform and CDK implementations of these targets. Terraform uses `snake_case`;
the mapping is one to one.

| Variable | Contract | Type | Default | Notes |
|---|---|---|---|---|
| `ash_version` | `AshVersion` | `string` | *required* | Git ref: release tag, branch, or full commit SHA. No default, so the pin is always deliberate. |
| `ash_offline_mode` | `AshOfflineMode` | `bool` | `false` | Builds with `OFFLINE=YES`, vendoring rulesets and setting `ASH_OFFLINE` in the image. |
| `ash_base_config_yaml` | `AshBaseConfigYaml` | `string` | `null` | Full `.ash.yaml` contents. Stored in SSM, written to `.ash/.ash.yaml` at container start. Capped at 8192 bytes. |
| `rebuild_schedule` | `RebuildSchedule` | `string` | `"rate(1 day)"` | EventBridge `rate(...)` or `cron(...)`. |
| `name_prefix` | — | `string` | `"ash"` | Prefix for every created resource name. |
| `ash_repository_clone_url` | — | `string` | ASH on GitHub | Point at a fork or an internal mirror. |
| `ash_image_target` | — | `string` | `"non-root"` | Dockerfile stage: `core`, `ci`, or `non-root`. |
| `target_architecture` | — | `string` | `"x86_64"` | `x86_64` or `arm64`. AgentCore requires `arm64`. Selects a native build fleet. |
| `image_tag` | — | `string` | `"latest"` | The moving tag targets consume. |
| `ash_version_tag_prefix` | — | `string` | `"ash-"` | Prefix for the per-build immutable audit tag. |
| `ecr_image_tag_mutability` | — | `string` | `"MUTABLE"` | `IMMUTABLE` breaks the scheduled rebuild. See below. |
| `ecr_force_delete` | — | `bool` | `false` | Let `destroy` remove a non-empty repository. |
| `ecr_kms_key_arn` | — | `string` | `null` | Customer managed key for ECR encryption. `null` uses AES256. |
| `image_retention_count` | — | `number` | `10` | Lifecycle policy expires images beyond this count. |
| `enable_scheduled_rebuild` | — | `bool` | `true` | Set `false` only if something else rebuilds and pushes. |
| `ssm_parameter_tier` | — | `string` | `"Intelligent-Tiering"` | `Standard`, `Advanced`, or `Intelligent-Tiering`. |
| `build_compute_type` | — | `string` | `null` | Defaults to `BUILD_GENERAL1_LARGE`. |
| `build_image_override` | — | `string` | `null` | Defaults to the current Amazon Linux 2023 image for the chosen architecture. |
| `build_timeout_minutes` | — | `number` | `120` | Offline builds install a lot. |
| `log_retention_days` | — | `number` | `30` | CloudWatch Logs retention for build logs. |
| `tags` | — | `map(string)` | `{}` | Applied to everything created. |

## Outputs

`image_uri`, `ecr_repository_url`, `ecr_repository_arn`, `ecr_repository_name`,
`codebuild_project_name`, `codebuild_project_arn`,
`base_config_ssm_parameter_name`, `base_config_ssm_parameter_arn`,
`bootstrap_command`, `build_log_group_name`.

## Constraints and known limitations

**Mutable tags are load-bearing.** The freshness model rewrites `image_tag` on
every rebuild. `IMMUTABLE` makes every scheduled rebuild fail on the push. If you
need immutable tags, also set `enable_scheduled_rebuild = false` and advance
`image_tag` yourself, and accept that patching becomes a Terraform change.

Each build additionally pushes `ash-<sanitized ash_version>`, so a specific build
stays addressable for rollback even though the moving tag has advanced.

**Config size ceiling.** SSM caps a parameter value at 4 KB on the Standard tier
and 8 KB on Advanced. Advanced is the highest tier, so 8 KB is a hard ceiling,
and `ash_base_config_yaml` is validated against it. A larger configuration has to
be baked into the image.

**Advanced tier is a one-way door.** A parameter can be upgraded from Standard to
Advanced but never downgraded, and Advanced is billed. `Intelligent-Tiering` is
the default because it picks Advanced only when the value actually exceeds 4 KB.
Shrinking a config back below 4 KB does not return the parameter to Standard.

**`privileged_mode` is required.** The project runs `docker build`, which needs
it. There is no way around this for a Docker-in-CodeBuild build.

**Native architecture only.** The build does not use QEMU emulation, so the
CodeBuild fleet architecture equals the image architecture. Building an `arm64`
image and an `x86_64` image means two instances of this module.

## What is first-party and what is not

Everything here is first-party Terraform against `hashicorp/aws`. No aws-ia
module is used: aws-ia publishes nothing covering ECR, CodeBuild, or an
EventBridge-triggered image build.
