# codepipeline-executor

Fans an ASH scan out across N parallel CodeBuild jobs, then merges the shards into
a single verdict.

Consumes the `image_uri` output of `ash-image-pipeline`.

## Stage layout

```
Source  ->  CodeCommit (existing repository, read only)
Scan    ->  N CodeBuild actions, all at run_order 1 (parallel)
            each: ash scan --shard-index <i> --shard-count <n>
Merge   ->  one CodeBuild action
            ash merge --results <shard-0> ... --results <shard-n-1> --output-dir merged
```

## The shard contract

Fixed, and the module holds to it exactly:

- `--shard-index` is **zero-based**. Indices 0 through `shard_count - 1` each run
  exactly once.
- `--shard-index` and `--shard-count` are **required together**. Both are always
  passed.
- `--results` is **repeatable** and accepts a **file or a directory**. The merge
  action passes one directory per shard.

## The merge action owns the verdict

This is the most important property here, and the reason the module is shaped the
way it is.

**A shard that happens to own no findings exits 0.** So a shard's exit code says
nothing about the scan as a whole. Gating the pipeline on shard exit codes would
report a clean scan every time the findings landed in some other shard — a false
pass, which is the worst failure a security gate can have.

So:

- Shards run with `--no-fail-on-findings`, so findings never fail a shard action.
- A shard *does* fail on a real crash. With `--no-fail-on-findings` in effect, a
  non-zero exit means a genuine failure rather than findings, so it is safe to
  propagate — and failing there stops the pipeline instead of letting the merge
  action form a verdict from incomplete data.
- The merge action computes pass or fail from the **merged** results.

The merge action also **refuses to merge a partial result set**. Each shard writes
a completion marker after its results are already uploaded; the merge action
requires one marker per shard and fails loudly if any is missing. Without that
check, a shard whose upload never landed would simply be absent, and a verdict
over some of the shards would look identical to a verdict over all of them.

It **refuses to run on zero shards** as well. `shard_count` is validated at
`>= 1` in Terraform, but `SHARD_COUNT` reaches the buildspec as an environment
variable and can be overridden at the project or action level. At zero the marker
loop would check nothing, `ash merge` would receive no `--results` at all, and the
verdict step would report a clean scan for a scan that never ran. The merge
buildspec therefore validates the value is a positive integer before doing
anything else.

The verdict itself is computed by a small script from the merged results file,
not from `ash merge`'s exit code. The shard flag contract fixes `--shard-index`,
`--shard-count`, `--results`, and `--output-dir`; it does not specify a gating
flag on `merge`, so depending on one would be depending on unpromised behavior.
A missing or unparseable merged results file exits 2 and is reported as unknown,
never as a pass.

## Why results travel through S3

A CodeBuild action accepts **1 to 5 input artifacts**. Passing shard results as
pipeline artifacts would cap the fan-in at five shards.

A CodePipeline stage permits **100 parallel actions**, and that quota is not
adjustable. So results go to
`s3://<bucket>/<results_prefix>/<pipeline-execution-id>/shard-<i>/`, and the merge
action reads them from there. `shard_count` is validated against 100 for that
reason.

The per-execution prefix comes from `#{codepipeline.PipelineExecutionId}`, an
implicit variable in CodePipeline's reserved namespace, passed to each action as an
environment variable override. That is what keeps two concurrent executions from
reading each other's shards.

## The ASH image is the build environment

Both projects set `image = container_image_uri` with
`image_pull_credentials_type = "SERVICE_ROLE"`, so `ash` is on PATH directly. No
Docker-in-Docker, no `privileged_mode`.

Two consequences follow, and both are easy to get wrong:

**No AWS CLI.** The ASH image ships `git`, `curl`, and `boto3` but not the AWS
CLI, so `aws s3 cp` is unavailable. S3 transfers go through
`files/ash_s3_sync.py`, a small boto3 helper embedded into the buildspecs.

**The image ENTRYPOINT does not run.** CodeBuild executes buildspec commands
through its own agent rather than the image's entrypoint — which is why a custom
image with its own entrypoint can run a buildspec at all. So
`ash-container-init`, which materializes the base config from SSM, would never
execute here. Both buildspecs therefore invoke it explicitly:

```
/usr/local/bin/ash-container-init ash scan ...
/usr/local/bin/ash-container-init ash merge ...
```

Without that, every shard would silently scan with ASH's defaults instead of the
configuration you supplied — a wrong result with no error. Invoking it explicitly
is also correct if a future CodeBuild release did run the entrypoint, since the
work it does is idempotent.

## Variables

| Variable | Contract | Type | Default | Notes |
|---|---|---|---|---|
| `codecommit_repository_arn` | `CodeCommitRepositoryArn` | `string` | *required* | Must already exist. Read only. |
| `container_image_uri` | — | `string` | *required* | Used as the CodeBuild environment image. |
| `shard_count` | `ShardCount` | `number` | `4` | 1-100. See the quota note above. |
| `ash_offline_mode` | `AshOfflineMode` | `bool` | `false` | Sets `ASH_OFFLINE`. |
| `base_config_ssm_parameter_name` | `AshBaseConfigYaml` (indirect) | `string` | `null` | Same config for every shard. |
| `base_config_ssm_parameter_arn` | — | `string` | `null` | Scopes `ssm:GetParameter`. |
| `name_prefix` | — | `string` | `"ash-scan"` | |
| `source_branch` | — | `string` | `"main"` | |
| `blocking_severities` | — | `list(string)` | `["critical","high"]` | Evaluated on merged results. |
| `enable_eventbridge_trigger` | — | `bool` | `true` | Preferred over polling. |
| `build_compute_type` | — | `string` | `BUILD_GENERAL1_LARGE` | Scanners are CPU-bound. |
| `build_environment_type` | — | `string` | `LINUX_CONTAINER` | Must match the image architecture. |
| `shard_build_timeout_minutes` | — | `number` | `120` | |
| `merge_build_timeout_minutes` | — | `number` | `60` | |
| `results_prefix` | — | `string` | `"shard-results"` | |
| `results_retention_days` | — | `number` | `90` | Scan output accumulates per execution. |
| `artifact_bucket_force_destroy` | — | `bool` | `false` | |
| `kms_key_arn` | — | `string` | `null` | `null` uses SSE-S3. |
| `log_retention_days` | — | `number` | `30` | |
| `tags` | — | `map(string)` | `{}` | |

## Outputs

`pipeline_name`, `pipeline_arn`, `shard_count`, `shard_project_name`,
`merge_project_name`, `artifact_bucket_name`, `results_prefix`,
`merged_results_location_template`, `blocking_severities`,
`shard_log_group_name`, `merge_log_group_name`, `pipeline_role_arn`,
`shard_role_arn`, `merge_role_arn`.

## Constraints and known limitations

**`shard_count` above 100 is impossible in one stage.** CodePipeline allows at
most 100 parallel actions per stage and the quota is not adjustable. Going wider
would need multiple stages, which serializes them and defeats the purpose.

**Sharding splits by scanner, not by file.** ASH's partitioning assigns whole
scanners to shards, so `shard_count` beyond the number of enabled scanners leaves
shards with nothing to do. They still cost a CodeBuild start and still upload a
completion marker, so nothing breaks — they are simply wasted. Size
`shard_count` against the number of scanners your configuration enables.

**One shard project, N actions.** Adding a shard adds an action, not a project.
The index arrives as a per-action `EnvironmentVariables` override. Note that
CodePipeline enforces a 1000-character limit on an action configuration value, so
a very large override set would be rejected — not reachable with what this module
passes.

**The results bucket also holds pipeline artifacts.** One bucket with two
prefixes, versioning on because CodePipeline requires it on its artifact bucket.
`results_retention_days` expires the results prefix; artifacts are left to
CodePipeline.

**Every shard must read the same configuration.** Merging partial results only
makes sense if the shards agreed on what to scan. Both projects therefore receive
the same `base_config_ssm_parameter_name`. Overriding the configuration per shard
would make the merged verdict meaningless.

**`ash merge` and the shard CLI flags are a cross-lane dependency.** At the commit
this module was written against, `automated_security_helper/core/sharding.py` and
the scan-phase shard selection exist, but `--shard-index` / `--shard-count` are
not yet wired onto `ash scan`, and there is no `ash merge` command or `--results`
flag. This module is written against the stated contract for both. It will plan
and apply against an image that lacks them; the shard and merge actions will fail
at run time until the image is built from a revision that has them.

## What is first-party and what is not

All first-party `hashicorp/aws`. No aws-ia module covers CodePipeline, CodeBuild,
or the S3 wiring between them.
