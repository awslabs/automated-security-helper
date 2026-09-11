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

## ASH owns the verdict, not this module

**A shard that happens to own no findings exits 0.** So a shard's exit code says
nothing about the scan as a whole. Gating the pipeline on shard exit codes would
report a clean scan every time the findings landed in some other shard — a false
pass, which is the worst failure a security gate can have.

So shards run with `--no-fail-on-findings` and findings never fail a shard action.
A shard *does* fail on a real crash: with that flag in effect a non-zero exit means
a genuine failure rather than findings, so it is safe to propagate, and failing
there stops the pipeline before anything forms a verdict from incomplete data.

The verdict is `ash merge`'s exit code, propagated unchanged:

| Exit | Meaning |
|---|---|
| 0 | No actionable findings at or above `min_severity` |
| 1 | Refused to merge — shard coverage incomplete, so findings are **unknown** |
| 2 | Actionable findings at or above `min_severity` |

**Nothing in this module re-derives that judgment**, and that is deliberate. ASH
routes the merged verdict through `_compute_exit_code`, the same function
`ash scan` uses, specifically so a merged verdict and a scanned verdict cannot
disagree about the same findings. A severity comparison written into a buildspec
would be a third copy of a table that has already drifted once in this codebase —
`automated_security_helper/utils/severity_ladder.py` exists because of that
drift — and the next time it drifted, this pipeline would silently report a
different verdict than `ash scan` for identical findings.

`min_severity` maps directly onto `ash merge --min-severity` for the same reason:
one implementation of "does this breach".

### `min_severity` is a floor, so lower is stricter

The name reads like a tolerance, but ASH tests
`rank(finding) >= rank(min_severity)`, which inverts the direction:

| `min_severity` | Fails the pipeline on | |
|---|---|---|
| `low` | low, medium, high | strictest |
| `medium` | medium, high | |
| `high` | high only | laxest |

`critical` and `high` share a rank in ASH's ladder, so they cannot be
distinguished here.

The default is `low`, matching ASH. On a gate the surprise has to run toward
failing a build for something you did not care about, never toward passing a build
that had findings. Raise it deliberately if that is what you want.

**Shard coverage is also ASH's check, not ours.** `merge_shard_results` raises
`ShardCoverageError` when the shard space is not fully covered and exits 1, with
the message being explicit that unknown findings are not the same as no findings.
That is stronger than anything this buildspec could do, because it reads the
`shard_index` and `shard_count` recorded *inside* each shard's own results rather
than trusting an external count or a marker file. An earlier version of this
module uploaded per-shard completion markers and checked them in shell; that was
removed as a duplicate.

One check does remain in the buildspec, because it is about the buildspec's own
input rather than about results: it **refuses to run on zero shards**.
`shard_count` is validated at `>= 1` in Terraform, but `SHARD_COUNT` reaches the
buildspec as an environment variable overridable at the project or action level,
below that validation. At zero, no `--results` would be passed at all.

`--fail-on-findings` is passed explicitly rather than left to ASH's default, which
falls back to the scan configuration. A base config carrying
`fail_on_findings: false` would otherwise make this pipeline green on every run
while still finding things.

The merged report is uploaded to S3 **before** the exit code is propagated, since a
threshold breach is exactly when someone wants the report.

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
| `min_severity` | — | `string` | `"low"` | Passed to `ash merge --min-severity`. A floor, so lower is stricter — see below. |
| `fail_on_findings` | — | `bool` | `true` | Passed explicitly so a base config cannot disable the gate. |
| `enable_eventbridge_trigger` | — | `bool` | `true` | Preferred over polling. |
| `build_compute_type` | — | `string` | `BUILD_GENERAL1_LARGE` | Scanners are CPU-bound. |
| `build_environment_type` | — | `string` | `LINUX_CONTAINER` | Must match the image architecture. |
| `shard_build_timeout_minutes` | — | `number` | `120` | |
| `merge_build_timeout_minutes` | — | `number` | `60` | |
| `results_prefix` | — | `string` | `"shard-results"` | |
| `results_retention_days` | — | `number` | `90` | Scan output accumulates per execution. |
| `artifact_bucket_force_destroy` | — | `bool` | `false` | |
| `kms_key_arn` | — | `string` | `null` | Existing key for the bucket, artifacts, build output and both log groups. `null` **creates one** — this changed, see below. |
| `kms_key_deletion_window_days` | — | `number` | `30` | 7-30. Recovery window for a created key. |
| `log_retention_days` | — | `number` | `30` | |
| `tags` | — | `map(string)` | `{}` | |

## Encryption

The results and artifact bucket, the pipeline's artifacts, both CodeBuild projects'
output and both build log groups are encrypted with a **customer managed** KMS key.
The merge log is the one to care about: it carries the whole scan's verdict and
every finding behind it.

**`kms_key_arn = null` changed meaning.** It used to mean "no customer managed
key", which left the bucket on SSE-S3 and both log groups under an Amazon-owned key
whose policy nobody here can read. It now means "create one". That is a behavior
change if you were relying on the old default, and the cost is one key's standing
monthly charge. There is no longer a third option.

**On upgrade this shows up as an unrequested resource.** If you have `kms_key_arn`
set to `null` explicitly, or never set it, the next `terraform plan` proposes
creating a KMS key you did not ask for and `terraform apply` starts billing for it.
The opt-out is to pass an existing key ARN, which is also how you avoid one key per
module; there is no way to opt back out of a customer managed key entirely.

`kms_key_arn` still overrides with a key you already have, which is how an adopter
composing several ASH modules ends up with one key instead of one per module — every
module exposes its key as the `kms_key_arn` output. `kms.tf` carries the rationale
and the key policy.

One key covers the results, the artifacts and both log groups rather than one key
each. AWS recommends a key per encrypted log group so a key policy can be narrowed
to a single log group ARN; that narrowing is not available here anyway (see below),
and the shard log, the merge log and the results they describe sit inside one trust
boundary, so a second key would buy no isolation and would multiply a standing
monthly charge.

**The encryption-context condition is account-scoped, not log-group-scoped.** The
tighter form names each log group's ARN, which would make the key reference the log
groups while the log groups reference the key — a cycle Terraform rejects outright,
and the same reason CloudFormation cannot express it either. AWS documents the
account-scoped variant for this case.

If you supply a key, it must already grant the CloudWatch Logs service principal
`kms:Encrypt`, `kms:Decrypt`, `kms:ReEncrypt*`, `kms:GenerateDataKey*` and
`kms:Describe*` under that condition. Terraform cannot check it, and a key without
it plans and validates cleanly, then fails at `CreateLogGroup`. Copy the policy
from `kms.tf`.

The principal running `terraform apply` needs `kms:DescribeKey` on the key, which
AWS requires of whoever calls `CreateLogGroup` with a `kmsKeyId`.

Bucket keys are on, which cuts the per-object KMS request count. That matters here:
a sharded scan writes one result set per shard per execution and the merge reads all
of them.

## Outputs

`pipeline_name`, `pipeline_arn`, `shard_count`, `shard_project_name`,
`merge_project_name`, `artifact_bucket_name`, `results_prefix`,
`merged_results_location_template`, `min_severity`, `fail_on_findings`,
`shard_log_group_name`, `merge_log_group_name`, `pipeline_role_arn`,
`shard_role_arn`, `merge_role_arn`, `kms_key_arn`.

## Constraints and known limitations

**`shard_count` above 100 is impossible in one stage.** CodePipeline allows at
most 100 parallel actions per stage and the quota is not adjustable. Going wider
would need multiple stages, which serializes them and defeats the purpose.

**Sharding splits by scanner, not by file.** ASH's partitioning assigns whole
scanners to shards, so `shard_count` beyond the number of enabled scanners leaves
shards with nothing to do. They still cost a CodeBuild start and still upload an
empty result set, so nothing breaks — they are simply wasted. Size `shard_count`
against the number of scanners your configuration enables.

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
