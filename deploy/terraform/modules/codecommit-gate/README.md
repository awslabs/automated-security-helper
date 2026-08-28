# codecommit-gate

Scans every pull request on an existing CodeCommit repository with ASH and posts
the result back to the pull request.

Flow: EventBridge rule on `CodeCommit Pull Request State Change` -> container
Lambda -> `ash scan` -> `PostCommentForPullRequest`, and optionally an approval
rule.

## Your repository is never created or deleted

`codecommit_repository_arn` names a repository you already have. There is no
`aws_codecommit_repository` resource in this module and there will not be one.
Every CodeCommit permission on the gate's role is scoped to that single ARN, and
the actions are reads plus `PostCommentForPullRequest`.

The one thing that touches your repository's configuration is the optional
approval rule template association, behind `create_approval_rule_template`, which
defaults to `false` and is reversible.

CodeCommit is available to new customers again, so nothing here is deprecated.

## Why there is a second image build

Lambda cannot invoke the shared ASH image. That image is not built from an AWS
Lambda base image, so it carries no runtime interface client, and without one
Lambda has nothing to hand an invocation to.

This module therefore runs its own small CodeBuild project that layers two things
onto the shared image:

- `awslambdaric`, the runtime interface client, which becomes the entrypoint. The
  shared `ash-container-init` entrypoint still runs first, so the base config
  from SSM is on disk before the client starts accepting invocations.
- `git-remote-codecommit`, so `git clone codecommit::<region>://<repo>` signs with
  the Lambda role's own credentials. The alternative is long-lived Git credentials
  or the AWS CLI credential helper, and the ASH image ships neither the CLI nor a
  reason to hold static credentials.

Keeping this separate from `ash-image-pipeline` is deliberate. Neither addition is
useful to the other three targets, and `pip install` needs a reachable index at
build time, which would break an otherwise offline image build for all of them.

Set `base_image_codebuild_project_arn` and the gate image rebuild is chained off
the shared image's successful builds through an EventBridge rule on
`CodeBuild Build State Change`. Without that, a daily base rebuild would leave the
Lambda on an image whose base has been replaced — which is the staleness the
schedule exists to prevent.

## Three outcomes, and why the exit code is not enough

The verdict is `ash scan`'s exit code, mapped directly:

| `ash scan` exit | Outcome | Comment says |
|---|---|---|
| 0 | `pass` | No actionable findings at or above `min_severity` |
| 2 | `findings` | Actionable findings, plus the severity table |
| anything else | `error` | Explicitly **not** a pass, with the exit code and log tail |

**The handler does not compare severities to reach that verdict.** It hands
`--min-severity` to ASH and reports what ASH decided. `ash scan` routes its exit
code through `_compute_exit_code` — the same function `ash merge` uses — so this
gate cannot disagree with a scan, or with the `codepipeline-executor` module, about
identical findings. A severity table reimplemented here would be another copy of
the one `automated_security_helper/utils/severity_ladder.py` exists to consolidate,
and when it drifted this gate would pass pull requests that `ash scan` fails.

Severity counts *are* read from the results file, but only to render the comment
table. A missing table never downgrades a clean verdict.

ASH returns 1 from `_compute_exit_code` when it produced no results at all, so a
crashed scan lands in `error` rather than being mistaken for either real outcome.
Reporting "no findings" for a scan that never ran would be the worst thing this
gate could do.

For the same reason, when `manage_approval_state` is on, approval is only ever set
to `APPROVE`, and only on `pass`. An `error` leaves the approval state untouched
rather than revoking it, so an infrastructure failure cannot be mistaken for a
security judgment.

## Variables

| Variable | Contract | Type | Default | Notes |
|---|---|---|---|---|
| `codecommit_repository_arn` | `CodeCommitRepositoryArn` | `string` | *required* | Must already exist. Never created or deleted. |
| `base_image_uri` | — | `string` | *required* | Shared ASH image, the base for the gate image. |
| `base_image_codebuild_project_arn` | — | `string` | `null` | Set it to chain the gate rebuild off the base rebuild. |
| `ash_offline_mode` | `AshOfflineMode` | `bool` | `false` | Sets `ASH_OFFLINE`. |
| `base_config_ssm_parameter_name` | `AshBaseConfigYaml` (indirect) | `string` | `null` | From the image module. |
| `base_config_ssm_parameter_arn` | — | `string` | `null` | Scopes `ssm:GetParameter`. |
| `name_prefix` | — | `string` | `"ash-pr-gate"` | |
| `trigger_events` | — | `list(string)` | created + source branch updated | The two that change what would merge. |
| `min_severity` | — | `string` | `"high"` | Passed to `ash scan --min-severity`. ASH evaluates it. |
| `fail_on_findings` | — | `bool` | `true` | Passed explicitly so a base config cannot disable the gate. |
| `create_approval_rule_template` | — | `bool` | `false` | Changes your repository's settings. |
| `manage_approval_state` | — | `bool` | `false` | Only ever approves, only on a clean scan. |
| `approval_rule_approvals_required` | — | `number` | `1` | Template only. |
| `lambda_timeout_seconds` | — | `number` | `900` | Lambda's hard maximum. See limitations. |
| `lambda_memory_mb` | — | `number` | `4096` | Also sets CPU share; ASH is CPU-bound. |
| `lambda_ephemeral_storage_mb` | — | `number` | `4096` | `/tmp` holds the clone and the output. |
| `lambda_architecture` | — | `string` | `"x86_64"` | Must match the base image. |
| `reserved_concurrent_executions` | — | `number` | `-1` | Worth setting on a busy repository. |
| `ash_scan_extra_args` | — | `string` | `""` | `--changed-files-only --base-ref ...` recommended. |
| `max_comment_chars` | — | `number` | `10000` | Defensive; the API documents no limit. |
| `image_tag` | — | `string` | `"latest"` | |
| `ecr_image_tag_mutability` | — | `string` | `"MUTABLE"` | Needed for the chained rebuild. |
| `ecr_force_delete` | — | `bool` | `false` | |
| `image_retention_count` | — | `number` | `10` | |
| `build_timeout_minutes` | — | `number` | `30` | |
| `log_retention_days` | — | `number` | `30` | |
| `tags` | — | `map(string)` | `{}` | |

## Outputs

`function_name`, `function_arn`, `role_arn`, `gate_image_uri`,
`gate_ecr_repository_url`, `gate_image_codebuild_project_name`,
`bootstrap_command`, `event_rule_arn`, `repository_name`,
`approval_rule_template_name`, `log_group_name`.

## Constraints and known limitations

**Lambda's 900 second ceiling is the real constraint on this target, and it is
not adjustable.** The clone plus the scan has to fit. Two things make that
reachable, and a third is the fallback:

1. `ash_scan_extra_args = "--changed-files-only --base-ref origin/<default>"`,
   so scan time scales with the change rather than the repository.
2. More `lambda_memory_mb`, since Lambda allocates CPU in proportion to memory
   and ASH is CPU-bound.
3. For repositories where neither is enough, use the `codepipeline-executor`
   module instead. CodeBuild's action timeout is measured in hours, not minutes.

**The clone is not shallow.** CodeCommit does not reliably permit fetching an
arbitrary commit SHA directly, so the pull request's source branch is cloned in
full and the SHA is then checked out from that history. Clone time therefore
scales with repository history, and it is the main cost driver here.

**The gate image build needs network access to a Python index**, for
`awslambdaric` and `git-remote-codecommit`, even when `ash_offline_mode` is true.
`ash_offline_mode` affects how ASH behaves at scan time; it does not make this
build offline.

**`/tmp` is reused across warm invocations.** The handler removes its working
tree at the start of each run, because otherwise a previous pull request's
checkout would be scanned alongside the current one.

**The comment length cap is defensive, not documented.** The
`PostCommentForPullRequest` API reference states no maximum for `content`, so
`max_comment_chars` is a guard against a rejected call losing the result, not
enforcement of a published limit.

**The severity-count parse is display-only and tolerates two shapes.** ASH's
results model permits extra fields and has carried severity counts both nested
under `severity_counts` and flat on `summary_stats`. The handler accepts either,
and if it finds neither it simply omits the table from the comment. That is safe
precisely because these counts do not decide anything — the verdict is already
`ash scan`'s exit code, so a report-shape change costs a table, not a correct
pass or fail.

## What is first-party and what is not

All first-party `hashicorp/aws`. No aws-ia module covers CodeCommit, EventBridge,
or Lambda.
