# Example: sharded ASH scan across 8 parallel CodeBuild jobs

Builds the ASH image, then runs a pipeline that fans a scan out across 8 shards
and merges the results into a single verdict.

## Run it

```console
terraform init
terraform plan -var 'codecommit_repository_arn=arn:aws:codecommit:<region>:<account>:<repo>'
terraform apply -var 'codecommit_repository_arn=arn:aws:codecommit:<region>:<account>:<repo>'
```

Then build the image. The shard and merge actions use it as their CodeBuild
environment image, so they cannot start until it exists:

```console
terraform output -raw run_the_first_build
```

Run the printed command. After it succeeds, push to `main` (or start the pipeline
by hand) and the scan runs.

## Reading the result

The verdict is printed in the merge build's log, not in any shard's:

```console
terraform output -raw where_the_verdict_is_printed
```

A shard log tells you only what that shard found. `terraform output
merged_results_location_template` shows where the full merged results are written
in S3.

## Why 8 shards is a meaningful number here

A CodeBuild action accepts 1 to 5 input artifacts. If shard results were passed as
pipeline artifacts, the merge action would cap out at 5 shards. They go through S3
instead, so the real ceiling is CodePipeline's 100-parallel-actions-per-stage
quota.

## Why the pipeline does not fail on a shard

A shard that happens to own no findings exits 0. Gating on shard exit codes would
therefore report a clean scan whenever the findings landed in a different shard.
Shards run with `--no-fail-on-findings` and fail only on a real crash; the merge
action forms the verdict from the merged results.

The merge action also refuses to merge a partial result set. If any shard's
completion marker is missing it fails rather than producing a confident verdict
over part of the codebase.
