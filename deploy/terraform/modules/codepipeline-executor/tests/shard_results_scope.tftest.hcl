# Each shard can write only its own results.
#
# Why this file exists: the merge action forms the pipeline's verdict from what is
# under <results_prefix>/<execution id>/ in the artifact bucket, and every shard runs
# scanners over the repository being scanned. Each shard writes
# <results_prefix>/*/shard-<its index>/* and nothing else, so no shard writes another
# shard's ash_aggregated_results.json or the merged output. That takes a role per
# shard: IAM cannot tell two actions of one role apart.
#
# The execution id segment is one `?` per character of a CodePipeline execution id,
# so a shard cannot nest its own index under another shard's key or under merged/.
# IAM has no variable holding the running execution's id, so a shard can write
# under another execution's id; the last run checks it cannot list the bucket or
# ask the pipeline, which is how it would learn one.
#
# The check is semantic. For every shard index it asks whether any write grant that
# applies to that shard COVERS a concrete key, using IAM's `*` wildcard, rather than
# comparing policy strings. The statements are read from the policy documents the
# module configures (a mocked provider does not render their JSON): one shard
# document per shard (`shard[i]`, the module uses count), plus the shared
# build_common document, which the expressions accept with or without an index.
# A per-shard reference cannot fall back to the unindexed name inside try():
# Terraform rejects `shard.statement` on a counted resource while validating the
# expression, before try() runs.
#
# Run with `terraform test` from this module directory after `terraform init
# -backend=false`. Every provider call is mocked.

mock_provider "aws" {
  override_during = plan

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "000000000000"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "us-east-1"
      name   = "us-east-1"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_resource "aws_s3_bucket" {
    defaults = {
      arn    = "arn:aws:s3:::ash-exec-artifacts"
      bucket = "ash-exec-artifacts"
      id     = "ash-exec-artifacts"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:us-east-1:000000000000:log-group:/aws/codebuild/ash-shard"
    }
  }
}

variables {
  codecommit_repository_arn = "arn:aws:codecommit:us-east-1:000000000000:scanned-repo"
  container_image_uri       = "000000000000.dkr.ecr.us-east-1.amazonaws.com/ash:latest"
  shard_count               = 3
}

# Control: a shard build can upload its own results under its own build ARN, so the run
# below is not passing because the shards lost their write grant. `$${codebuild:BuildArn}`
# is replaced with the calling build's ARN before matching, as IAM does.
run "each_shard_can_write_its_own_results" {
  command = plan

  assert {
    condition = alltrue([
      for i in range(var.shard_count) : anytrue([
        for statement in concat(
          tolist(data.aws_iam_policy_document.shard[i].statement),
          tolist(try(data.aws_iam_policy_document.build_common[i].statement, data.aws_iam_policy_document.build_common[tostring(i)].statement, data.aws_iam_policy_document.build_common.statement)),
          ) : anytrue([
            for resource in(statement.resources == null ? [] : tolist(statement.resources)) :
            can(regex("^${replace(replace(replace(replace(resource, "$${codebuild:BuildArn}", "arn:aws:codebuild:us-east-1:000000000000:build/ash-scan-shard-${i}:6d1f0e2c-4b5a-4968-8776-655443322110"), ".", "\\."), "*", ".*"), "?", ".")}$", "arn:aws:s3:::ash-exec-artifacts/${var.results_prefix}/0f1e2d3c-4b5a-4968-8776-655443322110/shard-${i}/arn:aws:codebuild:us-east-1:000000000000:build/ash-scan-shard-${i}:6d1f0e2c-4b5a-4968-8776-655443322110/ash_aggregated_results.json"))
        ])
        if(statement.effect == null ? "Allow" : statement.effect) == "Allow" && anytrue([
          for action in(statement.actions == null ? [] : tolist(statement.actions)) :
          action == "*" || can(regex("^s3:(\\*|Put|Delete|Abort|Restore|Replicate)", action))
        ])
      ])
    ])
    error_message = "Some shard has no grant that lets it upload its own results under its own build."
  }
}

run "no_shard_can_write_another_builds_or_shards_results_or_the_merged_output" {
  command = plan

  assert {
    condition = length(flatten([
      for i in range(var.shard_count) : [
        for key in [
          "${var.results_prefix}/0f1e2d3c-4b5a-4968-8776-655443322110/shard-${i}/arn:aws:codebuild:us-east-1:000000000000:build/ash-scan-shard-${i}:00000000-0000-4000-8000-000000000001/ash_aggregated_results.json",
          "${var.results_prefix}/0f1e2d3c-4b5a-4968-8776-655443322110/shard-${i}/ash_aggregated_results.json",
          "${var.results_prefix}/0f1e2d3c-4b5a-4968-8776-655443322110/shard-${(i + 1) % var.shard_count}/arn:aws:codebuild:us-east-1:000000000000:build/ash-scan-shard-${i}:6d1f0e2c-4b5a-4968-8776-655443322110/ash_aggregated_results.json",
          "${var.results_prefix}/0f1e2d3c-4b5a-4968-8776-655443322110/merged/arn:aws:codebuild:us-east-1:000000000000:build/ash-scan-shard-${i}:6d1f0e2c-4b5a-4968-8776-655443322110/ash_aggregated_results.json",
          "${var.results_prefix}/0f1e2d3c-4b5a-4968-8776-655443322110/shard-${i}0/arn:aws:codebuild:us-east-1:000000000000:build/ash-scan-shard-${i}:6d1f0e2c-4b5a-4968-8776-655443322110/ash_aggregated_results.json",
          "elsewhere/shard-${i}/arn:aws:codebuild:us-east-1:000000000000:build/ash-scan-shard-${i}:6d1f0e2c-4b5a-4968-8776-655443322110/ash_aggregated_results.json",
          "${var.results_prefix}/0f1e2d3c-4b5a-4968-8776-655443322110/merged/shard-${i}/arn:aws:codebuild:us-east-1:000000000000:build/ash-scan-shard-${i}:6d1f0e2c-4b5a-4968-8776-655443322110/ash_aggregated_results.json",
          "${var.results_prefix}/0f1e2d3c-4b5a-4968-8776-655443322110/shard-${(i + 1) % var.shard_count}/shard-${i}/arn:aws:codebuild:us-east-1:000000000000:build/ash-scan-shard-${i}:6d1f0e2c-4b5a-4968-8776-655443322110/ash_aggregated_results.json",
          "${var.results_prefix}/not-an-execution-id/shard-${i}/arn:aws:codebuild:us-east-1:000000000000:build/ash-scan-shard-${i}:6d1f0e2c-4b5a-4968-8776-655443322110/ash_aggregated_results.json",
        ] : "shard ${i} can write ${key}"
        if anytrue([
          for statement in concat(
            tolist(data.aws_iam_policy_document.shard[i].statement),
            tolist(try(data.aws_iam_policy_document.build_common[i].statement, data.aws_iam_policy_document.build_common[tostring(i)].statement, data.aws_iam_policy_document.build_common.statement)),
            ) : anytrue([
              for resource in(statement.resources == null ? [] : tolist(statement.resources)) :
              can(regex("^${replace(replace(replace(replace(resource, "$${codebuild:BuildArn}", "arn:aws:codebuild:us-east-1:000000000000:build/ash-scan-shard-${i}:6d1f0e2c-4b5a-4968-8776-655443322110"), ".", "\\."), "*", ".*"), "?", ".")}$", "arn:aws:s3:::ash-exec-artifacts/${key}"))
          ])
          if(statement.effect == null ? "Allow" : statement.effect) == "Allow" && anytrue([
            for action in(statement.actions == null ? [] : tolist(statement.actions)) :
            action == "*" || can(regex("^s3:(\\*|Put|Delete|Abort|Restore|Replicate)", action))
          ])
        ])
      ]
    ])) == 0
    error_message = "A shard build can write a key that is not its own results under its own build."
  }
}

run "the_merge_may_list_only_this_pipelines_action_executions" {
  command = plan

  assert {
    condition = flatten([
      for statement in tolist(data.aws_iam_policy_document.merge.statement) :
      tolist(statement.resources)
      if contains(tolist(statement.actions), "codepipeline:ListActionExecutions")
    ]) == ["arn:aws:codepipeline:us-east-1:000000000000:${var.name_prefix}"]
    error_message = "The merge role must list action executions of this module's pipeline and nothing else."
  }
}

run "no_shard_can_list_the_bucket_or_read_the_pipeline" {
  command = plan

  assert {
    condition = length(flatten([
      for i in range(var.shard_count) : [
        for statement in concat(
          tolist(data.aws_iam_policy_document.shard[i].statement),
          tolist(try(data.aws_iam_policy_document.build_common[i].statement, data.aws_iam_policy_document.build_common[tostring(i)].statement, data.aws_iam_policy_document.build_common.statement)),
          ) : [
          for action in(statement.actions == null ? [] : tolist(statement.actions)) :
          "shard ${i} holds ${action}"
          if can(regex("^(\\*|s3:\\*|s3:List|codepipeline:)", action))
        ]
        if(statement.effect == null ? "Allow" : statement.effect) == "Allow"
      ]
    ])) == 0
    error_message = "A shard role can list the results bucket or read the pipeline."
  }
}
