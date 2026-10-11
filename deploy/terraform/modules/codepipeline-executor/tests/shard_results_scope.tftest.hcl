# Each shard can write only its own results.
#
# Why this file exists: the merge action forms the pipeline's verdict from whatever
# sits under <results_prefix>/<execution id>/ in the artifact bucket. The shard role
# could write s3:PutObject anywhere under <results_prefix>/*, and every shard action
# runs as that one role while scanners run over the repository being scanned. So one
# shard could replace another shard's ash_aggregated_results.json, or the merged
# output, and the merge would report a verdict about results no shard produced. Each
# shard has to be able to write <results_prefix>/*/shard-<its index>/* and nothing
# else, which means a role per shard: IAM cannot tell two actions of one role apart.
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

# Control: a shard can upload its own results, so the run below is not passing
# because the shards lost their write grant.
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
            can(regex("^${replace(replace(resource, ".", "\\."), "*", ".*")}$", "arn:aws:s3:::ash-exec-artifacts/${var.results_prefix}/exec-1/shard-${i}/ash_aggregated_results.json"))
        ])
        if(statement.effect == null ? "Allow" : statement.effect) == "Allow" && anytrue([
          for action in(statement.actions == null ? [] : tolist(statement.actions)) :
          action == "*" || can(regex("^s3:(\\*|Put|Delete|Abort|Restore|Replicate)", action))
        ])
      ])
    ])
    error_message = "Some shard has no grant that lets it upload its own results."
  }
}

run "no_shard_can_write_another_shards_results_or_the_merged_output" {
  command = plan

  assert {
    condition = length(flatten([
      for i in range(var.shard_count) : [
        for key in [
          "${var.results_prefix}/exec-1/shard-${(i + 1) % var.shard_count}/ash_aggregated_results.json",
          "${var.results_prefix}/exec-1/merged/ash_aggregated_results.json",
          "${var.results_prefix}/exec-1/shard-${i}0/ash_aggregated_results.json",
          "elsewhere/shard-${i}/ash_aggregated_results.json",
        ] : "shard ${i} can write ${key}"
        if anytrue([
          for statement in concat(
            tolist(data.aws_iam_policy_document.shard[i].statement),
            tolist(try(data.aws_iam_policy_document.build_common[i].statement, data.aws_iam_policy_document.build_common[tostring(i)].statement, data.aws_iam_policy_document.build_common.statement)),
            ) : anytrue([
              for resource in(statement.resources == null ? [] : tolist(statement.resources)) :
              can(regex("^${replace(replace(resource, ".", "\\."), "*", ".*")}$", "arn:aws:s3:::ash-exec-artifacts/${key}"))
          ])
          if(statement.effect == null ? "Allow" : statement.effect) == "Allow" && anytrue([
            for action in(statement.actions == null ? [] : tolist(statement.actions)) :
            action == "*" || can(regex("^s3:(\\*|Put|Delete|Abort|Restore|Replicate)", action))
          ])
        ])
      ]
    ])) == 0
    error_message = "A shard can write results that are not its own: ${jsonencode(flatten([for i in range(var.shard_count) : [for key in ["${var.results_prefix}/exec-1/shard-${(i + 1) % var.shard_count}/ash_aggregated_results.json", "${var.results_prefix}/exec-1/merged/ash_aggregated_results.json"] : "shard ${i} can write ${key}" if anytrue([for statement in concat(tolist(data.aws_iam_policy_document.shard[i].statement), tolist(try(data.aws_iam_policy_document.build_common[i].statement, data.aws_iam_policy_document.build_common[tostring(i)].statement, data.aws_iam_policy_document.build_common.statement))) : anytrue([for resource in(statement.resources == null ? [] : tolist(statement.resources)) : can(regex("^${replace(replace(resource, ".", "\\."), "*", ".*")}$", "arn:aws:s3:::ash-exec-artifacts/${key}"))]) if anytrue([for action in(statement.actions == null ? [] : tolist(statement.actions)) : action == "*" || can(regex("^s3:(\\*|Put|Delete|Abort|Restore|Replicate)", action))])])]]))}"
  }
}
