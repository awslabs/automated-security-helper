# The pipeline role's StartBuild grant stays one pattern however many shards there are.
#
# Why this file exists: with one CodeBuild project per shard, listing every shard
# project's ARN in the pipeline role's inline policy grows the document with
# shard_count. At the 100-shard ceiling with the longest name_prefix the rule
# allows, that document is over the 10,240 characters IAM allows for a role's inline
# policies, so plan would pass and apply would fail. The grant names the shard
# projects by their shared name prefix instead, which every shard project matches
# and the merge project does not.
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
  shard_count               = 100
  name_prefix               = "abcdefghijklmnopqrstuvwxyz0123456"
}

run "start_builds_does_not_grow_with_shard_count" {
  command = plan

  assert {
    condition = alltrue([
      for statement in data.aws_iam_policy_document.pipeline.statement :
      length(statement.resources == null ? [] : tolist(statement.resources)) <= 2
      if statement.sid == "StartBuilds"
    ])
    error_message = "The StartBuilds statement lists ${length(flatten([for statement in data.aws_iam_policy_document.pipeline.statement : statement.resources if statement.sid == "StartBuilds"]))} resources at shard_count = 100; it must not grow with the shard count."
  }
}

# Control: the grant still reaches every shard project and the merge project, so the
# run above is not passing because the pipeline lost the right to start builds.
run "start_builds_still_reaches_every_project" {
  command = plan

  assert {
    condition = alltrue([
      for name in concat(aws_codebuild_project.shard[*].name, [aws_codebuild_project.merge.name]) : anytrue([
        for statement in data.aws_iam_policy_document.pipeline.statement : anytrue([
          for resource in(statement.resources == null ? [] : tolist(statement.resources)) :
          can(regex("^${replace(replace(resource, ".", "\\."), "*", ".*")}$", "arn:aws:codebuild:us-east-1:000000000000:project/${name}"))
        ])
        if statement.sid == "StartBuilds"
      ])
    ])
    error_message = "Some shard or merge project is not covered by the StartBuilds statement."
  }
}
