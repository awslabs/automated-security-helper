# The gate image build role pushes only to the gate's own ECR repository.
#
# Why this file exists: the role's policy granted the ECR push actions (PutImage and
# the three layer-upload actions) on `repository/*`, every repository in the account
# and Region, while the comment beside it said the role was scoped to this module's
# repository. The build runs privileged Docker over a base image, so a role that can
# overwrite any repository can replace the images every other workload in the account
# pulls. Pulling the shared base image still needs a read grant that reaches another
# repository; only the push half has to narrow.
#
# Run with `terraform test` from this module directory after `terraform init
# -backend=false`. Every provider call is mocked: nothing is planned against, or
# sent to, an AWS account. The assertions read the policy document's statements as
# the module configures them; a mocked provider does not render the document's JSON.

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

  mock_resource "aws_ecr_repository" {
    defaults = {
      arn            = "arn:aws:ecr:us-east-1:000000000000:repository/ash-pr-gate-lambda"
      repository_url = "000000000000.dkr.ecr.us-east-1.amazonaws.com/ash-pr-gate-lambda"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:us-east-1:000000000000:log-group:/aws/codebuild/ash-pr-gate-image-build"
    }
  }
}

variables {
  codecommit_repository_arn = "arn:aws:codecommit:us-east-1:000000000000:gated-repo"
  base_image_uri            = "000000000000.dkr.ecr.us-east-1.amazonaws.com/ash-shared:latest"
}

# Control: the build can push the image it builds, so the run below is not passing
# because push was dropped altogether.
run "the_build_role_can_push_to_the_gate_repository" {
  command = plan

  assert {
    condition = anytrue([
      for statement in data.aws_iam_policy_document.build.statement :
      contains(statement.resources == null ? [] : tolist(statement.resources), aws_ecr_repository.gate.arn)
      if(statement.effect == null ? "Allow" : statement.effect) == "Allow" && anytrue([
        for action in(statement.actions == null ? [] : tolist(statement.actions)) :
        action == "*" || can(regex("^ecr:(\\*|Put|InitiateLayerUpload|UploadLayerPart|CompleteLayerUpload)", action))
      ])
    ])
    error_message = "No statement lets the image build role push to the gate repository, so the gate image could not be published."
  }
}

run "the_build_role_pushes_to_no_other_repository" {
  command = plan

  assert {
    condition = length(flatten([
      for statement in data.aws_iam_policy_document.build.statement : [
        for resource in(statement.resources == null ? [] : tolist(statement.resources)) : resource
        if resource != aws_ecr_repository.gate.arn
      ]
      if(statement.effect == null ? "Allow" : statement.effect) == "Allow" && anytrue([
        for action in(statement.actions == null ? [] : tolist(statement.actions)) :
        action == "*" || can(regex("^ecr:(\\*|Put|InitiateLayerUpload|UploadLayerPart|CompleteLayerUpload)", action))
      ])
    ])) == 0
    error_message = "The image build role can push to repositories other than the gate's own: ${jsonencode(flatten([for statement in data.aws_iam_policy_document.build.statement : [for resource in(statement.resources == null ? [] : tolist(statement.resources)) : resource if resource != aws_ecr_repository.gate.arn] if anytrue([for action in(statement.actions == null ? [] : tolist(statement.actions)) : action == "*" || can(regex("^ecr:(\\*|Put|InitiateLayerUpload|UploadLayerPart|CompleteLayerUpload)", action))])]))}"
  }
}
