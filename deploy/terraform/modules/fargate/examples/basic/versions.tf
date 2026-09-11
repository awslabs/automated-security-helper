terraform {
  # 1.9.0 is the floor the fargate module sets, for cross-variable validation.
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.62"
    }
    # No resource here uses awscc. It is declared because aws-ia/vpc/aws
    # requires it, and a root module's required_providers bounds the providers
    # its child modules pull in. Without this entry the only ceiling on awscc is
    # the vpc module's own ">= 0.15.0, >= 1.0.0", which lets an init cross into
    # 2.x and take its breaking changes.
    #
    # "~> 1.99" rather than "~> 1.99.0": awscc is generated from CloudFormation
    # schemas and ships a new minor on essentially every release, having
    # published one patch in 99 minors. A patch-only bound would name a range
    # and behave like a pin to a single version.
    awscc = {
      source  = "hashicorp/awscc"
      version = "~> 1.99"
    }
  }
}
