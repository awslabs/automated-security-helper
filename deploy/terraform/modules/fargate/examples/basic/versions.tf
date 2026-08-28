terraform {
  # 1.9.0 is the floor the fargate module sets, for cross-variable validation.
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.62"
    }
  }
}
