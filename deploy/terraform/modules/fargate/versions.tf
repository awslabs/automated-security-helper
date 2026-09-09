terraform {
  # 1.9.0 for input variable validation rules that reference other variables.
  # This module uses one to refuse a plaintext listener carrying a static auth
  # header, which is a cross-variable condition.
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.62"
    }
  }
}
