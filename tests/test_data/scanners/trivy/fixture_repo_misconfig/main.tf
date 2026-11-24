# Benign test fixture for the facets program's M0 sample runs (never deployed).
# A minimal Terraform resource that trivy's misconfiguration scanner flags
# (an S3 bucket with none of the hardening properties set), so a captured
# `trivy fs --scanners misconfig` run shows whether the native output names
# the terraform resource address (aws_s3_bucket.m0_fixture_bucket).
resource "aws_s3_bucket" "m0_fixture_bucket" {
  bucket = "ash-m0-facets-fixture-bucket"
}
