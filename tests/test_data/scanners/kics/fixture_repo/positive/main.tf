resource "aws_s3_bucket" "b" {
  bucket = "ash-kics-fixture"
  acl    = "public-read"
}
