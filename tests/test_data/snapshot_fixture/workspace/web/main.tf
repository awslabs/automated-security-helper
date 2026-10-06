resource "aws_s3_bucket_acl" "site" {
  bucket = "snapshot-fixture-site"
  acl    = "public-read"
}
