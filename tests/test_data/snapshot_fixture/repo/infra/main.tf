# Public, unencrypted, unlogged bucket. Insecure on purpose.
resource "aws_s3_bucket" "exports" {
  bucket = "snapshot-fixture-exports"
}

resource "aws_s3_bucket_acl" "exports" {
  bucket = aws_s3_bucket.exports.id
  acl    = "public-read"
}
