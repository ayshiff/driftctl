resource "random_string" "prefix" {
  length  = 6
  upper   = false
  special = false
}

resource "aws_s3_bucket" "foobar" {
  bucket = "${random_string.prefix.result}.driftctl-test.com"
}
