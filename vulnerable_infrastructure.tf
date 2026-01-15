resource "aws_s3_bucket" "bad_bucket" {
  bucket = "company-sensitive-data"
}

resource "aws_s3_bucket_public_access_block" "bad_bucket_acl" {
  bucket = aws_s3_bucket.bad_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_security_group" "bad_sg" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
