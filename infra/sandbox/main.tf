data "aws_caller_identity" "current" {}

data "aws_region" "current" {}
resource "aws_s3_bucket" "cloudguardian_audit" {
  bucket = "cloudguardian-audit-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "CloudGuardian Audit Bucket"
    Project     = "CloudGuardian"
    Environment = "Sandbox"
    ManagedBy   = "Terraform"
  }
}
resource "aws_s3_bucket_public_access_block" "cloudguardian_audit" {
  bucket = aws_s3_bucket.cloudguardian_audit.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_versioning" "cloudguardian_audit" {
  bucket = aws_s3_bucket.cloudguardian_audit.id

  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudguardian_audit" {
  bucket = aws_s3_bucket.cloudguardian_audit.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_lifecycle_configuration" "cloudguardian_audit" {
  bucket = aws_s3_bucket.cloudguardian_audit.id

  rule {
    id     = "audit-retention"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = 90
    }
  }
}