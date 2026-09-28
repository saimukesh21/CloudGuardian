resource "aws_cloudtrail" "cloudguardian_trail" {
  name                          = "CloudGuardian-Trail"
  s3_bucket_name                = aws_s3_bucket.cloudguardian_audit.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  tags = {
    Project     = "CloudGuardian"
    Environment = "Sandbox"
    ManagedBy   = "Terraform"
  }

  depends_on = [
    aws_s3_bucket_policy.cloudguardian_cloudtrail
  ]
}

resource "aws_s3_bucket_policy" "cloudguardian_cloudtrail" {
  bucket = aws_s3_bucket.cloudguardian_audit.id

  policy = jsonencode({
    Version = "2012-10-17"


    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"

        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }

        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudguardian_audit.arn
      },

      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"

        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }

        Action = "s3:PutObject"

        Resource = "${aws_s3_bucket.cloudguardian_audit.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"

        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]


  })
}
