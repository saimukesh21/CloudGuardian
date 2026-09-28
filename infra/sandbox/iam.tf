# CloudGuardian Lambda IAM Role

resource "aws_iam_role" "cloudguardian_lambda_role" {
  name = "CloudGuardian-Lambda-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"


    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "lambda.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]


  })

  tags = {
    Project     = "CloudGuardian"
    Environment = "Sandbox"
    ManagedBy   = "Terraform"
  }
}

# CloudWatch Logs permission for Lambda

resource "aws_iam_role_policy_attachment" "cloudguardian_lambda_logs" {
  role       = aws_iam_role.cloudguardian_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# DynamoDB permissions

resource "aws_iam_role_policy" "cloudguardian_dynamodb_policy" {
  name = "CloudGuardian-DynamoDB-Policy"

  role = aws_iam_role.cloudguardian_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"


    Statement = [
      {
        Effect = "Allow"

        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:Scan",
          "dynamodb:Query"
        ]

        Resource = aws_dynamodb_table.cloudguardian_findings.arn
      }
    ]


  })
}

# IAM + S3 + EC2 read-only scanner permissions

resource "aws_iam_role_policy" "cloudguardian_iam_read_policy" {
  name = "CloudGuardian-IAM-ReadOnly-Policy"

  role = aws_iam_role.cloudguardian_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"


    Statement = [
      {
        Effect = "Allow"

        Action = [
          # IAM security checks
          "iam:GetAccountSummary",
          "iam:ListUsers",
          "iam:ListRoles",
          "iam:ListAccessKeys",
          "iam:ListMFADevices",
          "iam:GetLoginProfile",
          "iam:GetUser",

          # S3 security checks
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
          "s3:GetBucketAcl",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketVersioning",

          # EC2 security / cost checks
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "ec2:DescribeAddresses"
        ]

        Resource = "*"
      }
    ]


  })
}
# SNS permission for CloudGuardian Lambda

resource "aws_iam_role_policy" "cloudguardian_sns_policy" {
  name = "CloudGuardian-SNS-Policy"

  role = aws_iam_role.cloudguardian_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Action = [
          "sns:Publish"
        ]

        Resource = aws_sns_topic.cloudguardian_alerts.arn
      }
    ]
  })
}
resource "aws_iam_role_policy" "cloudguardian_bedrock_policy" {
  name = "CloudGuardian-Bedrock-Policy"

  role = aws_iam_role.cloudguardian_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Action = [
          "bedrock:InvokeModel"
        ]

        Resource = [
          "arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
          "arn:aws:bedrock:*:${data.aws_caller_identity.current.account_id}:inference-profile/global.anthropic.claude-haiku-4-5-20251001-v1:0"
        ]
      }
    ]
  })
}
resource "aws_iam_role_policy" "cloudguardian_report_s3_policy" {
  name = "CloudGuardian-Report-S3-Policy"

  role = aws_iam_role.cloudguardian_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Action = [
          "s3:PutObject"
        ]

        Resource = "${aws_s3_bucket.cloudguardian_audit.arn}/reports/*"
      }
    ]
  })
}