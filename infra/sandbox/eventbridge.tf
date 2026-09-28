# EventBridge Scheduler IAM Role

resource "aws_iam_role" "cloudguardian_scheduler_role" {
  name = "CloudGuardian-Scheduler-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "scheduler.amazonaws.com"
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

# Allow EventBridge Scheduler to invoke Lambda

resource "aws_iam_role_policy" "cloudguardian_scheduler_lambda_policy" {
  name = "CloudGuardian-Scheduler-Lambda-Policy"

  role = aws_iam_role.cloudguardian_scheduler_role.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Action = [
          "lambda:InvokeFunction"
        ]

        Resource = aws_lambda_function.cloudguardian_scanner.arn
      }
    ]
  })
}

# EventBridge Scheduler

resource "aws_scheduler_schedule" "cloudguardian_daily_scan" {
  name = "CloudGuardian-Daily-Scan"

  schedule_expression          = "cron(0 9 * * ? *)"
  schedule_expression_timezone = "Asia/Kolkata"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.cloudguardian_scanner.arn
    role_arn = aws_iam_role.cloudguardian_scheduler_role.arn
  }
}
