resource "aws_lambda_function" "cloudguardian_scanner" {
  function_name = "CloudGuardian-Security-Scanner"

  role = aws_iam_role.cloudguardian_lambda_role.arn

  runtime = "python3.12"
  handler = "lambda_function.lambda_handler"

  filename         = "${path.module}/lambda.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda.zip")

  timeout     = 30
  memory_size = 128

  environment {
    variables = {
      FINDINGS_TABLE = aws_dynamodb_table.cloudguardian_findings.name
      SNS_TOPIC_ARN  = aws_sns_topic.cloudguardian_alerts.arn
      AUDIT_BUCKET   = aws_s3_bucket.cloudguardian_audit.bucket
    }
  }

  tags = {
    Project     = "CloudGuardian"
    Environment = "Sandbox"
    ManagedBy   = "Terraform"
  }
}