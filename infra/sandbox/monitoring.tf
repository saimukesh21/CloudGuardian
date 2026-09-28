resource "aws_cloudwatch_metric_alarm" "cloudguardian_lambda_errors" {
  alarm_name          = "CloudGuardian-Lambda-Errors"
  alarm_description   = "Alerts when CloudGuardian Lambda encounters execution errors"

  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1

  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"

  dimensions = {
    FunctionName = aws_lambda_function.cloudguardian_scanner.function_name
  }

  alarm_actions = [
    aws_sns_topic.cloudguardian_alerts.arn
  ]

  treat_missing_data = "notBreaching"

  tags = {
    Project     = "CloudGuardian"
    Environment = "Sandbox"
    ManagedBy   = "Terraform"
  }
}