# CloudGuardian SNS Topic

resource "aws_sns_topic" "cloudguardian_alerts" {
  name = "CloudGuardian-Security-Alerts"

  tags = {
    Project     = "CloudGuardian"
    Environment = "Sandbox"
    ManagedBy   = "Terraform"
  }
}

# SNS Topic Subscription

resource "aws_sns_topic_subscription" "cloudguardian_email" {
  topic_arn = aws_sns_topic.cloudguardian_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}