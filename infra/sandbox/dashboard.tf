resource "aws_cloudwatch_dashboard" "cloudguardian_dashboard" {
  dashboard_name = "CloudGuardian-Dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 2

        properties = {
          markdown = "# CloudGuardian Security Dashboard\nAWS security scanning, monitoring and governance overview."
        }
      },

      {
        type   = "metric"
        x      = 0
        y      = 2
        width  = 12
        height = 6

        properties = {
          title  = "Lambda Invocations"
          region = "ap-south-2"
          view   = "timeSeries"

          metrics = [
            [
              "AWS/Lambda",
              "Invocations",
              "FunctionName",
              "CloudGuardian-Security-Scanner"
            ]
          ]

          period = 300
          stat   = "Sum"
        }
      },

      {
        type   = "metric"
        x      = 12
        y      = 2
        width  = 12
        height = 6

        properties = {
          title  = "Lambda Errors"
          region = "ap-south-2"
          view   = "timeSeries"

          metrics = [
            [
              "AWS/Lambda",
              "Errors",
              "FunctionName",
              "CloudGuardian-Security-Scanner"
            ]
          ]

          period = 300
          stat   = "Sum"
        }
      },

      {
        type   = "metric"
        x      = 0
        y      = 8
        width  = 12
        height = 6

        properties = {
          title  = "Lambda Duration"
          region = "ap-south-2"
          view   = "timeSeries"

          metrics = [
            [
              "AWS/Lambda",
              "Duration",
              "FunctionName",
              "CloudGuardian-Security-Scanner"
            ]
          ]

          period = 300
          stat   = "Average"
        }
      },

      {
        type   = "metric"
        x      = 12
        y      = 8
        width  = 12
        height = 6

        properties = {
          title  = "DynamoDB Consumed Capacity"
          region = "ap-south-2"
          view   = "timeSeries"

          metrics = [
            [
              "AWS/DynamoDB",
              "ConsumedReadCapacityUnits",
              "TableName",
              "CloudGuardian-Findings"
            ],
            [
              "AWS/DynamoDB",
              "ConsumedWriteCapacityUnits",
              "TableName",
              "CloudGuardian-Findings"
            ]
          ]

          period = 300
          stat   = "Sum"
        }
      },

      {
        type   = "alarm"
        x      = 0
        y      = 14
        width  = 24
        height = 5

        properties = {
          title = "CloudGuardian Lambda Error Alarm"

          alarms = [
            aws_cloudwatch_metric_alarm.cloudguardian_lambda_errors.arn
          ]
        }
      }
    ]
  })
}