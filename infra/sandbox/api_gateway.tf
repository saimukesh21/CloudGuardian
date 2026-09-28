# CloudGuardian API Gateway

resource "aws_apigatewayv2_api" "cloudguardian_api" {
  name          = "CloudGuardian-API"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST"]
    allow_headers = ["content-type"]
  }

  tags = {
    Project     = "CloudGuardian"
    Environment = "Sandbox"
    ManagedBy   = "Terraform"
  }
}

# Default stage with automatic deployment

resource "aws_apigatewayv2_stage" "cloudguardian_api_stage" {
  api_id      = aws_apigatewayv2_api.cloudguardian_api.id
  name        = "$default"
  auto_deploy = true
}

# Lambda integration

resource "aws_apigatewayv2_integration" "cloudguardian_lambda_integration" {
  api_id = aws_apigatewayv2_api.cloudguardian_api.id

  integration_type = "AWS_PROXY"

  integration_uri = aws_lambda_function.cloudguardian_scanner.invoke_arn

  payload_format_version = "2.0"
}

# Scan route

resource "aws_apigatewayv2_route" "cloudguardian_scan_route" {
  api_id = aws_apigatewayv2_api.cloudguardian_api.id

  route_key = "POST /scan"

  target = "integrations/${aws_apigatewayv2_integration.cloudguardian_lambda_integration.id}"
}

# Allow API Gateway to invoke Lambda

resource "aws_lambda_permission" "cloudguardian_api_gateway_permission" {
  statement_id = "AllowCloudGuardianAPIGateway"

  action = "lambda:InvokeFunction"

  function_name = aws_lambda_function.cloudguardian_scanner.function_name

  principal = "apigateway.amazonaws.com"

  source_arn = "${aws_apigatewayv2_api.cloudguardian_api.execution_arn}/*/*"
}