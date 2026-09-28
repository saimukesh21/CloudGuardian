output "cloudguardian_audit_bucket_name" {
  description = "CloudGuardian audit S3 bucket"
  value       = aws_s3_bucket.cloudguardian_audit.bucket
}

output "cloudguardian_audit_bucket_arn" {
  description = "CloudGuardian audit S3 bucket ARN"
  value       = aws_s3_bucket.cloudguardian_audit.arn
}
output "cloudguardian_lambda_name" {
  description = "CloudGuardian security scanner Lambda"
  value       = aws_lambda_function.cloudguardian_scanner.function_name
}
output "cloudguardian_api_endpoint" {
  description = "CloudGuardian API Gateway endpoint"
  value       = aws_apigatewayv2_api.cloudguardian_api.api_endpoint
}