# Terraform Outputs for Sentra Scanner
# Solutions Architecture: Provide necessary information for integration

output "lambda_function_arn" {
  description = "ARN of the Sentra scanner Lambda function"
  value       = aws_lambda_function.sentra_scanner.arn
}

output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.sentra_scanner.function_name
}

output "lambda_execution_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.lambda_execution_role.arn
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for Lambda logs"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "deployment_info" {
  description = "Key deployment information for Sentra integration"
  value = {
    customer_name               = var.customer_name
    environment                = var.environment
    lambda_function_arn        = aws_lambda_function.sentra_scanner.arn
    external_id               = "${var.customer_name}-external-id"
    s3_bucket_name            = var.s3_bucket_name
    allowed_file_extensions   = var.allowed_file_extensions
    max_file_size_mb          = var.max_file_size_mb
  }
}

output "monitoring_dashboard_url" {
  description = "CloudWatch dashboard URL for monitoring"
  value       = "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${var.customer_name}-sentra-scanner"
}

output "security_configuration" {
  description = "Security configuration summary"
  value = {
    encryption_enabled        = var.enable_encryption
    least_privilege_iam      = "Enabled - Custom policies with minimal permissions"
    data_privacy            = "Email hashes only, no plaintext storage"
    audit_logging           = "CloudWatch logs with ${var.retention_days} day retention"
  }
}
