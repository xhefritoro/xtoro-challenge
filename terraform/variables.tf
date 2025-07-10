# Variables for Sentra Scanner Infrastructure
# Solutions Architecture: Configurable parameters for different environments

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "sentra_account_id" {
  description = "Sentra SaaS AWS Account ID for cross-account access"
  type        = string
  # This would be provided by Sentra to customers
}

variable "customer_name" {
  description = "Customer identifier for resource naming"
  type        = string
}

variable "s3_bucket_name" {
  description = "S3 bucket to scan for email addresses"
  type        = string
}

variable "allowed_file_extensions" {
  description = "File extensions to scan (security consideration)"
  type        = list(string)
  default     = [".txt", ".csv", ".json", ".log", ".md"]
}

variable "max_file_size_mb" {
  description = "Maximum file size to process (cost optimization)"
  type        = number
  default     = 100
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds"
  type        = number
  default     = 300
}

variable "lambda_memory" {
  description = "Lambda memory allocation (cost vs performance trade-off)"
  type        = number
  default     = 512
}

variable "sentra_sqs_queue_arn" {
  description = "Sentra's SQS queue ARN for receiving scan results"
  type        = string
  # This would be provided by Sentra to customers
}

variable "enable_encryption" {
  description = "Enable S3 bucket encryption (security best practice)"
  type        = bool
  default     = true
}

variable "retention_days" {
  description = "CloudWatch logs retention period"
  type        = number
  default     = 14
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default = {
    Project     = "SentraScanner"
    ManagedBy   = "Terraform"
    CostCenter  = "Security"
  }
}
