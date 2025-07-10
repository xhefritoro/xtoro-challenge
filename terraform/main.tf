# Sentra Scanner Infrastructure
# Solutions Architecture: Secure, scalable email scanning solution

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
  
  default_tags {
    tags = var.tags
  }
}

locals {
  arn_parts   = split(":", var.sentra_sqs_queue_arn)
  region      = local.arn_parts[3]
  account_id  = local.arn_parts[4]
  queue_name  = local.arn_parts[5]

  sentra_sqs_queue_url = "https://sqs.${local.region}.amazonaws.com/${local.account_id}/${local.queue_name}"
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ============================================================================
# IAM ROLES & POLICIES (Least Privilege Design)
# ============================================================================

# Lambda execution role with minimal required permissions
resource "aws_iam_role" "lambda_execution_role" {
  name = "${var.customer_name}-sentra-scanner-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.customer_name}-sentra-scanner-lambda-role"
  })
}

# Custom policy for S3 access (read-only, specific bucket)
resource "aws_iam_policy" "lambda_s3_policy" {
  name        = "${var.customer_name}-sentra-scanner-s3-policy"
  description = "Minimal S3 permissions for email scanning"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = "arn:aws:s3:::${var.s3_bucket_name}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = "arn:aws:s3:::${var.s3_bucket_name}"
      }
    ]
  })
}

# Custom policy for CloudWatch metrics publishing
resource "aws_iam_policy" "lambda_cloudwatch_policy" {
  name        = "${var.customer_name}-sentra-scanner-cloudwatch-policy"
  description = "Permission to publish custom metrics to CloudWatch"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      }
    ]
  })
}

# Custom policy for SQS publishing to Sentra
resource "aws_iam_policy" "lambda_sqs_policy" {
  name        = "${var.customer_name}-sentra-scanner-sqs-policy"
  description = "Permission to send results to Sentra SQS queue"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = var.sentra_sqs_queue_arn
      }
    ]
  })
}

# Attach policies to lambda role
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_s3_access" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.lambda_s3_policy.arn
}

resource "aws_iam_role_policy_attachment" "lambda_cloudwatch_access" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.lambda_cloudwatch_policy.arn
}

resource "aws_iam_role_policy_attachment" "lambda_sqs_access" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.lambda_sqs_policy.arn
}

# ============================================================================
# CLOUDWATCH LOGS (Monitoring & Observability)
# ============================================================================

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.customer_name}-sentra-scanner"
  retention_in_days = var.retention_days

  tags = merge(var.tags, {
    Name = "${var.customer_name}-sentra-scanner-logs"
  })
}

# ============================================================================
# LAMBDA FUNCTION (Core Processing)
# ============================================================================

# Package Lambda code with dependencies
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../build"
  output_path = "${path.module}/../build/sentra-scanner.zip"
  depends_on  = []
}

# Use pre-built Lambda package (run ../scripts/build-lambda.sh first)
resource "aws_lambda_function" "sentra_scanner" {
  filename         = "${path.module}/../build/sentra-scanner.zip"
  function_name    = "${var.customer_name}-sentra-scanner"
  role            = aws_iam_role.lambda_execution_role.arn
  handler         = "scanner.lambda_handler"
  runtime         = "python3.11"
  timeout         = var.lambda_timeout
  memory_size     = var.lambda_memory
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SENTRA_SQS_QUEUE_URL    = local.sentra_sqs_queue_url
      ALLOWED_EXTENSIONS      = join(",", var.allowed_file_extensions)
      MAX_FILE_SIZE_MB        = var.max_file_size_mb
      CUSTOMER_NAME           = var.customer_name
      ENVIRONMENT             = var.environment
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic_execution
  ]

  tags = merge(var.tags, {
    Name = "${var.customer_name}-sentra-scanner"
  })
}

# ============================================================================
# S3 EVENT TRIGGER (Event-Driven Architecture)
# ============================================================================

# Permission for S3 to invoke Lambda
resource "aws_lambda_permission" "allow_s3_invoke" {
  statement_id  = "AllowExecutionFromS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sentra_scanner.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = "arn:aws:s3:::${var.s3_bucket_name}"
}

# S3 bucket notification
resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = var.s3_bucket_name

  lambda_function {
    lambda_function_arn = aws_lambda_function.sentra_scanner.arn
    events              = ["s3:ObjectCreated:*"]
    
    # Filter to only process allowed file types
    filter_prefix = ""
    filter_suffix = ""
  }

  depends_on = [aws_lambda_permission.allow_s3_invoke]
}

# ============================================================================
# CLOUDWATCH ALARMS (Operational Monitoring)
# ============================================================================

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.customer_name}-sentra-scanner-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This metric monitors lambda errors"
  alarm_actions       = [] # Add SNS topic ARN for notifications

  dimensions = {
    FunctionName = aws_lambda_function.sentra_scanner.function_name
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "lambda_duration" {
  alarm_name          = "${var.customer_name}-sentra-scanner-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Average"
  threshold           = "240000" # 4 minutes (80% of 5min timeout)
  alarm_description   = "This metric monitors lambda duration"

  dimensions = {
    FunctionName = aws_lambda_function.sentra_scanner.function_name
  }

  tags = var.tags
}

# ============================================================================
# CROSS-ACCOUNT ACCESS ROLE (For Sentra SaaS)
# ============================================================================

# Role that Sentra can assume for additional operations if needed
resource "aws_iam_role" "sentra_cross_account_role" {
  name = "${var.customer_name}-sentra-cross-account-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.sentra_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "${var.customer_name}-external-id"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.customer_name}-sentra-cross-account-role"
  })
}

# Minimal policy for cross-account role (read-only scanning metrics)
resource "aws_iam_policy" "sentra_cross_account_policy" {
  name        = "${var.customer_name}-sentra-cross-account-policy"
  description = "Minimal permissions for Sentra cross-account access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:GetFunction",
          "lambda:ListTags",
          "cloudwatch:GetMetricStatistics",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          aws_lambda_function.sentra_scanner.arn,
          aws_cloudwatch_log_group.lambda_logs.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "sentra_cross_account_attachment" {
  role       = aws_iam_role.sentra_cross_account_role.name
  policy_arn = aws_iam_policy.sentra_cross_account_policy.arn
}
