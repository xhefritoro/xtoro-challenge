# CloudWatch Dashboard for Sentra Email Scanner
# Solutions Architecture: Comprehensive operational visibility

resource "aws_cloudwatch_dashboard" "sentra_scanner_dashboard" {
  dashboard_name = "${var.customer_name}-sentra-scanner-mini"

  dashboard_body = jsonencode({
    widgets = [
      # Header text widget
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 1

        properties = {
          markdown = "# Sentra Email Scanner Dashboard - ${var.customer_name}\n**Environment:** ${var.environment}"
        }
      },
      # First row of metric widgets (y=2 to avoid header)
      {
        type   = "metric"
        x      = 0
        y      = 1
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.sentra_scanner.function_name],
            [".", "Errors", ".", "."],
            [".", "Duration", ".", "."],
            [".", "Throttles", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "Lambda Function Performance"
          period  = 300
          stat    = "Sum"
          setPeriodToTimeRange = true
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 1
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["Sentra/EmailScanner", "EmailsFound", "CustomerName", var.customer_name, "Environment", var.environment],
            [".", "UniqueDomainsFound", ".", "."],
            [".", "ProcessingErrors", ".", "."],
            [".", "ProcessingTime", ".", "."]
          ]
          view   = "timeSeries"
          region = data.aws_region.current.name
          title  = "Email Scanner Metrics"
          period = 300
          stat   = "Sum"
          setPeriodToTimeRange = true
          
        }
      },
      # Second row (y=8)
      {
        type   = "metric"
        x      = 0
        y      = 7
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.sentra_scanner.function_name]
          ]
          view   = "timeSeries"
          region = data.aws_region.current.name
          title  = "Processing Duration"
          period = 300
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 7
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["Sentra/EmailScanner", "FileSizeProcessed", "CustomerName", var.customer_name, "Environment", var.environment],
            [".", "FileSizeSkipped", ".", "."],
            [".", "FileSizeBinary", ".", "."]
          ]
          view   = "timeSeries"
          region = data.aws_region.current.name
          title  = "File Size Distribution"
          period = 300
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 13
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/Lambda", "ConcurrentExecutions", "FunctionName", aws_lambda_function.sentra_scanner.function_name]
          ]
          view   = "timeSeries"
          region = data.aws_region.current.name
          title  = "Concurrent Executions"
          period = 300
          stat   = "Maximum"
        }
      },
      {
        type   = "log"
        x      = 12
        y      = 13
        width  = 12
        height = 6

        properties = {
          logGroupNames = [aws_cloudwatch_log_group.lambda_logs.name]
          query   = "SOURCE '${aws_cloudwatch_log_group.lambda_logs.name}'\n| fields @timestamp, @message\n| filter @message like /ERROR/\n| sort @timestamp desc\n| limit 20"
          region  = data.aws_region.current.name
          title   = "Recent Errors"
          view    = "table"
        }
      },
      # Third row (y=19) - Custom Log Filter Metrics
      {
        type   = "metric"
        x      = 0
        y      = 19
        width  = 24
        height = 6

        properties = {
          metrics = [
            ["Sentra/EmailScanner", "ProcessingSuccess"],
            [".", "LargeFilesSkipped"],
            [".", "BinaryFilesSkipped"]
          ]
          view   = "timeSeries"
          region = data.aws_region.current.name
          title  = "Custom Processing Metrics"
          period = 300
          stat   = "Sum"
          setPeriodToTimeRange = true
        }
      }
    ]
  })
}

# Custom metric filters for advanced monitoring
resource "aws_cloudwatch_log_metric_filter" "processing_success_filter" {
  name           = "${var.customer_name}-sentra-scanner-success"
  log_group_name = aws_cloudwatch_log_group.lambda_logs.name
  pattern        = "[timestamp, request_id, level=\"INFO\", message=\"Successfully processed*\"]"

  metric_transformation {
    name      = "ProcessingSuccess"
    namespace = "Sentra/EmailScanner"
    value     = "1"

    default_value = 0
  }
}

resource "aws_cloudwatch_log_metric_filter" "large_file_filter" {
  name           = "${var.customer_name}-sentra-scanner-large-files"
  log_group_name = aws_cloudwatch_log_group.lambda_logs.name
  pattern        = "[timestamp, request_id, level, message=\"*File size*exceeds limit*\"]"

  metric_transformation {
    name      = "LargeFilesSkipped"
    namespace = "Sentra/EmailScanner"
    value     = "1"

    default_value = 0
  }
}

resource "aws_cloudwatch_log_metric_filter" "binary_file_filter" {
  name           = "${var.customer_name}-sentra-scanner-binary-files"
  log_group_name = aws_cloudwatch_log_group.lambda_logs.name
  pattern        = "[timestamp, request_id, level, message=\"*Binary file detected*\"]"

  metric_transformation {
    name      = "BinaryFilesSkipped"
    namespace = "Sentra/EmailScanner"
    value     = "1"

    default_value = 0
  }
}

# Performance insights alarm
resource "aws_cloudwatch_metric_alarm" "high_processing_volume" {
  alarm_name          = "${var.customer_name}-sentra-scanner-high-volume"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Invocations"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1000"
  alarm_description   = "High processing volume detected"
  alarm_actions       = [] # Add SNS topic for notifications

  dimensions = {
    FunctionName = aws_lambda_function.sentra_scanner.function_name
  }

  tags = var.tags
}
