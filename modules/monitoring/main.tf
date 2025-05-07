# File: modules/monitoring/main.tf

locals {
  monitoring_name = "${var.project_name}-monitoring"
}

# Variable validation and descriptions
variable "alarm_email_endpoint" {
  description = "Email address for SOC alert notifications"
  type        = string
  validation {
    condition     = can(regex("^.+@.+\\..+$", var.alarm_email_endpoint))
    error_message = "Must be a valid email address."
  }
}

variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "wazuh_asg_name" {
  description = "Name of the Wazuh Auto Scaling Group"
  type        = string
}

variable "n8n_asg_name" {
  description = "Name of the n8n Auto Scaling Group"
  type        = string
}

variable "thehive_asg_name" {
  description = "Name of the TheHive Auto Scaling Group"
  type        = string
}

variable "db_instance_id" {
  description = "RDS instance identifier"
  type        = string
}

variable "elasticsearch_domain_name" {
  description = "Elasticsearch domain name"
  type        = string
}

variable "wazuh_lb_arn_suffix" {
  description = "ARN suffix for Wazuh load balancer"
  type        = string
}

variable "thehive_lb_arn_suffix" {
  description = "ARN suffix for TheHive load balancer"
  type        = string
}

variable "misp_lb_arn_suffix" {
  description = "ARN suffix for MISP load balancer"
  type        = string
}

variable "monthly_budget_amount" {
  description = "Monthly budget amount in USD"
  type        = number
}

variable "grafana_api_key" {
  description = "API key for Grafana"
  type        = string
  sensitive   = true
}

# CloudWatch Dashboard for SOC metrics
resource "aws_cloudwatch_dashboard" "soc_dashboard" {
  dashboard_name = "${var.project_name}-soc-dashboard"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 1
        properties = {
          markdown = "# ${var.project_name} SOC Monitoring Dashboard"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 1
        width  = 12
        height = 6
        properties = {
          metrics = [
            [ "AWS/EC2", "CPUUtilization", "AutoScalingGroupName", var.wazuh_asg_name, { "stat": "Average", "period": 300 } ]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "Wazuh CPU Utilization"
          period  = 300
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
            [ "AWS/EC2", "CPUUtilization", "AutoScalingGroupName", var.n8n_asg_name, { "stat": "Average", "period": 300 } ]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "n8n CPU Utilization"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 7
        width  = 12
        height = 6
        properties = {
          metrics = [
            [ "AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", var.db_instance_id, { "stat": "Average", "period": 300 } ]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "Database CPU Utilization"
          period  = 300
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
            [ "AWS/ES", "CPUUtilization", "DomainName", var.elasticsearch_domain_name, "ClientId", data.aws_caller_identity.current.account_id, { "stat": "Average", "period": 300 } ]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "Elasticsearch CPU Utilization"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 13
        width  = 8
        height = 6
        properties = {
          metrics = [
            [ "AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", var.wazuh_lb_arn_suffix, { "stat": "Average", "period": 300 } ]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "Wazuh Response Time"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 13
        width  = 8
        height = 6
        properties = {
          metrics = [
            [ "AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", var.thehive_lb_arn_suffix, { "stat": "Average", "period": 300 } ]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "TheHive Response Time"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 13
        width  = 8
        height = 6
        properties = {
          metrics = [
            [ "AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", var.misp_lb_arn_suffix, { "stat": "Average", "period": 300 } ]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "MISP Response Time"
          period  = 300
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 19
        width  = 24
        height = 6
        properties = {
          query   = "SOURCE '/wazuh/alerts' | fields @timestamp, @message | sort @timestamp desc | limit 20"
          region  = data.aws_region.current.name
          title   = "Recent Wazuh Alerts"
          view    = "table"
        }
      }
    ]
  })
}

# Get current region
data "aws_region" "current" {}

# Get current account ID
data "aws_caller_identity" "current" {}

# SNS Topic for alerts
resource "aws_sns_topic" "soc_alerts" {
  name = "${var.project_name}-soc-alerts"
  kms_master_key_id = "alias/aws/sns"
  
  tags = {
    Name = "${local.monitoring_name}-alerts"
  }
}

# SNS Topic subscription for email notifications
resource "aws_sns_topic_subscription" "soc_alerts_email" {
  topic_arn = aws_sns_topic.soc_alerts.arn
  protocol  = "email"
  endpoint  = var.alarm_email_endpoint
}

# CloudWatch Alarm - Wazuh High CPU
resource "aws_cloudwatch_metric_alarm" "wazuh_high_cpu" {
  alarm_name          = "${var.project_name}-wazuh-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors Wazuh EC2 CPU utilization"
  alarm_actions       = [aws_sns_topic.soc_alerts.arn, var.wazuh_scale_up_policy_arn]
  ok_actions          = [aws_sns_topic.soc_alerts.arn]
  treat_missing_data  = "breaching"
  
  dimensions = {
    AutoScalingGroupName = var.wazuh_asg_name
  }
  
  tags = {
    Name = "${local.monitoring_name}-wazuh-high-cpu"
  }
}

# CloudWatch Alarm - n8n High CPU
resource "aws_cloudwatch_metric_alarm" "n8n_high_cpu" {
  alarm_name          = "${var.project_name}-n8n-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors n8n EC2 CPU utilization"
  alarm_actions       = [aws_sns_topic.soc_alerts.arn, var.n8n_scale_up_policy_arn]
  ok_actions          = [aws_sns_topic.soc_alerts.arn]
  treat_missing_data  = "breaching"
  
  dimensions = {
    AutoScalingGroupName = var.n8n_asg_name
  }
  
  tags = {
    Name = "${local.monitoring_name}-n8n-high-cpu"
  }
}

# CloudWatch Alarm - Wazuh Low CPU (scale down)
resource "aws_cloudwatch_metric_alarm" "wazuh_low_cpu" {
  alarm_name          = "${var.project_name}-wazuh-low-cpu"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "20"
  alarm_description   = "This metric monitors Wazuh EC2 CPU utilization for scale down"
  alarm_actions       = [var.wazuh_scale_down_policy_arn]
  treat_missing_data  = "breaching"
  
  dimensions = {
    AutoScalingGroupName = var.wazuh_asg_name
  }
  
  tags = {
    Name = "${local.monitoring_name}-wazuh-low-cpu"
  }
}

# CloudWatch Alarm - n8n Low CPU (scale down)
resource "aws_cloudwatch_metric_alarm" "n8n_low_cpu" {
  alarm_name          = "${var.project_name}-n8n-low-cpu"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "20"
  alarm_description   = "This metric monitors n8n EC2 CPU utilization for scale down"
  alarm_actions       = [var.n8n_scale_down_policy_arn]
  treat_missing_data  = "breaching"
  
  dimensions = {
    AutoScalingGroupName = var.n8n_asg_name
  }
  
  tags = {
    Name = "${local.monitoring_name}-n8n-low-cpu"
  }
}

# CloudWatch Alarm - Elasticsearch High CPU
resource "aws_cloudwatch_metric_alarm" "elasticsearch_high_cpu" {
  alarm_name          = "${var.project_name}-elasticsearch-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ES"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors Elasticsearch CPU utilization"
  alarm_actions       = [aws_sns_topic.soc_alerts.arn]
  ok_actions          = [aws_sns_topic.soc_alerts.arn]
  treat_missing_data  = "breaching"
  
  dimensions = {
    DomainName = var.elasticsearch_domain_name
    ClientId   = data.aws_caller_identity.current.account_id
  }
  
  tags = {
    Name = "${local.monitoring_name}-elasticsearch-high-cpu"
  }
}

# CloudWatch Alarm - Database High CPU
resource "aws_cloudwatch_metric_alarm" "db_high_cpu" {
  alarm_name          = "${var.project_name}-db-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors RDS CPU utilization"
  alarm_actions       = [aws_sns_topic.soc_alerts.arn]
  ok_actions          = [aws_sns_topic.soc_alerts.arn]
  treat_missing_data  = "breaching"
  
  dimensions = {
    DBInstanceIdentifier = var.db_instance_id
  }
  
  tags = {
    Name = "${local.monitoring_name}-db-high-cpu"
  }
}

# CloudWatch Alarm - Database Low Storage
resource "aws_cloudwatch_metric_alarm" "db_low_storage" {
  alarm_name          = "${var.project_name}-db-low-storage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "5000000000" # 5GB
  alarm_description   = "This metric monitors RDS free storage space"
  alarm_actions       = [aws_sns_topic.soc_alerts.arn]
  ok_actions          = [aws_sns_topic.soc_alerts.arn]
  treat_missing_data  = "breaching"
  
  dimensions = {
    DBInstanceIdentifier = var.db_instance_id
  }
  
  tags = {
    Name = "${local.monitoring_name}-db-low-storage"
  }
}

# CloudWatch Log Metric Filter for Critical Wazuh Alerts
resource "aws_cloudwatch_log_metric_filter" "critical_wazuh_alerts" {
  name           = "${var.project_name}-critical-wazuh-alerts"
  pattern        = "{ $.rule.level >= 12 }"
  log_group_name = "/wazuh/alerts"
  
  metric_transformation {
    name      = "CriticalWazuhAlerts"
    namespace = "${var.project_name}/SOC"
    value     = "1"
  }
}

# CloudWatch Alarm for Critical Wazuh Alerts
resource "aws_cloudwatch_metric_alarm" "critical_wazuh_alerts" {
  alarm_name          = "${var.project_name}-critical-wazuh-alerts"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CriticalWazuhAlerts"
  namespace           = "${var.project_name}/SOC"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This alarm triggers when critical (level 12+) Wazuh alerts are detected"
  alarm_actions       = [aws_sns_topic.soc_alerts.arn]
  treat_missing_data  = "breaching"
  
  tags = {
    Name = "${local.monitoring_name}-critical-wazuh-alerts"
  }
}

# CloudWatch Log Group for SOC Operations
resource "aws_cloudwatch_log_group" "soc_operations" {
  name              = "/${var.project_name}/soc/operations"
  retention_in_days = 90
  
  tags = {
    Name = "${local.monitoring_name}-operations"
  }
}

# CloudWatch Log Metric Filter for Login Failures
resource "aws_cloudwatch_log_metric_filter" "login_failures" {
  name           = "${var.project_name}-login-failures"
  pattern        = "{ $.event_type = \"login_failure\" }"
  log_group_name = aws_cloudwatch_log_group.soc_operations.name
  
  metric_transformation {
    name      = "LoginFailures"
    namespace = "${var.project_name}/SOC"
    value     = "1"
  }
}

# CloudWatch Alarm for Login Failures
resource "aws_cloudwatch_metric_alarm" "login_failures" {
  alarm_name          = "${var.project_name}-login-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "LoginFailures"
  namespace           = "${var.project_name}/SOC"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This alarm triggers when there are more than 5 login failures in 5 minutes"
  alarm_actions       = [aws_sns_topic.soc_alerts.arn]
  treat_missing_data  = "breaching"
  
  tags = {
    Name = "${local.monitoring_name}-login-failures"
  }
}

# Systems Manager (SSM) Parameter for API keys
resource "aws_ssm_parameter" "grafana_api_key" {
  name        = "/${var.project_name}/monitoring/grafana_api_key"
  description = "API key for Grafana"
  type        = "SecureString"
  value       = var.grafana_api_key
  
  tags = {
    Name = "${local.monitoring_name}-grafana-api-key"
  }
}

# Create a Lambda function to process CloudWatch logs
resource "aws_lambda_function" "process_soc_logs" {
  function_name    = "${var.project_name}-process-soc-logs"
  role             = aws_iam_role.lambda_role.arn
  handler          = "index.handler"
  runtime          = "nodejs16.x"
  timeout          = 30
  memory_size      = 256
  
  # Inline code for log processing
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  
  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.soc_alerts.arn
    }
  }
  
  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }
  
  tags = {
    Name = "${local.monitoring_name}-process-soc-logs"
  }
}

# Lambda deployment package
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_function.zip"
  
  source {
    content  = <<EOF
exports.handler = async (event, context) => {
  const zlib = require('zlib');
  const AWS = require('aws-sdk');
  const sns = new AWS.SNS();
  
  // Decode and decompress the CloudWatch logs
  const payload = Buffer.from(event.awslogs.data, 'base64');
  const decompressed = zlib.gunzipSync(payload).toString('utf8');
  const logData = JSON.parse(decompressed);
  
  // Process each log event
  for (const logEvent of logData.logEvents) {
    try {
      const logMessage = JSON.parse(logEvent.message);
      
      // Check for critical Wazuh alerts
      if (logData.logGroup === '/wazuh/alerts' && logMessage.rule && logMessage.rule.level >= 12) {
        // Send notification for critical alerts
        await sns.publish({
          TopicArn: process.env.SNS_TOPIC_ARN,
          Subject: `[CRITICAL] Wazuh Alert: ${logMessage.rule.description}`,
          Message: `
Critical Wazuh Alert Detected:
Rule: ${logMessage.rule.description}
Level: ${logMessage.rule.level}
Agent: ${logMessage.agent ? logMessage.agent.name : 'N/A'}
IP: ${logMessage.agent ? logMessage.agent.ip : 'N/A'}
Timestamp: ${logMessage.timestamp}

Details:
${logMessage.full_log}
          `
        }).promise();
      }
    } catch (error) {
      console.error('Error processing log event:', error);
    }
  }
  
  return {
    statusCode: 200,
    body: JSON.stringify({ message: 'Logs processed successfully' }),
  };
};
EOF
    filename = "index.js"
  }
}

# IAM role for Lambda
resource "aws_iam_role" "lambda_role" {
  name = "${var.project_name}-lambda-log-processor-role"
  
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
  
  tags = {
    Name = "${local.monitoring_name}-lambda-role"
  }
}

# IAM policy for Lambda to access CloudWatch Logs and publish to SNS
resource "aws_iam_policy" "lambda_policy" {
  name        = "${var.project_name}-lambda-log-processor-policy"
  description = "Policy for SOC log processor Lambda function"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Action = [
          "sns:Publish"
        ]
        Effect   = "Allow"
        Resource = aws_sns_topic.soc_alerts.arn
      }
    ]
  })
}

# Attach policy to Lambda role
resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# CloudWatch Logs subscription filter to trigger Lambda
resource "aws_cloudwatch_log_subscription_filter" "wazuh_alerts_subscription" {
  name            = "${var.project_name}-wazuh-alerts-subscription"
  log_group_name  = "/wazuh/alerts"
  filter_pattern  = "{ $.rule.level >= 12 }"
  destination_arn = aws_lambda_function.process_soc_logs.arn
}

# Lambda permission to allow CloudWatch to invoke it
resource "aws_lambda_permission" "cloudwatch_permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.process_soc_logs.function_name
  principal     = "logs.${data.aws_region.current.name}.amazonaws.com"
  source_arn    = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/wazuh/alerts:*"
}

# CloudWatch Alarm for Lambda errors
resource "aws_cloudwatch_metric_alarm" "lambda_error_alarm" {
  alarm_name          = "${var.project_name}-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Alarm if Lambda function for SOC log processing has any errors"
  alarm_actions       = [aws_sns_topic.soc_alerts.arn]
  treat_missing_data  = "breaching"
  dimensions = {
    FunctionName = aws_lambda_function.process_soc_logs.function_name
  }
  tags = {
    Name = "${local.monitoring_name}-lambda-errors"
  }
}

# AWS Budget for SOC costs
resource "aws_budgets_budget" "soc_budget" {
  name              = "${var.project_name}-soc-budget"
  budget_type       = "COST"
  limit_amount      = var.monthly_budget_amount
  limit_unit        = "USD"
  time_unit         = "MONTHLY"
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alarm_email_endpoint]
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alarm_email_endpoint]
  }
  
  cost_filter {
    name = "TagKeyValue"
    values = [
      "user:Project${var.project_name}"
    ]
  }
}

# Grafana dashboard template for SOC monitoring
resource "local_file" "grafana_dashboard" {
  content = <<EOF
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": "-- Grafana --",
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "gnetId": null,
  "graphTooltip": 0,
  "id": null,
  "links": [],
  "panels": [
    {
      "collapsed": false,
      "datasource": null,
      "gridPos": {
        "h": 1,
        "w": 24,
        "x": 0,
        "y": 0
      },
      "id": 10,
      "panels": [],
      "title": "SOC Overview",
      "type": "row"
    },
    {
      "aliasColors": {},
      "bars": false,
      "dashLength": 10,
      "dashes": false,
      "datasource": "CloudWatch",
      "fieldConfig": {
        "defaults": {},
        "overrides": []
      },
      "fill": 1,
      "fillGradient": 0,
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 1
      },
      "hiddenSeries": false,
      "id": 2,
      "legend": {
        "avg": false,
        "current": false,
        "max": false,
        "min": false,
        "show": true,
        "total": false,
        "values": false
      },
      "lines": true,
      "linewidth": 1,
      "nullPointMode": "null",
      "options": {
        "alertThreshold": true
      },
      "percentage": false,
      "pluginVersion": "7.5.5",
      "pointradius": 2,
      "points": false,
      "renderer": "flot",
      "seriesOverrides": [],
      "spaceLength": 10,
      "stack": false,
      "steppedLine": false,
      "targets": [
        {
          "alias": "Wazuh CPU",
          "dimensions": {
            "AutoScalingGroupName": "${var.wazuh_asg_name}"
          },
          "expression": "",
          "id": "",
          "matchExact": true,
          "metricName": "CPUUtilization",
          "namespace": "AWS/EC2",
          "period": "",
          "refId": "A",
          "region": "${data.aws_region.current.name}",
          "statistics": [
            "Average"
          ]
        }
      ],
      "thresholds": [],
      "timeFrom": null,
      "timeRegions": [],
      "timeShift": null,
      "title": "Wazuh CPU Utilization",
      "tooltip": {
        "shared": true,
        "sort": 0,
        "value_type": "individual"
      },
      "type": "graph",
      "xaxis": {
        "buckets": null,
        "mode": "time",
        "name": null,
        "show": true,
        "values": []
      },
      "yaxes": [
        {
          "format": "percent",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        },
        {
          "format": "short",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        }
      ],
      "yaxis": {
        "align": false,
        "alignLevel": null
      }
    },
    {
      "aliasColors": {},
      "bars": false,
      "dashLength": 10,
      "dashes": false,
      "datasource": "CloudWatch",
      "fieldConfig": {
        "defaults": {},
        "overrides": []
      },
      "fill": 1,
      "fillGradient": 0,
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 12,
        "y": 1
      },
      "hiddenSeries": false,
      "id": 4,
      "legend": {
        "avg": false,
        "current": false,
        "max": false,
        "min": false,
        "show": true,
        "total": false,
        "values": false
      },
      "lines": true,
      "linewidth": 1,
      "nullPointMode": "null",
      "options": {
        "alertThreshold": true
      },
      "percentage": false,
      "pluginVersion": "7.5.5",
      "pointradius": 2,
      "points": false,
      "renderer": "flot",
      "seriesOverrides": [],
      "spaceLength": 10,
      "stack": false,
      "steppedLine": false,
      "targets": [
        {
          "alias": "TheHive",
          "dimensions": {
            "AutoScalingGroupName": "${var.thehive_asg_name}"
          },
          "expression": "",
          "id": "",
          "matchExact": true,
          "metricName": "CPUUtilization",
          "namespace": "AWS/EC2",
          "period": "",
          "refId": "A",
          "region": "${data.aws_region.current.name}",
          "statistics": [
            "Average"
          ]
        }
      ],
      "thresholds": [],
      "timeFrom": null,
      "timeRegions": [],
      "timeShift": null,
      "title": "TheHive CPU Utilization",
      "tooltip": {
        "shared": true,
        "sort": 0,
        "value_type": "individual"
      },
      "type": "graph",
      "xaxis": {
        "buckets": null,
        "mode": "time",
        "name": null,
        "show": true,
        "values": []
      },
      "yaxes": [
        {
          "format": "percent",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        },
        {
          "format": "short",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        }
      ],
      "yaxis": {
        "align": false,
        "alignLevel": null
      }
    },
    {
      "collapsed": false,
      "datasource": null,
      "gridPos": {
        "h": 1,
        "w": 24,
        "x": 0,
        "y": 9
      },
      "id": 8,
      "panels": [],
      "title": "Security Events",
      "type": "row"
    },
    {
      "datasource": "CloudWatch",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 0.1,
            "gradientMode": "none",
            "hideFrom": {
              "legend": false,
              "tooltip": false,
              "viz": false
            },
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "never",
            "spanNulls": true,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 80
              }
            ]
          },
          "unit": "none"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 10
      },
      "id": 6,
      "options": {
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom"
        },
        "tooltip": {
          "mode": "single"
        }
      },
      "pluginVersion": "7.5.5",
      "targets": [
        {
          "alias": "Critical Alerts",
          "dimensions": {},
          "expression": "",
          "id": "",
          "matchExact": true,
          "metricName": "CriticalWazuhAlerts",
          "namespace": "${var.project_name}/SOC",
          "period": "",
          "refId": "A",
          "region": "${data.aws_region.current.name}",
          "statistics": [
            "Sum"
          ]
        }
      ],
      "timeFrom": null,
      "timeShift": null,
      "title": "Critical Wazuh Alerts",
      "type": "timeseries"
    },
    {
      "datasource": "CloudWatch",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 0.1,
            "gradientMode": "none",
            "hideFrom": {
              "legend": false,
              "tooltip": false,
              "viz": false
            },
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "never",
            "spanNulls": true,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 80
              }
            ]
          },
          "unit": "none"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 12,
        "y": 10
      },
      "id": 12,
      "options": {
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom"
        },
        "tooltip": {
          "mode": "single"
        }
      },
      "pluginVersion": "7.5.5",
      "targets": [
        {
          "alias": "Login Failures",
          "dimensions": {},
          "expression": "",
          "id": "",
          "matchExact": true,
          "metricName": "LoginFailures",
          "namespace": "${var.project_name}/SOC",
          "period": "",
          "refId": "A",
          "region": "${data.aws_region.current.name}",
          "statistics": [
            "Sum"
          ]
        }
      ],
      "timeFrom": null,
      "timeShift": null,
      "title": "Login Failures",
      "type": "timeseries"
    }
  ],
  "refresh": "5m",
  "schemaVersion": 27,
  "style": "dark",
  "tags": [
    "soc",
    "security"
  ],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-24h",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "",
  "title": "${var.project_name} - SOC Dashboard",
  "uid": "soc",
  "version": 1
}
EOF
  filename = "${path.module}/grafana_dashboard.json"
}

# Output dashboard URL
output "soc_dashboard_url" {
  description = "SOC CloudWatch dashboard URL"
  value       = "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.soc_dashboard.dashboard_name}"
}

# Output SNS topic ARN
output "soc_alerts_sns_topic_arn" {
  description = "ARN of the SOC alerts SNS topic"
  value       = aws_sns_topic.soc_alerts.arn
}

# Output Lambda function name
output "process_soc_logs_lambda_name" {
  description = "Name of the Lambda function processing SOC logs"
  value       = aws_lambda_function.process_soc_logs.function_name
}