# modules/elasticsearch/main.tf

locals {
  es_name = "${var.project_name}-es"
}

# Create security group for Elasticsearch
resource "aws_security_group" "es_sg" {
  name        = "${local.es_name}-sg"
  description = "Security group for Elasticsearch"
  vpc_id      = var.vpc_id
  
  ingress {
    description     = "HTTPS from allowed security groups"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = var.security_group_ids
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "${local.es_name}-sg"
  }
}

# Create the Elasticsearch domain
resource "aws_elasticsearch_domain" "es" {
  domain_name           = replace(local.es_name, "-", "")
  elasticsearch_version = var.elasticsearch_version
  
  cluster_config {
    instance_type          = var.instance_type
    instance_count         = var.instance_count
    zone_awareness_enabled = var.instance_count > 1
    
    dynamic "zone_awareness_config" {
      for_each = var.instance_count > 1 ? [1] : []
      content {
        availability_zone_count = min(var.instance_count, length(var.subnet_ids))
      }
    }
  }
  
  vpc_options {
    subnet_ids         = slice(var.subnet_ids, 0, min(var.instance_count, length(var.subnet_ids)))
    security_group_ids = [aws_security_group.es_sg.id]
  }
  
  ebs_options {
    ebs_enabled = true
    volume_size = var.ebs_volume_size
    volume_type = "gp3"
  }
  
  encrypt_at_rest {
    enabled = true
  }
  
  node_to_node_encryption {
    enabled = true
  }
  
  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }
  
  advanced_options = {
    "rest.action.multi.allow_explicit_index" = "true"
  }
  
  log_publishing_options {
    enabled                  = true
    log_type                 = "INDEX_SLOW_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.es_logs.arn
  }
  
  log_publishing_options {
    enabled                  = true
    log_type                 = "SEARCH_SLOW_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.es_logs.arn
  }
  
  log_publishing_options {
    enabled                  = true
    log_type                 = "ES_APPLICATION_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.es_logs.arn
  }
  
  access_policies = <<CONFIG
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "es:*",
      "Resource": "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${replace(local.es_name, "-", "")}/*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "10.0.0.0/8"
        }
      }
    }
  ]
}
CONFIG
  
  tags = {
    Name = local.es_name
  }
}

# CloudWatch Log Group for Elasticsearch logs
resource "aws_cloudwatch_log_group" "es_logs" {
  name              = "/aws/elasticsearch/${local.es_name}"
  retention_in_days = 30
  
  tags = {
    Name = "${local.es_name}-logs"
  }
}

# IAM Role for Elasticsearch
resource "aws_iam_role" "es_role" {
  name = "${local.es_name}-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "es.amazonaws.com"
        }
      }
    ]
  })
  
  tags = {
    Name = "${local.es_name}-role"
  }
}

# IAM Policy for Elasticsearch
resource "aws_iam_policy" "es_policy" {
  name        = "${local.es_name}-policy"
  description = "Policy for Elasticsearch to publish logs to CloudWatch"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:PutLogEventsBatch"
        ]
        Effect   = "Allow"
        Resource = "${aws_cloudwatch_log_group.es_logs.arn}:*"
      }
    ]
  })
}

# Attach policy to role
resource "aws_iam_role_policy_attachment" "es_policy_attachment" {
  role       = aws_iam_role.es_role.name
  policy_arn = aws_iam_policy.es_policy.arn
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}