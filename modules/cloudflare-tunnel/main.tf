# File: modules/cloudflare-tunnel/main.tf

locals {
  tunnel_name = "${var.project_name}-tunnel"
}

# Random secret for the tunnel
resource "random_password" "tunnel_secret" {
  length  = 64
  special = false
}

# Create the Cloudflare tunnel
resource "cloudflare_zero_trust_tunnel_cloudflared" "soc_tunnel" {
  account_id    = var.cloudflare_account_id
  name          = local.tunnel_name
  tunnel_secret = base64sha256(random_password.tunnel_secret.result)
  config_src    = "local"
}

# Configure the tunnel
resource "cloudflare_zero_trust_tunnel_cloudflared_config" "soc_tunnel" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.soc_tunnel.id
  source     = "local"
  
  config = {
    ingress = concat(
      [
        # Wazuh web interface
        {
          hostname = "wazuh.${var.dns_domain}"
          service  = "https://${var.wazuh_lb_dns}:443"
          # Disable TLS verification between cloudflared and Wazuh as we're using self-signed certs
          originRequest = {
            noTLSVerify = true
          }
        },
        # Wazuh API
        {
          hostname = "wazuh-api.${var.dns_domain}"
          service  = "https://${var.wazuh_lb_dns}:55000"
          originRequest = {
            noTLSVerify = true
          }
        },
        # TheHive
        {
          hostname = "thehive.${var.dns_domain}"
          service  = "https://${var.thehive_lb_dns}:443"
          originRequest = {
            noTLSVerify = true
          }
        },
        # MISP
        {
          hostname = "misp.${var.dns_domain}"
          service  = "https://${var.misp_lb_dns}:443"
          originRequest = {
            noTLSVerify = true
          }
        },
        # n8n
        {
          hostname = "n8n.${var.dns_domain}"
          service  = "https://${var.n8n_lb_dns}:443"
          originRequest = {
            noTLSVerify = true
          }
        }
      ],
      # Catch-all rule must be the last rule
      [
        {
          service = "http_status:404"
        }
      ]
    )
  }
}

# DNS records for all SOC services
resource "cloudflare_dns_record" "wazuh" {
  zone_id = var.cloudflare_zone_id
  name    = "wazuh"
  value   = "${cloudflare_zero_trust_tunnel_cloudflared.soc_tunnel.id}.cfargotunnel.com"
  type    = "CNAME"
  proxied = true
}

resource "cloudflare_dns_record" "wazuh_api" {
  zone_id = var.cloudflare_zone_id
  name    = "wazuh-api"
  value   = "${cloudflare_zero_trust_tunnel_cloudflared.soc_tunnel.id}.cfargotunnel.com"
  type    = "CNAME"
  proxied = true
}

resource "cloudflare_dns_record" "thehive" {
  zone_id = var.cloudflare_zone_id
  name    = "thehive"
  value   = "${cloudflare_zero_trust_tunnel_cloudflared.soc_tunnel.id}.cfargotunnel.com"
  type    = "CNAME"
  proxied = true
}

resource "cloudflare_dns_record" "misp" {
  zone_id = var.cloudflare_zone_id
  name    = "misp"
  value   = "${cloudflare_zero_trust_tunnel_cloudflared.soc_tunnel.id}.cfargotunnel.com"
  type    = "CNAME"
  proxied = true
}

resource "cloudflare_dns_record" "n8n" {
  zone_id = var.cloudflare_zone_id
  name    = "n8n"
  value   = "${cloudflare_zero_trust_tunnel_cloudflared.soc_tunnel.id}.cfargotunnel.com"
  type    = "CNAME"
  proxied = true
}

# Create Access policies to protect the services
resource "cloudflare_access_application" "wazuh" {
  zone_id          = var.cloudflare_zone_id
  name             = "Wazuh Dashboard"
  domain           = "wazuh.${var.dns_domain}"
  session_duration = "24h"
  type             = "self_hosted"
}

resource "cloudflare_access_application" "thehive" {
  zone_id          = var.cloudflare_zone_id
  name             = "TheHive"
  domain           = "thehive.${var.dns_domain}"
  session_duration = "24h"
  type             = "self_hosted"
}

resource "cloudflare_access_application" "misp" {
  zone_id          = var.cloudflare_zone_id
  name             = "MISP"
  domain           = "misp.${var.dns_domain}"
  session_duration = "24h"
  type             = "self_hosted"
}

resource "cloudflare_access_application" "n8n" {
  zone_id          = var.cloudflare_zone_id
  name             = "n8n"
  domain           = "n8n.${var.dns_domain}"
  session_duration = "24h"
  type             = "self_hosted"
}

# Create Access policies based on emails (can be modified for other auth methods)
resource "cloudflare_access_policy" "wazuh_policy" {
  application_id = cloudflare_access_application.wazuh.id
  zone_id        = var.cloudflare_zone_id
  name           = "Wazuh Access"
  precedence     = 1
  decision       = "allow"

  include {
    email = var.allowed_email_addresses
  }
}

resource "cloudflare_access_policy" "thehive_policy" {
  application_id = cloudflare_access_application.thehive.id
  zone_id        = var.cloudflare_zone_id
  name           = "TheHive Access"
  precedence     = 1
  decision       = "allow"

  include {
    email = var.allowed_email_addresses
  }
}

resource "cloudflare_access_policy" "misp_policy" {
  application_id = cloudflare_access_application.misp.id
  zone_id        = var.cloudflare_zone_id
  name           = "MISP Access"
  precedence     = 1
  decision       = "allow"

  include {
    email = var.allowed_email_addresses
  }
}

resource "cloudflare_access_policy" "n8n_policy" {
  application_id = cloudflare_access_application.n8n.id
  zone_id        = var.cloudflare_zone_id
  name           = "n8n Access"
  precedence     = 1
  decision       = "allow"

  include {
    email = var.allowed_email_addresses
  }
}

# ECS Fargate service to run cloudflared tunnel
resource "aws_ecs_cluster" "cloudflared" {
  name = "${var.project_name}-cloudflared-cluster"
}

# Store the credentials.json in SSM Parameter Store
resource "aws_ssm_parameter" "tunnel_credentials" {
  name        = "/${var.project_name}/cloudflare/tunnel_credentials"
  description = "Cloudflare Tunnel credentials"
  type        = "SecureString"
  value = jsonencode({
    AccountTag   = var.cloudflare_account_id
    TunnelSecret = random_password.tunnel_secret.result
    TunnelID     = cloudflare_zero_trust_tunnel_cloudflared.soc_tunnel.id
  })
}

# Task definition for cloudflared
resource "aws_ecs_task_definition" "cloudflared" {
  family                   = "${var.project_name}-cloudflared"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "cloudflared"
      image     = "cloudflare/cloudflared:latest"
      essential = true
      command   = ["tunnel", "--no-autoupdate", "run", "--credentials-contents", "/etc/cloudflared/credentials.json"]
      
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.cloudflared.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "cloudflared"
        }
      }
      
      secrets = [
        {
          name      = "TUNNEL_CREDENTIALS"
          valueFrom = aws_ssm_parameter.tunnel_credentials.arn
        }
      ]
      
      mountPoints = [
        {
          sourceVolume  = "credentials"
          containerPath = "/etc/cloudflared/credentials.json"
          readOnly      = true
        }
      ]
    }
  ])

  volume {
    name = "credentials"
    
    efs_volume_configuration {
      file_system_id = aws_efs_file_system.cloudflared.id
      root_directory = "/"
    }
  }
}

# Security group for the cloudflared service
resource "aws_security_group" "cloudflared" {
  name        = "${var.project_name}-cloudflared-sg"
  description = "Security group for cloudflared tunnel"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name = "${var.project_name}-cloudflared-sg"
  }
}

# EFS file system for cloudflared credentials
resource "aws_efs_file_system" "cloudflared" {
  creation_token = "${var.project_name}-cloudflared-efs"
  encrypted      = true
  
  tags = {
    Name = "${var.project_name}-cloudflared-efs"
  }
}

# Mount targets for EFS
resource "aws_efs_mount_target" "cloudflared" {
  count           = length(var.private_subnet_ids)
  file_system_id  = aws_efs_file_system.cloudflared.id
  subnet_id       = var.private_subnet_ids[count.index]
  security_groups = [aws_security_group.efs.id]
}

# Security group for EFS
resource "aws_security_group" "efs" {
  name        = "${var.project_name}-efs-sg"
  description = "Security group for EFS access"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.cloudflared.id]
    description     = "NFS from cloudflared"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name = "${var.project_name}-efs-sg"
  }
}

# IAM role for ECS task execution
resource "aws_iam_role" "ecs_execution_role" {
  name = "${var.project_name}-cloudflared-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

# IAM role for ECS task
resource "aws_iam_role" "ecs_task_role" {
  name = "${var.project_name}-cloudflared-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

# IAM policy for ECS task execution role
resource "aws_iam_policy" "ecs_execution_policy" {
  name        = "${var.project_name}-cloudflared-execution-policy"
  description = "Policy for cloudflared tunnel ECS task execution"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudflared.arn}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter"
        ]
        Resource = aws_ssm_parameter.tunnel_credentials.arn
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "elasticfilesystem:ClientMount",
          "elasticfilesystem:ClientWrite"
        ]
        Resource = aws_efs_file_system.cloudflared.arn
      }
    ]
  })
}

# Attach execution policy to role
resource "aws_iam_role_policy_attachment" "ecs_execution_policy_attachment" {
  role       = aws_iam_role.ecs_execution_role.name
  policy_arn = aws_iam_policy.ecs_execution_policy.arn
}

# CloudWatch log group for cloudflared
resource "aws_cloudwatch_log_group" "cloudflared" {
  name              = "/aws/ecs/${var.project_name}-cloudflared"
  retention_in_days = 30

  tags = {
    Name = "${var.project_name}-cloudflared-logs"
  }
}

# ECS service to run the cloudflared container
resource "aws_ecs_service" "cloudflared" {
  name                               = "${var.project_name}-cloudflared"
  cluster                            = aws_ecs_cluster.cloudflared.id
  task_definition                    = aws_ecs_task_definition.cloudflared.arn
  desired_count                      = 2
  launch_type                        = "FARGATE"
  platform_version                   = "1.4.0"
  health_check_grace_period_seconds  = 60
  propagate_tags                     = "SERVICE"
  enable_ecs_managed_tags            = true
  
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.cloudflared.id]
    assign_public_ip = false
  }

  # Ensure we always have at least one tunnel running
  deployment_controller {
    type = "ECS"
  }

  # Ensure proper replacement of tasks
  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${var.project_name}-cloudflared"
  }
}

# In modules/cloudflare-tunnel/main.tf, add to the ingress configuration:
{
  hostname = "cortex.${var.dns_domain}"
  service  = "https://${var.cortex_lb_dns}:443"
  originRequest = {
    noTLSVerify = true
  }
},