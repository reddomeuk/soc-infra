# modules/grafana/main.tf

locals {
  grafana_name = "${var.project_name}-grafana"
}

# Security group for Grafana servers
resource "aws_security_group" "grafana_sg" {
  name        = "${local.grafana_name}-sg"
  description = "Security group for Grafana monitoring"
  vpc_id      = var.vpc_id
  
  # Grafana Web Interface
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    security_groups = [aws_security_group.grafana_lb_sg.id]
    description = "Grafana web interface"
  }
  
  # SSH Access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_admin_cidrs
    description = "SSH"
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
  
  tags = {
    Name = "${local.grafana_name}-sg"
  }
}

# Security group for Grafana load balancer
resource "aws_security_group" "grafana_lb_sg" {
  name        = "${local.grafana_name}-lb-sg"
  description = "Security group for Grafana load balancer"
  vpc_id      = var.vpc_id
  
  # HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_admin_cidrs
    description = "HTTPS for Grafana web UI"
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
  
  tags = {
    Name = "${local.grafana_name}-lb-sg"
  }
}

# Load balancer for Grafana
resource "aws_lb" "grafana_lb" {
  name               = "${var.project_name}-grafana-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.grafana_lb_sg.id]
  subnets            = var.public_subnet_ids
  
  enable_deletion_protection = true
  
  access_logs {
    bucket  = aws_s3_bucket.grafana_lb_logs.bucket
    prefix  = "grafana-lb"
    enabled = true
  }
  
  tags = {
    Name = "${local.grafana_name}-lb"
  }
}

# S3 bucket for load balancer logs
resource "aws_s3_bucket" "grafana_lb_logs" {
  bucket = "${var.project_name}-grafana-lb-logs"
  
  tags = {
    Name = "${local.grafana_name}-lb-logs"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "grafana_lb_logs_encryption" {
  bucket = aws_s3_bucket.grafana_lb_logs.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Target group for Grafana web interface
resource "aws_lb_target_group" "grafana_tg" {
  name     = "${var.project_name}-grafana-tg"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = var.vpc_id
  
  health_check {
    enabled             = true
    interval            = 30
    path                = "/api/health"
    port                = "traffic-port"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    protocol            = "HTTP"
    matcher             = "200"
  }
  
  tags = {
    Name = "${local.grafana_name}-tg"
  }
}

# Listener for HTTPS
resource "aws_lb_listener" "grafana_https_listener" {
  load_balancer_arn = aws_lb.grafana_lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.grafana_tg.arn
  }
}

# Launch template for Grafana instances
resource "aws_launch_template" "grafana_launch_template" {
  name_prefix   = "${local.grafana_name}-"
  image_id      = var.ami_id
  instance_type = var.instance_type
  
  key_name = var.key_name
  
  iam_instance_profile {
    name = var.iam_instance_profile
  }
  
  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.grafana_sg.id]
  }
  
  block_device_mappings {
    device_name = "/dev/xvda"
    
    ebs {
      volume_size           = 50
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }
  
  user_data = base64encode(templatefile("${path.module}/templates/user_data.sh.tpl", {
    admin_password     = random_password.grafana_admin_password.result
    admin_email        = var.admin_email
    wazuh_endpoint     = var.wazuh_endpoint
    thehive_endpoint   = var.thehive_endpoint
    misp_endpoint      = var.misp_endpoint
    n8n_endpoint       = var.n8n_endpoint
    elasticsearch_endpoint = var.elasticsearch_endpoint
    cloudwatch_region  = var.aws_region
    project_name       = var.project_name
    grafana_version    = "10.0.0"
  }))
  
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }
  
  monitoring {
    enabled = true
  }
  
  tag_specifications {
    resource_type = "instance"
    
    tags = {
      Name = "${local.grafana_name}"
    }
  }
}

# Generate a secure admin password for Grafana
resource "random_password" "grafana_admin_password" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# Auto Scaling Group for Grafana
resource "aws_autoscaling_group" "grafana_asg" {
  name                = "${local.grafana_name}-asg"
  vpc_zone_identifier = var.subnet_ids
  min_size            = var.min_size
  max_size            = var.max_size
  desired_capacity    = var.desired_capacity
  
  launch_template {
    id      = aws_launch_template.grafana_launch_template.id
    version = "$Latest"
  }
  
  target_group_arns = [aws_lb_target_group.grafana_tg.arn]
  
  health_check_type         = "ELB"
  health_check_grace_period = 300
  
  default_cooldown          = 300
  
  termination_policies      = ["OldestInstance"]
  
  dynamic "tag" {
    for_each = {
      Name = "${local.grafana_name}"
      Component = "grafana"
      Environment = var.environment
    }
    
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

# SSM Parameter for storing Grafana admin credentials
resource "aws_ssm_parameter" "grafana_admin_password" {
  name        = "/${var.project_name}/grafana/admin_password"
  description = "Grafana admin password"
  type        = "SecureString"
  value       = random_password.grafana_admin_password.result
  
  tags = {
    Name = "${local.grafana_name}-admin-password"
  }
}

# Route53 record for Grafana
resource "aws_route53_record" "grafana" {
  count   = var.create_dns_record ? 1 : 0
  zone_id = var.route53_zone_id
  name    = "grafana.${var.dns_domain}"
  type    = "A"
  
  alias {
    name                   = aws_lb.grafana_lb.dns_name
    zone_id                = aws_lb.grafana_lb.zone_id
    evaluate_target_health = true
  }
}

# Add Grafana to the Cloudflare tunnel
resource "cloudflare_dns_record" "grafana" {
  zone_id = var.cloudflare_zone_id
  name    = "grafana"
  value   = "${var.cloudflare_tunnel_id}.cfargotunnel.com"
  type    = "CNAME"
  proxied = true
}

resource "cloudflare_access_application" "grafana" {
  zone_id          = var.cloudflare_zone_id
  name             = "Grafana Dashboard"
  domain           = "grafana.${var.dns_domain}"
  session_duration = "24h"
  type             = "self_hosted"
}

resource "cloudflare_access_policy" "grafana_policy" {
  application_id = cloudflare_access_application.grafana.id
  zone_id        = var.cloudflare_zone_id
  name           = "Grafana Access"
  precedence     = 1
  decision       = "allow"

  include {
    email = var.allowed_email_addresses
  }
}