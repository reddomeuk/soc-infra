# File: modules/wazuh/main.tf

locals {
  wazuh_name = "${var.project_name}-wazuh"
}

# Security group for Wazuh servers
resource "aws_security_group" "wazuh_sg" {
  name        = "${local.wazuh_name}-sg"
  description = "Security group for Wazuh servers"
  vpc_id      = var.vpc_id
  
  # Wazuh Manager Port
  ingress {
    from_port   = 1514
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
    description = "Wazuh agent connection"
  }
  
  # Wazuh Registration Service
  ingress {
    from_port   = 1515
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
    description = "Wazuh agent registration service"
  }
  
  # Wazuh API Port
  ingress {
    from_port   = 55000
    to_port     = 55000
    protocol    = "tcp"
    security_groups = [aws_security_group.wazuh_lb_sg.id]
    description = "Wazuh API"
  }
  
  # Wazuh Cluster Communications
  ingress {
    from_port   = 1516
    to_port     = 1516
    protocol    = "tcp"
    self        = true
    description = "Wazuh cluster daemon"
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
    Name = "${local.wazuh_name}-sg"
  }
}

# Security group for Wazuh load balancer
resource "aws_security_group" "wazuh_lb_sg" {
  name        = "${local.wazuh_name}-lb-sg"
  description = "Security group for Wazuh load balancer"
  vpc_id      = var.vpc_id
  
  # HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_admin_cidrs
    description = "HTTPS for web UI"
  }
  
  # Wazuh API
  ingress {
    from_port   = 55000
    to_port     = 55000
    protocol    = "tcp"
    cidr_blocks = var.allowed_admin_cidrs
    description = "Wazuh API"
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
  
  tags = {
    Name = "${local.wazuh_name}-lb-sg"
  }
}

# Get the VPC data
data "aws_vpc" "selected" {
  id = var.vpc_id
}

# Load balancer for Wazuh
resource "aws_lb" "wazuh_lb" {
  name               = "${var.project_name}-wazuh-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.wazuh_lb_sg.id]
  subnets            = var.public_subnet_ids
  
  enable_deletion_protection = true
  
  access_logs {
    bucket  = aws_s3_bucket.wazuh_lb_logs.bucket
    prefix  = "wazuh-lb"
    enabled = true
  }
  
  tags = {
    Name = "${local.wazuh_name}-lb"
  }
}

# S3 bucket for load balancer logs
resource "aws_s3_bucket" "wazuh_lb_logs" {
  bucket = "${var.project_name}-wazuh-lb-logs"
  
  tags = {
    Name = "${local.wazuh_name}-lb-logs"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "wazuh_lb_logs_encryption" {
  bucket = aws_s3_bucket.wazuh_lb_logs.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "wazuh_lb_logs_lifecycle" {
  bucket = aws_s3_bucket.wazuh_lb_logs.id
  
  rule {
    id     = "log-rotation"
    status = "Enabled"
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    
    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_policy" "wazuh_lb_logs_policy" {
  bucket = aws_s3_bucket.wazuh_lb_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_elb_service_account.main.id}:root"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.wazuh_lb_logs.arn}/*"
      }
    ]
  })
}

data "aws_elb_service_account" "main" {}

# Target group for Wazuh web interface
resource "aws_lb_target_group" "wazuh_web_tg" {
  name     = "${var.project_name}-wazuh-web-tg"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = var.vpc_id
  
  health_check {
    enabled             = true
    interval            = 30
    path                = "/"
    port                = "traffic-port"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    protocol            = "HTTPS"
    matcher             = "200-399"
  }
  
  tags = {
    Name = "${local.wazuh_name}-web-tg"
  }
}

# Target group for Wazuh API
resource "aws_lb_target_group" "wazuh_api_tg" {
  name     = "${var.project_name}-wazuh-api-tg"
  port     = 55000
  protocol = "HTTPS"
  vpc_id   = var.vpc_id
  
  health_check {
    enabled             = true
    interval            = 30
    path                = "/"
    port                = "traffic-port"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    protocol            = "HTTPS"
    matcher             = "200-399"
  }
  
  tags = {
    Name = "${local.wazuh_name}-api-tg"
  }
}

# Listener for HTTPS (Web UI)
resource "aws_lb_listener" "wazuh_https_listener" {
  load_balancer_arn = aws_lb.wazuh_lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wazuh_web_tg.arn
  }
}

# Listener for Wazuh API
resource "aws_lb_listener" "wazuh_api_listener" {
  load_balancer_arn = aws_lb.wazuh_lb.arn
  port              = "55000"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wazuh_api_tg.arn
  }
}

# Launch template for Wazuh instances
resource "aws_launch_template" "wazuh_launch_template" {
  name_prefix   = "${local.wazuh_name}-"
  image_id      = var.ami_id
  instance_type = var.instance_type
  
  key_name = var.key_name
  
  iam_instance_profile {
    name = var.iam_instance_profile
  }
  
  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.wazuh_sg.id]
  }
  
  block_device_mappings {
    device_name = "/dev/xvda"
    
    ebs {
      volume_size           = 100
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }
  
  user_data = base64encode(templatefile("${path.module}/templates/user_data.sh.tpl", {
    cluster_key             = random_password.wazuh_cluster_key.result
    node_type               = "master"
    node_name               = "wazuh-master"
    elasticsearch_endpoint  = var.elasticsearch_domain_endpoint
    s3_bucket               = var.s3_bucket_name
    wazuh_version           = "4.7.1"
    project_name            = var.project_name
  }))
  
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  
  monitoring {
    enabled = true
  }
  
  tag_specifications {
    resource_type = "instance"
    
    tags = {
      Name = "${local.wazuh_name}"
    }
  }
}

# Generate a random key for Wazuh cluster
resource "random_password" "wazuh_cluster_key" {
  length  = 32
  special = false
}

# Auto Scaling Group for Wazuh
resource "aws_autoscaling_group" "wazuh_asg" {
  name                = "${local.wazuh_name}-asg"
  vpc_zone_identifier = var.subnet_ids
  min_size            = var.min_size
  max_size            = var.max_size
  desired_capacity    = var.desired_capacity
  
  launch_template {
    id      = aws_launch_template.wazuh_launch_template.id
    version = "$Latest"
  }
  
  target_group_arns = [
    aws_lb_target_group.wazuh_web_tg.arn,
    aws_lb_target_group.wazuh_api_tg.arn
  ]
  
  health_check_type         = "ELB"
  health_check_grace_period = 300
  
  default_cooldown          = 300
  
  termination_policies      = ["OldestInstance"]
  
  dynamic "tag" {
    for_each = {
      Name = "${local.wazuh_name}"
      Component = "wazuh"
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

# Auto Scaling Policies
resource "aws_autoscaling_policy" "wazuh_scale_up" {
  name                   = "${local.wazuh_name}-scale-up"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.wazuh_asg.name
}

resource "aws_autoscaling_policy" "wazuh_scale_down" {
  name                   = "${local.wazuh_name}-scale-down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.wazuh_asg.name
}

# SSM Parameter for storing Wazuh admin credentials
resource "aws_ssm_parameter" "wazuh_admin_password" {
  name        = "/${var.project_name}/wazuh/admin_password"
  description = "Wazuh admin password"
  type        = "SecureString"
  value       = random_password.wazuh_admin_password.result
  
  tags = {
    Name = "${local.wazuh_name}-admin-password"
  }
}

resource "random_password" "wazuh_admin_password" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# Route53 record for Wazuh
resource "aws_route53_record" "wazuh" {
  count   = var.create_dns_record ? 1 : 0
  zone_id = var.route53_zone_id
  name    = "wazuh.${var.dns_domain}"
  type    = "A"
  
  alias {
    name                   = aws_lb.wazuh_lb.dns_name
    zone_id                = aws_lb.wazuh_lb.zone_id
    evaluate_target_health = true
  }
}