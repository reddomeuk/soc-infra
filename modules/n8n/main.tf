# File: modules/n8n/main.tf

locals {
  n8n_name = "${var.project_name}-n8n"
}

# Security group for n8n servers
resource "aws_security_group" "n8n_sg" {
  name        = "${local.n8n_name}-sg"
  description = "Security group for n8n workflow automation"
  vpc_id      = var.vpc_id
  
  # n8n Web Interface
  ingress {
    from_port   = 5678
    to_port     = 5678
    protocol    = "tcp"
    security_groups = [aws_security_group.n8n_lb_sg.id]
    description = "n8n web interface"
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
    Name = "${local.n8n_name}-sg"
  }
}

# Security group for n8n load balancer
resource "aws_security_group" "n8n_lb_sg" {
  name        = "${local.n8n_name}-lb-sg"
  description = "Security group for n8n load balancer"
  vpc_id      = var.vpc_id
  
  # HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_admin_cidrs
    description = "HTTPS for n8n web UI"
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
  
  tags = {
    Name = "${local.n8n_name}-lb-sg"
  }
}

# Load balancer for n8n
resource "aws_lb" "n8n_lb" {
  name               = "${var.project_name}-n8n-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.n8n_lb_sg.id]
  subnets            = var.public_subnet_ids
  
  enable_deletion_protection = true
  
  access_logs {
    bucket  = aws_s3_bucket.n8n_lb_logs.bucket
    prefix  = "n8n-lb"
    enabled = true
  }
  
  tags = {
    Name = "${local.n8n_name}-lb"
  }
}

# S3 bucket for load balancer logs
resource "aws_s3_bucket" "n8n_lb_logs" {
  bucket = "${var.project_name}-n8n-lb-logs"
  
  tags = {
    Name = "${local.n8n_name}-lb-logs"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "n8n_lb_logs_encryption" {
  bucket = aws_s3_bucket.n8n_lb_logs.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "n8n_lb_logs_lifecycle" {
  bucket = aws_s3_bucket.n8n_lb_logs.id
  
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

resource "aws_s3_bucket_policy" "n8n_lb_logs_policy" {
  bucket = aws_s3_bucket.n8n_lb_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_elb_service_account.main.id}:root"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.n8n_lb_logs.arn}/*"
      }
    ]
  })
}

data "aws_elb_service_account" "main" {}

# Target group for n8n web interface
resource "aws_lb_target_group" "n8n_tg" {
  name     = "${var.project_name}-n8n-tg"
  port     = 5678
  protocol = "HTTP"
  vpc_id   = var.vpc_id
  
  health_check {
    enabled             = true
    interval            = 30
    path                = "/"
    port                = "traffic-port"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    protocol            = "HTTP"
    matcher             = "200-399"
  }
  
  tags = {
    Name = "${local.n8n_name}-tg"
  }
}

# Listener for HTTPS
resource "aws_lb_listener" "n8n_https_listener" {
  load_balancer_arn = aws_lb.n8n_lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.n8n_tg.arn
  }
}

# Launch template for n8n instances
resource "aws_launch_template" "n8n_launch_template" {
  name_prefix   = "${local.n8n_name}-"
  image_id      = var.ami_id
  instance_type = var.instance_type
  
  key_name = var.key_name
  
  iam_instance_profile {
    name = var.iam_instance_profile
  }
  
  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.n8n_sg.id]
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
    db_endpoint      = var.db_endpoint
    db_name          = var.db_name
    db_user          = var.db_user
    db_password      = var.db_password
    wazuh_endpoint   = var.wazuh_endpoint
    thehive_endpoint = var.thehive_endpoint
    misp_endpoint    = var.misp_endpoint
    encryption_key   = random_password.n8n_encryption_key.result
    webhook_url      = var.webhook_url
    project_name     = var.project_name
    n8n_version      = "1.14.0"
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
      Name = "${local.n8n_name}"
    }
  }
}

# Generate a secure encryption key for n8n
resource "random_password" "n8n_encryption_key" {
  length  = 32
  special = true
}

# Auto Scaling Group for n8n
resource "aws_autoscaling_group" "n8n_asg" {
  name                = "${local.n8n_name}-asg"
  vpc_zone_identifier = var.subnet_ids
  min_size            = var.min_size
  max_size            = var.max_size
  desired_capacity    = var.desired_capacity
  
  launch_template {
    id      = aws_launch_template.n8n_launch_template.id
    version = "$Latest"
  }
  
  target_group_arns = [aws_lb_target_group.n8n_tg.arn]
  
  health_check_type         = "ELB"
  health_check_grace_period = 300
  
  default_cooldown          = 300
  
  termination_policies      = ["OldestInstance"]
  
  dynamic "tag" {
    for_each = {
      Name = "${local.n8n_name}"
      Component = "n8n"
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
resource "aws_autoscaling_policy" "n8n_scale_up" {
  name                   = "${local.n8n_name}-scale-up"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.n8n_asg.name
}

resource "aws_autoscaling_policy" "n8n_scale_down" {
  name                   = "${local.n8n_name}-scale-down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.n8n_asg.name
}

# SSM Parameter for storing n8n admin credentials
resource "aws_ssm_parameter" "n8n_admin_password" {
  name        = "/${var.project_name}/n8n/admin_password"
  description = "n8n admin password"
  type        = "SecureString"
  value       = random_password.n8n_admin_password.result
  
  tags = {
    Name = "${local.n8n_name}-admin-password"
  }
}

resource "random_password" "n8n_admin_password" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# Route53 record for n8n
resource "aws_route53_record" "n8n" {
  count   = var.create_dns_record ? 1 : 0
  zone_id = var.route53_zone_id
  name    = "n8n.${var.dns_domain}"
  type    = "A"
  
  alias {
    name                   = aws_lb.n8n_lb.dns_name
    zone_id                = aws_lb.n8n_lb.zone_id
    evaluate_target_health = true
  }
}

# S3 bucket for n8n workflows and data
resource "aws_s3_bucket" "n8n_data" {
  bucket = "${var.project_name}-n8n-data"
  
  tags = {
    Name = "${local.n8n_name}-data"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "n8n_data_encryption" {
  bucket = aws_s3_bucket.n8n_data.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "n8n_data_versioning" {
  bucket = aws_s3_bucket.n8n_data.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "n8n_data_access" {
  bucket = aws_s3_bucket.n8n_data.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM policy for n8n to access the S3 bucket
resource "aws_iam_policy" "n8n_s3_policy" {
  name        = "${local.n8n_name}-s3-policy"
  description = "Policy for n8n to access S3 bucket"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:DeleteObject"
        ]
        Resource = [
          aws_s3_bucket.n8n_data.arn,
          "${aws_s3_bucket.n8n_data.arn}/*"
        ]
      }
    ]
  })
}

# SSM Parameter to store n8n configuration
resource "aws_ssm_parameter" "n8n_config" {
  name        = "/${var.project_name}/n8n/config"
  description = "n8n configuration"
  type        = "SecureString"
  value = jsonencode({
    database = {
      endpoint = var.db_endpoint
      name     = var.db_name
      user     = var.db_user
      password = var.db_password
    }
    encryption_key = random_password.n8n_encryption_key.result
    admin_password = random_password.n8n_admin_password.result
    integrations = {
      wazuh_endpoint   = var.wazuh_endpoint
      thehive_endpoint = var.thehive_endpoint
      misp_endpoint    = var.misp_endpoint
      webhook_url      = var.webhook_url
    }
  })
  
  tags = {
    Name = "${local.n8n_name}-config"
  }
}