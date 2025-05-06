# File: modules/misp/main.tf

locals {
  misp_name = "${var.project_name}-misp"
}

# Security group for MISP servers
resource "aws_security_group" "misp_sg" {
  name        = "${local.misp_name}-sg"
  description = "Security group for MISP threat intelligence platform"
  vpc_id      = var.vpc_id
  
  # MISP Web Interface
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = [aws_security_group.misp_lb_sg.id]
    description = "MISP web interface (HTTPS)"
  }
  
  # SSH Access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_admin_cidrs
    description = "SSH"
  }
  
  # API Access from n8n
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = var.n8n_security_group_id != null ? [var.n8n_security_group_id] : []
    description = "MISP API access from n8n"
  }
  
  # API Access from TheHive
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = var.thehive_security_group_id != null ? [var.thehive_security_group_id] : []
    description = "MISP API access from TheHive"
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
  
  tags = {
    Name = "${local.misp_name}-sg"
  }
}

# Security group for MISP load balancer
resource "aws_security_group" "misp_lb_sg" {
  name        = "${local.misp_name}-lb-sg"
  description = "Security group for MISP load balancer"
  vpc_id      = var.vpc_id
  
  # HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_admin_cidrs
    description = "HTTPS for MISP web UI"
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
  
  tags = {
    Name = "${local.misp_name}-lb-sg"
  }
}

# Load balancer for MISP
resource "aws_lb" "misp_lb" {
  name               = "${var.project_name}-misp-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.misp_lb_sg.id]
  subnets            = var.public_subnet_ids
  
  enable_deletion_protection = true
  
  access_logs {
    bucket  = aws_s3_bucket.misp_lb_logs.bucket
    prefix  = "misp-lb"
    enabled = true
  }
  
  tags = {
    Name = "${local.misp_name}-lb"
  }
}

# S3 bucket for load balancer logs
resource "aws_s3_bucket" "misp_lb_logs" {
  bucket = "${var.project_name}-misp-lb-logs"
  
  tags = {
    Name = "${local.misp_name}-lb-logs"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "misp_lb_logs_encryption" {
  bucket = aws_s3_bucket.misp_lb_logs.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "misp_lb_logs_lifecycle" {
  bucket = aws_s3_bucket.misp_lb_logs.id
  
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

resource "aws_s3_bucket_policy" "misp_lb_logs_policy" {
  bucket = aws_s3_bucket.misp_lb_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_elb_service_account.main.id}:root"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.misp_lb_logs.arn}/*"
      }
    ]
  })
}

data "aws_elb_service_account" "main" {}

# Target group for MISP web interface
resource "aws_lb_target_group" "misp_tg" {
  name     = "${var.project_name}-misp-tg"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = var.vpc_id
  
  health_check {
    enabled             = true
    interval            = 30
    path                = "/users/login"
    port                = "traffic-port"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    protocol            = "HTTPS"
    matcher             = "200-399"
  }
  
  tags = {
    Name = "${local.misp_name}-tg"
  }
}

# Listener for HTTPS
resource "aws_lb_listener" "misp_https_listener" {
  load_balancer_arn = aws_lb.misp_lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.misp_tg.arn
  }
}

# Launch template for MISP instance
resource "aws_launch_template" "misp_launch_template" {
  name_prefix   = "${local.misp_name}-"
  image_id      = var.ami_id
  instance_type = var.instance_type
  
  key_name = var.key_name
  
  iam_instance_profile {
    name = var.iam_instance_profile
  }
  
  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.misp_sg.id]
  }
  
  block_device_mappings {
    device_name = "/dev/xvda"
    
    ebs {
      volume_size           = 80
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }
  
  user_data = base64encode(templatefile("${path.module}/templates/user_data.sh.tpl", {
    db_endpoint    = var.db_endpoint
    db_name        = var.db_name
    db_user        = var.db_user
    db_password    = var.db_password
    admin_email    = var.admin_email
    admin_password = random_password.misp_admin_password.result
    org_name       = var.org_name
    project_name   = var.project_name
    domain_name    = var.domain_name
    misp_version   = "2.4.167"
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
      Name = "${local.misp_name}"
    }
  }
}

# Generate a secure admin password for MISP
resource "random_password" "misp_admin_password" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# Auto Scaling Group for MISP
resource "aws_autoscaling_group" "misp_asg" {
  name                = "${local.misp_name}-asg"
  vpc_zone_identifier = var.subnet_ids
  min_size            = var.min_size
  max_size            = var.max_size
  desired_capacity    = var.desired_capacity
  
  launch_template {
    id      = aws_launch_template.misp_launch_template.id
    version = "$Latest"
  }
  
  target_group_arns = [aws_lb_target_group.misp_tg.arn]
  
  health_check_type         = "ELB"
  health_check_grace_period = 300
  
  default_cooldown          = 300
  
  termination_policies      = ["OldestInstance"]
  
  dynamic "tag" {
    for_each = {
      Name = "${local.misp_name}"
      Component = "misp"
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
resource "aws_autoscaling_policy" "misp_scale_up" {
  name                   = "${local.misp_name}-scale-up"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.misp_asg.name
}

resource "aws_autoscaling_policy" "misp_scale_down" {
  name                   = "${local.misp_name}-scale-down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.misp_asg.name
}

# SSM Parameter for storing MISP admin credentials
resource "aws_ssm_parameter" "misp_admin_password" {
  name        = "/${var.project_name}/misp/admin_password"
  description = "MISP admin password"
  type        = "SecureString"
  value       = random_password.misp_admin_password.result
  
  tags = {
    Name = "${local.misp_name}-admin-password"
  }
}

# Route53 record for MISP
resource "aws_route53_record" "misp" {
  count   = var.create_dns_record ? 1 : 0
  zone_id = var.route53_zone_id
  name    = "misp.${var.dns_domain}"
  type    = "A"
  
  alias {
    name                   = aws_lb.misp_lb.dns_name
    zone_id                = aws_lb.misp_lb.zone_id
    evaluate_target_health = true
  }
}

# S3 bucket for MISP file storage
resource "aws_s3_bucket" "misp_data" {
  bucket = "${var.project_name}-misp-data"
  
  tags = {
    Name = "${local.misp_name}-data"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "misp_data_encryption" {
  bucket = aws_s3_bucket.misp_data.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "misp_data_versioning" {
  bucket = aws_s3_bucket.misp_data.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "misp_data_access" {
  bucket = aws_s3_bucket.misp_data.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM policy for MISP to access the S3 bucket
resource "aws_iam_policy" "misp_s3_policy" {
  name        = "${local.misp_name}-s3-policy"
  description = "Policy for MISP to access S3 bucket"
  
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
          aws_s3_bucket.misp_data.arn,
          "${aws_s3_bucket.misp_data.arn}/*"
        ]
      }
    ]
  })
}