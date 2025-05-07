# modules/cortex/main.tf

locals {
  cortex_name = "${var.project_name}-cortex"
}

# Security group for Cortex servers
resource "aws_security_group" "cortex_sg" {
  name        = "${local.cortex_name}-sg"
  description = "Security group for Cortex security analysis"
  vpc_id      = var.vpc_id
  
  # Cortex Web Interface
  ingress {
    from_port   = 9001
    to_port     = 9001
    protocol    = "tcp"
    security_groups = [aws_security_group.cortex_lb_sg.id]
    description = "Cortex web interface"
  }
  
  # SSH Access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_admin_cidrs
    description = "SSH"
  }
  
  # TheHive Access
  ingress {
    from_port   = 9001
    to_port     = 9001
    protocol    = "tcp"
    security_groups = [var.thehive_security_group_id]
    description = "TheHive access to Cortex API"
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
  
  tags = {
    Name = "${local.cortex_name}-sg"
  }
}

# The rest of your Cortex infrastructure code would follow a similar
# pattern to your other modules (load balancer, auto-scaling group, etc.)