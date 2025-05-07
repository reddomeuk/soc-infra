# modules/database/main.tf

locals {
  db_name = "${var.project_name}-db"
}

# Create a subnet group for the RDS instance
resource "aws_db_subnet_group" "main" {
  name        = "${local.db_name}-subnet-group"
  description = "DB subnet group for ${var.project_name}"
  subnet_ids  = var.subnet_ids
  
  tags = {
    Name = "${local.db_name}-subnet-group"
  }
}

# Create a security group for the RDS instance
resource "aws_security_group" "db_sg" {
  name        = "${local.db_name}-sg"
  description = "Security group for ${var.project_name} database"
  vpc_id      = var.vpc_id
  
  ingress {
    description = "PostgreSQL from VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "${local.db_name}-sg"
  }
}

data "aws_vpc" "selected" {
  id = var.vpc_id
}

# Create a parameter group
resource "aws_db_parameter_group" "main" {
  name        = "${local.db_name}-param-group"
  family      = "postgres13"
  description = "Parameter group for ${var.project_name} database"
  
  parameter {
    name  = "log_connections"
    value = "1"
  }
  
  parameter {
    name  = "log_disconnections"
    value = "1"
  }
  
  parameter {
    name  = "log_duration"
    value = "1"
  }
  
  tags = {
    Name = "${local.db_name}-param-group"
  }
}

# Create an RDS instance
resource "aws_db_instance" "main" {
  identifier              = local.db_name
  allocated_storage       = var.allocated_storage
  storage_type            = "gp3"
  engine                  = "postgres"
  engine_version          = var.engine_version
  instance_class          = var.instance_class
  username                = var.db_username
  password                = var.db_password
  parameter_group_name    = aws_db_parameter_group.main.name
  db_subnet_group_name    = aws_db_subnet_group.main.name
  vpc_security_group_ids  = [aws_security_group.db_sg.id]
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "mon:04:00-mon:05:00"
  skip_final_snapshot     = false
  final_snapshot_identifier = "${local.db_name}-final-snapshot"
  storage_encrypted       = true
  multi_az                = true
  publicly_accessible     = false
  
  tags = {
    Name = local.db_name
  }
}

# Create databases for each component
resource "aws_db_instance" "thehive" {
  identifier              = "${var.project_name}-thehive"
  allocated_storage       = var.allocated_storage
  storage_type            = "gp3"
  engine                  = "postgres"
  engine_version          = var.engine_version
  instance_class          = var.instance_class
  username                = var.db_username
  password                = var.db_password
  parameter_group_name    = aws_db_parameter_group.main.name
  db_subnet_group_name    = aws_db_subnet_group.main.name
  vpc_security_group_ids  = [aws_security_group.db_sg.id]
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "mon:04:00-mon:05:00"
  skip_final_snapshot     = false
  final_snapshot_identifier = "${var.project_name}-thehive-final-snapshot"
  storage_encrypted       = true
  multi_az                = true
  publicly_accessible     = false
  
  tags = {
    Name = "${var.project_name}-thehive-db"
  }
}

resource "aws_db_instance" "misp" {
  identifier              = "${var.project_name}-misp"
  allocated_storage       = var.allocated_storage
  storage_type            = "gp3"
  engine                  = "mysql"
  engine_version          = "8.0"
  instance_class          = var.instance_class
  username                = var.db_username
  password                = var.db_password
  parameter_group_name    = "default.mysql8.0"
  db_subnet_group_name    = aws_db_subnet_group.main.name
  vpc_security_group_ids  = [aws_security_group.db_sg.id]
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "mon:04:00-mon:05:00"
  skip_final_snapshot     = false
  final_snapshot_identifier = "${var.project_name}-misp-final-snapshot"
  storage_encrypted       = true
  multi_az                = true
  publicly_accessible     = false
  
  tags = {
    Name = "${var.project_name}-misp-db"
  }
}

resource "aws_db_instance" "n8n" {
  identifier              = "${var.project_name}-n8n"
  allocated_storage       = var.allocated_storage
  storage_type            = "gp3"
  engine                  = "postgres"
  engine_version          = var.engine_version
  instance_class          = var.instance_class
  username                = var.db_username
  password                = var.db_password
  parameter_group_name    = aws_db_parameter_group.main.name
  db_subnet_group_name    = aws_db_subnet_group.main.name
  vpc_security_group_ids  = [aws_security_group.db_sg.id]
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "mon:04:00-mon:05:00"
  skip_final_snapshot     = false
  final_snapshot_identifier = "${var.project_name}-n8n-final-snapshot"
  storage_encrypted       = true
  multi_az                = true
  publicly_accessible     = false
  
  tags = {
    Name = "${var.project_name}-n8n-db"
  }
}