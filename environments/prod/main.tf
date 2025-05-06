# main.tf

# Configure required providers
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
  
  # Configure Terraform Cloud backend
  cloud {
    organization = var.tf_organization
    workspaces {
      name = var.tf_workspace
    }
  }
  
  required_version = ">= 1.4.0"
}

# AWS Provider
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Environment = var.environment
      Project     = var.project_name
      ManagedBy   = "Terraform"
      Repository  = "github.com/${var.github_repo}"
    }
  }
}

# Cloudflare Provider
provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# Networking Module
module "networking" {
  source = "./modules/networking"
  
  project_name = var.project_name
  aws_region   = var.aws_region
  vpc_cidr     = var.vpc_cidr
  availability_zones = var.availability_zones
  environment  = var.environment
}

# Database Module
module "database" {
  source = "./modules/database"
  
  project_name   = var.project_name
  vpc_id         = module.networking.vpc_id
  subnet_ids     = module.networking.database_subnet_ids
  instance_class = var.db_instance_class
  allocated_storage = var.db_allocated_storage
  engine_version    = var.db_engine_version
  db_name           = var.db_name
  db_username       = var.db_username
  db_password       = var.db_password
  environment       = var.environment
}

# Elasticsearch Module
module "elasticsearch" {
  source = "./modules/elasticsearch"
  
  project_name        = var.project_name
  vpc_id              = module.networking.vpc_id
  subnet_ids          = module.networking.private_subnet_ids
  security_group_ids  = [module.wazuh.security_group_id, module.thehive.security_group_id]
  elasticsearch_version = var.elasticsearch_version
  instance_type       = var.elasticsearch_instance_type
  instance_count      = var.elasticsearch_instance_count
  ebs_volume_size     = var.elasticsearch_ebs_volume_size
  environment         = var.environment
}

# Certificate Module
module "certificate" {
  source = "./modules/certificate"
  
  project_name = var.project_name
  domain_name  = var.dns_domain
  aws_region   = var.aws_region
}

# Wazuh Module
module "wazuh" {
  source = "./modules/wazuh"
  
  project_name         = var.project_name
  vpc_id               = module.networking.vpc_id
  subnet_ids           = module.networking.private_subnet_ids
  public_subnet_ids    = module.networking.public_subnet_ids
  ami_id               = var.wazuh_ami_id
  instance_type        = var.wazuh_instance_type
  key_name             = var.ssh_key_name
  min_size             = var.wazuh_min_size
  max_size             = var.wazuh_max_size
  desired_capacity     = var.wazuh_desired_capacity
  certificate_arn      = module.certificate.certificate_arn
  iam_instance_profile = aws_iam_instance_profile.wazuh_profile.name
  allowed_admin_cidrs  = var.allowed_admin_cidrs
  s3_bucket_name       = aws_s3_bucket.wazuh_data.bucket
  elasticsearch_domain_endpoint = module.elasticsearch.endpoint
  environment          = var.environment
  route53_zone_id      = var.route53_zone_id
  dns_domain           = var.dns_domain
  create_dns_record    = var.create_dns_record
}

# TheHive Module
module "thehive" {
  source = "./modules/thehive"
  
  project_name         = var.project_name
  vpc_id               = module.networking.vpc_id
  subnet_ids           = module.networking.private_subnet_ids
  public_subnet_ids    = module.networking.public_subnet_ids
  ami_id               = var.thehive_ami_id
  instance_type        = var.thehive_instance_type
  key_name             = var.ssh_key_name
  min_size             = var.thehive_min_size
  max_size             = var.thehive_max_size
  desired_capacity     = var.thehive_desired_capacity
  certificate_arn      = module.certificate.certificate_arn
  iam_instance_profile = aws_iam_instance_profile.thehive_profile.name
  allowed_admin_cidrs  = var.allowed_admin_cidrs
  db_endpoint          = module.database.endpoint
  db_name              = var.thehive_db_name
  db_user              = var.db_username
  db_password          = var.db_password
  elasticsearch_endpoint = module.elasticsearch.endpoint
  cortex_url           = var.cortex_url
  cortex_api_key       = var.cortex_api_key
  environment          = var.environment
  route53_zone_id      = var.route53_zone_id
  dns_domain           = var.dns_domain
  create_dns_record    = var.create_dns_record
  n8n_security_group_id = module.n8n.security_group_id
}

# MISP Module
module "misp" {
  source = "./modules/misp"
  
  project_name         = var.project_name
  vpc_id               = module.networking.vpc_id
  subnet_ids           = module.networking.private_subnet_ids
  public_subnet_ids    = module.networking.public_subnet_ids
  ami_id               = var.misp_ami_id
  instance_type        = var.misp_instance_type
  key_name             = var.ssh_key_name
  min_size             = var.misp_min_size
  max_size             = var.misp_max_size
  desired_capacity     = var.misp_desired_capacity
  certificate_arn      = module.certificate.certificate_arn
  iam_instance_profile = aws_iam_instance_profile.misp_profile.name
  allowed_admin_cidrs  = var.allowed_admin_cidrs
  db_endpoint          = module.database.endpoint
  db_name              = var.misp_db_name
  db_user              = var.db_username
  db_password          = var.db_password
  admin_email          = var.admin_email
  org_name             = var.org_name
  environment          = var.environment
  route53_zone_id      = var.route53_zone_id
  dns_domain           = var.dns_domain
  create_dns_record    = var.create_dns_record
  domain_name          = var.dns_domain
  n8n_security_group_id = module.n8n.security_group_id
  thehive_security_group_id = module.thehive.security_group_id
}

# n8n Module
module "n8n" {
  source = "./modules/n8n"
  
  project_name         = var.project_name
  vpc_id               = module.networking.vpc_id
  subnet_ids           = module.networking.private_subnet_ids
  public_subnet_ids    = module.networking.public_subnet_ids
  ami_id               = var.n8n_ami_id
  instance_type        = var.n8n_instance_type
  key_name             = var.ssh_key_name
  min_size             = var.n8n_min_size
  max_size             = var.n8n_max_size
  desired_capacity     = var.n8n_desired_capacity
  certificate_arn      = module.certificate.certificate_arn
  iam_instance_profile = aws_iam_instance_profile.n8n_profile.name
  allowed_admin_cidrs  = var.allowed_admin_cidrs
  db_endpoint          = module.database.endpoint
  db_name              = var.n8n_db_name
  db_user              = var.db_username
  db_password          = var.db_password
  wazuh_endpoint       = module.wazuh.api_endpoint
  thehive_endpoint     = module.thehive.endpoint
  misp_endpoint        = module.misp.endpoint
  webhook_url          = var.webhook_url
  environment          = var.environment
  route53_zone_id      = var.route53_zone_id
  dns_domain           = var.dns_domain
  create_dns_record    = var.create_dns_record
}

# Cloudflare Tunnel Module
module "cloudflare_tunnel" {
  source = "./modules/cloudflare-tunnel"
  
  project_name         = var.project_name
  aws_region           = var.aws_region
  cloudflare_account_id = var.cloudflare_account_id
  cloudflare_zone_id    = var.cloudflare_zone_id
  dns_domain            = var.dns_domain
  wazuh_lb_dns          = module.wazuh.lb_dns_name
  thehive_lb_dns        = module.thehive.lb_dns_name
  misp_lb_dns           = module.misp.lb_dns_name
  n8n_lb_dns            = module.n8n.lb_dns_name
  vpc_id                = module.networking.vpc_id
  private_subnet_ids    = module.networking.private_subnet_ids
  allowed_email_addresses = var.allowed_email_addresses
}

# Monitoring Module
module "monitoring" {
  source = "./modules/monitoring"
  
  project_name          = var.project_name
  alarm_email_endpoint  = var.admin_email
  wazuh_asg_name        = module.wazuh.asg_name
  n8n_asg_name          = module.n8n.asg_name
  thehive_asg_name      = module.thehive.asg_name
  wazuh_scale_up_policy_arn = module.wazuh.scale_up_policy_arn
  wazuh_scale_down_policy_arn = module.wazuh.scale_down_policy_arn
  n8n_scale_up_policy_arn = module.n8n.scale_up_policy_arn
  n8n_scale_down_policy_arn = module.n8n.scale_down_policy_arn
  db_instance_id        = module.database.instance_id
  wazuh_lb_arn_suffix   = module.wazuh.lb_arn_suffix
  thehive_lb_arn_suffix = module.thehive.lb_arn_suffix
  misp_lb_arn_suffix    = module.misp.lb_arn_suffix
  elasticsearch_domain_name = module.elasticsearch.domain_name
  monthly_budget_amount = var.monthly_budget_amount
  grafana_api_key       = var.grafana_api_key
}

# S3 bucket for Wazuh data
resource "aws_s3_bucket" "wazuh_data" {
  bucket = "${var.project_name}-wazuh-data"
  
  tags = {
    Name = "${var.project_name}-wazuh-data"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "wazuh_data_encryption" {
  bucket = aws_s3_bucket.wazuh_data.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# IAM profiles for EC2 instances
resource "aws_iam_role" "ec2_role" {
  name = "${var.project_name}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "wazuh_profile" {
  name = "${var.project_name}-wazuh-profile"
  role = aws_iam_role.ec2_role.name
}

resource "aws_iam_instance_profile" "thehive_profile" {
  name = "${var.project_name}-thehive-profile"
  role = aws_iam_role.ec2_role.name
}

resource "aws_iam_instance_profile" "misp_profile" {
  name = "${var.project_name}-misp-profile"
  role = aws_iam_role.ec2_role.name
}

resource "aws_iam_instance_profile" "n8n_profile" {
  name = "${var.project_name}-n8n-profile"
  role = aws_iam_role.ec2_role.name
}

# Attach policies to IAM role
resource "aws_iam_role_policy_attachment" "ssm_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cloudwatch_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "s3_read_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}