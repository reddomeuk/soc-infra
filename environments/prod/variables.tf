# variables.tf

# Terraform Cloud Variables
variable "tf_organization" {
  description = "Terraform Cloud organization name"
  type        = string
}

variable "tf_workspace" {
  description = "Terraform Cloud workspace name"
  type        = string
}

# Project Variables
variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "soc-prod"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
  default     = "your-org/soc-infra"
}

# AWS Configuration
variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

# Networking
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

# Database
variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "db_allocated_storage" {
  description = "Allocated storage for RDS in GB"
  type        = number
  default     = 20
}

variable "db_engine_version" {
  description = "RDS engine version"
  type        = string
  default     = "13.7"
}

variable "db_name" {
  description = "Master database name"
  type        = string
  default     = "socmaster"
}

variable "db_username" {
  description = "Master username for the database"
  type        = string
  sensitive   = true
}

variable "db_password" {
  description = "Master password for the database"
  type        = string
  sensitive   = true
}

variable "thehive_db_name" {
  description = "Database name for TheHive"
  type        = string
  default     = "thehive"
}

variable "misp_db_name" {
  description = "Database name for MISP"
  type        = string
  default     = "misp"
}

variable "n8n_db_name" {
  description = "Database name for n8n"
  type        = string
  default     = "n8n"
}

# Elasticsearch
variable "elasticsearch_version" {
  description = "Elasticsearch version"
  type        = string
  default     = "7.10"
}

variable "elasticsearch_instance_type" {
  description = "Elasticsearch instance type"
  type        = string
  default     = "t3.medium.elasticsearch"
}

variable "elasticsearch_instance_count" {
  description = "Number of Elasticsearch instances"
  type        = number
  default     = 3
}

variable "elasticsearch_ebs_volume_size" {
  description = "Size of EBS volumes for Elasticsearch"
  type        = number
  default     = 100
}

# EC2 Configuration
variable "ssh_key_name" {
  description = "Name of the SSH key pair"
  type        = string
}

# AMI IDs
variable "wazuh_ami_id" {
  description = "AMI ID for Wazuh instances"
  type        = string
  default     = "ami-0c55b159cbfafe1f0" # Amazon Linux 2
}

variable "thehive_ami_id" {
  description = "AMI ID for TheHive instances"
  type        = string
  default     = "ami-0c55b159cbfafe1f0" # Ubuntu 20.04
}

variable "misp_ami_id" {
  description = "AMI ID for MISP instances"
  type        = string
  default     = "ami-0c55b159cbfafe1f0" # Ubuntu 20.04
}

variable "n8n_ami_id" {
  description = "AMI ID for n8n instances"
  type        = string
  default     = "ami-0c55b159cbfafe1f0" # Ubuntu 20.04
}

# Instance Types
variable "wazuh_instance_type" {
  description = "Instance type for Wazuh"
  type        = string
  default     = "t3.large"
}

variable "thehive_instance_type" {
  description = "Instance type for TheHive"
  type        = string
  default     = "t3.large"
}

variable "misp_instance_type" {
  description = "Instance type for MISP"
  type        = string
  default     = "t3.large"
}

variable "n8n_instance_type" {
  description = "Instance type for n8n"
  type        = string
  default     = "t3.medium"
}

# Auto Scaling Configuration
variable "wazuh_min_size" {
  description = "Minimum size of Wazuh ASG"
  type        = number
  default     = 1
}

variable "wazuh_max_size" {
  description = "Maximum size of Wazuh ASG"
  type        = number
  default     = 3
}

variable "wazuh_desired_capacity" {
  description = "Desired capacity of Wazuh ASG"
  type        = number
  default     = 2
}

variable "thehive_min_size" {
  description = "Minimum size of TheHive ASG"
  type        = number
  default     = 1
}

variable "thehive_max_size" {
  description = "Maximum size of TheHive ASG"
  type        = number
  default     = 3
}

variable "thehive_desired_capacity" {
  description = "Desired capacity of TheHive ASG"
  type        = number
  default     = 2
}

variable "misp_min_size" {
  description = "Minimum size of MISP ASG"
  type        = number
  default     = 1
}

variable "misp_max_size" {
  description = "Maximum size of MISP ASG"
  type        = number
  default     = 2
}

variable "misp_desired_capacity" {
  description = "Desired capacity of MISP ASG"
  type        = number
  default     = 1
}

variable "n8n_min_size" {
  description = "Minimum size of n8n ASG"
  type        = number
  default     = 1
}

variable "n8n_max_size" {
  description = "Maximum size of n8n ASG"
  type        = number
  default     = 2
}

variable "n8n_desired_capacity" {
  description = "Desired capacity of n8n ASG"
  type        = number
  default     = 1
}

# Security
variable "allowed_admin_cidrs" {
  description = "List of CIDR blocks allowed to access SOC admin interfaces"
  type        = list(string)
  default     = ["0.0.0.0/0"] # You should restrict this in production
}

# Cloudflare Configuration
variable "cloudflare_api_token" {
  description = "Cloudflare API token"
  type        = string
  sensitive   = true
}

variable "cloudflare_account_id" {
  description = "Cloudflare account ID"
  type        = string
  sensitive   = true
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID"
  type        = string
}

# DNS Configuration
variable "dns_domain" {
  description = "Domain name for SOC services"
  type        = string
}

variable "route53_zone_id" {
  description = "Route53 hosted zone ID"
  type        = string
  default     = ""
}

variable "create_dns_record" {
  description = "Whether to create DNS records in Route53"
  type        = bool
  default     = false
}

# Email Configuration
variable "admin_email" {
  description = "Admin email address"
  type        = string
}

variable "allowed_email_addresses" {
  description = "List of email addresses allowed to access SOC services"
  type        = list(string)
}

# Organization Configuration
variable "org_name" {
  description = "Organization name"
  type        = string
  default     = "SOC Team"
}

# Integration Configuration
variable "cortex_url" {
  description = "URL for Cortex integration"
  type        = string
  default     = ""
}

variable "cortex_api_key" {
  description = "API key for Cortex integration"
  type        = string
  default     = ""
  sensitive   = true
}

variable "webhook_url" {
  description = "Webhook URL for alerts"
  type        = string
  default     = ""
}

# Monitoring
variable "monthly_budget_amount" {
  description = "Monthly budget amount in USD"
  type        = number
  default     = 500
}

variable "grafana_api_key" {
  description = "API key for Grafana"
  type        = string
  default     = ""
  sensitive   = true
}