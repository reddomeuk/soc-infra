# File: modules/cloudflare-tunnel/variables.tf

variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "cloudflare_account_id" {
  description = "Cloudflare account ID"
  type        = string
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID"
  type        = string
}

variable "dns_domain" {
  description = "Domain name for the SOC services"
  type        = string
}

variable "wazuh_lb_dns" {
  description = "DNS name of the Wazuh load balancer"
  type        = string
}

variable "thehive_lb_dns" {
  description = "DNS name of TheHive load balancer"
  type        = string
}

variable "misp_lb_dns" {
  description = "DNS name of MISP load balancer"
  type        = string
}

variable "n8n_lb_dns" {
  description = "DNS name of n8n load balancer"
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC"
  type        = string
}

variable "private_subnet_ids" {
  description = "IDs of private subnets for ECS Fargate"
  type        = list(string)
}

variable "allowed_email_addresses" {
  description = "List of email addresses allowed to access the SOC services"
  type        = list(string)
}