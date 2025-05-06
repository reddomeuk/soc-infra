# outputs.tf

output "vpc_id" {
  description = "ID of the VPC"
  value       = module.networking.vpc_id
}

output "database_endpoint" {
  description = "Endpoint of the RDS database"
  value       = module.database.endpoint
  sensitive   = true
}

output "elasticsearch_endpoint" {
  description = "Endpoint of the Elasticsearch domain"
  value       = module.elasticsearch.endpoint
  sensitive   = true
}

output "wazuh_lb_dns_name" {
  description = "DNS name of the Wazuh load balancer"
  value       = module.wazuh.lb_dns_name
}

output "thehive_lb_dns_name" {
  description = "DNS name of TheHive load balancer"
  value       = module.thehive.lb_dns_name
}

output "misp_lb_dns_name" {
  description = "DNS name of MISP load balancer"
  value       = module.misp.lb_dns_name
}

output "n8n_lb_dns_name" {
  description = "DNS name of n8n load balancer"
  value       = module.n8n.lb_dns_name
}

output "cloudflare_tunnel_id" {
  description = "ID of the Cloudflare tunnel"
  value       = module.cloudflare_tunnel.tunnel_id
}

output "wazuh_url" {
  description = "Public URL for Wazuh"
  value       = module.cloudflare_tunnel.wazuh_url
}

output "thehive_url" {
  description = "Public URL for TheHive"
  value       = module.cloudflare_tunnel.thehive_url
}

output "misp_url" {
  description = "Public URL for MISP"
  value       = module.cloudflare_tunnel.misp_url
}

output "n8n_url" {
  description = "Public URL for n8n"
  value       = module.cloudflare_tunnel.n8n_url
}

output "cloudwatch_dashboard_url" {
  description = "URL for the CloudWatch Dashboard"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${var.project_name}-soc-dashboard"
}

output "ssm_parameters" {
  description = "List of SSM Parameters created for storing credentials"
  value = [
    "/${var.project_name}/wazuh/admin_password",
    "/${var.project_name}/thehive/admin_password",
    "/${var.project_name}/thehive/api_key",
    "/${var.project_name}/misp/admin_password",
    "/${var.project_name}/misp/api_key",
    "/${var.project_name}/n8n/admin_password",
    "/${var.project_name}/n8n/config"
  ]
  sensitive = true
}