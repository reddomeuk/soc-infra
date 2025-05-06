# File: modules/cloudflare-tunnel/outputs.tf

output "tunnel_id" {
  description = "ID of the Cloudflare tunnel"
  value       = cloudflare_zero_trust_tunnel_cloudflared.soc_tunnel.id
}

output "tunnel_name" {
  description = "Name of the Cloudflare tunnel"
  value       = cloudflare_zero_trust_tunnel_cloudflared.soc_tunnel.name
}

output "wazuh_url" {
  description = "Public URL for Wazuh"
  value       = "https://wazuh.${var.dns_domain}"
}

output "thehive_url" {
  description = "Public URL for TheHive"
  value       = "https://thehive.${var.dns_domain}"
}

output "misp_url" {
  description = "Public URL for MISP"
  value       = "https://misp.${var.dns_domain}"
}

output "n8n_url" {
  description = "Public URL for n8n"
  value       = "https://n8n.${var.dns_domain}"
}

output "cloudflared_ecs_cluster_name" {
  description = "Name of the ECS cluster running cloudflared"
  value       = aws_ecs_cluster.cloudflared.name
}

output "cloudflared_ecs_service_name" {
  description = "Name of the ECS service running cloudflared"
  value       = aws_ecs_service.cloudflared.name
}