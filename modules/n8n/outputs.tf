# modules/n8n/outputs.tf

output "security_group_id" {
  description = "ID of the n8n security group"
  value       = aws_security_group.n8n_sg.id
}