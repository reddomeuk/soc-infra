# modules/database/outputs.tf

output "endpoint" {
  description = "Endpoint of the main database"
  value       = aws_db_instance.main.endpoint
}

output "thehive_endpoint" {
  description = "Endpoint of TheHive database"
  value       = aws_db_instance.thehive.endpoint
}

output "misp_endpoint" {
  description = "Endpoint of MISP database"
  value       = aws_db_instance.misp.endpoint
}

output "n8n_endpoint" {
  description = "Endpoint of n8n database"
  value       = aws_db_instance.n8n.endpoint
}

output "instance_id" {
  description = "ID of the main database instance"
  value       = aws_db_instance.main.id
}

output "security_group_id" {
  description = "ID of the database security group"
  value       = aws_security_group.db_sg.id
}