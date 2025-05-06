# modules/elasticsearch/outputs.tf

output "endpoint" {
  description = "Endpoint of the Elasticsearch domain"
  value       = "https://${aws_elasticsearch_domain.es.endpoint}"
}

output "domain_name" {
  description = "Name of the Elasticsearch domain"
  value       = aws_elasticsearch_domain.es.domain_name
}

output "domain_id" {
  description = "ID of the Elasticsearch domain"
  value       = aws_elasticsearch_domain.es.domain_id
}

output "security_group_id" {
  description = "ID of the Elasticsearch security group"
  value       = aws_security_group.es_sg.id
}