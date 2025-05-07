# modules/wazuh/outputs.tf

output "security_group_id" {
  description = "ID of the Wazuh security group"
  value       = aws_security_group.wazuh_sg.id
}

output "api_endpoint" {
  description = "Endpoint of the Wazuh API"
  value       = "https://${aws_lb.wazuh_lb.dns_name}:55000"
}

output "asg_name" {
  description = "Name of the Wazuh Auto Scaling Group"
  value       = aws_autoscaling_group.wazuh_asg.name
}

output "scale_up_policy_arn" {
  description = "ARN of the Wazuh scale up policy"
  value       = aws_autoscaling_policy.wazuh_scale_up.arn
}

output "scale_down_policy_arn" {
  description = "ARN of the Wazuh scale down policy"
  value       = aws_autoscaling_policy.wazuh_scale_down.arn
}

output "lb_dns_name" {
  description = "DNS name of the Wazuh load balancer"
  value       = aws_lb.wazuh_lb.dns_name
}

output "lb_arn_suffix" {
  description = "ARN suffix of the Wazuh load balancer"
  value       = aws_lb.wazuh_lb.arn_suffix
}