# modules/certificate/variables.tf

variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "domain_name" {
  description = "Domain name for the certificate"
  type        = string
}

variable "create_validation_records" {
  description = "Whether to create DNS validation records"
  type        = bool
  default     = false
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}