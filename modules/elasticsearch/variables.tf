# modules/elasticsearch/variables.tf

variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC"
  type        = string
}

variable "subnet_ids" {
  description = "IDs of subnets for Elasticsearch"
  type        = list(string)
}

variable "security_group_ids" {
  description = "Security groups allowed to access Elasticsearch"
  type        = list(string)
}

variable "elasticsearch_version" {
  description = "Version of Elasticsearch"
  type        = string
}

variable "instance_type" {
  description = "Instance type for Elasticsearch nodes"
  type        = string
}

variable "instance_count" {
  description = "Number of Elasticsearch nodes"
  type        = number
}

variable "ebs_volume_size" {
  description = "Size of EBS volume in GB"
  type        = number
}

variable "environment" {
  description = "Environment name"
  type        = string
}