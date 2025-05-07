# Cortex Configuration
variable "cortex_ami_id" {
  description = "AMI ID for Cortex instances"
  type        = string
  default     = "ami-0c55b159cbfafe1f0" # Ubuntu 20.04
}

variable "cortex_instance_type" {
  description = "Instance type for Cortex"
  type        = string
  default     = "t3.medium"
}

variable "cortex_min_size" {
  description = "Minimum size of Cortex ASG"
  type        = number
  default     = 1
}

variable "cortex_max_size" {
  description = "Maximum size of Cortex ASG"
  type        = number
  default     = 2
}

variable "cortex_desired_capacity" {
  description = "Desired capacity of Cortex ASG"
  type        = number
  default     = 1
}

variable "cortex_db_name" {
  description = "Database name for Cortex"
  type        = string
  default     = "cortex"
}