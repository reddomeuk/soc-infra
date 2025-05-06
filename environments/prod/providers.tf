terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
  
  # Configure Terraform Cloud
  cloud {
    organization = "your-organization"
    workspaces {
      name = "soc-prod"
    }
  }
  
  required_version = ">= 1.4.0"
}

# AWS Provider
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Environment = "production"
      Project     = "SOC-24-7"
      ManagedBy   = "Terraform"
      Repository  = "github.com/your-org/soc-infra"
    }
  }
}

# Cloudflare Provider
provider "cloudflare" {
  api_token = var.cloudflare_api_token
}