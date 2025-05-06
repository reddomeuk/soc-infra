# modules/certificate/main.tf

# Request a certificate from AWS Certificate Manager
resource "aws_acm_certificate" "main" {
  domain_name       = var.domain_name
  validation_method = "DNS"
  
  subject_alternative_names = [
    "*.${var.domain_name}"
  ]
  
  lifecycle {
    create_before_destroy = true
  }
  
  tags = {
    Name = "${var.project_name}-certificate"
  }
}

# Get the hosted zone for the domain
data "aws_route53_zone" "zone" {
  count        = var.create_validation_records ? 1 : 0
  name         = var.domain_name
  private_zone = false
}

# Create DNS records for certificate validation
resource "aws_route53_record" "validation" {
  for_each = var.create_validation_records ? {
    for dvo in aws_acm_certificate.main.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}
  
  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.zone[0].zone_id
}

# Validate the certificate
resource "aws_acm_certificate_validation" "main" {
  count                   = var.create_validation_records ? 1 : 0
  certificate_arn         = aws_acm_certificate.main.arn
  validation_record_fqdns = [for record in aws_route53_record.validation : record.fqdn]
}