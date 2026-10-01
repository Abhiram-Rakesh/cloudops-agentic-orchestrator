output "document_names" {
  value = [for d in aws_ssm_document.remediation : d.name]
}

output "document_arns" {
  value = { for k, d in aws_ssm_document.remediation : d.name => d.arn }
}
