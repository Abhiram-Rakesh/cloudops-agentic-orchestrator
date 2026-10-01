# One aws_ssm_document per file in ssm_documents/ — schemaVersion 0.3
# Automation documents, each starting with a protected-tag abort check.

locals {
  ssm_documents_dir = abspath("${path.module}/../../../ssm_documents")
  document_files    = fileset(local.ssm_documents_dir, "*.yaml")
}

resource "aws_ssm_document" "remediation" {
  for_each = local.document_files

  name            = trimsuffix(each.value, ".yaml")
  document_type   = "Automation"
  document_format = "YAML"
  content         = file("${local.ssm_documents_dir}/${each.value}")
}
