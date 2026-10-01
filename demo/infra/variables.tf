variable "enable_idle_instance" {
  type        = bool
  default     = false
  description = "Adds orders-demo-batch-worker (an idle, under-tagged, non-SSM-managed instance) for the COST-WASTE-IDLE-EC2 scenario."
}

variable "enable_public_bucket_violation" {
  type        = bool
  default     = false
  description = "Turns off orders-demo-exports' Block Public Access and adds a public-read bucket policy on public/* (SEC-003-3.2). Off by default so `demo-up` doesn't create a public bucket unless explicitly asked."
}
