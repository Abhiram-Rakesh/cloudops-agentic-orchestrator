output "state_machine_arn" {
  value = aws_sfn_state_machine.review.arn
}

output "state_machine_name" {
  value = aws_sfn_state_machine.review.name
}

output "scheduler_dlq_arn" {
  value = aws_sqs_queue.scheduler_dlq.arn
}

output "scheduler_dlq_name" {
  value = aws_sqs_queue.scheduler_dlq.name
}
