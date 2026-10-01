output "vpc_id" {
  value = aws_vpc.orders_demo.id
}

output "web_instance_id" {
  value = aws_instance.web.id
}

output "app_security_group_id" {
  value = aws_security_group.app.id
}

output "exports_bucket_name" {
  value = aws_s3_bucket.exports.id
}

output "assets_bucket_name" {
  value = aws_s3_bucket.assets.id
}
