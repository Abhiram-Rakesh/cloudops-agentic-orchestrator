# Lambda Function URL for slack_handler: auth NONE at the URL layer —
# slack_handler verifies Slack's own HMAC signature in code instead
# (handlers/slack_handler.py's verify_signature/is_fresh). A Function URL
# with authorization_type NONE still requires an explicit resource-based
# policy granting lambda:InvokeFunctionUrl to "*", or every request 403s.

resource "aws_lambda_function_url" "slack_handler" {
  function_name      = var.slack_handler_function_name
  authorization_type = "NONE"

  cors {
    allow_methods = ["POST"]
    allow_origins = ["https://slack.com"]
  }
}

resource "aws_lambda_permission" "slack_handler_function_url" {
  statement_id           = "AllowPublicInvokeViaFunctionUrl"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = var.slack_handler_function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}
