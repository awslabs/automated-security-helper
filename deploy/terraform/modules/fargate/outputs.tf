output "mcp_endpoint_url" {
  description = "Full URL MCP clients should POST to."
  value       = "${local.use_tls ? "https" : "http"}://${aws_lb.this.dns_name}:${local.listener_port}${var.mcp_mount_path}"
}

output "load_balancer_dns_name" {
  description = "DNS name of the load balancer."
  value       = aws_lb.this.dns_name
}

output "load_balancer_arn" {
  description = "ARN of the load balancer."
  value       = aws_lb.this.arn
}

output "load_balancer_zone_id" {
  description = "Hosted zone ID of the load balancer, for a Route 53 alias record."
  value       = aws_lb.this.zone_id
}

output "listener_arn" {
  description = "ARN of the listener, for attaching additional rules."
  value       = aws_lb_listener.this.arn
}

output "target_group_arn" {
  description = "ARN of the target group."
  value       = aws_lb_target_group.this.arn
}

output "allowed_hosts" {
  description = <<-EOT
    Host header values ASH is configured to accept, passed through its repeatable
    --allowed-host flag. Contains the load balancer DNS name with and without the
    listener port, plus anything supplied in mcp_allowed_host.

    A client dialing a name that is not in this list gets rejected by the MCP
    SDK's DNS-rebinding protection. Add such names to mcp_allowed_host.
  EOT
  value       = local.allowed_hosts
}

output "cluster_arn" {
  description = "ARN of the ECS cluster the service runs in, whether created here or supplied."
  value       = local.cluster_arn
}

output "service_name" {
  description = "Name of the ECS service."
  value       = aws_ecs_service.this.name
}

output "task_definition_arn" {
  description = "ARN of the task definition revision this apply produced."
  value       = aws_ecs_task_definition.this.arn
}

output "task_role_arn" {
  description = "ARN of the task role, for granting the container access to further resources."
  value       = aws_iam_role.task.arn
}

output "execution_role_arn" {
  description = "ARN of the ECS execution role."
  value       = aws_iam_role.execution.arn
}

output "service_security_group_id" {
  description = "Security group attached to the tasks."
  value       = aws_security_group.service.id
}

output "alb_security_group_id" {
  description = "Security group attached to the load balancer. Add ingress rules here to admit more callers."
  value       = aws_security_group.alb.id
}

output "auth_header_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the MCP auth header value, or null when mcp_auth_header_value was not set."
  value       = local.manage_auth_secret ? aws_secretsmanager_secret.auth_header[0].arn : null
}

output "log_group_name" {
  description = "CloudWatch Logs group the tasks write to."
  value       = aws_cloudwatch_log_group.task.name
}
