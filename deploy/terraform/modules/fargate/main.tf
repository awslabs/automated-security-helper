#
# ASH MCP server on ECS Fargate behind an Application Load Balancer.
#
# The load balancer is what makes this target different from the others. Two
# consequences drive most of the configuration below:
#
#   1. The Host header a request arrives with is the name the *client* dialed,
#      which is the load balancer's, not the container's. The MCP SDK's
#      DNS-rebinding protection compares against that header, so the load
#      balancer's DNS name is passed through ASH's --allowed-host flag rather
#      than turning the protection off.
#   2. Consecutive requests from one client may land on different tasks, so
#      stateless MCP is the default. A stateful server on the task that did not
#      issue the session answers 404 "Session not found".
#

data "aws_region" "current" {}

locals {
  manage_auth_secret = nonsensitive(var.mcp_auth_header_value != null)
  use_auth_header    = var.mcp_auth_header_name != null
  use_base_config    = var.base_config_ssm_parameter_name != null

  use_tls       = var.certificate_arn != null
  listener_port = coalesce(var.listener_port, local.use_tls ? 443 : 80)

  create_cluster = var.cluster_arn == null
  cluster_arn    = local.create_cluster ? aws_ecs_cluster.this[0].arn : var.cluster_arn

  # Both forms are included because a client may or may not append the port to
  # the Host header depending on whether the listener port is the scheme default.
  # Listing both costs nothing and avoids a rejection that presents as an opaque
  # 400 from deep inside the MCP SDK.
  load_balancer_hosts = distinct([
    aws_lb.this.dns_name,
    "${aws_lb.this.dns_name}:${local.listener_port}",
  ])

  allowed_hosts = distinct(concat(local.load_balancer_hosts, var.mcp_allowed_host))

  mcp_environment = {
    ASH_MCP_TRANSPORT             = "streamable-http"
    ASH_MCP_HOST                  = "0.0.0.0"
    ASH_MCP_PORT                  = tostring(var.container_port)
    ASH_MCP_MOUNT_PATH            = var.mcp_mount_path
    ASH_MCP_STATELESS_HTTP        = var.mcp_stateless_http ? "true" : "false"
    ASH_MCP_ALLOWED_HOSTS         = join(",", local.allowed_hosts)
    ASH_MCP_AUTH_HEADER_NAME      = local.use_auth_header ? var.mcp_auth_header_name : ""
    ASH_OFFLINE                   = var.ash_offline_mode ? "YES" : "NO"
    ASH_BASE_CONFIG_SSM_PARAMETER = local.use_base_config ? var.base_config_ssm_parameter_name : ""
    ASH_MCP_AUTH_SECRET_ARN       = local.manage_auth_secret ? aws_secretsmanager_secret.auth_header[0].arn : ""
  }

  # Caller values first so the module's own keys win on collision.
  environment_variables = merge(var.additional_environment_variables, local.mcp_environment)

  container_environment = [
    for key in sort(keys(local.environment_variables)) : {
      name  = key
      value = local.environment_variables[key]
    }
  ]
}

#
# MCP auth header value
#

resource "aws_secretsmanager_secret" "auth_header" {
  count = local.manage_auth_secret ? 1 : 0

  name        = "${var.name_prefix}-mcp-auth-header"
  description = "Expected value of the static MCP auth header for the ASH Fargate service."

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "auth_header" {
  count = local.manage_auth_secret ? 1 : 0

  secret_id     = aws_secretsmanager_secret.auth_header[0].id
  secret_string = var.mcp_auth_header_value
}

#
# Networking
#

resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb"
  description = "Ingress to the ASH MCP load balancer."
  vpc_id      = var.vpc_id

  tags = merge(var.tags, { Name = "${var.name_prefix}-alb" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "alb_from_cidr" {
  for_each = toset(var.ingress_cidr_blocks)

  security_group_id = aws_security_group.alb.id
  description       = "MCP clients from ${each.value}."
  cidr_ipv4         = each.value
  from_port         = local.listener_port
  to_port           = local.listener_port
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_from_sg" {
  for_each = toset(var.ingress_security_group_ids)

  security_group_id            = aws_security_group.alb.id
  description                  = "MCP clients from ${each.value}."
  referenced_security_group_id = each.value
  from_port                    = local.listener_port
  to_port                      = local.listener_port
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_service" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Forward to the ASH MCP tasks."
  referenced_security_group_id = aws_security_group.service.id
  from_port                    = var.container_port
  to_port                      = var.container_port
  ip_protocol                  = "tcp"
}

resource "aws_security_group" "service" {
  name        = "${var.name_prefix}-service"
  description = "ASH MCP Fargate tasks."
  vpc_id      = var.vpc_id

  tags = merge(var.tags, { Name = "${var.name_prefix}-service" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "service_from_alb" {
  security_group_id            = aws_security_group.service.id
  description                  = "MCP traffic from the load balancer."
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = var.container_port
  to_port                      = var.container_port
  ip_protocol                  = "tcp"
}

# The task pulls from ECR and writes to CloudWatch Logs, SSM, and Secrets
# Manager. Narrowing this to prefix lists or endpoint security groups is a
# reasonable hardening step, but it depends on whether the VPC uses NAT or
# interface endpoints, which this module does not know.
resource "aws_vpc_security_group_egress_rule" "service_all" {
  security_group_id = aws_security_group.service.id
  description       = "Outbound to ECR, CloudWatch Logs, SSM, and Secrets Manager."
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

#
# Load balancer
#

resource "aws_lb" "this" {
  name               = "${var.name_prefix}-alb"
  internal           = var.internal
  load_balancer_type = "application"
  subnets            = var.alb_subnet_ids
  security_groups    = [aws_security_group.alb.id]

  enable_deletion_protection = var.enable_deletion_protection
  drop_invalid_header_fields = true

  tags = var.tags
}

resource "aws_lb_target_group" "this" {
  name        = "${var.name_prefix}-tg"
  port        = var.container_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  # Streamable HTTP responses can be long-lived, so the deregistration delay is
  # kept short but the idle handling is left to the listener.
  deregistration_delay = 30

  health_check {
    enabled  = true
    path     = var.mcp_mount_path
    protocol = "HTTP"
    interval = var.health_check_interval_seconds

    # ASH's MCP server has no health endpoint. A GET to the mount path is not a
    # valid MCP request, and an auth-guarded server rejects the unauthenticated
    # probe outright, so a broad matcher is what distinguishes "process is
    # serving HTTP" from "process is gone". See the health_check_matcher variable.
    matcher             = var.health_check_matcher
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
  }

  tags = var.tags
}

resource "aws_lb_listener" "this" {
  load_balancer_arn = aws_lb.this.arn
  port              = local.listener_port
  protocol          = local.use_tls ? "HTTPS" : "HTTP"
  ssl_policy        = local.use_tls ? var.ssl_policy : null
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }

  tags = var.tags
}

#
# Cluster
#

resource "aws_ecs_cluster" "this" {
  count = local.create_cluster ? 1 : 0

  name = var.name_prefix

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = var.tags
}

#
# Task roles
#
# Two roles, because they are used at different times by different principals.
# The execution role is used by the ECS agent to pull the image and create log
# streams before the container exists. The task role is what the container's own
# process uses, and it is the one that reads the config parameter and the secret,
# because the entrypoint does that itself rather than relying on ECS secret
# injection. One code path across all four targets is worth more here than
# saving a role.
#

data "aws_iam_policy_document" "task_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_cloudwatch_log_group" "task" {
  name              = "/aws/ecs/${var.name_prefix}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

resource "aws_iam_role" "execution" {
  name               = "${var.name_prefix}-execution"
  description        = "Role the ECS agent uses to pull the ASH image and create log streams."
  assume_role_policy = data.aws_iam_policy_document.task_assume_role.json

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "task" {
  name               = "${var.name_prefix}-task"
  description        = "Role the ASH container process uses to read its configuration and auth secret."
  assume_role_policy = data.aws_iam_policy_document.task_assume_role.json

  tags = var.tags
}

data "aws_partition" "current" {}

data "aws_iam_policy_document" "task" {
  # Always present so the policy document is never empty, which the provider
  # rejects. Writing its own log stream is something the container process does
  # in addition to what the execution role does for it.
  statement {
    sid    = "WriteTaskLogs"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["${aws_cloudwatch_log_group.task.arn}:*"]
  }

  dynamic "statement" {
    for_each = local.use_base_config ? [1] : []

    content {
      sid       = "ReadBaseConfig"
      effect    = "Allow"
      actions   = ["ssm:GetParameter"]
      resources = [var.base_config_ssm_parameter_arn]
    }
  }

  dynamic "statement" {
    for_each = local.manage_auth_secret ? [1] : []

    content {
      sid       = "ReadAuthHeaderSecret"
      effect    = "Allow"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [aws_secretsmanager_secret.auth_header[0].arn]
    }
  }

  dynamic "statement" {
    for_each = var.enable_execute_command ? [1] : []

    content {
      sid    = "EcsExec"
      effect = "Allow"

      actions = [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel",
      ]

      resources = ["*"]
    }
  }
}

resource "aws_iam_role_policy" "task" {
  name   = "${var.name_prefix}-task"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task.json
}

#
# Task definition and service
#

resource "aws_ecs_task_definition" "this" {
  family                   = var.name_prefix
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  dynamic "ephemeral_storage" {
    for_each = var.ephemeral_storage_gib == null ? [] : [1]

    content {
      size_in_gib = var.ephemeral_storage_gib
    }
  }

  container_definitions = jsonencode([
    {
      name      = "ash-mcp"
      image     = var.container_image_uri
      essential = true
      command   = var.container_command

      portMappings = [
        {
          containerPort = var.container_port
          protocol      = "tcp"
        }
      ]

      environment = local.container_environment

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.task.name
          "awslogs-region"        = data.aws_region.current.region
          "awslogs-stream-prefix" = "ash-mcp"
        }
      }
    }
  ])

  tags = var.tags
}

resource "aws_ecs_service" "this" {
  name            = var.name_prefix
  cluster         = local.cluster_arn
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  enable_execute_command            = var.enable_execute_command
  health_check_grace_period_seconds = var.health_check_grace_period_seconds

  network_configuration {
    subnets          = var.service_subnet_ids
    security_groups  = [aws_security_group.service.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = "ash-mcp"
    container_port   = var.container_port
  }

  tags = var.tags

  # The listener has to exist before the service registers targets, otherwise
  # the first registration races the listener's creation.
  depends_on = [
    aws_lb_listener.this,
    aws_iam_role_policy.task,
    aws_iam_role_policy_attachment.execution,
  ]
}
