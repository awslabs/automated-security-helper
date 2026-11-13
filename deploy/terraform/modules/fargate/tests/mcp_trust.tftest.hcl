# The Fargate service relies on its Host allowlist and trusts nothing upstream.
#
# Why this file exists: ash-mcp-serve defaults ASH_MCP_TRUST_UPSTREAM_HOST_CHECK to
# true, which is AgentCore's need: it emits `--trust-upstream-host-check` whenever the
# Host allowlist is empty, and ASH then serves any Host. Behind a load balancer that
# is the wrong default. This module always passes the load balancer's DNS name as the
# allowlist, so it must also set the opt-out to false explicitly: if the allowlist were
# ever empty, ASH has to refuse to start on 0.0.0.0 rather than accept every Host. And
# a load balancer does not issue Mcp-Session-Id, so the module must never ask ASH to
# trust that header.
#
# Run with `terraform test` from this module directory after `terraform init
# -backend=false`. Every provider call is mocked.

mock_provider "aws" {
  override_during = plan

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "us-east-1"
      name   = "us-east-1"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_resource "aws_lb" {
    defaults = {
      arn      = "arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/ash-mcp-alb/0123456789abcdef"
      dns_name = "internal-ash-mcp-alb-123.us-east-1.elb.amazonaws.com"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:us-east-1:000000000000:log-group:/aws/ecs/ash-mcp"
    }
  }
}

variables {
  container_image_uri = "000000000000.dkr.ecr.us-east-1.amazonaws.com/ash:mcp-amd64"
  vpc_id              = "vpc-0123456789abcdef0"
  service_subnet_ids  = ["subnet-0123456789abcdef0"]
  alb_subnet_ids      = ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]
}

run "the_service_never_inherits_the_upstream_host_check" {
  command = plan

  assert {
    condition     = lookup({ for entry in jsondecode(aws_ecs_task_definition.this.container_definitions)[0].environment : entry.name => entry.value }, "ASH_MCP_TRUST_UPSTREAM_HOST_CHECK", "unset") == "false"
    error_message = "The Fargate task must set ASH_MCP_TRUST_UPSTREAM_HOST_CHECK=false; unset, the launcher's AgentCore default lets ASH serve any Host whenever the allowlist is empty."
  }
}

# Control: the allowlist is the load balancer's own name, which the module adds.
run "the_allowlist_names_the_load_balancer" {
  command = plan

  assert {
    condition     = contains(split(",", lookup({ for entry in jsondecode(aws_ecs_task_definition.this.container_definitions)[0].environment : entry.name => entry.value }, "ASH_MCP_ALLOWED_HOSTS", "")), "internal-ash-mcp-alb-123.us-east-1.elb.amazonaws.com")
    error_message = "ASH_MCP_ALLOWED_HOSTS does not name the load balancer's DNS name."
  }
}

# Control: a load balancer issues no session header for ASH to trust.
run "the_service_does_not_trust_a_session_header" {
  command = plan

  assert {
    condition     = lookup({ for entry in jsondecode(aws_ecs_task_definition.this.container_definitions)[0].environment : entry.name => entry.value }, "ASH_MCP_TRUST_UPSTREAM_SESSION_ID", "false") == "false"
    error_message = "The Fargate task asked ASH to trust Mcp-Session-Id, which nothing in front of it issues."
  }
}
