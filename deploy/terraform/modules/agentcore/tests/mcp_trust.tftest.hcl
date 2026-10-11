# The AgentCore runtime tells ASH that the platform issues the session header.
#
# Why this file exists: ASH's MCP server, in stateless streamable-http mode, no longer
# treats a client-supplied Mcp-Session-Id as a session identity. The tools that need
# one (source delivery, the scan registry, profiles) refuse unless the operator states
# that a platform in front of ASH issues and authenticates that header, which is what
# Bedrock AgentCore Runtime does. ash-mcp-serve maps ASH_MCP_TRUST_UPSTREAM_SESSION_ID
# to `--trust-upstream-session-id` and defaults it to false, so this module has to set
# it, and only in stateless mode, where the flag is valid.
#
# The Host side: AgentCore cannot forward Host, so no allowlist can name it and the
# platform is what restricts what reaches the container. The module states that with
# ASH_MCP_TRUST_UPSTREAM_HOST_CHECK=true rather than leaning on the launcher's
# default, which can change; the launcher passes the flag only when the allowlist is
# empty. The run below fails when the variable is absent, not only when it is false.
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

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "000000000000"
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
}

variables {
  container_image_uri = "000000000000.dkr.ecr.us-east-1.amazonaws.com/ash:mcp-arm64"
}

run "stateless_runtime_trusts_the_platform_session_header" {
  command = plan

  assert {
    condition     = lookup(aws_bedrockagentcore_agent_runtime.this.environment_variables, "ASH_MCP_TRUST_UPSTREAM_SESSION_ID", "unset") == "true"
    error_message = "A stateless AgentCore runtime must set ASH_MCP_TRUST_UPSTREAM_SESSION_ID=true, or every session tool refuses; got ${lookup(aws_bedrockagentcore_agent_runtime.this.environment_variables, "ASH_MCP_TRUST_UPSTREAM_SESSION_ID", "unset")}."
  }
}

# Control: the flag is valid only with stateless streamable-http, so a stateful
# runtime must not ask for it.
run "stateful_runtime_does_not_trust_a_session_header" {
  command = plan

  variables {
    mcp_stateless_http = false
  }

  assert {
    condition     = lookup(aws_bedrockagentcore_agent_runtime.this.environment_variables, "ASH_MCP_TRUST_UPSTREAM_SESSION_ID", "false") == "false"
    error_message = "A stateful runtime asked ASH to trust the session header, which ASH refuses outside stateless mode."
  }
}

# AgentCore cannot forward Host, so the module states the upstream Host check itself.
run "runtime_keeps_the_upstream_host_check" {
  command = plan

  assert {
    condition     = lookup(aws_bedrockagentcore_agent_runtime.this.environment_variables, "ASH_MCP_TRUST_UPSTREAM_HOST_CHECK", "unset") == "true"
    error_message = "The AgentCore runtime must set ASH_MCP_TRUST_UPSTREAM_HOST_CHECK=true; left to the launcher's default, a change of that default leaves ASH refusing to start on 0.0.0.0. Got ${lookup(aws_bedrockagentcore_agent_runtime.this.environment_variables, "ASH_MCP_TRUST_UPSTREAM_HOST_CHECK", "unset")}."
  }
}
