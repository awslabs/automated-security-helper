# Example: ASH over MCP on AgentCore Runtime

Builds an arm64 ASH image and runs it as a Bedrock AgentCore Runtime speaking
MCP.

Before you apply, change `ash_version` in `main.tf`. The example pins `v3.6.0`, whose
`ash mcp` has no `--stateless-http` option, and the image's launcher always passes
it or `--no-stateless-http`, so the container exits at startup. Set it to a tag or
commit whose ASH has `ash mcp --stateless-http`; v3.7.1 and earlier do not.

## Run it

<!-- doctest: illustrative reason="needs Terraform, network access and AWS credentials" -->
```console
terraform init
terraform plan
terraform apply
```

Then run the first image build, which the runtime cannot start without:

<!-- doctest: illustrative reason="needs an applied Terraform state" -->
```console
terraform output -raw run_the_first_build
```

Run the command it prints, wait for the build to succeed, then invoke the
runtime with `InvokeAgentRuntime` using the `agent_runtime_arn` output.

## Two things this example gets right on purpose

**arm64.** `target_architecture = "arm64"` on the image module. AgentCore's
container contract requires an arm64 container; an x86_64 image fails to start
with no useful signal at the Terraform layer.

**Stateless MCP.** `mcp_stateless_http = true`. AgentCore injects its own
`Mcp-Session-Id` header on every request, including the first. A stateful server
rejects a session id it never issued with 404 "Session not found"; a stateless
one returns 200.
