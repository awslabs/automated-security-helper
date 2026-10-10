# Deploy ASH on AWS

The repository's `deploy/` directory has infrastructure as code for running ASH as a
service in your own AWS account: an MCP server for agents, a pull request gate, and a
sharded pipeline for large repositories. Each target comes as a CDK stack, with its
synthesized CloudFormation template committed, and as a Terraform module.

ASH publishes no container image, so every target builds the ASH image into an ECR
repository in your account as part of the deployment, with a CodeBuild project that
clones ASH from GitHub and rebuilds the image on a schedule.

## What `deploy/` provides {#targets}

| Target | What it deploys | CDK template | Terraform module |
|---|---|---|---|
| Image pipeline | ECR repository and scheduled CodeBuild image builds | `AshImagePipeline` | `ash-image-pipeline` |
| AgentCore | ASH's MCP server on Amazon Bedrock AgentCore Runtime | `AshAgentCore` | `agentcore` |
| Fargate | ASH's MCP server on ECS Fargate behind an internal Application Load Balancer | `AshFargate` | `fargate` |
| CodeCommit gate | A container Lambda function that scans a CodeCommit pull request and comments on it | `AshCodeCommitGate` | `codecommit-gate` |
| Distributed pipeline | A CodePipeline that splits one scan across CodeBuild shards and merges the results into one verdict | `AshDistributedPipeline` | `codepipeline-executor` |

- [`deploy/cdk`](https://github.com/awslabs/automated-security-helper/blob/main/deploy/cdk/README.md)
  is a CDK app in TypeScript. Its templates are in
  [`deploy/cdk/templates`](https://github.com/awslabs/automated-security-helper/tree/main/deploy/cdk/templates),
  and you can launch them from the CloudFormation console without running CDK. Each
  target template includes its own image build.
- [`deploy/terraform`](https://github.com/awslabs/automated-security-helper/blob/main/deploy/terraform/README.md)
  has one module per target. Every target module uses the image that the
  `ash-image-pipeline` module builds, and you start its first build yourself after
  `terraform apply`.
- [`deploy/cdk-constructs`](https://github.com/awslabs/automated-security-helper/blob/main/deploy/cdk-constructs/README.md)
  has `ASHScanStep`, a construct that adds an ASH scan to a CDK Pipelines pipeline. It is
  not published to npm or any other registry; you build it from the repository to use it.

[`deploy/README.md`](https://github.com/awslabs/automated-security-helper/blob/main/deploy/README.md)
lists the parameters the targets share and how the CDK and Terraform names map.

## Prerequisites {#prerequisites}

- An AWS account, and credentials that can create IAM roles, an ECR repository, a
  privileged CodeBuild project (it builds a container image), and the services of the
  target you choose.
- Outbound internet access for the image build. CodeBuild clones ASH from GitHub, pulls
  the Python base image from Amazon ECR Public and downloads the scanner tools.
- For a console launch, nothing else. To deploy from source, Node.js and npm for CDK, or
  Terraform with access to the Terraform registry for `terraform init`.

## Before you deploy {#before}

- `AshVersion`, the ASH tag the image is built from, defaults to `v3.7.0`. Some targets
  call options that v3.7.0 does not have: stateless MCP (`ash mcp --stateless-http`), and
  `ash merge` with the shard options for the distributed pipeline. With the default
  version, the Fargate MCP container exits at startup, the AgentCore server starts in
  stateful mode and logs a warning, and the distributed pipeline's merge step fails. Set
  `AshVersion` to a release that has these options; each target's README lists what it
  needs.
- The image is only as current as its last build. The build runs on the `RebuildSchedule`
  you set, and rebuilding the image does not update a running service on its own; each
  target's README says how to roll it out.
- Deleting a stack leaves the ECR repository and artifact buckets in place on purpose.

## Network defaults {#network}

The templates set these defaults. Each README explains how to change them.

- Fargate: the load balancer is internal, listens on HTTP port 80, and has no ingress
  rule until you set `McpIngressCidr`, which rejects `0.0.0.0/0`. With it empty, nothing
  can reach the endpoint. The tasks can send only TCP 443.
- AgentCore: the runtime uses AgentCore's `PUBLIC` network mode, and callers reach it
  through the IAM-authorized `InvokeAgentRuntime` API.
- Both MCP targets: the server checks a shared header only when you set
  `McpAuthHeaderName` and `McpAuthHeaderValue`. Both are empty by default, which leaves
  the network rules (and, on AgentCore, IAM) as the only control on who can call it.

## Target READMEs {#readmes}

Each module's README covers its inputs, outputs, verified behavior and known limitations:

- [`ash-image-pipeline`](https://github.com/awslabs/automated-security-helper/blob/main/deploy/terraform/modules/ash-image-pipeline/README.md)
- [`agentcore`](https://github.com/awslabs/automated-security-helper/blob/main/deploy/terraform/modules/agentcore/README.md)
- [`fargate`](https://github.com/awslabs/automated-security-helper/blob/main/deploy/terraform/modules/fargate/README.md)
- [`codecommit-gate`](https://github.com/awslabs/automated-security-helper/blob/main/deploy/terraform/modules/codecommit-gate/README.md)
- [`codepipeline-executor`](https://github.com/awslabs/automated-security-helper/blob/main/deploy/terraform/modules/codepipeline-executor/README.md)

For the CDK stacks, see [`deploy/cdk/README.md`](https://github.com/awslabs/automated-security-helper/blob/main/deploy/cdk/README.md).
To run ASH's MCP server yourself instead, see [Run the MCP server](mcp-server.md).
