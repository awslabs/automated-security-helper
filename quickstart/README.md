# ASH quick start

This directory has no quick start of its own. The AWS Cloud9 template it described,
`c9template.yaml`, is not part of ASH v3, and AWS Cloud9 is not available to new
customers.

To start with ASH:

- On your machine, follow
  [Run your first scan](https://awslabs.github.io/automated-security-helper/latest/getting-started/local/).
  It installs ASH and its scanner tools, scans a small project, and walks through the
  results.
- In your AWS account, use [`deploy/`](../deploy/README.md). It has CDK and Terraform
  for running ASH on AWS: ASH's MCP server for agents, a gate for CodeCommit pull
  requests, and a pipeline that splits one scan across CodeBuild shards.
  [Deploy ASH on AWS](https://awslabs.github.io/automated-security-helper/latest/how-to/deploy-on-aws/)
  describes each target.
