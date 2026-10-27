# ASH quick start

There is no Cloud9 quick start. The `c9template.yaml` CloudFormation template, which created an AWS Cloud9 environment with an earlier ASH preinstalled, was removed in the ASH v3 release, and AWS Cloud9 is not available to new customers.

To start using ASH instead:

- On your own machine, follow the [quick start guide](https://awslabs.github.io/automated-security-helper/docs/quick-start-guide/). It installs ASH with `uvx`, `pipx`, or `pip` and runs a first scan.
- In your AWS account, use [`deploy/`](../deploy/README.md). It has CDK and Terraform for running ASH on AWS compute: scans on a schedule, a scan on every push to a CodeCommit repository, ASH's MCP server for agents, or one scan split across parallel CodeBuild shards.
