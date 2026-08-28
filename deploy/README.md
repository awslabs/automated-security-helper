# Deploying ASH on AWS

Infrastructure-as-code for running ASH as a service rather than as a local CLI.

- [`cdk/`](cdk) — AWS CDK (TypeScript) apps plus the synthesized CloudFormation
  templates in [`cdk/templates/`](cdk/templates). Launch a template from the
  CloudFormation console; you do not need to run `cdk`.
- `terraform/` — a Terraform mirror of the same targets, using the same parameter
  names.

Both implementations share one parameter surface so that moving between targets, or
between CDK and Terraform, does not mean relearning the options. The canonical
names live in [`cdk/lib/ash-config.ts`](cdk/lib/ash-config.ts) and are treated as a
contract; renaming one is a breaking change for adopters.

## Read this before anything else

**ASH publishes no container image to any public registry.** That is a settled
licensing decision, not a gap. So none of these templates can point at a prebuilt
public image, and every one of them **builds ASH into your own ECR repository as
part of deployment**.

The consequences are worth knowing up front:

- First deployment includes a container build. It is slow — minutes, and longer
  with `AshOfflineMode=YES`, which vendors scanner rulesets into the image.
- Two of the targets cannot create their workload until that build finishes, so the
  build gates stack creation rather than running alongside it.
- A scheduled rebuild (default `rate(1 day)`) keeps the image patched. It patches
  the *repository*; rolling a new image into an already-running workload takes one
  more step, documented per target.
- Deleting a stack leaves the ECR repository and the buckets behind, on purpose.
  An image that took twenty minutes to build should not disappear on a rollback.

## The four targets

| Target | Use it when |
| --- | --- |
| Bedrock AgentCore Runtime | You want ASH reachable as an MCP tool server, invoked through `bedrock-agentcore:InvokeAgentRuntime` with IAM authorization and no network of your own to manage. ARM64. |
| ECS Fargate | You want a long-lived MCP endpoint inside your VPC, behind a load balancer you control. |
| CodeCommit pull-request gate | You want a scan on every pull request, reported as a comment and optionally as an approval vote. Bounded by Lambda's 15-minute ceiling. |
| CodePipeline sharded executor | You want a whole-repository scan split across parallel jobs, with one merged verdict. Use this when the pull-request gate runs out of time. |

Full details, verified service contracts, known limitations and the list of things
that were **not** verified without deploying are in
[`cdk/README.md`](cdk/README.md). Read the limitations section before you deploy;
several of them will change how you configure a target.
