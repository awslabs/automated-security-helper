# Deploying ASH

Infrastructure as code for running ASH as a service in your own AWS account. Four
deployment targets, each available as a CDK stack with a committed CloudFormation
template and as a Terraform module. The two implementations take mostly the same
parameters, under the same names in snake case, and produce the same shape, so the
choice between them is a question of which tool your organization already runs, not
which one gets you more.

## Why this directory exists

ASH is a CLI first, and running it in CI is a matter of installing it and calling it.
These stacks are for the cases where a CLI invocation is not enough:

- A team wants ASH available to agents over MCP, without every agent installing it.
- A team wants one MCP endpoint inside its own VPC that several agents share.
- A team wants every pull request scanned, with the result posted on the pull request
  and, optionally, an approval vote that blocks the merge once an approval rule
  requires it. That needs something listening to the repository rather than
  something a developer runs.
- A team has a monorepo large enough that one scan does not finish inside a build
  timeout, and needs the work split across parallel executors.

Each of those is a different piece of infrastructure, so each is its own target rather
than one stack with switches.

## Launch targets

| Target | What it gives you | Compute | Entry point | Target-specific parameters |
| --- | --- | --- | --- | --- |
| AgentCore | ASH's MCP server, reachable by agents | Bedrock AgentCore runtime | MCP over streamable HTTP | `McpStatelessHttp`, `McpAuthHeaderName`, `McpAuthHeaderValue`, `McpMountPath`, `McpAllowedHost` |
| ECS Fargate | ASH's MCP server, reachable from inside your VPC | ECS service on Fargate behind an internal Application Load Balancer | MCP over streamable HTTP through the load balancer | `McpStatelessHttp`, `McpAuthHeaderName`, `McpAuthHeaderValue`, `McpMountPath`, `McpAllowedHost`, `McpIngressCidr` |
| Lambda CodeCommit gate | A scan when a pull request is opened or its source branch is updated, posted as a comment on the pull request | Lambda function | EventBridge rule on CodeCommit pull request events | `CodeCommitRepositoryArn`, `ApprovalGate`, `ChangedFilesOnly`, `MinSeverity`, `VpcId`, `VpcSubnetIds`, `ScanEgressCidr` |
| CodePipeline distributed executor | One logical scan split across parallel shards, results merged | CodeBuild projects in a pipeline | Pipeline execution | `ShardCount` (in CDK, chosen when the template is synthesized; see below) |

Every target builds the ASH container image into your own ECR repository. None of
them pull a prebuilt image, because there is no public one to pull. See
[Trust and the container image](#trust-and-the-container-image).

## What deploying actually costs you

Building the image per deployment is the price of there being no public one, and it
has consequences worth knowing before the first `create-stack` rather than after:

- AgentCore, Fargate and the CodeCommit gate build the image during stack creation.
  The build is slow: minutes, and longer with `AshOfflineMode` enabled, which builds
  scanner rulesets and databases into the image. The distributed pipeline builds its
  image in the pipeline's first stage on its first run, and the `AshImagePipeline`
  stack builds only on its schedule or when you start the build project.
- Those three targets cannot create their workload until that build finishes, so the
  build gates stack creation rather than running alongside it. A stack that looks
  stuck early on is usually waiting on the build.
- `RebuildSchedule` patches the **repository**. Rolling a newly built image into an
  already-running workload is a further step, documented per target — a rebuild
  alone does not update a running service.
- Deleting a stack leaves the ECR repository, the buckets, the log groups and the
  stack's KMS key behind, on purpose. An image that took twenty minutes to build
  should not vanish because a rollback removed the stack that referenced it. Deleting them is a deliberate,
  separate action.

## Which tool, and where the detail lives

`cdk/` holds the CDK apps and the synthesized templates in `cdk/templates/`. You can
launch any of them straight from the CloudFormation console without running `cdk` at
all. The console uploads the template for you, so template size never comes up.
`terraform/` mirrors the same targets. The parameters listed in `terraform/README.md`
under "Variable contract" keep their names in snake case; others can differ, such as
`McpIngressCidr`, which is the `ingress_cidr_blocks` list on the fargate module.

Scripting the launch is where size does come up. CloudFormation caps an inline
`aws cloudformation create-stack --template-body` at 51,200 bytes. Only `AshAgentCore`
fits; `AshCodeCommitGate`, `AshImagePipeline`, `AshFargate` and
`AshDistributedPipeline` do not, and have to be uploaded to S3 and launched with
`aws cloudformation create-stack --template-url` instead, where the cap is 1 MB.
`cdk/README.md` lists which template needs which and gives both commands; run
`wc -c cdk/templates/*.template.json` for the current sizes. `AshDistributedPipeline`
is about three times the inline cap and will not be brought under it: it emits one
CodeBuild action per shard, which is the entire point of that target.

The canonical parameter names live in `cdk/lib/ash-config.ts` and are treated as a
contract: renaming one is a breaking change for adopters.

Per-target detail, the verified service contracts, and the explicit list of things
that were **not** verified without deploying are in `cdk/README.md` and
`terraform/README.md`. Read the limitations before deploying; several of them change
how a target should be configured.

## Shared parameters

The CDK parameter names are given here. Terraform uses the same names in snake
case, so `AshOfflineMode` is `ash_offline_mode` — with one spelling exception and
one structural one, both of which will cost you a failed plan if you guess:

- `CodeCommitRepositoryArn` is `codecommit_repository_arn`, not
  `code_commit_repository_arn`. CodeCommit is one word in AWS's own naming, so
  splitting it mechanically produces a variable that does not exist.
- Three parameters are not accepted by the four target modules at all. See
  [Where the Terraform surface differs](#where-the-terraform-surface-differs).

<!-- doctest: options of=cloudformation:deploy/cdk/templates -->
| Parameter | Applies to | Meaning |
| --- | --- | --- |
| `AshOfflineMode` | all | Build the image in offline mode (`YES` or `NO`). Scanner vulnerability databases and rulesets are built into the image, and ASH runs offline, so a scan does not download them. Trades image size and rebuild frequency for a scan that does not depend on reaching those sources. It does not block network egress; each target's network configuration decides that. |
| `AshBaseConfigYaml` | each target template in CDK; the `ash-image-pipeline` module in Terraform | An ASH config file's contents, as a string, so the deployed configuration is part of the stack rather than something baked into the image. ASH uses one config file per scan and never merges two. On AgentCore and Fargate, a scan uses the scanned directory's own config file, or the file the client names, when there is one, and this one only when there is none. The CDK distributed pipeline uses this one and never reads the scanned repository's own config file; with this parameter empty, it scans with ASH's built-in defaults. The CDK CodeCommit gate does not apply it. The Terraform READMEs describe the Terraform modules. |
| `AshVersion` | image build | The ASH version the image is built from: a tag, a branch, or a full commit SHA. Pin it, so a rebuild reproduces the same scanner set rather than silently moving to whatever is newest. The default is the ASH release these files belong to. The targets need ASH options that no release up to 3.7.1 has; see [Which `AshVersion` to use](#which-ashversion-to-use). |
| `RebuildSchedule` | image build | How often the image is rebuilt. An image built once and never rebuilt ages, and the scanners inside it age with it — the tradeoff called out in the trust note below. Offline deployments need this most, because their vulnerability databases are only as fresh as the last build. |
| `McpStatelessHttp` | MCP-serving targets | Whether the MCP server runs stateless. Defaults to true, and that default is not cosmetic. See [Why `McpStatelessHttp` defaults to true](#why-mcpstatelesshttp-defaults-to-true). |
| `McpAuthHeaderName` | MCP-serving targets | The header the MCP server requires on every request. Names the header only; the value is separate so the two can be rotated independently. |
| `McpAuthHeaderValue` | MCP-serving targets | The expected value of that header. It is a bearer credential. The parameter is `NoEcho`, the stack stores the value in Secrets Manager, and the container receives only the secret's ARN. |
| `McpMountPath` | MCP-serving targets | The path the MCP server listens on. Leave it at `/mcp` on AgentCore, which routes nothing else; change it only on Fargate, when something else already occupies the default path. |
| `McpAllowedHost` | MCP-serving targets | Comma-separated `Host` values the server accepts, which keeps DNS-rebinding protection on. Empty accepts any `Host` on AgentCore and the load balancer's DNS name on Fargate. It needs an ASH whose `ash mcp` has `--allowed-host`, so set `AshVersion` to a tag, branch, or commit that has it. |
| `CodeCommitRepositoryArn` | Lambda CodeCommit gate | The repository the gate watches. |

`ShardCount`, for the CodePipeline distributed executor, is how many parallel shards
one logical scan is split into. In CDK it is not a stack parameter but the
`shardCount` context value, read when the template is synthesized (4 in
`cdk.json`); Terraform takes it as `shard_count`. Shards split the set of scanners,
not the files, so a count above the number of enabled scanners only adds empty
shards, and each shard pays image pull and scanner initialization before it scans
anything.

## Which `AshVersion` to use

The CDK default and the Terraform examples name the ASH release these files belong
to, and every release moves them to itself. A checkout of `main` between releases
still names the previous release.

The targets call ASH with options that no release up to 3.7.1 has:
`ash mcp --stateless-http` and `--allowed-host`, the shard options of `ash scan`,
`ash scan --fail-on-incomplete-scanners`, and `ash merge`. Set `AshVersion`
(`ash_version` in Terraform) to an ASH that has all of them, for example the full
commit SHA you deploy from. With one that lacks them, a target can fail to start, or
its `ash scan` ignores an option it does not know.

## Where the Terraform surface differs

`AshBaseConfigYaml`, `AshVersion`, and `RebuildSchedule` take effect where the
image is built, so in Terraform they are variables on the `ash-image-pipeline`
module and the four target modules do not accept them. Passing
`ash_base_config_yaml` to the fargate or agentcore module will not plan.

The targets consume the base config indirectly, through
`base_config_ssm_parameter_name` and `base_config_ssm_parameter_arn`. The value is
a whole `.ash.yaml` document, so it is stored in an SSM parameter at the
image-build layer, and the container entrypoint writes it to `.ash/.ash.yaml` under
`/tmp` at startup and points `ASH_CONFIG` at it. It travels that way because
AgentCore Runtime exposes only a flat environment map, which a real configuration
file does not fit into.

The full per-module variable matrix is in `terraform/README.md` under "Variable
contract". Where this table and that one disagree, that one is authoritative for
Terraform.

## Why `McpStatelessHttp` defaults to true

Measured against ASH's MCP server: given a session id the server never issued, the
server in stateful mode answers `404 Session not found`, while in stateless mode it
answers `200`. AgentCore returns a new `Mcp-Session-Id` on every response, and its
protocol contract tells clients to send the returned id on the next request. A
stateful server honors only the id it issued at `initialize`, so a client that follows
that guidance is refused on its third call. On Fargate, with more than one task behind
the load balancer, consecutive requests in one session can reach different tasks, and
a stateful task that did not issue the session answers 404 the same way. Stateless is
therefore the default on both targets rather than something an adopter has to
discover from a 404.

Both targets need an ASH whose `ash mcp` has `--stateless-http`, which no release up
to 3.7.1 has. What differs between the targets is what happens when the ASH in the
image lacks it: AgentCore starts a stateful server and logs a warning, and Fargate's
container refuses to start. A deployment where every client completes
ASH's own session handshake and keeps the id it issued can run stateful; stateless
mode gives up per-session server-side state.

## Trust and the container image

ASH publishes no container image to any public registry, and will not. Every stack
here builds the image into your own ECR repository, which is why each of them
provisions a build step you might otherwise expect to be a `docker pull`.

That is a deliberate position, not an omission. Building and hosting your own image,
and the rebuild cadence that obliges you to own, are covered in
[Run ASH in a container](https://awslabs.github.io/automated-security-helper/how-to/run-in-a-container/#own-image).
Read it before deploying any of these targets, because `RebuildSchedule` is the
parameter that decides whether you actually hold up your end of it.

## Committed generated artifacts

Two things in this directory are generated and committed, which is a deliberate
tradeoff: an adopter gets a one-click CloudFormation launch with no build step, at the
cost of a file that can go stale against the code that produces it.

| Artifact | Generated from | Regenerate with |
| --- | --- | --- |
| `cdk/templates/<StackName>.template.json` | the CDK app in `cdk/` | `cd deploy/cdk && npm ci && ./scripts/synth-templates.sh` |
| `cdk-constructs/buildspec*.yml` | the construct in `cdk-constructs/` | `cd deploy/cdk-constructs && npm ci && npm run generate:buildspec` |

One generator run emits several buildspecs, not one: the top-level spec, the
per-shard spec, and the merge spec that owns the pass/fail verdict for a sharded
scan. All of them are checked, so drift confined to a sibling file is caught
rather than passing because the top-level spec happened not to move.

Neither is edited by hand. `.github/workflows/ash-iac-drift.yml` regenerates both on
every pull request and fails if the result differs from what is committed, so a stale
artifact is a red build rather than something an adopter discovers at launch time.

The gate also runs `terraform fmt -check -recursive`, initializes and validates every
Terraform module and example, and requires that the CDK app register cdk-nag as a CDK
Aspect so that every stack is scanned. Suppress a cdk-nag finding next to the resource,
with a reason:

```js
NagSuppressions.addResourceSuppressions(scope, [
  {
    id: 'AwsSolutions-S1',
    reason: 'Access logs are centralized in a dedicated logging account bucket.',
  },
]);
```

A suppressed rule is reported as `Suppressed` alongside its reason and does not fail the
build. cdk-nag is pinned at **2.38.2**, where the pack is an Aspect — registered with
`Aspects.of(app).add(new AwsSolutionsChecks(...))`, not with
`Validations.of(app).addPlugins(...)`, which is the cdk-nag 3.x API and rejects an
Aspect. See `deploy/cdk/README.md` for the version boundary and what has to change if
the pin moves.

On 2.x a suppression is serialized into the emitted template as
`Metadata.cdk_nag.rules_to_suppress` on the resource it applies to, so the committed
templates do carry a record of every one. The reason string travels with it, which
means an incorrect reason is public — write it for a reviewer, not to silence output.

## Constraints and assumptions

- **The stacks synthesize offline.** CI runs `cdk synth --no-lookups` with no
  AWS credentials, so no stack may depend on a context lookup unless its resolved
  `cdk.context.json` is committed. A stack that needs to read an existing VPC or AMI
  at synthesis time cannot be validated by the drift gate.
- **The templates are environment-agnostic.** They take account and region from
  wherever they are launched. Nothing here embeds an account id.
- **`terraform init` reaches the Terraform registry** to fetch providers. That is a
  public artifact download, not an AWS API call, and it needs no credentials — but it
  does mean the modules cannot be validated on a host with no network at all.
- **The CDK CLI and `aws-cdk-lib` must stay compatible.** A CLI older than the
  cloud-assembly schema the library emits fails synth with a schema version mismatch
  rather than anything resembling a template problem.

## Known limitations

- A committed template is only as current as the last time someone ran the
  regeneration command. The CI gate is what makes that reliable; if the gate is
  disabled, the templates rot silently and nothing reports it.
- `AshOfflineMode` and `RebuildSchedule` interact. Offline scanning is only as good as
  the vulnerability data compiled into the image, so a long rebuild interval on an
  offline deployment produces scans that pass because the data is old rather than
  because the code is clean.
- `McpAuthHeaderValue` is a single shared credential. It authenticates the caller as
  "someone who holds the header value" and nothing more, so it does not distinguish
  between agents and it does not expire on its own.
- The CI gate's `terraform validate` does not evaluate variable validation rules.
  A `validation` block whose condition is wrong — including a cross-variable rule
  that should reject its input — passes `validate` cleanly. So `validate` passing
  means the configuration parses and its references resolve; it says nothing about
  whether the input contracts work.

  That gap is covered separately, by `terraform/tests/validate-inputs.sh`, which
  the gate runs after the per-module init. It works without credentials because
  Terraform evaluates input variable validation before it initializes the
  provider: a plan carrying a deliberately invalid value fails on the rule's own
  `error_message` and never reaches AWS. Measured with every `AWS_*` variable
  unset and `AWS_EC2_METADATA_DISABLED=true` — the invalid value produces the
  rule's message, and the same plan with valid values fails later, on
  `No valid credential sources found`, with no validation message at all. That
  second direction is what distinguishes a rule that ran and passed from one that
  was never reached.
