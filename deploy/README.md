# Deploying ASH

Infrastructure as code for running ASH as a service in your own AWS account. Four
deployment targets, each available as a CDK stack with a committed CloudFormation
template and as a Terraform module. The two implementations take the same parameters
and produce the same shape, so the choice between them is a question of which tool
your organization already runs, not which one gets you more.

## Why this directory exists

ASH is a CLI first, and running it in CI is a matter of installing it and calling it.
These stacks are for the cases where a CLI invocation is not enough:

- A team wants ASH available to agents over MCP, without every agent installing it.
- A team wants scans to run on a schedule against many repositories, on compute that
  is not a shared CI runner.
- A team wants a repository to reject a push that introduces a finding, which needs
  something listening to the repository rather than something a developer runs.
- A team has a monorepo large enough that one scan does not finish inside a build
  timeout, and needs the work split across parallel executors.

Each of those is a different piece of infrastructure, so each is its own target rather
than one stack with switches.

## Launch targets

| Target | What it gives you | Compute | Entry point | Target-specific parameters |
| --- | --- | --- | --- | --- |
| AgentCore | ASH's MCP server, reachable by agents | Bedrock AgentCore runtime | MCP over streamable HTTP | `McpStatelessHttp`, `McpAuthHeaderName`, `McpAuthHeaderValue`, `McpMountPath`, `McpAllowedHost` |
| ECS Fargate | Scheduled and on-demand scans of one or more repositories | ECS task on Fargate | Task invocation | — |
| Lambda CodeCommit gate | A scan on every push, with the result reported back to the repository | Lambda function | CodeCommit trigger | `CodeCommitRepositoryArn` |
| CodePipeline distributed executor | One logical scan split across parallel shards, results merged | CodeBuild projects in a pipeline | Pipeline execution | `ShardCount` |

Every target builds the ASH container image into your own ECR repository as part of
deployment. None of them pull a prebuilt image, because there is no public one to
pull. See [Trust and the container image](#trust-and-the-container-image).

## Shared parameters

The CDK parameter names are given here. Terraform uses the same names in snake
case, so `AshOfflineMode` is `ash_offline_mode` — with one spelling exception and
one structural one, both of which will cost you a failed plan if you guess:

- `CodeCommitRepositoryArn` is `codecommit_repository_arn`, not
  `code_commit_repository_arn`. CodeCommit is one word in AWS's own naming, so
  splitting it mechanically produces a variable that does not exist.
- Three parameters are not accepted by the four target modules at all. See
  [Where the Terraform surface differs](#where-the-terraform-surface-differs).

| Parameter | Applies to | Meaning |
| --- | --- | --- |
| `AshOfflineMode` | all | Run ASH with no network egress at scan time. Scanner vulnerability databases and rulesets are baked into the image at build time instead of fetched per scan. Trades image size and rebuild frequency for a scan that cannot fail on a network problem and cannot reach out from inside your account. |
| `AshBaseConfigYaml` | image build | The contents of the `.ash.yaml` the deployment scans with, as a string, so the deployed configuration is part of the stack rather than something baked into the image. A repository's own `.ash.yaml` still applies on top of it. |
| `AshVersion` | image build | The ASH version the image is built from. Pin it, so a rebuild reproduces the same scanner set rather than silently moving to whatever is newest. |
| `RebuildSchedule` | image build | How often the image is rebuilt. An image built once and never rebuilt ages, and the scanners inside it age with it — the tradeoff called out in the trust note below. Offline deployments need this most, because their vulnerability databases are only as fresh as the last build. |
| `McpStatelessHttp` | MCP-serving targets | Whether the MCP server runs stateless. Defaults to true on AgentCore, and that default is not cosmetic — see [Why `McpStatelessHttp` defaults to true on AgentCore](#why-mcpstatelesshttp-defaults-to-true-on-agentcore). |
| `McpAuthHeaderName` | MCP-serving targets | The header the MCP server requires on every request. Names the header only; the value is separate so the two can be rotated independently. |
| `McpAuthHeaderValue` | MCP-serving targets | The expected value of that header. Supply it from a secret rather than a literal — it is a bearer credential, and a stack parameter is visible to anyone who can describe the stack. |
| `McpMountPath` | MCP-serving targets | The path the MCP server is mounted at. Worth setting when something else already occupies the default path on the same host. |
| `McpAllowedHost` | MCP-serving targets | The `Host` value the server accepts, which is what stops a request that arrives with someone else's `Host` header from being served. |
| `ShardCount` | CodePipeline distributed executor | How many parallel shards one logical scan is split into. Higher is faster up to the point where per-shard startup dominates; a shard still pays image pull and scanner initialization before it scans anything. |
| `CodeCommitRepositoryArn` | Lambda CodeCommit gate | The repository the gate watches. |

## Where the Terraform surface differs

`AshBaseConfigYaml`, `AshVersion`, and `RebuildSchedule` take effect where the
image is built, so in Terraform they are variables on the `ash-image-pipeline`
module and the four target modules do not accept them. Passing
`ash_base_config_yaml` to the fargate or agentcore module will not plan.

The targets consume the base config indirectly, through
`base_config_ssm_parameter_name` and `base_config_ssm_parameter_arn`. The value is
a whole `.ash.yaml` document, so it is stored in an SSM parameter at the
image-build layer and the container entrypoint materializes it to
`.ash/.ash.yaml` at startup. It travels that way because AgentCore Runtime
exposes only a flat environment map, which a real configuration file does not fit
into.

The full per-module variable matrix is in `terraform/README.md` under "Variable
contract". Where this table and that one disagree, that one is authoritative for
Terraform.

## Why `McpStatelessHttp` defaults to true on AgentCore

AgentCore injects its own `Mcp-Session-Id` header into requests it forwards. Measured
against ASH's MCP server: given a session id the server never issued, the server in
stateful mode answers `404 Session not found`, while in stateless mode it answers
`200`. Since AgentCore supplies an id ASH did not issue, stateful mode rejects
AgentCore's traffic. Stateless is therefore the default for that target rather than
something an adopter has to discover from a 404.

The default is target-specific on purpose. A deployment where clients complete ASH's
own session handshake does not need it, and stateless mode gives up per-session
server-side state.

## Trust and the container image

ASH publishes no container image to any public registry, and will not. Every stack
here builds the image into your own ECR repository, which is why each of them
provisions a build step you might otherwise expect to be a `docker pull`.

That is a deliberate position, not an omission, and the reasoning — along with the
rebuild cadence it obliges you to own — is set out in
[Building your own container image](../docs/content/docs/building-your-own-image.md)
([published copy](https://awslabs.github.io/automated-security-helper/docs/building-your-own-image/)).
Read it before deploying any of these targets, because `RebuildSchedule` is the
parameter that decides whether you actually hold up your end of it.

## Committed generated artifacts

Two things in this directory are generated and committed, which is a deliberate
tradeoff: an adopter gets a one-click CloudFormation launch with no build step, at the
cost of a file that can go stale against the code that produces it.

| Artifact | Generated from | Regenerate with |
| --- | --- | --- |
| `cdk/templates/<StackName>.template.json` | the CDK app in `cdk/` | `cd deploy/cdk && npm ci && rm -rf cdk.out && npx cdk synth --all --output cdk.out --no-lookups --quiet && find templates -type f -name '*.template.json' -delete && cp cdk.out/*.template.json templates/` |
| `cdk-constructs/buildspec*.yml` | the construct in `cdk-constructs/` | `cd deploy/cdk-constructs && npm ci && npm run generate:buildspec` |

One generator run emits several buildspecs, not one: the top-level spec, the
per-shard spec, and the merge spec that owns the pass/fail verdict for a sharded
scan. All of them are checked, so drift confined to a sibling file is caught
rather than passing because the top-level spec happened not to move.

Neither is edited by hand. `.github/workflows/ash-iac-drift.yml` regenerates both on
every pull request and fails if the result differs from what is committed, so a stale
artifact is a red build rather than something an adopter discovers at launch time.

The gate also runs `terraform fmt -check -recursive`, initializes and validates every
Terraform module and example, and requires that the CDK app register cdk-nag as a
validation plugin so that unsuppressed findings fail synth. Suppress a cdk-nag finding
in the construct, with a reason:

```js
Validations.of(scope).acknowledge({
  id: 'AwsSolutions::AwsSolutions-S1',
  reason: 'Access logs are centralized in a dedicated logging account bucket.',
});
```

An acknowledged rule is not reported and does not fail the build. Note that
acknowledgements live in the construct and do not appear in the emitted template, so
the template is not the place to look for them.

## Constraints and assumptions

- **The stacks synthesize offline.** `cdk synth` runs in CI with `--no-lookups` and no
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
