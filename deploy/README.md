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
| EKS operator | The ASH operator installed into an EKS cluster you already run | Pods in your cluster | An `AshScan` or `AshMcpServer` custom resource | `EksClusterName`, `OperatorImageUri`, `OperatorNamespace`, `VpcSubnetIds`, `VpcSecurityGroupIds` |

None of these targets pulls a prebuilt ASH image, because there is no public one to
pull. See [Trust and the container image](#trust-and-the-container-image).

The first four go further and build the image into your own ECR repository as part of
deployment. **The EKS operator target does not, and this is the one place in `deploy/`
where the image is your job rather than the template's.** It installs an operator
whose image it takes as a required parameter with no default, pointing at your own
registry, and it creates no ECR repository. Build and push the operator image before
launching that stack; a blank `OperatorImageUri` is rejected at launch rather than
discovered later as an `ImagePullBackOff`.

That target also differs in what it needs from you up front. It installs into a
cluster it did not create, so these have to already be true and it cannot check any
of them for you:

- The cluster's **authentication mode must include the EKS API** (`API` or
  `API_AND_CONFIG_MAP`, not `CONFIG_MAP` alone). Without it the access entry the
  stack creates cannot be created at all.
- The cluster's **platform version must support access entries**.
- A **private-only API endpoint** means supplying `VpcSubnetIds` and
  `VpcSecurityGroupIds` so the installer can reach it. Supply both or neither; the
  template refuses one without the other before it creates anything.
- If you do attach it to a VPC, it needs egress to **three** services, not two: EKS,
  STS, and **S3**. S3 is the one that gets missed and it fails worst — CloudFormation's
  response URL is a presigned S3 URL, so an installer that can reach EKS and STS but
  not S3 applies every manifest successfully and then cannot report that it did. The
  stack sits in `CREATE_IN_PROGRESS` until it times out with the operator already
  installed and no error raised anywhere. Either a NAT gateway, or interface endpoints
  for EKS and STS plus a `com.amazonaws.<region>.s3` endpoint.
- The **EKS Pod Identity agent** must be installed for the operator's AWS identity to
  resolve. The stack does not install it, but it does report what it found in the
  `PodIdentityAgentStatus` output — `ABSENT` there means the operator will get no AWS
  credentials no matter what you attach to `OperatorRoleArn`.
- **A private registry needs a pull path, and nothing here creates one.** This is the
  likely case, because `OperatorImageUri` points at your own registry and that is
  usually private ECR — so the intended configuration is the one that needs this. The
  **kubelet** pulls the image, using the node role or an `imagePullSecret`, *before any
  pod identity exists*; the Pod Identity association this stack creates governs the
  container's own AWS calls and does nothing for image pull. Give the node role ECR
  pull permission, or attach an `imagePullSecret` to the ServiceAccounts. The operator
  sets `imagePullSecrets` nowhere, and neither does this stack.

  This bites twice. The operator's scan Jobs run under the ServiceAccount named by the
  custom resource's `scanServiceAccountName` field, which **defaults to `default`** if
  you omit it — and `default` has neither the RBAC nor any pull secret. So set that
  field to `ash-scan` (the account this stack creates) rather than leaving it unset.

`OperatorRoleArn` has **no policies attached, and the default configuration needs
none.** Nothing ASH runs by default calls an AWS API: every boto3 user is confined to
one plugin directory that nothing else references, and the package declares no
`entry_points`, so there is no auto-discovery path either.

Two things to know before you opt in to the AWS reporters, because the opt-in is
coarser and quieter than it looks:

- **Opting in activates four reporters, not one.** Adding `ash_aws_plugins` to a scan's
  `spec.config.ash_plugin_modules` turns on S3, Bedrock summary, CloudWatch Logs **and**
  Security Hub — all four default to enabled. Either attach permissions covering all
  four, or set `enabled: false` on the three you did not want.
- **A missing permission does not fail the scan.** ASH deliberately does not fail a whole
  scan because one output format could not be written; it logs an error and carries on.
  So an opt-in without the matching IAM produces error lines in the pod log, a pod that
  exits 0, and a scan this operator marks `Complete` — with the S3 copy never made.
  Check the operator's logs, not the scan phase, if a report does not arrive.

  This affects only delivery to AWS services. The operator's own result collection reads
  the shared volume and does not go through S3, so scan results themselves are unaffected.

The stack header in `cdk/lib/ash-eks-operator-stack.ts` says what each unmet
precondition looks like when it fails.

**Deleting the stack does not remove everything it created, on purpose.** It removes
the Deployment — so the operator stops — along with its NetworkPolicy, the
ServiceAccounts, Role and RoleBinding. It deliberately leaves the namespace, both CustomResourceDefinitions, the
ClusterRole and the ClusterRoleBinding in place, because all of those are cluster-scoped
and this stack may not be their only owner: deleting a namespace cascade-deletes
everything in it, and deleting `ashscans.ash.awslabs.github.io` would destroy every
`AshScan` in every namespace of the cluster, including any belonging to an installation
this stack knows nothing about. Remove them yourself if you are certain nothing else
uses them.

If you set `VpcSubnetIds`, the delete can also leave a Hyperplane network interface in
those subnets. CloudFormation deletes the installer's execution role right after the
function, and the Lambda guide says "If you delete the execution role before Lambda
deletes the Hyperplane ENI, Lambda won't be able to delete the Hyperplane ENI. You can
manually perform the deletion."
([Understanding Hyperplane ENIs](https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html#configuration-vpc-enis)).
Check the subnets for a leftover interface after the stack is gone.

## What deploying actually costs you

Building the image per deployment is the price of there being no public one, and it
has consequences worth knowing before the first `create-stack` rather than after:

- The first deployment includes a container build. It is slow — minutes, and longer
  with `AshOfflineMode` enabled, which vendors scanner rulesets into the image.
- Two of the targets cannot create their workload until that build finishes, so the
  build gates stack creation rather than running alongside it. A stack that looks
  stuck early on is usually waiting on the build.
- `RebuildSchedule` patches the **repository**. Rolling a newly built image into an
  already-running workload is a further step, documented per target — a rebuild
  alone does not update a running service.
- Deleting a stack leaves the ECR repository and the artifact buckets behind, on
  purpose. An image that took twenty minutes to build should not vanish because a
  rollback removed the stack that referenced it. Deleting them is a deliberate,
  separate action.

## Which tool, and where the detail lives

`cdk/` holds the CDK apps and the synthesized templates in `cdk/templates/`. You can
launch any of them straight from the CloudFormation console without running `cdk` at
all — the console uploads the template for you, so template size never comes up.
`terraform/` mirrors the same targets with the same parameter names — with one
exception: there is no Terraform module for the EKS operator target yet. `deploy/cdk`
is the only implementation of it today, so nothing under `terraform/` reads
`EksClusterName` or `OperatorImageUri`. `VpcSecurityGroupIds`, added with that target,
joins the shared parameter surface in `cdk/lib/ash-config.ts` and still needs a
Terraform counterpart when that module lands.

A quick-create link goes further: it opens the console with the template already chosen and
its parameters filled in. ASH ships no such links, because CloudFormation accepts only an S3
URL in one and ASH hosts no bucket — see [Hosting the templates for one-click
launch](#hosting-the-templates-for-one-click-launch).
[quick-create-links.md](quick-create-links.md) is how you render your own against a bucket
you control; it also lists which parameters each link sets and which ones you would still
have to type.

Scripting the launch is where size does come up. CloudFormation caps an inline
`--template-body` at 51,200 bytes. `AshAgentCore`, `AshCodeCommitGate` and
`AshEksOperator` fit;
`AshImagePipeline`, `AshFargate` and `AshDistributedPipeline` do not, and have to be
uploaded to S3 and launched with `--template-url` instead, where the cap is 1 MB.
`cdk/README.md` has the sizes and both commands. `AshDistributedPipeline` is roughly
2.5 times the inline cap and will not be brought under it: it emits one CodeBuild
action per shard, which is the entire point of that target.

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

Three things in this directory are generated and committed, which is a deliberate
tradeoff: an adopter deploys straight from this repository with no build step — nobody
runs `cdk synth` to launch one of these stacks — at the cost of files that can go stale
against the code that produces them.

No build step is not the same as one click. A console quick-create link additionally needs
the template sitting in an S3 bucket, which ASH deliberately does not provide. If you want
such a link, copy the template to a bucket you own and render one:
[Hosting the templates for one-click launch](#hosting-the-templates-for-one-click-launch)
explains why there is no upstream bucket, and
[quick-create-links.md](quick-create-links.md) under "Rendering links for your own bucket"
is the sequence.

| Artifact | Generated from | Regenerate with |
| --- | --- | --- |
| `cdk/templates/<StackName>.template.json` | the CDK app in `cdk/` | `cd deploy/cdk && npm ci && rm -rf cdk.out && npx cdk synth --all --output cdk.out --no-lookups --quiet && find templates -type f -name '*.template.json' -delete && cp cdk.out/*.template.json templates/` |
| `cdk-constructs/buildspec*.yml` | the construct in `cdk-constructs/` | `cd deploy/cdk-constructs && npm ci && npm run generate:buildspec` |
| `quick-create-links.md` | `quick-create-links.md.template`, the committed templates' own `Parameters` blocks, and `quick-create-hosting.json` | `python3 scripts/render_quick_create_links.py render` |

One generator run emits several buildspecs, not one: the top-level spec, the
per-shard spec, and the merge spec that owns the pass/fail verdict for a sharded
scan. All of them are checked, so drift confined to a sibling file is caught
rather than passing because the top-level spec happened not to move.

None of the three is edited by hand. `.github/workflows/ash-iac-drift.yml` regenerates all
of them on every pull request and fails if the result differs from what is committed, so a
stale artifact is a red build rather than something an adopter discovers at launch time.

The gate also runs `terraform fmt -check -recursive`, initializes and validates every
Terraform module and example, compares the CloudFormation and Terraform representations
against each other (see [Keeping CloudFormation and Terraform in
step](#keeping-cloudformation-and-terraform-in-step)), and requires that the CDK app
register cdk-nag as a CDK Aspect so that every stack is scanned. Suppress a cdk-nag
finding next to the resource, with a reason:

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

## Hosting the templates for one-click launch

A CloudFormation quick-create link opens the console with a template and its parameters
already filled in, and it requires `templateURL` — which CloudFormation accepts only as an
S3 URL. A link pointing at this repository's raw file URL does not work, so committing the
templates is not by itself enough to make a one-click launch possible. They have to be in a
bucket.

**ASH publishes them to no bucket, and will not.** That is the same position it takes on the
container image, for the same reason, set out in
[Building your own container image](../docs/content/docs/building-your-own-image.md): ASH
reads your source code, so anything that scans or provisions on your behalf sits in the
trust position of your build tooling, and what is in it, when it changed, and who approved
that should be answerable by the organization running it.

The argument is weaker for a template than for an image, and worth stating as such. A
template is text, it is committed here, and you can review one in the diff without trusting
any registry. What an upstream bucket would add is not provenance — it is a permanent
external dependency in your launch path, and one more artifact whose contents at any moment
are decided elsewhere.

So [quick-create-links.md](quick-create-links.md) ships with no links in it, permanently,
and says so. That is its finished state rather than a gap.

**The links are yours to render.** Copy the templates to a bucket you own, set it in
`quick-create-hosting.json`, and re-render — you get a working link per template, in your
account, to use or publish on your own runbook. The full sequence is in
[quick-create-links.md](quick-create-links.md) under "Rendering links for your own bucket",
and its first step is the same `aws s3 cp` that `cdk/README.md` already documents for
launching the three templates that exceed CloudFormation's inline size cap. For those three
the upload is not an extra cost of this feature; it is a step you were already taking.

Two things that were rejected, both for the same reason:

- **Rendering against a guessed or sample bucket name.** It fails in the console with an
  access error, and the reader spends their time auditing their own permissions before
  concluding the link was never real. Worse, a sample link is copyable, and a link pointing
  at a bucket its publisher does not control is a hazard rather than an illustration. The
  renderer emits an unmistakable `NO-BUCKET-CONFIGURED` instead.
- **Softening the placeholder into something that looks like a URL.** Same failure, one step
  removed.

Both are instances of one rule: a placeholder standing in for a security-relevant value
should be **unusable rather than plausible**, so that a wrong value fails loudly instead of
resolving to something. A syntactically valid stand-in gets deployed; an obviously broken one
gets replaced. That holds for a bucket in a launch URL the same way it holds for a checksum,
a signing identity, or an account id.

## Keeping CloudFormation and Terraform in step

`cdk/` and `terraform/` are two independent implementations of the same five targets.
Every check described above validates one representation against *its own* source, so
none of them would notice the two drifting apart: add a resource to the CDK app,
regenerate the template, and the drift gate passes while the Terraform module quietly
stops describing the same deployment.

`deploy/tests/iac-equivalence.py` is the check that compares them. It runs in the same
workflow, needs no credentials or network, and can be run by hand:

```console
python3 deploy/tests/iac-equivalence.py
```

Each CloudFormation stack is compared against the **union** of the Terraform modules
that implement it, because a template has to deploy on its own with no build step ahead
of it, while Terraform composes. `ash-image-pipeline` is part of every pair for that
reason:

| Stack | Terraform counterpart |
| --- | --- |
| `AshImagePipeline` | `ash-image-pipeline` |
| `AshAgentCore` | `ash-image-pipeline` + `agentcore` |
| `AshCodeCommitGate` | `ash-image-pipeline` + `codecommit-gate` |
| `AshDistributedPipeline` | `ash-image-pipeline` + `codepipeline-executor` |
| `AshFargate` | `ash-image-pipeline` + `fargate` (network from `aws-ia/vpc/aws`) |

`AshEksOperator` has no Terraform counterpart and is recorded in
`STACKS_WITHOUT_TERRAFORM`: it gets no census, and its resource types are still
checked against the vocabulary. Adopters of that target have only the
CloudFormation path.

### What it checks, and what it does not

It compares **which kinds of resource each side provisions** — a presence census over a
canonical vocabulary that maps CloudFormation types onto Terraform types.

Nothing unclassified is skipped, at either level:

- A **resource type** the vocabulary has never seen is a hard failure. That is what
  makes a new resource in either representation a red build.
- A **committed template** named in neither the pair table nor
  `STACKS_WITHOUT_TERRAFORM` is a hard failure. Templates are discovered by globbing
  `cdk/templates/`, never from a list, because a list cannot report the thing it is
  missing. If you add a stack with no Terraform module, record it in
  `STACKS_WITHOUT_TERRAFORM` with the reason and what an adopter of that target loses —
  a missing counterpart is a named entry, not an absence. Such a stack gets no census,
  but its resource types are still checked against the vocabulary.

Read this list before treating a green check as "the two sides agree", because it is
narrower than it sounds:

- **Properties are not compared.** Both sides declaring an `S3` bucket is a match even
  if one encrypts with a customer-managed key and the other with `AES256`. This is not
  hypothetical — it is the live KMS divergence recorded below.
- **Counts are not compared.** CDK synthesizes an implicit `AWS::IAM::Policy` per
  `grant*()` call, so the two sides never agree on resource counts and cannot be made
  to. `AshDistributedPipeline` carries 88 resources against 20 in Terraform.
- **Named resources are not matched.** Nothing checks that a role on one side is the
  *same* role as one on the other, only that both sides have roles.
- **IAM policy content is not read.** A statement granting `*` on one side is invisible.
- **External modules are not read.** The Fargate network comes from `aws-ia/vpc/aws`;
  its resource kinds are recorded as unverified, not confirmed.
- **Only a module's root `.tf` files are read.** A resource in a nested directory
  that the module calls as a local `module` is not counted. No module has one today;
  adding one means extending the check. Commented-out blocks (`#`, `//`, `/* */`) are
  not counted.
- **Property-equivalent Terraform resources are excluded by name**, because
  CloudFormation expresses them as properties — `aws_s3_bucket_versioning`,
  `aws_s3_bucket_server_side_encryption_configuration` and six others. Deleting one of
  those outright would *not* fail this check.
- **Conditional resources count as present.** A `resource` block behind `count = 0`,
  or a CloudFormation resource behind a false `Condition`, still counts.

Closing the first and last of those means mapping properties across two schemas that
disagree about shape. That is the right next increment and it is deliberately not part
of this one.

### The divergences that exist today

The five pairs do not currently match. Every difference is itemized in the script's
`BASELINE`, one entry per pair per resource kind with the reason it exists — there is
no wildcard and no pattern. An unlisted divergence fails the build; so does a baseline
entry that no longer matches, because a baseline that outlives what it describes becomes
the blanket exclusion it was written to avoid.

An entry can stop matching three ways, and the check distinguishes them because they
call for opposite actions. Both sides declaring the kind now means it was fixed — delete
the entry. **Neither side declaring it is not a fix**: it is consistent with the kind
having been removed from the side that had it, and the entry is then the only remaining
record of that, so the check says so rather than telling you to delete it. Only the other
side declaring it means the divergence reversed rather than closed.

The one worth knowing about without opening the file: **every CDK stack creates a
customer-managed KMS key and no Terraform module does.** The modules take an optional
`kms_key_arn` and fall back to `AES256` or the AWS-managed key when it is null, so the
two representations hand an adopter a different default encryption posture. Which
default is right is an open decision — a customer-managed key carries a recurring
per-key cost, which is the reason the Terraform side gives for not imposing one.

## Upgrade notes

- **Updating an existing AshAgentCore, AshFargate or AshCodeCommitGate stack runs one
  extra image build.** The image-build bootstrap starter used to read the CodeBuild
  project name from a Lambda environment variable. It now reads it from a new
  `ProjectName` property on the `Custom::AshImageBootstrap` resource, so the function
  has no environment at all. A changed custom resource property makes CloudFormation
  re-invoke the starter on the first update to a template with this change, and the
  starter starts one image build, the same thing an ASH version bump does. The update
  does not complete until that build finishes and answers CloudFormation, so expect
  it to take as long as a normal image build. If a scheduled rebuild holds the
  project's only build slot at that moment, the update fails with a message saying
  so, and retrying it once the rebuild finishes is safe. Logical ids are unchanged,
  so nothing is replaced. Stacks created from scratch see no difference.

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
