# ASH deployment targets (AWS CDK)

CDK TypeScript apps for running ASH on AWS, plus the synthesized CloudFormation
templates under [`templates/`](templates). The templates are the deliverable: an
adopter launches one from the CloudFormation console and never runs `cdk`.

## The constraint that shapes all of this

ASH publishes no container image to any public registry, and that is a settled
licensing decision rather than a gap waiting to be filled. A one-click template
therefore cannot reference a prebuilt public ASH image.

Every target here **builds ASH into your own ECR repository as part of
deployment**. The CodeBuild project is the bootstrap, not a freshness mechanism
bolted onto something that already works: without it there is no image and the
workload cannot start. The scheduled rebuild that keeps the image patched is the
secondary purpose.

Read that twice before changing anything about the image build. Two of the five
templates cannot create their workload at all until an image exists, which is why
the bootstrap answers CloudFormation from inside the build rather than as soon as
the build starts.

## What is here

| Template | What it deploys |
| --- | --- |
| `AshImagePipeline` | Shared image build only: one ECR repository, scheduled ARM64 and x86_64 CodeBuild projects. For adopters running more than one target. |
| `AshAgentCore` | ASH's MCP server on Amazon Bedrock AgentCore Runtime. ARM64. |
| `AshFargate` | ASH's MCP server on ECS Fargate behind an internal Application Load Balancer. |
| `AshCodeCommitGate` | One-shot container Lambda that scans a CodeCommit pull request and comments on it, optionally voting on an approval rule. |
| `AshDistributedPipeline` | CodePipeline that fans a scan across N CodeBuild shards and merges the results into one verdict. |

Each of the four target templates embeds its own image build so it is genuinely
one-click. The cost is duplication: deploying all four gives four ECR
repositories and four CodeBuild projects building the same ASH revision. If that
is not worth it, deploy `AshImagePipeline` and point the targets at its
repository. Consuming it by `Fn::ImportValue` was considered and rejected, because
a console launch of the AgentCore template would then fail with an unresolved
export and no hint about which stack to deploy first.

## Launching a committed template

The CloudFormation console launch flow reads the template from an S3 URL, so it
works for all five. Scripting `create-stack` does not: CloudFormation caps an
inline `--template-body` at **51,200 bytes**, and three of these templates are
larger than that. Upload those to a bucket and launch by URL, where the ceiling is
1 MB.
<https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cloudformation-limits.html>

| Template | Scripted launch |
| --- | --- |
| `AshCodeCommitGate` | `--template-body` |
| `AshAgentCore` | `--template-body` |
| `AshImagePipeline` | `--template-url` only |
| `AshFargate` | `--template-url` only |
| `AshDistributedPipeline` | `--template-url` only |

Byte counts are deliberately not repeated here — they change with every template
change and nothing would catch it if this table went stale. Run
`wc -c templates/*.template.json` for the current numbers.

The two under the cap launch directly:

```sh
aws cloudformation create-stack \
  --stack-name ash-agentcore \
  --template-body file://deploy/cdk/templates/AshAgentCore.template.json \
  --capabilities CAPABILITY_IAM
```

The other three need one upload first. Any bucket in the same region works:

```sh
aws s3 cp deploy/cdk/templates/AshFargate.template.json \
  "s3://${YOUR_BUCKET}/ash/AshFargate.template.json"

aws cloudformation create-stack \
  --stack-name ash-fargate \
  --template-url "https://${YOUR_BUCKET}.s3.${AWS_REGION}.amazonaws.com/ash/AshFargate.template.json" \
  --capabilities CAPABILITY_IAM
```

Sizes are pinned by `test/ash-template-size.test.ts`, which fails if a template
crosses the cap in either direction — so this table cannot quietly go stale.
`AshDistributedPipeline` will not come under the cap by trimming: it is large
because it emits one CodeBuild action per shard, which is the target's whole
purpose.

## Shared parameter surface

These names are a contract. A Terraform mirror of the same targets under
`deploy/terraform/` uses identical names, so renaming one here is a breaking
change for adopters and desynchronizes the two implementations.

| Parameter | Default | Notes |
| --- | --- | --- |
| `AshVersion` | `v3.7.0` | Git ref cloned and built. Not a PyPI version. |
| `AshImageTag` | empty | ECR tag the **workload** pulls. Empty tracks the moving tag. Not offered by `AshImagePipeline`, which runs no workload. See below. |
| `AshOfflineMode` | `NO` | `YES`/`NO`, forwarded to the ASH Dockerfile's `OFFLINE` build argument. The spelling is the Dockerfile's; a boolean would build an image that stayed online. |
| `AshBaseConfigYaml` | empty | An ASH configuration document. See the size note below. |
| `McpStatelessHttp` | `true` | Keep `true` on AgentCore, and behind any load balancer with more than one replica. See below for what is measured and what is inferred. |
| `McpMountPath` | `/mcp` | AgentCore routes only `/mcp`, so change this only for Fargate. |
| `McpAllowedHost` | empty | Comma-separated `Host` values, passed as repeated `--allowed-host`, lower-cased because load balancers lower-case the `Host` they forward. On Fargate, empty means the ALB DNS name. |
| `McpIngressCidr` | empty | Fargate only. CIDR allowed to reach the load balancer on port 80. Empty creates **no** ingress rule, so the endpoint is reachable from nowhere. See below. |
| `McpAuthHeaderName` | empty | Header ASH requires on every request. Must satisfy `^$|^[A-Za-z][A-Za-z0-9_-]{0,255}$`. |
| `McpAuthHeaderValue` | empty | `NoEcho`. Stored in Secrets Manager; the container gets the ARN, never the value. |
| `RebuildSchedule` | `rate(1 day)` | EventBridge schedule expression for the image rebuild. |
| `CodeCommitRepositoryArn` | required | An **existing** repository. The gate stack never creates or deletes one. |
| `ShardCount` | 4 | **Not a CloudFormation parameter.** See below. |

`AshBaseConfigYaml` is stored in an SSM parameter on the Advanced tier and written
into the container at start, applied through `ASH_CONFIG` so it covers every scan
the process runs. CloudFormation caps a parameter value at 4096 bytes, so that is
the real ceiling on what you can paste. Advanced tier holds 8 KB, so a larger
config can be pasted into Parameter Store after deployment; the next container
start picks it up. A `.ash.yaml` inside a scanned repository still wins, which is
the precedence you want.

The CloudFormation quotas page suggests working around the 4096-byte cap by
declaring several parameters and rejoining them with `Fn::Join`. That is lossless,
unlike a `CommaDelimitedList`, but it makes you chunk your own config by hand and
misordering the chunks fails silently. Editing one SSM parameter is cheaper and
fails visibly.

`ShardCount` is CDK context, not a CloudFormation parameter, and that asymmetry
with Terraform is deliberate. How many CodeBuild actions exist is decided when the
template is synthesized. Emitting a fixed action count while letting a deploy-time
parameter set `--shard-count` would be actively wrong: shards with an index at or
above the count are invalid, and shards beyond the action count would never run,
so findings would go missing behind a green pipeline. Terraform resolves
`count = var.shard_count` at plan time and has no such limit, so the Terraform
mirror can expose it as a real variable. Re-synthesize to change it:

```
npx cdk synth -c shardCount=8
./scripts/synth-templates.sh
```

## Pinning the image a workload runs

**The problem:** a mutable tag consumed by a running workload has no defined moment
at which the workload adopts a new image. Every build republishes the moving tag
(`mcp-arm64` and friends), so a task replaced for any unrelated reason — a scaling
event, a host failure, an ECS redeploy — silently picks up whatever the tag points
at then. Nothing promotes the image and nothing announces the swap.

`AshImageTag` is the way out. Leave it empty, the default, and the workload tracks
the moving tag exactly as before. Set it and the workload pulls that tag instead.
It changes only what the workload pulls: every build still pushes both the moving
tag and the version-qualified one, so pinning never stops an image being published.

**You cannot pin on the first deploy, and that is not a bug.** The tag worth
pinning is the version-qualified one, `<flavor>-<platform>-<folded-ref>-<digest>`,
whose digest is computed inside CodeBuild from the raw `AshVersion`. It does not
exist and cannot be predicted before a build has run. So the workflow is three
steps, in this order:

```sh
# 1. Deploy with AshImageTag empty. The build publishes both tags.

# 2. Read the tag it produced. It is also echoed in the CodeBuild log.
aws ecr list-images --repository-name <EcrRepositoryUri's last path segment> \
  --query 'imageIds[?starts_with(imageTag, `mcp-arm64-`)].imageTag' --output text

# 3. Pin it on a stack update.
aws cloudformation update-stack --stack-name <your-stack> \
  --use-previous-template --parameters \
    ParameterKey=AshImageTag,ParameterValue=mcp-arm64-v3.7.0-1a2b3c4d \
    ParameterKey=AshVersion,UsePreviousValue=true
```

Pinning a tag that does not exist yet fails workload creation rather than waiting
for it. On `AshDistributedPipeline` the reference resolves per build rather than at
deploy, so an unproduced tag fails the shard projects when they start instead.

The trade is the obvious one: a pinned workload stops taking rebuilt images, so it
no longer picks up base-image and scanner patches until you move the pin. Unpin by
setting the parameter back to empty. `AshImagePipeline` does not take this
parameter — it builds images and runs no workload.

## AgentCore: the contract, and why stateless is the default

The container's shape is confirmed by two successful deployments: streamable-http
transport, host `0.0.0.0`, port `8000`, ARM64 container, `POST /mcp`. Change any of
those and the runtime does not come up. The deployed template was byte-identical to
the committed `templates/AshAgentCore.template.json`, so this applies to what ships
here.

Session handling is a different matter, and this section is labeled because we have
been wrong about it three times — first too confident, then too cautious, then too
trusting of the documentation.

**Measured**, against two live runtimes. A stateful runtime completes `initialize`,
`tools/list` and `tools/call` successfully. Sessions are genuinely enforced, so
that pass is not vacuous: no session id returns 400, and two differently shaped
fabricated ids each return 404. AgentCore returns a **fresh** `Mcp-Session-Id` on
essentially every response, while only the id issued at `initialize` stays valid —
so a client that follows AgentCore's own affinity guidance and adopts the returned
id takes a 404 on its third call. Stateless is immune, because it ignores session
ids entirely. That is why `McpStatelessHttp` defaults to `true`.

**Claimed by AWS documentation, and not verified by us:** that in stateless mode
the platform generates the `Mcp-Session-Id`, includes it in the request to your
server, and routes on it to the same microVM. Treat that as unconfirmed. The
affinity guidance on
[that same page](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-mcp-protocol-contract.html)
is precisely what we measured to break a stateful server, so the page is not a
reliable authority on this point.

**Not determined:** what the container actually sees per request. Telling "an id is
injected and silently adopted" apart from "nothing is injected" needs the inbound
headers logged inside the image, which nobody has done. It does not change the
default either way.

So stateful is **not impossible** here — AgentCore does support
[stateful MCP servers](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/mcp-stateful-features.html),
which is what enables elicitation, sampling and progress notifications. It is
unsupportable, which is a weaker claim: it needs every client to avoid rotating the
session id, and nothing in this stack controls the clients. There is also no
template-level switch — `ProtocolConfiguration` is a plain string taking
`MCP | HTTP | A2A | AGUI`, so the mode lives in the container's own invocation.

Session affinity is not incidental to this target. AgentCore routing on that header
to the same microVM is what lets on-disk per-session state survive across separate
`InvokeAgentRuntime` calls — observed as a scan's state persisting across 18
progress calls — which anything that delivers source in chunks and then scans it
depends on.

`AgentRuntimeArtifact.ContainerConfiguration` has exactly one property,
`ContainerUri`. There is no `Command`, `EntryPoint` or `Args`, so the MCP
invocation cannot come from the template and is baked into the image instead. ASH's
own image ends with `CMD ["ash"]`, so pointing AgentCore at it directly would start
a process that prints help and exits. The `mcp` image flavor adds a shell
entrypoint that reads the tunables from environment variables, which AgentCore
*can* set.

**`AgentRuntimeName` constraint for adopters:** the name is derived from your stack
name with hyphens stripped, because the property is matched against
`[a-zA-Z][a-zA-Z0-9_]{0,47}`. Keep the stack name at most 48 characters once
hyphens are removed. CloudFormation intrinsics cannot truncate, so a longer name is
rejected by AgentCore at create time.

## `--host` and DNS-rebinding protection

ASH's `--host` does more than choose an interface. The MCP SDK enables
DNS-rebinding protection automatically when the app is built with a loopback host,
which then admits only `127.0.0.1`, `localhost` and `[::1]` in the `Host` header.
Binding `0.0.0.0`, which any load-balanced container must do, relaxes that check.
`--allowed-host` is the middle ground: protection stays on and a named hostname is
admitted.

- **Fargate uses it.** Behind an ALB the `Host` header is the ALB's own DNS name,
  which is knowable, so `McpAllowedHost` defaults to it and protection stays on.
- **AgentCore does not, and here is why.** `Host` is on
  [AgentCore's restricted-header list](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-header-allowlist.html)
  and cannot be forwarded to the container, so the `Host` value ASH would see is
  AgentCore's internal one, which is neither documented nor knowable from outside.
  There is no hostname to name. Binding `0.0.0.0` relaxes the check, and the
  accepted posture is that the runtime is reachable only through
  `bedrock-agentcore:InvokeAgentRuntime`, which is IAM-authorized.

The same restricted-header list is why `McpAuthHeaderName` has to be a header
AgentCore will forward. The stack adds it to the runtime's `RequestHeaderAllowlist`
when both auth parameters are set, but a restricted name (anything `x-amz-`,
`x-amzn-`, or in the CORS, proxy, caching or connection families) will pass
parameter validation and still never reach the container. `X-ASH-Auth` is a safe
shape.

## The sharded pipeline: the merge action owns the verdict

Shard actions must not gate, and this is the easiest thing to get wrong. ASH's
shard selection splits the **scanner** set, so a shard can legitimately finish with
nothing to report and exit 0 while another exits 2 for findings. Gating per shard
fails in both directions: a clean shard looks like a clean scan, and one shard with
findings fails the pipeline before the other shards' findings have been collected.

So shards pass `--no-fail-on-findings` and only the merge action fails.

A shard's success is not decided by an exit code at all, and that is deliberate.
Click reports a usage error as exit 2 and ASH reports actionable findings as exit
2, so the two are indistinguishable — and one of them means nothing was scanned. A
shard therefore succeeds if and only if ASH wrote `ash_aggregated_results.json`,
which is the artifact the merge actually consumes. The exit code is recorded for
diagnosis and never trusted. That holds whether the flag is unrecognized (usage
error, no results, shard fails), a scanner crashed (no results, shard fails),
findings were found (results present, merge gates) or the shard was clean.

`--no-fail-on-findings` was **not** verified from this repository, because ASH is
not installed in the checkout this was written in. Correctness does not depend on
it; the results-file check does the work.

The merge independently requires that file from every shard, and refuses two cases
separately: a partial result set, and zero collected shards. Reporting a clean scan
for scanners that never ran is worse than failing, and a merge over nothing would
exit 0 and look like a clean repository.

Shard results travel through an S3 bucket keyed by pipeline execution id, not
through pipeline artifacts. A CodeBuild pipeline action accepts
[1 to 5 input artifacts](https://docs.aws.amazon.com/codepipeline/latest/userguide/reference-action-artifacts.html),
so an artifact per shard cannot express a six-way split at all.

Those transfers use `boto3`, not `aws s3 cp`, and that is not a style preference.
The shard and merge actions run with the ASH image as their CodeBuild environment
image — which is what puts `ash` directly on `PATH` with no Docker-in-Docker — and
**the ASH image installs no AWS CLI.** It does depend on `boto3`, so `python3` is
the only AWS API client guaranteed to be present. An `aws` invocation in these
buildspecs exits 127 at runtime, after the scan has already succeeded, and takes
the results with it. The same constraint shapes the MCP entrypoint in
`lib/ash-container-scripts.ts`, and `test/ash-no-aws-cli.test.ts` enforces it for
every project whose environment image is the ASH image.

The image build in stage one is the exception and is unaffected: it runs on a
CodeBuild managed image, which does ship the CLI, and it needs
`aws ecr get-login-password` to push. So do the two operator commands below —
they run on your workstation, not in the image.

Because the split is over scanners rather than files, a shard count above the
number of enabled scanners produces empty shards and no extra parallelism. Check
`ash plugin list` for the pinned version before raising it.

Start a scan by uploading an archive and starting the pipeline; the source action
does not poll:

```
aws s3 cp ./my-repo.zip s3://<SourceBucketName>/source.zip
aws codepipeline start-pipeline-execution --name <PipelineName>
```

## The CodeCommit gate

`CodeCommitRepositoryArn` names an existing repository. Nothing in the stack
creates, modifies or deletes it: a stack that created the repository would delete
it on rollback, and nobody should take that risk to get a pull request comment.

The rule listens for `pullRequestCreated` and `pullRequestSourceBranchUpdated`.
`pullRequestStatusChanged` is excluded on purpose, because closing or merging a
pull request is not a reason to scan it.

The vote is not binding on its own. CloudFormation has no resource type for a
CodeCommit approval rule template, so the stack cannot create one. To make the gate
block a merge, create a template naming the `ScanFunctionRoleArn` output and
associate it with the repository:

```
aws codecommit create-approval-rule-template --approval-rule-template-name ash-gate \
  --approval-rule-template-content '{"Version":"2018-11-08","Statements":[{"Type":"Approvers","NumberOfApprovalsNeeded":1,"ApprovalPoolMembers":["<ScanFunctionRoleArn>/*"]}]}'
aws codecommit associate-approval-rule-template-with-repository \
  --approval-rule-template-name ash-gate --repository-name <GatedRepositoryName>
```

## Requires CLI surface from sibling changes

Two things these templates invoke are being added alongside this change and are
**not** present in ASH as of the commit this was written against:

- `ash scan --shard-index <i> --shard-count <n>` — the sharding primitives exist in
  `automated_security_helper/core/sharding.py` and are honoured by the scan phase,
  but the flags are not yet on the `ash scan` CLI.
- `ash merge --results ... --output-dir ...` — no `merge` command is registered yet.

The `AshDistributedPipeline` template is written to the agreed contract for both:
zero-based index, both shard flags always passed together, `--results` repeatable
and accepting a file or a directory. It will fail at pipeline run time until those
land. Nothing else here depends on them.

## What is NOT verified

Most of what follows was originally unverified because nothing had been deployed.
Two AgentCore deployments have since closed the first two items, and they are kept
here as settled rather than deleted, so the next reader can see what was actually
checked instead of re-testing it.

**Now confirmed by deployment:**

- **AgentCore accepts this property combination.** `PUBLIC` network mode with `MCP`
  protocol and this role's permission set creates a working runtime.
- **The derived ARM64 image satisfies AgentCore's container probe.** ASH's MCP
  server binds `0.0.0.0:8000`, serves `POST /mcp`, and passes the readiness check.

The deployed template was byte-identical to the committed
`templates/AshAgentCore.template.json`, so that evidence applies to what ships
here rather than to a variant.

**Still unverified:**

1. **That a scheduled rebuild rolls into a running workload.** It does not, on any
   target. The rebuild replaces what the moving tag points at, which patches the
   *repository*. AgentCore pins a runtime version at create time, ECS does not
   redeploy on a tag change, and Lambda resolves the image at update time. Rolling
   the new image in needs `aws ecs update-service --force-new-deployment`, a
   `aws lambda update-function-code --image-uri`, or a stack update for AgentCore.
   An automatic post-rebuild promotion was designed and left out: for ECS and
   Lambda it is straightforward, but for AgentCore it would require guessing at
   `UpdateAgentRuntime` CLI semantics, and a guessed API is worse than a documented
   gap.

   Use `AshImageTag` if that bothers you. See below.
4. **That the ASH image builds at all under these build arguments.** No Docker
   daemon was available, so no image was built. The derived Dockerfiles assume
   `awslambdaric` publishes a wheel for `linux/amd64` CPython 3.12 (no compiler is
   installed) and that `pip install` works in ASH's base image without
   PEP 668 interference. Both fail loudly at build time if wrong.
5. **That the bootstrap custom resource completes.** The design is sound on paper
   and its failure mode is documented below, but the CloudFormation response
   round-trip has not been exercised.
6. **Every service quota consumed.** Nothing here approaches a documented limit,
   but no account was checked for existing usage.

## Known limitations and failure modes

- **A stopped or timed-out bootstrap build hangs the stack.** The image build sends
  the CloudFormation response itself, from `post_build`. A build that *fails* is
  fine: `post_build` still runs, reports FAILED, and the stack rolls back with the
  CodeBuild build id in the reason. A build that is *stopped*, or that exceeds the
  two-hour project timeout, may never run `post_build`, and the stack then sits in
  `CREATE_IN_PROGRESS` on `BootstrapBuild` until CloudFormation's own timeout.
  Cancel the stack operation if you see that.
- **The Lambda gate is bounded by Lambda.** 900 seconds is the
  [hard maximum](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html),
  and the clone plus ASH's output share 4 GB of `/tmp`. A large repository or a slow
  scanner set will be killed. The gate reports an error rather than passing, but it
  cannot finish the work. Use the sharded pipeline instead.
- **The shared secret is visible inside its own container.** ASH takes the value as
  `--auth-header-value`, a command-line argument, with no environment-variable
  equivalent, so it appears in the container's process list. It never reaches the
  template, the task definition or a runtime's environment map. Closing this needs
  an env-var option in ASH itself.
- **The Fargate listener is HTTP, not HTTPS.** A certificate ARN would be needed,
  and the shared parameter surface has no slot for one. The load balancer is
  internal by default to match.
- **No target sets `ASH_MCP_ALLOWED_ROOTS`, so the MCP scan boundary is the
  permissive fallback.** Only two targets run `ash mcp` at all — AgentCore and
  Fargate. The CodeCommit gate and the sharded pipeline invoke `ash scan` directly
  and are unaffected. On the two that do, the variable is unset, so scan targets
  fall back to a short denylist of system directories, which ASH's own docs call
  "a safety net rather than a boundary." On a network-reachable MCP endpoint that is
  not the same as naming the roots.

  The stacks do not set it, and the reason is a real obstacle rather than an
  omission. The scannable path on these targets is the per-session workspace that
  protocol source delivery writes into, and its location is resolved *inside the
  container* — `$ASH_MCP_WORKSPACE_ROOT`, else `$XDG_CACHE_HOME/ash-mcp`, else
  `~/.cache/ash-mcp`. So a value is only correct if the stack also pins
  `ASH_MCP_WORKSPACE_ROOT`. Worse, `validate_scan_target` adds the per-session
  directory to the allowlist only when a caller passes a session id, and several
  call sites — including output-directory validation — do not. A value that looks
  right can therefore admit the scan and still refuse its output directory partway
  through. Setting that wrong from here would break source delivery on a live
  feature, which is worse than leaving the documented fallback in place.

  To set it yourself, pin both, and make the allowlist include the workspace root:

  ```sh
  ASH_MCP_WORKSPACE_ROOT=/var/cache/ash-mcp
  ASH_MCP_ALLOWED_ROOTS=/var/cache/ash-mcp
  ```

  Naming the workspace **root** rather than a per-session directory is what makes
  every call site agree, including those that pass no session id. The cost is that
  it no longer scopes a session to its own subdirectory, so concurrent sessions can
  reach each other's uploaded source; add further roots for anything else you want
  scannable. Judge that against the alternative, which is most of the container
  filesystem.

- **The Fargate endpoint is closed until you open it.** The listener is created
  closed, so on deployment the load balancer's security group has allow-all egress
  and **no ingress rule at all** — reachable from nowhere, not even from inside the
  VPC. That is deliberate for an endpoint that accepts source code and returns
  findings about it, but it does mean the stack is not usable the moment it
  finishes. Set `McpIngressCidr` to the range your clients come from:

  ```sh
  # At deploy time, or on an update of an existing stack.
  ParameterKey=McpIngressCidr,ParameterValue=10.1.0.0/16
  ```

  Leaving it empty creates no rule, which is the default and is unchanged from
  before the parameter existed. A CIDR is required — a bare address is rejected at
  parameter validation rather than silently becoming a `/32` nobody intended; use
  `x.x.x.x/32` for a single host. For several sources, or to allow a client's
  security group rather than a CIDR, authorize the `McpSecurityGroupId` output
  directly:

  ```sh
  aws ec2 authorize-security-group-ingress --group-id <McpSecurityGroupId> \
    --protocol tcp --port 80 --source-group <client-sg-id>
  ```

  Defaulting to the stack's own VPC CIDR was rejected: this stack creates its own
  VPC and puts nothing in it but the ASH tasks, so that rule would admit a range
  with no clients in it while still widening access. Real consumers arrive from a
  peered VPC, a VPN or a transit gateway, none of which fall inside it.
- **An unused Secrets Manager secret is created even with auth disabled.** The
  alternative was a CloudFormation Condition gating the resource, which makes every
  IAM grant that mentions its ARN an invalid template. Costs a few cents a month.
- **ECR repositories and buckets are `RETAIN`.** `autoDeleteObjects` and
  `emptyOnDelete` synthesize asset-backed custom resources, which need a staging
  bucket and therefore `cdk bootstrap`, and these templates are meant to launch from
  the console. Deleting a stack leaves the repository and buckets behind.
- **Log groups are `RETAIN`, so they outlive the stack.** A Fargate deployment that
  tripped the ECS circuit breaker rolled back and took its own `TaskLogs` group with
  it, destroying the container stderr that explained the rollback. Every log group in
  these stacks is now retained for that reason, which makes each one a teardown
  residual: `TaskLogs` and `VpcFlowLogs` (Fargate), `ScanLogs` (gate), and
  `BuildLogs` plus `BootstrapStarterLogs` per image build — twelve groups across the
  five stacks. None pins a physical name, so a re-created stack gets a fresh group
  rather than colliding with the old one, and repeated deploy/rollback cycles
  accumulate one group per attempt. Retention stays at 30 days, so a residual group
  stops holding anything after a month; sweep the empty groups with
  `aws logs delete-log-group` when you tear an environment down.
- **Two CloudFormation spec warnings on every synth are false positives.** `cdk
  synth` reports an empty `SecretString` and an empty `RequestHeaderAllowlist`
  entry. The validator resolves each parameter to its default and then evaluates the
  true branch of the `Fn::If` guarding it. Verified against the synthesized
  template: both are `{"Fn::If": [<condition>, <parameter>, <fallback>]}` where the
  condition is false exactly when the parameter is empty, so CloudFormation receives
  the fallback. `Annotations.acknowledgeWarning` does not clear them, because the
  spec validator emits outside that mechanism.

## cdk-nag

`AwsSolutionsChecks` runs over every stack on every synth, so a new finding fails
`cdk synth`. Findings were fixed in preference to suppression:

| Rule | Handling |
| --- | --- |
| `AwsSolutions-VPC7` | Fixed: VPC flow logs to CloudWatch. |
| `AwsSolutions-ELB2` | Fixed: ALB access logs, wired at the L1 with the `logdelivery.elasticloadbalancing.amazonaws.com` service principal so no per-region ELB account id is needed. `logAccessLogs` throws on an environment-agnostic stack. |
| `AwsSolutions-CB4` | Fixed: one customer-managed KMS key per stack, shared by its CodeBuild projects. |
| `AwsSolutions-IAM4` | Fixed: `AWSLambdaBasicExecutionRole` replaced by a logs policy scoped to one log group. |
| `AwsSolutions-L1` | Fixed: newest available Python runtime. |
| `AwsSolutions-IAM5` | Suppressed. Wildcards are the CodeBuild log-stream and report-group suffixes, `ecr:GetAuthorizationToken` (which IAM defines with no resource ARN), and object-level access inside buckets these stacks create. |
| `AwsSolutions-SMG4` | Suppressed. Rotation would break authentication rather than improve it: ASH reads the value once at container start, so a rotated secret leaves running tasks validating the old value with no signal. |
| `AwsSolutions-ECS2` | Suppressed. No secret is in that environment map; the secret is fetched from an ARN inside the container, which is what the rule asks for. |
| `AwsSolutions-S1` | Suppressed on the access-log bucket only. Self-logging is an infinite loop and chaining to another bucket leaves that one unlogged. |
| `CdkNagValidationFailure` | Suppressed where a property resolves to an intrinsic (`AwsSolutions-CB5`, and IAM5 on the AgentCore role). Recorded rather than ignored: those rules did not run, so they neither passed nor failed. |

cdk-nag is pinned at **2.38.2** and registered as a CDK Aspect. On 2.x,
`AwsSolutionsChecks.prototype.visit` is a function and the Aspect path works —
measured here, and demonstrated by the run that surfaced 110 findings before they
were fixed. cdk-nag 3.x makes `NagPack` an `IPolicyValidationPlugin` — verified by
reading the declarations in the published 3.0.2 tarball — and needs
`Validations.of(app).addPlugins(...)` instead; if this app is ever moved to 3.x,
the registration in `bin/ash.ts` and every `NagSuppressions` call have to move with
it.

**The CI gate is pinned to the same major version.** The `cdk-nag` job in
`.github/workflows/ash-iac-drift.yml` reads the per-stack compliance reports 2.x
writes into the cloud assembly — `cdk.out/AwsSolutions--<StackName>-NagReport.csv`,
one row per rule × resource, failing on `Non-Compliant` or `UNKNOWN`. It does not
read `cdk.out/validation-report.json`, because on 2.x no cdk-nag finding ever
appears there. On 3.x that inverts: findings land in `validation-report.json` and
the CSV reports go away, so the gate has to move with the pin. A gate written
against the wrong major version reported another validator's findings as cdk-nag's
while cdk-nag had never run, which is the failure this note exists to prevent
happening twice.

Two further 2.x-only facts the gate depends on: suppressions serialize into the
emitted template as `Metadata.cdk_nag.rules_to_suppress` (82 resources across the
committed templates carry one), and a rule that throws while evaluating is recorded
as `UNKNOWN` rather than skipped — which is why the gate fails on it instead of
counting only `Non-Compliant`.

`AwsSolutions-IAM5` suppressions deliberately do not use `appliesTo`. The granular
form needs strings embedding CDK logical ids, which rot on any rename and fail
open. The reasons enumerate every wildcard instead.

## Reproducibility

Templates are byte-reproducible from `cdk synth` for a pinned `aws-cdk-lib`
version. Three consecutive synths produced identical bytes. What makes that hold:

- Stacks are environment-agnostic, so account and region are pseudo-parameters and
  the output does not depend on who ran it. `CDK_DEFAULT_ACCOUNT` and
  `CDK_DEFAULT_REGION` are read only under `-c useEnvironment=true`, which is not
  how the committed templates are produced.
- Nothing uses a CDK asset, so there are no content hashes and no staging bucket.
  Each stack defaults its own synthesizer with `generateBootstrapVersionRule:
  false`, so there is no `BootstrapVersion` parameter to resolve. That default lives
  on the stack rather than in `bin/ash.ts` because setting it only at the call site
  produced a stack that behaved one way when deployed and another when constructed
  by a test.
- `analyticsReporting: false` drops the version-keyed `CDKMetadata` resource.

Bumping the pinned `aws-cdk-lib` version *will* change the templates. CDK changes
generated logical ids and default properties between releases. That is a real diff
to review, not drift to suppress.

```
npm ci
npm run build         # tsc, emits into dist/
npm test              # 89 assertions
npm run synth         # write templates/
npm run synth:check   # fail if templates/ is stale
```

`tsc` emits into `dist/` rather than beside each source, and that is load-bearing
rather than tidiness. With output beside the sources, `npm run build` leaves
`lib/*.js` next to `lib/*.ts`, and jest's default `moduleFileExtensions` prefers
`js` — so `npm test` silently loads the stale compiled copy and reports a green run
against code that is no longer there. This was hit in development: four new
assertions failed against a buildspec that had already been changed.
`jest.config.js` also lists `ts` first, so the invariant is stated where it matters.

The templates synthesize with no AWS credentials and no `cdk.context.json`: nothing
uses `fromLookup`, so `npx cdk synth --all --no-lookups` works offline. The pinned
`aws-cdk` CLI (2.1139.0) matches the cloud-assembly schema `aws-cdk-lib` 2.267.0
emits (54.0.0); an older CLI fails synth with a schema mismatch that does not look
like a template problem.

## Layout

```
bin/ash.ts                      app entry; five stacks
lib/ash-config.ts               the shared parameter surface (the contract)
lib/ash-container-scripts.ts    the MCP entrypoint and the gate handler
lib/ash-image-build.ts          ECR + CodeBuild + schedule + bootstrap
lib/ash-image-pipeline-stack.ts shared build, standalone
lib/ash-agentcore-stack.ts
lib/ash-fargate-stack.ts
lib/ash-codecommit-gate-stack.ts
lib/ash-distributed-pipeline-stack.ts
lib/ash-nag-suppressions.ts     every suppression, with its reason
scripts/synth-templates.sh      emit or verify templates/
templates/                      committed CloudFormation, the deliverable
```
