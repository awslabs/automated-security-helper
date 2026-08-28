/**
 * The shared parameter surface for every ASH deployment target.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * ASH ships four deployment targets (AgentCore, ECS Fargate, a one-shot Lambda
 * pull-request gate, and a sharded CodePipeline executor) plus a shared image
 * build. Adopters move between them, and a Terraform mirror of these same
 * targets lives under `deploy/terraform/`. If each target invented its own
 * spelling for "which ASH version" or "is the MCP server stateless", moving
 * from one target to another — or from CDK to Terraform — would mean relearning
 * the surface every time.
 *
 * So the names in `ASH_PARAMETER_NAMES` are a CONTRACT, not an implementation
 * detail. The Terraform mirror uses the same names. Renaming one here is a
 * breaking change for adopters and desynchronizes the two implementations.
 *
 * WHAT WAS TRIED AND REJECTED
 * ---------------------------
 * - One mega-stack with every parameter: rejected. A CloudFormation console
 *   launch shows every parameter of a template, so an adopter deploying the
 *   Lambda gate would be asked for `ShardCount`. Each stack now declares only
 *   the parameters it actually reads, via the factory functions below.
 * - `CommaDelimitedList` for `AshBaseConfigYaml` to dodge the 4096-byte
 *   parameter cap: rejected. It corrupts any YAML containing a comma, which is
 *   most YAML. See the size discussion on `ashBaseConfigYaml` below.
 * - Free-form strings for `AshOfflineMode` / `McpStatelessHttp`: rejected in
 *   favour of `allowedValues`, so a typo fails at CloudFormation validation
 *   time instead of producing a container that silently behaves the other way.
 *
 * CONSTRAINTS AND ASSUMPTIONS
 * ---------------------------
 * - CloudFormation parameter values cap at 4096 bytes. `AshBaseConfigYaml` is
 *   therefore bounded by that, even though the SSM parameter it lands in can
 *   hold more (see `ashBaseConfigYaml`).
 * - `ShardCount` is deliberately NOT a CloudFormation parameter. Fanning out N
 *   CodeBuild actions is a synthesis-time decision, so it is CDK context. See
 *   `resolveShardCount` for the full reasoning.
 */

import { CfnParameter, DefaultStackSynthesizer, IStackSynthesizer, Stack } from 'aws-cdk-lib';

/**
 * Canonical parameter names, shared with the Terraform mirror.
 *
 * Treat the values as frozen. The keys are local ergonomics and may change.
 */
export const ASH_PARAMETER_NAMES = {
  ashOfflineMode: 'AshOfflineMode',
  ashBaseConfigYaml: 'AshBaseConfigYaml',
  ashVersion: 'AshVersion',
  mcpStatelessHttp: 'McpStatelessHttp',
  mcpAuthHeaderName: 'McpAuthHeaderName',
  mcpAuthHeaderValue: 'McpAuthHeaderValue',
  mcpMountPath: 'McpMountPath',
  mcpAllowedHost: 'McpAllowedHost',
  rebuildSchedule: 'RebuildSchedule',
  shardCount: 'ShardCount',
  codeCommitRepositoryArn: 'CodeCommitRepositoryArn',
} as const;

/**
 * The ASH git ref that every image build is pinned to.
 *
 * This is a git ref passed to `git clone --branch`, not a PyPI version: the
 * build clones the ASH repository and builds its Dockerfile, because ASH
 * publishes no container image to any public registry. Keep the `v` prefix —
 * ASH tags releases as `v3.7.0`.
 */
export const DEFAULT_ASH_VERSION = 'v3.7.0';

/** Default cadence for the scheduled rebuild that keeps the image patched. */
export const DEFAULT_REBUILD_SCHEDULE = 'rate(1 day)';

/**
 * The port AgentCore Runtime requires, and the default everywhere else so the
 * targets stay interchangeable.
 *
 * Verified: AgentCore's MCP protocol contract mandates port 8000 and host
 * 0.0.0.0 on an ARM64 container.
 * https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-mcp-protocol-contract.html
 */
export const MCP_PORT = 8000;

/** Default HTTP path the streamable-HTTP transport listens on. */
export const DEFAULT_MCP_MOUNT_PATH = '/mcp';

/**
 * Hard CloudFormation limit on a single parameter value, in bytes.
 * https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cloudformation-limits.html
 */
export const CFN_PARAMETER_MAX_BYTES = 4096;

/**
 * Value size above which an SSM parameter must use the Advanced tier.
 * Standard tops out at 4 KB, Advanced at 8 KB.
 * https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-advanced-parameters.html
 */
export const SSM_STANDARD_TIER_MAX_BYTES = 4096;

/**
 * `YES`/`NO` toggle forwarded to the Dockerfile's `OFFLINE` build argument.
 *
 * The spelling is the Dockerfile's, not ours: `ARG OFFLINE="NO"` fans out into
 * `ASH_OFFLINE`, `OFFLINE_AT_BUILD_TIME` and friends inside the image. Passing
 * `true` here would build an image that quietly stayed online.
 */
export function ashOfflineMode(scope: Stack): CfnParameter {
  return new CfnParameter(scope, ASH_PARAMETER_NAMES.ashOfflineMode, {
    type: 'String',
    default: 'NO',
    allowedValues: ['YES', 'NO'],
    description:
      'Build the ASH image in offline mode, vendoring scanner rulesets and tools ' +
      'into the image so scans need no network egress. Forwarded to the ASH ' +
      "Dockerfile's OFFLINE build argument. Offline images are larger and slower " +
      'to build.',
  });
}

/**
 * An entire ASH configuration document, materialized into the container.
 *
 * SIZE, HONESTLY: CloudFormation caps a parameter value at 4096 bytes, so that
 * is the real ceiling on what you can paste here — the stack cannot widen it.
 * The value is stored in an SSM parameter on the Advanced tier, which holds up
 * to 8 KB, so a config that outgrows the CloudFormation cap can be edited
 * directly in Parameter Store after deployment without touching the stack. The
 * container reads the parameter at start, so the next task or invocation picks
 * the change up.
 *
 * TWO ALTERNATIVES WERE REJECTED. Splitting the YAML across a
 * `CommaDelimitedList` corrupts any document containing a comma, which is most
 * YAML. Splitting it across several numbered parameters rejoined with `Fn::Join`
 * — the tuning strategy the CloudFormation quotas page itself suggests — is
 * lossless, but it makes the adopter chunk their own config by hand and puts the
 * burden of getting the order right on them, with a silent misconfiguration if
 * they do not. Editing one SSM parameter after deployment costs less and fails
 * visibly.
 * https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cloudformation-limits.html
 */
export function ashBaseConfigYaml(scope: Stack): CfnParameter {
  return new CfnParameter(scope, ASH_PARAMETER_NAMES.ashBaseConfigYaml, {
    type: 'String',
    default: '',
    maxLength: CFN_PARAMETER_MAX_BYTES,
    description:
      'Optional ASH configuration document (YAML). Stored in an SSM parameter and ' +
      'written to .ash/.ash.yaml inside the container at start. Leave empty to use ' +
      "ASH's built-in defaults. CloudFormation caps this at 4096 bytes; for a " +
      'larger config, deploy empty and edit the SSM parameter afterwards (Advanced ' +
      'tier, 8 KB).',
  });
}

/** The ASH git ref to build. */
export function ashVersion(scope: Stack): CfnParameter {
  return new CfnParameter(scope, ASH_PARAMETER_NAMES.ashVersion, {
    type: 'String',
    default: DEFAULT_ASH_VERSION,
    minLength: 1,
    description:
      'ASH git ref (tag, branch, or commit) to build the image from, for example ' +
      'v3.7.0. Pinning a tag makes the build reproducible; the scheduled rebuild ' +
      'still repulls base-image and OS patches for that same ASH revision.',
  });
}

/**
 * Whether the MCP server treats each streamable-HTTP request independently.
 *
 * WHY THE DEFAULT IS `true`: AgentCore injects its own `Mcp-Session-Id` header.
 * Measured against ASH directly, a session id the server never issued yields
 * HTTP 404 "Session not found" in stateful mode and HTTP 200 in stateless mode.
 * AWS documents the same requirement: "In stateless mode, servers must support
 * stateless operation so as to not reject platform generated Mcp-Session-Id
 * header."
 * https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-mcp-protocol-contract.html
 *
 * The same reasoning applies behind any load balancer that may route
 * consecutive requests to different replicas.
 */
export function mcpStatelessHttp(scope: Stack): CfnParameter {
  return new CfnParameter(scope, ASH_PARAMETER_NAMES.mcpStatelessHttp, {
    type: 'String',
    default: 'true',
    allowedValues: ['true', 'false'],
    description:
      'Handle each streamable-HTTP request independently instead of binding it to a ' +
      'server-held session. Must stay true on AgentCore, which injects its own ' +
      'Mcp-Session-Id that a stateful server rejects with 404. Also required behind ' +
      'a load balancer that may route consecutive requests to different replicas.',
  });
}

/** Header name for ASH's single-tenant shared-secret auth. */
export function mcpAuthHeaderName(scope: Stack): CfnParameter {
  return new CfnParameter(scope, ASH_PARAMETER_NAMES.mcpAuthHeaderName, {
    type: 'String',
    default: '',
    // The non-empty alternative is AgentCore's own declared pattern for a
    // request-header allowlist entry, so an unusable header name is rejected at
    // parameter validation rather than after a runtime has been created. The
    // empty alternative is what disables ASH-level auth.
    //
    // AgentCore additionally REFUSES to forward a long list of headers — Host,
    // Authorization-adjacent ones, every `x-amz-`/`x-amzn-` prefix, and the CORS
    // and proxy families. A restricted name passes this pattern and still never
    // reaches the container. See the restricted-header list:
    // https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-header-allowlist.html
    allowedPattern: '^$|^[A-Za-z][A-Za-z0-9_-]{0,255}$',
    description:
      'HTTP header name ASH requires on every MCP request, for example ' +
      'X-ASH-Auth. Leave both this and McpAuthHeaderValue empty to disable ' +
      'ASH-level auth and rely solely on the surrounding network controls.',
  });
}

/**
 * The expected value of {@link mcpAuthHeaderName}.
 *
 * `noEcho` keeps it out of the CloudFormation console, events and
 * `DescribeStacks`. The stack puts it in Secrets Manager and hands the
 * container the secret's ARN rather than the value, so the secret never lands
 * in a task definition, a runtime's environment-variable map, or the template.
 */
export function mcpAuthHeaderValue(scope: Stack): CfnParameter {
  return new CfnParameter(scope, ASH_PARAMETER_NAMES.mcpAuthHeaderValue, {
    type: 'String',
    default: '',
    noEcho: true,
    description:
      'Expected value of McpAuthHeaderName. Stored in Secrets Manager; the ' +
      "container is given the secret's ARN and resolves it at start, so the value " +
      'is never written into a task definition or a runtime environment variable.',
  });
}

/** HTTP path the streamable-HTTP transport listens on. */
export function mcpMountPath(scope: Stack): CfnParameter {
  return new CfnParameter(scope, ASH_PARAMETER_NAMES.mcpMountPath, {
    type: 'String',
    default: DEFAULT_MCP_MOUNT_PATH,
    allowedPattern: '^/.*',
    description:
      'HTTP path the MCP streamable-HTTP transport listens on. AgentCore requires ' +
      '/mcp and will not route anything else, so only change this for the Fargate ' +
      'target.',
  });
}

/**
 * Host-header allowlist that keeps DNS-rebinding protection switched on.
 *
 * The MCP SDK enables DNS-rebinding protection automatically when the app is
 * built with a loopback host, which then permits only `127.0.0.1`, `localhost`
 * and `[::1]` in the `Host` header. Binding `0.0.0.0` — mandatory on
 * AgentCore — relaxes that. `--allowed-host` is the middle ground: protection
 * stays on, but a known proxy hostname is admitted. Prefer it wherever the
 * hostname is knowable, which behind an ALB it is.
 */
export function mcpAllowedHost(scope: Stack): CfnParameter {
  return new CfnParameter(scope, ASH_PARAMETER_NAMES.mcpAllowedHost, {
    type: 'String',
    default: '',
    description:
      'Comma-separated Host header values to accept, passed to ASH as repeated ' +
      '--allowed-host flags. Keeps DNS-rebinding protection enabled while admitting ' +
      'a known proxy or load balancer hostname. Leave empty to accept any Host.',
  });
}

/** Cadence of the scheduled image rebuild. */
export function rebuildSchedule(scope: Stack): CfnParameter {
  return new CfnParameter(scope, ASH_PARAMETER_NAMES.rebuildSchedule, {
    type: 'String',
    default: DEFAULT_REBUILD_SCHEDULE,
    minLength: 1,
    description:
      'EventBridge schedule expression for the image rebuild, for example ' +
      '"rate(1 day)" or "cron(0 6 * * ? *)". The rebuild repulls the base image and ' +
      'scanner tools so a long-lived deployment keeps getting OS and scanner ' +
      'patches without a stack update.',
  });
}

/**
 * The customer's existing CodeCommit repository, supplied as an ARN.
 *
 * The gate stack reads pull-request events from this repository and posts
 * comments back to it. It deliberately does not create or delete it: an adopter
 * wiring a scan into an existing repository must never risk a stack rollback
 * taking their source history with it.
 */
export function codeCommitRepositoryArn(scope: Stack): CfnParameter {
  return new CfnParameter(scope, ASH_PARAMETER_NAMES.codeCommitRepositoryArn, {
    type: 'String',
    minLength: 1,
    allowedPattern: '^arn:aws[a-zA-Z-]*:codecommit:[a-z0-9-]+:\\d{12}:[\\w\\.-]+$',
    description:
      'ARN of an EXISTING CodeCommit repository to gate, in the form ' +
      'arn:aws:codecommit:<region>:<account-id>:<repository-name>. This stack references ' +
      'the repository and never creates, modifies or deletes it.',
  });
}

/**
 * Resolve the shard count from CDK context.
 *
 * WHY THIS IS NOT A CLOUDFORMATION PARAMETER, AND WHY THAT DIFFERS FROM
 * TERRAFORM: the distributed executor fans out one CodeBuild action per shard.
 * How many actions exist is decided when the template is synthesized, and a
 * CloudFormation parameter is not known until deploy time. Emitting a fixed
 * number of actions while letting a parameter set `--shard-count` would be
 * actively wrong: shards with an index at or above the count are invalid, and
 * shards beyond the action count would silently never run, so findings would go
 * missing with a green pipeline.
 *
 * Terraform has no such limit — `count = var.shard_count` is resolved at plan
 * time — so the Terraform mirror can expose `ShardCount` as a real variable.
 * The name is shared; the mechanism is not. Changing it here means re-synthesizing.
 *
 * The value is surfaced as a stack output and in template metadata so the
 * deployed shape is legible from the template alone.
 */
export function resolveShardCount(scope: Stack, fallback = 4): number {
  const raw = scope.node.tryGetContext(ASH_PARAMETER_NAMES.shardCount) ?? scope.node.tryGetContext('shardCount');
  if (raw === undefined || raw === null || raw === '') {
    return fallback;
  }
  const parsed = typeof raw === 'number' ? raw : Number.parseInt(String(raw), 10);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error(
      `shardCount context must be a positive integer, got ${JSON.stringify(raw)}. ` +
        'Synthesize with -c shardCount=8 to fan out eight shards.',
    );
  }
  return parsed;
}

/**
 * Reduce an arbitrary string to something AgentCore will accept as a name.
 *
 * `AgentRuntimeName` is matched against `[a-zA-Z][a-zA-Z0-9_]{0,47}` — letters,
 * digits and underscores only, first character a letter, 48 characters total.
 * CDK-derived names routinely contain hyphens, so they must be folded to
 * underscores rather than passed through.
 * https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-bedrockagentcore-runtime.html
 */
export function toAgentCoreName(raw: string): string {
  const folded = raw.replace(/[^a-zA-Z0-9_]/g, '_').replace(/^[^a-zA-Z]+/, '');
  const seeded = folded.length > 0 ? folded : 'ash';
  return seeded.slice(0, 48);
}

/**
 * The synthesizer every ASH stack uses unless a caller overrides it.
 *
 * WHY THIS IS NOT LEFT TO `bin/ash.ts`: it was, and it produced a test that
 * passed against a stack nobody deploys. Constructing `new AshAgentCoreStack(app,
 * id)` without the synthesizer emits a `BootstrapVersion` parameter of type
 * `AWS::SSM::Parameter::Value<String>` pointing at `/cdk-bootstrap/.../version`.
 * CloudFormation resolves SSM-typed parameters at deploy time and FAILS when the
 * parameter does not exist, so a console launch in an account that has never been
 * `cdk bootstrap`ped would fail — which is the one thing these templates must not
 * do. Making it the stack's own default means the shipped behaviour and the
 * tested behaviour are the same object.
 *
 * Safe here only because nothing in these stacks uses a CDK asset: Lambda code is
 * inline or an ECR reference, and no bucket or repository auto-deletes. Adding an
 * asset would need a staging bucket and would reintroduce the dependency.
 */
export function ashSynthesizer(): IStackSynthesizer {
  return new DefaultStackSynthesizer({ generateBootstrapVersionRule: false });
}
