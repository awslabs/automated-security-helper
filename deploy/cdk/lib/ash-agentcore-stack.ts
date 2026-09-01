/**
 * ASH's MCP server on Amazon Bedrock AgentCore Runtime.
 *
 * WHAT THIS TARGET SCANS
 * ----------------------
 * Nothing, until a caller sends it something. The runtime holds no copy of any
 * repository, this template mounts no filesystem into it, and the only way in is
 * `bedrock-agentcore:InvokeAgentRuntime`. The source tree arrives over MCP: either
 * the runtime clones it (`set_source_git`) or the caller uploads it in chunks
 * (`set_source_zip_chunk` / `set_source_zip_finalize`), after which `run_ash_scan`
 * with no `source_dir` scans what was delivered.
 *
 * That is why `networkMode` is `PUBLIC` and why no `filesystemConfigurations` are
 * set. The service does offer up to five of them, but the bring-your-own S3
 * Files/EFS types need a VPC-mode runtime and the managed types start empty, so
 * none of them removes the need to deliver the source. See deploy/cdk/README.md,
 * "What this target can scan, and how you give it something".
 *
 * EVERY CONSTRAINT IN THIS FILE IS A CONTRACT, NOT A PREFERENCE
 * ------------------------------------------------------------
 * AgentCore's MCP protocol contract fixes the container's shape, and two
 * successful deployments confirmed it — change any of these and the runtime does
 * not come up. Verified at
 * https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-mcp-protocol-contract.html:
 *
 * - streamable-http transport is required.
 * - Host `0.0.0.0`, port `8000`, ARM64 container.
 * - `POST /mcp`.
 *
 * The same page also says the following about sessions. These are QUOTED, not
 * verified by us, and the session-handling half of that page is where we have been
 * wrong three times — see the labelled split below before relying on either:
 *
 * - "Platform automatically adds `Mcp-Session-Id` header for session isolation.
 *   In stateless mode, servers must support stateless operation so as to not
 *   reject platform generated `Mcp-Session-Id` header."
 * - "By default, use stateless mode (`stateless_http=True`) for compatibility
 *   with AWS's session management and load balancing."
 *
 * https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-mcp-protocol-contract.html
 *
 * WHY `McpStatelessHttp` DEFAULTS TO `true`
 * ----------------------------------------
 * This comment previously said stateful "fails every request" on AgentCore,
 * because the platform injects a session id a stateful server rejects. That was
 * measured against a live runtime and is FALSE. A stateful runtime
 * (`ASH_MCP_STATELESS: "false"`, confirmed in the deployed configuration)
 * completed a full round trip: `initialize` with no session id returned 200,
 * `notifications/initialized` 202, `tools/list` 200 with 14 tools, and
 * `tools/call check_installation` 200 with a real result.
 *
 * That pass is not the server ignoring session ids, which would make it
 * meaningless. Controls against the same runtime: no session id returns 400, a
 * fabricated undashed 32-hex id in ASH's own format returns 404, and a fabricated
 * dashed UUID returns 404. Sessions are genuinely enforced, so those 200s can only
 * be a session ASH itself issued.
 *
 * The real hazard is sharper, and it is what keeps the default at `true`.
 * AgentCore returns a FRESH platform-minted `Mcp-Session-Id` on every response,
 * and its own contract tells clients to capture the returned id and send it on
 * subsequent requests. A stateful server honors only the id it issued at
 * `initialize`, so following that guidance literally breaks on the third call:
 *
 *   initialize, no id   -> 200, returns id A   (client adopts A, per the docs)
 *   tools/list with A   -> 200, returns id B   (client adopts B, per the docs)
 *   tools/list with B   -> 404 Session not found
 *
 * A docs-following MCP client therefore fails against a stateful runtime.
 * Stateless is immune because it ignores session ids entirely.
 *
 * WHICH PART IS WHICH — READ THIS BEFORE TRUSTING ANY OF IT
 * -------------------------------------------------------
 * This claim has now been wrong in three different directions: first too
 * confident that the platform injects an id a stateful server rejects, then too
 * cautious in calling the mechanism unknown, then too trusting of the
 * documentation. So the labels below are load-bearing. If this comment ever reads
 * as though we know the mechanism, it will foreclose the next person's check
 * exactly as the original wrong version did.
 *
 * - MEASURED, against two live runtimes: the round trip above, the three controls
 *   proving sessions are enforced, and the id rotation on essentially every
 *   response.
 * - CLAIMED BY AWS DOCUMENTATION, and NOT verified by us: that in stateless mode
 *   the platform generates the `Mcp-Session-Id`, includes it in the request to the
 *   server, and routes on it to the same microVM. Treat this as unconfirmed rather
 *   than settled — the affinity guidance on that same page is what we measured to
 *   break a stateful server on the third call, so the page is not a reliable
 *   authority on this specific point.
 * - NOT DETERMINED: what the container actually sees per request. Distinguishing
 *   "an id is injected and silently adopted" from "nothing is injected" needs the
 *   inbound headers logged inside the image, which is a change nobody has made. It
 *   does not affect the default either way.
 *
 * WHY SESSION AFFINITY IS LOAD-BEARING HERE, NOT INCIDENTAL
 * -------------------------------------------------------
 * AgentCore routes on `Mcp-Session-Id` to the same microVM, which is what lets
 * on-disk per-session state survive across separate `InvokeAgentRuntime` calls —
 * observed as a scan's state persisting across 18 progress calls. Anything that
 * delivers source in chunks and then scans it depends on that, so session
 * semantics matter to this target rather than being a protocol detail.
 *
 * `mcpStatelessHttp` in `ash-config.ts` carries the parameter-facing version.
 *
 * WHY THE ENTRYPOINT IS BAKED INTO THE IMAGE
 * ------------------------------------------
 * `AgentRuntimeArtifact.ContainerConfiguration` has exactly one property,
 * `ContainerUri`. No `Command`, no `EntryPoint`, no `Args`. The MCP invocation
 * therefore cannot come from this template and must be inside the image — which
 * is what the `mcp` flavor in `ash-image-build.ts` builds. ASH's own image ends
 * with `CMD ["ash"]`, so pointing AgentCore straight at it would start a process
 * that prints help and exits.
 *
 * WHY THERE IS NO `--allowed-host` HERE
 * -------------------------------------
 * `Host` is on AgentCore's restricted-header list and cannot be forwarded to the
 * container
 * (https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-header-allowlist.html),
 * so the `Host` value ASH would see is AgentCore's internal one, which is not
 * documented and not knowable from outside. `--allowed-host` needs a hostname you
 * can name. Binding `0.0.0.0` — which AgentCore mandates anyway — relaxes the MCP
 * SDK's DNS-rebinding protection, and that is the accepted posture for this
 * target: the runtime is not reachable except through
 * `bedrock-agentcore:InvokeAgentRuntime`, which is IAM-authorized. The Fargate
 * target, where the hostname IS knowable, does set `--allowed-host`.
 *
 * WHAT DEPLOYING SETTLED, AND WHAT IT DID NOT
 * ------------------------------------------
 * Two successful deployments confirmed the two items that used to head this list:
 * AgentCore accepts this exact property combination, and the derived ARM64 image
 * satisfies its container probe. The deployed template was byte-identical to the
 * committed `templates/AshAgentCore.template.json`, so that evidence applies to
 * what ships here rather than to a variant.
 *
 * Still unverified: that a rebuilt image behind a moving tag rolls into a running
 * runtime. It does not — AgentCore pins a runtime version at create time. See
 * deploy/cdk/README.md, which also names the version-qualified tag to point at
 * instead when a workload needs pinning.
 */

import { Aws, CfnOutput, Fn, RemovalPolicy, Stack, StackProps } from 'aws-cdk-lib';
import * as bedrockagentcore from 'aws-cdk-lib/aws-bedrockagentcore';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import { Construct } from 'constructs';

import {
  ashSynthesizer,
  AshCustomerKey,
  ashImageTag,
  ashOfflineMode, ashVersion, rebuildSchedule,
} from './ash-config';
import { AshImageBuild } from './ash-image-build';
import { suppressSecretRotation, suppressUnevaluableRules } from './ash-nag-suppressions';
import { AshRuntimeConfig } from './ash-runtime-config';

export class AshAgentCoreStack extends Stack {
  constructor(scope: Construct, id: string, props: StackProps = {}) {
    super(scope, id, {
      // Before ...props, so a caller can still override it.
      synthesizer: ashSynthesizer(),
      ...props,
      description:
        'ASH MCP server on Amazon Bedrock AgentCore Runtime. Builds the ASH ARM64 image ' +
        "into this account's ECR repository, because ASH publishes no public image.",
    });

    const version = ashVersion(this);
    const offline = ashOfflineMode(this);
    const schedule = rebuildSchedule(this);
    const customerKey = new AshCustomerKey(this);
    const config = new AshRuntimeConfig(this, 'Config', {
      includeMcpParameters: true,
      customerKey,
    });

    // One customer-managed key per stack, shared by every CodeBuild project here.
    // Rotation is on: the key only protects build output, so a rotated key needs
    // no coordination with anything outside the stack.
    const encryptionKey = new kms.Key(this, 'EncryptionKey', {
      description: 'Encrypts ASH CodeBuild project output for this stack.',
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // ARM64 is required, not chosen. AgentCore rejects an x86_64 image.
    const image = new AshImageBuild(this, 'Image', {
      platform: 'arm64',
      flavors: ['mcp'],
      ashVersion: version,
      offlineMode: offline,
      rebuildSchedule: schedule,
      imageTag: ashImageTag(this),
      encryptionKey,
      customerKey,
    });

    /**
     * `AgentRuntimeName` is matched against `[a-zA-Z][a-zA-Z0-9_]{0,47}` — no
     * hyphens. CloudFormation stack names are `[a-zA-Z][-a-zA-Z0-9]*`, so
     * stripping hyphens yields a legal name and keeps it unique per stack, which
     * a synth-time constant would not.
     *
     * CONSTRAINT FOR ADOPTERS: the stack name must be at most 48 characters once
     * hyphens are removed. CloudFormation intrinsics cannot truncate, so a longer
     * name is rejected by AgentCore at create time rather than silently trimmed.
     */
    const runtimeName = Fn.join('', Fn.split('-', Aws.STACK_NAME));

    const role = new iam.Role(this, 'RuntimeRole', {
      description: 'Execution role AgentCore Runtime assumes to run the ASH MCP server.',
      // Trust policy verified against
      // https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-permissions.html
      // The two conditions are part of the documented policy, not hardening we
      // invented: without them the role is assumable on behalf of any account.
      assumedBy: new iam.ServicePrincipal('bedrock-agentcore.amazonaws.com', {
        conditions: {
          StringEquals: { 'aws:SourceAccount': Aws.ACCOUNT_ID },
          ArnLike: {
            'aws:SourceArn': `arn:${Aws.PARTITION}:bedrock-agentcore:${Aws.REGION}:${Aws.ACCOUNT_ID}:*`,
          },
        },
      }),
    });

    image.repository.grantPull(role);
    config.grantRead(role);

    // ECR's authorization token is account-scoped and has no resource ARN.
    role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'EcrTokenAccess',
        actions: ['ecr:GetAuthorizationToken'],
        resources: ['*'],
      }),
    );

    const runtimeLogGroups = `arn:${Aws.PARTITION}:logs:${Aws.REGION}:${Aws.ACCOUNT_ID}:log-group:/aws/bedrock-agentcore/runtimes`;
    role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'RuntimeLogging',
        actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:DescribeLogStreams', 'logs:PutLogEvents'],
        resources: [`${runtimeLogGroups}/*`, `${runtimeLogGroups}/*:log-stream:*`],
      }),
    );
    role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'RuntimeLogGroupDiscovery',
        // DescribeLogGroups is a list operation and cannot be scoped to one group.
        actions: ['logs:DescribeLogGroups'],
        resources: [`arn:${Aws.PARTITION}:logs:${Aws.REGION}:${Aws.ACCOUNT_ID}:log-group:*`],
      }),
    );
    role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'RuntimeLogResourcePolicy',
        actions: ['logs:PutResourcePolicy'],
        resources: [Fn.join('', [runtimeLogGroups, '/', runtimeName, '-*'])],
      }),
    );
    role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'RuntimeTelemetry',
        // X-Ray's write and sampling APIs take no resource.
        actions: [
          'xray:PutTraceSegments',
          'xray:PutTelemetryRecords',
          'xray:GetSamplingRules',
          'xray:GetSamplingTargets',
        ],
        resources: ['*'],
      }),
    );
    role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'RuntimeMetrics',
        actions: ['cloudwatch:PutMetricData'],
        resources: ['*'],
        conditions: { StringEquals: { 'cloudwatch:namespace': 'bedrock-agentcore' } },
      }),
    );

    const runtime = new bedrockagentcore.CfnRuntime(this, 'Runtime', {
      agentRuntimeName: runtimeName,
      agentRuntimeArtifact: {
        containerConfiguration: { containerUri: image.imageUriForFlavor('mcp') },
      },
      // PUBLIC is AgentCore's own network sandbox, not an internet-facing
      // listener: nothing reaches the container except through
      // InvokeAgentRuntime. VPC mode exists for runtimes that must reach private
      // resources, which a scanner of supplied source does not.
      networkConfiguration: { networkMode: 'PUBLIC' },
      // A plain string, not an object. The CloudFormation shape is
      // `ProtocolConfiguration: MCP | HTTP | A2A | AGUI`.
      protocolConfiguration: 'MCP',
      roleArn: role.roleArn,
      environmentVariables: config.mcpEnvironment(),
      description: 'ASH security scanner exposed over MCP.',
    });

    /**
     * A custom auth header only reaches the container if it is on the runtime's
     * allowlist, so the allowlist must appear exactly when auth is configured.
     *
     * The object keys are CloudFormation-cased on purpose. `Fn::If` bypasses the
     * L1's camelCase-to-PascalCase property mapper, so writing
     * `requestHeaderAllowlist` here would emit a property AgentCore does not
     * recognize — and it would emit silently.
     */
    if (config.headerAuthCondition && config.authHeaderName) {
      runtime.requestHeaderConfiguration = Fn.conditionIf(
        config.headerAuthCondition.logicalId,
        { RequestHeaderAllowlist: [config.authHeaderName.valueAsString] },
        Aws.NO_VALUE,
      );
    }

    // The image has to exist before AgentCore can create a runtime version from
    // it. This is the whole reason the bootstrap answers CloudFormation from
    // inside the build rather than as soon as the build starts.
    runtime.node.addDependency(image.bootstrap!);

    suppressSecretRotation(config.authSecret);
    /*
     * A FAMILY OF CLOUDFORMATION SPEC WARNINGS IS EXPECTED HERE. ALL FALSE POSITIVES.
     *
     * `cdk synth` reports "SecretString: length 0 is below minimum 1" and
     * "RequestHeaderAllowlist.{}: '' does not match pattern". Since `KmsKeyArn`
     * arrived there are three more, on every resource that takes the key:
     * "KmsKeyId: Value is not valid under any of the given schemas", "KmsKeyId: ''
     * does not match pattern '^arn:...kms:...(key|alias)/.+'" and
     * "EncryptionConfiguration.KmsKey: length 0 is below minimum 1".
     *
     * They are all ONE mechanism, which is why they are documented together rather
     * than listed exhaustively - the list will grow with every conditional property
     * added. The validator resolves each parameter to its DEFAULT and then evaluates
     * the true branch of the `Fn::If` guarding it, so it sees the empty default.
     *
     * Verified against the synthesized template rather than assumed: every one of
     * these properties emits as `{"Fn::If": [<condition>, <parameter>, <fallback>]}`,
     * where the condition is `Fn::And(name != '', value != '')` for the auth pair and
     * `KmsKeyArn != ''` for the key. So whenever the validator's empty value would
     * apply, the condition is false and CloudFormation receives the fallback
     * instead — a non-empty placeholder for the secret, and `AWS::NoValue`, which
     * removes the property outright, for the allowlist and for every KMS key
     * reference. No empty value can reach any of these services.
     *
     * `Annotations.acknowledgeWarning` does NOT clear these: the CloudFormation
     * spec validator emits outside the `addWarningV2` acknowledgement mechanism,
     * so a call here would be dead code that looked effective. Left visible and
     * explained instead; synth still exits 0 because they are warnings.
     */


    // Every ARN in this role is assembled from pseudo-parameters so the template
    // stays account- and region-agnostic, which is exactly the shape cdk-nag's
    // IAM5 evaluator cannot resolve. The wildcards themselves are justified at
    // each addToPolicy call above.
    suppressUnevaluableRules(role, ['AwsSolutions-IAM5']);

    new CfnOutput(this, 'AgentRuntimeArn', {
      description: 'Invoke with bedrock-agentcore:InvokeAgentRuntime against this ARN.',
      value: runtime.attrAgentRuntimeArn,
    });
    new CfnOutput(this, 'AgentRuntimeId', {
      description: 'AgentCore Runtime id.',
      value: runtime.attrAgentRuntimeId,
    });
    new CfnOutput(this, 'EcrRepositoryUri', {
      description: 'Repository the ASH image is built into. Retained if the stack is deleted.',
      value: image.repository.repositoryUri,
    });
    new CfnOutput(this, 'ImageBuildProjectName', {
      description:
        'CodeBuild project that builds the image. Start it manually to rebuild ahead of ' +
        'the schedule.',
      value: image.project.projectName,
    });
    new CfnOutput(this, 'BaseConfigParameterName', {
      description:
        'SSM parameter holding the ASH base configuration. Edit it to change the ' +
        'deployment-wide config without a stack update.',
      value: config.configParameter.parameterName,
    });
  }
}
