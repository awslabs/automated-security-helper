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
 * AgentCore's MCP protocol contract fixes the container's shape. Verified at
 * https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-mcp-protocol-contract.html:
 *
 * - streamable-http transport is required.
 * - Host `0.0.0.0`, port `8000`, ARM64 container.
 * - `POST /mcp`.
 * - "Platform automatically adds `Mcp-Session-Id` header for session isolation.
 *   In stateless mode, servers must support stateless operation so as to not
 *   reject platform generated `Mcp-Session-Id` header."
 *
 * That last point is why `McpStatelessHttp` defaults to `true`. Measured against
 * ASH directly: given a session id the server never issued, ASH's MCP returns
 * HTTP 404 "Session not found" in stateful mode and HTTP 200 in stateless mode.
 * Deploying stateful here produces a runtime that fails every request, and the
 * failure looks like a client bug rather than a configuration one.
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
 * NOT VERIFIED WITHOUT DEPLOYING
 * ------------------------------
 * See deploy/cdk/README.md. In short: that AgentCore accepts this exact property
 * combination, that the derived ARM64 image satisfies its container probe, and
 * that a rebuilt image behind a moving tag does not roll into a running runtime.
 */

import { Aws, CfnOutput, Fn, RemovalPolicy, Stack, StackProps } from 'aws-cdk-lib';
import * as bedrockagentcore from 'aws-cdk-lib/aws-bedrockagentcore';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import { Construct } from 'constructs';

import {
  ashSynthesizer,
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
    const config = new AshRuntimeConfig(this, 'Config', { includeMcpParameters: true });

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
      encryptionKey,
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
     * TWO CLOUDFORMATION SPEC WARNINGS ARE EXPECTED HERE AND ARE FALSE POSITIVES.
     *
     * `cdk synth` reports "SecretString: length 0 is below minimum 1" and, on the
     * AgentCore stack, "RequestHeaderAllowlist.{}: '' does not match pattern".
     * The validator resolves each parameter to its DEFAULT and then evaluates the
     * true branch of the `Fn::If` guarding it, so it sees the empty default.
     *
     * Verified against the synthesized template rather than assumed: both
     * properties emit as
     * `{"Fn::If": ["ConfigHasHeaderAuth...", <parameter>, <fallback>]}`, and that
     * condition is `Fn::And(name != '', value != '')`. So whenever the validator's
     * empty value would apply, the condition is false and CloudFormation receives
     * the fallback instead — a non-empty placeholder for the secret, and
     * `AWS::NoValue` for the allowlist. Neither empty value can reach the service.
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
