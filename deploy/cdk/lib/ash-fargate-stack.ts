/**
 * ASH's MCP server on ECS Fargate behind an Application Load Balancer.
 *
 * WHY THIS TARGET SETS `--allowed-host` AND AGENTCORE DOES NOT
 * -----------------------------------------------------------
 * ASH's `--host` is load-bearing beyond deciding which interface to bind. The
 * MCP SDK turns DNS-rebinding protection ON automatically when the app is built
 * with a loopback host, which then permits only `127.0.0.1`, `localhost` and
 * `[::1]` in the `Host` header. Binding `0.0.0.0` — which a container behind a
 * load balancer must do to be reachable at all — relaxes that check.
 *
 * `--allowed-host` is the option that does not force the choice: protection
 * stays on, and a named hostname is admitted. Behind an ALB the `Host` header the
 * container sees is the ALB's own DNS name, and that name is knowable — it is a
 * stack attribute. So this stack defaults `McpAllowedHost` to the ALB DNS name
 * when the adopter leaves it empty, and DNS-rebinding protection stays enabled.
 * The AgentCore target cannot do this: `Host` is on AgentCore's restricted-header
 * list, so the container never sees a hostname anyone can predict.
 *
 * WHY `McpStatelessHttp` STILL MATTERS HERE
 * ----------------------------------------
 * With more than one task behind the ALB, consecutive requests in the same MCP
 * session can land on different replicas. A stateful server on the second
 * replica has no record of the session and answers 404. Stateless is the default
 * for that reason, independently of AgentCore's requirement.
 *
 * WHAT WAS REJECTED
 * -----------------
 * - `ApplicationLoadBalancedFargateService` (the ecs-patterns L3): rejected. It
 *   hides the target-group health check and the listener, both of which need
 *   non-default settings here — the MCP mount path answers POST, not GET, so the
 *   default `GET /` health check fails a healthy server.
 * - HTTPS on the listener by default: not possible without a certificate ARN the
 *   adopter has to supply, and the shared parameter surface has no slot for one.
 *   The listener is HTTP and the README says so plainly rather than pretending
 *   otherwise.
 */

import {
  Aws,
  CfnCondition,
  CfnOutput,
  Duration,
  Fn,
  RemovalPolicy,
  Stack,
  StackProps,
} from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';

import {
  ashSynthesizer,
  ashOfflineMode, ashVersion, MCP_PORT, rebuildSchedule,
} from './ash-config';
import { AshImageBuild } from './ash-image-build';
import {
  suppressCodeBuildRoleWildcards,
  suppressLogBucketSelfLogging,
  suppressSecretRotation,
  suppressTaskDefinitionEnvironment,
} from './ash-nag-suppressions';
import { AshRuntimeConfig } from './ash-runtime-config';

export class AshFargateStack extends Stack {
  constructor(scope: Construct, id: string, props: StackProps = {}) {
    super(scope, id, {
      // Before ...props, so a caller can still override it.
      synthesizer: ashSynthesizer(),
      ...props,
      description:
        'ASH MCP server on ECS Fargate behind an Application Load Balancer. Builds the ASH ' +
        "image into this account's ECR repository, because ASH publishes no public image.",
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

    const image = new AshImageBuild(this, 'Image', {
      platform: 'amd64',
      flavors: ['mcp'],
      ashVersion: version,
      offlineMode: offline,
      rebuildSchedule: schedule,
      encryptionKey,
    });

    // Two AZs is the ALB minimum. `natGateways: 1` keeps the running cost of an
    // idle deployment to one NAT rather than one per AZ; tasks need egress to
    // pull the image and, unless the image was built offline, to fetch scanner
    // rulesets.
    const vpc = new ec2.Vpc(this, 'Vpc', {
      maxAzs: 2,
      natGateways: 1,
      // Flow logs are on because this VPC carries source code being scanned and
      // the findings about it; without them a suspected exfiltration has nothing
      // to investigate.
      flowLogs: {
        Vpc: {
          destination: ec2.FlowLogDestination.toCloudWatchLogs(
            new logs.LogGroup(this, 'VpcFlowLogs', {
              retention: logs.RetentionDays.ONE_MONTH,
              removalPolicy: RemovalPolicy.DESTROY,
            }),
          ),
          trafficType: ec2.FlowLogTrafficType.ALL,
        },
      },
    });

    const cluster = new ecs.Cluster(this, 'Cluster', {
      vpc,
      containerInsightsV2: ecs.ContainerInsights.ENABLED,
    });

    const logGroup = new logs.LogGroup(this, 'TaskLogs', {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const taskDefinition = new ecs.FargateTaskDefinition(this, 'TaskDefinition', {
      // ASH runs several scanners concurrently. 2 vCPU / 4 GiB is the smallest
      // pairing that does not have scanners competing for memory; smaller task
      // sizes surface as scanners being OOM-killed, which ASH reports as a
      // scanner failure rather than a resourcing problem.
      cpu: 2048,
      memoryLimitMiB: 4096,
      runtimePlatform: {
        cpuArchitecture: ecs.CpuArchitecture.X86_64,
        operatingSystemFamily: ecs.OperatingSystemFamily.LINUX,
      },
    });

    /**
     * Default the allowed host to the ALB's DNS name.
     *
     * The ALB is created below, so its DNS name is referenced after the fact via
     * the token. There is no dependency cycle: the task definition's environment
     * is a value the ALB produces, and the ALB does not depend on the task
     * definition — only the target group does, and target-group registration is
     * a property of the service.
     */
    const container = taskDefinition.addContainer('Ash', {
      image: ecs.ContainerImage.fromEcrRepository(
        image.repository,
        image.tagForFlavor('mcp'),
      ),
      logging: ecs.LogDrivers.awsLogs({ streamPrefix: 'ash-mcp', logGroup }),
      // A scanner that dies takes the server's usefulness with it, so let ECS
      // replace the task rather than serve a half-working one.
      essential: true,
      portMappings: [{ containerPort: MCP_PORT, protocol: ecs.Protocol.TCP }],
      environment: config.mcpEnvironment(),
    });

    config.grantRead(taskDefinition.taskRole);

    const accessLogsBucket = new s3.Bucket(this, 'AccessLogs', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      // RETAIN, not autoDeleteObjects: the latter synthesizes an asset-backed
      // custom resource, which would make these templates need `cdk bootstrap`.
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const loadBalancer = new elbv2.ApplicationLoadBalancer(this, 'LoadBalancer', {
      vpc,
      internetFacing: false,
      // Internal by default. An ASH MCP endpoint accepts source code and returns
      // findings about it; putting that on the public internet behind nothing but
      // an optional shared-secret header is not a default anyone should inherit.
      // Flip to internet-facing deliberately, with auth configured.
    });

    /**
     * Override the allowed host with the ALB DNS name unless the adopter named
     * one.
     *
     * `Fn::If` on the container environment value, rather than a synth-time
     * choice, because `McpAllowedHost` is a deploy-time parameter.
     */
    if (config.allowedHost) {
      const allowedHostSupplied = new CfnCondition(this, 'AllowedHostSupplied', {
        expression: Fn.conditionNot(Fn.conditionEquals(config.allowedHost.valueAsString, '')),
      });
      container.addEnvironment(
        'ASH_MCP_ALLOWED_HOST',
        Fn.conditionIf(
          allowedHostSupplied.logicalId,
          config.allowedHost.valueAsString,
          loadBalancer.loadBalancerDnsName,
        ).toString(),
      );
    }

    /**
     * ALB access logs, wired at the L1 rather than through `logAccessLogs`.
     *
     * `logAccessLogs` throws `RegionRequiredEnableBvAccess` on an
     * environment-agnostic stack: it wants a concrete region so it can look up the
     * legacy per-region Elastic Load Balancing ACCOUNT ID for the bucket policy.
     * Baking a region in would defeat both goals of these templates — one artifact
     * that deploys anywhere, and byte-identical synth output.
     *
     * The modern policy needs no region lookup. It grants `s3:PutObject` to the
     * service principal `logdelivery.elasticloadbalancing.amazonaws.com`, and AWS
     * documents it as the recommended replacement for the legacy account-id form:
     * "This legacy policy is still supported, but we recommend that you replace it
     * with the newer policy above."
     * https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html
     *
     * Two details from that page are load-bearing:
     * - The resource path must include the account id and must not wildcard it, so
     *   that only load balancers in this account can write here.
     * - SSE-S3 is the ONLY supported encryption for an ALB log bucket, which is
     *   why the bucket above uses S3_MANAGED rather than a KMS key.
     */
    const accessLogPrefix = 'alb';
    accessLogsBucket.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AllowElbAccessLogDelivery',
        principals: [new iam.ServicePrincipal('logdelivery.elasticloadbalancing.amazonaws.com')],
        actions: ['s3:PutObject'],
        resources: [
          `${accessLogsBucket.bucketArn}/${accessLogPrefix}/AWSLogs/${Aws.ACCOUNT_ID}/*`,
        ],
        // Documented hardening: confine delivery to load balancers in this
        // account and region rather than any caller the service principal fronts.
        conditions: {
          ArnLike: {
            'aws:SourceArn': `arn:${Aws.PARTITION}:elasticloadbalancing:${Aws.REGION}:${Aws.ACCOUNT_ID}:loadbalancer/*`,
          },
        },
      }),
    );
    loadBalancer.setAttribute('access_logs.s3.enabled', 'true');
    loadBalancer.setAttribute('access_logs.s3.bucket', accessLogsBucket.bucketName);
    loadBalancer.setAttribute('access_logs.s3.prefix', accessLogPrefix);

    const service = new ecs.FargateService(this, 'Service', {
      cluster,
      taskDefinition,
      desiredCount: 1,
      // With desiredCount 1 the 50% default lets ECS stop the only task during a
      // deployment, so the endpoint goes down. 100/200 keeps the old task serving
      // until the replacement is healthy.
      minHealthyPercent: 100,
      maxHealthyPercent: 200,
      // Private subnets plus the NAT above. Tasks are reachable only through the
      // load balancer.
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      // An ASH image is large and the first pull is slow; give the task time to
      // become healthy before the load balancer starts failing it.
      healthCheckGracePeriod: Duration.minutes(5),
      circuitBreaker: { rollback: true },
    });

    // The image must exist before the service tries to place a task.
    service.node.addDependency(image.bootstrap!);

    /**
     * `open: false`, so this stack adds NO ingress rule and the endpoint starts
     * unreachable — from outside the VPC and from inside it.
     *
     * That is deliberate, and the outputs below say so rather than implying the
     * endpoint is usable on deployment. An observed stack had exactly one rule on
     * this security group, allow-all egress, while the `McpEndpoint` output
     * described the endpoint as "reachable from inside the VPC or over a
     * peered/VPN path". It was reachable from nowhere.
     *
     * WHAT WAS REJECTED, AND WHY NOT JUST OPEN IT TO THE VPC
     * ----------------------------------------------------
     * - Ingress from this VPC's CIDR: rejected as the appearance of a fix. This
     *   stack creates its OWN VPC and puts nothing in it but the ASH tasks, so
     *   that rule would admit a range containing no clients. Every real consumer
     *   arrives from somewhere else — a peered VPC, a VPN, a transit gateway —
     *   and none of those are inside this CIDR. It would widen access without
     *   making the endpoint usable.
     * - A new `McpIngressCidr` parameter: rejected here, though it is the right
     *   shape eventually. The parameter surface in `ash-config.ts` is a contract
     *   shared with the Terraform mirror under `deploy/terraform/`, and adding a
     *   name on one side only desynchronizes the two. That is a change to make
     *   across both implementations at once, not half of one.
     *
     * So the posture stays closed and the stack instead tells the adopter exactly
     * what to run, via the `McpSecurityGroupId` output. Being closed is
     * defensible; being closed while claiming otherwise is not.
     */
    const listener = loadBalancer.addListener('Listener', {
      port: 80,
      protocol: elbv2.ApplicationProtocol.HTTP,
      open: false,
    });

    listener.addTargets('Mcp', {
      port: MCP_PORT,
      protocol: elbv2.ApplicationProtocol.HTTP,
      targets: [service],
      healthCheck: {
        /**
         * The MCP mount path answers POST, not GET, so a health check against it
         * would fail a perfectly healthy server. ASH's streamable-HTTP transport
         * responds to an unroutable GET with a 4xx, which is a truthful liveness
         * signal — the process is up and serving HTTP — so 400-405 are accepted.
         * This checks liveness, not MCP protocol correctness; a deeper check
         * would need an MCP handshake, which a target-group health check cannot
         * perform.
         */
        path: '/',
        healthyHttpCodes: '200,400-405',
        interval: Duration.seconds(30),
        timeout: Duration.seconds(10),
      },
      deregistrationDelay: Duration.seconds(30),
    });

    suppressSecretRotation(config.authSecret);
    suppressLogBucketSelfLogging(accessLogsBucket);
    suppressTaskDefinitionEnvironment(taskDefinition);
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

    suppressCodeBuildRoleWildcards(taskDefinition.executionRole!);

    new CfnOutput(this, 'McpEndpoint', {
      description:
        'MCP endpoint, once you allow traffic to it. The load balancer is internal AND ' +
        'its security group has no ingress rule on deployment, so this address is not ' +
        'reachable from anywhere yet — see McpSecurityGroupId. Append the McpMountPath ' +
        'value. The listener is plain HTTP.',
      value: Fn.join('', ['http://', loadBalancer.loadBalancerDnsName]),
    });
    new CfnOutput(this, 'McpSecurityGroupId', {
      description:
        "The load balancer's security group, which starts with no ingress rule. Authorize " +
        'the range your MCP clients come from, for example: aws ec2 ' +
        'authorize-security-group-ingress --group-id <this> --protocol tcp --port 80 ' +
        '--cidr <your-client-cidr>. Prefer --source-group over --cidr where the client ' +
        'has its own security group.',
      // The ALB L2 creates exactly one security group, and this stack adds none,
      // so indexing it is a synth-time fact rather than an assumption about
      // deploy-time ordering. It is asserted in ash-fargate-stack.test.ts.
      value: loadBalancer.connections.securityGroups[0].securityGroupId,
    });
    new CfnOutput(this, 'LoadBalancerDnsName', {
      description:
        'Value ASH admits in the Host header when McpAllowedHost is left empty, keeping ' +
        'DNS-rebinding protection enabled.',
      value: loadBalancer.loadBalancerDnsName,
    });
    new CfnOutput(this, 'ClusterName', { value: cluster.clusterName });
    new CfnOutput(this, 'ServiceName', {
      description:
        'Run `aws ecs update-service --force-new-deployment` against this after a ' +
        'scheduled image rebuild to roll the new image into the running service.',
      value: service.serviceName,
    });
    new CfnOutput(this, 'EcrRepositoryUri', { value: image.repository.repositoryUri });
    new CfnOutput(this, 'ImageBuildProjectName', { value: image.project.projectName });
    new CfnOutput(this, 'BaseConfigParameterName', {
      value: config.configParameter.parameterName,
    });
  }
}
