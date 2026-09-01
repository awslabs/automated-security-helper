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
  accessLogArchiveProps,
  ashSynthesizer,
  AshCustomerKey,
  ashImageTag,
  ashOfflineMode, ashVersion, diagnosticLogGroupProps, mcpIngressCidr, MCP_PORT, rebuildSchedule,
} from './ash-config';
import { AshImageBuild } from './ash-image-build';
import {
  suppressCodeBuildRoleWildcards,
  suppressParameterizedIngressRule,
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
    const ingressCidr = mcpIngressCidr(this);
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

    const image = new AshImageBuild(this, 'Image', {
      platform: 'amd64',
      flavors: ['mcp'],
      ashVersion: version,
      offlineMode: offline,
      rebuildSchedule: schedule,
      imageTag: ashImageTag(this),
      encryptionKey,
      customerKey,
    });

    // Two AZs is the ALB minimum. `natGateways: 1` keeps the running cost of an
    // idle deployment to one NAT rather than one per AZ; tasks need egress to
    // pull the image and, unless the image was built offline, to fetch scanner
    // rulesets.
    const vpc = new ec2.Vpc(this, 'Vpc', {
      maxAzs: 2,
      natGateways: 1,
      /*
       * CDK's default subnet layout, spelled out so the public subnets can opt out
       * of auto-assigning public IPv4 addresses.
       *
       * CDK sets `MapPublicIpOnLaunch: true` on every PUBLIC subnet of an
       * IPv4-only VPC. Nothing in this stack needs it. The only resource placed in
       * a public subnet is the NAT gateway, and a NAT gateway takes its address
       * from the Elastic IP named in its `AllocationId`, not from the subnet
       * default; `natGateways: 1` puts that single gateway in the first public
       * subnet, so the second holds nothing but a route table association. The
       * load balancer is `internetFacing: false` and the service below runs with
       * `assignPublicIp` disabled, so both of those live in the private subnets.
       *
       * The names and types are `Vpc.DEFAULT_SUBNETS` verbatim -- 'Public' with
       * SubnetType.PUBLIC and 'Private' with SubnetType.PRIVATE_WITH_EGRESS --
       * because the subnet group NAME feeds the generated logical ids. Renaming a
       * group would rename every subnet, route table, route and association in an
       * existing stack, which is a replacement, not a property change.
       */
      subnetConfiguration: [
        { name: 'Public', subnetType: ec2.SubnetType.PUBLIC, mapPublicIpOnLaunch: false },
        { name: 'Private', subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      ],
      // Flow logs are on because this VPC carries source code being scanned and
      // the findings about it; without them a suspected exfiltration has nothing
      // to investigate.
      flowLogs: {
        Vpc: {
          destination: ec2.FlowLogDestination.toCloudWatchLogs(
            // Retained for the same reason, one step removed: forensics you
            // delete on teardown are not forensics. This is the highest-volume
            // group of the set, but retention is finite so its events still age
            // out on the same schedule.
            new logs.LogGroup(this, 'VpcFlowLogs', diagnosticLogGroupProps(customerKey)),
          ),
          trafficType: ec2.FlowLogTrafficType.ALL,
        },
      },
    });

    const cluster = new ecs.Cluster(this, 'Cluster', {
      vpc,
      containerInsightsV2: ecs.ContainerInsights.ENABLED,
    });

    /**
     * Retained, and this is the group the whole policy exists for.
     *
     * A deployment that trips the ECS circuit breaker rolls back, and the
     * container stderr saying why lived here — so rollback destroyed the evidence
     * for the rollback. The ECS-owned container-insights group survives but
     * carries only performance metrics, no stderr. See
     * `diagnosticLogGroupProps`.
     */
    const logGroup = new logs.LogGroup(this, 'TaskLogs', diagnosticLogGroupProps(customerKey));

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
        image.workloadTagForFlavor('mcp'),
      ),
      logging: ecs.LogDrivers.awsLogs({ streamPrefix: 'ash-mcp', logGroup }),
      // A scanner that dies takes the server's usefulness with it, so let ECS
      // replace the task rather than serve a half-working one.
      essential: true,
      portMappings: [{ containerPort: MCP_PORT, protocol: ecs.Protocol.TCP }],
      environment: config.mcpEnvironment(),
    });

    config.grantRead(taskDefinition.taskRole);

    /*
     * Terminates the access-log chain, and self-logs because something has to.
     *
     * MEASURED, against checkov rather than inferred from its rule name:
     * `CKV_AWS_18` inspects `Properties/LoggingConfiguration` and accepts ANY value
     * there. A bucket naming itself passes, a bucket carrying only a `LogFilePrefix`
     * passes, and a bucket with no `LoggingConfiguration` fails. So every bucket in a
     * chain needs one, the chain cannot be infinite, and the last link has to point
     * at itself. Adding a further bucket does not avoid that - it relocates the
     * finding one hop.
     *
     * Given the self-reference is forced, the only real decision is WHICH bucket
     * makes it, and it should be the quietest one. `accessLogArchiveProps` carries
     * that argument in full, along with the bound on what the loop can accumulate.
     */
    const logArchiveBucket = new s3.Bucket(this, 'AccessLogsArchive', accessLogArchiveProps());

    const accessLogsBucket = new s3.Bucket(this, 'AccessLogs', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      // The load balancer writes each log file under a unique key, so versioning
      // creates no noncurrent versions here and needs no expiration rule to bound
      // it. It is on because the bucket's posture should not depend on the write
      // pattern of whatever happens to be delivering into it today.
      versioned: true,
      // This bucket holds the record of who reached the load balancer, so access to
      // IT is worth recording too.
      serverAccessLogsBucket: logArchiveBucket,
      serverAccessLogsPrefix: 'access-logs/',
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

      /*
       * Discard a request carrying a header the load balancer cannot parse, rather
       * than forwarding it to the container.
       *
       * The default is to pass such a header through, which is what makes request
       * smuggling possible: a malformed header the ALB tolerates and the container
       * interprets differently lets one HTTP request be read as two. ASH's MCP
       * server is a streamable-HTTP endpoint that accepts source code, so a second
       * request smuggled past the load balancer is a request that was never
       * authorized by anything in front of it.
       *
       * Free and behaviour-neutral for any client that sends valid headers, which
       * is why it is on unconditionally rather than behind a parameter.
       */
      dropInvalidHeaderFields: true,
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

    /**
     * The task's egress, narrowed from CDK's default of every IP protocol to TCP 443.
     *
     * `FargateService` otherwise creates this group itself with `allowAllOutbound`,
     * which renders as one rule with `IpProtocol: -1` to `0.0.0.0/0` -- cfn-nag's
     * CFN_NAG_W40 and CFN_NAG_W5 respectively. Pinning one port clears W40 and also
     * CFN_NAG_W29, which passes only when FromPort equals ToPort. W5 survives and its
     * reason is recorded in .ash/.ash.yaml.
     *
     * WHY 0.0.0.0/0 STAYS
     * -------------------
     * The task runs in a private subnet with `assignPublicIp` disabled and this
     * stack creates no VPC endpoint, so everything it sends -- the image pull, the
     * awslogs delivery, the Systems Manager and Secrets Manager reads, and whatever
     * the scanners fetch -- leaves through the NAT gateway to a public endpoint.
     *
     * AWS-managed prefix lists would be the way to name those endpoints, and none of
     * them is covered. The published set is CloudFront origin-facing, DynamoDB, EC2
     * Instance Connect, Ground Station, Route 53 health checkers, S3, S3 Express One
     * Zone, VPC Lattice, and Secrets Manager's MANAGED EXTERNAL SECRETS ranges --
     * that last one is not the Secrets Manager API endpoint, so it does not help
     * here. Nothing covers ECR, CloudWatch Logs, the Secrets Manager endpoint or
     * Systems Manager.
     * https://docs.aws.amazon.com/vpc/latest/userguide/working-with-aws-managed-prefix-lists.html
     *
     * Naming them instead needs interface endpoints, billed hourly per Availability
     * Zone, which is the cost already recorded against CKV_AWS_117.
     *
     * WHAT 443 COVERS, AND THE LIMITATION IT INTRODUCES
     * ------------------------------------------------
     * Everything THIS STACK reaches is 443: the ECR image pull, CloudWatch Logs via
     * the awslogs driver, and the Secrets Manager and Systems Manager reads that
     * `config.grantRead` grants. DNS is unaffected either way, because "You cannot
     * filter traffic to or from the Amazon DNS server using network ACLs or security
     * groups."
     * https://docs.aws.amazon.com/vpc/latest/userguide/AmazonDNS-concepts.html
     *
     * What is NOT covered is egress the SCANNED repository decides. The npm-audit
     * scanner runs `npm`, `yarn` or `pnpm audit` against whatever registry that
     * repository configures, and corepack fetches the package manager it pins -- see
     * the corepack note in the Dockerfile. So a scan fails to fetch when the source
     * under scan needs any of:
     *
     *   - a registry served over plain HTTP on port 80;
     *   - a registry on a non-standard port, such as an internal mirror on 8080;
     *   - a `git:` dependency, which is port 9418, or a `git+ssh:` one, which is 22.
     *
     * READ THIS BEFORE DEBUGGING SUCH A SCAN. The symptom is not a permission error.
     * The security group DROPS the packet rather than rejecting it, so the scanner
     * hangs until its own timeout and then reports a fetch failure or a registry
     * that is unreachable. Nothing in the ASH output names the security group, which
     * is what makes this expensive to diagnose without this comment.
     *
     * THE WAY OUT, so an adopter does not have to edit this template: the group id is
     * the `TaskSecurityGroupId` output. Authorize further egress against it directly,
     * the same way `McpSecurityGroupId` is the handle for widening INGRESS. The
     * output's description carries the command.
     *
     * The other cost, stated rather than hidden: creating the group here rather than
     * letting the service create it moves its construct path, so an existing stack
     * replaces the security group and its load-balancer ingress rule on update. The
     * ECS service is updated to the new group before the old one is deleted. The
     * alternative -- overwriting the rendered rule through the L1 -- would have
     * kept the logical id, but would leave the L2 still believing outbound is open,
     * so a later `connections.allowTo` would be dropped with only a synth warning.
     */
    const serviceSecurityGroup = new ec2.SecurityGroup(this, 'ServiceSecurityGroup', {
      vpc,
      description:
        'ASH MCP tasks. Egress is TCP 443 only; widen it against TaskSecurityGroupId ' +
        'for a registry on another port. See ash-fargate-stack.ts.',
      allowAllOutbound: false,
    });
    serviceSecurityGroup.addEgressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(443),
      'Image pull, log delivery, and SSM and Secrets Manager reads, all via NAT.',
    );

    const service = new ecs.FargateService(this, 'Service', {
      cluster,
      taskDefinition,
      securityGroups: [serviceSecurityGroup],
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
     * SO THE POSTURE STAYS CLOSED, AND `McpIngressCidr` IS THE WAY TO OPEN IT
     * ---------------------------------------------------------------------
     * `open: false` is kept, and the parameter defaults to empty, so an adopter
     * who sets nothing gets exactly the behaviour above — no ingress rule, nothing
     * reachable, and no new rule appearing on an update of an existing stack.
     * Setting it adds one rule for that CIDR on the listener port.
     *
     * Both halves are needed and neither is sufficient. Correcting the output text
     * without a parameter leaves the adopter with an accurate message and no way to
     * act on it, which is the same documented-but-unreachable defect wearing
     * different clothes. Adding the parameter without correcting the output leaves
     * the stack claiming a reachability it does not have until someone sets it.
     *
     * REJECTED: defaulting to this VPC's CIDR. The stack creates its own VPC and
     * puts nothing in it but the ASH tasks, so that rule would admit a range
     * containing no clients while still widening access. Real consumers arrive from
     * a peered VPC, a VPN or a transit gateway, none of which fall inside it.
     *
     * REJECTED: an `IPeer` list or a comma-separated CIDR list. One CIDR covers the
     * common case, and `McpSecurityGroupId` is still an output, so an adopter
     * needing several sources authorizes the rest against that group directly —
     * which is also how to use `--source-group` instead of a CIDR.
     */
    const listener = loadBalancer.addListener('Listener', {
      port: 80,
      protocol: elbv2.ApplicationProtocol.HTTP,
      open: false,
    });

    /**
     * `Fn::If` on the rule's existence, not on its CIDR.
     *
     * `McpIngressCidr` is a deploy-time parameter, so the choice cannot be made at
     * synth time. Emitting the rule unconditionally with a conditional CIDR was
     * rejected: there is no CIDR value that means "no access", and `0.0.0.0/32`
     * would be a real rule that merely looks inert. Gating the RESOURCE on the
     * condition means the empty default emits no ingress rule at all, which is
     * what preserves the closed posture byte for byte.
     */
    const ingressSupplied = new CfnCondition(this, 'McpIngressCidrSupplied', {
      expression: Fn.conditionNot(Fn.conditionEquals(ingressCidr.valueAsString, '')),
    });
    const ingressRule = new ec2.CfnSecurityGroupIngress(this, 'McpIngress', {
      groupId: loadBalancer.connections.securityGroups[0].securityGroupId,
      ipProtocol: 'tcp',
      fromPort: 80,
      toPort: 80,
      cidrIp: ingressCidr.valueAsString,
      description: 'MCP clients allowed by McpIngressCidr.',
    });
    ingressRule.cfnOptions.condition = ingressSupplied;
    suppressParameterizedIngressRule(ingressRule);

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
    /*
     * `suppressLogBucketSelfLogging` used to sit here, on `accessLogsBucket`.
     *
     * It is gone because the finding it silenced is now FIXED rather than
     * suppressed: that bucket delivers its server access logs to
     * `AccessLogsArchive`, so `AwsSolutions-S1` passes on it outright. The archive
     * bucket passes too, because cdk-nag's rule accepts a `LogFilePrefix` with no
     * destination, which is the self-reference. The reasoning the old suppression
     * carried has not been discarded, only moved: it is the design argument in
     * `accessLogArchiveProps`, where the choice of WHICH bucket self-logs is made.
     */
    suppressTaskDefinitionEnvironment(taskDefinition);
    /*
     * A FAMILY OF CLOUDFORMATION SPEC WARNINGS IS EXPECTED HERE. ALL FALSE POSITIVES.
     *
     * `cdk synth` reports "SecretString: length 0 is below minimum 1" and, on the
     * AgentCore stack, "RequestHeaderAllowlist.{}: '' does not match pattern".
     * Since `KmsKeyArn` arrived there are three more, on every resource that takes
     * the key: "KmsKeyId: Value is not valid under any of the given schemas",
     * "KmsKeyId: '' does not match pattern '^arn:...kms:...(key|alias)/.+'" and
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

    suppressCodeBuildRoleWildcards(taskDefinition.executionRole!);

    new CfnOutput(this, 'McpEndpoint', {
      description:
        'MCP endpoint. The load balancer is internal, and reachable only from the range ' +
        'given in McpIngressCidr. If you left that empty there is NO ingress rule, so ' +
        'this address is not reachable from anywhere — set McpIngressCidr, or authorize ' +
        'McpSecurityGroupId directly. Append the McpMountPath value. Plain HTTP.',
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
    /*
     * The egress counterpart of McpSecurityGroupId above, and it exists for the same
     * reason: a rule an adopter cannot widen without editing the template is worse
     * than the finding it clears.
     *
     * The task's egress is TCP 443 only, which covers every service this stack
     * itself reaches but not a package registry the SCANNED repository points at on
     * another port. The comment on `serviceSecurityGroup` lists the cases and says
     * why the failure looks like a scanner timeout rather than a denial.
     */
    new CfnOutput(this, 'TaskSecurityGroupId', {
      description:
        "The ASH task's security group. Egress is TCP 443 only, which covers ECR, " +
        'CloudWatch Logs, Secrets Manager and Systems Manager. If a scanned repository ' +
        'resolves dependencies from a registry on another port, add that port, for ' +
        'example: aws ec2 authorize-security-group-egress --group-id <this> --protocol ' +
        'tcp --port 8080 --cidr <your-registry-cidr>. A missing rule shows up as a ' +
        'scanner timing out or failing to fetch, not as a permission error.',
      value: serviceSecurityGroup.securityGroupId,
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
