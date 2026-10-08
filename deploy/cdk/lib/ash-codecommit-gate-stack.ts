/**
 * A one-shot container Lambda that scans a CodeCommit pull request and reports
 * back on it.
 *
 * THE REPOSITORY IS THE ADOPTER'S AND THIS STACK NEVER TOUCHES ITS LIFECYCLE
 * ------------------------------------------------------------------------
 * `CodeCommitRepositoryArn` names an EXISTING repository. Nothing here creates,
 * modifies or deletes it. That is deliberate and worth stating loudly: a stack
 * that created the repository would delete it on rollback, and an adopter wiring
 * a scan into a repository full of history must never take that risk to get a
 * pull-request comment. The stack reads events about the repository and writes
 * comments to it; that is the whole blast radius.
 *
 * WHAT IT LISTENS TO
 * ------------------
 * EventBridge, `source: aws.codecommit`, `detail-type: "CodeCommit Pull Request
 * State Change"`, filtered to `pullRequestCreated` and
 * `pullRequestSourceBranchUpdated` — a new pull request and every push to it.
 * `pullRequestStatusChanged` is excluded on purpose: closing or merging a pull
 * request should not trigger a scan. Event shape verified at
 * https://docs.aws.amazon.com/codecommit/latest/userguide/monitoring-events.html
 *
 * THE COMMIT ORDERING IS THE API'S, NOT A GUESS
 * ---------------------------------------------
 * `PostCommentForPullRequest` documents `beforeCommitId` as the destination
 * branch's commit and `afterCommitId` as the current tip of the source branch, so
 * the handler passes `detail.destinationCommit` and `detail.sourceCommit` in that
 * order. Swapping them attaches the comment to the wrong diff.
 * https://docs.aws.amazon.com/codecommit/latest/APIReference/API_PostCommentForPullRequest.html
 *
 * THE APPROVAL GATE IS NOT FULLY DECLARATIVE, AND CANNOT BE
 * --------------------------------------------------------
 * When `ApprovalGate` is on, the function votes with
 * `UpdatePullRequestApprovalState` (`APPROVE` on a clean scan, `REVOKE`
 * otherwise). For that vote to actually BLOCK a merge, an approval rule must
 * require an approval from this function's role. CloudFormation has no resource
 * type for a CodeCommit approval rule template, so the stack cannot create one —
 * it outputs the role ARN and the two CLI commands instead. Claiming the gate
 * blocks merges without that step would be false.
 *
 * HARD LIMITS, STATED RATHER THAN HIDDEN
 * --------------------------------------
 * - Lambda's ceiling is 900 seconds
 *   (https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html).
 *   A repository or scanner set that needs longer will be killed. The gate then
 *   reports an error rather than passing, but it cannot finish the work. Adopters
 *   who outgrow it should use the sharded CodePipeline target.
 * - The clone plus ASH's output live in /tmp, whose size is the function's
 *   ephemeral storage (512 MB to 10,240 MB). This stack asks for 4 GB.
 */

import {
  Aws,
  CfnCondition,
  CfnOutput,
  CfnParameter,
  CfnRule,
  Duration,
  Fn,
  RemovalPolicy,
  Size,
  Stack,
  StackProps,
} from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';

import {
  ashOfflineMode,
  ashSynthesizer,
  AshCustomerKey,
  ashVersion,
  ashImageTag,
  codeCommitRepositoryArn,
  diagnosticLogGroupProps,
  rebuildSchedule,
  ashVpcId,
  vpcSubnetIds,
} from './ash-config';
import { AshImageBuild } from './ash-image-build';
import {
  suppressGuardRule,
  suppressLambdaLogWildcard,
  suppressScanFunctionVpcAccess,
} from './ash-nag-suppressions';
import { AshRuntimeConfig } from './ash-runtime-config';

export class AshCodeCommitGateStack extends Stack {
  constructor(scope: Construct, id: string, props: StackProps = {}) {
    super(scope, id, {
      // Before ...props, so a caller can still override it.
      synthesizer: ashSynthesizer(),
      ...props,
      description:
        'One-shot ASH scan of CodeCommit pull requests, posting results as a pull request ' +
        'comment and optionally voting on an approval rule. References an existing ' +
        'repository; never creates or deletes one.',
    });

    const version = ashVersion(this);
    const offline = ashOfflineMode(this);
    const schedule = rebuildSchedule(this);
    const repositoryArn = codeCommitRepositoryArn(this);
    const customerKey = new AshCustomerKey(this);
    const config = new AshRuntimeConfig(this, 'Config', {
      includeMcpParameters: false,
      customerKey,
    });

    const approvalGate = new CfnParameter(this, 'ApprovalGate', {
      type: 'String',
      default: 'false',
      allowedValues: ['true', 'false'],
      description:
        "Vote on the pull request's approval rules with the scan result. Requires an " +
        "approval rule that names this stack's ScanFunctionRoleArn; see the stack outputs. " +
        'With no such rule the vote is recorded but blocks nothing.',
    });

    const changedFilesOnly = new CfnParameter(this, 'ChangedFilesOnly', {
      type: 'String',
      default: 'true',
      allowedValues: ['true', 'false'],
      description:
        "Scan only files the pull request changed, using ASH's --changed-files-only " +
        '--base-ref against the destination commit. The repository is still cloned in ' +
        'full, so scanners keep whole-repository context such as lockfiles.',
    });

    const minSeverity = new CfnParameter(this, 'MinSeverity', {
      type: 'String',
      default: 'medium',
      allowedValues: ['critical', 'high', 'medium', 'low', 'none'],
      description:
        'Severity at or above which findings fail the gate. Findings below it are still ' +
        "reported in the comment. ASH treats critical and high as equivalent because SARIF " +
        'does not distinguish them.',
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
      flavors: ['lambda'],
      ashVersion: version,
      offlineMode: offline,
      rebuildSchedule: schedule,
      imageTag: ashImageTag(this),
      encryptionKey,
      customerKey,
    });

    // The repository name is the last colon-delimited field of a CodeCommit ARN,
    // which has no slashes. Deriving it avoids a second parameter that could
    // disagree with the ARN.
    const repositoryName = Fn.select(5, Fn.split(':', repositoryArn.valueAsString));

    // This group was already retained, but only by accident: it was the one that
    // omitted `removalPolicy` and so inherited CDK's RETAIN default, while the
    // groups that named a policy chose DESTROY. Stating it explicitly means the
    // behaviour no longer depends on a library default, and the split is no longer
    // invisible in the source. See `diagnosticLogGroupProps`.
    const logGroup = new logs.LogGroup(this, 'ScanLogs', diagnosticLogGroupProps(customerKey));

    // Own role rather than the AWS managed AWSLambdaBasicExecutionRole: the only
    // logging grant this function needs is on the one log group above.
    const scanRole = new iam.Role(this, 'ScanFunctionRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: 'Execution role for the ASH pull-request scan.',
    });
    scanRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
        resources: [logGroup.logGroupArn, `${logGroup.logGroupArn}:*`],
      }),
    );

    const scanFunction = new lambda.DockerImageFunction(this, 'ScanFunction', {
      role: scanRole,
      description: 'Scans a CodeCommit pull request with ASH and comments the result.',
      // fromEcr, not fromImageAsset: an asset would build the image locally at
      // synth time and push it through a bootstrap staging bucket. The image has
      // to be built in the adopter's account by the CodeBuild project.
      code: lambda.DockerImageCode.fromEcr(image.repository, {
        tagOrDigest: image.workloadTagForFlavor('lambda'),
      }),
      // 900 seconds is Lambda's maximum, not a tuned value. A gate that needs
      // more cannot run on Lambda at all.
      timeout: Duration.minutes(15),
      // ASH runs several scanners; Lambda scales CPU with memory, so this is as
      // much about CPU as about headroom.
      memorySize: 10240,
      // Clone plus ASH output, both under /tmp.
      ephemeralStorageSize: Size.gibibytes(4),
      logGroup,
      // Encrypts the four variables below at rest with the adopter's key when one
      // was supplied, and disappears when it was not. None of them is a secret -
      // the values are two booleans, a severity name and an SSM parameter NAME -
      // so this is defence in depth rather than the thing keeping a credential
      // safe. See `AshCustomerKey` in ash-config.ts.
      environmentEncryption: customerKey.key,
      /*
       * TEN CONCURRENT SCANS, AND THIS INTRODUCES A NEW WAY TO LOSE ONE.
       *
       * The number bounds a burst of pull requests: without a reservation, one busy
       * repository can take an account's entire unreserved concurrency, and each of
       * these executions holds 10 GB for up to 15 minutes. Ten is enough for a
       * normal review day on one repository and small enough that the reservation
       * itself is affordable.
       *
       * BOTH HALVES OF THE COST, BECAUSE NEITHER IS OBVIOUS:
       *
       * 1. Reserved concurrency is subtracted from the account's unreserved pool for
       *    as long as the stack exists, running or not. Ten executions is not free
       *    to the rest of the account.
       * 2. It is also a CEILING, which this function did not have before. An
       *    eleventh concurrent pull request is throttled, and the EventBridge target
       *    below retries once inside a one-hour window - so a burst that stays above
       *    ten for longer than that loses a scan, and the pull request gets no
       *    comment. There is no finite reservation that avoids this; the trade is
       *    accepted here rather than hidden, and raising the number is the lever if
       *    a repository outgrows it.
       */
      reservedConcurrentExecutions: 10,
      environment: {
        ASH_APPROVAL_GATE: approvalGate.valueAsString,
        ASH_CHANGED_FILES_ONLY: changedFilesOnly.valueAsString,
        ASH_MIN_SEVERITY: minSeverity.valueAsString,
        ASH_BASE_CONFIG_SSM_PARAMETER: config.configParameterNameOrEmpty(),
      },
    });

    /*
     * OPTIONAL VPC PLACEMENT: VpcId plus VpcSubnetIds.
     *
     * Both empty, the default, leaves the function outside any VPC, as it always was:
     * egress is then open to the internet, which is how it reaches CodeCommit, ECR,
     * Systems Manager and CloudWatch Logs with nothing to configure. Both set attaches
     * it to those subnets with a security group this stack creates in that VPC,
     * `ScanSecurityGroup`, whose only egress is TCP 443 -- the same shape as the
     * Fargate task group. The function still needs a NAT gateway or interface
     * endpoints for those four services, or every scan fails. Egress is then that
     * group plus the adopter's network ACLs and route tables, and the group id is the
     * `ScanSecurityGroupId` output, the handle for widening it.
     *
     * WHY THE STACK CREATES THE GROUP rather than taking adopter group ids. An optional
     * list parameter needs an empty default, and CDK's CloudFormation validator (which
     * ASH's cdk-nag scanner runs) substitutes parameter defaults into property values
     * on every branch while treating parameter-keyed conditions as unknown. So a `Ref`
     * to such a parameter in `SecurityGroupIds` always reads as an empty group id
     * (E1150), whichever structure carries it: an `Fn::If`, a condition-gated second
     * function, or a separate on/off parameter all still reported it. A `GetAtt` on a
     * group the stack creates cannot be empty.
     *
     * KNOWN LIMITATION: the same substitution puts `[""]` into `SubnetIds` on that
     * branch. The validator does not format-check Lambda subnet ids, so nothing reports
     * it, but nothing proves that slot non-empty either. The Rule below is what keeps a
     * real launch from reaching it empty.
     *
     * Conditions rather than a synth-time switch, so the one template serves both and
     * a console launch with nothing filled in behaves as before. The Rule refuses a
     * launch that sets only one of the two, before anything is created.
     */
    const vpcId = ashVpcId(this);
    const subnetIds = vpcSubnetIds(this);
    const scanInVpc = new CfnCondition(this, 'ScanFunctionInVpc', {
      // A CommaDelimitedList left empty resolves to [""]; see vpcSubnetIds.
      expression: Fn.conditionNot(Fn.conditionEquals(Fn.select(0, subnetIds.valueAsList), '')),
    });
    const vpcIdEmpty = Fn.conditionEquals(vpcId.valueAsString, '');
    const subnetsEmpty = Fn.conditionEachMemberEquals(subnetIds.valueAsList, '');
    new CfnRule(this, 'VpcIdWithSubnets', {
      assertions: [
        {
          assert: Fn.conditionOr(
            Fn.conditionAnd(vpcIdEmpty, subnetsEmpty),
            Fn.conditionAnd(Fn.conditionNot(vpcIdEmpty), Fn.conditionNot(subnetsEmpty)),
          ),
          assertDescription: 'Set VpcId and VpcSubnetIds together, or neither.',
        },
      ],
    });
    const scanSecurityGroup = new ec2.CfnSecurityGroup(this, 'ScanSecurityGroup', {
      vpcId: vpcId.valueAsString,
      groupDescription:
        'ASH pull-request scan function. Egress is TCP 443 only; widen it against ' +
        'ScanSecurityGroupId.',
      securityGroupEgress: [
        {
          ipProtocol: 'tcp',
          fromPort: 443,
          toPort: 443,
          cidrIp: '0.0.0.0/0',
          description: 'CodeCommit, ECR, SSM and CloudWatch Logs over HTTPS, via your NAT.',
        },
      ],
    });
    scanSecurityGroup.cfnOptions.condition = scanInVpc;
    // cfn-nag W5 (egress to 0.0.0.0/0), suppressed on this one group, for the reason
    // the Fargate task group's .ash/.ash.yaml entry records: the destinations are
    // public AWS endpoints reached through NAT, and no AWS-managed prefix list covers
    // ECR or CloudWatch Logs. Protocol and port are already pinned to TCP 443.
    scanSecurityGroup.addMetadata('cfn_nag', {
      rules_to_suppress: [
        {
          id: 'W5',
          reason:
            'Egress is TCP 443 to public AWS endpoints (CodeCommit, ECR, SSM, CloudWatch ' +
            'Logs) through the adopter NAT. No AWS-managed prefix list covers ECR or Logs, ' +
            'and naming them needs interface endpoints. Widen via ScanSecurityGroupId.',
        },
      ],
    });
    const cfnScanFunction = scanFunction.node.defaultChild as lambda.CfnFunction;
    cfnScanFunction.vpcConfig = Fn.conditionIf(
      scanInVpc.logicalId,
      { SubnetIds: subnetIds.valueAsList, SecurityGroupIds: [scanSecurityGroup.attrGroupId] },
      Aws.NO_VALUE,
    );
    const scanSecurityGroupOutput = new CfnOutput(this, 'ScanSecurityGroupId', {
      description:
        "The scan function's security group, created only when VpcId and VpcSubnetIds are " +
        'set. Egress is TCP 443 only. To reach a registry on another port: aws ec2 ' +
        'authorize-security-group-egress --group-id <this> --protocol tcp --port 8080 ' +
        '--cidr <your-registry-cidr>. A missing rule shows up as a scan timing out.',
      value: scanSecurityGroup.attrGroupId,
    });
    scanSecurityGroupOutput.condition = scanInVpc;
    /*
     * The network-interface permissions Lambda needs to attach the function, granted
     * only when it is attached. Lambda documents these as `Resource: "*"`:
     * https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html
     *
     * A separate AWS::IAM::Policy behind the same condition. Not an inline role policy:
     * cfn-guard's IAM_NO_INLINE_POLICY_CHECK rejects those, and an inline `Fn::If` is also
     * opaque to cdk-nag's IAM5, so neither checker would review it.
     *
     * ORDERING. Lambda checks the role holds these when the function is created, so the
     * policy must exist first. A `DependsOn` cannot say that: it would name a resource
     * that does not exist when the condition is false, which CloudFormation refuses
     * (cfn-lint E3005). So the dependency is carried by a `Ref` inside an `Fn::If` on the
     * SAME condition -- a tag on the function naming the policy -- which CloudFormation
     * resolves only when both exist. The tag is set as a raw property override, so a
     * future `Tags.of(...)` on this function would need to merge with it.
     *
     * The Deny is the same page's least-privilege advice. These permissions would
     * otherwise reach the function's own code too, and `lambda:SourceFunctionArn` is
     * present only on calls made by function code, so the Lambda service keeps them
     * and scanned code does not. It denies all of `ec2:*` rather than the page's seven
     * actions: the function code needs no EC2 call at all.
     */
    const vpcAccess = new iam.Policy(this, 'ScanFunctionRoleEc2Access', {
      roles: [scanRole],
      statements: [
        new iam.PolicyStatement({
          sid: 'LambdaManagesNetworkInterfaces',
          actions: [
            'ec2:CreateNetworkInterface',
            'ec2:DescribeNetworkInterfaces',
            'ec2:DescribeSubnets',
            'ec2:DeleteNetworkInterface',
            'ec2:AssignPrivateIpAddresses',
            'ec2:UnassignPrivateIpAddresses',
          ],
          resources: ['*'],
          // Keeps Resource "*" as Lambda documents, and pins the calls to this stack's
          // Region, which is the only Region the function's interfaces can live in.
          // NOT DEPLOY-TESTED: AWS does not document whether Lambda's service-side ENI
          // calls carry aws:RequestedRegion. It is a global key present on signed
          // requests, but if VPC attachment fails with a permissions error on
          // CreateNetworkInterface, this condition is the first suspect.
          conditions: { StringEquals: { 'aws:RequestedRegion': Aws.REGION } },
        }),
        new iam.PolicyStatement({
          sid: 'FunctionCodeCannotUseThem',
          effect: iam.Effect.DENY,
          actions: ['ec2:*'],
          resources: ['*'],
          conditions: { Null: { 'lambda:SourceFunctionArn': 'false' } },
        }),
      ],
    });
    const cfnVpcAccess = vpcAccess.node.defaultChild as iam.CfnPolicy;
    cfnVpcAccess.cfnOptions.condition = scanInVpc;
    // cfn-nag W12 (Resource "*"), suppressed on this one policy rather than by
    // widening the file-level entry in .ash/.ash.yaml, which covers only the image
    // build role's DefaultPolicy.
    cfnVpcAccess.addMetadata('cfn_nag', {
      rules_to_suppress: [
        {
          id: 'W12',
          reason:
            'Resource "*" on the network-interface actions Lambda documents as all-resources ' +
            'for VPC attachment; Region-pinned, created only when VpcSubnetIds is set, and ' +
            'ec2:* is denied to function code.',
        },
      ],
    });
    cfnScanFunction.addPropertyOverride('Tags', [
      Fn.conditionIf(
        scanInVpc.logicalId,
        { Key: 'ash:vpc-access-policy', Value: cfnVpcAccess.ref },
        Aws.NO_VALUE,
      ),
    ]);
    suppressScanFunctionVpcAccess(vpcAccess);
    suppressGuardRule(
      scanFunction,
      'LAMBDA_INSIDE_VPC',
      'Opt-in: set VpcId and VpcSubnetIds to confine egress to a 443-only SG and your ' +
        'NACLs. Empty (default) leaves egress open.',
    );

    scanFunction.node.addDependency(image.bootstrap!);
    config.grantRead(scanFunction);

    // Read the repository, comment on pull requests, and vote. Scoped to the one
    // repository the adopter named — nothing here can reach another repository.
    scanFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'ReadRepositoryAndComment',
        actions: [
          // GitPull is what the codecommit:// git transport authorizes against.
          'codecommit:GitPull',
          'codecommit:GetRepository',
          'codecommit:GetBranch',
          'codecommit:GetCommit',
          'codecommit:GetDifferences',
          'codecommit:GetPullRequest',
          'codecommit:PostCommentForPullRequest',
          'codecommit:UpdatePullRequestApprovalState',
        ],
        resources: [repositoryArn.valueAsString],
      }),
    );

    new events.Rule(this, 'PullRequestRule', {
      description:
        'Runs ASH when a pull request is opened on the named repository or its source ' +
        'branch is updated.',
      eventPattern: {
        source: ['aws.codecommit'],
        detailType: ['CodeCommit Pull Request State Change'],
        // `resources` carries the repository ARN, which is how the rule is
        // confined to the adopter's repository rather than every repository in
        // the account.
        resources: [repositoryArn.valueAsString],
        detail: {
          // Deliberately excludes pullRequestStatusChanged: closing or merging a
          // pull request is not a reason to scan it.
          event: ['pullRequestCreated', 'pullRequestSourceBranchUpdated'],
        },
      },
      targets: [
        new targets.LambdaFunction(scanFunction, {
          // One retry. A scan that failed for a transient reason is worth
          // repeating; a scan that fails deterministically should not be retried
          // for hours, because each attempt posts another comment.
          retryAttempts: 1,
          maxEventAge: Duration.hours(1),
        }),
      ],
    });

    suppressLambdaLogWildcard(scanRole);

    new CfnOutput(this, 'ScanFunctionRoleArn', {
      description:
        'Grant this role approval authority to make the gate binding. Create an approval ' +
        'rule template naming it, then associate the template with the repository: ' +
        '`aws codecommit create-approval-rule-template` followed by ' +
        '`aws codecommit associate-approval-rule-template-with-repository`.',
      value: scanFunction.role!.roleArn,
    });
    new CfnOutput(this, 'ScanFunctionName', { value: scanFunction.functionName });
    new CfnOutput(this, 'GatedRepositoryName', { value: repositoryName });
    new CfnOutput(this, 'EcrRepositoryUri', { value: image.repository.repositoryUri });
    new CfnOutput(this, 'ImageBuildProjectName', { value: image.project.projectName });
    new CfnOutput(this, 'BaseConfigParameterName', {
      value: config.configParameter.parameterName,
    });
  }
}
