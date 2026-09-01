/**
 * cdk-nag suppressions, each with the reason it is justified.
 *
 * THE RULE THIS FILE FOLLOWS: a finding is FIXED unless the fix is impossible or
 * would make the deployment worse. Only then is it suppressed, and the
 * suppression states why in terms a reviewer can check. Nothing here is
 * suppressed to make the output quiet.
 *
 * What was fixed rather than suppressed, for contrast:
 * - AwsSolutions-VPC7 — VPC flow logs are enabled.
 * - AwsSolutions-ELB2 — ALB access logs are enabled.
 * - AwsSolutions-CB4  — CodeBuild projects use a customer-managed KMS key.
 * - AwsSolutions-IAM4 — the AWS managed `AWSLambdaBasicExecutionRole` is
 *                       replaced by a logs policy scoped to one log group.
 * - AwsSolutions-L1   — Lambda functions run the newest available Python runtime.
 * - AwsSolutions-S1   — every bucket delivers server access logs, including the
 *                       access-log buckets themselves. This one used to be
 *                       suppressed here, by `suppressLogBucketSelfLogging`. The
 *                       argument that suppression made is still true and still
 *                       needed, so it moved rather than vanished: it is now the
 *                       design comment on `accessLogArchiveProps` in
 *                       ash-config.ts, which decides which single bucket in a
 *                       log chain points at itself.
 *
 * WHY IAM5 SUPPRESSIONS HERE DO NOT USE `appliesTo`
 * ------------------------------------------------
 * The granular form needs strings like
 * `Resource::arn:<AWS::Partition>:logs:...:/aws/codebuild/<MergeProject4EB0C9A5>:*`,
 * which embed CDK logical ids. Those change whenever a construct is renamed or
 * moved, and a stale `appliesTo` fails open — the suppression silently stops
 * matching and the finding reappears, or worse, matches something else. A
 * resource-level suppression whose reason enumerates every wildcard in that
 * policy is checkable by a reviewer and does not rot. Where a policy is written
 * by hand in this app, the wildcard is also justified at the call site.
 */

import { NagSuppressions } from 'cdk-nag';
import { IConstruct } from 'constructs';

/**
 * The wildcards CDK's own CodeBuild project role always contains.
 *
 * CodeBuild writes to a log STREAM inside its log group, and a report group name
 * is suffixed per report, so neither can be named exactly ahead of time. ECR's
 * authorization token is an account-level operation with no resource ARN at all —
 * see the IAM reference for `ecr:GetAuthorizationToken`. The S3 wildcard is object
 * access within one bucket this stack owns, not bucket-level access.
 */
export function suppressCodeBuildRoleWildcards(scope: IConstruct): void {
  NagSuppressions.addResourceSuppressions(
    scope,
    [
      {
        id: 'AwsSolutions-IAM5',
        reason:
          'Inherent to CodeBuild and ECR, not a broadening of scope. The wildcards are: ' +
          '(1) the log-stream suffix on this project\'s own CloudWatch log group, which is ' +
          'created per build; (2) the per-report suffix on this project\'s own report group; ' +
          '(3) ecr:GetAuthorizationToken, which IAM defines with no resource ARN, so "*" is ' +
          'the only valid value; (4) object-level access inside buckets created by this ' +
          'stack. None of them reach a resource outside this stack.',
      },
    ],
    true,
  );
}

/**
 * The Lambda-side equivalent, for the inline logs policy.
 *
 * A log group's streams cannot be enumerated in advance, so `:*` on the group's
 * own ARN is the narrowest expressible grant for `logs:PutLogEvents`.
 */
export function suppressLambdaLogWildcard(scope: IConstruct): void {
  NagSuppressions.addResourceSuppressions(
    scope,
    [
      {
        id: 'AwsSolutions-IAM5',
        reason:
          "The only wildcard is the log-stream suffix on the function's own log group. " +
          'Lambda creates a stream per execution environment, so the stream name is not ' +
          'knowable at deploy time and ":*" on that one group is the narrowest grant that ' +
          'permits logging at all.',
      },
    ],
    true,
  );
}

/**
 * CodePipeline's generated roles.
 *
 * The pipeline needs object access across its artifact bucket and the ability to
 * assume the per-action roles it created. Both are scoped to resources this stack
 * owns.
 */
export function suppressPipelineRoleWildcards(scope: IConstruct): void {
  NagSuppressions.addResourceSuppressions(
    scope,
    [
      {
        id: 'AwsSolutions-IAM5',
        reason:
          'Object-level access within the artifact and source buckets this stack creates, ' +
          'plus assuming the per-action roles this stack creates. CodePipeline cannot name ' +
          'the artifact object keys in advance because they are generated per execution.',
      },
    ],
    true,
  );
}

/**
 * Rules cdk-nag could not evaluate because the property is an intrinsic.
 *
 * This is a cdk-nag limitation, not a finding. It shows up on the AgentCore
 * execution role (ARNs built from pseudo-parameters) and on the CodeBuild
 * projects whose environment image is an `Fn::Join` over the ECR repository
 * attributes. Suppressing the failure is recorded explicitly so nobody reads a
 * clean run as "every rule passed" when one rule could not run.
 */
export function suppressUnevaluableRules(scope: IConstruct, ruleIds: string[]): void {
  NagSuppressions.addResourceSuppressions(
    scope,
    [
      {
        id: 'CdkNagValidationFailure',
        reason:
          'cdk-nag cannot evaluate these properties because they resolve to CloudFormation ' +
          'intrinsics rather than literals: the ECR image URI is an Fn::Join over the ' +
          'repository attributes, and the IAM resources are built from pseudo-parameters so ' +
          'the templates stay account- and region-agnostic. Rules affected: ' +
          `${ruleIds.join(', ')}. Recorded rather than silently ignored — these rules did ` +
          'not run, so they neither passed nor failed.',
      },
    ],
    true,
  );
}

/**
 * `AwsSolutions-EC23` on the MCP ingress rule, whose CIDR is a parameter.
 *
 * Separate from `suppressUnevaluableRules` on purpose: that helper's reason names
 * ECR image URIs and pseudo-parameter ARNs, and reusing it here would attach a
 * false explanation to a real gap.
 *
 * EC23 exists to catch a security group opened to `0.0.0.0/0`. It cannot run on
 * this rule, because `CidrIp` is an `Fn::Ref` to `McpIngressCidr` and the rule
 * reports a validation failure rather than a verdict. What makes suppressing it
 * honest is that the constraint has not been dropped — `mcpIngressCidr` rejects a
 * `/0` prefix at parameter validation, which is where a deploy-time value is
 * actually available. So the check moved rather than disappeared.
 */
export function suppressParameterizedIngressRule(scope: IConstruct): void {
  NagSuppressions.addResourceSuppressions(scope, [
    {
      id: 'CdkNagValidationFailure',
      reason:
        'AwsSolutions-EC23 cannot evaluate CidrIp because it is an Fn::Ref to the ' +
        'McpIngressCidr parameter, so it resolves to a non-primitive. The rule did not ' +
        'run — it neither passed nor failed. The property it checks is enforced instead ' +
        'by that parameter\'s AllowedPattern, which rejects a /0 prefix, so an ' +
        'open-to-the-world CIDR is refused at parameter validation rather than reaching ' +
        'this resource. Granting more broadly is done deliberately against the ' +
        'McpSecurityGroupId output.',
    },
  ]);
}

/**
 * The Secrets Manager secret that holds the MCP shared secret.
 *
 * Rotation is not merely unconfigured; it would be actively wrong here. ASH reads
 * the value once, at container start, and passes it to
 * `ash mcp --auth-header-value`. A rotation would change the expected value while
 * every running task kept comparing against the old one, so callers would start
 * failing authentication until each task happened to restart — and nothing would
 * report why. Callers are configured with the same value out of band, so a
 * rotation has to be coordinated with them in any case.
 */
export function suppressSecretRotation(scope: IConstruct): void {
  NagSuppressions.addResourceSuppressions(scope, [
    {
      id: 'AwsSolutions-SMG4',
      reason:
        'Automatic rotation would break authentication rather than improve it. ASH resolves ' +
        'this value once at container start and compares every request against it, so a ' +
        'rotated secret leaves running tasks validating the old value while callers send the ' +
        'new one, with no signal. The value is a shared secret the adopter also configures ' +
        'on the calling side, so any change has to be coordinated with callers regardless. ' +
        'Rotate by updating the secret and restarting the tasks.',
    },
  ]);
}

/**
 * The ECS task definition's environment variables.
 *
 * AwsSolutions-ECS2 wants no plaintext environment variables. Everything in this
 * map is non-secret configuration — a port, a mount path, a boolean, an SSM
 * parameter NAME and a Secrets Manager ARN. The one actual secret is deliberately
 * NOT here: the container receives the ARN and resolves it at start, which is the
 * behaviour the rule is trying to encourage.
 */
export function suppressTaskDefinitionEnvironment(scope: IConstruct): void {
  NagSuppressions.addResourceSuppressions(
    scope,
    [
      {
        id: 'AwsSolutions-ECS2',
        reason:
          'No secret is in this environment map. It carries a port, a mount path, two ' +
          'booleans, a Host allowlist, a header NAME, an SSM parameter NAME and a Secrets ' +
          'Manager ARN. The secret value itself is fetched inside the container from that ' +
          'ARN, so it never enters the task definition — which is what this rule is asking ' +
          'for. AgentCore offers only a plaintext environment map, so the same indirection ' +
          'is used across both targets for one code path.',
      },
    ],
    true,
  );
}

