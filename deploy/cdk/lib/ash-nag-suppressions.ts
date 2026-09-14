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
 *
 * WHY NOTHING HERE USES `applyToChildren: true` ANY MORE
 * -----------------------------------------------------
 * It used to, and it was writing 225 of the app's 298 suppression entries onto
 * resources that never consulted them. `applyToChildren` walks the whole subtree
 * and writes the metadata onto every L1 it finds, so suppressing IAM5 on a role put
 * a ~450-byte reason on the role, on its CodeBuild project, and on every policy --
 * when only the policies holding a wildcard ever read it.
 *
 * That is a fifth to a third of a committed template spent on metadata nothing
 * reads, and for the two inline-launchable stacks it was the difference between
 * fitting CloudFormation's 51,200-byte `--template-body` cap and not. The header of
 * test/ash-template-size.test.ts has the measurement, and records why the cap
 * cannot be paid for with unindented JSON instead.
 *
 * SO EVERY SUPPRESSION HERE IS APPLIED TO THE RESOURCES THAT CONSUME IT, and the
 * classification is cdk-nag's own per-(rule, resource) verdict rather than a
 * reading of which rule looks applicable. Those two differ, and the difference is
 * not academic: when a rule THROWS on a resource cdk-nag reports SUPPRESSED_ERROR
 * and writes no SUPPRESSED row, so an entry that is load-bearing looks unused to
 * anything counting only SUPPRESSED. `AshAgentCore/RuntimeRole/LogsAccess` is
 * exactly that case, and dropping its entry on that reading turns a
 * SUPPRESSED_ERROR into an ERROR.
 *
 * WHAT MAKES NARROWING SAFE RATHER THAN A GAMBLE: every rule involved is
 * ERROR-level, so a suppression that is now too narrow does not fail open. The
 * finding, or the unsuppressed validation failure, comes back as a cdk-nag error
 * and fails synth. Too wide only costs bytes; too narrow is loud. That asymmetry is
 * why this is expressed as "the resources that consume it" rather than defended
 * with a belt-and-braces subtree walk.
 */

import { CfnResource } from 'aws-cdk-lib';
import { NagPackSuppression, NagSuppressions } from 'cdk-nag';
import { IConstruct } from 'constructs';

/**
 * The resource types `AwsSolutions-IAM5` reads a policy document off.
 *
 * A role, user or group can carry inline `Policies` too and IAM5 does look at
 * those -- but nothing in this app writes them. Every grant reaches a role through
 * `addToPrincipalPolicy`, which produces a separate `AWS::IAM::Policy`. Measured
 * over all five stacks, IAM5's verdict on every `AWS::IAM::Role` here is COMPLIANT,
 * which is why dropping the entry from roles changes no verdict. A role that later
 * gained a wildcard inline policy would go NON_COMPLIANT and fail synth, which is
 * the visible direction.
 */
const IAM_POLICY_DOCUMENT_TYPES = ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy'];

/**
 * Apply `suppressions` to the IAM policy resources under `scope`, and to nothing
 * else in the subtree.
 *
 * REPLACES `applyToChildren: true` FOR EVERY IAM5 SUPPRESSION IN THIS FILE. The
 * subtree still has to be walked rather than the scope suppressed directly, because
 * the resource carrying the finding is usually not the one the caller holds: a
 * role's wildcards live in the `AWS::IAM::Policy` children CDK generates for it,
 * and `codepipeline.Pipeline` generates a role per action several levels down.
 * Walking finds those; naming them would be the `appliesTo` rot the header rejects.
 *
 * Throws on an empty match rather than returning quietly. A caller that hands this
 * a scope holding no policy is either suppressing the wrong construct or running
 * before the policy exists, and both are silent otherwise -- the first spends no
 * bytes and protects nothing, the second is the timing trap `onPolicyCreated`
 * exists for (see ash-policy-split.ts).
 */
function suppressPolicyWildcards(scope: IConstruct, suppressions: NagPackSuppression[]): void {
  const policies = new Set<CfnResource>();
  for (const construct of scope.node.findAll()) {
    const l1 = construct.node.defaultChild ?? construct;
    if (l1 instanceof CfnResource && IAM_POLICY_DOCUMENT_TYPES.includes(l1.cfnResourceType)) {
      policies.add(l1);
    }
  }
  if (policies.size === 0) {
    throw new Error(
      `No ${IAM_POLICY_DOCUMENT_TYPES.join(' or ')} resource under ${scope.node.path} to ` +
        'suppress. Either the wrong construct was passed, or this ran before the policy was ' +
        'created -- see onPolicyCreated in ash-policy-split.ts.',
    );
  }
  NagSuppressions.addResourceSuppressions([...policies], suppressions);
}

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
  suppressPolicyWildcards(scope, [
    {
      id: 'AwsSolutions-IAM5',
      reason:
        'Inherent to CodeBuild and ECR, not a widening of scope. The wildcards are: ' +
        '(1) the per-build log-stream suffix on this project\'s own log group; ' +
        '(2) the per-report suffix on its own report group; ' +
        '(3) ecr:GetAuthorizationToken, which IAM defines with no resource ARN, so "*" is ' +
        'the only valid value; (4) object-level access inside buckets this stack creates. ' +
        'None of them reach a resource outside this stack.',
    },
  ]);
}

/**
 * Both CodeBuild-role suppressions, for one policy produced by the per-service
 * split in ash-policy-split.ts.
 *
 * Pass this as that role's `onPolicyCreated`. It has to run per policy AS THE
 * POLICY IS CREATED rather than once over the role, because a suppression applied
 * to a scope only reaches the resources that exist when it is applied — and a
 * grant made later creates a policy resource the earlier walk could not see. The
 * measured case is the artifact-bucket read `codepipeline_actions.CodeBuildAction`
 * adds to a project's role while the pipeline is assembled.
 *
 * `AwsSolutions-IAM5` for the wildcards, which are the same wildcards as before
 * the split and are enumerated in `suppressCodeBuildRoleWildcards`.
 *
 * IT USED TO ADD `CdkNagValidationFailure` TOO, AND THE SPLIT IS WHY IT NO LONGER
 * DOES. The argument for it was that a policy whose resources are all
 * CloudFormation intrinsics makes IAM5 throw rather than pass or fail, which was
 * true of the single `DefaultPolicy` these statements used to share. It stopped
 * being true when they were filed per service: measured across all five stacks,
 * IAM5 throws on no split CodeBuild policy, so the entry was written 40-odd times
 * app-wide and consulted never. Keeping a suppression whose justification names a
 * state the code left behind is how the next reader concludes it is load-bearing.
 *
 * If IAM5 ever does throw on one of these again, the error is not suppressed and
 * synth fails naming the resource. That is the outcome to fix at the time, with the
 * reason `suppressUnevaluableRules` gives, rather than pre-suppressed here.
 */
export function suppressSplitCodeBuildPolicy(policy: IConstruct): void {
  suppressCodeBuildRoleWildcards(policy);
}

/**
 * The wildcards on the AgentCore execution role, which the per-service split made
 * visible for the first time.
 *
 * These grants did not change. What changed is that cdk-nag can now evaluate
 * them. Before the split every statement on this role shared one policy document,
 * and because some of those statements scope themselves with ARNs built from
 * pseudo-parameters, AwsSolutions-IAM5 threw on the document as a whole and was
 * recorded as a CdkNagValidationFailure. The rule therefore never reached the
 * three statements that genuinely use "*". Split per service, those three sit in
 * documents the rule can read, and it correctly reports them.
 *
 * So this suppression is not new permissiveness; it is a finding that was masked
 * becoming a finding that is stated. Each of the three is a wildcard IAM itself
 * requires:
 *
 *   * `ecr:GetAuthorizationToken` is an account-level operation that IAM defines
 *     with no resource ARN, so "*" is the only value it accepts.
 *   * The four X-Ray actions the AgentCore runtime needs for tracing are likewise
 *     defined with no resource ARN.
 *   * `cloudwatch:PutMetricData` has no resource ARN either. It is scoped by the
 *     `cloudwatch:namespace` condition on the statement instead, which limits it
 *     to the one namespace the runtime publishes to.
 *
 * The three live in three different policies, because the per-service split files
 * each statement under its action's service. `AGENTCORE_WILDCARD_POLICIES` names
 * them, and the call site is what decides which policies this reaches.
 */
export function suppressAgentCoreRuntimeWildcards(scope: IConstruct): void {
  suppressPolicyWildcards(scope, [
    {
      id: 'AwsSolutions-IAM5',
      reason:
        'Every wildcard on this role is an action IAM defines with no resource ARN, so "*" ' +
        'is the only value the policy will accept: ecr:GetAuthorizationToken, the four ' +
        'X-Ray tracing actions, and cloudwatch:PutMetricData. PutMetricData is scoped by a ' +
        'cloudwatch:namespace condition on its statement rather than by a resource. ' +
        'Nothing here reaches a resource outside this stack, and no statement was ' +
        'widened to obtain this suppression.',
    },
  ]);
}

/**
 * The construct ids of the AgentCore runtime role's policies that hold a wildcard.
 *
 * WHY NAMING THEM IS NOT THE `appliesTo` ROT THIS FILE REFUSES ELSEWHERE. These are
 * not logical ids and not ARN fragments: `policyGroupFor` in ash-policy-split.ts
 * derives a policy's construct id from its statements' action service, so
 * `ecr:GetAuthorizationToken` lands in `EcrAccess` by construction and cannot land
 * anywhere else. The three entries here correspond one-to-one with the three
 * `resources: ['*']` statements in ash-agentcore-stack.ts.
 *
 * And it fails closed. A wildcard added under a fourth service gets no suppression,
 * so ERROR-level IAM5 reports it and synth fails naming the policy. A stale
 * `appliesTo` fails the other way, which is the whole reason the header rejects it.
 *
 * `LogsAccess` is deliberately absent. IAM5 throws on it rather than reporting a
 * wildcard -- its ARNs are assembled from pseudo-parameters -- so what it needs is
 * the `CdkNagValidationFailure` entry, applied at the call site. Listing it here as
 * well would suppress the same throw twice: `NagPack.ignoreRule` walks
 * `rules_to_suppress` in array order and returns on the first match, so the second
 * entry would be metadata in the deliverable that nothing can ever read.
 */
export const AGENTCORE_WILDCARD_POLICIES = ['EcrAccess', 'XrayAccess', 'CloudwatchAccess'];

/**
 * The Lambda-side equivalent, for the inline logs policy.
 *
 * A log group's streams cannot be enumerated in advance, so `:*` on the group's
 * own ARN is the narrowest expressible grant for `logs:PutLogEvents`.
 */
export function suppressLambdaLogWildcard(scope: IConstruct): void {
  suppressPolicyWildcards(scope, [
    {
      id: 'AwsSolutions-IAM5',
      reason:
        "The only wildcard is the log-stream suffix on the function's own log group. " +
        'Lambda creates a stream per execution environment, so the stream name is not ' +
        'knowable at deploy time and ":*" on that one group is the narrowest grant that ' +
        'permits logging at all.',
    },
  ]);
}

/**
 * CodePipeline's generated roles.
 *
 * The pipeline needs object access across its artifact bucket and the ability to
 * assume the per-action roles it created. Both are scoped to resources this stack
 * owns.
 */
export function suppressPipelineRoleWildcards(scope: IConstruct): void {
  suppressPolicyWildcards(scope, [
    {
      id: 'AwsSolutions-IAM5',
      reason:
        'Object-level access within the artifact and source buckets this stack creates, ' +
        'plus assuming the per-action roles this stack creates. CodePipeline cannot name ' +
        'the artifact object keys in advance because they are generated per execution.',
    },
  ]);
}

/**
 * Rules cdk-nag could not evaluate because the property is an intrinsic.
 *
 * This is a cdk-nag limitation, not a finding. It shows up on the AgentCore
 * execution role's logs policy (ARNs built from pseudo-parameters) and on the
 * CodeBuild projects whose environment image is an `Fn::Join` over the ECR
 * repository attributes. Suppressing the failure is recorded explicitly so nobody
 * reads a clean run as "every rule passed" when one rule could not run.
 *
 * APPLIED TO THE ONE RESOURCE THAT THROWS, NOT TO A SUBTREE
 * --------------------------------------------------------
 * This used to pass `applyToChildren: true`, and it was the single largest source of
 * dead metadata in the app: 154 of the 225 unread entries. A validation failure
 * happens on ONE resource for ONE reason -- this property, on that resource, is an
 * intrinsic -- so a suppression sprayed across a role and its six policies makes a
 * claim about five resources where no rule threw at all.
 *
 * Callers therefore pass the resource whose property is the intrinsic. Getting that
 * wrong is not silent: the unsuppressed throw is reported as a cdk-nag ERROR naming
 * the resource, and synth fails.
 *
 * THIS REASON HAS TO STAY PURE ASCII, AND THAT IS A TEMPLATE-SIZE CONSTRAINT
 * -------------------------------------------------------------------------
 * cdk-nag base64-encodes any suppression reason containing a non-ASCII character
 * and records that it did so with a sibling `"is_reason_encoded": true`. Verified
 * against cdk-nag 2.38.2 by synthesizing one plain reason beside one carrying an
 * em dash. Base64 spends 4 bytes per 3, so a 417-character reason arrives in the
 * template as 586 bytes rather than 417.
 *
 * Size is how this was noticed and not why ASCII is right. The committed template is
 * the deliverable, and an encoded reason reaches an adopter as an opaque base64
 * blob. A justification nobody can read in the artifact it ships in is not doing the
 * job it exists for.
 *
 * NO REASON IN THIS FILE IS ENCODED ANY MORE. `suppressTaskDefinitionEnvironment`
 * and `suppressParameterizedIngressRule` were the last two holding an em dash, and
 * both are now ASCII, so the app synthesizes zero `"is_reason_encoded": true`
 * entries. `.ash/.ash.yaml` describes that population from the other side, as one of
 * the mechanisms behind its SECRET-BASE64-HIGH-ENTROPY-STRING entries on these
 * templates; it is updated to say the set is empty rather than left describing a
 * population that no longer exists.
 */
export function suppressUnevaluableRules(scope: IConstruct, ruleIds: string[]): void {
  NagSuppressions.addResourceSuppressions(scope, [
    {
      id: 'CdkNagValidationFailure',
      reason:
        'cdk-nag cannot evaluate these properties because they resolve to CloudFormation ' +
        'intrinsics rather than literals: the ECR image URI is an Fn::Join over the ' +
        'repository attributes, and the IAM resources are built from pseudo-parameters so ' +
        'the templates stay account- and region-agnostic. Rules affected: ' +
        `${ruleIds.join(', ')}. Recorded rather than silently ignored: these rules did ` +
        'not run, so they neither passed nor failed.',
    },
  ]);
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
        'run: it neither passed nor failed. The property it checks is enforced instead ' +
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
 * map is non-secret configuration: a port, a mount path, a boolean, an SSM
 * parameter NAME and a Secrets Manager ARN. The one actual secret is deliberately
 * NOT here: the container receives the ARN and resolves it at start, which is the
 * behaviour the rule is trying to encourage.
 *
 * ECS2 reads `ContainerDefinitions`, which only the `AWS::ECS::TaskDefinition`
 * itself has, so this applies to that resource and nothing under it. It used to fan
 * out over the subtree and put the reason on the task role, the execution role and
 * both of their default policies as well -- five copies of a suppression for a
 * property four of those resources do not have. Those four were also the last
 * base64-encoded reasons in the app, so narrowing this removed most of that
 * population before the em dash above was replaced.
 */
export function suppressTaskDefinitionEnvironment(scope: IConstruct): void {
  NagSuppressions.addResourceSuppressions(scope, [
    {
      id: 'AwsSolutions-ECS2',
      reason:
        'No secret is in this environment map. It carries a port, a mount path, two ' +
        'booleans, a Host allowlist, a header NAME, an SSM parameter NAME and a Secrets ' +
        'Manager ARN. The secret value itself is fetched inside the container from that ' +
        'ARN, so it never enters the task definition, which is what this rule is asking ' +
        'for. AgentCore offers only a plaintext environment map, so the same indirection ' +
        'is used across both targets for one code path.',
    },
  ]);
}

