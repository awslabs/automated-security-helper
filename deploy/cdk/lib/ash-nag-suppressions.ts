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
 * EVERY REASON IS A CLAIM ABOUT ONE POLICY, NOT ABOUT THE ROLE ABOVE IT
 * --------------------------------------------------------------------
 * This is the second half of "enumerates every wildcard in that policy", and it was
 * missing. Three helpers here used to hold a single reason that was the UNION of every
 * wildcard shape anywhere on the role, applied to every policy the per-service split
 * produced. Each such reason was true at role scope and false at every site:
 * `ImageBuildRole/KmsAccess` holds two wildcard ACTIONS and no wildcard resource, while
 * the shared reason enumerated four resource wildcards; `RuntimeRole/XrayAccess` holds
 * `Resource: "*"` for four X-Ray actions, while the shared reason also named
 * `ecr:GetAuthorizationToken` and `cloudwatch:PutMetricData`, which live in two other
 * policies. A reader checking the reason against the resource it is attached to would
 * find most of it describing something else.
 *
 * So each helper now carries one reason per POLICY, keyed on the policy's construct id,
 * and `suppressPolicyWildcardsByGroup` throws rather than guessing when it meets a
 * policy the map does not name.
 *
 * KEYING ON THE CONSTRUCT ID IS NOT THE `appliesTo` ROT REFUSED ABOVE. `policyGroupFor`
 * in ash-policy-split.ts derives a policy's construct id from its statements' action
 * service, so an `ecr:` statement lands in `EcrAccess` by construction and cannot land
 * anywhere else. The key is a service name, not a logical id and not an ARN fragment,
 * and there is nothing in it for a construct rename to invalidate. It also fails closed:
 * a wildcard granted under a service with no entry in the map is a synth-time throw
 * naming the policy, where a stale `appliesTo` would have silently stopped matching.
 *
 * WHAT WAS REJECTED. Keeping the union and hedging it -- the reasons were previously
 * phrased "every wildcard on this ROLE", which makes them true again by widening the
 * subject. That reads as accurate and tells a reviewer looking at one policy almost
 * nothing, which is the failure this file exists to prevent. Also rejected: deriving the
 * enumeration from the policy document at suppression time. `onPolicyCreated` fires
 * BEFORE the first statement is added (see `AshSplitPolicyRole.addToPrincipalPolicy`), so
 * the document is empty exactly when the reason has to be written, and the only hook that
 * sees a populated document before cdk-nag's aspect runs is another aspect registered
 * ahead of it -- an ordering dependency between aspects, which is a new silent-failure
 * mode rather than a fix for one.
 *
 * KNOWN LIMITATION, AND WHERE IT IS CAUGHT. A per-policy reason can go stale in one
 * direction the throw does not cover: a new grant inside a service that ALREADY has an
 * entry adds a wildcard the existing reason does not name, and the suppression keeps
 * matching. Three tests in test/ash-template-size.test.ts close that, all computed from
 * each policy's own committed document rather than from a list: every wildcard action a
 * policy grants has to appear in its reason, a reason may not name an IAM action its
 * policy does not grant, and a reason may claim the policy holds no wildcard only if it
 * holds none.
 *
 * WHY NOTHING HERE USES `applyToChildren: true` ANY MORE
 * -----------------------------------------------------
 * It used to, and against `main` it was writing 99 of the app's 129 suppression
 * entries onto resources that never consulted them. `applyToChildren` walks the
 * whole subtree and writes the metadata onto every L1 it finds, so suppressing IAM5
 * on a role put a ~450-byte reason on the role, on its CodeBuild project, and on
 * every policy -- when only the policies holding a wildcard ever read it.
 *
 * That is a fifth to a third of a committed template spent on metadata nothing
 * reads, and for the two inline-launchable stacks it was the difference between
 * fitting CloudFormation's 51,200-byte `--template-body` cap and not. The header of
 * test/ash-template-size.test.ts has the measurement, and records why the cap
 * cannot be paid for with unindented JSON instead.
 *
 * The figures are stated against `main` on purpose, because that is the diff a
 * reviewer reads. Measured by recording all six `INagLogger` callbacks and joining
 * each shipped `rules_to_suppress` entry to the verdicts that consulted it:
 * 129 entries -> 89, of which 99 unconsulted -> 17, and 53 base64-encoded reasons
 * -> 0. Intermediate states of this branch went higher than 129 before coming down;
 * those numbers are not the ones to quote.
 *
 * THE 17 THAT REMAIN ARE ALL IN AshDistributedPipeline, AND THEY STAY DELIBERATELY.
 * test/ash-template-size.test.ts pins the number and enumerates them, so a new
 * unconsulted entry is a test failure rather than something a reader has to tell
 * apart from the known ones. Why they are not removed: every one of them hangs off a
 * grant written by an aws-cdk-lib grant helper, not by this app, so an allowlist of
 * "the policy groups that hold a wildcard" would be a claim about aws-cdk-lib's grant
 * implementations and would rot on a CDK bump -- the same failure mode as `appliesTo`
 * above, one layer out. Six of them are worse: they are CDK-generated per-action
 * `DefaultPolicy` resources whose only distinguishing handle is the pipeline STAGE and
 * ACTION name.
 *
 * WHAT DID CHANGE ABOUT THEM IS THE TEXT. Retaining an inert entry is a byte cost;
 * retaining one whose reason describes wildcards its policy does not have is a false
 * statement in a public template, and all 17 carried one. `Shard0Project/Role/SsmAccess`
 * grants four `ssm:*Parameter*` reads on a single parameter ARN and was shipping a reason
 * about log streams and S3 object keys. Each of the four now says the thing that is
 * actually true of it -- IAM5 evaluates this policy as COMPLIANT, it holds no wildcard,
 * and the entry is kept because the statements come from an aws-cdk-lib grant helper
 * rather than from this app. `no reason claims a policy holds no wildcard unless it holds
 * none` in test/ash-template-size.test.ts is what stops that claim from outliving a grant
 * that adds one.
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

import { CfnResource, Stack } from 'aws-cdk-lib';
import { CfnManagedPolicy, CfnPolicy } from 'aws-cdk-lib/aws-iam';
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
 * The IAM policies under `scope`, each paired with the construct id that names it.
 *
 * The id is read off the OWNING L2 rather than off the L1, because the L1 under an
 * `iam.Policy` is always called `Resource` and it is the L2's id that carries the service
 * group -- `KmsAccess`, `S3Access`, `DefaultPolicy`. `node.findAll()` is parent-first, so
 * the L2 is seen first and claims the entry; the L1 is skipped when it turns up as its own
 * construct a moment later. A raw `CfnResource` passed in with no L2 above it keeps its
 * own id, which is the right answer for the only case that produces one.
 *
 * Throws on an empty match for the same reason `suppressPolicyWildcards` does, and takes
 * the timing half of that message from the caller because the two have different ones.
 */
function policyGroupsUnder(scope: IConstruct, timingHint: string): Map<CfnResource, string> {
  const found = new Map<CfnResource, string>();
  for (const construct of scope.node.findAll()) {
    const l1 = construct.node.defaultChild ?? construct;
    if (!(l1 instanceof CfnResource) || !IAM_POLICY_DOCUMENT_TYPES.includes(l1.cfnResourceType)) {
      continue;
    }
    if (l1 !== construct || !found.has(l1)) {
      found.set(l1, construct.node.id);
    }
  }
  if (found.size === 0) {
    throw new Error(
      `No ${IAM_POLICY_DOCUMENT_TYPES.join(' or ')} resource under ${scope.node.path} to ` +
        `suppress. Either the wrong construct was passed, or ${timingHint}.`,
    );
  }
  return found;
}

/**
 * Suppress `AwsSolutions-IAM5` on the policies under `scope`, giving each the reason
 * written for ITS service group.
 *
 * `reasons` is keyed by policy construct id, which `policyGroupFor` in
 * ash-policy-split.ts derives from the statements' action service. The header explains
 * why that key does not rot and why a union reason is not an acceptable substitute.
 *
 * THROWS ON A POLICY THE MAP DOES NOT NAME, AND THAT IS THE POINT. The alternative is to
 * fall back to some general reason, which is how a false justification reaches a public
 * template: nobody wrote a claim about that policy, so there is no claim to make. A
 * wildcard granted under a new service therefore fails synth naming the policy, and the
 * fix is to write the sentence. Passing a scope that holds no policy at all throws too,
 * for the reasons on `suppressPolicyWildcards`.
 *
 * IT RUNS TWICE OVER MOST POLICIES AND THAT IS SAFE. The CodeBuild and pipeline-role
 * helpers each hand this to `onPolicyCreated` AND walk the finished role, because the
 * callback is the only thing that sees a policy created by a later grant while the walk is
 * the only thing that would see a policy the callback's keying declined. (The AgentCore
 * runtime role is the exception: its call site filters by construct id inside the callback
 * and never walks, so each of its three policies is reached once.)
 * `NagSuppressionHelper.addRulesToMetadata` deduplicates entries by their serialized form,
 * so the same (id, reason) pair applied twice collapses to one -- which holds only while
 * both paths produce the SAME reason for the same policy, and is why this dispatch is a
 * pure function of the policy's construct id rather than of which path reached it.
 */
function suppressPolicyWildcardsByGroup(scope: IConstruct, reasons: Record<string, string>): void {
  const policies = policyGroupsUnder(
    scope,
    'this ran before the policy was created -- see onPolicyCreated in ash-policy-split.ts',
  );
  for (const [policy, group] of policies) {
    const reason = reasons[group];
    if (reason === undefined) {
      throw new Error(
        `No IAM5 suppression reason is written for the '${group}' policy at ` +
          `${policy.node.path}. A reason has to be true of the resource it lands on, so ` +
          'there is no default to fall back to: add an entry naming that policy\'s own ' +
          'wildcards to the map in ash-nag-suppressions.ts, or stop suppressing it. ' +
          `Known groups: ${Object.keys(reasons).sort().join(', ')}.`,
      );
    }
    NagSuppressions.addResourceSuppressions(policy, [{ id: 'AwsSolutions-IAM5', reason }]);
  }
}

/**
 * The statements of one IAM policy L1, resolved to the shape they take in the template.
 *
 * `resolve` is what turns a `Fn::GetAtt` token into the `{ "Fn::GetAtt": [...] }` object
 * the template carries, which is the form the wildcard test below has to see.
 */
function resolvedStatements(policy: CfnResource): { Effect?: string; Action?: unknown; Resource?: unknown }[] {
  if (!(policy instanceof CfnPolicy) && !(policy instanceof CfnManagedPolicy)) {
    throw new Error(`${policy.node.path} is a ${policy.cfnResourceType}, not an IAM policy.`);
  }
  const document = Stack.of(policy).resolve(policy.policyDocument);
  return document?.Statement ?? [];
}

/**
 * Whether `AwsSolutions-IAM5` would find a wildcard in this policy.
 *
 * Mirrors cdk-nag's own `analyzePolicy` (rules/iam/IAMNoWildcardPermissions): Allow
 * statements only, a wildcard ACTION counts as much as a wildcard RESOURCE, and the
 * resource is tested in its SERIALIZED form. That last part is not a detail -- after the
 * per-service split most of these ARNs are `Fn::Join` structures whose literal tail is the
 * wildcard (`:*`, `-*`, `/*`), so a check that only looked at string resources would
 * report "no wildcard" on policies cdk-nag has just raised a finding against.
 */
function holdsWildcard(policy: CfnResource): boolean {
  for (const statement of resolvedStatements(policy)) {
    if (statement.Effect !== 'Allow') {
      continue;
    }
    const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
    if (actions.some((action) => typeof action === 'string' && action.includes('*'))) {
      return true;
    }
    const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
    if (resources.some((resource) => JSON.stringify(resource ?? null).includes('*'))) {
      return true;
    }
  }
  return false;
}

/**
 * The one wildcard shape every CodeBuild project role shares, per service group.
 *
 * WHY THESE ARE SEPARATE STRINGS RATHER THAN ONE. The header has the argument; the
 * measurement behind it is that each group holds exactly one wildcard shape and holds it
 * alone. Read off the committed templates, `AwsSolutions-IAM5` reports, per policy:
 *
 *   CodebuildAccess       Resource  report-group/<Project>-*
 *   EcrAccess             Resource  *                            (GetAuthorizationToken)
 *   KmsAccess             Action    kms:GenerateDataKey*, kms:ReEncrypt*   -- no resource
 *   LogsAccess            Resource  log-group:/aws/codebuild/<Project>:*
 *   SsmAccess             (none, COMPLIANT)
 *   SecretsmanagerAccess  (none, COMPLIANT)
 *
 * IAM5 RAISES A FINDING PER WILDCARD ACTION AS WELL AS PER WILDCARD RESOURCE, which is
 * why `KmsAccess` appears here at all and why a resource-only reading of these policies
 * misses it entirely. It was a resource-only reading that produced the shared reason
 * these replace: it enumerated four resource wildcards and stopped, so on eleven
 * `KmsAccess` policies across five stacks it suppressed two findings it never mentioned.
 */
const CODEBUILD_REPORT_GROUP_REASON =
  'The only wildcard is the "-*" suffix on this project\'s own report-group ARN. CodeBuild ' +
  'derives a report group name per report and prefixes it with the project name, so the ' +
  'name is not knowable at deploy time and the prefix keeps the grant inside this ' +
  'project. No action in this policy is wildcarded.';

/** Shared with the AgentCore runtime role, which holds the identical statement pair. */
const ECR_AUTHORIZATION_TOKEN_REASON =
  'The only wildcard is Resource "*" on ecr:GetAuthorizationToken, for which IAM defines ' +
  'no resource ARN at all, so "*" is the only value the policy will accept. Every other ' +
  'action in this policy is scoped to the one ECR repository this stack creates, and no ' +
  'action is wildcarded.';

const KMS_ACTION_SUFFIX_REASON =
  'The two wildcards are the action suffixes kms:GenerateDataKey* and kms:ReEncrypt*, ' +
  'which CDK\'s key grant writes to cover the WithoutPlaintext and From/To variants. They ' +
  'widen the verb set, not the reach: every statement in this policy names the one ' +
  'customer-managed key this stack creates, so no resource here is wildcarded.';

const CODEBUILD_LOG_STREAM_REASON =
  'The only wildcard is the log-stream suffix ":*" on this project\'s own CodeBuild log ' +
  'group. A build creates a stream per run, so the stream name is not knowable at deploy ' +
  'time and ":*" on that one group is the narrowest grant that permits logging at all. No ' +
  'action in this policy is wildcarded.';

/**
 * The four groups both kinds of CodeBuild project role in this app produce, with the
 * identical wildcard in each. `S3Access` is deliberately absent: the image-build role
 * reads the artifact bucket and the scan and merge roles also write the results bucket,
 * so the two have different wildcards and get different reasons below.
 */
const CODEBUILD_SHARED_REASONS: Record<string, string> = {
  CodebuildAccess: CODEBUILD_REPORT_GROUP_REASON,
  EcrAccess: ECR_AUTHORIZATION_TOKEN_REASON,
  KmsAccess: KMS_ACTION_SUFFIX_REASON,
  LogsAccess: CODEBUILD_LOG_STREAM_REASON,
};

/**
 * The image-build project role, one policy at a time.
 *
 * Pass this as the role's `onPolicyCreated` AND call it once on the finished role: the
 * callback is the only thing that catches a policy created by a grant made later, the
 * walk is the only thing that would catch a policy the callback's keying declined, and
 * `suppressPolicyWildcardsByGroup` explains why running both is safe.
 *
 * WHY IT HAS TO RUN PER POLICY AS THE POLICY IS CREATED. A suppression applied to a scope
 * only reaches the resources that exist when it is applied, and a grant made later creates
 * a policy resource the earlier walk could not see. The measured case is the
 * artifact-bucket read `codepipeline_actions.CodeBuildAction` adds to this project's role
 * while the pipeline is assembled -- which is also why `S3Access` is in the map even
 * though nothing in ash-image-build.ts grants S3.
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
 * WHAT HAPPENS IF IAM5 THROWS ON ONE OF THESE AGAIN -- IT DOES NOT FAIL SYNTH. An
 * earlier version of this comment claimed it would, and that claim is false. A
 * validation failure is matched on EITHER of two disjuncts (cdk-nag 2.38.2,
 * nag-pack.js:120): a suppression whose `id` is the RULE's own id, or one whose `id`
 * is `CdkNagValidationFailure`. The throw path passes `ruleId` -- not
 * `VALIDATION_FAILURE_ID` -- as the first argument (nag-pack.js:93), and `doesApply`
 * returns true for any suppression whose `id` equals that ruleId once `appliesTo` is
 * absent, which this file bans everywhere. So the `AwsSolutions-IAM5` entry these
 * policies already carry absorbs an IAM5 THROW as well as an IAM5 finding:
 * `onSuppressedError` fires, not `onError`, and synth exits 0.
 *
 * WHICH MAKES THE REMOVAL MORE CLEARLY RIGHT, NOT LESS. `ignoreRule` walks
 * `rules_to_suppress` in array order and returns on the first match, and the IAM5
 * entry is applied first here, so a `CdkNagValidationFailure` entry beside it could
 * never be reached even on the throw it was added for. It was not a safety net; it was
 * 40-odd bytes-costing entries that no code path can read. The same first-match rule is
 * why `LogsAccess` is kept out of `AGENTCORE_WILDCARD_POLICIES` below.
 *
 * THE COST OF THAT, STATED PLAINLY: the reason recorded against such a throw would be the
 * per-group wildcard enumeration, which does not explain a rule that could not run. So the
 * throw stays visible -- SUPPRESSED_ERROR, which the app's compliance reports carry -- but
 * the string attached to it would be the wrong explanation. Measured at this commit there
 * is no such case: all seven throws in the app are absorbed by a `CdkNagValidationFailure`
 * entry and none by an IAM5 entry. test/ash-template-size.test.ts pins that, so a new one
 * is a test failure rather than a misleading justification shipped in a public template,
 * and test/ash-nag-gate.test.ts proves the absorption mechanism above against cdk-nag
 * itself rather than leaving it as a reading of the source.
 */
export function suppressImageBuildRoleWildcards(scope: IConstruct): void {
  suppressPolicyWildcardsByGroup(scope, {
    ...CODEBUILD_SHARED_REASONS,
    S3Access:
      'Read-only object access inside the pipeline artifact bucket this stack creates, ' +
      'which is the only bucket this policy names. RESOURCE: the "/*" object-key suffix on ' +
      'it, because CodePipeline names artifact objects per execution. ACTION: ' +
      's3:GetBucket*, s3:GetObject* and s3:List*, API-family suffixes on that same bucket ' +
      'rather than extra reach.',
  });
}

/**
 * The scan-shard and merge project roles, one policy at a time. Same two call shapes as
 * `suppressImageBuildRoleWildcards` and for the same reasons.
 *
 * TWO GROUPS HERE HOLD NO WILDCARD AT ALL, AND THEIR ENTRIES STAY. `SsmAccess` and
 * `SecretsmanagerAccess` are ten of the seventeen entries no rule consults, pinned and
 * enumerated by test/ash-template-size.test.ts; the header says why removing them would
 * be a claim about aws-cdk-lib's grant implementations rather than about this app. What
 * they must not do is carry a reason describing wildcards they do not have, which is what
 * the shared reason did to them -- `Shard0Project/Role/SsmAccess` grants four
 * `ssm:*Parameter*` reads on one parameter ARN and was shipping a sentence about log
 * streams and S3 object keys.
 */
export function suppressScanProjectRoleWildcards(scope: IConstruct): void {
  suppressPolicyWildcardsByGroup(scope, {
    ...CODEBUILD_SHARED_REASONS,
    S3Access:
      'Object access inside two buckets this stack creates: read on the pipeline artifact ' +
      'bucket, write on the results bucket. RESOURCE: the "/*" object-key suffix on each, ' +
      'because CodePipeline names artifact objects per execution and ASH writes one results ' +
      'prefix per execution. ACTION: s3:Abort*, s3:DeleteObject*, s3:GetBucket*, ' +
      's3:GetObject* and s3:List*, API-family suffixes on those same two buckets rather ' +
      'than extra reach.',
    SsmAccess:
      'This policy holds no wildcard: ssm:GetParameter and its three read siblings are ' +
      'scoped to the one Parameter Store parameter this stack creates, and no action is ' +
      'wildcarded. IAM5 reports COMPLIANT here. The entry is kept because an aws-cdk-lib ' +
      'grant helper writes these statements, so which of this role\'s service groups holds ' +
      'a wildcard is aws-cdk-lib\'s choice rather than this app\'s.',
    SecretsmanagerAccess:
      'This policy holds no wildcard: secretsmanager:GetSecretValue and ' +
      'secretsmanager:DescribeSecret are scoped to the one secret this stack creates, and ' +
      'no action is wildcarded. IAM5 reports COMPLIANT here. The entry is kept because an ' +
      'aws-cdk-lib grant helper writes these statements, so which of this role\'s service ' +
      'groups holds a wildcard is aws-cdk-lib\'s choice rather than this app\'s.',
  });
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
 * requires, and each is in a policy of its own, so each gets its own reason -- the
 * shared reason they used to carry named all three on all three, which meant two
 * thirds of every one of those sentences was about a different resource.
 */
const AGENTCORE_POLICY_REASONS: Record<string, string> = {
  EcrAccess: ECR_AUTHORIZATION_TOKEN_REASON,
  XrayAccess:
    'The only wildcard is Resource "*", which is the only value IAM accepts for the four ' +
    'X-Ray actions here: none of xray:GetSamplingRules, xray:GetSamplingTargets, ' +
    'xray:PutTelemetryRecords or xray:PutTraceSegments is defined with a resource ARN. No ' +
    'action in this policy is wildcarded.',
  CloudwatchAccess:
    'The only wildcard is Resource "*", which is the only value IAM accepts for ' +
    'cloudwatch:PutMetricData. The statement is scoped by a cloudwatch:namespace condition ' +
    'instead, limiting it to the one namespace the AgentCore runtime publishes to. No ' +
    'action in this policy is wildcarded.',
};

export function suppressAgentCoreRuntimeWildcards(scope: IConstruct): void {
  suppressPolicyWildcardsByGroup(scope, AGENTCORE_POLICY_REASONS);
}

/**
 * The construct ids of the AgentCore runtime role's policies that hold a wildcard.
 *
 * Derived from `AGENTCORE_POLICY_REASONS` rather than written out again, so the list the
 * call site filters on and the list of reasons that exist cannot drift apart. The three
 * correspond one-to-one with the three `resources: ['*']` statements in
 * ash-agentcore-stack.ts.
 *
 * WHY NAMING THEM IS NOT THE `appliesTo` ROT THIS FILE REFUSES ELSEWHERE. These are
 * not logical ids and not ARN fragments: `policyGroupFor` in ash-policy-split.ts
 * derives a policy's construct id from its statements' action service, so
 * `ecr:GetAuthorizationToken` lands in `EcrAccess` by construction and cannot land
 * anywhere else.
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
export const AGENTCORE_WILDCARD_POLICIES = Object.keys(AGENTCORE_POLICY_REASONS);

/**
 * The ECS task execution role's one wildcard.
 *
 * SPLIT OUT OF THE CODEBUILD PROJECT-ROLE HELPER, WHICH WAS THE WRONG REASON HERE. This
 * role was handed to that helper while its reason was still one role-scoped union, so the
 * AshFargate template shipped a justification naming a per-build log stream, a report
 * group and S3 object keys on a role that has none of the three and nothing to do with
 * CodeBuild. The reason was not merely over-broad, it described a different resource.
 *
 * What the resource actually holds, read off the committed AshFargate template: exactly
 * one IAM5 finding, `Resource::*` on `ecr:GetAuthorizationToken`. The ECR pull actions
 * are scoped to the repository ARN and the log writes to the task log group's ARN, so
 * neither contributes a wildcard.
 *
 * Getting this wrong in the other direction is loud rather than silent: IAM5 is
 * ERROR-level, so a wildcard this reason does not cover is reported and fails synth.
 */
export function suppressTaskExecutionRoleWildcard(scope: IConstruct): void {
  suppressPolicyWildcards(scope, [
    {
      id: 'AwsSolutions-IAM5',
      reason:
        'The only wildcard is ecr:GetAuthorizationToken, which IAM defines with no resource ' +
        'ARN, so "*" is the only value the policy will accept. The image pull and the log ' +
        'writes on this role are each scoped to one ARN this stack creates.',
    },
  ]);
}

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
 * The pipeline's OWN role, one policy at a time.
 *
 * The pipeline needs object access across its artifact bucket, and it assumes the
 * per-action roles it created. Only the first of those contributes a wildcard, and after
 * the per-service split the two are in different policies -- which is why one reason
 * cannot serve both. Same two call shapes as the CodeBuild helpers above: this is the
 * role's `onPolicyCreated` and it is also called once on the finished role.
 *
 * THE ASSUME-ROLE CLAUSE WAS DROPPED BECAUSE THE SPLIT REMOVED THE THING IT DESCRIBED.
 * Before the per-service split, both statements shared one `DefaultPolicy` and the
 * suppression covered the pair. Filed separately, `PipelineRole/StsAccess` enumerates the
 * seven per-action role ARNs by `Fn::GetAtt` and holds no wildcard at all -- read off the
 * committed AshDistributedPipeline template. A reason that kept claiming an assume-role
 * wildcard would be naming a state the code left behind, which is the failure mode the
 * header of this file is about.
 *
 * `S3Access` names ONE bucket, not two. The reason these replace said "the artifact and
 * source buckets", which is true of the source ACTION's role below and false here: this
 * policy's five action wildcards and its one `/*` object-key wildcard are all on the
 * artifact bucket. The source bucket is reached only by the role
 * `codepipeline_actions.S3SourceAction` gets for itself.
 */
export function suppressPipelineRoleWildcards(scope: IConstruct): void {
  suppressPolicyWildcardsByGroup(scope, {
    S3Access:
      'Object access inside the pipeline artifact bucket this stack creates, which is the ' +
      'only bucket this policy names. RESOURCE: the "/*" object-key suffix on it, because ' +
      'CodePipeline names artifact objects per execution. ACTION: s3:Abort*, ' +
      's3:DeleteObject*, s3:GetBucket*, s3:GetObject* and s3:List*, API-family suffixes on ' +
      'that same bucket rather than extra reach.',
    StsAccess:
      'This policy holds no wildcard: its one sts:AssumeRole statement names each of the ' +
      'seven per-action roles CodePipeline generated, by ARN. IAM5 reports COMPLIANT here. ' +
      'The entry is kept because codepipeline.Pipeline writes that statement, so which of ' +
      'this role\'s service groups holds a wildcard is aws-cdk-lib\'s choice rather than ' +
      'this app\'s.',
  });
}

/**
 * The role CodePipeline generates PER ACTION, of which this pipeline has seven.
 *
 * WHY THIS IS NOT `suppressPipelineRoleWildcards`. These are seven different roles under
 * the `codepipeline.Pipeline` construct rather than policies of the one role this stack
 * supplies, and only one of them holds a wildcard: the S3 source action's role, which gets
 * the same object-level artifact access the pipeline role has plus a read on the source
 * bucket. The other six each name one CodeBuild project by ARN and hold nothing wildcarded
 * at all. They were all sharing the pipeline role's reason, so six of the seven shipped a
 * sentence about S3 object keys on a policy whose only actions are `codebuild:StartBuild`
 * and two siblings.
 *
 * KEYED ON WHETHER THE POLICY HOLDS A WILDCARD, NOT ON WHICH ACTION IT BELONGS TO. All
 * seven policies are CDK-generated and all seven are called `DefaultPolicy`, so the
 * construct id says nothing here and the only handle CDK leaves is the pipeline STAGE and
 * ACTION name -- which is the `appliesTo` rot the header refuses. What the two reasons
 * differ on IS the presence of a wildcard, so reading that off the document is not a proxy
 * for the classification, it is the classification. This runs after the pipeline is fully
 * assembled, which is when those documents are populated.
 *
 * THE ASSUMPTION THAT MAKES IT SAFE, AND WHERE IT IS CHECKED: nothing adds a statement to
 * one of these roles after this call. If something did, a policy that acquired a wildcard
 * afterwards would keep the "holds no wildcard" reason -- so `no reason claims a policy
 * holds no wildcard unless it holds none` in test/ash-template-size.test.ts asserts it
 * against the committed template, where the outcome rather than the timing is visible.
 */
export function suppressPipelineActionRoleWildcards(scope: IConstruct): void {
  const withWildcard =
    'Object access inside the source and artifact buckets this stack creates. RESOURCE: ' +
    'the "/*" object-key suffix on the artifact bucket, because CodePipeline names artifact ' +
    'objects per execution; the source object itself is named exactly. ACTION: s3:Abort*, ' +
    's3:DeleteObject*, s3:GetBucket*, s3:GetObject* and s3:List*, API-family suffixes on ' +
    'those same two buckets rather than extra reach.';
  const withoutWildcard =
    'This policy holds no wildcard: its codebuild:StartBuild, codebuild:StopBuild and ' +
    'codebuild:BatchGetBuilds grants name one project by ARN, and no action is wildcarded. ' +
    'IAM5 reports COMPLIANT here. The entry is kept because CodePipeline generates this ' +
    'role and its policy per pipeline action, so the shape is aws-cdk-lib\'s choice rather ' +
    'than this app\'s.';

  const policies = policyGroupsUnder(
    scope,
    'this ran before CodePipeline generated its per-action roles',
  );
  for (const policy of policies.keys()) {
    NagSuppressions.addResourceSuppressions(policy, [
      {
        id: 'AwsSolutions-IAM5',
        reason: holdsWildcard(policy) ? withWildcard : withoutWildcard,
      },
    ]);
  }
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

