/**
 * Spread a role's generated policy statements across one `AWS::IAM::Policy` per
 * AWS service, so no single policy document trips cfn-nag's W76 ceiling.
 *
 * WHAT W76 MEASURES, AND WHY THE FIX IS THE DENOMINATOR
 * ----------------------------------------------------
 * cfn-nag's W76 fires when a policy document's Simple Policy Complexity Metric
 * exceeds 25. The metric charges a statement +2 for every "extra service" beyond
 * the first, counting the union of the service prefixes it can read off the
 * actions and off the resource ARNs, and another +1 for every resource service
 * that does not line up with an action service.
 *
 * The catch is what "can read off" means. cfn-model, which cfn-nag parses with,
 * flattens `Fn::Join` by concatenating the parts and stringifying the ones it
 * cannot resolve, so an ARN assembled from pseudo-parameters becomes something
 * like `arn:{"Ref"=>"AWS::Partition"}:logs:...`. Splitting that on ':' puts an
 * empty string where the service name belongs. An `Fn::GetAtt` stays a structure
 * and is not a string at all. Either way the resource's service never matches the
 * action's service, so a correctly scoped ARN costs +3 that the identical ARN
 * written as a literal would not, and N distinct `Fn::GetAtt` ARNs in one
 * statement cost 3N.
 *
 * Measured on this app with cfn-nag 0.8.10: the pipeline role's single
 * `sts:AssumeRole` statement, naming the seven action-role ARNs it is allowed to
 * assume, scores 22. The same statement written `Resource: "*"` scores 1. The
 * metric prices precision as complexity.
 *
 * So there are two ways to get under 25, and only one of them is honest. Widening
 * a resource, dropping a condition or deleting a statement lowers the score by
 * giving the role more access than it needs. Splitting the document lowers it by
 * changing what the score is divided across, and changes no permission at all.
 * This file does the second. It exists so that nobody is tempted by the first.
 *
 * WHY PARTITIONING IS EXACT
 * -------------------------
 * cfn-nag computes a document's score as a plain sum over its statements
 * (`PolicyDocumentMetric#metric` reduces `StatementMetric` over
 * `policy_document.statements`), and a statement's own score depends on nothing
 * outside that statement. Partitioning a document's statements therefore
 * partitions its score exactly: the parts sum to the whole, and the largest part
 * is what W76 sees.
 *
 * WHY THE KEY IS THE ACTION'S SERVICE
 * -----------------------------------
 * Three properties, none of which the obvious alternatives have.
 *
 *   * Stable logical ids. A policy's identity is the service it covers, so
 *     granting a role new S3 access never moves its ECR statements into a
 *     different resource. Round-robin over statements, or bin-packing by cost,
 *     reshuffles every bucket when one grant is inserted, and every reshuffle is
 *     a resource replacement in a deployed stack.
 *   * No configuration. The bucket is a pure function of the statement's own
 *     actions, so a grant added years from now files itself. There is no list of
 *     services to keep in step with what `grantRead`/`grantWrite`/
 *     `codebuild.Project` happen to generate, which is the thing that would rot.
 *   * It reads as something. `Shard0ProjectRoleS3Access` says what it holds.
 *
 * It also cannot lose a `minimizePolicies` merge. That flag is on in cdk.json, and
 * merging happens per document, so a split could in principle separate two
 * statements that would have combined. It cannot separate these: CDK merges
 * statements that share an action set (unioning resources) or share a resource set
 * and conditions (unioning actions). Sharing an action set implies sharing the
 * service, so those land together. The other case would produce a statement whose
 * actions span two services, and measured across all 33 generated policy documents
 * in this app there is not one such statement -- so no cross-service merge is
 * happening today for a split to undo.
 *
 * WHAT HAPPENS TO A STATEMENT THIS CANNOT KEY
 * ------------------------------------------
 * It goes to the ordinary `DefaultPolicy`, exactly as it would without this file.
 * `NotAction`-only statements, `Action: "*"`, an action that is still an
 * unresolved token, and actions spanning more than one service all take that
 * path. This is the fail-safe direction on purpose: the worst outcome is a policy
 * document that is still large and still reported by W76, which is visible. The
 * outcome that must never happen is a statement going missing, and a statement
 * that cannot be keyed is never dropped.
 *
 * KNOWN LIMITATION
 * ----------------
 * A single service can still exceed 25 on its own, if a role accumulates enough
 * statements for one service. The largest per-service document this app produces
 * is 22, and that one is the `sts:AssumeRole` statement described above, which is
 * a single statement and cannot be split further without duplicating a resource
 * list across documents. Nothing here detects that case; cfn-nag reporting W76
 * again is what would.
 *
 * ALSO NOT HANDLED: the aggregate inline-policy size limit. IAM allows as many
 * inline policies per role as you like but caps their combined size at 10,240
 * characters, whitespace excluded
 * (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html).
 * Splitting adds one `{"Version":...,"Statement":[]}` wrapper per extra document,
 * about 39 characters each. Measured before this change, the heaviest role in the
 * app used 2,225 of the 10,240, so the wrappers are noise against the headroom --
 * but a role that ever approached the cap would be made worse by splitting, not
 * better.
 */

import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

/**
 * The construct id to give a construct that would otherwise generate its own
 * role, when it is placed inside the scope returned by `ashRoleSplitScope`.
 *
 * WHY THIS IS THE STRING `Default` AND WHY THAT IS NOT A STYLE CHOICE
 * ------------------------------------------------------------------
 * `codebuild.Project` and `codepipeline.Pipeline` create their own role as a child
 * named `Role` unless one is passed in. Passing one in is the only way to
 * intercept the statements they add to it -- and the role has to be constructed
 * before the construct that would have created it, which means it cannot be that
 * construct's child.
 *
 * Putting both under a shared scope named after the original construct would
 * normally move every logical id underneath it, which for `codepipeline.Pipeline`
 * would move the per-action ROLES it generates. That is exactly what must not
 * happen: a moved role logical id is a new role ARN on the next deploy.
 *
 * `Default` is the one id that costs nothing. aws-cdk-lib's `makeUniqueId`
 * (core/lib/private/uniqueid.ts) opens with
 *
 *     components = components.filter(x => x !== HIDDEN_ID)   // HIDDEN_ID = 'Default'
 *
 * and only then computes the path hash, so a component named `Default`
 * contributes to neither the human-readable prefix nor the hash. Verified against
 * the pinned aws-cdk-lib 2.267.0. A construct at `<Parent>/Thing/Default/Resource`
 * therefore gets byte-for-byte the logical id it had at
 * `<Parent>/Thing/Resource`, and so does every one of its descendants.
 *
 * The `aws:cdk:path` metadata does change, because that records the real
 * construct path. It is metadata, not a property and not an id.
 */
export const GENERATED_CONSTRUCT_ID = 'Default';

export interface AshSplitPolicyRoleProps extends iam.RoleProps {
  /**
   * Called once for each policy this role creates, at the moment it is created.
   *
   * WHY A CALLBACK AND NOT A SUPPRESSION APPLIED AFTERWARDS
   * ------------------------------------------------------
   * This exists for cdk-nag suppressions, and the reason it has to be a callback
   * is a timing trap that is easy to walk into and silent until synth fails.
   *
   * `NagSuppressions.addResourceSuppressions(scope, ..., applyToChildren)` walks
   * the construct tree AT CALL TIME and writes metadata onto the resources it
   * finds then. With a single `DefaultPolicy` that was harmless: the policy already
   * existed by the time a construct suppressed itself, and every statement added
   * later landed in an already-suppressed resource. Splitting per service breaks
   * that, because a grant made later by somebody else -- measured case: the
   * artifact-bucket read that `codepipeline_actions.CodeBuildAction` adds to a
   * project's role when the pipeline is assembled, long after the construct that
   * owns the project finished -- creates a NEW policy resource that the earlier
   * walk could not have seen. That resource is then unsuppressed, and because
   * AwsSolutions-IAM5 is ERROR level it fails synth.
   *
   * A callback fires whenever a policy appears, including for grants added by
   * code that has never heard of this file, so there is no ordering to get right.
   */
  readonly onPolicyCreated?: (policy: iam.Policy) => void;
}

/**
 * A role whose statements are filed into one `AWS::IAM::Policy` per AWS service
 * instead of all landing in a single `DefaultPolicy`.
 *
 * Everything routes through `addToPrincipalPolicy`: `addToPolicy` delegates to it,
 * and every `grant*()` in aws-cdk-lib reaches a role through
 * `Grant.addToPrincipal`, which calls `grantee.grantPrincipal.addToPrincipalPolicy`.
 * Overriding that one method is therefore enough to catch grants this file has
 * never heard of, including the ones `codebuild.Project` and `codepipeline.Pipeline`
 * add to their own roles.
 */
export class AshSplitPolicyRole extends iam.Role {
  /**
   * Declared optional and created on first use rather than as a field
   * initializer. Class fields initialize after `super()` returns, so a future
   * aws-cdk-lib whose `Role` constructor adds a statement would otherwise call
   * this override before the map existed.
   */
  private byService?: Map<string, iam.Policy>;

  private readonly onPolicyCreated?: (policy: iam.Policy) => void;

  constructor(scope: Construct, id: string, props: AshSplitPolicyRoleProps) {
    super(scope, id, props);
    this.onPolicyCreated = props.onPolicyCreated;
  }

  public addToPrincipalPolicy(statement: iam.PolicyStatement): iam.AddToPrincipalPolicyResult {
    const group = policyGroupFor(statement);
    if (group === undefined) {
      return super.addToPrincipalPolicy(statement);
    }

    const byService = (this.byService ??= new Map<string, iam.Policy>());
    let policy = byService.get(group);
    if (policy === undefined) {
      // Created only when a statement actually needs it. An `iam.Policy` with no
      // statements fails validation, and an empty one would be a resource in the
      // template that grants nothing.
      policy = new iam.Policy(this, group);
      this.attachInlinePolicy(policy);
      byService.set(group, policy);
      this.onPolicyCreated?.(policy);
    }
    policy.addStatements(statement);

    // The policy that received the statement is what a caller has to wait for.
    // This matches what the base class ends up with: it returns an empty
    // DependencyGroup and fills it with the declaring policy during its own
    // `splitLargePolicy` aspect.
    return { statementAdded: true, policyDependable: policy };
  }
}

/**
 * Create the scope and role for a construct that generates its own role.
 *
 * Use with `GENERATED_CONSTRUCT_ID`:
 *
 *     const { scope, role } = ashRoleSplitScope(this, 'MergeProject', 'codebuild.amazonaws.com');
 *     return new codebuild.Project(scope, GENERATED_CONSTRUCT_ID, { role, ... });
 *
 * `constructId` must be the id the generating construct had before, because that
 * is what keeps every logical id underneath it -- the role's included -- where it
 * was. The trust policy is reproduced rather than inherited: both
 * `codebuild.Project` and `codepipeline.Pipeline` give their generated role
 * nothing but an `sts:AssumeRole` grant to their own service principal, with no
 * path, description or condition, so a single `ServicePrincipal` reproduces it
 * exactly. Verified against the committed templates before this change.
 */
export function ashRoleSplitScope(
  parent: Construct,
  constructId: string,
  servicePrincipal: string,
  onPolicyCreated?: (policy: iam.Policy) => void,
): { scope: Construct; role: AshSplitPolicyRole } {
  const scope = new Construct(parent, constructId);
  const role = new AshSplitPolicyRole(scope, 'Role', {
    assumedBy: new iam.ServicePrincipal(servicePrincipal),
    onPolicyCreated,
  });
  return { scope, role };
}

/**
 * Recover the scope `ashRoleSplitScope` created, given the construct that was
 * placed at `GENERATED_CONSTRUCT_ID` inside it.
 *
 * WHY ANYTHING NEEDS THIS
 * -----------------------
 * A cdk-nag suppression applied with `applyToChildren` walks the construct tree
 * downwards. Before the role was supplied it was a CHILD of the project or
 * pipeline, so suppressing on the project reached the role and its policies. Now
 * the role is that construct's SIBLING, and a suppression on the project silently
 * stops reaching it: the finding comes back, and it comes back as an ERROR-level
 * cdk-nag rule that fails synth. Suppressing on the enclosing scope covers both
 * again, and covers exactly the same set of resources as before.
 *
 * The id check is deliberate. Handed the wrong construct this would otherwise
 * return some unrelated parent and widen a suppression, which is the failure mode
 * a suppression helper must not have.
 */
export function ashRoleSplitScopeOf(generated: Construct): Construct {
  if (generated.node.id !== GENERATED_CONSTRUCT_ID) {
    throw new Error(
      `ashRoleSplitScopeOf expects the construct created at '${GENERATED_CONSTRUCT_ID}' ` +
        `inside an ashRoleSplitScope, but was given '${generated.node.id}' ` +
        `(${generated.node.path}).`,
    );
  }
  const scope = generated.node.scope;
  if (scope === undefined) {
    throw new Error(`${generated.node.path} has no scope.`);
  }
  return scope;
}

/**
 * The construct id of the policy a statement belongs in, or `undefined` when the
 * statement cannot be keyed and should stay in `DefaultPolicy`.
 *
 * Exported for the test that pins these cases; not part of the stacks' API.
 */
export function policyGroupFor(statement: iam.PolicyStatement): string | undefined {
  const actions = statement.actions;
  // No actions means a NotAction-only statement. Its effective "actions" are an
  // exclusion, which names no service to file under.
  if (actions.length === 0) {
    return undefined;
  }

  const services = new Set<string>();
  for (const action of actions) {
    const service = action.split(':')[0];
    // Anything that is not a plain service prefix falls back to DefaultPolicy:
    // `*`, and an unresolved token such as `${Token[TOKEN.123]}`, whose braces and
    // brackets fail this test. A colonless action is covered by the same test but
    // cannot actually arrive -- `iam.PolicyStatement` rejects it at construction
    // with «ActionInvalid» -- so the test for it is deliberately absent rather
    // than written against a state CDK prevents.
    if (!/^[a-z][a-z0-9-]*$/.test(service)) {
      return undefined;
    }
    services.add(service);
  }
  // A statement spanning two services has no single home. Filing it under either
  // one would make the key depend on iteration order.
  if (services.size !== 1) {
    return undefined;
  }

  return `${pascalCase([...services][0])}Access`;
}

/**
 * `s3` -> `S3`, `execute-api` -> `ExecuteApi`.
 *
 * A service prefix may contain hyphens, which `Names.uniqueId` would strip from
 * the logical id anyway; doing it here keeps the construct id and the logical id
 * telling the same story.
 */
function pascalCase(service: string): string {
  return service
    .split('-')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
}

/**
 * The per-service policies this role created, sorted by construct id.
 *
 * `DefaultPolicy` is excluded. It is an `iam.Policy` child too, but the base class
 * creates it and it holds only the statements the split declined to key — so
 * counting it here would make "the split produced no per-service policy" and "the
 * split produced one, plus a fallback" look the same.
 */
export function splitPolicyIds(role: AshSplitPolicyRole): string[] {
  return role.node.children
    .filter((child): child is iam.Policy => child instanceof iam.Policy)
    .map((policy) => policy.node.id)
    .filter((id) => id !== 'DefaultPolicy')
    .sort();
}
