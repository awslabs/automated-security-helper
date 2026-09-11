/**
 * The per-service policy split, and the two things about it that must not break
 * silently.
 *
 * WHY THESE PARTICULAR ASSERTIONS
 * ------------------------------
 * The split exists to get eight generated policy documents under cfn-nag's W76
 * ceiling without changing a permission. Two properties carry that, and each fails
 * in a way nothing else in this repo would notice.
 *
 *   1. NO ROLE LOGICAL ID MOVED. Supplying a role to `codebuild.Project` and
 *      `codepipeline.Pipeline` means creating it outside the construct that would
 *      have created it, which normally moves its logical id -- and a moved IAM role
 *      logical id is a REPLACED role with a new ARN on the next deploy. It is
 *      avoided by placing the generating construct at the id aws-cdk-lib drops from
 *      logical id derivation. That is a fact about aws-cdk-lib's internals, so it
 *      is pinned here against the pinned version rather than trusted. If a future
 *      bump stops filtering that component, every one of these ids changes at once
 *      and this test says so.
 *
 *   2. EVERY POLICY DOCUMENT HOLDS ONE SERVICE. That is the mechanism's contract,
 *      and it is what makes the SPCM bound per document a function of one service's
 *      statements. A statement that started spanning two services would silently
 *      fall back to DefaultPolicy and quietly re-grow the document the split was
 *      meant to shrink.
 *
 * WHAT IS DELIBERATELY NOT ASSERTED HERE
 * -------------------------------------
 * The SPCM score itself. Reproducing cfn-nag's metric in TypeScript would mean
 * reproducing cfn-model's `Fn::Join` stringification, which is where a hand port of
 * it went wrong by three points during this work. cfn-nag 0.8.10 is the authority
 * on its own rule and is run against the committed templates; this file asserts the
 * structure the split is supposed to produce, not a second opinion on the metric.
 */

import { App, Lazy, Names, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import { AshFargateStack } from '../lib/ash-fargate-stack';
import { AshImagePipelineStack } from '../lib/ash-image-pipeline-stack';
import {
  AshSplitPolicyRole,
  GENERATED_CONSTRUCT_ID,
  ashRoleSplitScope,
  ashRoleSplitScopeOf,
  policyGroupFor,
  splitPolicyIds,
} from '../lib/ash-policy-split';

type StackFactory = (app: App, id: string) => Stack;

const STACKS: Record<string, StackFactory> = {
  AshImagePipeline: (app, id) => new AshImagePipelineStack(app, id),
  AshAgentCore: (app, id) => new AshAgentCoreStack(app, id),
  AshFargate: (app, id) => new AshFargateStack(app, id),
  AshCodeCommitGate: (app, id) => new AshCodeCommitGateStack(app, id),
  AshDistributedPipeline: (app, id) => new AshDistributedPipelineStack(app, id),
};

const TEMPLATES: Record<string, Template> = Object.fromEntries(
  Object.entries(STACKS).map(([name, factory]) => [
    name,
    Template.fromStack(factory(new App({ analyticsReporting: false }), name)),
  ]),
);

/**
 * The IAM role logical ids as they stood before the split, measured from the
 * committed templates.
 *
 * These are the roles whose creation moved out of `codebuild.Project` /
 * `codepipeline.Pipeline`, so they are the ones a mistake in the transparent-scope
 * trick would move. Written out rather than derived, because a derivation would
 * reproduce whatever bug it is meant to catch.
 */
const ROLE_LOGICAL_IDS_BEFORE_THE_SPLIT: Record<string, string[]> = {
  AshImagePipeline: [
    'Amd64BuildEventsRole1D6BA9C3',
    'Amd64BuildRole23AB6DE3',
    'Arm64BuildEventsRoleC8CC6E3E',
    'Arm64BuildRole996AACA9',
  ],
  AshAgentCore: [
    'ImageBootstrapStarterRole4262AC52',
    'ImageBuildEventsRoleDF4F46F6',
    'ImageBuildRole1BB51BF0',
    'RuntimeRoleFD8790A4',
  ],
  AshFargate: [
    'ImageBootstrapStarterRole4262AC52',
    'ImageBuildEventsRoleDF4F46F6',
    'ImageBuildRole1BB51BF0',
    'TaskDefinitionExecutionRole8D61C2FB',
    'TaskDefinitionTaskRoleFD40A61D',
    'VpcIAMRoleAED9A610',
  ],
  AshCodeCommitGate: [
    'ImageBootstrapStarterRole4262AC52',
    'ImageBuildEventsRoleDF4F46F6',
    'ImageBuildRole1BB51BF0',
    'ScanFunctionRoleD9323212',
  ],
  AshDistributedPipeline: [
    'ImageBuildEventsRoleDF4F46F6',
    'ImageBuildRole1BB51BF0',
    'MergeProjectRoleE1E953C0',
    // The per-action roles CodePipeline generates sit UNDER the pipeline, so they
    // are the ones that move if the transparent scope is named anything
    // aws-cdk-lib does not drop from logical id derivation.
    'PipelineBuildImageBuildAshImageCodePipelineActionRoleF9455BEF',
    'PipelineMergeMergeAndGateCodePipelineActionRoleBF4A894E',
    'PipelineRoleD68726F7',
    'PipelineScanShard0CodePipelineActionRole7F5B77AB',
    'PipelineScanShard1CodePipelineActionRole56612A75',
    'PipelineScanShard2CodePipelineActionRole495938BB',
    'PipelineScanShard3CodePipelineActionRole10B19A0C',
    'PipelineSourceCodePipelineActionRoleC6F9E7F5',
    'Shard0ProjectRoleF3A1C5B4',
    'Shard1ProjectRole6761C196',
    'Shard2ProjectRole2D41E181',
    'Shard3ProjectRole052E7B3A',
  ],
};

describe('no role logical id moved', () => {
  for (const [stack, expected] of Object.entries(ROLE_LOGICAL_IDS_BEFORE_THE_SPLIT)) {
    it(`${stack} declares exactly the pre-split set of role logical ids`, () => {
      const present = Object.keys(TEMPLATES[stack].findResources('AWS::IAM::Role')).sort();
      // Exact set equality, not containment. A subset check would pass a stack that
      // grew a role, and a superset check would pass one that lost a role -- and a
      // lost role reads as "renamed" in a template diff, which is the case this is
      // guarding.
      expect(present).toEqual([...expected].sort());
    });
  }
});

/**
 * Policies this stack authors by hand, which the split neither created nor names.
 *
 * `AshRuntimeConfig` builds `new iam.Policy(this, 'KeyAccess', ...)` for the
 * conditional `kms:Decrypt` on an adopter-supplied `KmsKeyArn` -- it exists as its
 * own policy resource precisely so the grant can be made conditional, which
 * `Secret.grantRead` cannot do. It holds one service and so would satisfy the
 * one-service rule below, but its logical id is `ConfigKeyAccess<hash>` rather than
 * the split's `<Role><Service>Access`, so the naming rule has to skip it.
 *
 * Listed by name rather than matched by a pattern: a pattern loose enough to
 * excuse this id would also excuse a split policy that had been misnamed, which is
 * the thing the naming rule exists to catch. The test below asserts every entry
 * here is actually present, so a rename or removal fails rather than silently
 * widening the exemption.
 */
const POLICIES_AUTHORED_OUTSIDE_THE_SPLIT = ['ConfigKeyAccess'];

describe('every generated policy document holds exactly one service', () => {
  /** `[stack/logicalId, services]` for every AWS::IAM::Policy in every stack. */
  function policyServices(): [string, string[]][] {
    return Object.entries(TEMPLATES).flatMap(([stack, template]) =>
      Object.entries<any>(template.findResources('AWS::IAM::Policy')).map(
        ([logicalId, resource]) => {
          const statements: any[] = resource.Properties?.PolicyDocument?.Statement ?? [];
          const services = new Set<string>();
          for (const statement of statements) {
            const actions = Array.isArray(statement.Action)
              ? statement.Action
              : [statement.Action];
            for (const action of actions) {
              if (typeof action === 'string') {
                services.add(action.split(':')[0]);
              }
            }
          }
          return [`${stack}/${logicalId}`, [...services].sort()] as [string, string[]];
        },
      ),
    );
  }

  const POLICIES = policyServices();

  it('found policies to check', () => {
    // The floor is the pre-split count. Anything at or below it means the split
    // did not happen and every assertion below would be checking the old shape.
    expect(POLICIES.length).toBeGreaterThan(33);
  });

  it('no policy created by the split mixes services', () => {
    const mixed = POLICIES.filter(
      ([id, services]) => !id.includes('DefaultPolicy') && services.length > 1,
    );
    expect(mixed).toEqual([]);
  });

  it('each split policy is named after the service it holds', () => {
    for (const [id, services] of POLICIES) {
      if (
        id.includes('DefaultPolicy') ||
        services.length === 0 ||
        POLICIES_AUTHORED_OUTSIDE_THE_SPLIT.some((name) => id.includes(name))
      ) {
        continue;
      }
      const service = services[0].replace(/-/g, '').toLowerCase();
      // e.g. AshDistributedPipeline/Shard0ProjectRoleS3Access1A2B3C4D holds s3.
      expect(id.toLowerCase()).toContain(`${service}access`);
    }
  });

  it('every hand-authored exemption is still present', () => {
    // Non-vacuity for the skip above. A stale entry here would silently excuse a
    // split policy whose id happened to contain the same substring, and the naming
    // rule would stop being able to fail.
    for (const name of POLICIES_AUTHORED_OUTSIDE_THE_SPLIT) {
      expect(POLICIES.filter(([id]) => id.includes(name)).length).toBeGreaterThan(0);
    }
  });
});

describe('policyGroupFor', () => {
  const statement = (props: iam.PolicyStatementProps) => new iam.PolicyStatement(props);

  it('keys a single-service statement by that service', () => {
    expect(policyGroupFor(statement({ actions: ['s3:GetObject'], resources: ['*'] })))
      .toBe('S3Access');
  });

  it('pascal-cases a hyphenated service prefix', () => {
    expect(policyGroupFor(statement({ actions: ['execute-api:Invoke'], resources: ['*'] })))
      .toBe('ExecuteApiAccess');
  });

  it('declines a wildcard action, which belongs to no service', () => {
    expect(policyGroupFor(statement({ actions: ['*'], resources: ['*'] }))).toBeUndefined();
  });

  it('declines a statement whose actions span two services', () => {
    expect(
      policyGroupFor(statement({ actions: ['s3:GetObject', 'kms:Decrypt'], resources: ['*'] })),
    ).toBeUndefined();
  });

  it('declines a NotAction-only statement', () => {
    expect(policyGroupFor(statement({ notActions: ['s3:DeleteObject'], resources: ['*'] })))
      .toBeUndefined();
  });

  // No case here for a colonless action such as 'GetObject'. `policyGroupFor`
  // rejects it, but `iam.PolicyStatement` rejects it first, at construction, with
  // «ActionInvalid» -- so a test for it would be asserting on a state CDK does not
  // allow to exist. The same guard is exercised by the wildcard case above.

  it('declines an unresolved token, rather than keying on its placeholder', () => {
    // The literal shape aws-cdk-lib renders an unresolved string token as. Keying
    // on it would put every deferred action in a policy named after a token id.
    const stack = new Stack(new App({ analyticsReporting: false }), 'S');
    const deferred = Lazy.string({ produce: () => 's3:GetObject' });
    expect(stack.resolve(deferred)).toBe('s3:GetObject');
    expect(policyGroupFor(statement({ actions: [deferred], resources: ['*'] })))
      .toBeUndefined();
  });
});

describe('AshSplitPolicyRole', () => {
  function fixture(): { stack: Stack; role: AshSplitPolicyRole; created: string[] } {
    const stack = new Stack(new App({ analyticsReporting: false }), 'Fixture');
    const created: string[] = [];
    const role = new AshSplitPolicyRole(stack, 'Role', {
      assumedBy: new iam.ServicePrincipal('codebuild.amazonaws.com'),
      onPolicyCreated: (policy) => created.push(policy.node.id),
    });
    return { stack, role, created };
  }

  it('files statements for different services into different policies', () => {
    const { stack, role } = fixture();
    role.addToPrincipalPolicy(
      new iam.PolicyStatement({ actions: ['s3:GetObject'], resources: ['arn:aws:s3:::b/*'] }),
    );
    role.addToPrincipalPolicy(
      new iam.PolicyStatement({ actions: ['kms:Decrypt'], resources: ['arn:aws:kms:::key/k'] }),
    );

    expect(splitPolicyIds(role)).toEqual(['KmsAccess', 'S3Access']);
    Template.fromStack(stack).resourceCountIs('AWS::IAM::Policy', 2);
  });

  it('reuses one policy for repeated statements of the same service', () => {
    const { stack, role } = fixture();
    for (const action of ['s3:GetObject', 's3:PutObject', 's3:ListBucket']) {
      role.addToPrincipalPolicy(
        new iam.PolicyStatement({ actions: [action], resources: [`arn:aws:s3:::b/${action}`] }),
      );
    }
    expect(splitPolicyIds(role)).toEqual(['S3Access']);
    Template.fromStack(stack).resourceCountIs('AWS::IAM::Policy', 1);
  });

  it('calls onPolicyCreated once per policy, as it is created', () => {
    const { role, created } = fixture();
    role.addToPrincipalPolicy(
      new iam.PolicyStatement({ actions: ['s3:GetObject'], resources: ['*'] }),
    );
    role.addToPrincipalPolicy(
      new iam.PolicyStatement({ actions: ['s3:PutObject'], resources: ['*'] }),
    );
    role.addToPrincipalPolicy(
      new iam.PolicyStatement({ actions: ['logs:PutLogEvents'], resources: ['*'] }),
    );
    // Twice, not three times: the second S3 statement reuses the first policy.
    expect(created).toEqual(['S3Access', 'LogsAccess']);
  });

  it('falls back to DefaultPolicy for a statement it cannot key', () => {
    const { stack, role } = fixture();
    role.addToPrincipalPolicy(
      new iam.PolicyStatement({ actions: ['*'], resources: ['*'] }),
    );
    // No per-service policy, and the ordinary DefaultPolicy exists instead. The
    // statement is never dropped, which is the property that matters.
    expect(splitPolicyIds(role)).toEqual([]);
    expect(role.node.tryFindChild('DefaultPolicy')).toBeDefined();
    Template.fromStack(stack).hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: [{ Action: '*', Effect: 'Allow', Resource: '*' }],
      },
    });
  });

  it('returns the receiving policy as the dependable', () => {
    const { role } = fixture();
    const result = role.addToPrincipalPolicy(
      new iam.PolicyStatement({ actions: ['s3:GetObject'], resources: ['*'] }),
    );
    expect(result.statementAdded).toBe(true);
    expect(result.policyDependable).toBe(role.node.tryFindChild('S3Access'));
  });

  it('routes addToPolicy through the same split', () => {
    const { role } = fixture();
    expect(
      role.addToPolicy(new iam.PolicyStatement({ actions: ['ssm:GetParameter'], resources: ['*'] })),
    ).toBe(true);
    expect(splitPolicyIds(role)).toEqual(['SsmAccess']);
  });
});

describe('the transparent scope', () => {
  /**
   * The whole trick, isolated: a resource at `<Thing>/Default/...` must get the
   * logical id it would have had at `<Thing>/...`.
   */
  it('leaves logical ids exactly where they were', () => {
    const stack = new Stack(new App({ analyticsReporting: false }), 'S');

    const direct = new iam.Role(stack, 'Thing', {
      assumedBy: new iam.ServicePrincipal('codebuild.amazonaws.com'),
    });

    const otherStack = new Stack(new App({ analyticsReporting: false }), 'S');
    const scope = new Construct(otherStack, 'Thing');
    const nested = new iam.Role(scope, GENERATED_CONSTRUCT_ID, {
      assumedBy: new iam.ServicePrincipal('codebuild.amazonaws.com'),
    });

    expect(Names.uniqueId(nested.node.defaultChild as Construct)).toBe(
      Names.uniqueId(direct.node.defaultChild as Construct),
    );
  });

  it('puts the role where the generating construct would have put it', () => {
    const stack = new Stack(new App({ analyticsReporting: false }), 'S');
    const { role } = ashRoleSplitScope(stack, 'Thing', 'codebuild.amazonaws.com');
    // The path a construct's own `new iam.Role(this, 'Role')` would produce.
    expect(role.node.path).toBe('S/Thing/Role');
  });

  it('ashRoleSplitScopeOf recovers the scope', () => {
    const stack = new Stack(new App({ analyticsReporting: false }), 'S');
    const { scope } = ashRoleSplitScope(stack, 'Thing', 'codebuild.amazonaws.com');
    const generated = new Construct(scope, GENERATED_CONSTRUCT_ID);
    expect(ashRoleSplitScopeOf(generated)).toBe(scope);
  });

  it('ashRoleSplitScopeOf refuses a scopeless root', () => {
    // Reachable: constructs lets a tree root carry any id, so a root literally
    // named `Default` passes the id check and then has no scope to return.
    // Measured with constructs 10.8.1 -- `new Construct(undefined, 'Default')`
    // succeeds and its node.scope is undefined.
    const root = new Construct(undefined as unknown as Construct, GENERATED_CONSTRUCT_ID);
    expect(() => ashRoleSplitScopeOf(root)).toThrow(/has no scope/);
  });

  it('a role given no onPolicyCreated still splits', () => {
    // The callback is optional, and a missing one must not stop the split or throw.
    const stack = new Stack(new App({ analyticsReporting: false }), 'S');
    const { role } = ashRoleSplitScope(stack, 'Thing', 'codebuild.amazonaws.com');
    role.addToPrincipalPolicy(
      new iam.PolicyStatement({ actions: ['logs:PutLogEvents'], resources: ['*'] }),
    );
    expect(splitPolicyIds(role)).toEqual(['LogsAccess']);
  });

  it('ashRoleSplitScopeOf refuses a construct that is not the generated one', () => {
    const stack = new Stack(new App({ analyticsReporting: false }), 'S');
    const { scope } = ashRoleSplitScope(stack, 'Thing', 'codebuild.amazonaws.com');
    const wrong = new Construct(scope, 'NotTheGeneratedOne');
    // Refusing is the point: returning some unrelated parent would silently widen
    // whatever suppression the caller was about to apply.
    expect(() => ashRoleSplitScopeOf(wrong)).toThrow(/expects the construct created at 'Default'/);
  });
});
