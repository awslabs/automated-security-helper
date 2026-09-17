/**
 * Cross-stack hardening invariants, asserted as properties rather than per
 * resource.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * cfn-nag reported 12 unencrypted log groups and 4 unencrypted secrets across the
 * five committed templates. Fixing them is one line per resource; keeping them
 * fixed is not, because the failure mode is a log group somebody adds later and
 * forgets to pass the key to. Nothing fails at synth time when that happens — the
 * group is created with CloudWatch Logs' default encryption and reads as working.
 *
 * So these tests iterate over every resource of the type in every stack instead of
 * naming the ones that exist today. A sixth log group in the Fargate stack fails
 * here on the day it lands.
 *
 * NON-VACUITY IS ASSERTED, NOT ASSUMED
 * ------------------------------------
 * "every log group specifies a key" is trivially true of a stack with no log
 * groups, and a rename that stopped the iteration finding any would pass silently.
 * Each property test is therefore preceded by an EXACT count, not a lower bound.
 * Exact is deliberate: `toBeGreaterThanOrEqual` would keep passing while a log
 * group was added and left unencrypted, which is the whole failure this file
 * exists to catch. A count that is exact fails on the day a resource lands, which
 * is when someone can still decide whether it should carry a key.
 */

import * as fs from 'fs';
import * as path from 'path';

import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';

import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import {
  ashFargateSubnetLayout,
  AshFargateStack,
  NAT_GATEWAYS,
} from '../lib/ash-fargate-stack';
import { AshImagePipelineStack } from '../lib/ash-image-pipeline-stack';

type StackFactory = (app: App, id: string) => Stack;

const STACKS: Record<string, StackFactory> = {
  AshImagePipeline: (app, id) => new AshImagePipelineStack(app, id),
  AshAgentCore: (app, id) => new AshAgentCoreStack(app, id),
  AshFargate: (app, id) => new AshFargateStack(app, id),
  AshCodeCommitGate: (app, id) => new AshCodeCommitGateStack(app, id),
  AshDistributedPipeline: (app, id) => new AshDistributedPipelineStack(app, id),
};

/**
 * The context `cdk.json` supplies, which a bare `new App()` in a test does not get.
 *
 * The CDK CLI reads `cdk.json`'s `context` block and hands it to the app; jest does
 * not. Without it the templates a test builds are NOT the templates
 * scripts/synth-templates.sh commits, and the difference is not cosmetic — the
 * block turns on `@aws-cdk/aws-iam:minimizePolicies`, so an unminimized in-memory
 * policy document has statements the shipped template has merged away. That
 * matters most to the duplicate-statement assertion below, which exists to catch a
 * `Sid` defeating that same minimizer: with the flag off it would be looking for
 * the defect in the one configuration that cannot produce it.
 *
 * Loading it here means these tests pin the artifact an adopter launches.
 */
const CDK_JSON_CONTEXT: Record<string, unknown> = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'cdk.json'), 'utf8'),
).context;

const TEMPLATES: Record<string, Template> = Object.fromEntries(
  Object.entries(STACKS).map(([name, factory]) => [
    name,
    Template.fromStack(
      factory(new App({ analyticsReporting: false, context: CDK_JSON_CONTEXT }), name),
    ),
  ]),
);

const CASES = Object.entries(TEMPLATES);

describe('the templates under test are the templates that ship', () => {
  test('cdk.json context reached the App', () => {
    // Non-vacuity for the block above. If the path breaks or cdk.json is
    // restructured, `CDK_JSON_CONTEXT` becomes undefined, `new App({context:
    // undefined})` is silently accepted, and every assertion in this file starts
    // measuring an unminimized artifact that never ships. Nothing else would say so.
    expect(CDK_JSON_CONTEXT).toBeDefined();
    expect(CDK_JSON_CONTEXT['@aws-cdk/aws-iam:minimizePolicies']).toBe(true);
  });
});

/** Every resource of one type across every stack, as `[stack/logicalId, props]`. */
function everyResource(type: string): [string, Record<string, any>][] {
  return CASES.flatMap(([stack, template]) =>
    Object.entries<any>(template.findResources(type)).map(
      ([logicalId, resource]) =>
        [`${stack}/${logicalId}`, resource.Properties ?? {}] as [string, Record<string, any>],
    ),
  );
}

describe('every log group specifies a KmsKeyId', () => {
  const groups = everyResource('AWS::Logs::LogGroup');

  test('there are log groups to check', () => {
    // Two per image build, one per bootstrap starter, plus the gate's scan log and
    // the Fargate task and flow logs. A number below that means the iteration
    // stopped finding them, not that the stacks got simpler.
    expect(groups.length).toBe(12);
  });

  test.each(groups.map(([name, props]) => [name, props] as const))(
    '%s specifies a KmsKeyId',
    (_name, props) => {
      // Presence only. The key is the adopter-supplied `KmsKeyArn`, so the value is
      // `Fn::If(HasKmsKey, <ref>, AWS::NoValue)` and an adopter who sets nothing gets
      // the AWS-managed key. ash-parameter-contract.test.ts pins that exact shape;
      // this is the per-group non-vacuity witness that none was missed.
      expect(props.KmsKeyId).toBeDefined();
    },
  );
});

describe('every secret specifies a KmsKeyId', () => {
  const secrets = everyResource('AWS::SecretsManager::Secret');

  test('there are secrets to check', () => {
    // One per stack that declares the MCP auth surface plus the two that create it
    // unconditionally for one class shape: four, which is the W77 count.
    expect(secrets.length).toBe(4);
  });

  test.each(secrets.map(([name, props]) => [name, props] as const))(
    '%s specifies a KmsKeyId',
    (_name, props) => {
      // cfn-nag W77. Set through an L1 override rather than the L2 `encryptionKey`
      // prop -- see ash-runtime-config.ts -- so nothing else in the app asserts it.
      expect(props.KmsKeyId).toBeDefined();
    },
  );
});

describe('each stack creates exactly one key', () => {
  test.each(CASES)('%s has exactly one key', (_name, template) => {
    // One key per stack, so every resource in the stack that is given a key is
    // given the same one. Two keys would let a resource point at whichever of them
    // a later edit forgot to configure, with nothing reporting the difference.
    template.resourceCountIs('AWS::KMS::Key', 1);
  });
});

describe('the image-build bootstrap starter is concurrency-bounded', () => {
  const functions = everyResource('AWS::Lambda::Function').filter(([name]) =>
    name.includes('BootstrapStarter'),
  );

  test('there are bootstrap starters to check', () => {
    // Three: the stacks whose workload cannot be created against an empty
    // repository. The sharded pipeline and the standalone image build set
    // bootstrapOnDeploy false and have none.
    expect(functions.length).toBe(3);
  });

  test.each(functions.map(([name, props]) => [name, props] as const))(
    '%s reserves one execution',
    (_name, props) => {
      // cfn-nag W92. CloudFormation is the only caller and it invokes the custom
      // resource serially, so 1 caps the function without throttling anything the
      // design does.
      expect(props.ReservedConcurrentExecutions).toBe(1);
    },
  );
});

describe('the Fargate VPC does not auto-assign public IPv4 addresses', () => {
  const template = TEMPLATES.AshFargate;
  const subnets = Object.entries<any>(template.findResources('AWS::EC2::Subnet'));

  test('there are subnets to check', () => {
    // Two public and two private across two AZs.
    expect(subnets.length).toBe(4);
  });

  test.each(subnets.map(([id, resource]) => [id, resource] as const))(
    '%s has MapPublicIpOnLaunch false',
    (_id, resource) => {
      // cfn-nag W33 fired on the two public subnets, which exist only to hold the
      // NAT gateway. Asserted on all four rather than on the public pair by name,
      // so a third subnet group cannot land with the default back on.
      expect(resource.Properties.MapPublicIpOnLaunch).toBe(false);
    },
  );

  test('the private subnets still keep their egress route', () => {
    // MapPublicIpOnLaunch is the only thing the explicit subnetConfiguration
    // changes. If restating CDK's default layout had also dropped the NAT, the
    // tasks would lose egress and every scan would fail on a ruleset fetch.
    template.resourceCountIs('AWS::EC2::NatGateway', 1);
  });

  test('the NAT the template deploys is the one the layout was built for', () => {
    // Binds the constant to the artifact. Without this the guard below could be
    // bypassed by leaving NAT_GATEWAYS at 1 and writing a different literal into
    // the VPC's own `natGateways`, which is precisely the drift the guard exists to
    // catch.
    template.resourceCountIs('AWS::EC2::NatGateway', NAT_GATEWAYS);
    expect(NAT_GATEWAYS).toBeGreaterThan(0);
  });

  test('a layout with no NAT is refused at synth rather than deployed broken', () => {
    // The failure this replaces is silent. `natGateways: 0` is the obvious cost
    // edit, and CDK's own default layout switches to DEFAULT_SUBNETS_NO_NAT for it —
    // but an explicit subnetConfiguration overrides that switch, so the private
    // subnets keep PRIVATE_WITH_EGRESS and get a default route to a NAT gateway that
    // was never created. cdk synth reports nothing; the first scan times out
    // fetching a ruleset and reads as a scanner bug.
    expect(() => ashFargateSubnetLayout(0)).toThrow(/DEFAULT_SUBNETS_NO_NAT/);
    // Negative is nonsense rather than a cost choice, but it reaches the same
    // broken layout, so it is refused by the same guard.
    expect(() => ashFargateSubnetLayout(-1)).toThrow(/natGateways is -1/);
  });

  test('the layout it does return is the two-tier one the stack uses', () => {
    // Positive control for the guard: a test that only proves 0 throws would still
    // pass if the function threw on everything.
    const layout = ashFargateSubnetLayout(NAT_GATEWAYS);
    expect(layout.map((tier) => [tier.name, tier.subnetType, tier.mapPublicIpOnLaunch])).toEqual([
      ['Public', 'Public', false],
      ['Private', 'Private', undefined],
    ]);
  });
});

describe('no IAM policy grants the same thing twice', () => {
  // `Repository.grantPull` already emits ecr:GetAuthorizationToken on "*". The
  // AgentCore execution role used to add an identical statement of its own under a
  // sid, and the sid is what stopped CDK's policy minimizer from folding the two
  // together, so the deployed role carried the grant twice.
  //
  // Stated as "no duplicates anywhere in the document" rather than "no second
  // token statement", because the mechanism — a sid defeating minimization —
  // applies to any statement in any policy. So it is measured over every stack
  // rather than over the one where it was first noticed: the sharded pipeline has
  // 40-odd policies, and the next occurrence is likelier there than in AgentCore.
  const policiesPerStack = CASES.map(
    ([stack, template]) =>
      [stack, Object.entries<any>(template.findResources('AWS::IAM::Policy'))] as const,
  );

  test('there are policies to check in every stack', () => {
    // 90 across the five stacks, in the order STACKS declares them. Exact and
    // per-stack, so one stack losing its policies to a rename cannot leave the loop
    // for that stack iterating over nothing while the others carry the assertion.
    //
    // Was [4, 4, 6, 4, 15] = 33 before the per-service policy split in
    // ash-policy-split.ts, which files each role's statements into one
    // AWS::IAM::Policy per AWS service so that no single document trips cfn-nag's
    // W76 ceiling. The counts rose; the statements did not change, which the
    // duplicate check below is a second witness to -- it passes over all 90.
    //
    // 88 of the 90 come from the split. The other two are AshAgentCore's and
    // AshFargate's `ConfigKeyAccess`, which AshRuntimeConfig authors directly so
    // the `kms:Decrypt` grant on an adopter-supplied key can be made conditional.
    // That is why those two stacks are one higher than the split alone produces.
    expect(policiesPerStack.map(([, policies]) => policies.length)).toEqual([
      10, 13, 10, 7, 50,
    ]);
  });

  test.each(policiesPerStack)('%s has no statement that duplicates another', (_stack, policies) => {
    for (const [logicalId, policy] of policies) {
      const statements: unknown[] = policy.Properties.PolicyDocument.Statement;
      const withoutSids = statements.map((statement) => {
        const { Sid, ...rest } = statement as Record<string, unknown>;
        return JSON.stringify(rest);
      });
      // Compared as objects carrying the logical id, so the failure output NAMES
      // the policy. `expect(size).toBe(length)` reports "Expected: 4, Received: 3"
      // and the test.each title carries only the stack name -- for
      // AshDistributedPipeline that leaves a reader 50 policies to search.
      // A separate `expect(logicalId).toBeTruthy()` cannot do this job: an
      // Object.entries key is always a non-empty string, so it never fails and
      // never prints anything.
      expect({ policy: logicalId, distinct: new Set(withoutSids).size }).toEqual({
        policy: logicalId,
        distinct: withoutSids.length,
      });
    }
  });
});
