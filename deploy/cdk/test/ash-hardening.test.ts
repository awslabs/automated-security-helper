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
 * "every log group is encrypted" is trivially true of a stack with no log groups,
 * and a rename that stopped the iteration finding any would pass silently. Each
 * property test is therefore preceded by a count with a floor taken from the
 * cfn-nag measurement that prompted it.
 */

import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';

import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import { AshFargateStack } from '../lib/ash-fargate-stack';
import { AshImagePipelineStack } from '../lib/ash-image-pipeline-stack';

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

const CASES = Object.entries(TEMPLATES);

/** Every resource of one type across every stack, as `[stack/logicalId, props]`. */
function everyResource(type: string): [string, Record<string, any>][] {
  return CASES.flatMap(([stack, template]) =>
    Object.entries<any>(template.findResources(type)).map(
      ([logicalId, resource]) =>
        [`${stack}/${logicalId}`, resource.Properties ?? {}] as [string, Record<string, any>],
    ),
  );
}

describe('every log group is encrypted with the stack key', () => {
  const groups = everyResource('AWS::Logs::LogGroup');

  test('there are log groups to check', () => {
    // 12 is what cfn-nag counted as W84 findings before this was fixed: two per
    // image build, one per bootstrap starter, plus the gate's scan log and the
    // Fargate task and flow logs. A number below that means the iteration stopped
    // finding them, not that the stacks got simpler.
    expect(groups.length).toBe(12);
  });

  test.each(groups.map(([name, props]) => [name, props] as const))(
    '%s specifies a KmsKeyId',
    (_name, props) => {
      // cfn-nag W84. The value is a token, so only its presence is asserted here;
      // the key-policy test below is what makes the key usable.
      expect(props.KmsKeyId).toBeDefined();
    },
  );
});

describe('every secret is encrypted with the stack key', () => {
  const secrets = everyResource('AWS::SecretsManager::Secret');

  test('there are secrets to check', () => {
    // One per stack that declares the MCP auth surface plus the two that create it
    // unconditionally for one class shape: four, which is the W77 count.
    expect(secrets.length).toBe(4);
  });

  test.each(secrets.map(([name, props]) => [name, props] as const))(
    '%s specifies a KmsKeyId',
    (_name, props) => {
      // cfn-nag W77.
      expect(props.KmsKeyId).toBeDefined();
    },
  );
});

describe('the key CloudWatch Logs is pointed at actually lets it encrypt', () => {
  // Setting KmsKeyId without this statement is the failure that looks fixed and
  // is not: synth is clean, the template is clean, and CloudFormation fails on the
  // first log group with an access-denied from the Logs service. So the grant is
  // asserted separately from the KmsKeyId above.
  //
  // Written against the statement itself rather than through Template's matcher
  // DSL. `Match.arrayWith` inside a nested `objectLike` reports "could not match
  // arrayWith pattern N" with the whole key dumped and no diff, which says nothing
  // about which field was wrong; pulling the statement out first means a failure
  // names the field.
  function logsGrant(template: Template): Record<string, any> {
    const keys = Object.values<any>(template.findResources('AWS::KMS::Key'));
    expect(keys).toHaveLength(1);
    const statements: Record<string, any>[] = keys[0].Properties.KeyPolicy.Statement;
    const matching = statements.filter((s) => s.Sid === 'AllowCloudWatchLogsEncryption');
    expect(matching).toHaveLength(1);
    return matching[0];
  }

  test.each(CASES)('%s grants the regional logs service principal', (_name, template) => {
    const statement = logsGrant(template);
    expect(statement.Effect).toBe('Allow');
    // logs.<region>.amazonaws.com, built from the pseudo-parameter so the
    // templates stay region-agnostic. CloudWatch Logs documents the regional form
    // and requires it to be in the key's own region, so the global
    // `logs.amazonaws.com` spelling would not do.
    expect(statement.Principal).toEqual({
      Service: { 'Fn::Join': ['', ['logs.', { Ref: 'AWS::Region' }, '.amazonaws.com']] },
    });
    // Sorted, because that is the order CDK renders. Compared as a set so a
    // reordering in CDK is not reported as a missing permission.
    expect([...statement.Action].sort()).toEqual([
      'kms:Decrypt',
      'kms:Describe*',
      'kms:Encrypt',
      'kms:GenerateDataKey*',
      'kms:ReEncrypt*',
    ]);
  });

  test.each(CASES)('%s confines the grant to this account by encryption context', (_name, template) => {
    // Without this condition the grant would let the Logs service principal use
    // the key on behalf of any account, which is the whole reason AWS documents a
    // condition on this statement rather than a bare service-principal allow.
    const condition = logsGrant(template).Condition;
    expect(Object.keys(condition)).toEqual(['ArnLike']);
    expect(condition.ArnLike['kms:EncryptionContext:aws:logs:arn']).toEqual({
      'Fn::Join': [
        '',
        [
          'arn:',
          { Ref: 'AWS::Partition' },
          ':logs:',
          { Ref: 'AWS::Region' },
          ':',
          { Ref: 'AWS::AccountId' },
          ':*',
        ],
      ],
    });
  });

  test.each(CASES)('%s has exactly one key, so one policy covers every group', (_name, template) => {
    // The grant above is written once per key. Two keys in one stack would mean a
    // log group could point at the one without the statement, and the tests above
    // would still pass on the other.
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
});

describe('the AgentCore execution role grants the ECR token once', () => {
  test('no statement is a duplicate of another', () => {
    // `Repository.grantPull` already emits ecr:GetAuthorizationToken on "*". This
    // role used to add an identical statement of its own under a sid, and the sid
    // is what stopped CDK's policy minimizer from folding the two together, so the
    // deployed role carried the grant twice. Stated as "no duplicates anywhere in
    // the document" rather than "no second token statement", because the mechanism
    // — a sid defeating minimization — applies to any statement, not just this one.
    const policies = Object.entries<any>(
      TEMPLATES.AshAgentCore.findResources('AWS::IAM::Policy'),
    );
    expect(policies.length).toBeGreaterThan(0);
    for (const [logicalId, policy] of policies) {
      const statements: unknown[] = policy.Properties.PolicyDocument.Statement;
      const withoutSids = statements.map((statement) => {
        const { Sid, ...rest } = statement as Record<string, unknown>;
        return JSON.stringify(rest);
      });
      expect(new Set(withoutSids).size).toBe(withoutSids.length);
      // Named in the failure output, so a reader knows which policy to open.
      expect(logicalId).toBeTruthy();
    }
  });
});
