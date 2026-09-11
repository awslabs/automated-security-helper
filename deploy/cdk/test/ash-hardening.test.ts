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
 * property test is therefore preceded by an EXACT count, taken from the cfn-nag
 * measurement that prompted it. Exact rather than a floor deliberately: a floor
 * catches the iteration going blind but not a resource arriving that nobody
 * looked at, and the second is the failure these tests exist for -- a sixth log
 * group in the Fargate stack should fail here on the day it lands, whether or not
 * somebody remembered to pass it the key.
 *
 * WHAT "ENCRYPTED WITH THE STACK KEY" IS ASSERTED TO MEAN
 * ------------------------------------------------------
 * Equality against `{"Fn::GetAtt": [<the one key>, "Arn"]}`, with the logical id
 * read out of the template rather than written down here. Asserting only that a
 * `KmsKeyId` is present is not enough to hold the describe blocks' own claim: a
 * log group handed `kms.Key.fromKeyArn(...)` carries a KmsKeyId, creates no
 * `AWS::KMS::Key` resource, and so satisfies both a presence check and
 * `resourceCountIs('AWS::KMS::Key', 1)` while being encrypted under a key this
 * stack's policy does not govern.
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
 * policy document has statements the shipped template has merged away. That was
 * measured while writing the key-policy assertions below: the Fargate key policy
 * has 4 statements as committed and 5 as this file used to construct it.
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

/**
 * Every resource of one type across every stack, as
 * `[stack/logicalId, props, stack]`.
 *
 * The stack name is carried through so an assertion can compare against that
 * stack's own key rather than against any key.
 */
function everyResource(type: string): [string, Record<string, any>, string][] {
  return CASES.flatMap(([stack, template]) =>
    Object.entries<any>(template.findResources(type)).map(
      ([logicalId, resource]) =>
        [`${stack}/${logicalId}`, resource.Properties ?? {}, stack] as [
          string,
          Record<string, any>,
          string,
        ],
    ),
  );
}

/**
 * The statements of the one KMS key in a stack.
 *
 * Throws rather than `expect`s on the count, because this runs at module scope to
 * build the per-stack key reference below and a thrown error there names the
 * problem; a failed `expect` outside a test does not.
 */
function keyPolicyStatements(template: Template): Record<string, any>[] {
  const keys = Object.values<any>(theOneKey(template));
  return keys[0].Properties.KeyPolicy.Statement;
}

/** `{logicalId: resource}` for the stack's single key, or a throw naming what it found. */
function theOneKey(template: Template): Record<string, any> {
  const keys = template.findResources('AWS::KMS::Key');
  const ids = Object.keys(keys);
  if (ids.length !== 1) {
    throw new Error(`expected exactly one AWS::KMS::Key, found ${ids.length}: ${ids.join(', ')}`);
  }
  return keys;
}

/**
 * What a resource encrypted with the stack's own key renders as.
 *
 * Derived from the template, not hardcoded, so a construct rename moves this with
 * it instead of rotting into an assertion that silently matches nothing.
 */
const STACK_KEY_ARN: Record<string, unknown> = Object.fromEntries(
  CASES.map(([stack, template]) => [
    stack,
    { 'Fn::GetAtt': [Object.keys(theOneKey(template))[0], 'Arn'] },
  ]),
);

/** True for the three stacks whose workload cannot be created against an empty repository. */
function hasBootstrapStarter(template: Template): boolean {
  return Object.keys(template.findResources('AWS::Lambda::Function')).some((logicalId) =>
    logicalId.includes('BootstrapStarter'),
  );
}

describe('the templates under test are the templates that ship', () => {
  test('cdk.json context reached the App', () => {
    // Non-vacuity for the block above. If the path breaks or cdk.json is
    // restructured, `CDK_JSON_CONTEXT` becomes undefined, `new App({context:
    // undefined})` is silently accepted, and every assertion in this file quietly
    // starts measuring an unminimized template again. Pinning the one flag whose
    // absence was observed to change the output stops that.
    expect(CDK_JSON_CONTEXT).toBeDefined();
    expect(CDK_JSON_CONTEXT['@aws-cdk/aws-iam:minimizePolicies']).toBe(true);
  });
});

describe('every log group is encrypted with the stack key', () => {
  const groups = everyResource('AWS::Logs::LogGroup');

  test('there are log groups to check', () => {
    // 12 is what cfn-nag counted as W84 findings before this was fixed: two per
    // image build, one per bootstrap starter, plus the gate's scan log and the
    // Fargate task and flow logs. Exact, so neither a rename that stops the
    // iteration finding them nor a thirteenth group nobody looked at passes.
    expect(groups.length).toBe(12);
  });

  test.each(groups)('%s is encrypted with its own stack key', (_name, props, stack) => {
    // cfn-nag W84 only asks for a KmsKeyId. This asserts the stronger property the
    // describe block claims: the key is THIS stack's key, the one whose policy the
    // tests below check. An imported key would satisfy a presence check and add no
    // AWS::KMS::Key resource, so the count assertion further down would not catch
    // it either.
    expect(props.KmsKeyId).toEqual(STACK_KEY_ARN[stack]);
  });
});

describe('every secret is encrypted with the stack key', () => {
  const secrets = everyResource('AWS::SecretsManager::Secret');

  test('there are secrets to check', () => {
    // One per stack that declares the MCP auth surface plus the two that create it
    // unconditionally for one class shape: four, which is the W77 count.
    expect(secrets.length).toBe(4);
  });

  test.each(secrets)('%s is encrypted with its own stack key', (_name, props, stack) => {
    // cfn-nag W77, plus the same strengthening as the log groups above.
    expect(props.KmsKeyId).toEqual(STACK_KEY_ARN[stack]);
  });
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
    const matching = keyPolicyStatements(template).filter(
      (s) => s.Sid === 'AllowCloudWatchLogsEncryption',
    );
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

describe('the key policy is also what makes the auth secret readable', () => {
  // The KmsKeyId assertions above prove the secret names this key. They do not
  // prove the key lets Secrets Manager use it, and they do not prove any principal
  // can read through it. Both of those live in the key policy, and neither was
  // covered before: delete both statements and the secret still carries a
  // KmsKeyId, every count still matches, cdk-nag and cfn-nag both stay clean, and
  // the container fails at start with an access-denied nobody predicted.
  //
  // The two statements are CDK's, not written out in this repository -- passing
  // `encryptionKey` to `new Secret(...)` emits the first and each `grantRead`
  // extends the second -- which is exactly why they need asserting. Nothing in
  // lib/ would have to change for them to disappear.

  /** `secretsmanager.<region>.amazonaws.com`, region-agnostic like the logs form. */
  const VIA_SECRETSMANAGER = {
    'Fn::Join': ['', ['secretsmanager.', { Ref: 'AWS::Region' }, '.amazonaws.com']],
  };
  const ACCOUNT_ROOT = {
    AWS: {
      'Fn::Join': [
        '',
        ['arn:', { Ref: 'AWS::Partition' }, ':iam::', { Ref: 'AWS::AccountId' }, ':root'],
      ],
    },
  };

  function viaSecretsManager(template: Template): Record<string, any>[] {
    return keyPolicyStatements(template).filter(
      (s) =>
        JSON.stringify(s.Condition?.StringEquals?.['kms:ViaService']) ===
        JSON.stringify(VIA_SECRETSMANAGER),
    );
  }

  const hasSecret = (template: Template) =>
    Object.keys(template.findResources('AWS::SecretsManager::Secret')).length > 0;
  const WITH_SECRET = CASES.filter(([, template]) => hasSecret(template));
  const WITHOUT_SECRET = CASES.filter(([, template]) => !hasSecret(template));

  test('four stacks declare a secret and one does not', () => {
    // Both lists are pinned so neither arm of the split can quietly empty out. The
    // four match the W77 count asserted above; AshImagePipeline builds images and
    // serves nothing, so it has no MCP auth surface at all.
    expect(WITH_SECRET.map(([name]) => name).sort()).toEqual([
      'AshAgentCore',
      'AshCodeCommitGate',
      'AshDistributedPipeline',
      'AshFargate',
    ]);
    expect(WITHOUT_SECRET.map(([name]) => name)).toEqual(['AshImagePipeline']);
  });

  test.each(WITH_SECRET)('%s lets Secrets Manager use the key', (_name, template) => {
    const statements = viaSecretsManager(template);
    expect(statements).toHaveLength(2);

    // Split by shape rather than by position: CDK's rendering order is not a
    // property worth pinning, and a reordering would otherwise read as a missing
    // grant.
    const forTheService = statements.filter((s) => Array.isArray(s.Action));
    expect(forTheService).toHaveLength(1);
    expect(forTheService[0].Effect).toBe('Allow');
    expect([...forTheService[0].Action].sort()).toEqual([
      'kms:CreateGrant',
      'kms:Decrypt',
      'kms:DescribeKey',
      'kms:Encrypt',
      'kms:GenerateDataKey*',
      'kms:ReEncrypt*',
    ]);
    // The account root, confined by kms:ViaService. Note what this statement is
    // NOT: it does not name Secrets Manager as a principal, it delegates to
    // identity policies and then restricts the route. That is the same root
    // delegation ash-runtime-config.ts records as the reason deleting the reader
    // statement below revokes nothing.
    expect(forTheService[0].Principal).toEqual(ACCOUNT_ROOT);
  });

  test.each(WITH_SECRET)('%s lets its own readers decrypt', (_name, template) => {
    const forReaders = viaSecretsManager(template).filter((s) => s.Action === 'kms:Decrypt');
    expect(forReaders).toHaveLength(1);
    expect(forReaders[0].Effect).toBe('Allow');

    // One principal in most stacks, several in the sharded pipeline. Asserted as
    // "every principal is a role this template declares" rather than by name, so a
    // rename cannot leave a dangling reference that still reads as a grant.
    const principal = forReaders[0].Principal.AWS;
    const principals: any[] = Array.isArray(principal) ? principal : [principal];
    expect(principals.length).toBeGreaterThan(0);
    const roles = Object.keys(template.findResources('AWS::IAM::Role'));
    for (const entry of principals) {
      expect(Object.keys(entry)).toEqual(['Fn::GetAtt']);
      const [logicalId, attribute] = entry['Fn::GetAtt'];
      expect(attribute).toBe('Arn');
      expect(roles).toContain(logicalId);
    }
  });

  test.each(WITHOUT_SECRET)('%s carries no Secrets Manager statement', (_name, template) => {
    // The absence is measured, not skipped. Two statements is the whole policy of a
    // stack with no secret: the root delegation KMS creates by default, and the
    // CloudWatch Logs grant. ash-encryption.ts's key description is written to be
    // true of this stack too, and this is what would redden if a secret arrived
    // here without that being revisited.
    expect(viaSecretsManager(template)).toHaveLength(0);
    expect(keyPolicyStatements(template)).toHaveLength(2);
  });
});

describe('the key survives the stack that created it', () => {
  // The property under test is unrecoverability, not tidiness. ash-encryption.ts
  // records that deleting the key takes every log group encrypted with it beyond
  // recovery, and the gate's ScanLogs is itself DeletionPolicy: Retain — so a key
  // flipped to DESTROY leaves retained scan logs that nothing can ever read again
  // after a stack delete. Nothing in the suite reddened on that flip before these
  // tests existed: RemovalPolicy is not a resource property, so the
  // findResources-based property tests above cannot see it at all.
  test.each(CASES)('%s retains its key on delete and on replace', (_name, template) => {
    // Both halves matter and they are different failures. DeletionPolicy covers
    // deleting the stack; UpdateReplacePolicy covers a property change that makes
    // CloudFormation replace the key rather than update it in place, which would
    // strand the old key's ciphertext just as thoroughly.
    template.hasResource('AWS::KMS::Key', {
      DeletionPolicy: 'Retain',
      UpdateReplacePolicy: 'Retain',
    });
  });

  test.each(CASES)('%s gives the key an alias that cannot collide', (stack, template) => {
    // Retained and unaliased, the key is a uuid in the console and in `aws kms
    // list-keys`, distinguishable only by its description. `alias/ash-<stack>` makes
    // it navigable, which matters most in the situation that produced this
    // assertion: an operator finding a leftover key after a stack delete and
    // deciding whether it is safe to schedule for deletion.
    //
    // The name comes from AWS::StackName, not from the CDK construct id. Two ASH
    // deployments in one account are two stacks with two names, so a fixed
    // `alias/ash-fargate` would make the second launch fail with
    // AlreadyExistsException. CloudFormation admits no two stacks of the same name
    // in one region, which makes the pseudo-parameter collision-free by
    // construction rather than by convention.
    template.resourceCountIs('AWS::KMS::Alias', 1);
    template.hasResourceProperties('AWS::KMS::Alias', {
      AliasName: { 'Fn::Join': ['', ['alias/ash-', { Ref: 'AWS::StackName' }]] },
      TargetKeyId: STACK_KEY_ARN[stack],
    });
  });

  test.each(CASES)('%s lets the alias go and keeps the name in the key', (_name, template) => {
    // The alias deliberately does NOT get RemovalPolicy.RETAIN, even though it is
    // the retained key's label. A retained alias would keep naming the key after the
    // stack was deleted, and would also make relaunching a stack of the same name
    // fail on AlreadyExistsException with nothing in the template explaining why --
    // a worse trap than the one it fixes. So the post-delete case is carried by the
    // key's own Description, which names AWS::StackName and cannot be orphaned.
    const alias = Object.values<any>(template.findResources('AWS::KMS::Alias'))[0];
    expect(alias.DeletionPolicy).toBeUndefined();
    expect(alias.UpdateReplacePolicy).toBeUndefined();
    const description = Object.values<any>(theOneKey(template))[0].Properties.Description;
    expect(JSON.stringify(description)).toContain('AWS::StackName');
  });

  test.each(CASES)('%s rotates its key', (_name, template) => {
    // Asserted here rather than left to cdk-nag: no cdk-nag rule in AwsSolutions
    // covers key rotation, so nothing else in this repository fails if it is
    // turned off.
    template.hasResourceProperties('AWS::KMS::Key', { EnableKeyRotation: true });
  });
});

describe('the image-build bootstrap starter reserves no concurrency', () => {
  // cfn-nag W92 asks for a reservation. It is suppressed rather than satisfied,
  // because a reservation makes stack CREATION depend on the account's unreserved
  // concurrency: Lambda rejects any reservation that would leave the account below
  // 100 unreserved, so an adopter with a reduced quota gets a failed create and a
  // rolled-back stack -- to remediate a warning. These tests pin both halves of that
  // decision: the property is absent, and the suppression carries the argument.
  const starters = everyResource('AWS::Lambda::Function').filter(([name]) =>
    name.includes('BootstrapStarter'),
  );

  test('there are bootstrap starters to check', () => {
    // Three: the stacks whose workload cannot be created against an empty
    // repository. The sharded pipeline and the standalone image build set
    // bootstrapOnDeploy false and have none.
    expect(starters.length).toBe(3);
  });

  test.each(starters)('%s sets no reservation', (_name, props) => {
    expect(props.ReservedConcurrentExecutions).toBeUndefined();
  });

  test.each(CASES.filter(([, template]) => hasBootstrapStarter(template)))(
    '%s suppresses W92 with a reason, not a bare rule id',
    (_name, template) => {
      // A suppression whose reason is empty or a restatement of the rule id leaves the
      // next reader to re-derive the concurrency-quota argument. Asserted as
      // substance: the reason has to name the invoker and the quota.
      const starter = Object.entries<any>(template.findResources('AWS::Lambda::Function')).filter(
        ([logicalId]) => logicalId.includes('BootstrapStarter'),
      );
      expect(starter).toHaveLength(1);
      const suppressed = starter[0][1].Metadata?.cfn_nag?.rules_to_suppress;
      expect(suppressed).toHaveLength(1);
      expect(suppressed[0].id).toBe('W92');
      expect(suppressed[0].reason).toMatch(/Custom::AshImageBootstrap/);
      expect(suppressed[0].reason).toMatch(/unreserved/);
      expect(suppressed[0].reason.length).toBeGreaterThan(120);
    },
  );

  test.each(CASES.filter(([, template]) => hasBootstrapStarter(template)))(
    '%s gives no service principal a way to invoke the starter',
    (_name, template) => {
      // This is what makes the suppression true rather than merely stated. If a
      // Lambda::Permission ever appears for a bootstrap starter, something other than
      // CloudFormation can invoke it, the "no fan-out" argument stops holding, and the
      // suppression has to be revisited.
      const permissions = Object.values<any>(template.findResources('AWS::Lambda::Permission'));
      for (const permission of permissions) {
        expect(JSON.stringify(permission.Properties.FunctionName)).not.toContain(
          'BootstrapStarter',
        );
      }
      // And the starter's ARN is referenced exactly once, by the custom resource.
      const [starterId] = Object.keys(template.findResources('AWS::Lambda::Function')).filter(
        (logicalId) => logicalId.includes('BootstrapStarter'),
      );
      const referrers = Object.entries<any>(template.toJSON().Resources).filter(
        ([logicalId, resource]) =>
          logicalId !== starterId && JSON.stringify(resource).includes(`"${starterId}"`),
      );
      expect(referrers.map(([, resource]) => resource.Type)).toEqual([
        'Custom::AshImageBootstrap',
      ]);
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
    // 88 across the five stacks, in the order STACKS declares them. Exact and
    // per-stack, so one stack losing its policies to a rename cannot leave the loop
    // for that stack iterating over nothing while the others carry the assertion.
    //
    // Was [4, 4, 6, 4, 15] = 33 before the per-service policy split in
    // ash-policy-split.ts, which files each role's statements into one
    // AWS::IAM::Policy per AWS service so that no single document trips cfn-nag's
    // W76 ceiling. The counts rose; the statements did not change, which the
    // duplicate check below is a second witness to -- it passes over all 88.
    expect(policiesPerStack.map(([, policies]) => policies.length)).toEqual([
      10, 12, 9, 7, 50,
    ]);
  });

  test.each(policiesPerStack)('%s has no statement that duplicates another', (_stack, policies) => {
    for (const [logicalId, policy] of policies) {
      const statements: unknown[] = policy.Properties.PolicyDocument.Statement;
      const withoutSids = statements.map((statement) => {
        const { Sid, ...rest } = statement as Record<string, unknown>;
        return JSON.stringify(rest);
      });
      // Named in the failure output, so a reader knows which policy to open.
      expect({ policy: logicalId, distinct: new Set(withoutSids).size }).toEqual({
        policy: logicalId,
        distinct: withoutSids.length,
      });
    }
  });
});
