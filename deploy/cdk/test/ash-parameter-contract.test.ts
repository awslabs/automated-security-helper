/**
 * The shared parameter surface is a contract with the Terraform mirror, so it is
 * tested as one.
 *
 * A rename here is a breaking change for adopters AND desynchronizes the two
 * implementations. These tests exist so that happens loudly.
 */

import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';

import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import { ASH_PARAMETER_NAMES, toAgentCoreName } from '../lib/ash-config';
import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import { AshEksOperatorStack } from '../lib/ash-eks-operator-stack';
import { AshFargateStack } from '../lib/ash-fargate-stack';
import { AshImagePipelineStack } from '../lib/ash-image-pipeline-stack';

type StackFactory = (app: App, id: string) => Stack;

const STACKS: Record<string, StackFactory> = {
  AshImagePipeline: (app, id) => new AshImagePipelineStack(app, id),
  AshAgentCore: (app, id) => new AshAgentCoreStack(app, id),
  AshFargate: (app, id) => new AshFargateStack(app, id),
  AshCodeCommitGate: (app, id) => new AshCodeCommitGateStack(app, id),
  AshDistributedPipeline: (app, id) => new AshDistributedPipelineStack(app, id),
  AshEksOperator: (app, id) => new AshEksOperatorStack(app, id),
};

function templates(): Record<string, Template> {
  const out: Record<string, Template> = {};
  for (const [id, factory] of Object.entries(STACKS)) {
    const app = new App({ analyticsReporting: false });
    out[id] = Template.fromStack(factory(app, id));
  }
  return out;
}

const ALL = templates();

describe('parameter names are the contract', () => {
  test('the canonical set has not drifted', () => {
    // Spelled out rather than derived, so that changing ASH_PARAMETER_NAMES
    // requires changing this list too and cannot happen by accident.
    //
    // Two names were added deliberately, and adding them here is the deliberate
    // half. `AshImageTag` lets a workload pin the image it pulls instead of
    // tracking the moving tag. `McpIngressCidr` is what opens the Fargate load
    // balancer, which is created with no ingress rule at all. Like every name in
    // this list both are part of the surface the Terraform mirror under
    // `deploy/terraform/` is expected to match, so both still need adding there.
    //
    // Three more arrived with the checkov hardening pass, and TWO OF THEM ARE
    // RESERVED NAMES RATHER THAN LIVE PARAMETERS. That distinction is the point of
    // this comment, because the next test asserts every DECLARED parameter is in
    // this list but nothing asserts the reverse:
    //
    // - `KmsKeyArn` is live. Every stack declares it, and it encrypts the log
    //   groups, the ECR repository, the secret and the Lambda environment.
    // - `VpcSubnetIds` and `CertificateArn` are RESERVED. `ash-config.ts` ships a
    //   factory for each, with the type and pattern settled, and no stack calls
    //   either one. They are the opt-in names the `CKV_AWS_117` and
    //   `CKV_AWS_2`/`CKV_AWS_103` suppressions in `.ash/.ash.yaml` refer to, fixed
    //   here so the suppression reason and the eventual parameter cannot disagree.
    //   Declaring them in a template before anything reads them would be the exact
    //   defect the "no stack declares a parameter it does not read" test below
    //   exists to catch, so they stay out of the templates until the resources that
    //   consume them land.
    expect(Object.values(ASH_PARAMETER_NAMES).sort()).toEqual(
      [
        'AshBaseConfigYaml',
        'AshImageTag',
        'AshOfflineMode',
        'AshVersion',
        'CertificateArn',
        'CodeCommitRepositoryArn',
        'KmsKeyArn',
        'McpAllowedHost',
        'McpAuthHeaderName',
        'McpIngressCidr',
        'McpAuthHeaderValue',
        'McpMountPath',
        'McpStatelessHttp',
        'RebuildSchedule',
        'ShardCount',
        'VpcSubnetIds',
        // Added with AshEksOperator, which is the first target to attach a Lambda
        // to a VPC and therefore the first to need a security group alongside the
        // subnets. Like every name in this list it is part of the surface a
        // Terraform mirror of that target would have to match, so it still needs
        // adding under deploy/terraform/ when that mirror lands.
        'VpcSecurityGroupIds',
      ].sort(),
    );
  });

  /**
   * The one stack that has taken `VpcSubnetIds` off the reserved list.
   *
   * `AshEksOperator` attaches its installer function to a VPC so it can reach a
   * cluster whose API endpoint is private-only, which is exactly the "until the
   * resources that consume them land" condition the note below describes. The name
   * going live for one stack does not un-reserve it for the others, so this is a
   * single-stack exception rather than a relaxation of the assertion.
   */
  const VPC_SUBNETS_LIVE_IN = new Set(['AshEksOperator']);

  test('the reserved names are reserved, not quietly declared', () => {
    // The other half of the note above, as an assertion rather than a promise. If
    // someone instantiates one of these without wiring a resource to it, the
    // "no stack declares a parameter it does not read" test would catch it only if
    // they also forgot the Ref -- and adding a lone CfnCondition would satisfy that
    // test while still asking an adopter a question with no consequence. This
    // closes that gap directly.
    for (const [id, template] of Object.entries(ALL)) {
      const declared = Object.keys(template.toJSON().Parameters ?? {});
      // Compared as one object carrying the stack id, so a failure NAMES the stack.
      // Bare `toContain` assertions report only the parameter list, and this is a
      // plain loop rather than a test.each, so nothing else identifies which of the
      // five stacks produced the failure. A separate `expect(id).toBeTruthy()`
      // cannot supply the name either: an Object.entries key is always a non-empty
      // string, so that assertion can never fail and never prints anything.
      //
      // `kmsKeyArn` is the positive control. Without it the two reserved-name
      // assertions would also hold for a template that declared no parameters at all.
      expect({
        stack: id,
        vpcSubnetIds: declared.includes(ASH_PARAMETER_NAMES.vpcSubnetIds),
        certificateArn: declared.includes(ASH_PARAMETER_NAMES.certificateArn),
        kmsKeyArn: declared.includes(ASH_PARAMETER_NAMES.kmsKeyArn),
      }).toEqual({
        stack: id,
        vpcSubnetIds: VPC_SUBNETS_LIVE_IN.has(id),
        certificateArn: false,
        kmsKeyArn: true,
      });
    }
  });

  test('every log group is encrypted with the customer-managed key when one is set', () => {
    // The guard that replaces a compile-time one. `diagnosticLogGroupProps` takes
    // its key as an OPTIONAL argument, so a call site that forgets it still
    // compiles and still gets the right retention -- and the missing encryption
    // would be invisible in the source, which is exactly how the
    // DESTROY/RETAIN split in ash-log-retention.test.ts went unnoticed.
    //
    // Asserted over the synthesized templates rather than the helper, so it also
    // covers a group created without going through the helper at all.
    let groups = 0;
    for (const template of Object.values(ALL)) {
      for (const [, resource] of Object.entries<any>(
        template.findResources('AWS::Logs::LogGroup'),
      )) {
        groups++;
        expect(resource.Properties?.KmsKeyId).toEqual({
          'Fn::If': ['HasKmsKey', { Ref: 'KmsKeyArn' }, { Ref: 'AWS::NoValue' }],
        });
      }
    }
    // A findResources filter that matched nothing would make the loop vacuous.
    expect(groups).toBeGreaterThanOrEqual(12);
  });

  test('no IAM statement puts the conditional key ARN in a Resource list', () => {
    /*
     * The failure this exists for synthesizes clean and fails at deploy.
     *
     * `AshCustomerKey.keyArnOrNoValue` is `Fn::If(HasKmsKey, <ref>, AWS::NoValue)`,
     * which is correct as an entire property value -- `AWS::NoValue` removes the
     * property. Inside a LIST it removes the ELEMENT instead, so an unset key turns
     * an IAM statement into `"Resource": []`, which CloudFormation rejects. CDK's
     * `Secret.grantRead` does exactly this if the secret is given the L2
     * `encryptionKey` prop, which is why ash-runtime-config.ts sets `KmsKeyId`
     * through an L1 override and grants `kms:Decrypt` through a conditional policy
     * resource instead.
     *
     * Nothing else in the app would report this. cdk-nag does not evaluate it, the
     * drift gate only compares bytes, and synth exits 0.
     */
    let statements = 0;
    for (const template of Object.values(ALL)) {
      for (const [, resource] of Object.entries<any>(template.toJSON().Resources ?? {})) {
        const document = resource.Properties?.PolicyDocument;
        for (const statement of document?.Statement ?? []) {
          statements++;
          for (const entry of [statement.Resource ?? []].flat()) {
            expect(JSON.stringify(entry)).not.toContain('AWS::NoValue');
          }
        }
      }
    }
    expect(statements).toBeGreaterThan(0);
  });

  test('the live-reserved-name exception names a stack that exists', () => {
    // Without this the exception set could outlive the stack that earned it: if
    // AshEksOperator were removed from STACKS the loop above would stop consulting
    // the set entirely and the stale entry would never be reported.
    for (const id of VPC_SUBNETS_LIVE_IN) {
      expect(Object.keys(ALL)).toContain(id);
    }
  });

  test('every declared parameter is one of the canonical names or a documented extra', () => {
    /*
     * Two stacks add names of their own, and each extra is recorded WITH ITS OWNER
     * rather than in a flat allowlist. A flat set would let any stack declare any
     * extra -- the previous form asserted `id === 'AshCodeCommitGate'` for every
     * non-canonical name, which was the same property while only one stack had
     * extras and would have silently become wrong the moment a second did.
     *
     * Anything absent from this map is either a typo or an undocumented addition.
     */
    const extraOwners: Record<string, string> = {
      ApprovalGate: 'AshCodeCommitGate',
      ChangedFilesOnly: 'AshCodeCommitGate',
      MinSeverity: 'AshCodeCommitGate',
      // AshEksOperator's three. None is a shared-shape name: the cluster and the
      // image identify a target that exists only for this stack, and the namespace
      // is a Kubernetes concept the other five have no use for. VpcSubnetIds and
      // VpcSecurityGroupIds are NOT here -- both are canonical.
      EksClusterName: 'AshEksOperator',
      OperatorImageUri: 'AshEksOperator',
      OperatorNamespace: 'AshEksOperator',
    };
    const canonical = new Set<string>(Object.values(ASH_PARAMETER_NAMES));
    for (const [id, template] of Object.entries(ALL)) {
      for (const name of Object.keys(template.toJSON().Parameters ?? {})) {
        expect(canonical.has(name) || name in extraOwners).toBe(true);
        if (!canonical.has(name)) {
          // Carries both names so a failure says which stack declared what.
          expect({ name, declaredBy: id }).toEqual({ name, declaredBy: extraOwners[name] });
        }
      }
    }
  });

  test('a parameter with the same name has the same default in every stack', () => {
    // Two stacks disagreeing on the default for McpStatelessHttp would mean one
    // of the two targets was quietly deploying a broken configuration.
    const seen = new Map<string, unknown>();
    for (const template of Object.values(ALL)) {
      for (const [name, spec] of Object.entries<Record<string, unknown>>(
        template.toJSON().Parameters ?? {},
      )) {
        if (seen.has(name)) {
          expect(spec.Default).toEqual(seen.get(name));
        } else {
          seen.set(name, spec.Default);
        }
      }
    }
  });

  test('no stack declares a parameter it does not read', () => {
    // A console launch shows every parameter of a template. Asking for ShardCount
    // on the Lambda gate would be a question with no consequence.
    for (const template of Object.values(ALL)) {
      const json = template.toJSON();
      const body = JSON.stringify({
        Resources: json.Resources,
        Conditions: json.Conditions,
        Outputs: json.Outputs,
      });
      for (const name of Object.keys(json.Parameters ?? {})) {
        expect(body).toContain(`"Ref":"${name}"`);
      }
    }
  });

  test('the offline flag uses the Dockerfile spelling, not a boolean', () => {
    // ASH's Dockerfile has `ARG OFFLINE="NO"`. Passing `true` would build an image
    // that stayed online while the parameter said otherwise.
    for (const template of Object.values(ALL)) {
      if (template.toJSON().Parameters?.[ASH_PARAMETER_NAMES.ashOfflineMode]) {
        template.hasParameter(ASH_PARAMETER_NAMES.ashOfflineMode, {
          Default: 'NO',
          AllowedValues: ['YES', 'NO'],
        });
      }
    }
  });

  test('the auth header name accepts empty or a name AgentCore would allowlist', () => {
    const pattern = ALL.AshAgentCore.toJSON().Parameters[ASH_PARAMETER_NAMES.mcpAuthHeaderName]
      .AllowedPattern;
    const re = new RegExp(pattern);
    expect('').toMatch(re);
    expect('X-ASH-Auth').toMatch(re);
    // Leading digit and a space are both rejected by AgentCore's own pattern.
    expect('1Bad').not.toMatch(re);
    expect('has space').not.toMatch(re);
  });

  test('the config parameter is bounded by the CloudFormation limit', () => {
    ALL.AshAgentCore.hasParameter(ASH_PARAMETER_NAMES.ashBaseConfigYaml, { MaxLength: 4096 });
  });
});

describe('every template stays portable and asset-free', () => {
  test.each(Object.keys(STACKS))('%s carries no account id and needs no bootstrap', (id) => {
    const json = ALL[id].toJSON();
    const rendered = JSON.stringify(json);
    // 12 consecutive digits is what an AWS account id looks like. This repository
    // is public.
    expect(rendered).not.toMatch(/\b\d{12}\b/);
    expect(Object.keys(json.Parameters ?? {})).not.toContain('BootstrapVersion');
    expect(json.Rules?.CheckBootstrapVersion).toBeUndefined();
    // CDKMetadata is version-keyed noise in a committed artifact.
    expect(json.Resources?.CDKMetadata).toBeUndefined();
  });

  /*
   * The image invariant has two halves, and until AshEksOperator landed one test
   * could carry both because every stack satisfied them the same way.
   *
   * THE HALF THAT IS UNIVERSAL: no template may reference a prebuilt public ASH
   * image. That follows from the trust position in
   * docs/content/docs/building-your-own-image.md and holds for every stack.
   *
   * THE HALF THAT IS NOT: "therefore the stack builds ASH itself, into an ECR
   * repository it creates". That is the mechanism the five workload stacks use
   * because each one RUNS ASH and needs an image to exist before its workload
   * starts. AshEksOperator runs nothing -- it installs an operator into a cluster
   * and the operator's image is the ADOPTER'S, built by them, in their registry.
   * There is no image for it to build and no repository for it to create.
   *
   * Exempting it from the second half without replacing it would leave the stack
   * with the weaker guarantee of the two, so it gets its own assertion instead: the
   * image must arrive as a parameter with NO Default. That is what makes a silent
   * substitution impossible -- a defaulted parameter is precisely how a public
   * image could creep back in, and CloudFormation refuses to create the stack at
   * all when a defaultless parameter is left blank.
   */
  const BUILDS_ASH_IMAGE = Object.keys(STACKS).filter((id) => id !== 'AshEksOperator');

  test.each(Object.keys(STACKS))('%s references no prebuilt public ASH image', (id) => {
    expect(JSON.stringify(ALL[id].toJSON())).not.toContain('public.ecr.aws/aws-labs');
  });

  test.each(BUILDS_ASH_IMAGE)('%s builds ASH into a repository it creates', (id) => {
    const rendered = JSON.stringify(ALL[id].toJSON());
    expect(rendered).toContain('automated-security-helper.git');
    expect(Object.keys(ALL[id].findResources('AWS::ECR::Repository')).length).toBeGreaterThan(0);
  });

  test('the exempt stack is exempt because it takes the image, not because it defaults one', () => {
    // Non-vacuity for the filter above: if AshEksOperator ever stopped declaring
    // the parameter, the exemption would silently become a hole rather than a
    // documented exception.
    const image = ALL.AshEksOperator.toJSON().Parameters?.OperatorImageUri;
    expect(image).toBeDefined();
    expect(image).not.toHaveProperty('Default');
    expect(image.MinLength).toBe(1);
    expect(BUILDS_ASH_IMAGE).not.toContain('AshEksOperator');
    expect(BUILDS_ASH_IMAGE).toHaveLength(Object.keys(STACKS).length - 1);
  });
});

describe('toAgentCoreName', () => {
  test('folds hyphens and drops a leading non-letter', () => {
    expect(toAgentCoreName('ash-agent-core')).toBe('ash_agent_core');
    expect(toAgentCoreName('9lives')).toBe('lives');
    expect(toAgentCoreName('')).toBe('ash');
  });

  test('never exceeds the 48-character limit', () => {
    expect(toAgentCoreName('a'.repeat(80))).toHaveLength(48);
  });

  test('always produces a name AgentCore accepts', () => {
    const pattern = /^[a-zA-Z][a-zA-Z0-9_]{0,47}$/;
    for (const input of ['ash-agent-core', 'Ash.Stack/Name', '---', '9', 'x'.repeat(200)]) {
      expect(toAgentCoreName(input)).toMatch(pattern);
    }
  });
});
