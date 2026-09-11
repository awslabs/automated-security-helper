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
      ].sort(),
    );
  });

  test('the reserved names are reserved, not quietly declared', () => {
    // The other half of the note above, as an assertion rather than a promise. If
    // someone instantiates one of these without wiring a resource to it, the
    // "no stack declares a parameter it does not read" test would catch it only if
    // they also forgot the Ref -- and adding a lone CfnCondition would satisfy that
    // test while still asking an adopter a question with no consequence. This
    // closes that gap directly.
    for (const [id, template] of Object.entries(ALL)) {
      const declared = Object.keys(template.toJSON().Parameters ?? {});
      expect(declared).not.toContain(ASH_PARAMETER_NAMES.vpcSubnetIds);
      expect(declared).not.toContain(ASH_PARAMETER_NAMES.certificateArn);
      // Positive control: without this, the two assertions above would also pass
      // for a template that declared no parameters at all.
      expect(declared).toContain(ASH_PARAMETER_NAMES.kmsKeyArn);
      expect(id).toBeTruthy();
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

  test('every declared parameter is one of the canonical names or a documented extra', () => {
    // The gate stack adds three of its own. Anything beyond this list is either a
    // typo or an undocumented addition the Terraform mirror will not have.
    const allowedExtras = new Set(['ApprovalGate', 'ChangedFilesOnly', 'MinSeverity']);
    const canonical = new Set<string>(Object.values(ASH_PARAMETER_NAMES));
    for (const [id, template] of Object.entries(ALL)) {
      for (const name of Object.keys(template.toJSON().Parameters ?? {})) {
        expect(canonical.has(name) || allowedExtras.has(name)).toBe(true);
        if (!canonical.has(name)) {
          expect(id).toBe('AshCodeCommitGate');
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

  test.each(Object.keys(STACKS))('%s builds ASH rather than pulling a prebuilt image', (id) => {
    // ASH publishes no public image. A reference to one would mean this template
    // could never work.
    const rendered = JSON.stringify(ALL[id].toJSON());
    expect(rendered).not.toContain('public.ecr.aws/aws-labs');
    expect(rendered).toContain('automated-security-helper.git');
    expect(Object.keys(ALL[id].findResources('AWS::ECR::Repository')).length).toBeGreaterThan(0);
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
