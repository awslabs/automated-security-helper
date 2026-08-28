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
    expect(Object.values(ASH_PARAMETER_NAMES).sort()).toEqual(
      [
        'AshBaseConfigYaml',
        'AshImageTag',
        'AshOfflineMode',
        'AshVersion',
        'CodeCommitRepositoryArn',
        'McpAllowedHost',
        'McpAuthHeaderName',
        'McpIngressCidr',
        'McpAuthHeaderValue',
        'McpMountPath',
        'McpStatelessHttp',
        'RebuildSchedule',
        'ShardCount',
      ].sort(),
    );
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
